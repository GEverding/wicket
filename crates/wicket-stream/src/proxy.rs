//! L4 TCP/TLS stream proxy implementation.
//!
//! Provides high-performance TCP proxying with SNI-based routing, source IP pooling,
//! PROXY protocol support, and optional eBPF sockmap acceleration. Supports hot-reload
//! of routing and upstream configuration without dropping active connections.

use arc_swap::ArcSwap;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
#[cfg(unix)]
use tokio::net::UnixStream;
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;

use crate::endpoint::StreamBackendAddr;
use crate::health::BackendHealth;
use crate::metrics::{
    STREAM_BACKEND_HEALTH_TRANSITIONS_TOTAL, STREAM_BYTES_TOTAL, STREAM_CONFIG_RELOADS_TOTAL,
    STREAM_CONNECTIONS_ACTIVE, STREAM_CONNECTIONS_REJECTED_TOTAL, STREAM_CONNECTIONS_TOTAL,
    STREAM_CONNECTION_DURATION_SECONDS, STREAM_CONNECTION_ERRORS_TOTAL,
    STREAM_CONNECT_DURATION_SECONDS, STREAM_PROXY_PATH_TOTAL, STREAM_SNI_EXTRACTIONS_TOTAL,
    STREAM_UPSTREAM_HEALTH,
};
use crate::pool::SourceIpPool;
use crate::protocol::{ProxyProtocolEncoder, ProxyProtocolVersion};
use crate::router::SniRouter;
use crate::sni::extract_sni;
use crate::StreamError;

enum BackendConnection {
    Tcp(TcpStream),
    #[cfg(unix)]
    Unix(UnixStream),
}

impl AsyncRead for BackendConnection {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_read(cx, buf),
            #[cfg(unix)]
            Self::Unix(stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for BackendConnection {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_write(cx, buf),
            #[cfg(unix)]
            Self::Unix(stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_flush(cx),
            #[cfg(unix)]
            Self::Unix(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_shutdown(cx),
            #[cfg(unix)]
            Self::Unix(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

/// RAII guard that decrements the active-connections gauge and records duration on drop.
struct ConnectionGuard {
    upstream: Option<String>,
    start: Instant,
}

impl ConnectionGuard {
    fn new() -> Self {
        STREAM_CONNECTIONS_ACTIVE.inc();
        Self {
            upstream: None,
            start: Instant::now(),
        }
    }

    fn set_upstream(&mut self, name: String) {
        self.upstream = Some(name);
    }
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        STREAM_CONNECTIONS_ACTIVE.dec();
        if let Some(ref upstream) = self.upstream {
            STREAM_CONNECTION_DURATION_SECONDS
                .with_label_values(&[upstream])
                .observe(self.start.elapsed().as_secs_f64());
        }
    }
}

#[cfg(all(target_os = "linux", feature = "ebpf"))]
use std::sync::Mutex;

#[cfg(all(target_os = "linux", feature = "ebpf"))]
use wicket_sockmap::SocketMap;

/// Upstream server configuration with passive health tracking.
#[derive(Debug)]
pub struct Upstream {
    pub name: String,
    pub servers: Vec<StreamBackendAddr>,
    pub(crate) health: Vec<BackendHealth>,
    counter: AtomicUsize,
    cooldown: Duration,
}

impl Upstream {
    /// Create a new upstream with the given name and servers.
    /// Uses a default 30-second cooldown for unhealthy backends.
    pub fn new(name: String, servers: Vec<StreamBackendAddr>) -> Self {
        Self::with_cooldown(name, servers, Duration::from_secs(30))
    }

    /// Create a new upstream with a custom cooldown duration.
    pub fn with_cooldown(
        name: String,
        servers: Vec<StreamBackendAddr>,
        cooldown: Duration,
    ) -> Self {
        let health = servers
            .iter()
            .map(|endpoint| BackendHealth::new(endpoint.to_string()))
            .collect();
        Self {
            name,
            servers,
            health,
            counter: AtomicUsize::new(0),
            cooldown,
        }
    }

    /// Select next healthy/eligible server using round-robin.
    ///
    /// Tries up to `servers.len()` slots starting from the current counter position.
    /// If all backends are unhealthy and within cooldown, fails open — returns the
    /// next round-robin server anyway to avoid refusing all traffic.
    pub fn next_server(&self) -> StreamBackendAddr {
        let len = self.servers.len();
        let start = self.counter.fetch_add(1, Ordering::Relaxed);

        // First pass: find an eligible (healthy or past cooldown) server
        for i in 0..len {
            let idx = (start + i) % len;
            if self.health[idx].is_eligible(self.cooldown) {
                return self.servers[idx].clone();
            }
        }

        // Fail-open: all unhealthy and in cooldown — route anyway
        tracing::warn!(
            upstream = %self.name,
            "All backends unhealthy; routing to next backend anyway (fail-open)"
        );
        self.servers[start % len].clone()
    }

    /// Report a successful connect for a specific backend address.
    pub fn report_success(&self, endpoint: &StreamBackendAddr) {
        let label = endpoint.to_string();
        if let Some(h) = self.health.iter().find(|h| h.label() == label) {
            let was_healthy = h.is_healthy();
            h.record_success();
            if !was_healthy {
                STREAM_UPSTREAM_HEALTH
                    .with_label_values(&[&self.name, &label])
                    .set(1);
                STREAM_BACKEND_HEALTH_TRANSITIONS_TOTAL
                    .with_label_values(&[&self.name, &label, "unhealthy_to_healthy"])
                    .inc();
            }
        }
    }

    /// Report a failed connect for a specific backend address.
    pub fn report_failure(&self, endpoint: &StreamBackendAddr) {
        let label = endpoint.to_string();
        if let Some(h) = self.health.iter().find(|h| h.label() == label) {
            let was_healthy = h.is_healthy();
            h.record_failure();
            if was_healthy {
                STREAM_UPSTREAM_HEALTH
                    .with_label_values(&[&self.name, &label])
                    .set(0);
                STREAM_BACKEND_HEALTH_TRANSITIONS_TOTAL
                    .with_label_values(&[&self.name, &label, "healthy_to_unhealthy"])
                    .inc();
            }
        }
    }
}

/// Main L4 stream proxy.
#[derive(Debug)]
pub struct StreamProxy {
    pub(crate) router: ArcSwap<SniRouter>,
    pub(crate) upstreams: ArcSwap<HashMap<String, Arc<Upstream>>>,
    pub(crate) source_ip_pool: Option<SourceIpPool>,
    pub(crate) proxy_protocol: Option<ProxyProtocolVersion>,
    pub(crate) local_addr: SocketAddr,
    pub(crate) connect_timeout: Duration,
    /// Semaphore for connection limiting. `None` means unlimited.
    ///
    /// Set at startup from `max_connections`; not reloadable (restart required to change).
    pub(crate) connection_semaphore: Option<Arc<tokio::sync::Semaphore>>,
    /// How long to wait for active connections to drain on shutdown.
    pub(crate) drain_timeout: Duration,
    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    pub(crate) sockmap: Option<Arc<Mutex<SocketMap>>>,
}

impl StreamProxy {
    /// Create a new stream proxy.
    pub fn new(
        router: SniRouter,
        upstreams: HashMap<String, Arc<Upstream>>,
        source_ip_pool: Option<SourceIpPool>,
        proxy_protocol: Option<ProxyProtocolVersion>,
        local_addr: SocketAddr,
        connect_timeout: Duration,
        max_connections: u32,
    ) -> Self {
        let connection_semaphore = if max_connections > 0 {
            Some(Arc::new(tokio::sync::Semaphore::new(
                max_connections as usize,
            )))
        } else {
            None
        };
        Self {
            router: ArcSwap::new(Arc::new(router)),
            upstreams: ArcSwap::new(Arc::new(upstreams)),
            source_ip_pool,
            proxy_protocol,
            local_addr,
            connect_timeout,
            connection_semaphore,
            drain_timeout: Duration::from_secs(30),
            #[cfg(all(target_os = "linux", feature = "ebpf"))]
            sockmap: None,
        }
    }

    /// Set the eBPF sockmap for kernel-level proxying.
    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    pub fn with_sockmap(mut self, sockmap: SocketMap) -> Self {
        self.sockmap = Some(Arc::new(Mutex::new(sockmap)));
        self
    }

    /// Build from config.
    pub fn from_config(config: &wicket_config::StreamConfig) -> Result<Self, StreamError> {
        // Build router
        let router = SniRouter::new(&config.sni_routes, config.default_upstream.clone());

        let cooldown = Duration::from_secs(config.health_cooldown_secs);

        // Build upstreams
        let mut upstreams = HashMap::new();
        for upstream_config in &config.upstreams {
            let servers = parse_backend_endpoints(&upstream_config.servers)?;

            upstreams.insert(
                upstream_config.name.clone(),
                Arc::new(Upstream::with_cooldown(
                    upstream_config.name.clone(),
                    servers,
                    cooldown,
                )),
            );
        }

        // Build source IP pool
        let source_ip_pool = if config.source_ips.is_empty() {
            None
        } else {
            Some(SourceIpPool::new(config.source_ips.clone()))
        };

        // Parse proxy protocol
        let proxy_protocol = match &config.proxy_protocol {
            wicket_config::ProxyProtocolConfig::None => None,
            wicket_config::ProxyProtocolConfig::V1 => Some(ProxyProtocolVersion::V1),
            wicket_config::ProxyProtocolConfig::V2 => Some(ProxyProtocolVersion::V2),
        };

        let local_addr: SocketAddr = config
            .listen
            .parse()
            .map_err(|e| StreamError::ConfigError(format!("Invalid listen address: {}", e)))?;

        let connect_timeout = Duration::from_millis(config.connect_timeout_ms);
        let connection_semaphore = if config.max_connections > 0 {
            Some(Arc::new(tokio::sync::Semaphore::new(
                config.max_connections as usize,
            )))
        } else {
            None
        };

        Ok(Self {
            router: ArcSwap::new(Arc::new(router)),
            upstreams: ArcSwap::new(Arc::new(upstreams)),
            source_ip_pool,
            proxy_protocol,
            local_addr,
            connect_timeout,
            connection_semaphore,
            drain_timeout: Duration::from_secs(config.drain_timeout_secs),
            #[cfg(all(target_os = "linux", feature = "ebpf"))]
            sockmap: None,
        })
    }

    /// Reload configuration. Active connections continue with the previous config.
    ///
    /// On success, atomically swaps in the new router and upstreams.
    /// On failure, the running config is unchanged.
    pub fn reload(&self, config: &wicket_config::StreamConfig) -> Result<(), StreamError> {
        // Build new router
        let router = SniRouter::new(&config.sni_routes, config.default_upstream.clone());

        // Build new upstreams (fresh health state — all healthy)
        let cooldown = Duration::from_secs(config.health_cooldown_secs);
        let mut upstreams = HashMap::new();
        for upstream_config in &config.upstreams {
            let servers = parse_backend_endpoints(&upstream_config.servers)?;

            upstreams.insert(
                upstream_config.name.clone(),
                Arc::new(Upstream::with_cooldown(
                    upstream_config.name.clone(),
                    servers,
                    cooldown,
                )),
            );
        }

        self.router.store(Arc::new(router));
        self.upstreams.store(Arc::new(upstreams));

        STREAM_CONFIG_RELOADS_TOTAL.inc();
        tracing::info!("Stream proxy configuration reloaded");
        Ok(())
    }

    /// Run the proxy server until `shutdown` is cancelled.
    ///
    /// On shutdown, stops accepting new connections and waits up to `drain_timeout`
    /// for active connections to finish before returning.
    pub async fn run(
        self: Arc<Self>,
        listener: TcpListener,
        shutdown: CancellationToken,
    ) -> Result<(), StreamError> {
        let active_tasks = Arc::new(AtomicUsize::new(0));

        loop {
            tokio::select! {
                result = listener.accept() => {
                    let (client_stream, client_addr) = result?;
                    let proxy = Arc::clone(&self);

                    // Acquire connection permit (if limits configured).
                    // try_acquire_owned never blocks the accept loop.
                    let permit = if let Some(ref sem) = self.connection_semaphore {
                        match sem.clone().try_acquire_owned() {
                            Ok(permit) => Some(permit),
                            Err(_) => {
                                STREAM_CONNECTIONS_REJECTED_TOTAL.inc();
                                tracing::warn!(
                                    client = %client_addr,
                                    "Connection rejected: max connections reached"
                                );
                                continue;
                            }
                        }
                    } else {
                        None
                    };

                    active_tasks.fetch_add(1, Ordering::Relaxed);
                    let task_counter = Arc::clone(&active_tasks);

                    tokio::spawn(async move {
                        let _permit = permit; // held until task completes
                        if let Err(e) = proxy.handle_connection(client_stream, client_addr).await {
                            tracing::warn!(client = %client_addr, error = %e, "Connection failed");
                        }
                        task_counter.fetch_sub(1, Ordering::Relaxed);
                    });
                }
                _ = shutdown.cancelled() => {
                    tracing::info!("Stream proxy shutting down, draining active connections...");
                    break;
                }
            }
        }

        // Drain: wait for active connections with a hard timeout.
        let drain_start = Instant::now();
        loop {
            let remaining = active_tasks.load(Ordering::Relaxed);
            if remaining == 0 {
                tracing::info!("Stream proxy: all connections drained");
                break;
            }
            if drain_start.elapsed() >= self.drain_timeout {
                tracing::warn!(
                    remaining = remaining,
                    "Stream proxy: drain timeout reached, forcing shutdown"
                );
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        Ok(())
    }

    /// Handle a single client connection.
    async fn handle_connection(
        &self,
        mut client: TcpStream,
        client_addr: SocketAddr,
    ) -> Result<(), StreamError> {
        // Snapshot config at connection start — a mid-connection reload won't affect this conn.
        let router = self.router.load();
        let upstreams = self.upstreams.load();

        // Active-connection guard: decrements gauge + records duration on every return path.
        let mut guard = ConnectionGuard::new();

        // 1. Peek bytes to extract SNI
        let mut peek_buf = vec![0u8; 4096];
        let n = client.peek(&mut peek_buf).await?;
        let sni = extract_sni(&peek_buf[..n]);

        // Record SNI extraction result
        match &sni {
            Some(_) => {
                STREAM_SNI_EXTRACTIONS_TOTAL
                    .with_label_values(&["success"])
                    .inc();
            }
            None => {
                // First byte 0x16 = TLS ClientHello record type — TLS but no SNI extension.
                let result = if peek_buf.first() == Some(&0x16) {
                    "failure"
                } else {
                    "none"
                };
                STREAM_SNI_EXTRACTIONS_TOTAL
                    .with_label_values(&[result])
                    .inc();
            }
        }

        // 2. Route to upstream
        let upstream_name = match router.match_sni(sni.as_deref()) {
            Some(name) => name,
            None => {
                STREAM_CONNECTION_ERRORS_TOTAL
                    .with_label_values(&["routing"])
                    .inc();
                return Err(StreamError::RoutingError("No matching upstream".into()));
            }
        };

        let upstream = upstreams.get(upstream_name).ok_or_else(|| {
            STREAM_CONNECTION_ERRORS_TOTAL
                .with_label_values(&["routing"])
                .inc();
            StreamError::RoutingError(format!("Unknown upstream: {}", upstream_name))
        })?;

        let backend_addr = upstream.next_server();
        let upstream_name = upstream_name.to_owned();

        tracing::debug!(
            client = %client_addr,
            sni = ?sni,
            upstream = %upstream_name,
            backend = %backend_addr,
            "Routing connection"
        );

        // 3. Connect to backend (with optional source IP binding) — timed
        let connect_start = Instant::now();
        let mut backend =
            match tokio::time::timeout(self.connect_timeout, self.connect_backend(&backend_addr))
                .await
            {
                Ok(Ok(b)) => {
                    upstream.report_success(&backend_addr);
                    b
                }
                Ok(Err(e)) => {
                    upstream.report_failure(&backend_addr);
                    STREAM_CONNECTION_ERRORS_TOTAL
                        .with_label_values(&["connect"])
                        .inc();
                    return Err(e);
                }
                Err(_elapsed) => {
                    upstream.report_failure(&backend_addr);
                    STREAM_CONNECTION_ERRORS_TOTAL
                        .with_label_values(&["connect_timeout"])
                        .inc();
                    return Err(StreamError::Io(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        format!(
                            "{} backend '{}' connect timed out after {}ms",
                            backend_addr.transport(),
                            backend_addr,
                            self.connect_timeout.as_millis()
                        ),
                    )));
                }
            };
        STREAM_CONNECT_DURATION_SECONDS
            .with_label_values(&[&upstream_name])
            .observe(connect_start.elapsed().as_secs_f64());

        // Connection is established — record it and arm the duration guard.
        STREAM_CONNECTIONS_TOTAL
            .with_label_values(&[&upstream_name])
            .inc();
        guard.set_upstream(upstream_name.clone());

        // 4. Send proxy protocol header if configured
        if let Some(version) = self.proxy_protocol {
            let header = ProxyProtocolEncoder::encode(version, client_addr, self.local_addr);
            backend.write_all(&header).await?;
        }

        // 5. Bidirectional copy (with optional eBPF sockmap acceleration)
        #[cfg(all(target_os = "linux", feature = "ebpf"))]
        if let Some(ref sockmap) = self.sockmap {
            use std::os::fd::AsRawFd;
            let BackendConnection::Tcp(ref backend_tcp) = backend else {
                STREAM_PROXY_PATH_TOTAL
                    .with_label_values(&["userspace"])
                    .inc();
                return copy_userspace(&mut client, &mut backend).await;
            };
            let client_fd = client.as_raw_fd();
            let backend_fd = backend_tcp.as_raw_fd();

            // Try to register for kernel-level proxying
            let registered = sockmap
                .lock()
                .ok()
                .and_then(|mut sm| sm.register_pair(client_fd, backend_fd).ok())
                .is_some();

            if registered {
                tracing::debug!(
                    client = %client_addr,
                    "Using eBPF sockmap for kernel-level proxying"
                );
                STREAM_PROXY_PATH_TOTAL.with_label_values(&["ebpf"]).inc();

                // Kernel handles data transfer - just wait for either side to close.
                // Bytes are not measurable in this path (kernel does the copy).
                tokio::select! {
                    _ = client.readable() => {}
                    _ = backend_tcp.readable() => {}
                }

                // Unregister on close
                let _ = sockmap
                    .lock()
                    .ok()
                    .map(|mut sm| sm.unregister_pair(client_fd, backend_fd));

                return Ok(());
            }
            // Fall through to user-space proxying if registration failed
            STREAM_PROXY_PATH_TOTAL
                .with_label_values(&["ebpf_fallback"])
                .inc();
        }

        // User-space bidirectional copy (fallback or non-Linux).
        // copy_bidirectional returns (client→backend bytes, backend→client bytes).
        STREAM_PROXY_PATH_TOTAL
            .with_label_values(&["userspace"])
            .inc();
        copy_userspace(&mut client, &mut backend).await
    }

    /// Connect to backend with optional source IP binding.
    async fn connect_backend(
        &self,
        endpoint: &StreamBackendAddr,
    ) -> Result<BackendConnection, StreamError> {
        match endpoint {
            StreamBackendAddr::Tcp(addr) => self
                .connect_tcp_backend(*addr)
                .await
                .map(BackendConnection::Tcp)
                .map_err(|e| {
                    StreamError::ConnectionError(format!(
                        "failed to connect TCP stream backend '{}': {}",
                        endpoint, e
                    ))
                }),
            StreamBackendAddr::Unix(path) => connect_unix_backend(endpoint, path).await,
        }
    }

    async fn connect_tcp_backend(&self, addr: SocketAddr) -> Result<TcpStream, StreamError> {
        if let Some(ref pool) = self.source_ip_pool {
            let source_ip = pool.next_ip();

            // Create socket with source IP binding
            let socket = socket2::Socket::new(
                if addr.is_ipv4() {
                    socket2::Domain::IPV4
                } else {
                    socket2::Domain::IPV6
                },
                socket2::Type::STREAM,
                Some(socket2::Protocol::TCP),
            )?;

            crate::pool::configure_outbound_socket(&socket, source_ip)?;
            socket.set_nonblocking(true)?;

            // Connect (non-blocking)
            // EINPROGRESS indicates connection in progress - this is expected
            #[cfg(target_os = "linux")]
            const EINPROGRESS: i32 = 115;
            #[cfg(target_os = "macos")]
            const EINPROGRESS: i32 = 36;
            #[cfg(not(any(target_os = "linux", target_os = "macos")))]
            const EINPROGRESS: i32 = 115;

            match socket.connect(&addr.into()) {
                Ok(()) => {}
                Err(e) if e.raw_os_error() == Some(EINPROGRESS) => {}
                Err(e) => return Err(e.into()),
            }

            // Convert to tokio stream and wait for connection to complete
            let std_stream: std::net::TcpStream = socket.into();
            let stream = TcpStream::from_std(std_stream)?;
            stream.writable().await?;

            // Check for connection errors
            if let Some(e) = stream.take_error()? {
                return Err(e.into());
            }

            Ok(stream)
        } else {
            Ok(TcpStream::connect(addr).await?)
        }
    }
}

#[cfg(unix)]
async fn connect_unix_backend(
    endpoint: &StreamBackendAddr,
    path: &std::path::Path,
) -> Result<BackendConnection, StreamError> {
    UnixStream::connect(path)
        .await
        .map(BackendConnection::Unix)
        .map_err(|e| {
            StreamError::ConnectionError(format!(
                "failed to connect Unix stream backend '{}': {}",
                endpoint, e
            ))
        })
}

#[cfg(not(unix))]
async fn connect_unix_backend(
    endpoint: &StreamBackendAddr,
    _path: &std::path::Path,
) -> Result<BackendConnection, StreamError> {
    Err(StreamError::ConnectionError(format!(
        "Unix stream backend '{}' is not supported on this platform",
        endpoint
    )))
}

async fn copy_userspace(
    client: &mut TcpStream,
    backend: &mut BackendConnection,
) -> Result<(), StreamError> {
    match tokio::io::copy_bidirectional(client, backend).await {
        Ok((client_to_backend, backend_to_client)) => {
            STREAM_BYTES_TOTAL
                .with_label_values(&["rx"])
                .inc_by(client_to_backend);
            STREAM_BYTES_TOTAL
                .with_label_values(&["tx"])
                .inc_by(backend_to_client);
        }
        Err(e) => {
            STREAM_CONNECTION_ERRORS_TOTAL
                .with_label_values(&["transfer"])
                .inc();
            tracing::debug!(error = %e, "Transfer error");
        }
    }

    Ok(())
}

fn parse_backend_endpoints(servers: &[String]) -> Result<Vec<StreamBackendAddr>, StreamError> {
    servers
        .iter()
        .map(|server| StreamBackendAddr::parse(server))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::path::PathBuf;

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port)
    }

    fn endpoint(port: u16) -> StreamBackendAddr {
        StreamBackendAddr::Tcp(addr(port))
    }

    fn unix_endpoint(name: &str) -> StreamBackendAddr {
        StreamBackendAddr::Unix(PathBuf::from(format!("/run/wicket/{name}.sock")))
    }

    // ============================================================================
    // Upstream Tests
    // ============================================================================

    #[test]
    fn test_upstream_next_server_round_robin() {
        let upstream = Upstream::new("test".into(), vec![endpoint(1), endpoint(2), endpoint(3)]);
        assert_eq!(upstream.next_server(), endpoint(1));
        assert_eq!(upstream.next_server(), endpoint(2));
        assert_eq!(upstream.next_server(), endpoint(3));
    }

    #[test]
    fn test_upstream_next_server_wraps_around() {
        let upstream = Upstream::new("test".into(), vec![endpoint(1), endpoint(2)]);
        assert_eq!(upstream.next_server(), endpoint(1));
        assert_eq!(upstream.next_server(), endpoint(2));
        assert_eq!(upstream.next_server(), endpoint(1)); // wraps
        assert_eq!(upstream.next_server(), endpoint(2));
    }

    #[test]
    fn test_upstream_single_server() {
        let upstream = Upstream::new("test".into(), vec![endpoint(1)]);
        assert_eq!(upstream.next_server(), endpoint(1));
        assert_eq!(upstream.next_server(), endpoint(1));
        assert_eq!(upstream.next_server(), endpoint(1));
    }

    #[test]
    fn test_upstream_many_servers() {
        let servers: Vec<_> = (1..=100).map(endpoint).collect();
        let upstream = Upstream::new("test".into(), servers.clone());

        for (i, expected) in servers.iter().enumerate() {
            assert_eq!(upstream.next_server(), *expected, "iteration {}", i);
        }
        // Wraps around
        assert_eq!(upstream.next_server(), endpoint(1));
    }

    #[test]
    fn test_upstream_concurrent_selection() {
        use std::sync::Arc;
        use std::thread;

        let upstream = Arc::new(Upstream::new(
            "test".into(),
            vec![endpoint(1), endpoint(2), endpoint(3)],
        ));
        let mut handles = vec![];

        for _ in 0..10 {
            let u = Arc::clone(&upstream);
            handles.push(thread::spawn(move || {
                for _ in 0..100 {
                    let _ = u.next_server(); // Should never panic
                }
            }));
        }

        for h in handles {
            h.join().unwrap();
        }
        // If we got here without panic, concurrent access is safe
    }

    // ============================================================================
    // StreamProxy::from_config Tests
    // ============================================================================

    fn test_stream_config() -> wicket_config::StreamConfig {
        wicket_config::StreamConfig {
            listen: "127.0.0.1:0".into(),
            backlog: 128,
            reuseport: false,
            proxy_protocol: wicket_config::ProxyProtocolConfig::None,
            source_ips: vec![],
            default_upstream: Some("default".into()),
            sni_routes: std::collections::HashMap::new(),
            upstreams: vec![wicket_config::StreamUpstreamConfig {
                name: "default".into(),
                servers: vec!["127.0.0.1:8080".into()],
            }],
            health_cooldown_secs: 30,
            connect_timeout_ms: 5000,
            max_connections: 10000,
            drain_timeout_secs: 30,
        }
    }

    #[test]
    fn test_stream_proxy_from_config_valid() {
        let config = test_stream_config();
        let proxy = StreamProxy::from_config(&config);
        assert!(proxy.is_ok());
    }

    #[test]
    fn test_stream_proxy_from_config_invalid_server_address() {
        let mut config = test_stream_config();
        config.upstreams[0].servers = vec!["not-an-address".into()];
        let proxy = StreamProxy::from_config(&config);
        assert!(proxy.is_err());
        assert!(proxy
            .unwrap_err()
            .to_string()
            .contains("invalid TCP stream backend endpoint"));
    }

    #[test]
    fn test_stream_proxy_from_config_invalid_listen_address() {
        let mut config = test_stream_config();
        config.listen = "not-an-address".into();
        let proxy = StreamProxy::from_config(&config);
        assert!(proxy.is_err());
        assert!(proxy
            .unwrap_err()
            .to_string()
            .contains("Invalid listen address"));
    }

    #[test]
    fn test_stream_proxy_from_config_with_source_ips() {
        let mut config = test_stream_config();
        config.source_ips = vec!["127.0.0.2".parse().unwrap(), "127.0.0.3".parse().unwrap()];
        let proxy = StreamProxy::from_config(&config).unwrap();
        assert!(proxy.source_ip_pool.is_some());
    }

    #[test]
    fn test_stream_proxy_reload_updates_router() {
        let mut config = test_stream_config();
        // No default upstream so unmatched SNI returns None
        config.default_upstream = None;
        let proxy = StreamProxy::from_config(&config).unwrap();

        // Initially no route for "new.example.com"
        assert!(
            proxy
                .router
                .load()
                .match_sni(Some("new.example.com"))
                .is_none(),
            "should not match before reload"
        );

        // Add a new SNI route and reload
        config.upstreams.push(wicket_config::StreamUpstreamConfig {
            name: "new".into(),
            servers: vec!["127.0.0.1:9999".into()],
        });
        config
            .sni_routes
            .insert("new.example.com".into(), "new".into());

        proxy.reload(&config).unwrap();

        // After reload, the new route should match
        assert_eq!(
            proxy.router.load().match_sni(Some("new.example.com")),
            Some("new")
        );
    }

    #[test]
    fn test_stream_proxy_from_config_proxy_protocol_v1() {
        let mut config = test_stream_config();
        config.proxy_protocol = wicket_config::ProxyProtocolConfig::V1;
        let proxy = StreamProxy::from_config(&config).unwrap();
        assert_eq!(proxy.proxy_protocol, Some(ProxyProtocolVersion::V1));
    }

    #[test]
    fn test_stream_proxy_from_config_proxy_protocol_v2() {
        let mut config = test_stream_config();
        config.proxy_protocol = wicket_config::ProxyProtocolConfig::V2;
        let proxy = StreamProxy::from_config(&config).unwrap();
        assert_eq!(proxy.proxy_protocol, Some(ProxyProtocolVersion::V2));
    }

    #[test]
    fn test_stream_proxy_from_config_no_proxy_protocol() {
        let config = test_stream_config();
        let proxy = StreamProxy::from_config(&config).unwrap();
        assert_eq!(proxy.proxy_protocol, None);
    }

    #[test]
    fn test_stream_proxy_from_config_multiple_upstreams() {
        let mut config = test_stream_config();
        config.upstreams.push(wicket_config::StreamUpstreamConfig {
            name: "api".into(),
            servers: vec!["127.0.0.1:9090".into()],
        });
        config
            .sni_routes
            .insert("api.example.com".into(), "api".into());

        let proxy = StreamProxy::from_config(&config).unwrap();
        assert_eq!(proxy.upstreams.load().len(), 2);
    }

    #[test]
    fn test_stream_proxy_from_config_stores_local_addr() {
        let mut config = test_stream_config();
        config.listen = "127.0.0.1:9999".into();
        let proxy = StreamProxy::from_config(&config).unwrap();
        assert_eq!(proxy.local_addr.port(), 9999);
    }

    #[test]
    fn test_stream_proxy_from_config_ipv6_address() {
        let mut config = test_stream_config();
        config.listen = "[::1]:8080".into();
        config.upstreams[0].servers = vec!["[::1]:9090".into()];
        let proxy = StreamProxy::from_config(&config);
        assert!(proxy.is_ok());
    }

    #[test]
    fn test_stream_proxy_from_config_multiple_servers_per_upstream() {
        let mut config = test_stream_config();
        config.upstreams[0].servers = vec![
            "127.0.0.1:8080".into(),
            "127.0.0.1:8081".into(),
            "127.0.0.1:8082".into(),
        ];
        let proxy = StreamProxy::from_config(&config).unwrap();
        let upstream = proxy.upstreams.load();
        let upstream = upstream.get("default").unwrap();
        assert_eq!(upstream.servers.len(), 3);
    }

    #[test]
    fn test_stream_proxy_from_config_default_upstream_set() {
        let config = test_stream_config();
        let proxy = StreamProxy::from_config(&config).unwrap();
        // Router should have default upstream configured
        assert!(proxy.router.load().match_sni(None).is_some());
    }

    #[test]
    fn test_stream_proxy_from_config_sni_routing() {
        let mut config = test_stream_config();
        config.upstreams.push(wicket_config::StreamUpstreamConfig {
            name: "secure".into(),
            servers: vec!["127.0.0.1:9443".into()],
        });
        config
            .sni_routes
            .insert("secure.example.com".into(), "secure".into());

        let proxy = StreamProxy::from_config(&config).unwrap();
        let router = proxy.router.load();
        let matched = router.match_sni(Some("secure.example.com"));
        assert_eq!(matched, Some("secure"));
    }

    #[test]
    fn test_stream_proxy_reload_updates_upstreams() {
        let config = test_stream_config();
        let proxy = StreamProxy::from_config(&config).unwrap();

        // Initially only "default" upstream
        assert_eq!(proxy.upstreams.load().len(), 1);
        assert!(proxy.upstreams.load().contains_key("default"));

        // Reload with an additional upstream
        let mut new_config = config;
        new_config
            .upstreams
            .push(wicket_config::StreamUpstreamConfig {
                name: "extra".into(),
                servers: vec!["127.0.0.1:7777".into()],
            });

        proxy.reload(&new_config).unwrap();

        let upstreams = proxy.upstreams.load();
        assert_eq!(upstreams.len(), 2);
        assert!(upstreams.contains_key("default"));
        assert!(upstreams.contains_key("extra"));
    }

    #[test]
    fn test_upstream_name_preserved() {
        let upstream = Upstream::new("my-upstream".into(), vec![endpoint(1), endpoint(2)]);
        assert_eq!(upstream.name, "my-upstream");
    }

    #[test]
    fn test_upstream_servers_preserved() {
        let servers = vec![endpoint(1), endpoint(2), endpoint(3)];
        let upstream = Upstream::new("test".into(), servers.clone());
        assert_eq!(upstream.servers, servers);
    }

    // ============================================================================
    // Health-aware selection tests
    // ============================================================================

    #[test]
    fn test_upstream_skips_unhealthy_backend() {
        let upstream = Upstream::with_cooldown(
            "test".into(),
            vec![endpoint(1), endpoint(2), endpoint(3)],
            Duration::from_secs(3600), // long cooldown
        );
        // Mark addr(1) unhealthy
        upstream.health[0].record_failure();

        // next_server should skip addr(1) and return addr(2) or addr(3)
        let selected = upstream.next_server();
        assert_ne!(selected, endpoint(1), "should skip unhealthy backend");
    }

    #[test]
    fn test_upstream_fail_open_all_unhealthy() {
        let upstream = Upstream::with_cooldown(
            "test".into(),
            vec![endpoint(1), endpoint(2)],
            Duration::from_secs(3600), // long cooldown
        );
        // Mark all unhealthy
        upstream.health[0].record_failure();
        upstream.health[1].record_failure();

        // Should still return a server (fail-open)
        let selected = upstream.next_server();
        assert!(
            selected == endpoint(1) || selected == endpoint(2),
            "fail-open must return a server"
        );
    }

    #[test]
    fn test_upstream_recovery_after_cooldown() {
        let upstream = Upstream::with_cooldown(
            "test".into(),
            vec![endpoint(1)],
            Duration::from_secs(0), // zero cooldown — immediately eligible
        );
        upstream.health[0].record_failure();
        // With zero cooldown, backend is immediately eligible again
        assert!(upstream.health[0].is_eligible(Duration::from_secs(0)));
        let selected = upstream.next_server();
        assert_eq!(selected, endpoint(1));
    }

    #[test]
    fn test_report_success_recovers_backend() {
        let upstream = Upstream::new("test".into(), vec![endpoint(1)]);
        upstream.health[0].record_failure();
        assert!(!upstream.health[0].is_healthy());

        upstream.report_success(&endpoint(1));
        assert!(upstream.health[0].is_healthy());
        assert_eq!(upstream.health[0].consecutive_failures(), 0);
    }

    #[test]
    fn test_report_failure_marks_unhealthy() {
        let upstream = Upstream::new("test".into(), vec![endpoint(1)]);
        assert!(upstream.health[0].is_healthy());

        upstream.report_failure(&endpoint(1));
        assert!(!upstream.health[0].is_healthy());
        assert_eq!(upstream.health[0].consecutive_failures(), 1);
    }

    #[test]
    fn test_unix_endpoint_health_tracking() {
        let endpoint = unix_endpoint("backend");
        let upstream = Upstream::new("test".into(), vec![endpoint.clone()]);

        assert_eq!(upstream.next_server(), endpoint);

        upstream.report_failure(&unix_endpoint("backend"));
        assert!(!upstream.health[0].is_healthy());
        assert_eq!(upstream.health[0].label(), "unix:/run/wicket/backend.sock");

        upstream.report_success(&unix_endpoint("backend"));
        assert!(upstream.health[0].is_healthy());
    }

    #[test]
    fn test_report_unknown_addr_is_noop() {
        let upstream = Upstream::new("test".into(), vec![endpoint(1)]);
        // Reporting for an address not in the upstream should not panic
        upstream.report_success(&endpoint(9999));
        upstream.report_failure(&endpoint(9999));
        // addr(1) health unchanged
        assert!(upstream.health[0].is_healthy());
    }

    #[test]
    fn test_upstream_with_cooldown_constructor() {
        let upstream = Upstream::with_cooldown(
            "test".into(),
            vec![endpoint(1), endpoint(2)],
            Duration::from_secs(60),
        );
        assert_eq!(upstream.servers.len(), 2);
        assert_eq!(upstream.health.len(), 2);
        assert_eq!(upstream.cooldown, Duration::from_secs(60));
    }

    // ============================================================================
    // Connect timeout tests (bd-2f4)
    // ============================================================================

    #[test]
    fn test_stream_proxy_from_config_connect_timeout() {
        let mut config = test_stream_config();
        config.connect_timeout_ms = 3000;
        let proxy = StreamProxy::from_config(&config).unwrap();
        assert_eq!(proxy.connect_timeout, Duration::from_millis(3000));
    }

    #[test]
    fn test_stream_proxy_from_config_connect_timeout_default() {
        let config = test_stream_config();
        let proxy = StreamProxy::from_config(&config).unwrap();
        assert_eq!(proxy.connect_timeout, Duration::from_millis(5000));
    }

    // ============================================================================
    // Connection limit tests (bd-tpd)
    // ============================================================================

    #[test]
    fn test_stream_proxy_from_config_connection_limit() {
        let mut config = test_stream_config();
        config.max_connections = 500;
        let proxy = StreamProxy::from_config(&config).unwrap();
        assert!(proxy.connection_semaphore.is_some());
        let sem = proxy.connection_semaphore.unwrap();
        assert_eq!(sem.available_permits(), 500);
    }

    #[test]
    fn test_stream_proxy_from_config_unlimited_connections() {
        let mut config = test_stream_config();
        config.max_connections = 0;
        let proxy = StreamProxy::from_config(&config).unwrap();
        assert!(proxy.connection_semaphore.is_none());
    }

    #[test]
    fn test_stream_proxy_from_config_default_connection_limit() {
        let config = test_stream_config();
        let proxy = StreamProxy::from_config(&config).unwrap();
        assert!(proxy.connection_semaphore.is_some());
        let sem = proxy.connection_semaphore.unwrap();
        assert_eq!(sem.available_permits(), 10000);
    }
}
