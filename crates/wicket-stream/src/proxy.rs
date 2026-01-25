//! TCP stream proxy implementation.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

use crate::pool::SourceIpPool;
use crate::protocol::{ProxyProtocolEncoder, ProxyProtocolVersion};
use crate::router::SniRouter;
use crate::sni::extract_sni;
use crate::StreamError;

#[cfg(all(target_os = "linux", feature = "ebpf"))]
use std::sync::Mutex;

#[cfg(all(target_os = "linux", feature = "ebpf"))]
use volt_sockmap::SocketMap;

/// Upstream server configuration.
#[derive(Debug)]
pub struct Upstream {
    pub name: String,
    pub servers: Vec<SocketAddr>,
    counter: AtomicUsize,
}

impl Upstream {
    /// Create a new upstream with the given name and servers.
    pub fn new(name: String, servers: Vec<SocketAddr>) -> Self {
        Self {
            name,
            servers,
            counter: AtomicUsize::new(0),
        }
    }

    /// Get next server using round-robin selection.
    pub fn next_server(&self) -> SocketAddr {
        let idx = self.counter.fetch_add(1, Ordering::Relaxed) % self.servers.len();
        self.servers[idx]
    }
}

/// Main L4 stream proxy.
#[derive(Debug)]
pub struct StreamProxy {
    pub(crate) router: SniRouter,
    pub(crate) upstreams: HashMap<String, Arc<Upstream>>,
    pub(crate) source_ip_pool: Option<SourceIpPool>,
    pub(crate) proxy_protocol: Option<ProxyProtocolVersion>,
    pub(crate) local_addr: SocketAddr,
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
    ) -> Self {
        Self {
            router,
            upstreams,
            source_ip_pool,
            proxy_protocol,
            local_addr,
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

        // Build upstreams
        let mut upstreams = HashMap::new();
        for upstream_config in &config.upstreams {
            let servers: Vec<SocketAddr> = upstream_config
                .servers
                .iter()
                .map(|s| s.parse())
                .collect::<Result<_, _>>()
                .map_err(|e| StreamError::ConfigError(format!("Invalid server address: {}", e)))?;

            upstreams.insert(
                upstream_config.name.clone(),
                Arc::new(Upstream::new(upstream_config.name.clone(), servers)),
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

        Ok(Self {
            router,
            upstreams,
            source_ip_pool,
            proxy_protocol,
            local_addr,
            #[cfg(all(target_os = "linux", feature = "ebpf"))]
            sockmap: None,
        })
    }

    /// Run the proxy server.
    pub async fn run(self: Arc<Self>, listener: TcpListener) -> Result<(), StreamError> {
        loop {
            let (client_stream, client_addr) = listener.accept().await?;
            let proxy = Arc::clone(&self);

            tokio::spawn(async move {
                if let Err(e) = proxy.handle_connection(client_stream, client_addr).await {
                    tracing::warn!(client = %client_addr, error = %e, "Connection failed");
                }
            });
        }
    }

    /// Handle a single client connection.
    async fn handle_connection(
        &self,
        client: TcpStream,
        client_addr: SocketAddr,
    ) -> Result<(), StreamError> {
        // 1. Peek bytes to extract SNI
        let mut peek_buf = vec![0u8; 4096];
        let n = client.peek(&mut peek_buf).await?;
        let sni = extract_sni(&peek_buf[..n]);

        // 2. Route to upstream
        let upstream_name = self
            .router
            .match_sni(sni.as_deref())
            .ok_or_else(|| StreamError::RoutingError("No matching upstream".into()))?;

        let upstream = self.upstreams.get(upstream_name).ok_or_else(|| {
            StreamError::RoutingError(format!("Unknown upstream: {}", upstream_name))
        })?;

        let backend_addr = upstream.next_server();

        tracing::debug!(
            client = %client_addr,
            sni = ?sni,
            upstream = upstream_name,
            backend = %backend_addr,
            "Routing connection"
        );

        // 3. Connect to backend (with optional source IP binding)
        let mut backend = self.connect_backend(backend_addr).await?;

        // 4. Send proxy protocol header if configured
        if let Some(version) = self.proxy_protocol {
            let header = ProxyProtocolEncoder::encode(version, client_addr, self.local_addr);
            backend.write_all(&header).await?;
        }

        // 5. Bidirectional copy (with optional eBPF sockmap acceleration)
        #[cfg(all(target_os = "linux", feature = "ebpf"))]
        if let Some(ref sockmap) = self.sockmap {
            use std::os::fd::AsRawFd;
            let client_fd = client.as_raw_fd();
            let backend_fd = backend.as_raw_fd();

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

                // Kernel handles data transfer - just wait for either side to close
                tokio::select! {
                    _ = client.readable() => {}
                    _ = backend.readable() => {}
                }

                // Unregister on close
                let _ = sockmap
                    .lock()
                    .ok()
                    .map(|mut sm| sm.unregister_pair(client_fd, backend_fd));

                return Ok(());
            }
            // Fall through to user-space proxying if registration failed
        }

        // User-space bidirectional copy (fallback or non-Linux)
        let (mut client_read, mut client_write) = client.into_split();
        let (mut backend_read, mut backend_write) = backend.into_split();

        let client_to_backend = tokio::io::copy(&mut client_read, &mut backend_write);
        let backend_to_client = tokio::io::copy(&mut backend_read, &mut client_write);

        tokio::select! {
            result = client_to_backend => {
                if let Err(e) = result {
                    tracing::debug!(error = %e, "Client to backend copy ended");
                }
            }
            result = backend_to_client => {
                if let Err(e) = result {
                    tracing::debug!(error = %e, "Backend to client copy ended");
                }
            }
        }

        Ok(())
    }

    /// Connect to backend with optional source IP binding.
    async fn connect_backend(&self, addr: SocketAddr) -> Result<TcpStream, StreamError> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port)
    }

    // ============================================================================
    // Upstream Tests
    // ============================================================================

    #[test]
    fn test_upstream_next_server_round_robin() {
        let upstream = Upstream::new("test".into(), vec![addr(1), addr(2), addr(3)]);
        assert_eq!(upstream.next_server(), addr(1));
        assert_eq!(upstream.next_server(), addr(2));
        assert_eq!(upstream.next_server(), addr(3));
    }

    #[test]
    fn test_upstream_next_server_wraps_around() {
        let upstream = Upstream::new("test".into(), vec![addr(1), addr(2)]);
        assert_eq!(upstream.next_server(), addr(1));
        assert_eq!(upstream.next_server(), addr(2));
        assert_eq!(upstream.next_server(), addr(1)); // wraps
        assert_eq!(upstream.next_server(), addr(2));
    }

    #[test]
    fn test_upstream_single_server() {
        let upstream = Upstream::new("test".into(), vec![addr(1)]);
        assert_eq!(upstream.next_server(), addr(1));
        assert_eq!(upstream.next_server(), addr(1));
        assert_eq!(upstream.next_server(), addr(1));
    }

    #[test]
    fn test_upstream_many_servers() {
        let servers: Vec<_> = (1..=100).map(|p| addr(p)).collect();
        let upstream = Upstream::new("test".into(), servers.clone());

        for (i, expected) in servers.iter().enumerate() {
            assert_eq!(upstream.next_server(), *expected, "iteration {}", i);
        }
        // Wraps around
        assert_eq!(upstream.next_server(), addr(1));
    }

    #[test]
    fn test_upstream_concurrent_selection() {
        use std::sync::Arc;
        use std::thread;

        let upstream = Arc::new(Upstream::new(
            "test".into(),
            vec![addr(1), addr(2), addr(3)],
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
            .contains("Invalid server address"));
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
    fn test_stream_proxy_from_config_without_source_ips() {
        let config = test_stream_config();
        let proxy = StreamProxy::from_config(&config).unwrap();
        assert!(proxy.source_ip_pool.is_none());
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
        assert_eq!(proxy.upstreams.len(), 2);
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
        let upstream = proxy.upstreams.get("default").unwrap();
        assert_eq!(upstream.servers.len(), 3);
    }

    #[test]
    fn test_stream_proxy_from_config_default_upstream_set() {
        let config = test_stream_config();
        let proxy = StreamProxy::from_config(&config).unwrap();
        // Router should have default upstream configured
        assert!(proxy.router.match_sni(None).is_some());
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
        let matched = proxy.router.match_sni(Some("secure.example.com"));
        assert_eq!(matched, Some("secure"));
    }

    #[test]
    fn test_upstream_name_preserved() {
        let upstream = Upstream::new("my-upstream".into(), vec![addr(1), addr(2)]);
        assert_eq!(upstream.name, "my-upstream");
    }

    #[test]
    fn test_upstream_servers_preserved() {
        let servers = vec![addr(1), addr(2), addr(3)];
        let upstream = Upstream::new("test".into(), servers.clone());
        assert_eq!(upstream.servers, servers);
    }
}
