//! Pingora-based proxy service for Wicket.
//!
//! This module implements the core proxy functionality using Pingora's HttpProxy trait.

use crate::metrics::{
    BYTES_RECEIVED_TOTAL, BYTES_SENT_TOTAL, CLIENT_CONNECTIONS_ACTIVE, CLIENT_CONNECTIONS_TOTAL,
    HTTP_ERRORS_TOTAL, HTTP_REQUESTS_ACTIVE, HTTP_REQUESTS_TOTAL, HTTP_REQUEST_DURATION_SECONDS,
    ROUTE_NOT_FOUND_TOTAL, UPSTREAM_CONNECTIONS_ACTIVE, UPSTREAM_DURATION_SECONDS,
    UPSTREAM_ERRORS_TOTAL,
};
use crate::routing::{RouteMatch, Router};
use anyhow::Result;
use arc_swap::ArcSwap;
use async_trait::async_trait;
use pingora_core::prelude::*;
use pingora_core::upstreams::peer::{HttpPeer, Peer};
use pingora_core::Result as PingoraResult;
use pingora_load_balancing::selection::consistent::KetamaHashing;
use pingora_load_balancing::selection::RoundRobin;
use pingora_load_balancing::{health_check::TcpHealthCheck, LoadBalancer};
use pingora_http::RequestHeader;
use pingora_proxy::{ProxyHttp, Session};
use rand::Rng;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error, info, warn};
use wicket_config::{Config, LoadBalanceStrategy, UpstreamConfig};
use wicket_tls::CertManager;

#[cfg(all(target_os = "linux", feature = "ebpf"))]
use std::os::unix::io::RawFd;

#[cfg(all(target_os = "linux", feature = "ebpf"))]
use std::sync::Mutex;

#[cfg(all(target_os = "linux", feature = "ebpf"))]
use wicket_sockmap::SocketMap;

/// Per-request context for the Wicket proxy.
///
/// This struct carries request-specific information through the entire request lifecycle,
/// from initial routing to final logging. It is created fresh for each request and
/// populated during the `request_filter` phase.
pub struct WicketCtx {
    /// The matched route information, populated after routing succeeds.
    ///
    /// Contains the upstream name and optional route name that matched this request.
    /// `None` if no route matched the request.
    pub route_match: Option<RouteMatch>,

    /// Start time for request duration tracking.
    ///
    /// Captured at the beginning of request processing and used to calculate
    /// the total request duration for logging.
    pub start_time: std::time::Instant,

    /// Unique identifier for this request, used in logging and tracing.
    ///
    /// Generated as a hex-encoded nanosecond timestamp, ensuring uniqueness
    /// across requests for correlation in logs and distributed tracing.
    pub request_id: String,

    /// HTTP method for this request (cached for metrics).
    pub method: String,

    /// Start time when we connected to upstream (for upstream duration metric).
    pub upstream_connect_time: Option<std::time::Instant>,

    /// Whether we've already decremented the active request counter.
    /// Prevents double-decrement on error paths.
    pub metrics_recorded: bool,

    /// Whether eBPF sockmap is registered for this connection.
    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    pub ebpf_registered: bool,

    /// Client socket FD (for sockmap unregistration).
    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    pub client_fd: Option<RawFd>,

    /// Upstream socket FD (for sockmap unregistration).
    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    pub upstream_fd: Option<RawFd>,
}

/// The main Wicket proxy service.
pub struct WicketProxy {
    /// Router for matching requests to upstreams
    router: Arc<ArcSwap<Router>>,

    /// Map of upstream name to load balancer
    upstreams: Arc<ArcSwap<HashMap<String, Arc<UpstreamCluster>>>>,

    /// TLS certificate manager (if TLS is enabled)
    cert_manager: Option<Arc<CertManager>>,

    /// eBPF sockmap for kernel-level proxying (Linux only)
    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    sockmap: Option<Arc<Mutex<SocketMap>>>,
}

/// Handle for reloading HTTP proxy configuration at runtime.
///
/// This is obtained via [`WicketProxy::reload_handle`] before the proxy is
/// consumed by the Pingora service.  The handle shares the same `ArcSwap`
/// instances, so stores are immediately visible to in-flight request handling.
#[derive(Clone)]
pub struct HttpReloadHandle {
    router: Arc<ArcSwap<Router>>,
    upstreams: Arc<ArcSwap<HashMap<String, Arc<UpstreamCluster>>>>,
}

impl HttpReloadHandle {
    /// Reload HTTP proxy routes and upstreams from a new config.
    pub fn reload(&self, config: &Config) -> Result<()> {
        let router = Router::build(&config.routes)?;
        let upstreams = WicketProxy::build_upstreams(&config.upstreams)?;

        self.router.store(Arc::new(router));
        self.upstreams.store(Arc::new(upstreams));

        info!("HTTP proxy configuration reloaded");
        Ok(())
    }
}

/// An upstream cluster with load balancing and health checking.
///
/// Wraps one or more backend servers and provides peer selection based on the
/// configured load balancing strategy. Only one load balancer is active at a time,
/// determined by the `strategy` field.
pub struct UpstreamCluster {
    /// Round-robin load balancer for backend selection.
    ///
    /// Active when `strategy` is `LoadBalanceStrategy::RoundRobin`.
    /// Distributes requests evenly across healthy backends in rotation.
    /// `None` if using a different strategy.
    lb_round_robin: Option<Arc<LoadBalancer<RoundRobin>>>,

    /// Consistent hashing (Ketama) load balancer for backend selection.
    ///
    /// Active when `strategy` is `LoadBalanceStrategy::ConsistentHash`.
    /// Routes requests to the same backend based on a hash key (typically the request path).
    /// `None` if using a different strategy.
    lb_ketama: Option<Arc<LoadBalancer<KetamaHashing>>>,

    /// Load balancing strategy being used by this cluster.
    ///
    /// Determines which load balancer (`lb_round_robin` or `lb_ketama`) is active
    /// and how peer selection is performed.
    strategy: LoadBalanceStrategy,
}

impl WicketProxy {
    /// Create a new WicketProxy from configuration.
    pub fn new(config: &Config) -> Result<Self> {
        let router = Router::build(&config.routes)?;
        let upstreams = Self::build_upstreams(&config.upstreams)?;

        Ok(WicketProxy {
            router: Arc::new(ArcSwap::new(Arc::new(router))),
            upstreams: Arc::new(ArcSwap::new(Arc::new(upstreams))),
            cert_manager: None,
            #[cfg(all(target_os = "linux", feature = "ebpf"))]
            sockmap: None,
        })
    }

    /// Obtain a reload handle that can update routes and upstreams at runtime.
    ///
    /// Call this *before* the proxy is moved into `http_proxy_service`.
    pub fn reload_handle(&self) -> HttpReloadHandle {
        HttpReloadHandle {
            router: Arc::clone(&self.router),
            upstreams: Arc::clone(&self.upstreams),
        }
    }

    /// Set the TLS certificate manager.
    pub fn with_cert_manager(mut self, manager: Arc<CertManager>) -> Self {
        self.cert_manager = Some(manager);
        self
    }

    /// Set the eBPF sockmap for kernel-level proxying.
    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    pub fn with_sockmap(mut self, sockmap: SocketMap) -> Self {
        self.sockmap = Some(Arc::new(Mutex::new(sockmap)));
        self
    }

    /// Get the certificate manager if TLS is enabled.
    pub fn cert_manager(&self) -> Option<&Arc<CertManager>> {
        self.cert_manager.as_ref()
    }

    /// Build upstream load balancers from configuration.
    fn build_upstreams(
        configs: &HashMap<String, UpstreamConfig>,
    ) -> Result<HashMap<String, Arc<UpstreamCluster>>> {
        let mut upstreams = HashMap::new();

        for (name, config) in configs {
            let cluster = UpstreamCluster::new(config)?;
            info!(
                upstream = %name,
                backends = config.backends.len(),
                strategy = ?config.strategy,
                "Configured upstream"
            );
            upstreams.insert(name.clone(), Arc::new(cluster));
        }

        Ok(upstreams)
    }

    /// Reload configuration at runtime.
    pub fn reload(&self, config: &Config) -> Result<()> {
        let router = Router::build(&config.routes)?;
        let upstreams = Self::build_upstreams(&config.upstreams)?;

        self.router.store(Arc::new(router));
        self.upstreams.store(Arc::new(upstreams));

        info!("Configuration reloaded");
        Ok(())
    }

    /// Get an upstream peer for the given upstream name.
    fn get_peer(&self, upstream_name: &str, key: &[u8]) -> Option<HttpPeer> {
        let upstreams = self.upstreams.load();
        let cluster = upstreams.get(upstream_name)?;
        cluster.select_peer(key)
    }
}

impl UpstreamCluster {
    /// Create a new upstream cluster from configuration.
    fn new(config: &UpstreamConfig) -> Result<Self> {
        // Parse backend addresses
        let backends: Vec<_> = config
            .backends
            .iter()
            .map(|b| {
                // Parse address, handling potential scheme prefix
                let addr = b
                    .strip_prefix("http://")
                    .or_else(|| b.strip_prefix("https://"))
                    .unwrap_or(b);
                addr.to_string()
            })
            .collect();

        let backend_refs: Vec<&str> = backends.iter().map(|s| s.as_str()).collect();

        match config.strategy {
            LoadBalanceStrategy::RoundRobin => {
                let mut lb = LoadBalancer::try_from_iter(backend_refs)?;

                // Configure health check if specified
                if let Some(ref hc_config) = config.health_check {
                    let hc = TcpHealthCheck::new();
                    lb.set_health_check(hc);
                    lb.health_check_frequency = Some(Duration::from_secs(hc_config.interval));
                }

                Ok(UpstreamCluster {
                    lb_round_robin: Some(Arc::new(lb)),
                    lb_ketama: None,
                    strategy: LoadBalanceStrategy::RoundRobin,
                })
            }
            LoadBalanceStrategy::ConsistentHash => {
                let lb = LoadBalancer::<KetamaHashing>::try_from_iter(backend_refs)?;

                Ok(UpstreamCluster {
                    lb_round_robin: None,
                    lb_ketama: Some(Arc::new(lb)),
                    strategy: LoadBalanceStrategy::ConsistentHash,
                })
            }
        }
    }

    /// Select a peer from this upstream cluster.
    fn select_peer(&self, key: &[u8]) -> Option<HttpPeer> {
        match self.strategy {
            LoadBalanceStrategy::RoundRobin => {
                let lb = self.lb_round_robin.as_ref()?;
                let backend = lb.select(key, 256)?;
                Some(HttpPeer::new(backend.addr, false, String::new()))
            }
            LoadBalanceStrategy::ConsistentHash => {
                let lb = self.lb_ketama.as_ref()?;
                let backend = lb.select(key, 256)?;
                Some(HttpPeer::new(backend.addr, false, String::new()))
            }
        }
    }
}

#[async_trait]
impl ProxyHttp for WicketProxy {
    type CTX = WicketCtx;

    fn new_ctx(&self) -> Self::CTX {
        // Increment active connection counter
        // Note: "default" listener since we don't have listener info here
        CLIENT_CONNECTIONS_ACTIVE
            .with_label_values(&["default"])
            .inc();
        CLIENT_CONNECTIONS_TOTAL
            .with_label_values(&["default"])
            .inc();

        WicketCtx {
            route_match: None,
            start_time: std::time::Instant::now(),
            request_id: generate_request_id(),
            method: String::new(),
            upstream_connect_time: None,
            metrics_recorded: false,
            #[cfg(all(target_os = "linux", feature = "ebpf"))]
            ebpf_registered: false,
            #[cfg(all(target_os = "linux", feature = "ebpf"))]
            client_fd: None,
            #[cfg(all(target_os = "linux", feature = "ebpf"))]
            upstream_fd: None,
        }
    }

    async fn request_filter(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> PingoraResult<bool>
    where
        Self::CTX: Send + Sync,
    {
        let req_header = session.req_header();

        // Propagate incoming X-Request-Id if present, otherwise keep generated one
        if let Some(incoming_id) = req_header
            .headers
            .get("x-request-id")
            .and_then(|v| v.to_str().ok())
        {
            ctx.request_id = incoming_id.to_string();
        }

        // Extract request properties
        let host = req_header.headers.get("host").and_then(|v| v.to_str().ok());

        let path = req_header.uri.path();
        let method = req_header.method.as_str();

        // Store method for metrics
        ctx.method = method.to_string();

        // Match route
        let router = self.router.load();

        // Lazily build headers map only if any route requires header matching
        let headers = if router.has_header_matchers() {
            req_header
                .headers
                .iter()
                .filter_map(|(k, v)| {
                    v.to_str()
                        .ok()
                        .map(|v| (k.as_str().to_lowercase(), v.to_string()))
                })
                .collect()
        } else {
            HashMap::new()
        };

        let route_match = router.match_request(host, path, method, &headers);

        if let Some(ref rm) = route_match {
            // Increment active requests for this route
            let route_label = rm.route_name.as_deref().unwrap_or(&rm.upstream);
            HTTP_REQUESTS_ACTIVE.with_label_values(&[route_label]).inc();

            debug!(
                request_id = %ctx.request_id,
                route = ?rm.route_name,
                upstream = %rm.upstream,
                method = %method,
                path = %path,
                host = ?host,
                "Request matched route"
            );
        } else {
            // Track route not found
            ROUTE_NOT_FOUND_TOTAL.inc();

            warn!(
                request_id = %ctx.request_id,
                method = %method,
                path = %path,
                host = ?host,
                "No matching route found"
            );
        }

        ctx.route_match = route_match;

        // Return false to continue processing (true would mean we handled it ourselves)
        Ok(false)
    }

    async fn upstream_peer(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> PingoraResult<Box<HttpPeer>> {
        let route_match = ctx.route_match.as_ref().ok_or_else(|| {
            warn!(
                request_id = %ctx.request_id,
                path = %session.req_header().uri.path(),
                "No matching route found"
            );
            Error::new(ErrorType::HTTPStatus(404))
        })?;

        // Use request URI as hash key for consistent hashing
        let key = session.req_header().uri.path().as_bytes();

        let peer = self.get_peer(&route_match.upstream, key).ok_or_else(|| {
            // Track upstream error
            UPSTREAM_ERRORS_TOTAL
                .with_label_values(&[&route_match.upstream, "no_healthy_backends"])
                .inc();

            error!(
                upstream = %route_match.upstream,
                "No healthy backends available"
            );
            Error::new(ErrorType::HTTPStatus(503))
        })?;

        // Track upstream connection and start timing
        UPSTREAM_CONNECTIONS_ACTIVE
            .with_label_values(&[&route_match.upstream])
            .inc();
        ctx.upstream_connect_time = Some(std::time::Instant::now());

        debug!(
            request_id = %ctx.request_id,
            peer = ?peer.address(),
            "Selected upstream peer"
        );

        Ok(Box::new(peer))
    }

    async fn upstream_request_filter(
        &self,
        session: &mut Session,
        upstream_request: &mut RequestHeader,
        ctx: &mut Self::CTX,
    ) -> PingoraResult<()>
    where
        Self::CTX: Send + Sync,
    {
        // Inject X-Request-Id header to upstream
        upstream_request
            .insert_header("x-request-id", &ctx.request_id)
            .map_err(|e| {
                warn!(
                    request_id = %ctx.request_id,
                    error = %e,
                    "Failed to insert X-Request-Id header"
                );
                Error::new(ErrorType::InternalError)
            })?;

        // Append client IP to X-Forwarded-For header.
        // If an upstream proxy (e.g. Cloudflare, WAF) already set X-Forwarded-For,
        // append the connecting address; otherwise create a new header.
        if let Some(inet_addr) = session.client_addr().and_then(|a| a.as_inet()) {
            let client_ip = inet_addr.ip().to_string();

            let xff_value = if let Some(existing) = upstream_request.headers.get("x-forwarded-for") {
                format!("{}, {}", existing.to_str().unwrap_or(""), client_ip)
            } else {
                client_ip
            };

            upstream_request
                .insert_header("x-forwarded-for", &xff_value)
                .map_err(|e| {
                    warn!(
                        request_id = %ctx.request_id,
                        error = %e,
                        "Failed to insert X-Forwarded-For header"
                    );
                    Error::new(ErrorType::InternalError)
                })?;
        }

        Ok(())
    }

    /// Called after successfully connecting to upstream.
    /// Register socket pair with eBPF sockmap for kernel-level proxying.
    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    async fn connected_to_upstream(
        &self,
        session: &mut Session,
        _reused: bool,
        _peer: &HttpPeer,
        upstream_fd: std::os::unix::io::RawFd,
        _digest: Option<&pingora_core::protocols::Digest>,
        ctx: &mut Self::CTX,
    ) -> PingoraResult<()> {
        use std::os::unix::io::AsRawFd;

        if let Some(ref sockmap) = self.sockmap {
            // Get client FD from downstream session (only works for HTTP/1.1)
            if let Some(stream) = session.as_downstream().stream() {
                let client_fd = stream.as_raw_fd();

                if let Ok(mut sm) = sockmap.lock() {
                    if sm.register_pair(client_fd, upstream_fd).is_ok() {
                        ctx.ebpf_registered = true;
                        ctx.client_fd = Some(client_fd);
                        ctx.upstream_fd = Some(upstream_fd);
                        debug!(
                            request_id = %ctx.request_id,
                            "eBPF sockmap registered for kernel-level proxying"
                        );
                    }
                }
            }
        }
        Ok(())
    }

    async fn logging(&self, session: &mut Session, error: Option<&Error>, ctx: &mut Self::CTX)
    where
        Self::CTX: Send + Sync,
    {
        // Unregister eBPF sockmap if registered
        #[cfg(all(target_os = "linux", feature = "ebpf"))]
        if ctx.ebpf_registered {
            if let (Some(client_fd), Some(upstream_fd)) = (ctx.client_fd, ctx.upstream_fd) {
                if let Some(ref sockmap) = self.sockmap {
                    if let Ok(mut sm) = sockmap.lock() {
                        let _ = sm.unregister_pair(client_fd, upstream_fd);
                    }
                }
            }
        }

        // Prevent double recording
        if ctx.metrics_recorded {
            return;
        }
        ctx.metrics_recorded = true;

        let duration = ctx.start_time.elapsed();
        let duration_secs = duration.as_secs_f64();
        let req_header = session.req_header();

        let status = session
            .response_written()
            .map(|r| r.status.as_u16())
            .unwrap_or(0);

        let method = if ctx.method.is_empty() {
            req_header.method.as_str()
        } else {
            &ctx.method
        };
        let path = req_header.uri.path();
        let host = req_header
            .headers
            .get("host")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("-");

        let route_label = ctx
            .route_match
            .as_ref()
            .and_then(|r| r.route_name.as_deref())
            .or_else(|| ctx.route_match.as_ref().map(|r| r.upstream.as_str()))
            .unwrap_or("unknown");

        let upstream = ctx
            .route_match
            .as_ref()
            .map(|r| r.upstream.as_str())
            .unwrap_or("unknown");

        let status_str = status.to_string();

        // Record request total
        HTTP_REQUESTS_TOTAL
            .with_label_values(&[method, route_label, &status_str])
            .inc();

        // Record request duration
        HTTP_REQUEST_DURATION_SECONDS
            .with_label_values(&[method, route_label])
            .observe(duration_secs);

        // Decrement active requests
        if ctx.route_match.is_some() {
            HTTP_REQUESTS_ACTIVE.with_label_values(&[route_label]).dec();
        }

        // Record upstream duration if we connected
        if let Some(upstream_start) = ctx.upstream_connect_time {
            let upstream_duration = upstream_start.elapsed().as_secs_f64();
            UPSTREAM_DURATION_SECONDS
                .with_label_values(&[upstream])
                .observe(upstream_duration);

            // Decrement upstream connection counter
            UPSTREAM_CONNECTIONS_ACTIVE
                .with_label_values(&[upstream])
                .dec();
        }

        // Record errors (4xx, 5xx)
        if status >= 400 {
            let error_type = if status >= 500 {
                "server_error"
            } else {
                "client_error"
            };
            HTTP_ERRORS_TOTAL
                .with_label_values(&[method, route_label, &status_str, error_type])
                .inc();
        }

        // Record upstream errors if there was an error connecting
        if let Some(e) = error {
            let error_type = match e.etype() {
                ErrorType::ConnectTimedout => "connect_timeout",
                ErrorType::ReadTimedout => "read_timeout",
                ErrorType::WriteTimedout => "write_timeout",
                ErrorType::ConnectRefused => "connect_refused",
                ErrorType::ConnectionClosed => "connection_closed",
                _ => "other",
            };
            UPSTREAM_ERRORS_TOTAL
                .with_label_values(&[upstream, error_type])
                .inc();
        }

        // Record bytes (approximate from content-length headers if available)
        // Note: For accurate byte counting, we'd need to track actual bytes in
        // upstream_request_filter and upstream_response_filter
        if let Some(resp) = session.response_written() {
            if let Some(cl) = resp.headers.get("content-length") {
                if let Ok(bytes) = cl.to_str().unwrap_or("0").parse::<u64>() {
                    BYTES_SENT_TOTAL
                        .with_label_values(&[route_label])
                        .inc_by(bytes);
                }
            }
        }
        if let Some(cl) = req_header.headers.get("content-length") {
            if let Ok(bytes) = cl.to_str().unwrap_or("0").parse::<u64>() {
                BYTES_RECEIVED_TOTAL
                    .with_label_values(&[route_label])
                    .inc_by(bytes);
            }
        }

        // Decrement connection counter
        CLIENT_CONNECTIONS_ACTIVE
            .with_label_values(&["default"])
            .dec();

        info!(
            request_id = %ctx.request_id,
            method = %method,
            path = %path,
            host = %host,
            status = status,
            duration_ms = duration.as_millis() as u64,
            route = %route_label,
            upstream = %upstream,
            "Request completed"
        );
    }
}

/// Generate a unique request ID using a cryptographically random 64-bit value.
///
/// Format: `req_<16 hex chars>` (e.g. `req_a1b2c3d4e5f67890`).
fn generate_request_id() -> String {
    let value: u64 = rand::thread_rng().gen();
    format!("req_{:016x}", value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_id_generation() {
        let id1 = generate_request_id();
        let id2 = generate_request_id();
        assert!(!id1.is_empty());
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_upstream_cluster_creation() {
        let config = UpstreamConfig {
            backends: vec!["127.0.0.1:3000".to_string()],
            strategy: LoadBalanceStrategy::RoundRobin,
            health_check: None,
        };

        let cluster = UpstreamCluster::new(&config).unwrap();
        assert!(cluster.lb_round_robin.is_some());
        assert!(cluster.lb_ketama.is_none());
    }
}
