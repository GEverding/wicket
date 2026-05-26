//! Pingora-based proxy service for Wicket.
//!
//! This module implements the core proxy functionality using Pingora's HttpProxy trait.

use crate::metrics::{
    classify_http_error, BYTES_RECEIVED_TOTAL, BYTES_SENT_TOTAL, CLIENT_CONNECTIONS_ACTIVE,
    CLIENT_CONNECTIONS_TOTAL, HTTP_ERRORS_TOTAL, HTTP_REQUESTS_ACTIVE, HTTP_REQUESTS_TOTAL,
    HTTP_REQUEST_DURATION_SECONDS, ROUTE_NOT_FOUND_TOTAL, UPSTREAM_CONNECTIONS_ACTIVE,
    UPSTREAM_DURATION_SECONDS, UPSTREAM_ERRORS_TOTAL,
};
use crate::routing::{rewrite_path_and_query, RouteMatch, Router};
use anyhow::Result;
use arc_swap::ArcSwap;
use async_trait::async_trait;
use pingora_core::prelude::*;
use pingora_core::upstreams::peer::{HttpPeer, Peer};
use pingora_core::Result as PingoraResult;
use pingora_http::RequestHeader;
use pingora_load_balancing::selection::consistent::KetamaHashing;
use pingora_load_balancing::selection::RoundRobin;
use pingora_load_balancing::{health_check::TcpHealthCheck, LoadBalancer};
use pingora_proxy::{ProxyHttp, Session};
use rand::Rng;
use std::collections::{BTreeMap, HashMap};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
use tracing::{debug, error, info, warn};
use wicket_config::{AccessLogFormat, Config, LoadBalanceStrategy, UpstreamConfig};
use wicket_tls::CertManager;

// Header name constants
const HEADER_REQUEST_ID: &str = "x-request-id";
const HEADER_HOST: &str = "host";
const HEADER_X_FORWARDED_FOR: &str = "x-forwarded-for";
const HEADER_CONTENT_LENGTH: &str = "content-length";
const HEADER_REFERER: &str = "referer";
const HEADER_USER_AGENT: &str = "user-agent";

// Metric label constants
const LISTENER_DEFAULT: &str = "default";
const ERROR_NO_HEALTHY_BACKENDS: &str = "no_healthy_backends";

/// TLS SNI captured at handshake time for HTTPS requests.
#[derive(Debug, Clone)]
pub struct TlsSni(pub String);

#[cfg(all(target_os = "linux", feature = "ebpf"))]
use std::os::unix::io::RawFd;

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
#[derive(Clone)]
pub struct WicketProxy {
    /// Router for matching requests to upstreams
    router: Arc<ArcSwap<Router>>,

    /// Map of upstream name to load balancer
    upstreams: Arc<ArcSwap<HashMap<String, Arc<UpstreamCluster>>>>,

    /// TLS certificate manager (if TLS is enabled)
    cert_manager: Option<Arc<CertManager>>,

    /// Optional Apache/Nginx-style access log writer.
    access_logger: Option<Arc<AccessLogger>>,

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

/// Atomically rebuild and store router + upstreams from a new config.
fn apply_reload(
    router_slot: &ArcSwap<Router>,
    upstreams_slot: &ArcSwap<HashMap<String, Arc<UpstreamCluster>>>,
    config: &Config,
) -> Result<()> {
    // Build both before storing either, so a failure in upstreams
    // doesn't leave a partially-updated router.
    let router = Router::build(&config.routes)?;
    let upstreams = WicketProxy::build_upstreams(&config.upstreams)?;

    router_slot.store(Arc::new(router));
    upstreams_slot.store(Arc::new(upstreams));
    Ok(())
}

impl HttpReloadHandle {
    /// Reload HTTP proxy routes and upstreams from a new config.
    pub fn reload(&self, config: &Config) -> Result<()> {
        apply_reload(&self.router, &self.upstreams, config)?;
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
        let access_logger = AccessLogger::from_config(config)?;

        Ok(WicketProxy {
            router: Arc::new(ArcSwap::new(Arc::new(router))),
            upstreams: Arc::new(ArcSwap::new(Arc::new(upstreams))),
            cert_manager: None,
            access_logger,
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
        configs: &BTreeMap<String, UpstreamConfig>,
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
        apply_reload(&self.router, &self.upstreams, config)?;
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

struct AccessLogger {
    writer: Mutex<std::fs::File>,
    format: AccessLogFormat,
}

struct AccessLogEntry<'a> {
    remote_addr: &'a str,
    time_local: String,
    method: &'a str,
    request_uri: &'a str,
    protocol: String,
    status: u16,
    bytes_sent: u64,
    referer: &'a str,
    user_agent: &'a str,
    request_id: &'a str,
    route: &'a str,
    upstream: &'a str,
    duration_ms: u64,
}

impl AccessLogger {
    fn from_config(config: &Config) -> Result<Option<Arc<Self>>> {
        if !config.logging.access.enabled || !config.logging.files.enabled {
            return Ok(None);
        }

        let directory = &config.logging.files.directory;
        fs::create_dir_all(directory)?;
        let path = directory.join(&config.logging.files.access);
        let file = OpenOptions::new().create(true).append(true).open(path)?;

        Ok(Some(Arc::new(Self {
            writer: Mutex::new(file),
            format: config.logging.access.format.clone(),
        })))
    }

    fn write(&self, entry: &AccessLogEntry<'_>) -> std::io::Result<()> {
        let line = match self.format {
            AccessLogFormat::Combined => format_combined_access_log(entry),
            AccessLogFormat::Json => format_json_access_log(entry),
        };

        let mut writer = self
            .writer
            .lock()
            .map_err(|_| std::io::Error::other("access log lock poisoned"))?;
        writeln!(writer, "{line}")
    }
}

fn format_combined_access_log(entry: &AccessLogEntry<'_>) -> String {
    format!(
        r#"{} - - [{}] "{} {} {}" {} {} "{}" "{}" "{}" "{}" "{}" {}"#,
        escape_access_field(entry.remote_addr),
        entry.time_local,
        escape_access_field(entry.method),
        escape_access_field(entry.request_uri),
        escape_access_field(&entry.protocol),
        entry.status,
        entry.bytes_sent,
        escape_access_field(entry.referer),
        escape_access_field(entry.user_agent),
        escape_access_field(entry.request_id),
        escape_access_field(entry.route),
        escape_access_field(entry.upstream),
        entry.duration_ms,
    )
}

fn format_json_access_log(entry: &AccessLogEntry<'_>) -> String {
    format!(
        r#"{{"remote_addr":"{}","time_local":"{}","method":"{}","request_uri":"{}","protocol":"{}","status":{},"bytes_sent":{},"referer":"{}","user_agent":"{}","request_id":"{}","route":"{}","upstream":"{}","duration_ms":{}}}"#,
        escape_json(entry.remote_addr),
        escape_json(&entry.time_local),
        escape_json(entry.method),
        escape_json(entry.request_uri),
        escape_json(&entry.protocol),
        entry.status,
        entry.bytes_sent,
        escape_json(entry.referer),
        escape_json(entry.user_agent),
        escape_json(entry.request_id),
        escape_json(entry.route),
        escape_json(entry.upstream),
        entry.duration_ms,
    )
}

fn escape_access_field(value: &str) -> String {
    value
        .replace('\\', r#"\\"#)
        .replace('"', r#"\""#)
        .replace('\n', r#"\n"#)
        .replace('\r', r#"\r"#)
        .replace('\t', r#"\t"#)
}

fn escape_json(value: &str) -> String {
    value
        .replace('\\', r#"\\"#)
        .replace('"', r#"\""#)
        .replace('\n', r#"\n"#)
        .replace('\r', r#"\r"#)
        .replace('\t', r#"\t"#)
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
        let backend = match self.strategy {
            LoadBalanceStrategy::RoundRobin => self.lb_round_robin.as_ref()?.select(key, 256)?,
            LoadBalanceStrategy::ConsistentHash => self.lb_ketama.as_ref()?.select(key, 256)?,
        };
        Some(HttpPeer::new(backend.addr, false, String::new()))
    }
}

#[async_trait]
impl ProxyHttp for WicketProxy {
    type CTX = WicketCtx;

    fn new_ctx(&self) -> Self::CTX {
        // Increment active connection counter
        // Note: "default" listener since we don't have listener info here
        CLIENT_CONNECTIONS_ACTIVE
            .with_label_values(&[LISTENER_DEFAULT])
            .inc();
        CLIENT_CONNECTIONS_TOTAL
            .with_label_values(&[LISTENER_DEFAULT])
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
            .get(HEADER_REQUEST_ID)
            .and_then(|v| v.to_str().ok())
        {
            ctx.request_id = incoming_id.to_string();
        }

        // Extract request properties
        let host = request_host(req_header);

        let path = req_header.uri.path();
        let method = req_header.method.as_str();
        let tls_sni = request_tls_sni(session);

        if let (Some(sni), Some(host)) = (tls_sni, host) {
            if !same_hostname(host, sni) {
                warn!(
                    request_id = %ctx.request_id,
                    method = %method,
                    path = %path,
                    host = %host,
                    sni = %sni,
                    "Rejecting HTTPS request with mismatched SNI and Host"
                );
                return Err(Error::new(ErrorType::HTTPStatus(421)));
            }
        }

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
                .with_label_values(&[&route_match.upstream, ERROR_NO_HEALTHY_BACKENDS])
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
        if let Some(route_match) = &ctx.route_match {
            if let Some(rewrite) = &route_match.url_rewrite {
                let uri = &upstream_request.uri;
                if let Some(path_and_query) = rewrite_path_and_query(
                    uri.path(),
                    uri.query(),
                    &route_match.matched_path_prefix,
                    rewrite,
                ) {
                    upstream_request
                        .set_raw_path(path_and_query.as_bytes())
                        .map_err(|error| {
                            warn!(
                                request_id = %ctx.request_id,
                                error = %error,
                                path_and_query = %path_and_query,
                                "Failed to rewrite upstream request path"
                            );
                            Error::new(ErrorType::InternalError)
                        })?;
                    debug!(
                        request_id = %ctx.request_id,
                        route = ?route_match.route_name,
                        path_and_query = %path_and_query,
                        "Rewrote upstream request path"
                    );
                }
            }
        }

        // Inject X-Request-Id header to upstream
        upstream_request
            .insert_header(HEADER_REQUEST_ID, &ctx.request_id)
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

            let xff_value =
                if let Some(existing) = upstream_request.headers.get(HEADER_X_FORWARDED_FOR) {
                    format!("{}, {}", existing.to_str().unwrap_or(""), client_ip)
                } else {
                    client_ip
                };

            upstream_request
                .insert_header(HEADER_X_FORWARDED_FOR, &xff_value)
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
        let request_uri = req_header.uri.to_string();
        let protocol = format!("{:?}", req_header.version);
        let remote_addr = session
            .as_downstream()
            .client_addr()
            .map(|addr| {
                addr.as_inet()
                    .map(|addr| addr.ip().to_string())
                    .unwrap_or_else(|| addr.to_string())
            })
            .unwrap_or_else(|| "-".to_string());
        let host = request_host(req_header).unwrap_or("-");
        let referer = req_header
            .headers
            .get(HEADER_REFERER)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("-");
        let user_agent = req_header
            .headers
            .get(HEADER_USER_AGENT)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("-");

        let (route_label, upstream) = match ctx.route_match.as_ref() {
            Some(rm) => (
                rm.route_name.as_deref().unwrap_or(rm.upstream.as_str()),
                rm.upstream.as_str(),
            ),
            None => ("unknown", "unknown"),
        };

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
            HTTP_ERRORS_TOTAL
                .with_label_values(&[
                    method,
                    route_label,
                    &status_str,
                    classify_http_error(status),
                ])
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
        let bytes_sent = if let Some(resp) = session.response_written() {
            let bytes = resp
                .headers
                .get(HEADER_CONTENT_LENGTH)
                .and_then(|cl| cl.to_str().ok())
                .and_then(|s| s.parse::<u64>().ok());
            if let Some(bytes) = bytes {
                BYTES_SENT_TOTAL
                    .with_label_values(&[route_label])
                    .inc_by(bytes);
            }
            bytes.unwrap_or(0)
        } else {
            0
        };
        if let Some(bytes) = req_header
            .headers
            .get(HEADER_CONTENT_LENGTH)
            .and_then(|cl| cl.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok())
        {
            BYTES_RECEIVED_TOTAL
                .with_label_values(&[route_label])
                .inc_by(bytes);
        }

        // Decrement connection counter
        CLIENT_CONNECTIONS_ACTIVE
            .with_label_values(&[LISTENER_DEFAULT])
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

        if let Some(access_logger) = &self.access_logger {
            let entry = AccessLogEntry {
                remote_addr: &remote_addr,
                time_local: chrono::Local::now()
                    .format("%d/%b/%Y:%H:%M:%S %z")
                    .to_string(),
                method,
                request_uri: &request_uri,
                protocol,
                status,
                bytes_sent,
                referer,
                user_agent,
                request_id: &ctx.request_id,
                route: route_label,
                upstream,
                duration_ms: duration.as_millis() as u64,
            };

            if let Err(error) = access_logger.write(&entry) {
                warn!(error = %error, "failed to write access log");
            }
        }
    }
}

/// Generate a unique request ID using a cryptographically random 64-bit value.
///
/// Format: `req_<16 hex chars>` (e.g. `req_a1b2c3d4e5f67890`).
fn generate_request_id() -> String {
    let value: u64 = rand::thread_rng().gen();
    format!("req_{:016x}", value)
}

fn request_host(req_header: &RequestHeader) -> Option<&str> {
    req_header
        .headers
        .get(HEADER_HOST)
        .and_then(|v| v.to_str().ok())
        .or_else(|| {
            req_header
                .uri
                .authority()
                .map(|authority| authority.as_str())
        })
}

fn request_tls_sni(session: &Session) -> Option<&str> {
    session
        .as_downstream()
        .digest()
        .and_then(|digest| digest.proxy_digest.as_ref())
        .and_then(|digest| digest.user_data.as_deref())
        .and_then(|user_data| user_data.downcast_ref::<TlsSni>())
        .map(|sni| sni.0.as_str())
}

fn same_hostname(host: &str, sni: &str) -> bool {
    normalize_hostname(host) == normalize_hostname(sni)
}

fn normalize_hostname(host: &str) -> String {
    let host = host.trim_end_matches('.').to_lowercase();
    if let Some(stripped) = host.strip_prefix('[').and_then(|h| h.split_once(']')) {
        return stripped.0.to_string();
    }
    host.split(':').next().unwrap_or(&host).to_string()
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
    fn test_same_hostname_allows_matching_sni_and_host() {
        assert!(same_hostname(
            "cdn-chi-1.cooldaddypop.com:443",
            "cdn-chi-1.cooldaddypop.com"
        ));
        assert!(same_hostname(
            "CDN-CHI-1.COOLDADDYPOP.COM.",
            "cdn-chi-1.cooldaddypop.com"
        ));
    }

    #[test]
    fn test_same_hostname_rejects_domain_fronting() {
        assert!(!same_hostname(
            "other.cooldaddypop.com",
            "cdn-chi-1.cooldaddypop.com"
        ));
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

    #[test]
    fn test_combined_access_log_format_escapes_quoted_fields() {
        let entry = AccessLogEntry {
            remote_addr: "127.0.0.1:12345",
            time_local: "26/May/2026:03:00:00 +0000".to_string(),
            method: "GET",
            request_uri: "/path?q=1",
            protocol: "HTTP/1.1".to_string(),
            status: 200,
            bytes_sent: 123,
            referer: "https://example.com/a\"b",
            user_agent: "curl\n8",
            request_id: "req_abc",
            route: "updates",
            upstream: "s3cache",
            duration_ms: 42,
        };

        assert_eq!(
            format_combined_access_log(&entry),
            r#"127.0.0.1:12345 - - [26/May/2026:03:00:00 +0000] "GET /path?q=1 HTTP/1.1" 200 123 "https://example.com/a\"b" "curl\n8" "req_abc" "updates" "s3cache" 42"#
        );
    }

    #[test]
    fn test_json_access_log_format_escapes_control_characters() {
        let entry = AccessLogEntry {
            remote_addr: "127.0.0.1:12345",
            time_local: "26/May/2026:03:00:00 +0000".to_string(),
            method: "GET",
            request_uri: "/path?q=1",
            protocol: "HTTP/1.1".to_string(),
            status: 200,
            bytes_sent: 123,
            referer: "-",
            user_agent: "agent\nwith\"quote",
            request_id: "req_abc",
            route: "updates",
            upstream: "s3cache",
            duration_ms: 42,
        };

        let line = format_json_access_log(&entry);
        assert!(line.contains(r#""user_agent":"agent\nwith\"quote""#));
        assert!(line.contains(r#""status":200"#));
    }
}
