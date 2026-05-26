//! Wicket - A Kubernetes Gateway API implementation and reverse proxy built on Pingora.
//!
//! Wicket is designed to be the "Caddy of Gateway API" - simple to configure,
//! observable by default, and fast enough to replace nginx/HAProxy.

use anyhow::{Context, Result};
use async_trait::async_trait;
use clap::Parser;
use foundations::telemetry::settings::{
    Level, LogFormat, LogVerbosity, LoggingSettings, TelemetrySettings,
};
use foundations::telemetry::{self};
use foundations::{service_info, BootstrapResult};
use pingora::prelude::ResponseHeader;
use pingora_core::apps::ServerApp;
use pingora_core::prelude::*;
use pingora_core::protocols::raw_connect::ProxyDigest;
use pingora_core::protocols::{
    GetProxyDigest, GetSocketDigest, GetTimingDigest, Peek, Shutdown, SocketDigest, Ssl,
    TimingDigest, UniqueID, UniqueIDType, ALPN,
};
use pingora_core::server::configuration::ServerConf;
use pingora_core::server::ShutdownWatch;
use pingora_core::services::listening::Service as ListeningService;
use pingora_core::services::Service;
use pingora_proxy::{http_proxy, http_proxy_service, HttpProxy};
use std::ffi::OsStr;
use std::fmt;
use std::fs;
use std::net::SocketAddr;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use std::time::{Duration, Instant, SystemTime};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer};
use wicket_config::Config;
use wicket_core::{
    metrics::{TLS_HANDSHAKES_TOTAL, TLS_HANDSHAKE_DURATION_SECONDS, TLS_HANDSHAKE_ERRORS_TOTAL},
    register_metrics as register_proxy_metrics,
    wicket_tls::{AcmeConfig, AcmeProvider, CertManager, FileWatcher, TlsMode},
    TlsSni, WicketProxy,
};
use wicket_stream::{create_listener, into_tokio_listener, ListenerConfig, StreamProxy};

/// Wicket - Fast, observable reverse proxy built on Pingora
#[derive(Parser, Debug)]
#[command(name = "wicket")]
#[command(version, about, long_about = None)]
struct Args {
    /// Path to the configuration file
    #[arg(short, long, default_value = "wicket.toml")]
    config: PathBuf,

    /// Validate configuration and exit
    #[arg(long)]
    validate: bool,

    /// Override log level (trace, debug, info, warn, error)
    #[arg(short, long)]
    log_level: Option<String>,

    /// Force JSON log output
    #[arg(long)]
    json_logs: bool,

    /// Print the parsed configuration and exit
    #[arg(long)]
    dump_config: bool,

    /// Print the JSON Schema for the configuration and exit
    #[arg(long)]
    dump_schema: bool,

    /// Prometheus metrics server address
    #[arg(long, default_value = "0.0.0.0:9090")]
    metrics_addr: String,

    /// Enable Pingora binary upgrade mode
    #[arg(long)]
    upgrade: bool,

    /// Path to the PID file used by Pingora when daemon mode is enabled
    #[arg(long, default_value = "/run/wicket/wicket.pid")]
    pid_file: String,

    /// Path to the upgrade socket used for Pingora binary handoff
    #[arg(long, default_value = "/run/wicket/upgrade.sock")]
    upgrade_sock: String,
}

fn main() {
    // Bootstrap with foundations for telemetry
    if let Err(e) = bootstrap() {
        eprintln!("Fatal error: {:#}", e);
        std::process::exit(1);
    }
}

fn bootstrap() -> BootstrapResult<()> {
    install_rustls_crypto_provider()?;

    let args = Args::parse();

    // Handle --dump-schema (does not require a config file)
    if args.dump_schema {
        let schema = schemars::schema_for!(wicket_config::Config);
        println!("{}", serde_json::to_string_pretty(&schema).unwrap());
        return Ok(());
    }

    // Load configuration first to get log settings
    let config = Config::load(&args.config)
        .with_context(|| format!("Failed to load config from {}", args.config.display()))?;

    // Initialize foundations telemetry
    let log_level = args
        .log_level
        .as_deref()
        .or(config.logging.level.as_deref())
        .unwrap_or(&config.server.log_level);
    let json_logs = args.json_logs
        || config
            .logging
            .format
            .as_ref()
            .map(|format| matches!(format, wicket_config::LogFormat::Json))
            .unwrap_or(config.server.json_logs);

    // Set up telemetry with foundations
    let telemetry_settings = TelemetrySettings {
        logging: LoggingSettings {
            verbosity: parse_verbosity(log_level),
            format: if json_logs {
                LogFormat::Json
            } else {
                LogFormat::Text
            },
            ..Default::default()
        },
        ..Default::default()
    };

    // Create service info using the macro
    let service_info = service_info!();

    // Initialize tracing before foundations so Wicket's tracing macros always have a subscriber.
    let _log_guards =
        init_logging(&config, log_level, json_logs).context("Failed to initialize logging")?;

    // Initialize telemetry
    telemetry::init(&service_info, &telemetry_settings)?;

    info!(
        config_path = %args.config.display(),
        log_level = %log_level,
        json_logs,
        "Wicket logging initialized"
    );

    // Handle --dump-config
    if args.dump_config {
        println!("{:#?}", config);
        return Ok(());
    }

    // Handle --validate
    if args.validate {
        info!("Configuration is valid");
        println!("Configuration at {} is valid", args.config.display());
        return Ok(());
    }

    run_server(config, &args)
}

fn init_logging(config: &Config, level: &str, json: bool) -> Result<Vec<WorkerGuard>> {
    let mut guards = Vec::new();
    let filter = std::env::var("RUST_LOG").unwrap_or_else(|_| default_tracing_filter(level));
    let mut layers: Vec<Box<dyn Layer<tracing_subscriber::Registry> + Send + Sync + 'static>> =
        Vec::new();

    if json {
        layers.push(
            tracing_subscriber::fmt::layer()
                .json()
                .with_writer(std::io::stderr)
                .with_filter(EnvFilter::new(filter.clone()))
                .boxed(),
        );
    } else {
        layers.push(
            tracing_subscriber::fmt::layer()
                .with_writer(std::io::stderr)
                .with_filter(EnvFilter::new(filter.clone()))
                .boxed(),
        );
    }

    if config.logging.files.enabled {
        let directory = &config.logging.files.directory;
        fs::create_dir_all(directory)?;

        let error_appender =
            tracing_appender::rolling::never(directory, &config.logging.files.error);
        let (error_writer, error_guard) = tracing_appender::non_blocking(error_appender);
        guards.push(error_guard);

        if json {
            layers.push(
                tracing_subscriber::fmt::layer()
                    .json()
                    .with_writer(error_writer)
                    .with_filter(EnvFilter::new(filter.clone()))
                    .boxed(),
            );
        } else {
            layers.push(
                tracing_subscriber::fmt::layer()
                    .with_writer(error_writer)
                    .with_filter(EnvFilter::new(filter.clone()))
                    .boxed(),
            );
        }

        let acme_appender = tracing_appender::rolling::never(directory, &config.logging.files.acme);
        let (acme_writer, acme_guard) = tracing_appender::non_blocking(acme_appender);
        guards.push(acme_guard);
        let acme_filter = acme_tracing_filter(level);

        if json {
            layers.push(
                tracing_subscriber::fmt::layer()
                    .json()
                    .with_writer(acme_writer)
                    .with_filter(EnvFilter::new(acme_filter))
                    .boxed(),
            );
        } else {
            layers.push(
                tracing_subscriber::fmt::layer()
                    .with_writer(acme_writer)
                    .with_filter(EnvFilter::new(acme_filter))
                    .boxed(),
            );
        }
    }

    tracing_subscriber::registry()
        .with(layers)
        .try_init()
        .map_err(|error| anyhow::anyhow!(error))?;

    Ok(guards)
}

fn tracing_filter_level(level: &str) -> &'static str {
    match level.to_lowercase().as_str() {
        "trace" => "trace",
        "debug" => "debug",
        "info" => "info",
        "warn" | "warning" => "warn",
        "error" => "error",
        _ => "info",
    }
}

fn default_tracing_filter(level: &str) -> String {
    let level = tracing_filter_level(level);
    match level {
        "trace" | "debug" => format!(
            "info,wicket={level},wicket_tls={level},wicket_core={level},wicket_config={level},wicket_stream={level}"
        ),
        _ => level.to_string(),
    }
}

fn acme_tracing_filter(level: &str) -> String {
    let level = tracing_filter_level(level);
    format!("wicket_tls::acme={level},wicket_tls::acme::cloudflare={level}")
}

fn install_rustls_crypto_provider() -> Result<()> {
    if rustls::crypto::CryptoProvider::get_default().is_some() {
        return Ok(());
    }

    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("failed to install aws-lc-rs rustls crypto provider"))
}

/// Initialize ACME provider with auto-TLS domains and start renewal loop.
fn init_acme(
    config: &Config,
    acme_config: &AcmeConfig,
    manager: &Arc<CertManager>,
    rt: &tokio::runtime::Runtime,
) -> Result<()> {
    let auto_tls_domains = config.collect_auto_tls_domains_with_providers();
    if !auto_tls_domains.is_empty() {
        info!(
            domains = ?auto_tls_domains.iter().map(|d| &d.domain).collect::<Vec<_>>(),
            "Auto-TLS domains collected from routes"
        );
    }

    let provider = Arc::new(
        AcmeProvider::builder(acme_config.clone(), manager.clone())
            .auto_tls_domains(auto_tls_domains)
            .build()
            .context("Failed to create ACME provider")?,
    );

    // Initialize synchronously using the provided runtime
    rt.block_on(provider.initialize())
        .context("Failed to initialize ACME certificates")?;

    // Spawn renewal loop in a dedicated thread with its own runtime
    let provider_clone = Arc::clone(&provider);
    std::thread::spawn(move || match tokio::runtime::Runtime::new() {
        Ok(rt) => {
            rt.block_on(async move {
                if let Err(e) = provider_clone.start_renewal_loop().await {
                    error!(error = %e, "ACME renewal loop failed");
                }
            });
        }
        Err(e) => {
            error!(error = %e, "Failed to create runtime for ACME renewal");
        }
    });

    info!("ACME provider initialized with renewal loop");
    Ok(())
}

static NEXT_TLS_STREAM_ID: AtomicI32 = AtomicI32::new(1);

struct DynamicTlsService {
    name: String,
    addr: SocketAddr,
    proxy: Arc<HttpProxy<WicketProxy>>,
    acceptor: TlsAcceptor,
}

impl DynamicTlsService {
    fn new(
        addr: SocketAddr,
        proxy: WicketProxy,
        cert_manager: Arc<CertManager>,
        server_conf: &Arc<ServerConf>,
    ) -> Result<Self> {
        let proxy = Arc::new(http_proxy(server_conf, proxy));
        let acceptor = dynamic_tls_acceptor(cert_manager)?;

        Ok(Self {
            name: "Wicket HTTPS Proxy Service".to_string(),
            addr,
            proxy,
            acceptor,
        })
    }
}

#[async_trait]
impl Service for DynamicTlsService {
    async fn start_service(
        &mut self,
        #[cfg(unix)] _fds: Option<pingora_core::server::ListenFds>,
        mut shutdown: ShutdownWatch,
        _listeners_per_fd: usize,
    ) {
        let listener = match TcpListener::bind(self.addr).await {
            Ok(listener) => listener,
            Err(error) => {
                error!(address = %self.addr, error = %error, "Failed to bind HTTPS listener");
                return;
            }
        };

        info!(address = %self.addr, "HTTPS proxy listening with dynamic SNI resolver");

        loop {
            tokio::select! {
                result = shutdown.changed() => {
                    if result.is_err() || *shutdown.borrow() {
                        info!(address = %self.addr, "HTTPS proxy listener shutting down");
                        break;
                    }
                }
                accepted = listener.accept() => {
                    let (stream, peer_addr) = match accepted {
                        Ok(accepted) => accepted,
                        Err(error) => {
                            error!(address = %self.addr, error = %error, "Failed to accept HTTPS connection");
                            continue;
                        }
                    };

                    let proxy = Arc::clone(&self.proxy);
                    let acceptor = self.acceptor.clone();
                    let connection_shutdown = shutdown.clone();
                    let listener_label = self.addr.to_string();

                    tokio::spawn(async move {
                        let socket_digest = Arc::new(SocketDigest::from_raw_fd(stream.as_raw_fd()));
                        let stream_id = NEXT_TLS_STREAM_ID.fetch_add(1, Ordering::Relaxed);
                        let handshake_start = Instant::now();

                        let (tls_stream, tls_sni) = match tokio::time::timeout(
                            Duration::from_secs(60),
                            acceptor.accept(stream),
                        ).await {
                            Ok(Ok(stream)) => {
                                let tls_sni = stream.get_ref().1.server_name().map(String::from);
                                let elapsed = handshake_start.elapsed().as_secs_f64();
                                TLS_HANDSHAKE_DURATION_SECONDS
                                    .with_label_values(&[&listener_label])
                                    .observe(elapsed);
                                record_tls_handshake_success(&listener_label, &stream);
                                (stream, tls_sni)
                            }
                            Ok(Err(error)) => {
                                TLS_HANDSHAKE_ERRORS_TOTAL
                                    .with_label_values(&[&listener_label, "failure"])
                                    .inc();
                                error!(peer = %peer_addr, error = %error, "HTTPS TLS handshake failed");
                                return;
                            }
                            Err(_) => {
                                TLS_HANDSHAKE_ERRORS_TOTAL
                                    .with_label_values(&[&listener_label, "timeout"])
                                    .inc();
                                error!(peer = %peer_addr, "HTTPS TLS handshake timed out");
                                return;
                            }
                        };

                        let mut stream = Some(Box::new(DynamicTlsStream::new(
                            tls_stream,
                            stream_id,
                            socket_digest,
                            tls_sni,
                        )) as pingora_core::protocols::Stream);

                        while let Some(next_stream) = stream {
                            stream = proxy.process_new(next_stream, &connection_shutdown).await;
                        }
                    });
                }
            }
        }
    }

    fn name(&self) -> &str {
        &self.name
    }
}

fn dynamic_tls_acceptor(cert_manager: Arc<CertManager>) -> Result<TlsAcceptor> {
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let mut config = rustls::ServerConfig::builder_with_provider(provider.into())
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .context("Failed to configure TLS protocol versions")?
        .with_no_client_auth()
        .with_cert_resolver(cert_manager);
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok(TlsAcceptor::from(Arc::new(config)))
}

fn record_tls_handshake_success(listener: &str, stream: &TlsStream<TcpStream>) {
    let (_, connection) = stream.get_ref();
    let tls_version = connection
        .protocol_version()
        .map(|version| format!("{version:?}"))
        .unwrap_or_else(|| "unknown".to_string());
    let cipher = connection
        .negotiated_cipher_suite()
        .map(|suite| format!("{:?}", suite.suite()))
        .unwrap_or_else(|| "unknown".to_string());

    TLS_HANDSHAKES_TOTAL
        .with_label_values(&[listener, &tls_version, &cipher])
        .inc();
}

struct DynamicTlsStream {
    inner: TlsStream<TcpStream>,
    id: UniqueIDType,
    timing_digest: Vec<Option<TimingDigest>>,
    socket_digest: Arc<SocketDigest>,
    proxy_digest: Option<Arc<ProxyDigest>>,
}

impl DynamicTlsStream {
    fn new(
        inner: TlsStream<TcpStream>,
        id: UniqueIDType,
        socket_digest: Arc<SocketDigest>,
        tls_sni: Option<String>,
    ) -> Self {
        let proxy_digest = tls_sni.and_then(|sni| {
            ResponseHeader::build(200, None).ok().map(|response| {
                Arc::new(ProxyDigest::new(
                    Box::new(response),
                    Some(Box::new(TlsSni(sni))),
                ))
            })
        });

        Self {
            inner,
            id,
            timing_digest: vec![Some(TimingDigest {
                established_ts: SystemTime::now(),
            })],
            socket_digest,
            proxy_digest,
        }
    }
}

impl fmt::Debug for DynamicTlsStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DynamicTlsStream")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

impl AsyncRead for DynamicTlsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for DynamicTlsStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[async_trait]
impl Shutdown for DynamicTlsStream {
    async fn shutdown(&mut self) {
        if let Err(error) = AsyncWriteExt::shutdown(&mut self.inner).await {
            warn!(error = %error, "HTTPS TLS stream shutdown failed");
        }
    }
}

impl UniqueID for DynamicTlsStream {
    fn id(&self) -> UniqueIDType {
        self.id
    }
}

impl Ssl for DynamicTlsStream {
    fn selected_alpn_proto(&self) -> Option<ALPN> {
        match self.inner.get_ref().1.alpn_protocol() {
            Some(b"h2") => Some(ALPN::H2),
            Some(b"http/1.1") => Some(ALPN::H1),
            _ => None,
        }
    }
}

impl GetTimingDigest for DynamicTlsStream {
    fn get_timing_digest(&self) -> Vec<Option<TimingDigest>> {
        self.timing_digest.clone()
    }
}

impl GetProxyDigest for DynamicTlsStream {
    fn get_proxy_digest(&self) -> Option<Arc<ProxyDigest>> {
        self.proxy_digest.clone()
    }
}

impl GetSocketDigest for DynamicTlsStream {
    fn get_socket_digest(&self) -> Option<Arc<SocketDigest>> {
        Some(Arc::clone(&self.socket_digest))
    }
}

impl Peek for DynamicTlsStream {}

/// Initialize and run the Wicket proxy server.
///
/// Sets up TLS (file-watch, ACME, or mixed), creates the Pingora HTTP proxy service,
/// optionally starts the L4 stream proxy, installs signal handlers for graceful
/// shutdown, and starts a config-file watcher for hot reloads.
fn run_server(config: Config, args: &Args) -> Result<()> {
    info!(
        config_path = %args.config.display(),
        listen = %config.server.listen,
        upstreams = config.upstreams.len(),
        routes = config.routes.len(),
        workers = ?config.server.workers,
        shutdown_timeout = config.server.shutdown_timeout,
        "Starting Wicket proxy"
    );

    if args.upgrade && config.stream.is_some() {
        anyhow::bail!(
            "graceful binary upgrade is HTTP-only in v1 and unsupported when stream listeners are configured"
        );
    }

    // Create a tokio runtime for async operations (TLS/ACME, stream proxy,
    // signal handling, config watcher).  We enter it immediately so that
    // `tokio::spawn`, `TcpListener::from_std`, and signal handlers used
    // later in this function have an active reactor context.  Pingora's
    // `run_forever()` blocks the main thread; spawned tasks execute on
    // this runtime's worker pool.
    let tls_runtime = tokio::runtime::Runtime::new().context("Failed to create async runtime")?;
    let _rt_guard = tls_runtime.enter();

    // Initialize TLS if configured
    let cert_manager: Option<Arc<CertManager>> = if let Some(ref tls_config) = config.tls {
        let manager = Arc::new(CertManager::new());

        match tls_config.mode {
            TlsMode::File => {
                if let Some(ref file_config) = tls_config.file {
                    let watcher = FileWatcher::new(file_config.clone(), manager.clone());
                    watcher
                        .load_all()
                        .context("Failed to load file-based certificates")?;

                    if file_config.watch {
                        watcher.start();
                        info!("File watcher started for certificate updates");
                    }
                }
            }
            TlsMode::Acme => {
                if let Some(ref acme_config) = tls_config.acme {
                    init_acme(&config, acme_config, &manager, &tls_runtime)?;
                } else {
                    info!("ACME TLS mode configured but no [tls.acme] section found");
                }
            }
            TlsMode::Mixed => {
                // Load file certs first
                if let Some(ref file_config) = tls_config.file {
                    let watcher = FileWatcher::new(file_config.clone(), manager.clone());
                    watcher
                        .load_all()
                        .context("Failed to load file-based certificates")?;
                    if file_config.watch {
                        watcher.start();
                        info!("File watcher started for certificate updates");
                    }
                }

                // Then ACME
                if let Some(ref acme_config) = tls_config.acme {
                    init_acme(&config, acme_config, &manager, &tls_runtime)?;
                    info!("Mixed TLS mode: file certs loaded, ACME initialized");
                } else {
                    info!("Mixed TLS mode: file certs loaded, no ACME config");
                }
            }
        }

        info!(
            mode = ?tls_config.mode,
            certificates = manager.store().len(),
            "TLS initialized"
        );

        if manager.is_empty() {
            anyhow::bail!("TLS configured but certificate store is empty");
        }

        Some(manager)
    } else {
        None
    };

    // Create Pingora server configuration from our config
    let mut pingora_conf = ServerConf::default();

    // Wire up worker threads if specified
    if let Some(workers) = config.server.workers {
        pingora_conf.threads = workers;
    }

    // Pingora's grace period defaults to 5 minutes. In standalone mode we
    // want `server.shutdown_timeout` to bound the full graceful drain window,
    // so start runtime shutdown immediately and let Pingora wait up to the
    // configured shutdown timeout for active work to finish.
    pingora_conf.grace_period_seconds = Some(0);

    // Wire up graceful shutdown timeout
    pingora_conf.graceful_shutdown_timeout_seconds = Some(config.server.shutdown_timeout);
    pingora_conf.pid_file = args.pid_file.clone();
    pingora_conf.upgrade_sock = args.upgrade_sock.clone();

    // Create the Pingora server with our configuration
    let mut server = Server::new_with_opt_and_conf(
        Some(Opt {
            upgrade: args.upgrade,
            daemon: false,
            nocapture: false,
            test: false,
            conf: None,
        }),
        pingora_conf,
    );

    // Register custom proxy metrics with Prometheus
    // These will automatically appear at the /metrics endpoint
    if let Err(e) = register_proxy_metrics() {
        error!(error = %e, "Failed to register proxy metrics");
    }

    // Register stream proxy metrics (always safe to call; no-op if stream not configured)
    wicket_stream::metrics::register_stream_metrics();

    // Register TLS/ACME metrics with the Prometheus default registry.
    wicket_core::wicket_tls::metrics::register_metrics();

    // Add Pingora's built-in Prometheus metrics server
    let mut prometheus_service = ListeningService::prometheus_http_service();
    prometheus_service.add_tcp(&args.metrics_addr);
    server.add_service(prometheus_service);
    info!(address = %args.metrics_addr, "Prometheus metrics server enabled");

    // Create the proxy service
    let mut wicket_proxy = WicketProxy::new(&config).context("Failed to create proxy service")?;

    // Wire up TLS if enabled
    if let Some(ref cm) = cert_manager {
        wicket_proxy = wicket_proxy.with_cert_manager(cm.clone());
        info!("TLS certificate manager wired to proxy");
    }

    // Obtain a reload handle before the proxy is consumed by Pingora.
    let http_reload_handle = wicket_proxy.reload_handle();
    let https_proxy = wicket_proxy.clone();

    // Create HTTP proxy service
    let mut proxy_service = http_proxy_service(&server.configuration, wicket_proxy);

    // Configure the HTTP listener unless explicitly disabled.
    //
    // `disable_http` is set by the controller for HTTPS-only Gateways so
    // that HTTP and HTTPS do not contend for the same port.
    if !config.server.disable_http {
        for address in config.server.http_listen_addrs() {
            proxy_service.add_tcp(&address.to_string());
            info!(address = %address, "HTTP proxy listening");
        }
    } else {
        info!("HTTP listener disabled (server.disable_http = true)");
    }

    // Add service to server
    server.add_service(proxy_service);

    // Add HTTPS listener if TLS is configured. This service uses CertManager as
    // the rustls resolver, so SNI is evaluated at handshake time.
    if let Some(ref cert_manager) = cert_manager {
        let https_addr = match config.server.https_listen {
            Some(addr) => addr,
            None => compute_https_addr(config.server.listen),
        };
        let https_service = DynamicTlsService::new(
            https_addr,
            https_proxy,
            Arc::clone(cert_manager),
            &server.configuration,
        )?;
        server.add_service(https_service);
    }

    // Optionally start stream proxy
    let shutdown_token = CancellationToken::new();

    let stream_proxy: Option<Arc<StreamProxy>> = if let Some(ref stream_config) = config.stream {
        #[allow(unused_mut)]
        let mut proxy_builder =
            StreamProxy::from_config(stream_config).context("Failed to build stream proxy")?;

        #[cfg(all(target_os = "linux", feature = "ebpf"))]
        {
            use wicket_sockmap::{SocketMap, SocketMapConfig};

            let sockmap_config = SocketMapConfig {
                bpf_object_path: None, // Use embedded BPF bytecode
                max_connections: 500_000,
                verbose: false,
            };

            match SocketMap::load(sockmap_config) {
                Ok(mut sockmap) => match sockmap.attach() {
                    Ok(()) => {
                        tracing::info!("eBPF sockmap loaded and attached");
                        proxy_builder = proxy_builder.with_sockmap(sockmap);
                    }
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            "Failed to attach eBPF sockmap, falling back to userspace proxying"
                        );
                    }
                },
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "Failed to load eBPF sockmap, falling back to userspace proxying"
                    );
                }
            }
        }

        let proxy = Arc::new(proxy_builder);

        let listener_config = ListenerConfig {
            addr: stream_config
                .listen
                .parse()
                .context("Invalid stream listen address")?,
            backlog: stream_config.backlog,
            reuseport: stream_config.reuseport,
        };

        let listener =
            create_listener(&listener_config).context("Failed to create stream listener")?;
        let listener = into_tokio_listener(listener)?;

        info!(
            listen = %stream_config.listen,
            upstreams = stream_config.upstreams.len(),
            routes = stream_config.sni_routes.len(),
            proxy_protocol = ?stream_config.proxy_protocol,
            source_ips = stream_config.source_ips.len(),
            "Starting stream proxy"
        );

        let proxy_run = Arc::clone(&proxy);
        let stream_shutdown = shutdown_token.clone();
        tokio::spawn(async move {
            if let Err(e) = proxy_run.run(listener, stream_shutdown).await {
                error!(error = %e, "Stream proxy error");
            }
        });

        Some(proxy)
    } else {
        None
    };

    // Signal handler: cancel the shutdown token on SIGTERM or SIGINT.
    let signal_shutdown = shutdown_token.clone();
    tokio::spawn(async move {
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler");
        let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
            .expect("failed to install SIGINT handler");

        tokio::select! {
            _ = sigterm.recv() => { tracing::info!("Received SIGTERM"); }
            _ = sigint.recv() => { tracing::info!("Received SIGINT"); }
        }
        signal_shutdown.cancel();
    });

    // Config file watcher: poll every 2s, reload both HTTP and stream proxies on mtime change.
    let config_path = args.config.clone();
    let stream_reload = stream_proxy.clone();
    tokio::spawn(async move {
        let mut last_modified = tokio::fs::metadata(&config_path)
            .await
            .ok()
            .and_then(|m| m.modified().ok());

        loop {
            tokio::time::sleep(Duration::from_secs(2)).await;

            let current_modified = tokio::fs::metadata(&config_path)
                .await
                .ok()
                .and_then(|m| m.modified().ok());

            if current_modified != last_modified {
                info!("Config file changed, reloading...");
                match Config::load(&config_path) {
                    Ok(new_config) => {
                        // Reload HTTP proxy routes and upstreams.
                        if let Err(e) = http_reload_handle.reload(&new_config) {
                            error!(error = %e, "Failed to reload HTTP proxy config");
                        }

                        // Reload stream (L4) proxy if configured.
                        if let Some(ref proxy) = stream_reload {
                            if let Some(ref stream_config) = new_config.stream {
                                if let Err(e) = proxy.reload(stream_config) {
                                    error!(error = %e, "Failed to reload stream proxy config");
                                }
                            }
                        }
                        last_modified = current_modified;
                    }
                    Err(e) => {
                        error!(error = %e, "Failed to load new config, keeping current config");
                    }
                }
            }
        }
    });

    // Bootstrap only after the likely-fallible proxy/service setup is complete.
    server.bootstrap();

    // Publish the serving PID only once startup has crossed the bootstrap boundary.
    let _pid_guard = PidFileGuard::install(&args.pid_file)?;

    let startup_status = if args.upgrade {
        "HTTP upgrade takeover complete"
    } else {
        "HTTP service ready"
    };

    systemd_notify_ready(startup_status)?;
    info!(status = startup_status, "Wicket service ready");

    // Run the server (blocks until shutdown)
    server.run_forever();
}

struct PidFileGuard {
    path: PathBuf,
    pid: u32,
}

impl PidFileGuard {
    fn install(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        let pid = std::process::id();

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).with_context(|| {
                format!("Failed to create PID file directory: {}", parent.display())
            })?;
        }

        write_pid_file(&path, pid)?;

        Ok(Self { path, pid })
    }
}

impl Drop for PidFileGuard {
    fn drop(&mut self) {
        if pid_file_matches_pid(&self.path, self.pid).unwrap_or(false) {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

fn write_pid_file(path: &Path, pid: u32) -> Result<()> {
    use std::io::Write;

    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "wicket.pid".to_string());
    let tmp_path = parent.join(format!(".{}.{}.tmp", file_name, pid));

    {
        let mut file = std::fs::File::create(&tmp_path)
            .with_context(|| format!("Failed to create temp PID file: {}", tmp_path.display()))?;

        #[cfg(unix)]
        file.set_permissions(std::fs::Permissions::from_mode(0o640))
            .with_context(|| format!("Failed to set permissions on {}", tmp_path.display()))?;

        writeln!(file, "{pid}")
            .with_context(|| format!("Failed to write PID to {}", tmp_path.display()))?;
    }

    std::fs::rename(&tmp_path, path).with_context(|| {
        format!(
            "Failed to atomically replace PID file {} with {}",
            path.display(),
            tmp_path.display()
        )
    })?;

    Ok(())
}

fn pid_file_matches_pid(path: &Path, pid: u32) -> Result<bool> {
    let contents = match std::fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => {
            return Err(e).with_context(|| format!("Failed to read PID file {}", path.display()))
        }
    };

    let current_pid = contents.trim().parse::<u32>().ok();
    Ok(current_pid == Some(pid))
}

fn systemd_notify_ready(status: &str) -> Result<()> {
    let Some(socket) = std::env::var_os("NOTIFY_SOCKET") else {
        return Ok(());
    };

    let pid = std::process::id().to_string();
    systemd_notify(
        socket.as_os_str(),
        &[
            ("READY", "1"),
            ("MAINPID", pid.as_str()),
            ("STATUS", status),
        ],
    )
}

fn systemd_notify(socket: &OsStr, fields: &[(&str, &str)]) -> Result<()> {
    let payload = fields
        .iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join("\n");

    let bytes = payload.as_bytes();

    if socket.as_bytes().first() == Some(&b'@') {
        systemd_notify_abstract(socket, bytes)
    } else {
        let sock = UnixDatagram::unbound().context("Failed to create notify socket")?;
        sock.send_to(bytes, Path::new(socket)).with_context(|| {
            format!(
                "Failed to send systemd notification to {}",
                Path::new(socket).display()
            )
        })?;
        Ok(())
    }
}

fn systemd_notify_abstract(socket: &OsStr, payload: &[u8]) -> Result<()> {
    use std::os::fd::AsRawFd;

    let socket_bytes = socket.as_bytes();
    let name = socket_bytes
        .get(1..)
        .ok_or_else(|| anyhow::anyhow!("invalid abstract notify socket"))?;

    if name.len() + 2 > std::mem::size_of::<libc::sockaddr_un>() {
        anyhow::bail!("abstract notify socket path is too long");
    }

    let mut addr = unsafe { std::mem::zeroed::<libc::sockaddr_un>() };
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;

    for (slot, byte) in addr.sun_path.iter_mut().skip(1).zip(name.iter()) {
        *slot = *byte as libc::c_char;
    }

    let sock = UnixDatagram::unbound().context("Failed to create notify socket")?;
    let fd = sock.as_raw_fd();
    let addr_len = (std::mem::size_of::<libc::sa_family_t>() + 1 + name.len()) as libc::socklen_t;

    let rc = unsafe {
        libc::sendto(
            fd,
            payload.as_ptr() as *const libc::c_void,
            payload.len(),
            0,
            &addr as *const libc::sockaddr_un as *const libc::sockaddr,
            addr_len,
        )
    };

    if rc < 0 {
        return Err(std::io::Error::last_os_error())
            .context("Failed to send systemd notification")
            .with_context(|| format!("notify socket={}", socket.to_string_lossy()));
    }

    Ok(())
}

/// Compute the HTTPS listen address from the HTTP listen address.
///
/// Port mapping: 80 → 443, anything else → port + 363 (e.g. 8080 → 8443).
fn compute_https_addr(http_addr: SocketAddr) -> SocketAddr {
    let https_port = if http_addr.port() == 80 {
        443
    } else {
        http_addr.port().saturating_add(443 - 80)
    };
    SocketAddr::new(http_addr.ip(), https_port)
}

/// Parse log level string to foundations LogVerbosity
fn parse_verbosity(level: &str) -> LogVerbosity {
    let level = match level.to_lowercase().as_str() {
        "trace" => Level::Trace,
        "debug" => Level::Debug,
        "info" => Level::Info,
        "warn" | "warning" => Level::Warning,
        "error" => Level::Error,
        _ => Level::Info,
    };
    LogVerbosity(level)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── compute_https_addr ────────────────────────────────────────────────────

    #[test]
    fn test_https_addr_port_80_maps_to_443() {
        let addr: SocketAddr = "0.0.0.0:80".parse().unwrap();
        assert_eq!(compute_https_addr(addr), "0.0.0.0:443".parse().unwrap());
    }

    #[test]
    fn test_https_addr_port_8080_maps_to_8443() {
        let addr: SocketAddr = "0.0.0.0:8080".parse().unwrap();
        assert_eq!(compute_https_addr(addr), "0.0.0.0:8443".parse().unwrap());
    }

    #[test]
    fn test_https_addr_ipv6_port_80() {
        let addr: SocketAddr = "[::]:80".parse().unwrap();
        assert_eq!(compute_https_addr(addr), "[::]:443".parse().unwrap());
    }

    #[test]
    fn test_https_addr_ipv6_port_8080() {
        let addr: SocketAddr = "[::1]:8080".parse().unwrap();
        assert_eq!(compute_https_addr(addr), "[::1]:8443".parse().unwrap());
    }

    #[test]
    fn test_https_addr_non_standard_port() {
        // 3000 + 363 = 3363
        let addr: SocketAddr = "127.0.0.1:3000".parse().unwrap();
        assert_eq!(compute_https_addr(addr), "127.0.0.1:3363".parse().unwrap());
    }

    // ── domain candidate extraction order ────────────────────────────────────

    use wicket_core::wicket_tls::{AcmeCertConfig, AcmeConfig, AutoTlsDomain, DnsProviderConfig};

    fn test_dns_provider() -> DnsProviderConfig {
        DnsProviderConfig {
            provider: "cloudflare".to_string(),
            api_token: "token".to_string(),
            api_token_file: None,
            zone_id: None,
        }
    }

    /// Build a minimal AcmeConfig with the given cert domain lists.
    fn make_acme_config(domain_groups: &[&[&str]]) -> AcmeConfig {
        let certs = domain_groups
            .iter()
            .map(|domains| AcmeCertConfig {
                domains: domains.iter().map(|d| d.to_string()).collect(),
                dns: test_dns_provider(),
            })
            .collect();

        AcmeConfig {
            email: "test@example.com".to_string(),
            staging: true,
            storage: PathBuf::from("/tmp/acme-test"),
            renew_before_days: 30,
            certs,
            default_dns: None,
            dns_providers: Default::default(),
        }
    }

    #[test]
    fn test_domain_candidate_order_explicit_certs_first() {
        let acme = make_acme_config(&[&["explicit.example.com"], &["second.example.com"]]);

        // No auto-TLS domains
        let candidates = acme.all_certs_with_providers(&[]);
        assert_eq!(candidates.len(), 2);
        assert_eq!(candidates[0].domains[0], "explicit.example.com");
        assert_eq!(candidates[1].domains[0], "second.example.com");
    }

    #[test]
    fn test_domain_candidate_auto_tls_appended_after_explicit() {
        let mut acme = make_acme_config(&[&["explicit.example.com"]]);
        // Give it a default_dns so auto-TLS domains get included
        acme.default_dns = Some(test_dns_provider());

        let auto_domains = vec![
            AutoTlsDomain {
                domain: "auto1.example.com".to_string(),
                provider: None,
            },
            AutoTlsDomain {
                domain: "auto2.example.com".to_string(),
                provider: None,
            },
        ];

        let candidates = acme.all_certs_with_providers(&auto_domains);
        // explicit first, then auto in order
        assert_eq!(candidates.len(), 3);
        assert_eq!(candidates[0].domains[0], "explicit.example.com");
        assert_eq!(candidates[1].domains[0], "auto1.example.com");
        assert_eq!(candidates[2].domains[0], "auto2.example.com");
    }

    #[test]
    fn test_domain_candidate_already_covered_not_duplicated() {
        let mut acme = make_acme_config(&[&["explicit.example.com"]]);
        acme.default_dns = Some(test_dns_provider());

        // explicit.example.com is already in certs — should not be duplicated
        let auto_domains = vec![AutoTlsDomain {
            domain: "explicit.example.com".to_string(),
            provider: None,
        }];

        let candidates = acme.all_certs_with_providers(&auto_domains);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].domains[0], "explicit.example.com");
    }
}
