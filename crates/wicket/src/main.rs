//! Wicket - A Kubernetes Gateway API implementation and reverse proxy built on Pingora.
//!
//! Wicket is designed to be the "Caddy of Gateway API" - simple to configure,
//! observable by default, and fast enough to replace nginx/HAProxy.

use anyhow::{Context, Result};
use clap::Parser;
use foundations::telemetry::settings::{
    Level, LogFormat, LogVerbosity, LoggingSettings, TelemetrySettings,
};
use foundations::telemetry::{self};
use foundations::{service_info, BootstrapResult};
use pingora_core::prelude::*;
use pingora_core::server::configuration::ServerConf;
use pingora_proxy::http_proxy_service;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{error, info};
use wicket_config::Config;
use wicket_core::{
    wicket_tls::{AcmeConfig, AcmeProvider, CertManager, FileWatcher, TlsMode},
    WicketProxy,
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
}

fn main() {
    // Bootstrap with foundations for telemetry
    if let Err(e) = bootstrap() {
        eprintln!("Fatal error: {:#}", e);
        std::process::exit(1);
    }
}

fn bootstrap() -> BootstrapResult<()> {
    let args = Args::parse();

    // Load configuration first to get log settings
    let config = Config::load(&args.config)
        .with_context(|| format!("Failed to load config from {}", args.config.display()))?;

    // Initialize foundations telemetry
    let log_level = args
        .log_level
        .as_deref()
        .unwrap_or(&config.server.log_level);
    let json_logs = args.json_logs || config.server.json_logs;

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

    // Initialize telemetry
    telemetry::init(&service_info, &telemetry_settings)?;

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
        AcmeProvider::with_auto_tls_domains_and_providers(
            acme_config.clone(),
            manager.clone(),
            auto_tls_domains,
        )
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

    // Create a runtime for async TLS operations (ACME)
    // We need this before Pingora takes over the main thread
    let tls_runtime = tokio::runtime::Runtime::new().context("Failed to create TLS runtime")?;

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

    // Wire up graceful shutdown timeout
    pingora_conf.graceful_shutdown_timeout_seconds = Some(config.server.shutdown_timeout);

    // Create the Pingora server with our configuration
    let mut server = Server::new_with_opt_and_conf(
        Some(Opt {
            upgrade: false,
            daemon: false,
            nocapture: false,
            test: false,
            conf: None,
        }),
        pingora_conf,
    );

    server.bootstrap();

    // Create the proxy service
    let mut wicket_proxy = WicketProxy::new(&config).context("Failed to create proxy service")?;

    // Wire up TLS if enabled
    if let Some(ref cm) = cert_manager {
        wicket_proxy = wicket_proxy.with_cert_manager(cm.clone());
        info!("TLS certificate manager wired to proxy");
    }

    // Create HTTP proxy service
    let mut proxy_service = http_proxy_service(&server.configuration, wicket_proxy);

    // Configure the listener
    proxy_service.add_tcp(&config.server.listen.to_string());

    info!(
        address = %config.server.listen,
        "Proxy listening"
    );

    // TODO: Add HTTPS listener if TLS is enabled
    // This requires understanding Pingora's TLS listener API
    // The CertManager implements rustls::server::ResolvesServerCert
    // and can be passed to rustls ServerConfig for HTTPS support

    // Add service to server
    server.add_service(proxy_service);

    // Optionally start stream proxy
    if let Some(ref stream_config) = config.stream {
        let stream_proxy = Arc::new(
            StreamProxy::from_config(stream_config).context("Failed to build stream proxy")?,
        );

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

        let proxy = Arc::clone(&stream_proxy);
        tokio::spawn(async move {
            if let Err(e) = proxy.run(listener).await {
                error!(error = %e, "Stream proxy error");
            }
        });
    }

    // Run the server (blocks until shutdown)
    server.run_forever();
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
