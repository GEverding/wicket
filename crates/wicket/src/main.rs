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
use pingora_core::services::listening::Service as ListeningService;
use pingora_proxy::http_proxy_service;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::{error, info, warn};
use wicket_config::Config;
use wicket_core::{
    register_metrics as register_proxy_metrics,
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

    /// Prometheus metrics server address
    #[arg(long, default_value = "0.0.0.0:9090")]
    metrics_addr: String,
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

    // Register custom proxy metrics with Prometheus
    // These will automatically appear at the /metrics endpoint
    if let Err(e) = register_proxy_metrics() {
        error!(error = %e, "Failed to register proxy metrics");
    }

    // Register stream proxy metrics (always safe to call; no-op if stream not configured)
    wicket_stream::metrics::register_stream_metrics();

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

    // Create HTTP proxy service
    let mut proxy_service = http_proxy_service(&server.configuration, wicket_proxy);

    // Configure the listener
    proxy_service.add_tcp(&config.server.listen.to_string());

    info!(
        address = %config.server.listen,
        "HTTP proxy listening"
    );

    // Add HTTPS listener if TLS is configured
    if let Some(ref tls_config) = config.tls {
        let https_addr = compute_https_addr(config.server.listen);

        match select_tls_cert(tls_config, &config) {
            Some((cert_path, key_path, source)) => {
                let cert_str = cert_path.to_str().unwrap_or("");
                let key_str = key_path.to_str().unwrap_or("");

                if let Err(e) = proxy_service.add_tls(&https_addr, cert_str, key_str) {
                    error!(
                        error = %e,
                        source = %source,
                        cert = %cert_path.display(),
                        "Failed to configure TLS listener, HTTPS disabled"
                    );
                } else {
                    info!(
                        address = %https_addr,
                        source = %source,
                        cert = %cert_path.display(),
                        "HTTPS proxy listening"
                    );
                }
            }
            None => {
                warn!(
                    "TLS configured but no cert material found (no file certs, no stored ACME certs); \
                     HTTPS listener skipped"
                );
            }
        }
    }

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

/// Compute the HTTPS listen address from the HTTP listen address.
///
/// Port mapping: 80 → 443, anything else → port + 363 (e.g. 8080 → 8443).
fn compute_https_addr(http_addr: SocketAddr) -> String {
    let https_port = if http_addr.port() == 80 {
        443
    } else {
        http_addr.port().saturating_add(363)
    };
    // SocketAddr::to_string() already formats IPv6 with brackets: [::1]:port
    SocketAddr::new(http_addr.ip(), https_port).to_string()
}

/// Select the TLS cert/key source for the HTTPS listener.
///
/// Precedence:
/// 1. First file cert from `tls.file.certs` (if present)
/// 2. First available ACME stored cert for configured domains
///
/// Returns `(cert_path, key_path, source_label)` or `None` if nothing is available.
fn select_tls_cert(
    tls_config: &wicket_core::wicket_tls::TlsConfig,
    config: &Config,
) -> Option<(PathBuf, PathBuf, &'static str)> {
    // 1. File cert takes priority
    if let Some(ref file_config) = tls_config.file {
        if let Some(first) = file_config.certs.first() {
            return Some((first.cert.clone(), first.key.clone(), "file"));
        }
    }

    // 2. ACME stored cert fallback
    if let Some(ref acme_config) = tls_config.acme {
        let auto_tls_domains = config.collect_auto_tls_domains_with_providers();
        let all_certs = acme_config.all_certs_with_providers(&auto_tls_domains);

        for cert_cfg in &all_certs {
            if let Some(primary_domain) = cert_cfg.domains.first() {
                match materialize_acme_cert(acme_config, primary_domain) {
                    Ok(Some((cert_path, key_path))) => {
                        return Some((cert_path, key_path, "acme_storage"));
                    }
                    Ok(None) => continue,
                    Err(e) => {
                        warn!(
                            domain = %primary_domain,
                            error = %e,
                            "Failed to materialize ACME cert for listener"
                        );
                        continue;
                    }
                }
            }
        }
    }

    None
}

/// Read a stored ACME cert/key and write runtime listener files.
///
/// Files are written to `<storage>/runtime-listener/{domain}.cert.pem` and `.key.pem`.
/// Returns `(cert_path, key_path)` if a stored cert exists, `None` if not yet provisioned.
fn materialize_acme_cert(
    acme_config: &wicket_core::wicket_tls::AcmeConfig,
    primary_domain: &str,
) -> Result<Option<(PathBuf, PathBuf)>> {
    use wicket_core::wicket_tls::acme::storage::AcmeStorage;

    let storage = AcmeStorage::new(acme_config.storage.clone()).with_context(|| {
        format!(
            "Failed to open ACME storage at {}",
            acme_config.storage.display()
        )
    })?;

    let stored = match storage.load_cert(primary_domain)? {
        Some(s) => s,
        None => return Ok(None),
    };

    // Write runtime listener files
    let runtime_dir = acme_config.storage.join("runtime-listener");
    std::fs::create_dir_all(&runtime_dir).with_context(|| {
        format!(
            "Failed to create runtime-listener dir: {}",
            runtime_dir.display()
        )
    })?;

    let safe_domain = primary_domain.replace(['/', '\\', '\0'], "_");
    let cert_path = runtime_dir.join(format!("{}.cert.pem", safe_domain));
    let key_path = runtime_dir.join(format!("{}.key.pem", safe_domain));

    write_runtime_file(&cert_path, stored.cert_pem.as_bytes(), 0o644)?;
    write_runtime_file(&key_path, stored.key_pem.as_bytes(), 0o600)?;

    Ok(Some((cert_path, key_path)))
}

/// Write data to a file with the given Unix permissions (atomic via temp file).
fn write_runtime_file(path: &Path, data: &[u8], mode: u32) -> Result<()> {
    use std::io::Write;

    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    let parent = path.parent().unwrap_or(Path::new("."));
    let file_name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "tmp".to_string());
    let tmp_path = parent.join(format!(".{}.tmp", file_name));

    {
        let mut f = std::fs::File::create(&tmp_path)
            .with_context(|| format!("Failed to create temp file: {}", tmp_path.display()))?;

        #[cfg(unix)]
        f.set_permissions(std::fs::Permissions::from_mode(mode))
            .with_context(|| format!("Failed to set permissions on {}", tmp_path.display()))?;

        f.write_all(data)
            .with_context(|| format!("Failed to write to {}", tmp_path.display()))?;
    }

    std::fs::rename(&tmp_path, path).with_context(|| {
        format!(
            "Failed to rename {} to {}",
            tmp_path.display(),
            path.display()
        )
    })?;

    Ok(())
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
        assert_eq!(compute_https_addr(addr), "0.0.0.0:443");
    }

    #[test]
    fn test_https_addr_port_8080_maps_to_8443() {
        let addr: SocketAddr = "0.0.0.0:8080".parse().unwrap();
        assert_eq!(compute_https_addr(addr), "0.0.0.0:8443");
    }

    #[test]
    fn test_https_addr_ipv6_port_80() {
        let addr: SocketAddr = "[::]:80".parse().unwrap();
        assert_eq!(compute_https_addr(addr), "[::]:443");
    }

    #[test]
    fn test_https_addr_ipv6_port_8080() {
        let addr: SocketAddr = "[::1]:8080".parse().unwrap();
        assert_eq!(compute_https_addr(addr), "[::1]:8443");
    }

    #[test]
    fn test_https_addr_non_standard_port() {
        // 3000 + 363 = 3363
        let addr: SocketAddr = "127.0.0.1:3000".parse().unwrap();
        assert_eq!(compute_https_addr(addr), "127.0.0.1:3363");
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
