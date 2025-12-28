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
use pingora_proxy::http_proxy_service;
use std::path::PathBuf;
use tracing::info;
use wicket_config::Config;
use wicket_core::WicketProxy;

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

fn run_server(config: Config, args: &Args) -> Result<()> {
    info!(
        config_path = %args.config.display(),
        listen = %config.server.listen,
        upstreams = config.upstreams.len(),
        routes = config.routes.len(),
        "Starting Wicket proxy"
    );

    // Create the Pingora server
    let mut server = Server::new(Some(Opt {
        upgrade: false,
        daemon: false,
        nocapture: false,
        test: false,
        conf: None,
    }))?;

    server.bootstrap();

    // Create the proxy service
    let wicket_proxy = WicketProxy::new(&config).context("Failed to create proxy service")?;

    // Create HTTP proxy service
    let mut proxy_service = http_proxy_service(&server.configuration, wicket_proxy);

    // Configure the listener
    proxy_service.add_tcp(&config.server.listen.to_string());

    info!(
        address = %config.server.listen,
        "Proxy listening"
    );

    // Add service to server
    server.add_service(proxy_service);

    // Run the server
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
