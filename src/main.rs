//! Wicket - A Kubernetes Gateway API implementation and reverse proxy built on Pingora.
//!
//! Wicket is designed to be the "Caddy of Gateway API" - simple to configure,
//! observable by default, and fast enough to replace nginx/HAProxy.

mod config;
mod logging;
mod proxy;
mod routing;

use anyhow::{Context, Result};
use clap::Parser;
use config::Config;
use pingora_core::prelude::*;
use pingora_proxy::http_proxy_service;
use proxy::WicketProxy;
use std::path::PathBuf;
use tracing::{error, info};

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
    if let Err(e) = run() {
        error!("Fatal error: {:#}", e);
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let args = Args::parse();

    // Load configuration
    let config = Config::load(&args.config)
        .with_context(|| format!("Failed to load config from {}", args.config.display()))?;

    // Initialize logging (use CLI overrides if provided)
    let log_level = args
        .log_level
        .as_deref()
        .unwrap_or(&config.server.log_level);
    let json_logs = args.json_logs || config.server.json_logs;

    logging::init(json_logs, log_level)?;

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
    let wicket_proxy =
        WicketProxy::new(&config).context("Failed to create proxy service")?;

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
