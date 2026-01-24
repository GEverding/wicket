//! Wicket Kubernetes Gateway API Controller
//!
//! This binary runs the Kubernetes controller that watches Gateway API resources
//! and generates Wicket configuration.

use std::net::SocketAddr;
use std::sync::Arc;

use clap::Parser;
use kube::Client;
use tokio::signal;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use wicket_controller::{
    metrics::{register_metrics, serve_metrics, CONTROLLER_IS_LEADER, CONTROLLER_UPTIME_SECONDS},
    reconcilers::{
        run_endpoints_controller, run_gateway_class_controller, run_gateway_controller,
        run_httproute_controller, run_secret_controller, Context,
    },
};

/// Wicket Gateway API Controller
#[derive(Parser, Debug)]
#[command(name = "wicket-controller")]
#[command(about = "Kubernetes Gateway API controller for Wicket")]
#[command(version)]
struct Args {
    /// Metrics server listen address
    #[arg(long, default_value = "0.0.0.0:8081")]
    metrics_addr: SocketAddr,

    /// Namespace the controller is deployed in
    #[arg(long, env = "POD_NAMESPACE", default_value = "wicket-system")]
    namespace: String,

    /// Watch all namespaces (if false, only watches controller namespace)
    #[arg(long, default_value = "true")]
    watch_all_namespaces: bool,

    /// Path to write generated Wicket configuration
    #[arg(long, default_value = "/etc/wicket/wicket.toml")]
    config_output: String,

    /// Log level (trace, debug, info, warn, error)
    #[arg(long, short = 'l', default_value = "info")]
    log_level: String,

    /// Enable JSON log format
    #[arg(long)]
    json_logs: bool,

    /// Enable leader election (for HA deployments)
    #[arg(long, default_value = "true")]
    leader_election: bool,

    /// Leader election lease name
    #[arg(long, default_value = "wicket-controller-leader")]
    leader_election_name: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // Initialize logging
    init_logging(&args.log_level, args.json_logs)?;

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        namespace = %args.namespace,
        watch_all_namespaces = args.watch_all_namespaces,
        config_output = %args.config_output,
        "Starting Wicket Gateway API Controller"
    );

    // Register Prometheus metrics
    register_metrics().expect("Failed to register metrics");

    // Create Kubernetes client
    let client = Client::try_default().await?;
    tracing::info!("Connected to Kubernetes API server");

    // Create shared context
    let ctx = Arc::new(Context::new(
        client.clone(),
        args.namespace.clone(),
        args.watch_all_namespaces,
        args.config_output.clone(),
    ));

    // Mark as leader (simplified - in production use proper leader election)
    CONTROLLER_IS_LEADER.set(1);

    // Track uptime
    let start_time = std::time::Instant::now();
    let uptime_ctx = ctx.clone();
    tokio::spawn(async move {
        loop {
            CONTROLLER_UPTIME_SECONDS.set(start_time.elapsed().as_secs() as i64);
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
    });

    // Start metrics server
    let metrics_addr = args.metrics_addr;
    tokio::spawn(async move {
        if let Err(e) = serve_metrics(metrics_addr).await {
            tracing::error!(error = %e, "Metrics server failed");
        }
    });
    tracing::info!(addr = %args.metrics_addr, "Metrics server started");

    // Run all controllers concurrently
    tracing::info!("Starting controllers");

    let gc_ctx = ctx.clone();
    let gw_ctx = ctx.clone();
    let route_ctx = ctx.clone();
    let endpoints_ctx = ctx.clone();
    let secret_ctx = ctx.clone();

    tokio::select! {
        result = run_gateway_class_controller(gc_ctx) => {
            if let Err(e) = result {
                tracing::error!(error = %e, "GatewayClass controller failed");
            }
        }
        result = run_gateway_controller(gw_ctx) => {
            if let Err(e) = result {
                tracing::error!(error = %e, "Gateway controller failed");
            }
        }
        result = run_httproute_controller(route_ctx) => {
            if let Err(e) = result {
                tracing::error!(error = %e, "HTTPRoute controller failed");
            }
        }
        result = run_endpoints_controller(endpoints_ctx) => {
            if let Err(e) = result {
                tracing::error!(error = %e, "Endpoints controller failed");
            }
        }
        result = run_secret_controller(secret_ctx) => {
            if let Err(e) = result {
                tracing::error!(error = %e, "Secret controller failed");
            }
        }
        _ = shutdown_signal() => {
            tracing::info!("Received shutdown signal");
        }
    }

    tracing::info!("Wicket controller shutting down");
    Ok(())
}

/// Initialize logging with the specified level and format.
fn init_logging(level: &str, json: bool) -> anyhow::Result<()> {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(level));

    if json {
        tracing_subscriber::registry()
            .with(filter)
            .with(tracing_subscriber::fmt::layer().json())
            .init();
    } else {
        tracing_subscriber::registry()
            .with(filter)
            .with(tracing_subscriber::fmt::layer())
            .init();
    }

    Ok(())
}

/// Wait for shutdown signal (SIGTERM or SIGINT).
async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
