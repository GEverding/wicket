//! Wicket Kubernetes Gateway API Controller
//!
//! This binary runs the Kubernetes controller that watches Gateway API resources
//! and generates Wicket configuration.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use kube::Client;
use tokio::signal;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use wicket_controller::{
    leader_election::{LeaderElection, LeaderElectionConfig},
    metrics::{
        register_metrics, serve_metrics, CONFIG_SYNC_LAG_SECONDS, CONTROLLER_IS_LEADER,
        CONTROLLER_UPTIME_SECONDS,
    },
    reconcilers::{
        contracts::ServiceType, run_endpoints_controller, run_gateway_class_controller,
        run_gateway_controller, run_httproute_controller, run_referencegrant_controller,
        run_secret_controller, run_service_controller, run_tcproute_controller,
        run_tlsroute_controller, runtime_plan::ControllerConfig, Context, DEFAULT_TLS_CERT_DIR,
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
    #[arg(long, default_value = "true", action = clap::ArgAction::Set)]
    watch_all_namespaces: bool,

    /// Name of the ConfigMap to update with proxy configuration
    #[arg(long, default_value = "wicket-proxy-config")]
    config_configmap_name: String,

    /// Namespace of the ConfigMap to update (defaults to controller namespace)
    #[arg(long)]
    config_configmap_namespace: Option<String>,

    /// Log level (trace, debug, info, warn, error)
    #[arg(long, short = 'l', default_value = "info")]
    log_level: String,

    /// Enable JSON log format
    #[arg(long)]
    json_logs: bool,

    /// Enable leader election (for HA deployments)
    #[arg(long, default_value = "true", action = clap::ArgAction::Set)]
    leader_election: bool,

    /// Leader election lease name
    #[arg(long, default_value = "wicket-controller-leader")]
    leader_election_name: String,

    // ── Managed-runtime defaults ──────────────────────────────────────────────
    /// Container image for managed proxy Deployments.
    #[arg(
        long,
        env = "WICKET_PROXY_IMAGE",
        default_value = "ghcr.io/geverding/wicket:latest"
    )]
    proxy_image: String,

    /// Default replica count for managed proxy Deployments (>= 1, <= i32::MAX).
    #[arg(long, env = "WICKET_DEFAULT_REPLICAS", default_value = "1")]
    default_replicas: u32,

    /// Default service type for managed Services (ClusterIP, LoadBalancer, NodePort).
    #[arg(long, env = "WICKET_DEFAULT_SERVICE_TYPE", default_value = "ClusterIP")]
    default_service_type: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Install rustls crypto provider before kube client initialization
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    let args = Args::parse();

    // Initialize logging
    init_logging(&args.log_level, args.json_logs)?;

    // ── Validate and build ControllerConfig ───────────────────────────────────
    // Parse service type fail-fast: do not silently default on an invalid value.
    let default_service_type: ServiceType =
        args.default_service_type.parse().map_err(|e: String| {
            anyhow::anyhow!(
                "--default-service-type / WICKET_DEFAULT_SERVICE_TYPE: {}",
                e
            )
        })?;

    // Validate replicas via the explicit constructor (>= 1, <= i32::MAX).
    let controller_config = ControllerConfig::new(
        args.proxy_image.clone(),
        args.default_replicas,
        default_service_type,
    )
    .map_err(|e| anyhow::anyhow!("invalid managed-runtime defaults: {}", e))?;

    // Determine ConfigMap namespace (default to controller namespace)
    let config_configmap_namespace = args
        .config_configmap_namespace
        .clone()
        .unwrap_or_else(|| args.namespace.clone());

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        namespace = %args.namespace,
        watch_all_namespaces = args.watch_all_namespaces,
        config_configmap_name = %args.config_configmap_name,
        config_configmap_namespace = %config_configmap_namespace,
        "Starting Wicket Gateway API Controller"
    );

    // Log effective managed-runtime defaults for operability.
    tracing::info!(
        proxy_image = %controller_config.proxy_image,
        default_replicas = controller_config.default_replicas,
        default_service_type = %controller_config.default_service_type,
        "Managed-runtime defaults"
    );

    // Register Prometheus metrics
    register_metrics().expect("Failed to register metrics");

    // Create Kubernetes client
    let client = Client::try_default().await?;
    tracing::info!("Connected to Kubernetes API server");

    // Create shared context with explicit managed-runtime config.
    let ctx = Arc::new(Context::with_controller_config(
        client.clone(),
        args.namespace.clone(),
        args.watch_all_namespaces,
        args.config_configmap_name.clone(),
        config_configmap_namespace.clone(),
        DEFAULT_TLS_CERT_DIR.to_string(),
        controller_config,
    ));

    // Set up leader election if enabled
    let is_leader = Arc::new(AtomicBool::new(false));
    let _is_leader_clone = is_leader.clone();

    if args.leader_election {
        // Get pod name from environment (set by Kubernetes downward API)
        let holder_id = std::env::var("POD_NAME").unwrap_or_else(|_| {
            // Fallback to hostname if POD_NAME not set
            hostname::get()
                .map(|h| h.to_string_lossy().to_string())
                .unwrap_or_else(|_| format!("wicket-controller-{}", std::process::id()))
        });

        tracing::info!(
            lease_name = %args.leader_election_name,
            holder_id = %holder_id,
            namespace = %args.namespace,
            "Starting leader election"
        );

        let config = LeaderElectionConfig {
            lease_name: args.leader_election_name.clone(),
            namespace: args.namespace.clone(),
            holder_identity: holder_id,
            lease_duration: Duration::from_secs(15),
            retry_period: Duration::from_secs(2),
            renew_deadline: Duration::from_secs(10),
        };
        let leader_election = LeaderElection::new(client.clone(), config);

        // Spawn leader election task
        let is_leader_election = is_leader.clone();
        tokio::spawn(async move {
            loop {
                match leader_election.try_acquire_or_renew().await {
                    Ok(state) => {
                        let was_leader = is_leader_election.load(Ordering::Relaxed);
                        let now_leader = state.is_leader;

                        if now_leader && !was_leader {
                            tracing::info!("Acquired leadership");
                        } else if !now_leader && was_leader {
                            tracing::warn!(
                                current_holder = ?state.holder,
                                "Lost leadership"
                            );
                        }

                        is_leader_election.store(now_leader, Ordering::Relaxed);
                        CONTROLLER_IS_LEADER.set(if now_leader { 1 } else { 0 });
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "Leader election error");
                        is_leader_election.store(false, Ordering::Relaxed);
                        CONTROLLER_IS_LEADER.set(0);
                    }
                }
                // Renew every 5 seconds (lease TTL is 15 seconds)
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        });

        // Wait for initial leader election
        tracing::info!("Waiting for leader election...");
        tokio::time::sleep(Duration::from_secs(1)).await;
    } else {
        // Leader election disabled - act as leader
        tracing::info!("Leader election disabled, acting as leader");
        is_leader.store(true, Ordering::Relaxed);
        CONTROLLER_IS_LEADER.set(1);
    }

    // Track uptime and config sync lag
    let start_time = std::time::Instant::now();
    tokio::spawn(async move {
        let mut last_config_generation: i64 = 0;
        let mut last_config_update_time = std::time::Instant::now();

        loop {
            CONTROLLER_UPTIME_SECONDS.set(start_time.elapsed().as_secs() as i64);

            // Check if config has been updated by comparing generation
            let current_generation = wicket_controller::metrics::CONFIG_GENERATION.get();
            if current_generation != last_config_generation {
                last_config_generation = current_generation;
                last_config_update_time = std::time::Instant::now();
            }

            // Track time since last successful config sync
            CONFIG_SYNC_LAG_SECONDS.set(last_config_update_time.elapsed().as_secs() as i64);

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
    let http_route_ctx = ctx.clone();
    let tcp_route_ctx = ctx.clone();
    let tls_route_ctx = ctx.clone();
    let endpoints_ctx = ctx.clone();
    let service_ctx = ctx.clone();
    let secret_ctx = ctx.clone();
    let refgrant_ctx = ctx.clone();

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
        result = run_httproute_controller(http_route_ctx) => {
            if let Err(e) = result {
                tracing::error!(error = %e, "HTTPRoute controller failed");
            }
        }
        result = run_tcproute_controller(tcp_route_ctx) => {
            if let Err(e) = result {
                tracing::error!(error = %e, "TCPRoute controller failed");
            }
        }
        result = run_tlsroute_controller(tls_route_ctx) => {
            if let Err(e) = result {
                tracing::error!(error = %e, "TLSRoute controller failed");
            }
        }
        result = run_endpoints_controller(endpoints_ctx) => {
            if let Err(e) = result {
                tracing::error!(error = %e, "Endpoints controller failed");
            }
        }
        result = run_service_controller(service_ctx) => {
            if let Err(e) = result {
                tracing::error!(error = %e, "Service controller failed");
            }
        }
        result = run_secret_controller(secret_ctx) => {
            if let Err(e) = result {
                tracing::error!(error = %e, "Secret controller failed");
            }
        }
        result = run_referencegrant_controller(refgrant_ctx) => {
            if let Err(e) = result {
                tracing::error!(error = %e, "ReferenceGrant controller failed");
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
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));

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
