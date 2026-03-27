//! Prometheus metrics for the Wicket controller.
//!
//! Exposes controller-level metrics following Envoy Gateway patterns.

use lazy_static::lazy_static;
use prometheus::{
    GaugeVec, HistogramOpts, HistogramVec, IntCounterVec, IntGauge, IntGaugeVec, Opts, Registry,
};

lazy_static! {
    /// Global Prometheus registry for controller metrics.
    pub static ref REGISTRY: Registry = Registry::new();

    // ============================================================
    // Resource Counts
    // ============================================================

    /// Number of GatewayClass resources.
    pub static ref GATEWAY_CLASSES: IntGauge = IntGauge::new(
        "wicket_gateway_classes",
        "Number of GatewayClass resources"
    ).expect("metric can be created");

    /// Number of Gateway resources by namespace and class.
    pub static ref GATEWAYS: IntGaugeVec = IntGaugeVec::new(
        Opts::new("wicket_gateways", "Number of Gateway resources"),
        &["namespace", "gateway_class"]
    ).expect("metric can be created");

    /// Number of HTTPRoute resources by namespace.
    pub static ref HTTPROUTES: IntGaugeVec = IntGaugeVec::new(
        Opts::new("wicket_httproutes", "Number of HTTPRoute resources"),
        &["namespace"]
    ).expect("metric can be created");

    /// Number of TCPRoute resources by namespace.
    pub static ref TCPROUTES: IntGaugeVec = IntGaugeVec::new(
        Opts::new("wicket_tcproutes", "Number of TCPRoute resources"),
        &["namespace"]
    ).expect("metric can be created");

    /// Number of TLSRoute resources by namespace.
    pub static ref TLSROUTES: IntGaugeVec = IntGaugeVec::new(
        Opts::new("wicket_tlsroutes", "Number of TLSRoute resources"),
        &["namespace"]
    ).expect("metric can be created");

    /// Number of ReferenceGrant resources by namespace.
    pub static ref REFERENCE_GRANTS: IntGaugeVec = IntGaugeVec::new(
        Opts::new("wicket_reference_grants", "Number of ReferenceGrant resources"),
        &["namespace"]
    ).expect("metric can be created");

    // ============================================================
    // Reconciliation Metrics
    // ============================================================

    /// Total reconciliation attempts by resource type and result.
    pub static ref RECONCILE_TOTAL: IntCounterVec = IntCounterVec::new(
        Opts::new("wicket_reconcile_total", "Total number of reconciliation attempts"),
        &["resource_type", "result"]
    ).expect("metric can be created");

    /// Reconciliation duration histogram by resource type.
    pub static ref RECONCILE_DURATION_SECONDS: HistogramVec = HistogramVec::new(
        HistogramOpts::new(
            "wicket_reconcile_duration_seconds",
            "Time spent in reconciliation"
        ).buckets(vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]),
        &["resource_type"]
    ).expect("metric can be created");

    /// Number of reconciliation errors by resource type and error type.
    pub static ref RECONCILE_ERRORS_TOTAL: IntCounterVec = IntCounterVec::new(
        Opts::new("wicket_reconcile_errors_total", "Total number of reconciliation errors"),
        &["resource_type", "error_type"]
    ).expect("metric can be created");

    /// Current queue depth for reconciliation.
    pub static ref RECONCILE_QUEUE_DEPTH: IntGaugeVec = IntGaugeVec::new(
        Opts::new("wicket_reconcile_queue_depth", "Current depth of reconciliation queue"),
        &["resource_type"]
    ).expect("metric can be created");

    // ============================================================
    // Backend/Service Metrics
    // ============================================================

    /// Number of backend services being watched.
    pub static ref BACKENDS: IntGaugeVec = IntGaugeVec::new(
        Opts::new("wicket_backends", "Number of backend services"),
        &["namespace"]
    ).expect("metric can be created");

    /// Number of healthy endpoints per service.
    pub static ref BACKEND_ENDPOINTS_HEALTHY: IntGaugeVec = IntGaugeVec::new(
        Opts::new("wicket_backend_endpoints_healthy", "Number of healthy endpoints per backend"),
        &["namespace", "service"]
    ).expect("metric can be created");

    /// Number of unhealthy endpoints per service.
    pub static ref BACKEND_ENDPOINTS_UNHEALTHY: IntGaugeVec = IntGaugeVec::new(
        Opts::new("wicket_backend_endpoints_unhealthy", "Number of unhealthy endpoints per backend"),
        &["namespace", "service"]
    ).expect("metric can be created");

    // ============================================================
    // Configuration Metrics
    // ============================================================

    /// Total configuration updates.
    pub static ref CONFIG_UPDATES_TOTAL: IntCounterVec = IntCounterVec::new(
        Opts::new("wicket_config_updates_total", "Total number of configuration updates"),
        &["result"]
    ).expect("metric can be created");

    /// Time since last successful configuration update.
    pub static ref CONFIG_LAST_UPDATE_TIMESTAMP: IntGauge = IntGauge::new(
        "wicket_config_last_update_timestamp_seconds",
        "Unix timestamp of last successful configuration update"
    ).expect("metric can be created");

    /// Current configuration generation/version.
    pub static ref CONFIG_GENERATION: IntGauge = IntGauge::new(
        "wicket_controller_config_generation",
        "Current controller configuration generation"
    ).expect("metric can be created");

    // ============================================================
    // TLS/Certificate Metrics
    // ============================================================

    /// Number of TLS certificates being managed.
    pub static ref TLS_CERTIFICATES: IntGaugeVec = IntGaugeVec::new(
        Opts::new("wicket_tls_certificates", "Number of TLS certificates"),
        &["namespace", "type"]
    ).expect("metric can be created");

    /// Certificate expiration time (Unix timestamp).
    pub static ref TLS_CERTIFICATE_EXPIRY_TIMESTAMP: GaugeVec = GaugeVec::new(
        Opts::new("wicket_tls_certificate_expiry_timestamp_seconds", "Certificate expiration Unix timestamp"),
        &["namespace", "name"]
    ).expect("metric can be created");

    // ============================================================
    // Controller Health
    // ============================================================

    /// Whether the controller is the leader (1 = leader, 0 = not leader).
    pub static ref CONTROLLER_IS_LEADER: IntGauge = IntGauge::new(
        "wicket_controller_is_leader",
        "Whether this controller instance is the leader"
    ).expect("metric can be created");

    /// Controller uptime in seconds.
    pub static ref CONTROLLER_UPTIME_SECONDS: IntGauge = IntGauge::new(
        "wicket_controller_uptime_seconds",
        "Controller uptime in seconds"
    ).expect("metric can be created");

    /// Kubernetes API request duration.
    pub static ref K8S_API_DURATION_SECONDS: HistogramVec = HistogramVec::new(
        HistogramOpts::new(
            "wicket_k8s_api_duration_seconds",
            "Kubernetes API request duration"
        ).buckets(vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0]),
        &["operation", "resource"]
    ).expect("metric can be created");

    /// Kubernetes API errors.
    pub static ref K8S_API_ERRORS_TOTAL: IntCounterVec = IntCounterVec::new(
        Opts::new("wicket_k8s_api_errors_total", "Total Kubernetes API errors"),
        &["operation", "resource", "error_type"]
    ).expect("metric can be created");

    // ============================================================
    // TLS Secret Metrics (RED pattern)
    // ============================================================

    /// TLS secret extraction attempts (Rate).
    pub static ref TLS_SECRET_EXTRACTIONS_TOTAL: IntCounterVec = IntCounterVec::new(
        Opts::new("wicket_tls_secret_extractions_total", "Total TLS secret extraction attempts"),
        &["namespace", "result"]
    ).expect("metric can be created");

    /// TLS secret extraction duration (Duration).
    pub static ref TLS_SECRET_EXTRACTION_DURATION_SECONDS: HistogramVec = HistogramVec::new(
        HistogramOpts::new(
            "wicket_tls_secret_extraction_duration_seconds",
            "Time to extract TLS secrets from Kubernetes"
        ).buckets(vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0]),
        &["namespace"]
    ).expect("metric can be created");

    /// ReferenceGrant validation attempts.
    pub static ref REFERENCE_GRANT_VALIDATIONS_TOTAL: IntCounterVec = IntCounterVec::new(
        Opts::new("wicket_reference_grant_validations_total", "Total ReferenceGrant validation attempts"),
        &["from_namespace", "to_namespace", "result"]
    ).expect("metric can be created");

    /// Cross-namespace references blocked (Errors - security metric).
    pub static ref CROSS_NAMESPACE_BLOCKED_TOTAL: IntCounterVec = IntCounterVec::new(
        Opts::new("wicket_cross_namespace_blocked_total", "Cross-namespace references blocked by missing ReferenceGrant"),
        &["from_namespace", "to_namespace", "resource_type"]
    ).expect("metric can be created");

    // ============================================================
    // Gateway Status Metrics
    // ============================================================

    /// Gateway programmed status (1 = programmed, 0 = not programmed).
    pub static ref GATEWAY_PROGRAMMED: IntGaugeVec = IntGaugeVec::new(
        Opts::new("wicket_gateway_programmed", "Whether gateway is programmed and ready"),
        &["namespace", "name"]
    ).expect("metric can be created");

    /// Gateway listener status.
    pub static ref GATEWAY_LISTENER_ATTACHED_ROUTES: IntGaugeVec = IntGaugeVec::new(
        Opts::new("wicket_gateway_listener_attached_routes", "Number of routes attached to listener"),
        &["namespace", "gateway", "listener"]
    ).expect("metric can be created");

    // ============================================================
    // Route Status Metrics
    // ============================================================

    /// Routes accepted by parent gateway.
    pub static ref ROUTES_ACCEPTED: IntGaugeVec = IntGaugeVec::new(
        Opts::new("wicket_routes_accepted", "Routes accepted by parent gateway"),
        &["namespace", "route_type", "gateway"]
    ).expect("metric can be created");

    /// Routes rejected (validation failures, no matching gateway, etc).
    pub static ref ROUTES_REJECTED_TOTAL: IntCounterVec = IntCounterVec::new(
        Opts::new("wicket_routes_rejected_total", "Routes rejected"),
        &["namespace", "route_type", "reason"]
    ).expect("metric can be created");

    // ============================================================
    // Config Sync Metrics (critical for controller health)
    // ============================================================

    /// Config sync lag - time since last successful sync.
    pub static ref CONFIG_SYNC_LAG_SECONDS: IntGauge = IntGauge::new(
        "wicket_config_sync_lag_seconds",
        "Seconds since last successful config synchronization"
    ).expect("metric can be created");

    /// Config hash for detecting drift.
    pub static ref CONFIG_HASH: IntGauge = IntGauge::new(
        "wicket_config_hash",
        "Hash of current configuration for drift detection"
    ).expect("metric can be created");

    /// Number of resources pending reconciliation.
    pub static ref RESOURCES_PENDING_SYNC: IntGaugeVec = IntGaugeVec::new(
        Opts::new("wicket_resources_pending_sync", "Resources waiting to be synchronized"),
        &["resource_type"]
    ).expect("metric can be created");

    // ============================================================
    // Watch/Informer Metrics
    // ============================================================

    /// Watch connection status per resource type.
    pub static ref WATCH_CONNECTIONS_ACTIVE: IntGaugeVec = IntGaugeVec::new(
        Opts::new("wicket_watch_connections_active", "Active watch connections"),
        &["resource_type"]
    ).expect("metric can be created");

    /// Watch errors requiring reconnection.
    pub static ref WATCH_ERRORS_TOTAL: IntCounterVec = IntCounterVec::new(
        Opts::new("wicket_watch_errors_total", "Watch connection errors"),
        &["resource_type", "error_type"]
    ).expect("metric can be created");

    /// Events received from watches.
    pub static ref WATCH_EVENTS_TOTAL: IntCounterVec = IntCounterVec::new(
        Opts::new("wicket_watch_events_total", "Events received from Kubernetes watches"),
        &["resource_type", "event_type"]
    ).expect("metric can be created");
}

/// Register all metrics with the global registry.
pub fn register_metrics() -> Result<(), prometheus::Error> {
    REGISTRY.register(Box::new(GATEWAY_CLASSES.clone()))?;
    REGISTRY.register(Box::new(GATEWAYS.clone()))?;
    REGISTRY.register(Box::new(HTTPROUTES.clone()))?;
    REGISTRY.register(Box::new(TCPROUTES.clone()))?;
    REGISTRY.register(Box::new(TLSROUTES.clone()))?;
    REGISTRY.register(Box::new(REFERENCE_GRANTS.clone()))?;
    REGISTRY.register(Box::new(RECONCILE_TOTAL.clone()))?;
    REGISTRY.register(Box::new(RECONCILE_DURATION_SECONDS.clone()))?;
    REGISTRY.register(Box::new(RECONCILE_ERRORS_TOTAL.clone()))?;
    REGISTRY.register(Box::new(RECONCILE_QUEUE_DEPTH.clone()))?;
    REGISTRY.register(Box::new(BACKENDS.clone()))?;
    REGISTRY.register(Box::new(BACKEND_ENDPOINTS_HEALTHY.clone()))?;
    REGISTRY.register(Box::new(BACKEND_ENDPOINTS_UNHEALTHY.clone()))?;
    REGISTRY.register(Box::new(CONFIG_UPDATES_TOTAL.clone()))?;
    REGISTRY.register(Box::new(CONFIG_LAST_UPDATE_TIMESTAMP.clone()))?;
    REGISTRY.register(Box::new(CONFIG_GENERATION.clone()))?;
    REGISTRY.register(Box::new(TLS_CERTIFICATES.clone()))?;
    REGISTRY.register(Box::new(TLS_CERTIFICATE_EXPIRY_TIMESTAMP.clone()))?;
    REGISTRY.register(Box::new(CONTROLLER_IS_LEADER.clone()))?;
    REGISTRY.register(Box::new(CONTROLLER_UPTIME_SECONDS.clone()))?;
    REGISTRY.register(Box::new(K8S_API_DURATION_SECONDS.clone()))?;
    REGISTRY.register(Box::new(K8S_API_ERRORS_TOTAL.clone()))?;

    // TLS Secret metrics
    REGISTRY.register(Box::new(TLS_SECRET_EXTRACTIONS_TOTAL.clone()))?;
    REGISTRY.register(Box::new(TLS_SECRET_EXTRACTION_DURATION_SECONDS.clone()))?;
    REGISTRY.register(Box::new(REFERENCE_GRANT_VALIDATIONS_TOTAL.clone()))?;
    REGISTRY.register(Box::new(CROSS_NAMESPACE_BLOCKED_TOTAL.clone()))?;

    // Gateway status metrics
    REGISTRY.register(Box::new(GATEWAY_PROGRAMMED.clone()))?;
    REGISTRY.register(Box::new(GATEWAY_LISTENER_ATTACHED_ROUTES.clone()))?;

    // Route status metrics
    REGISTRY.register(Box::new(ROUTES_ACCEPTED.clone()))?;
    REGISTRY.register(Box::new(ROUTES_REJECTED_TOTAL.clone()))?;

    // Config sync metrics
    REGISTRY.register(Box::new(CONFIG_SYNC_LAG_SECONDS.clone()))?;
    REGISTRY.register(Box::new(CONFIG_HASH.clone()))?;
    REGISTRY.register(Box::new(RESOURCES_PENDING_SYNC.clone()))?;

    // Watch metrics
    REGISTRY.register(Box::new(WATCH_CONNECTIONS_ACTIVE.clone()))?;
    REGISTRY.register(Box::new(WATCH_ERRORS_TOTAL.clone()))?;
    REGISTRY.register(Box::new(WATCH_EVENTS_TOTAL.clone()))?;

    Ok(())
}

/// Helper to record reconciliation metrics.
pub struct ReconcileMetrics {
    resource_type: String,
    start_time: std::time::Instant,
}

impl ReconcileMetrics {
    pub fn new(resource_type: &str) -> Self {
        Self {
            resource_type: resource_type.to_string(),
            start_time: std::time::Instant::now(),
        }
    }

    pub fn record_success(self) {
        let duration = self.start_time.elapsed().as_secs_f64();
        RECONCILE_TOTAL
            .with_label_values(&[&self.resource_type, "success"])
            .inc();
        RECONCILE_DURATION_SECONDS
            .with_label_values(&[&self.resource_type])
            .observe(duration);
    }

    pub fn record_error(self, error_type: &str) {
        let duration = self.start_time.elapsed().as_secs_f64();
        RECONCILE_TOTAL
            .with_label_values(&[&self.resource_type, "error"])
            .inc();
        RECONCILE_DURATION_SECONDS
            .with_label_values(&[&self.resource_type])
            .observe(duration);
        RECONCILE_ERRORS_TOTAL
            .with_label_values(&[&self.resource_type, error_type])
            .inc();
    }

    pub fn record_requeue(self) {
        let duration = self.start_time.elapsed().as_secs_f64();
        RECONCILE_TOTAL
            .with_label_values(&[&self.resource_type, "requeue"])
            .inc();
        RECONCILE_DURATION_SECONDS
            .with_label_values(&[&self.resource_type])
            .observe(duration);
    }
}

/// Serve Prometheus metrics on an HTTP endpoint.
pub async fn serve_metrics(
    addr: std::net::SocketAddr,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use axum::{routing::get, Router};

    async fn metrics_handler() -> String {
        use prometheus::Encoder;
        let encoder = prometheus::TextEncoder::new();
        let metric_families = REGISTRY.gather();
        let mut buffer = Vec::new();
        encoder.encode(&metric_families, &mut buffer).unwrap();
        String::from_utf8(buffer).unwrap()
    }

    async fn health_handler() -> &'static str {
        "ok"
    }

    async fn ready_handler() -> &'static str {
        "ready"
    }

    let app = Router::new()
        .route("/metrics", get(metrics_handler))
        .route("/healthz", get(health_handler))
        .route("/readyz", get(ready_handler));

    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("Metrics server listening on {}", addr);
    axum::serve(listener, app).await?;
    Ok(())
}
