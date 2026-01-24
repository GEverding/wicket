//! Prometheus metrics for the Wicket controller.
//!
//! Exposes controller-level metrics following Envoy Gateway patterns.

use lazy_static::lazy_static;
use prometheus::{
    Counter, CounterVec, Gauge, GaugeVec, Histogram, HistogramOpts, HistogramVec, IntCounter,
    IntCounterVec, IntGauge, IntGaugeVec, Opts, Registry,
};

lazy_static! {
    /// Global Prometheus registry for controller metrics.
    pub static ref REGISTRY: Registry = Registry::new();

    // ============================================================
    // Resource Counts
    // ============================================================

    /// Number of GatewayClass resources.
    pub static ref GATEWAY_CLASSES_TOTAL: IntGauge = IntGauge::new(
        "wicket_gateway_classes_total",
        "Total number of GatewayClass resources"
    ).expect("metric can be created");

    /// Number of Gateway resources by namespace and class.
    pub static ref GATEWAYS_TOTAL: IntGaugeVec = IntGaugeVec::new(
        Opts::new("wicket_gateways_total", "Total number of Gateway resources"),
        &["namespace", "gateway_class"]
    ).expect("metric can be created");

    /// Number of HTTPRoute resources by namespace.
    pub static ref HTTPROUTES_TOTAL: IntGaugeVec = IntGaugeVec::new(
        Opts::new("wicket_httproutes_total", "Total number of HTTPRoute resources"),
        &["namespace"]
    ).expect("metric can be created");

    /// Number of TCPRoute resources by namespace.
    pub static ref TCPROUTES_TOTAL: IntGaugeVec = IntGaugeVec::new(
        Opts::new("wicket_tcproutes_total", "Total number of TCPRoute resources"),
        &["namespace"]
    ).expect("metric can be created");

    /// Number of TLSRoute resources by namespace.
    pub static ref TLSROUTES_TOTAL: IntGaugeVec = IntGaugeVec::new(
        Opts::new("wicket_tlsroutes_total", "Total number of TLSRoute resources"),
        &["namespace"]
    ).expect("metric can be created");

    /// Number of ReferenceGrant resources by namespace.
    pub static ref REFERENCE_GRANTS_TOTAL: IntGaugeVec = IntGaugeVec::new(
        Opts::new("wicket_reference_grants_total", "Total number of ReferenceGrant resources"),
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
    pub static ref BACKENDS_TOTAL: IntGaugeVec = IntGaugeVec::new(
        Opts::new("wicket_backends_total", "Total number of backend services"),
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
        "wicket_config_generation",
        "Current configuration generation"
    ).expect("metric can be created");

    // ============================================================
    // TLS/Certificate Metrics
    // ============================================================

    /// Number of TLS certificates being managed.
    pub static ref TLS_CERTIFICATES_TOTAL: IntGaugeVec = IntGaugeVec::new(
        Opts::new("wicket_tls_certificates_total", "Total number of TLS certificates"),
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

    /// Kubernetes API request latency.
    pub static ref K8S_API_LATENCY_SECONDS: HistogramVec = HistogramVec::new(
        HistogramOpts::new(
            "wicket_k8s_api_latency_seconds",
            "Kubernetes API request latency"
        ).buckets(vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0]),
        &["operation", "resource"]
    ).expect("metric can be created");

    /// Kubernetes API errors.
    pub static ref K8S_API_ERRORS_TOTAL: IntCounterVec = IntCounterVec::new(
        Opts::new("wicket_k8s_api_errors_total", "Total Kubernetes API errors"),
        &["operation", "resource", "error_type"]
    ).expect("metric can be created");
}

/// Register all metrics with the global registry.
pub fn register_metrics() -> Result<(), prometheus::Error> {
    REGISTRY.register(Box::new(GATEWAY_CLASSES_TOTAL.clone()))?;
    REGISTRY.register(Box::new(GATEWAYS_TOTAL.clone()))?;
    REGISTRY.register(Box::new(HTTPROUTES_TOTAL.clone()))?;
    REGISTRY.register(Box::new(TCPROUTES_TOTAL.clone()))?;
    REGISTRY.register(Box::new(TLSROUTES_TOTAL.clone()))?;
    REGISTRY.register(Box::new(REFERENCE_GRANTS_TOTAL.clone()))?;
    REGISTRY.register(Box::new(RECONCILE_TOTAL.clone()))?;
    REGISTRY.register(Box::new(RECONCILE_DURATION_SECONDS.clone()))?;
    REGISTRY.register(Box::new(RECONCILE_ERRORS_TOTAL.clone()))?;
    REGISTRY.register(Box::new(RECONCILE_QUEUE_DEPTH.clone()))?;
    REGISTRY.register(Box::new(BACKENDS_TOTAL.clone()))?;
    REGISTRY.register(Box::new(BACKEND_ENDPOINTS_HEALTHY.clone()))?;
    REGISTRY.register(Box::new(BACKEND_ENDPOINTS_UNHEALTHY.clone()))?;
    REGISTRY.register(Box::new(CONFIG_UPDATES_TOTAL.clone()))?;
    REGISTRY.register(Box::new(CONFIG_LAST_UPDATE_TIMESTAMP.clone()))?;
    REGISTRY.register(Box::new(CONFIG_GENERATION.clone()))?;
    REGISTRY.register(Box::new(TLS_CERTIFICATES_TOTAL.clone()))?;
    REGISTRY.register(Box::new(TLS_CERTIFICATE_EXPIRY_TIMESTAMP.clone()))?;
    REGISTRY.register(Box::new(CONTROLLER_IS_LEADER.clone()))?;
    REGISTRY.register(Box::new(CONTROLLER_UPTIME_SECONDS.clone()))?;
    REGISTRY.register(Box::new(K8S_API_LATENCY_SECONDS.clone()))?;
    REGISTRY.register(Box::new(K8S_API_ERRORS_TOTAL.clone()))?;
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
pub async fn serve_metrics(addr: std::net::SocketAddr) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
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
