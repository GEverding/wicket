//! Prometheus metrics for the Wicket proxy (data plane).
//!
//! Implements RED pattern metrics (Rate, Errors, Duration) for observability.
//!
//! These metrics are automatically registered with Prometheus's default global registry,
//! which Pingora's `prometheus_http_service()` exposes at /metrics.

use lazy_static::lazy_static;
use prometheus::{
    register_gauge_vec, register_histogram_vec, register_int_counter, register_int_counter_vec,
    register_int_gauge, register_int_gauge_vec, GaugeVec, HistogramVec, IntCounter, IntCounterVec,
    IntGauge, IntGaugeVec,
};

lazy_static! {
    // ============================================================
    // RED Metrics - Request Rate
    // ============================================================

    /// Total HTTP requests received.
    pub static ref HTTP_REQUESTS_TOTAL: IntCounterVec = register_int_counter_vec!(
        "wicket_http_requests_total",
        "Total HTTP requests received",
        &["method", "route", "status_code"]
    ).expect("metric can be created");

    /// Active HTTP requests currently being processed.
    pub static ref HTTP_REQUESTS_ACTIVE: IntGaugeVec = register_int_gauge_vec!(
        "wicket_http_requests_active",
        "Active HTTP requests being processed",
        &["route"]
    ).expect("metric can be created");

    /// Requests per second (computed from total, but useful for dashboards).
    pub static ref HTTP_REQUESTS_PER_SECOND: GaugeVec = register_gauge_vec!(
        "wicket_http_requests_per_second",
        "HTTP requests per second",
        &["route"]
    ).expect("metric can be created");

    // ============================================================
    // RED Metrics - Errors
    // ============================================================

    /// HTTP error responses (4xx, 5xx).
    pub static ref HTTP_ERRORS_TOTAL: IntCounterVec = register_int_counter_vec!(
        "wicket_http_errors_total",
        "Total HTTP error responses",
        &["method", "route", "status_code", "error_type"]
    ).expect("metric can be created");

    /// Upstream connection errors.
    pub static ref UPSTREAM_ERRORS_TOTAL: IntCounterVec = register_int_counter_vec!(
        "wicket_upstream_errors_total",
        "Total upstream connection errors",
        &["upstream", "error_type"]
    ).expect("metric can be created");

    /// TLS handshake errors.
    pub static ref TLS_HANDSHAKE_ERRORS_TOTAL: IntCounterVec = register_int_counter_vec!(
        "wicket_tls_handshake_errors_total",
        "Total TLS handshake errors",
        &["listener", "error_type"]
    ).expect("metric can be created");

    /// Request timeouts.
    pub static ref REQUEST_TIMEOUTS_TOTAL: IntCounterVec = register_int_counter_vec!(
        "wicket_request_timeouts_total",
        "Total request timeouts",
        &["route", "timeout_type"]
    ).expect("metric can be created");

    /// Circuit breaker trips.
    pub static ref CIRCUIT_BREAKER_TRIPS_TOTAL: IntCounterVec = register_int_counter_vec!(
        "wicket_circuit_breaker_trips_total",
        "Total circuit breaker trips",
        &["upstream"]
    ).expect("metric can be created");

    // ============================================================
    // RED Metrics - Duration
    // ============================================================

    /// HTTP request duration (total time from request received to response sent).
    pub static ref HTTP_REQUEST_DURATION_SECONDS: HistogramVec = register_histogram_vec!(
        "wicket_http_request_duration_seconds",
        "HTTP request duration in seconds",
        &["method", "route"],
        vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
    ).expect("metric can be created");

    /// Upstream response time (time waiting for upstream to respond).
    pub static ref UPSTREAM_DURATION_SECONDS: HistogramVec = register_histogram_vec!(
        "wicket_upstream_duration_seconds",
        "Upstream response time in seconds",
        &["upstream"],
        vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
    ).expect("metric can be created");

    /// Time to first byte (TTFB).
    pub static ref TIME_TO_FIRST_BYTE_SECONDS: HistogramVec = register_histogram_vec!(
        "wicket_time_to_first_byte_seconds",
        "Time to first byte in seconds",
        &["route"],
        vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0]
    ).expect("metric can be created");

    // ============================================================
    // Connection Metrics
    // ============================================================

    /// Active client connections.
    pub static ref CLIENT_CONNECTIONS_ACTIVE: IntGaugeVec = register_int_gauge_vec!(
        "wicket_client_connections_active",
        "Active client connections",
        &["listener"]
    ).expect("metric can be created");

    /// Total client connections accepted.
    pub static ref CLIENT_CONNECTIONS_TOTAL: IntCounterVec = register_int_counter_vec!(
        "wicket_client_connections_total",
        "Total client connections accepted",
        &["listener"]
    ).expect("metric can be created");

    /// Active upstream connections.
    pub static ref UPSTREAM_CONNECTIONS_ACTIVE: IntGaugeVec = register_int_gauge_vec!(
        "wicket_upstream_connections_active",
        "Active upstream connections",
        &["upstream"]
    ).expect("metric can be created");

    /// Upstream connection pool size.
    pub static ref UPSTREAM_POOL_SIZE: IntGaugeVec = register_int_gauge_vec!(
        "wicket_upstream_pool_size",
        "Upstream connection pool size",
        &["upstream"]
    ).expect("metric can be created");

    // ============================================================
    // Upstream Health Metrics
    // ============================================================

    /// Upstream health status (1 = healthy, 0 = unhealthy).
    pub static ref UPSTREAM_HEALTH: IntGaugeVec = register_int_gauge_vec!(
        "wicket_upstream_health",
        "Upstream health status",
        &["upstream", "backend"]
    ).expect("metric can be created");

    /// Healthy backends per upstream.
    pub static ref UPSTREAM_HEALTHY_BACKENDS: IntGaugeVec = register_int_gauge_vec!(
        "wicket_upstream_healthy_backends",
        "Number of healthy backends per upstream",
        &["upstream"]
    ).expect("metric can be created");

    /// Health check attempts.
    pub static ref HEALTH_CHECK_TOTAL: IntCounterVec = register_int_counter_vec!(
        "wicket_health_check_total",
        "Total health check attempts",
        &["upstream", "backend", "result"]
    ).expect("metric can be created");

    // ============================================================
    // TLS Metrics
    // ============================================================

    /// TLS handshakes completed.
    pub static ref TLS_HANDSHAKES_TOTAL: IntCounterVec = register_int_counter_vec!(
        "wicket_tls_handshakes_total",
        "Total TLS handshakes completed",
        &["listener", "tls_version", "cipher"]
    ).expect("metric can be created");

    /// TLS handshake duration.
    pub static ref TLS_HANDSHAKE_DURATION_SECONDS: HistogramVec = register_histogram_vec!(
        "wicket_tls_handshake_duration_seconds",
        "TLS handshake duration",
        &["listener"],
        vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5]
    ).expect("metric can be created");

    /// Certificate expiry (days until expiry).
    pub static ref TLS_CERT_EXPIRY_DAYS: GaugeVec = register_gauge_vec!(
        "wicket_tls_cert_expiry_days",
        "Days until certificate expires",
        &["domain"]
    ).expect("metric can be created");

    // ============================================================
    // Bandwidth Metrics
    // ============================================================

    /// Bytes received from clients.
    pub static ref BYTES_RECEIVED_TOTAL: IntCounterVec = register_int_counter_vec!(
        "wicket_bytes_received_total",
        "Total bytes received from clients",
        &["route"]
    ).expect("metric can be created");

    /// Bytes sent to clients.
    pub static ref BYTES_SENT_TOTAL: IntCounterVec = register_int_counter_vec!(
        "wicket_bytes_sent_total",
        "Total bytes sent to clients",
        &["route"]
    ).expect("metric can be created");

    // ============================================================
    // Route Metrics
    // ============================================================

    /// Route match latency (time to match request to route).
    pub static ref ROUTE_MATCH_DURATION_SECONDS: HistogramVec = register_histogram_vec!(
        "wicket_route_match_duration_seconds",
        "Time to match request to route",
        &[],
        vec![0.0001, 0.0005, 0.001, 0.005, 0.01]
    ).expect("metric can be created");

    /// Requests with no matching route.
    pub static ref ROUTE_NOT_FOUND_TOTAL: IntCounter = register_int_counter!(
        "wicket_route_not_found_total",
        "Requests with no matching route"
    ).expect("metric can be created");

    // ============================================================
    // Config Hot-Reload Metrics
    // ============================================================

    /// Config reloads.
    pub static ref CONFIG_RELOADS_TOTAL: IntCounterVec = register_int_counter_vec!(
        "wicket_config_reloads_total",
        "Total configuration reloads",
        &["result"]
    ).expect("metric can be created");

    /// Current config generation.
    pub static ref CONFIG_GENERATION: IntGauge = register_int_gauge!(
        "wicket_proxy_config_generation",
        "Current configuration generation"
    ).expect("metric can be created");

    /// Time since last config reload.
    pub static ref CONFIG_LAST_RELOAD_TIMESTAMP: IntGauge = register_int_gauge!(
        "wicket_config_last_reload_timestamp_seconds",
        "Unix timestamp of last configuration reload"
    ).expect("metric can be created");

    // ============================================================
    // Process Metrics
    // ============================================================

    /// Process uptime.
    pub static ref PROXY_UPTIME_SECONDS: IntGauge = register_int_gauge!(
        "wicket_proxy_uptime_seconds",
        "Proxy uptime in seconds"
    ).expect("metric can be created");

    /// Number of worker threads.
    pub static ref WORKER_THREADS: IntGauge = register_int_gauge!(
        "wicket_worker_threads",
        "Number of worker threads"
    ).expect("metric can be created");
}

/// Initialize metrics by accessing lazy_static values.
/// This ensures all metrics are registered with Prometheus before the server starts.
pub fn register_metrics() -> Result<(), prometheus::Error> {
    // Access each metric to trigger lazy initialization and registration
    // The register_* macros handle registration with the default global registry
    let _ = &*HTTP_REQUESTS_TOTAL;
    let _ = &*HTTP_REQUESTS_ACTIVE;
    let _ = &*HTTP_REQUESTS_PER_SECOND;
    let _ = &*HTTP_ERRORS_TOTAL;
    let _ = &*UPSTREAM_ERRORS_TOTAL;
    let _ = &*TLS_HANDSHAKE_ERRORS_TOTAL;
    let _ = &*REQUEST_TIMEOUTS_TOTAL;
    let _ = &*CIRCUIT_BREAKER_TRIPS_TOTAL;
    let _ = &*HTTP_REQUEST_DURATION_SECONDS;
    let _ = &*UPSTREAM_DURATION_SECONDS;
    let _ = &*TIME_TO_FIRST_BYTE_SECONDS;
    let _ = &*CLIENT_CONNECTIONS_ACTIVE;
    let _ = &*CLIENT_CONNECTIONS_TOTAL;
    let _ = &*UPSTREAM_CONNECTIONS_ACTIVE;
    let _ = &*UPSTREAM_POOL_SIZE;
    let _ = &*UPSTREAM_HEALTH;
    let _ = &*UPSTREAM_HEALTHY_BACKENDS;
    let _ = &*HEALTH_CHECK_TOTAL;
    let _ = &*TLS_HANDSHAKES_TOTAL;
    let _ = &*TLS_HANDSHAKE_DURATION_SECONDS;
    let _ = &*TLS_CERT_EXPIRY_DAYS;
    let _ = &*BYTES_RECEIVED_TOTAL;
    let _ = &*BYTES_SENT_TOTAL;
    let _ = &*ROUTE_MATCH_DURATION_SECONDS;
    let _ = &*ROUTE_NOT_FOUND_TOTAL;
    let _ = &*CONFIG_RELOADS_TOTAL;
    let _ = &*CONFIG_GENERATION;
    let _ = &*CONFIG_LAST_RELOAD_TIMESTAMP;
    let _ = &*PROXY_UPTIME_SECONDS;
    let _ = &*WORKER_THREADS;

    Ok(())
}

/// Helper for tracking request metrics.
pub struct RequestMetrics {
    route: String,
    method: String,
    start_time: std::time::Instant,
}

impl RequestMetrics {
    /// Start tracking a new request.
    pub fn start(route: &str, method: &str) -> Self {
        HTTP_REQUESTS_ACTIVE.with_label_values(&[route]).inc();
        Self {
            route: route.to_string(),
            method: method.to_string(),
            start_time: std::time::Instant::now(),
        }
    }

    /// Record a successful response.
    pub fn success(self, status_code: u16, bytes_sent: u64, bytes_received: u64) {
        let duration = self.start_time.elapsed().as_secs_f64();
        let status = status_code.to_string();

        HTTP_REQUESTS_TOTAL
            .with_label_values(&[&self.method, &self.route, &status])
            .inc();
        HTTP_REQUEST_DURATION_SECONDS
            .with_label_values(&[&self.method, &self.route])
            .observe(duration);
        HTTP_REQUESTS_ACTIVE
            .with_label_values(&[&self.route])
            .dec();

        BYTES_SENT_TOTAL
            .with_label_values(&[&self.route])
            .inc_by(bytes_sent);
        BYTES_RECEIVED_TOTAL
            .with_label_values(&[&self.route])
            .inc_by(bytes_received);

        // Track errors (4xx, 5xx)
        if status_code >= 400 {
            let error_type = if status_code >= 500 {
                "server_error"
            } else {
                "client_error"
            };
            HTTP_ERRORS_TOTAL
                .with_label_values(&[&self.method, &self.route, &status, error_type])
                .inc();
        }
    }

    /// Record a timeout.
    pub fn timeout(self, timeout_type: &str) {
        let duration = self.start_time.elapsed().as_secs_f64();

        HTTP_REQUESTS_TOTAL
            .with_label_values(&[&self.method, &self.route, "504"])
            .inc();
        HTTP_REQUEST_DURATION_SECONDS
            .with_label_values(&[&self.method, &self.route])
            .observe(duration);
        HTTP_REQUESTS_ACTIVE
            .with_label_values(&[&self.route])
            .dec();
        REQUEST_TIMEOUTS_TOTAL
            .with_label_values(&[&self.route, timeout_type])
            .inc();
        HTTP_ERRORS_TOTAL
            .with_label_values(&[&self.method, &self.route, "504", "timeout"])
            .inc();
    }

    /// Record an upstream error.
    pub fn upstream_error(self, upstream: &str, error_type: &str) {
        let duration = self.start_time.elapsed().as_secs_f64();

        HTTP_REQUESTS_TOTAL
            .with_label_values(&[&self.method, &self.route, "502"])
            .inc();
        HTTP_REQUEST_DURATION_SECONDS
            .with_label_values(&[&self.method, &self.route])
            .observe(duration);
        HTTP_REQUESTS_ACTIVE
            .with_label_values(&[&self.route])
            .dec();
        UPSTREAM_ERRORS_TOTAL
            .with_label_values(&[upstream, error_type])
            .inc();
        HTTP_ERRORS_TOTAL
            .with_label_values(&[&self.method, &self.route, "502", "upstream_error"])
            .inc();
    }
}

/// Record upstream response time.
pub fn record_upstream_duration(upstream: &str, duration_secs: f64) {
    UPSTREAM_DURATION_SECONDS
        .with_label_values(&[upstream])
        .observe(duration_secs);
}

/// Record time to first byte.
pub fn record_ttfb(route: &str, duration_secs: f64) {
    TIME_TO_FIRST_BYTE_SECONDS
        .with_label_values(&[route])
        .observe(duration_secs);
}

/// Update upstream health status.
pub fn set_upstream_health(upstream: &str, backend: &str, healthy: bool) {
    UPSTREAM_HEALTH
        .with_label_values(&[upstream, backend])
        .set(if healthy { 1 } else { 0 });
}

/// Record a health check result.
pub fn record_health_check(upstream: &str, backend: &str, success: bool) {
    let result = if success { "success" } else { "failure" };
    HEALTH_CHECK_TOTAL
        .with_label_values(&[upstream, backend, result])
        .inc();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_registration() {
        // This will trigger lazy initialization and registration
        let result = register_metrics();
        assert!(result.is_ok());
    }
}
