//! Prometheus metrics for the Wicket stream (L4) proxy.
//!
//! Metrics are registered with Prometheus's default global registry,
//! which Pingora's `prometheus_http_service()` exposes at /metrics.

use lazy_static::lazy_static;
use prometheus::{
    register_histogram_vec, register_int_counter_vec, register_int_gauge, HistogramVec,
    IntCounterVec, IntGauge,
};

lazy_static! {
    // ============================================================
    // Connection lifecycle
    // ============================================================

    /// Total stream proxy connections, labelled by upstream.
    pub static ref STREAM_CONNECTIONS_TOTAL: IntCounterVec = register_int_counter_vec!(
        "wicket_stream_connections_total",
        "Total stream proxy connections",
        &["upstream"]
    )
    .expect("metric can be created");

    /// Currently active stream proxy connections.
    pub static ref STREAM_CONNECTIONS_ACTIVE: IntGauge = register_int_gauge!(
        "wicket_stream_connections_active",
        "Currently active stream proxy connections"
    )
    .expect("metric can be created");

    /// Stream connection duration in seconds, labelled by upstream.
    pub static ref STREAM_CONNECTION_DURATION_SECONDS: HistogramVec = register_histogram_vec!(
        "wicket_stream_connection_duration_seconds",
        "Stream connection duration in seconds",
        &["upstream"],
        vec![0.1, 0.5, 1.0, 5.0, 10.0, 30.0, 60.0, 300.0, 600.0, 1800.0, 3600.0]
    )
    .expect("metric can be created");

    // ============================================================
    // Errors
    // ============================================================

    /// Stream proxy connection errors.
    ///
    /// `error_type` values: `"sni_extract"`, `"routing"`, `"connect"`, `"transfer"`.
    pub static ref STREAM_CONNECTION_ERRORS_TOTAL: IntCounterVec = register_int_counter_vec!(
        "wicket_stream_connection_errors_total",
        "Stream proxy connection errors",
        &["error_type"]
    )
    .expect("metric can be created");

    // ============================================================
    // Bytes transferred (userspace path only)
    // ============================================================

    /// Total bytes transferred through the stream proxy.
    ///
    /// `direction` values: `"rx"` (client→backend), `"tx"` (backend→client).
    pub static ref STREAM_BYTES_TOTAL: IntCounterVec = register_int_counter_vec!(
        "wicket_stream_bytes_total",
        "Total bytes transferred through stream proxy",
        &["direction"]
    )
    .expect("metric can be created");

    // ============================================================
    // SNI routing
    // ============================================================

    /// SNI extraction attempts.
    ///
    /// `result` values: `"success"`, `"failure"` (TLS but no SNI), `"none"` (non-TLS).
    pub static ref STREAM_SNI_EXTRACTIONS_TOTAL: IntCounterVec = register_int_counter_vec!(
        "wicket_stream_sni_extractions_total",
        "SNI extraction attempts",
        &["result"]
    )
    .expect("metric can be created");

    // ============================================================
    // Backend connect latency
    // ============================================================

    /// Backend connect latency in seconds, labelled by upstream.
    pub static ref STREAM_CONNECT_DURATION_SECONDS: HistogramVec = register_histogram_vec!(
        "wicket_stream_connect_duration_seconds",
        "Backend connect latency in seconds",
        &["upstream"],
        vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0]
    )
    .expect("metric can be created");
}

/// Force lazy_static initialization. Call from main before serving traffic.
pub fn register_stream_metrics() {
    let _ = &*STREAM_CONNECTIONS_TOTAL;
    let _ = &*STREAM_CONNECTIONS_ACTIVE;
    let _ = &*STREAM_CONNECTION_DURATION_SECONDS;
    let _ = &*STREAM_CONNECTION_ERRORS_TOTAL;
    let _ = &*STREAM_BYTES_TOTAL;
    let _ = &*STREAM_SNI_EXTRACTIONS_TOTAL;
    let _ = &*STREAM_CONNECT_DURATION_SECONDS;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stream_metrics_registration() {
        // Triggers lazy initialization — panics if registration fails.
        register_stream_metrics();
    }
}
