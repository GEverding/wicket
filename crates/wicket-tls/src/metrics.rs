//! TLS and ACME Prometheus metrics.

use lazy_static::lazy_static;
use prometheus::{register_gauge_vec, register_int_counter_vec, GaugeVec, IntCounterVec};

lazy_static! {
    /// Total certificate reload attempts.
    pub static ref CERT_RELOAD_TOTAL: IntCounterVec = register_int_counter_vec!(
        "wicket_cert_reload_total",
        "Total certificate reload attempts",
        &["status"]
    ).expect("metric can be created");

    /// ACME renewal checks and outcomes.
    pub static ref ACME_RENEWAL_TOTAL: IntCounterVec = register_int_counter_vec!(
        "wicket_acme_renewal_total",
        "ACME renewal attempts by status",
        &["status"]
    ).expect("metric can be created");

    /// ACME renewal failures by domain and bounded reason.
    pub static ref ACME_RENEWAL_FAILURES_TOTAL: IntCounterVec = register_int_counter_vec!(
        "wicket_acme_renewal_failures_total",
        "ACME renewal failures by domain and reason",
        &["domain", "reason"]
    ).expect("metric can be created");

    /// Last ACME renewal attempt timestamp by primary cert domain.
    pub static ref ACME_LAST_RENEWAL_ATTEMPT_TIMESTAMP_SECONDS: GaugeVec = register_gauge_vec!(
        "wicket_acme_last_renewal_attempt_timestamp_seconds",
        "Unix timestamp of the last ACME renewal attempt",
        &["domain"]
    ).expect("metric can be created");

    /// Last successful ACME renewal timestamp by primary cert domain.
    pub static ref ACME_LAST_RENEWAL_SUCCESS_TIMESTAMP_SECONDS: GaugeVec = register_gauge_vec!(
        "wicket_acme_last_renewal_success_timestamp_seconds",
        "Unix timestamp of the last successful ACME renewal",
        &["domain"]
    ).expect("metric can be created");

    /// Certificate expiry timestamp in seconds since epoch.
    pub static ref TLS_CERTIFICATE_EXPIRY_TIMESTAMP_SECONDS: GaugeVec = register_gauge_vec!(
        "wicket_tls_certificate_expiry_timestamp_seconds",
        "Certificate expiration Unix timestamp in seconds",
        &["domain"]
    ).expect("metric can be created");

    /// Certificate resolver outcomes during TLS handshake.
    pub static ref TLS_CERT_RESOLUTION_TOTAL: IntCounterVec = register_int_counter_vec!(
        "wicket_tls_cert_resolution_total",
        "TLS certificate resolver outcomes",
        &["outcome"]
    ).expect("metric can be created");
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub enum CertReloadStatus {
    Success,
    Failure,
}

impl CertReloadStatus {
    #[must_use]
    pub const fn as_label(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failure => "failure",
        }
    }
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub enum AcmeRenewalStatus {
    Success,
    Failure,
    Skipped,
}

impl AcmeRenewalStatus {
    #[must_use]
    pub const fn as_label(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failure => "failure",
            Self::Skipped => "skipped",
        }
    }
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub enum CertResolutionOutcome {
    Exact,
    Wildcard,
    Default,
    Miss,
    NoSni,
}

impl CertResolutionOutcome {
    #[must_use]
    pub const fn as_label(self) -> &'static str {
        match self {
            Self::Exact => "exact",
            Self::Wildcard => "wildcard",
            Self::Default => "default",
            Self::Miss => "miss",
            Self::NoSni => "no_sni",
        }
    }
}

pub fn inc_cert_reload(status: CertReloadStatus) {
    CERT_RELOAD_TOTAL
        .with_label_values(&[status.as_label()])
        .inc();
}

pub fn inc_acme_renewal(status: AcmeRenewalStatus) {
    ACME_RENEWAL_TOTAL
        .with_label_values(&[status.as_label()])
        .inc();
}

pub fn inc_acme_renewal_failure(domain: &str, reason: &str) {
    ACME_RENEWAL_FAILURES_TOTAL
        .with_label_values(&[domain, reason])
        .inc();
}

pub fn set_acme_last_attempt(domain: &str, timestamp: i64) {
    ACME_LAST_RENEWAL_ATTEMPT_TIMESTAMP_SECONDS
        .with_label_values(&[domain])
        .set(timestamp as f64);
}

pub fn set_acme_last_success(domain: &str, timestamp: i64) {
    ACME_LAST_RENEWAL_SUCCESS_TIMESTAMP_SECONDS
        .with_label_values(&[domain])
        .set(timestamp as f64);
}

pub fn set_cert_expiry(domain: &str, timestamp: i64) {
    TLS_CERTIFICATE_EXPIRY_TIMESTAMP_SECONDS
        .with_label_values(&[domain])
        .set(timestamp as f64);
}

pub fn inc_cert_resolution(outcome: CertResolutionOutcome) {
    TLS_CERT_RESOLUTION_TOTAL
        .with_label_values(&[outcome.as_label()])
        .inc();
}

/// Initialize TLS metrics by accessing lazy_static values.
pub fn register_metrics() {
    let _ = &*CERT_RELOAD_TOTAL;
    let _ = &*ACME_RENEWAL_TOTAL;
    let _ = &*ACME_RENEWAL_FAILURES_TOTAL;
    let _ = &*ACME_LAST_RENEWAL_ATTEMPT_TIMESTAMP_SECONDS;
    let _ = &*ACME_LAST_RENEWAL_SUCCESS_TIMESTAMP_SECONDS;
    let _ = &*TLS_CERTIFICATE_EXPIRY_TIMESTAMP_SECONDS;
    let _ = &*TLS_CERT_RESOLUTION_TOTAL;
}
