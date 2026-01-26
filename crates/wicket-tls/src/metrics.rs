//! TLS certificate metrics.

use foundations::telemetry::metrics::{metrics, Counter, Gauge};
use serde::Serialize;

#[metrics]
pub mod tls_metrics {
    /// Total certificate reload attempts
    pub fn cert_reload_total(status: CertReloadStatus) -> Counter;

    /// ACME renewal attempts
    pub fn acme_renewal_total(status: AcmeRenewalStatus) -> Counter;

    /// Certificate expiry timestamp in seconds since epoch
    pub fn certificate_expiry_timestamp_seconds(name: String, domain: String) -> Gauge;
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, Serialize)]
pub enum CertReloadStatus {
    #[serde(rename = "success")]
    Success,
    #[serde(rename = "failure")]
    Failure,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, Serialize)]
pub enum AcmeRenewalStatus {
    #[serde(rename = "success")]
    Success,
    #[serde(rename = "failure")]
    Failure,
    #[serde(rename = "skipped")]
    Skipped,
}
