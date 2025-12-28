//! TLS configuration types.
//!
//! Supports three modes:
//! - `acme`: Automatic certificate provisioning via Let's Encrypt with DNS-01 validation
//! - `file`: Static certificates loaded from disk with optional file watching
//! - `mixed`: Both ACME and file-based certificates

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Top-level TLS configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TlsConfig {
    /// Mode: "acme", "file", or "mixed"
    pub mode: TlsMode,
    /// ACME configuration (if mode is acme or mixed)
    #[serde(default)]
    pub acme: Option<AcmeConfig>,
    /// File-based certs (if mode is file or mixed)
    #[serde(default)]
    pub file: Option<FileConfig>,
}

/// TLS mode selection.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TlsMode {
    /// ACME-only (auto-obtain via DNS-01)
    #[default]
    Acme,
    /// File-based certs only
    File,
    /// Both ACME and file-based
    Mixed,
}

/// ACME configuration for automatic certificate provisioning.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AcmeConfig {
    /// Contact email for Let's Encrypt account
    pub email: String,
    /// Use staging directory for testing (no rate limits)
    #[serde(default)]
    pub staging: bool,
    /// Storage path for certificates and account key
    #[serde(default = "default_storage_path")]
    pub storage: PathBuf,
    /// Days before expiry to renew certificate
    #[serde(default = "default_renew_before_days")]
    pub renew_before_days: u32,
    /// Certificate configurations
    #[serde(default)]
    pub certs: Vec<AcmeCertConfig>,
}

/// Individual ACME certificate configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AcmeCertConfig {
    /// Domains for this certificate (first is primary, rest are SANs)
    pub domains: Vec<String>,
    /// DNS provider configuration for validation
    pub dns: DnsProviderConfig,
}

/// DNS provider configuration for ACME DNS-01 validation.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DnsProviderConfig {
    /// Provider name: "cloudflare"
    pub provider: String,
    /// API token (supports ${ENV_VAR} syntax for environment variable substitution)
    pub api_token: String,
    /// Zone ID (optional, auto-detected if not specified)
    #[serde(default)]
    pub zone_id: Option<String>,
}

/// File-based certificate configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FileConfig {
    /// Watch for file changes and reload automatically
    #[serde(default = "default_true")]
    pub watch: bool,
    /// Poll interval in seconds for filesystems that don't support inotify
    #[serde(default = "default_poll_interval")]
    pub poll_interval_secs: u64,
    /// Certificate configurations
    #[serde(default)]
    pub certs: Vec<FileCertConfig>,
}

/// Individual file-based certificate configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FileCertConfig {
    /// Unique name for this certificate
    pub name: String,
    /// Path to certificate PEM file
    pub cert: PathBuf,
    /// Path to private key PEM file
    pub key: PathBuf,
    /// Domains this certificate covers (for SNI matching)
    pub domains: Vec<String>,
}

// Default value functions
fn default_storage_path() -> PathBuf {
    PathBuf::from("/var/lib/wicket/acme")
}

fn default_renew_before_days() -> u32 {
    30
}

fn default_true() -> bool {
    true
}

fn default_poll_interval() -> u64 {
    30
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_acme_config() {
        let toml = r#"
            mode = "acme"
            
            [acme]
            email = "admin@example.com"
            staging = true
            
            [[acme.certs]]
            domains = ["example.com", "*.example.com"]
            
            [acme.certs.dns]
            provider = "cloudflare"
            api_token = "${CF_API_TOKEN}"
        "#;

        let config: TlsConfig = toml::from_str(toml).unwrap();
        assert!(matches!(config.mode, TlsMode::Acme));
        assert_eq!(config.acme.unwrap().certs.len(), 1);
    }

    #[test]
    fn test_parse_file_config() {
        let toml = r#"
            mode = "file"
            
            [file]
            watch = true
            
            [[file.certs]]
            name = "main"
            cert = "/certs/tls.crt"
            key = "/certs/tls.key"
            domains = ["example.com"]
        "#;

        let config: TlsConfig = toml::from_str(toml).unwrap();
        assert!(matches!(config.mode, TlsMode::File));
        assert_eq!(config.file.unwrap().certs.len(), 1);
    }

    #[test]
    fn test_parse_mixed_config() {
        let toml = r#"
            mode = "mixed"
            
            [acme]
            email = "admin@example.com"
            
            [[acme.certs]]
            domains = ["api.example.com"]
            
            [acme.certs.dns]
            provider = "cloudflare"
            api_token = "token123"
            
            [file]
            watch = true
            
            [[file.certs]]
            name = "fallback"
            cert = "/certs/fallback.crt"
            key = "/certs/fallback.key"
            domains = ["example.com"]
        "#;

        let config: TlsConfig = toml::from_str(toml).unwrap();
        assert!(matches!(config.mode, TlsMode::Mixed));
        assert!(config.acme.is_some());
        assert!(config.file.is_some());
    }

    #[test]
    fn test_default_values() {
        let toml = r#"
            mode = "acme"
            
            [acme]
            email = "admin@example.com"
        "#;

        let config: TlsConfig = toml::from_str(toml).unwrap();
        let acme = config.acme.unwrap();
        assert_eq!(acme.storage, PathBuf::from("/var/lib/wicket/acme"));
        assert_eq!(acme.renew_before_days, 30);
        assert!(!acme.staging);
    }

    #[test]
    fn test_file_config_defaults() {
        let toml = r#"
            mode = "file"
            
            [file]
            
            [[file.certs]]
            name = "test"
            cert = "/certs/test.crt"
            key = "/certs/test.key"
            domains = ["test.com"]
        "#;

        let config: TlsConfig = toml::from_str(toml).unwrap();
        let file = config.file.unwrap();
        assert!(file.watch);
        assert_eq!(file.poll_interval_secs, 30);
    }

    #[test]
    fn test_dns_provider_optional_zone_id() {
        let toml = r#"
            mode = "acme"
            
            [acme]
            email = "admin@example.com"
            
            [[acme.certs]]
            domains = ["example.com"]
            
            [acme.certs.dns]
            provider = "cloudflare"
            api_token = "token123"
            zone_id = "zone123"
        "#;

        let config: TlsConfig = toml::from_str(toml).unwrap();
        let dns = &config.acme.unwrap().certs[0].dns;
        assert_eq!(dns.zone_id, Some("zone123".to_string()));
    }
}
