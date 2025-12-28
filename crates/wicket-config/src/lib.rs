//! Configuration parsing for Wicket proxy.
//!
//! This crate handles loading and parsing TOML configuration files that define
//! upstreams, routes, server settings, and TLS configuration.

use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;

pub use wicket_tls::TlsConfig;

/// Root configuration structure for Wicket.
#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    /// Server configuration
    pub server: ServerConfig,

    /// Named upstream definitions
    #[serde(default)]
    pub upstreams: HashMap<String, UpstreamConfig>,

    /// Route definitions
    #[serde(default)]
    pub routes: Vec<RouteConfig>,

    /// TLS configuration (optional)
    #[serde(default)]
    pub tls: Option<TlsConfig>,
}

/// Server-level configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    /// Address to listen on (e.g., "0.0.0.0:8080")
    pub listen: SocketAddr,

    /// Number of worker threads (defaults to CPU count)
    #[serde(default)]
    pub workers: Option<usize>,

    /// Enable structured JSON logging
    #[serde(default = "default_true")]
    pub json_logs: bool,

    /// Log level (trace, debug, info, warn, error)
    #[serde(default = "default_log_level")]
    pub log_level: String,

    /// Graceful shutdown timeout in seconds
    #[serde(default = "default_shutdown_timeout")]
    pub shutdown_timeout: u64,
}

/// Configuration for an upstream (backend) service.
#[derive(Debug, Clone, Deserialize)]
pub struct UpstreamConfig {
    /// List of backend addresses (e.g., ["127.0.0.1:3000", "127.0.0.1:3001"])
    pub backends: Vec<String>,

    /// Load balancing strategy: "round_robin" or "consistent_hash"
    #[serde(default = "default_lb_strategy")]
    pub strategy: LoadBalanceStrategy,

    /// Health check configuration
    #[serde(default)]
    pub health_check: Option<HealthCheckConfig>,
}

/// Load balancing strategy.
#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LoadBalanceStrategy {
    #[default]
    RoundRobin,
    ConsistentHash,
}

/// Health check configuration for upstreams.
#[derive(Debug, Clone, Deserialize)]
pub struct HealthCheckConfig {
    /// Path to check (e.g., "/health")
    #[serde(default = "default_health_path")]
    pub path: String,

    /// Interval between checks in seconds
    #[serde(default = "default_health_interval")]
    pub interval: u64,

    /// Number of consecutive failures before marking unhealthy
    #[serde(default = "default_health_threshold")]
    pub unhealthy_threshold: u32,
}

/// Route configuration for matching and proxying requests.
#[derive(Debug, Clone, Deserialize)]
pub struct RouteConfig {
    /// Optional route name for logging
    pub name: Option<String>,

    /// Match conditions for this route
    #[serde(rename = "match")]
    pub match_rules: RouteMatch,

    /// Upstream to proxy to
    pub upstream: String,
}

/// Matching rules for a route.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct RouteMatch {
    /// Host header to match (supports wildcards like "*.example.com")
    pub host: Option<String>,

    /// Path prefix to match (e.g., "/api")
    pub path_prefix: Option<String>,

    /// Exact path to match
    pub path: Option<String>,

    /// HTTP methods to match (e.g., ["GET", "POST"])
    #[serde(default)]
    pub methods: Vec<String>,

    /// Headers to match (exact match)
    #[serde(default)]
    pub headers: HashMap<String, String>,
}

// Default value functions
fn default_true() -> bool {
    true
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_shutdown_timeout() -> u64 {
    30
}

fn default_lb_strategy() -> LoadBalanceStrategy {
    LoadBalanceStrategy::RoundRobin
}

fn default_health_path() -> String {
    "/health".to_string()
}

fn default_health_interval() -> u64 {
    10
}

fn default_health_threshold() -> u32 {
    3
}

impl Config {
    /// Load configuration from a TOML file.
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file: {}", path.display()))?;

        Self::parse(&content)
    }

    /// Parse configuration from a TOML string.
    pub fn parse(content: &str) -> Result<Self> {
        let config: Config =
            toml::from_str(content).with_context(|| "Failed to parse TOML configuration")?;

        config.validate()?;
        Ok(config)
    }

    /// Validate the configuration for consistency.
    pub fn validate(&self) -> Result<()> {
        // Check that all routes reference defined upstreams
        for route in &self.routes {
            if !self.upstreams.contains_key(&route.upstream) {
                anyhow::bail!(
                    "Route '{}' references undefined upstream '{}'",
                    route.name.as_deref().unwrap_or("<unnamed>"),
                    route.upstream
                );
            }

            // Validate that at least one match rule is defined
            let has_match = route.match_rules.host.is_some()
                || route.match_rules.path_prefix.is_some()
                || route.match_rules.path.is_some()
                || !route.match_rules.methods.is_empty()
                || !route.match_rules.headers.is_empty();

            if !has_match {
                anyhow::bail!(
                    "Route '{}' has no match rules defined",
                    route.name.as_deref().unwrap_or("<unnamed>")
                );
            }
        }

        // Validate upstreams have at least one backend
        for (name, upstream) in &self.upstreams {
            if upstream.backends.is_empty() {
                anyhow::bail!("Upstream '{}' has no backends defined", name);
            }
        }

        // Validate TLS config if present
        if let Some(ref tls) = self.tls {
            self.validate_tls(tls)?;
        }

        Ok(())
    }

    fn validate_tls(&self, tls: &TlsConfig) -> Result<()> {
        use wicket_tls::TlsMode;

        // Validate ACME config if mode is Acme or Mixed
        if matches!(tls.mode, TlsMode::Acme | TlsMode::Mixed) {
            if let Some(ref acme) = tls.acme {
                if acme.certs.is_empty() {
                    anyhow::bail!("TLS ACME mode requires at least one cert config");
                }
                for cert in &acme.certs {
                    if cert.domains.is_empty() {
                        anyhow::bail!("ACME cert config requires at least one domain");
                    }
                }
            } else if matches!(tls.mode, TlsMode::Acme) {
                anyhow::bail!("TLS mode 'acme' requires [tls.acme] section");
            }
        }

        // Validate File config if mode is File or Mixed
        if matches!(tls.mode, TlsMode::File | TlsMode::Mixed) {
            if let Some(ref file) = tls.file {
                if file.certs.is_empty() && matches!(tls.mode, TlsMode::File) {
                    anyhow::bail!("TLS file mode requires at least one cert config");
                }
                for cert in &file.certs {
                    if cert.domains.is_empty() {
                        anyhow::bail!("File cert config requires at least one domain");
                    }
                }
            } else if matches!(tls.mode, TlsMode::File) {
                anyhow::bail!("TLS mode 'file' requires [tls.file] section");
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_minimal_config() {
        let config = r#"
[server]
listen = "127.0.0.1:8080"

[upstreams.backend]
backends = ["127.0.0.1:3000"]

[[routes]]
upstream = "backend"
[routes.match]
path_prefix = "/"
"#;

        let config = Config::parse(config).unwrap();
        assert_eq!(config.server.listen.port(), 8080);
        assert_eq!(config.upstreams.len(), 1);
        assert_eq!(config.routes.len(), 1);
    }

    #[test]
    fn test_parse_full_config() {
        let config = r#"
[server]
listen = "0.0.0.0:8080"
workers = 4
json_logs = true
log_level = "debug"
shutdown_timeout = 60

[upstreams.api]
backends = ["127.0.0.1:3000", "127.0.0.1:3001"]
strategy = "round_robin"

[upstreams.api.health_check]
path = "/health"
interval = 5
unhealthy_threshold = 2

[upstreams.static]
backends = ["127.0.0.1:4000"]

[[routes]]
name = "api-route"
upstream = "api"
[routes.match]
host = "api.example.com"
path_prefix = "/v1"
methods = ["GET", "POST"]

[[routes]]
name = "static-route"
upstream = "static"
[routes.match]
path_prefix = "/static"
"#;

        let config = Config::parse(config).unwrap();
        assert_eq!(config.server.workers, Some(4));
        assert_eq!(config.upstreams.len(), 2);
        assert_eq!(config.routes.len(), 2);

        let api = &config.upstreams["api"];
        assert_eq!(api.backends.len(), 2);
        assert_eq!(api.strategy, LoadBalanceStrategy::RoundRobin);
        assert!(api.health_check.is_some());
    }

    #[test]
    fn test_invalid_upstream_reference() {
        let config = r#"
[server]
listen = "127.0.0.1:8080"

[[routes]]
upstream = "nonexistent"
[routes.match]
path_prefix = "/"
"#;

        let result = Config::parse(config);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("undefined upstream"));
    }

    #[test]
    fn test_empty_backends() {
        let config = r#"
[server]
listen = "127.0.0.1:8080"

[upstreams.backend]
backends = []

[[routes]]
upstream = "backend"
[routes.match]
path_prefix = "/"
"#;

        let result = Config::parse(config);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("no backends"));
    }

    #[test]
    fn test_parse_config_with_tls_file() {
        let toml = r#"
[server]
listen = "0.0.0.0:8080"

[tls]
mode = "file"

[tls.file]
watch = true

[[tls.file.certs]]
name = "default"
cert = "/certs/tls.crt"
key = "/certs/tls.key"
domains = ["example.com"]

[upstreams.backend]
backends = ["127.0.0.1:3000"]

[[routes]]
upstream = "backend"
[routes.match]
path_prefix = "/"
"#;

        let config = Config::parse(toml).unwrap();
        assert!(config.tls.is_some());
        let tls = config.tls.unwrap();
        assert!(tls.file.is_some());
        assert_eq!(tls.file.unwrap().certs.len(), 1);
    }

    #[test]
    fn test_parse_config_with_tls_acme() {
        let toml = r#"
[server]
listen = "0.0.0.0:8080"

[tls]
mode = "acme"

[tls.acme]
email = "admin@example.com"
staging = true

[[tls.acme.certs]]
domains = ["example.com", "*.example.com"]

[tls.acme.certs.dns]
provider = "cloudflare"
api_token = "test-token"

[upstreams.backend]
backends = ["127.0.0.1:3000"]

[[routes]]
upstream = "backend"
[routes.match]
path_prefix = "/"
"#;

        let config = Config::parse(toml).unwrap();
        assert!(config.tls.is_some());
        let tls = config.tls.unwrap();
        assert!(tls.acme.is_some());
        assert_eq!(tls.acme.unwrap().certs.len(), 1);
    }

    #[test]
    fn test_parse_config_without_tls() {
        let toml = r#"
[server]
listen = "0.0.0.0:8080"

[upstreams.backend]
backends = ["127.0.0.1:3000"]

[[routes]]
upstream = "backend"
[routes.match]
path_prefix = "/"
"#;

        let config = Config::parse(toml).unwrap();
        assert!(config.tls.is_none());
    }

    #[test]
    fn test_tls_acme_missing_certs() {
        let toml = r#"
[server]
listen = "0.0.0.0:8080"

[tls]
mode = "acme"

[tls.acme]
email = "admin@example.com"

[upstreams.backend]
backends = ["127.0.0.1:3000"]

[[routes]]
upstream = "backend"
[routes.match]
path_prefix = "/"
"#;

        let result = Config::parse(toml);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("requires at least one cert config"));
    }

    #[test]
    fn test_tls_file_missing_section() {
        let toml = r#"
[server]
listen = "0.0.0.0:8080"

[tls]
mode = "file"

[upstreams.backend]
backends = ["127.0.0.1:3000"]

[[routes]]
upstream = "backend"
[routes.match]
path_prefix = "/"
"#;

        let result = Config::parse(toml);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("requires [tls.file] section"));
    }

    #[test]
    fn test_tls_cert_missing_domains() {
        let toml = r#"
[server]
listen = "0.0.0.0:8080"

[tls]
mode = "file"

[tls.file]
watch = true

[[tls.file.certs]]
name = "default"
cert = "/certs/tls.crt"
key = "/certs/tls.key"
domains = []

[upstreams.backend]
backends = ["127.0.0.1:3000"]

[[routes]]
upstream = "backend"
[routes.match]
path_prefix = "/"
"#;

        let result = Config::parse(toml);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("requires at least one domain"));
    }
}
