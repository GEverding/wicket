//! Configuration parsing for Wicket proxy.
//!
//! This crate handles loading and parsing TOML configuration files that define
//! upstreams, routes, server settings, and TLS configuration.

use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
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

    /// Stream (L4) proxy configuration (optional)
    #[serde(default)]
    pub stream: Option<StreamConfig>,
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

    /// Per-route TLS configuration
    #[serde(default)]
    pub tls: Option<RouteTlsConfig>,
}

/// Per-route TLS configuration.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RouteTlsConfig {
    /// Auto-provision certificate via ACME for this route's host
    Auto,
    /// Use a specific certificate by name (must be defined in tls.file.certs)
    Cert(String),
    /// Disable TLS for this route (use HTTP)
    Off,
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

/// Stream (L4) proxy configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct StreamConfig {
    /// Address to listen on (e.g., "0.0.0.0:443")
    pub listen: String,

    /// TCP backlog size
    #[serde(default = "default_backlog")]
    pub backlog: u32,

    /// Enable SO_REUSEPORT for multi-process load balancing
    #[serde(default = "default_true")]
    pub reuseport: bool,

    /// PROXY protocol configuration
    #[serde(default)]
    pub proxy_protocol: ProxyProtocolConfig,

    /// Source IP addresses for ephemeral port multiplication
    #[serde(default)]
    pub source_ips: Vec<IpAddr>,

    /// Default upstream when no SNI route matches
    pub default_upstream: Option<String>,

    /// SNI-based routing map (hostname -> upstream name)
    #[serde(default)]
    pub sni_routes: HashMap<String, String>,

    /// Stream upstream definitions
    #[serde(default)]
    pub upstreams: Vec<StreamUpstreamConfig>,
}

/// Configuration for a stream upstream.
#[derive(Debug, Clone, Deserialize)]
pub struct StreamUpstreamConfig {
    /// Upstream name
    pub name: String,

    /// Backend server addresses
    pub servers: Vec<String>,
}

/// PROXY protocol configuration.
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ProxyProtocolConfig {
    /// No PROXY protocol
    #[default]
    None,
    /// PROXY protocol v1 (text)
    V1,
    /// PROXY protocol v2 (binary)
    V2,
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

fn default_backlog() -> u32 {
    8000
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

        // Validate stream config if present
        if let Some(ref stream) = self.stream {
            self.validate_stream(stream)?;
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

    fn validate_stream(&self, stream: &StreamConfig) -> Result<()> {
        // Validate listen address is parseable
        stream
            .listen
            .parse::<SocketAddr>()
            .with_context(|| format!("Invalid stream listen address: {}", stream.listen))?;

        // Build upstream name set
        let upstream_names: HashMap<&str, ()> = stream
            .upstreams
            .iter()
            .map(|u| (u.name.as_str(), ()))
            .collect();

        // Validate default_upstream exists if specified
        if let Some(ref default) = stream.default_upstream {
            if !upstream_names.contains_key(default.as_str()) {
                anyhow::bail!(
                    "Stream default_upstream '{}' references undefined upstream",
                    default
                );
            }
        }

        // Validate sni_routes reference defined upstreams
        for (sni, upstream) in &stream.sni_routes {
            if !upstream_names.contains_key(upstream.as_str()) {
                anyhow::bail!(
                    "Stream SNI route '{}' references undefined upstream '{}'",
                    sni,
                    upstream
                );
            }
        }

        // Validate at least one upstream is defined
        if stream.upstreams.is_empty() {
            anyhow::bail!("Stream config requires at least one upstream");
        }

        // Validate each upstream has at least one server
        for upstream in &stream.upstreams {
            if upstream.servers.is_empty() {
                anyhow::bail!("Stream upstream '{}' has no servers defined", upstream.name);
            }
        }

        Ok(())
    }

    /// Collect domains from routes that have `tls = "auto"`.
    ///
    /// These domains will be auto-provisioned via ACME.
    /// Only routes with explicit host matches are included (wildcards are supported).
    pub fn collect_auto_tls_domains(&self) -> Vec<String> {
        self.routes
            .iter()
            .filter(|r| matches!(r.tls, Some(RouteTlsConfig::Auto)))
            .filter_map(|r| r.match_rules.host.clone())
            .collect()
    }

    /// Check if any route requires auto TLS.
    pub fn has_auto_tls_routes(&self) -> bool {
        self.routes
            .iter()
            .any(|r| matches!(r.tls, Some(RouteTlsConfig::Auto)))
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

    #[test]
    fn test_parse_stream_config() {
        let config = r#"
[server]
listen = "127.0.0.1:8080"

[stream]
listen = "0.0.0.0:443"
backlog = 8000
reuseport = true
proxy_protocol = "v2"
source_ips = ["127.0.0.2", "127.0.0.3", "127.0.0.4"]
default_upstream = "backend_3001"

[stream.sni_routes]
"api.example.com" = "backend_5443"
"*.internal.com" = "backend_6443"

[[stream.upstreams]]
name = "backend_3001"
servers = ["127.0.0.2:3001", "127.0.0.3:3001", "127.0.0.4:3001"]

[[stream.upstreams]]
name = "backend_5443"
servers = ["127.0.0.2:5443", "127.0.0.3:5443", "127.0.0.4:5443"]

[[stream.upstreams]]
name = "backend_6443"
servers = ["127.0.0.2:6443"]

[upstreams.backend]
backends = ["127.0.0.1:3000"]

[[routes]]
upstream = "backend"
[routes.match]
path_prefix = "/"
"#;

        let config = Config::parse(config).unwrap();
        assert!(config.stream.is_some());

        let stream = config.stream.unwrap();
        assert_eq!(stream.listen, "0.0.0.0:443");
        assert_eq!(stream.backlog, 8000);
        assert!(stream.reuseport);
        assert_eq!(stream.proxy_protocol, ProxyProtocolConfig::V2);
        assert_eq!(stream.source_ips.len(), 3);
        assert_eq!(stream.default_upstream, Some("backend_3001".to_string()));
        assert_eq!(stream.sni_routes.len(), 2);
        assert_eq!(stream.upstreams.len(), 3);
    }

    #[test]
    fn test_stream_config_defaults() {
        let config = r#"
[server]
listen = "127.0.0.1:8080"

[stream]
listen = "0.0.0.0:443"

[[stream.upstreams]]
name = "backend"
servers = ["127.0.0.1:3001"]

[upstreams.backend]
backends = ["127.0.0.1:3000"]

[[routes]]
upstream = "backend"
[routes.match]
path_prefix = "/"
"#;

        let config = Config::parse(config).unwrap();
        let stream = config.stream.unwrap();
        assert_eq!(stream.backlog, 8000);
        assert!(stream.reuseport);
        assert_eq!(stream.proxy_protocol, ProxyProtocolConfig::None);
        assert!(stream.source_ips.is_empty());
        assert!(stream.default_upstream.is_none());
        assert!(stream.sni_routes.is_empty());
    }

    #[test]
    fn test_stream_invalid_listen_address() {
        let config = r#"
[server]
listen = "127.0.0.1:8080"

[stream]
listen = "invalid:address"

[[stream.upstreams]]
name = "backend"
servers = ["127.0.0.1:3001"]

[upstreams.backend]
backends = ["127.0.0.1:3000"]

[[routes]]
upstream = "backend"
[routes.match]
path_prefix = "/"
"#;

        let result = Config::parse(config);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Invalid stream listen address"));
    }

    #[test]
    fn test_stream_undefined_default_upstream() {
        let config = r#"
[server]
listen = "127.0.0.1:8080"

[stream]
listen = "0.0.0.0:443"
default_upstream = "nonexistent"

[[stream.upstreams]]
name = "backend"
servers = ["127.0.0.1:3001"]

[upstreams.backend]
backends = ["127.0.0.1:3000"]

[[routes]]
upstream = "backend"
[routes.match]
path_prefix = "/"
"#;

        let result = Config::parse(config);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("default_upstream"));
    }

    #[test]
    fn test_stream_undefined_sni_route_upstream() {
        let config = r#"
[server]
listen = "127.0.0.1:8080"

[stream]
listen = "0.0.0.0:443"

[stream.sni_routes]
"api.example.com" = "nonexistent"

[[stream.upstreams]]
name = "backend"
servers = ["127.0.0.1:3001"]

[upstreams.backend]
backends = ["127.0.0.1:3000"]

[[routes]]
upstream = "backend"
[routes.match]
path_prefix = "/"
"#;

        let result = Config::parse(config);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("SNI route"));
    }

    #[test]
    fn test_stream_no_upstreams() {
        let config = r#"
[server]
listen = "127.0.0.1:8080"

[stream]
listen = "0.0.0.0:443"

[upstreams.backend]
backends = ["127.0.0.1:3000"]

[[routes]]
upstream = "backend"
[routes.match]
path_prefix = "/"
"#;

        let result = Config::parse(config);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("at least one upstream"));
    }

    #[test]
    fn test_stream_upstream_no_servers() {
        let config = r#"
[server]
listen = "127.0.0.1:8080"

[stream]
listen = "0.0.0.0:443"

[[stream.upstreams]]
name = "backend"
servers = []

[upstreams.backend]
backends = ["127.0.0.1:3000"]

[[routes]]
upstream = "backend"
[routes.match]
path_prefix = "/"
"#;

        let result = Config::parse(config);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("no servers"));
    }

    #[test]
    fn test_stream_proxy_protocol_variants() {
        let configs = vec![
            (r#"proxy_protocol = "none""#, ProxyProtocolConfig::None),
            (r#"proxy_protocol = "v1""#, ProxyProtocolConfig::V1),
            (r#"proxy_protocol = "v2""#, ProxyProtocolConfig::V2),
        ];

        for (proto_line, expected) in configs {
            let config = format!(
                r#"
[server]
listen = "127.0.0.1:8080"

[stream]
listen = "0.0.0.0:443"
{}

[[stream.upstreams]]
name = "backend"
servers = ["127.0.0.1:3001"]

[upstreams.backend]
backends = ["127.0.0.1:3000"]

[[routes]]
upstream = "backend"
[routes.match]
path_prefix = "/"
"#,
                proto_line
            );

            let parsed = Config::parse(&config).unwrap();
            assert_eq!(parsed.stream.unwrap().proxy_protocol, expected);
        }
    }

    #[test]
    fn test_route_tls_auto() {
        let config = r#"
[server]
listen = "127.0.0.1:8080"

[upstreams.app1]
backends = ["127.0.0.1:3001"]

[upstreams.app2]
backends = ["127.0.0.1:3002"]

[[routes]]
name = "app1"
upstream = "app1"
tls = "auto"
[routes.match]
host = "app1.example.com"
path_prefix = "/"

[[routes]]
name = "app2"
upstream = "app2"
tls = "auto"
[routes.match]
host = "app2.example.com"
path_prefix = "/"
"#;

        let config = Config::parse(config).unwrap();
        assert_eq!(config.routes.len(), 2);
        assert_eq!(config.routes[0].tls, Some(RouteTlsConfig::Auto));
        assert_eq!(config.routes[1].tls, Some(RouteTlsConfig::Auto));

        let domains = config.collect_auto_tls_domains();
        assert_eq!(domains.len(), 2);
        assert!(domains.contains(&"app1.example.com".to_string()));
        assert!(domains.contains(&"app2.example.com".to_string()));
    }

    #[test]
    fn test_route_tls_cert_reference() {
        let config = r#"
[server]
listen = "127.0.0.1:8080"

[upstreams.backend]
backends = ["127.0.0.1:3000"]

[[routes]]
name = "api"
upstream = "backend"
tls = { cert = "my-cert" }
[routes.match]
host = "api.example.com"
path_prefix = "/"
"#;

        let config = Config::parse(config).unwrap();
        assert_eq!(
            config.routes[0].tls,
            Some(RouteTlsConfig::Cert("my-cert".to_string()))
        );
    }

    #[test]
    fn test_route_tls_off() {
        let config = r#"
[server]
listen = "127.0.0.1:8080"

[upstreams.backend]
backends = ["127.0.0.1:3000"]

[[routes]]
name = "health"
upstream = "backend"
tls = "off"
[routes.match]
path_prefix = "/health"
"#;

        let config = Config::parse(config).unwrap();
        assert_eq!(config.routes[0].tls, Some(RouteTlsConfig::Off));
    }

    #[test]
    fn test_collect_auto_tls_domains_mixed() {
        let config = r#"
[server]
listen = "127.0.0.1:8080"

[upstreams.backend]
backends = ["127.0.0.1:3000"]

[[routes]]
name = "app1"
upstream = "backend"
tls = "auto"
[routes.match]
host = "app1.example.com"
path_prefix = "/"

[[routes]]
name = "app2"
upstream = "backend"
tls = "off"
[routes.match]
host = "app2.example.com"
path_prefix = "/"

[[routes]]
name = "app3"
upstream = "backend"
[routes.match]
host = "app3.example.com"
path_prefix = "/"

[[routes]]
name = "app4"
upstream = "backend"
tls = "auto"
[routes.match]
host = "app4.example.com"
path_prefix = "/"
"#;

        let config = Config::parse(config).unwrap();
        let domains = config.collect_auto_tls_domains();

        // Only app1 and app4 have tls = "auto"
        assert_eq!(domains.len(), 2);
        assert!(domains.contains(&"app1.example.com".to_string()));
        assert!(domains.contains(&"app4.example.com".to_string()));
        assert!(!domains.contains(&"app2.example.com".to_string()));
        assert!(!domains.contains(&"app3.example.com".to_string()));
    }

    #[test]
    fn test_has_auto_tls_routes() {
        let config_with_auto = r#"
[server]
listen = "127.0.0.1:8080"

[upstreams.backend]
backends = ["127.0.0.1:3000"]

[[routes]]
upstream = "backend"
tls = "auto"
[routes.match]
host = "example.com"
path_prefix = "/"
"#;

        let config_without_auto = r#"
[server]
listen = "127.0.0.1:8080"

[upstreams.backend]
backends = ["127.0.0.1:3000"]

[[routes]]
upstream = "backend"
[routes.match]
path_prefix = "/"
"#;

        assert!(Config::parse(config_with_auto).unwrap().has_auto_tls_routes());
        assert!(!Config::parse(config_without_auto)
            .unwrap()
            .has_auto_tls_routes());
    }
}
