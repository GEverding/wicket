//! TLS configuration types.
//!
//! Supports three modes:
//! - `acme`: Automatic certificate provisioning via Let's Encrypt with DNS-01 validation
//! - `file`: Static certificates loaded from disk with optional file watching
//! - `mixed`: Both ACME and file-based certificates

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
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
    /// Default DNS provider for per-route auto TLS (routes with `tls = "auto"`)
    #[serde(default)]
    pub default_dns: Option<DnsProviderConfig>,
    /// Named DNS providers for multi-account support
    /// Routes can reference these by name: `tls = { auto = "provider-name" }`
    #[serde(default)]
    pub dns_providers: HashMap<String, DnsProviderConfig>,
}

/// Domain with optional provider override for auto-TLS.
#[derive(Debug, Clone)]
pub struct AutoTlsDomain {
    /// The domain name
    pub domain: String,
    /// Optional DNS provider name (uses default_dns if None)
    pub provider: Option<String>,
}

impl AcmeConfig {
    /// Get all certificate configs, including auto-generated ones from route domains.
    ///
    /// Domains can optionally specify a provider name to use instead of default_dns.
    /// Provider names are resolved from the `dns_providers` map.
    pub fn all_certs_with_providers(
        &self,
        auto_tls_domains: &[AutoTlsDomain],
    ) -> Vec<AcmeCertConfig> {
        let mut all_certs = self.certs.clone();

        for auto_domain in auto_tls_domains {
            // Skip if already covered by explicit certs
            let already_covered = self
                .certs
                .iter()
                .any(|c| c.domains.contains(&auto_domain.domain));
            if already_covered {
                continue;
            }

            // Resolve DNS provider: named provider > default_dns
            let dns = if let Some(ref provider_name) = auto_domain.provider {
                self.dns_providers.get(provider_name).cloned()
            } else {
                self.default_dns.clone()
            };

            if let Some(dns) = dns {
                all_certs.push(AcmeCertConfig {
                    domains: vec![auto_domain.domain.clone()],
                    dns,
                });
            }
        }

        all_certs
    }

    /// Get all certificate configs (simple version for backwards compatibility).
    ///
    /// If `auto_tls_domains` is provided and `default_dns` is configured,
    /// generates additional cert configs for each domain.
    pub fn all_certs(&self, auto_tls_domains: &[String]) -> Vec<AcmeCertConfig> {
        let domains: Vec<AutoTlsDomain> = auto_tls_domains
            .iter()
            .map(|d| AutoTlsDomain {
                domain: d.clone(),
                provider: None,
            })
            .collect();
        self.all_certs_with_providers(&domains)
    }
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

    #[test]
    fn test_parse_dns_providers_map() {
        let toml = r#"
            mode = "acme"

            [acme]
            email = "admin@example.com"

            [acme.default_dns]
            provider = "cloudflare"
            api_token = "default-token"

            [acme.dns_providers.acme-corp]
            provider = "cloudflare"
            api_token = "acme-corp-token"
            zone_id = "zone-acme"

            [acme.dns_providers.other-account]
            provider = "cloudflare"
            api_token = "other-token"
        "#;

        let config: TlsConfig = toml::from_str(toml).unwrap();
        let acme = config.acme.unwrap();

        assert!(acme.default_dns.is_some());
        assert_eq!(acme.default_dns.as_ref().unwrap().api_token, "default-token");

        assert_eq!(acme.dns_providers.len(), 2);

        let acme_corp = acme.dns_providers.get("acme-corp").unwrap();
        assert_eq!(acme_corp.api_token, "acme-corp-token");
        assert_eq!(acme_corp.zone_id, Some("zone-acme".to_string()));

        let other = acme.dns_providers.get("other-account").unwrap();
        assert_eq!(other.api_token, "other-token");
        assert_eq!(other.zone_id, None);
    }

    #[test]
    fn test_all_certs_with_providers() {
        let acme_config = AcmeConfig {
            email: "admin@example.com".to_string(),
            staging: false,
            storage: PathBuf::from("/tmp/acme"),
            renew_before_days: 30,
            certs: vec![AcmeCertConfig {
                domains: vec!["explicit.example.com".to_string()],
                dns: DnsProviderConfig {
                    provider: "cloudflare".to_string(),
                    api_token: "explicit-token".to_string(),
                    zone_id: None,
                },
            }],
            default_dns: Some(DnsProviderConfig {
                provider: "cloudflare".to_string(),
                api_token: "default-token".to_string(),
                zone_id: None,
            }),
            dns_providers: [
                (
                    "acme-corp".to_string(),
                    DnsProviderConfig {
                        provider: "cloudflare".to_string(),
                        api_token: "acme-corp-token".to_string(),
                        zone_id: Some("zone-acme".to_string()),
                    },
                ),
                (
                    "other-account".to_string(),
                    DnsProviderConfig {
                        provider: "cloudflare".to_string(),
                        api_token: "other-token".to_string(),
                        zone_id: None,
                    },
                ),
            ]
            .into_iter()
            .collect(),
        };

        let auto_domains = vec![
            AutoTlsDomain {
                domain: "app1.example.com".to_string(),
                provider: Some("acme-corp".to_string()),
            },
            AutoTlsDomain {
                domain: "app2.example.com".to_string(),
                provider: None, // uses default_dns
            },
            AutoTlsDomain {
                domain: "app3.example.com".to_string(),
                provider: Some("other-account".to_string()),
            },
            AutoTlsDomain {
                domain: "explicit.example.com".to_string(), // already in certs, should be skipped
                provider: None,
            },
        ];

        let all_certs = acme_config.all_certs_with_providers(&auto_domains);

        // 1 explicit + 3 auto (1 skipped because already covered)
        assert_eq!(all_certs.len(), 4);

        // Explicit cert is first
        assert_eq!(all_certs[0].domains, vec!["explicit.example.com"]);
        assert_eq!(all_certs[0].dns.api_token, "explicit-token");

        // app1 uses acme-corp provider
        let app1 = all_certs.iter().find(|c| c.domains[0] == "app1.example.com").unwrap();
        assert_eq!(app1.dns.api_token, "acme-corp-token");
        assert_eq!(app1.dns.zone_id, Some("zone-acme".to_string()));

        // app2 uses default_dns
        let app2 = all_certs.iter().find(|c| c.domains[0] == "app2.example.com").unwrap();
        assert_eq!(app2.dns.api_token, "default-token");

        // app3 uses other-account provider
        let app3 = all_certs.iter().find(|c| c.domains[0] == "app3.example.com").unwrap();
        assert_eq!(app3.dns.api_token, "other-token");
    }

    #[test]
    fn test_all_certs_unknown_provider_skipped() {
        let acme_config = AcmeConfig {
            email: "admin@example.com".to_string(),
            staging: false,
            storage: PathBuf::from("/tmp/acme"),
            renew_before_days: 30,
            certs: vec![],
            default_dns: None,
            dns_providers: Default::default(),
        };

        let auto_domains = vec![AutoTlsDomain {
            domain: "app.example.com".to_string(),
            provider: Some("nonexistent".to_string()),
        }];

        let all_certs = acme_config.all_certs_with_providers(&auto_domains);

        // Domain with unknown provider and no default_dns is skipped
        assert_eq!(all_certs.len(), 0);
    }
}
