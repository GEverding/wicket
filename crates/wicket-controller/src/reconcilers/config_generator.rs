//! Configuration generator that converts Gateway API resources to Wicket TOML config.

use regex::RegexBuilder;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use tracing::warn;

use crate::crds::{
    BackendRef, Gateway, GatewaySpec, HTTPRoute, HTTPRouteRule, Listener, ProtocolType, TCPRoute,
    TLSRoute,
};

/// Generated Wicket configuration that matches wicket-config format.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct WicketConfig {
    pub server: ServerConfig,

    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub upstreams: HashMap<String, UpstreamConfig>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub routes: Vec<RouteConfig>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls: Option<TlsConfig>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub stream: Option<StreamConfig>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServerConfig {
    pub listen: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub workers: Option<usize>,

    #[serde(default)]
    pub json_logs: bool,

    #[serde(default = "default_log_level")]
    pub log_level: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub shutdown_timeout: Option<u64>,
}

fn default_log_level() -> String {
    "info".to_string()
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: "0.0.0.0:8080".to_string(),
            workers: None,
            json_logs: true,
            log_level: default_log_level(),
            shutdown_timeout: Some(30),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UpstreamConfig {
    pub backends: Vec<String>,

    #[serde(default = "default_strategy")]
    pub strategy: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub health_check: Option<HealthCheckConfig>,
}

fn default_strategy() -> String {
    "round_robin".to_string()
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HealthCheckConfig {
    pub path: String,

    #[serde(default = "default_interval")]
    pub interval: u64,

    #[serde(default = "default_unhealthy_threshold")]
    pub unhealthy_threshold: u32,
}

fn default_interval() -> u64 {
    10
}

fn default_unhealthy_threshold() -> u32 {
    3
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RouteConfig {
    pub name: String,
    pub upstream: String,

    #[serde(rename = "match")]
    pub route_match: RouteMatchConfig,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls: Option<RouteTlsConfig>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub filters: Option<RouteFilters>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u64>,
}

/// Filters that can be applied to requests and responses.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RouteFilters {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_headers: Option<HeaderModifier>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_headers: Option<HeaderModifier>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect: Option<RedirectFilter>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub url_rewrite: Option<UrlRewriteFilter>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub mirror: Option<MirrorFilter>,
}

impl RouteFilters {
    pub fn is_empty(&self) -> bool {
        self.request_headers.is_none()
            && self.response_headers.is_none()
            && self.redirect.is_none()
            && self.url_rewrite.is_none()
            && self.mirror.is_none()
    }
}

/// Header modification filter.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct HeaderModifier {
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub add: HashMap<String, String>,

    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub set: HashMap<String, String>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub remove: Vec<String>,
}

impl HeaderModifier {
    pub fn is_empty(&self) -> bool {
        self.add.is_empty() && self.set.is_empty() && self.remove.is_empty()
    }
}

/// Redirect filter configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RedirectFilter {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scheme: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<PathModifier>,

    #[serde(default = "default_redirect_status")]
    pub status_code: u16,
}

fn default_redirect_status() -> u16 {
    302
}

/// Path modification for redirects and rewrites.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathModifier {
    ReplaceFullPath(String),
    ReplacePrefixMatch(String),
}

/// URL rewrite filter configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UrlRewriteFilter {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<PathModifier>,
}

/// Request mirroring filter configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MirrorFilter {
    pub upstream: String,

    #[serde(default = "default_mirror_percent")]
    pub percent: u8,
}

fn default_mirror_percent() -> u8 {
    100
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RouteMatchConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub path_prefix: Option<String>,

    /// Regular expression path match
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path_regex: Option<String>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub methods: Vec<String>,

    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub headers: HashMap<String, String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RouteTlsConfig {
    Auto(String),
    Off,
    Cert { cert: String },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TlsConfig {
    pub mode: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<FileTlsConfig>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub acme: Option<AcmeTlsConfig>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FileTlsConfig {
    #[serde(default)]
    pub watch: bool,

    #[serde(default = "default_poll_interval")]
    pub poll_interval_secs: u64,

    #[serde(default)]
    pub certs: Vec<CertConfig>,
}

fn default_poll_interval() -> u64 {
    30
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CertConfig {
    pub name: String,
    pub cert: String,
    pub key: String,

    #[serde(default)]
    pub domains: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AcmeTlsConfig {
    pub email: String,

    #[serde(default)]
    pub staging: bool,

    pub storage: String,

    #[serde(default = "default_renew_before_days")]
    pub renew_before_days: u32,
}

fn default_renew_before_days() -> u32 {
    30
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StreamConfig {
    pub listen: String,

    #[serde(default = "default_backlog")]
    pub backlog: u32,

    #[serde(default)]
    pub reuseport: bool,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy_protocol: Option<String>,

    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub sni_routes: HashMap<String, String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_upstream: Option<String>,

    #[serde(default)]
    pub upstreams: Vec<StreamUpstreamConfig>,
}

fn default_backlog() -> u32 {
    8000
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StreamUpstreamConfig {
    pub name: String,
    pub servers: Vec<String>,
}

/// Endpoint information for a Kubernetes Service.
#[derive(Clone, Debug)]
pub struct ServiceEndpoints {
    pub namespace: String,
    pub name: String,
    pub port: u16,
    pub endpoints: Vec<String>,
}

/// State collected from Gateway API resources.
#[derive(Clone, Debug, Default)]
pub struct GatewayState {
    /// Gateways by namespace/name.
    pub gateways: HashMap<String, Gateway>,

    /// HTTPRoutes by namespace/name.
    pub http_routes: HashMap<String, HTTPRoute>,

    /// TCPRoutes by namespace/name.
    pub tcp_routes: HashMap<String, TCPRoute>,

    /// TLSRoutes by namespace/name.
    pub tls_routes: HashMap<String, TLSRoute>,

    /// Service endpoints by namespace/name.
    pub service_endpoints: HashMap<String, ServiceEndpoints>,

    /// TLS secrets by namespace/name (cert_path, key_path).
    pub tls_secrets: HashMap<String, (String, String)>,
}

/// Validates a regex pattern for complexity and ReDoS vulnerability.
///
/// Checks:
/// - Pattern length <= 1000 characters
/// - Compiled regex size <= 100,000 bytes
/// - Rejects patterns with nested quantifiers like `(a+)+` or `(a*)*`
///
/// Returns `Some(pattern)` if valid, `None` if invalid.
fn validate_regex_pattern(pattern: &str) -> Option<String> {
    const MAX_PATTERN_LEN: usize = 1000;
    const MAX_COMPILED_SIZE: usize = 100_000;

    // Check pattern length
    if pattern.len() > MAX_PATTERN_LEN {
        warn!(
            pattern_len = pattern.len(),
            max_len = MAX_PATTERN_LEN,
            "Regex pattern exceeds maximum length"
        );
        return None;
    }

    // Check for nested quantifiers: (a+)+, (a*)*, (a+)*, (a*)+, etc.
    // Look for )+, )*, )+?, )*? patterns which indicate quantifier after group
    if pattern.contains(")+") || pattern.contains(")*") {
        warn!("Regex pattern contains nested quantifiers");
        return None;
    }

    // Try to compile with size limit
    match RegexBuilder::new(pattern)
        .size_limit(MAX_COMPILED_SIZE)
        .build()
    {
        Ok(_) => Some(pattern.to_string()),
        Err(e) => {
            warn!(
                error = %e,
                "Failed to compile regex pattern or exceeded size limit"
            );
            None
        }
    }
}

impl GatewayState {
    /// Create a key from namespace and name.
    pub fn key(namespace: &str, name: &str) -> String {
        format!("{}/{}", namespace, name)
    }

    /// Convert HTTPRoute filters to RouteFilters.
    fn convert_filters(
        filters: &[crate::crds::HTTPRouteFilter],
        route_ns: &str,
        upstreams: &mut HashMap<String, UpstreamConfig>,
        service_endpoints: &HashMap<String, ServiceEndpoints>,
    ) -> Option<RouteFilters> {
        use crate::crds::HTTPRouteFilterType;

        let mut result = RouteFilters::default();
        let mut has_filters = false;

        for filter in filters {
            match filter.type_ {
                HTTPRouteFilterType::RequestHeaderModifier => {
                    if let Some(ref modifier) = filter.request_header_modifier {
                        let mut header_mod = HeaderModifier::default();
                        for h in &modifier.add {
                            header_mod.add.insert(h.name.clone(), h.value.clone());
                        }
                        for h in &modifier.set {
                            header_mod.set.insert(h.name.clone(), h.value.clone());
                        }
                        header_mod.remove = modifier.remove.clone();
                        if !header_mod.is_empty() {
                            result.request_headers = Some(header_mod);
                            has_filters = true;
                        }
                    }
                }
                HTTPRouteFilterType::ResponseHeaderModifier => {
                    if let Some(ref modifier) = filter.response_header_modifier {
                        let mut header_mod = HeaderModifier::default();
                        for h in &modifier.add {
                            header_mod.add.insert(h.name.clone(), h.value.clone());
                        }
                        for h in &modifier.set {
                            header_mod.set.insert(h.name.clone(), h.value.clone());
                        }
                        header_mod.remove = modifier.remove.clone();
                        if !header_mod.is_empty() {
                            result.response_headers = Some(header_mod);
                            has_filters = true;
                        }
                    }
                }
                HTTPRouteFilterType::RequestRedirect => {
                    if let Some(ref redirect) = filter.request_redirect {
                        let path = redirect.path.as_ref().map(|p| match p.type_ {
                            crate::crds::HTTPPathModifierType::ReplaceFullPath => {
                                PathModifier::ReplaceFullPath(
                                    p.replace_full_path.clone().unwrap_or_default(),
                                )
                            }
                            crate::crds::HTTPPathModifierType::ReplacePrefixMatch => {
                                PathModifier::ReplacePrefixMatch(
                                    p.replace_prefix_match.clone().unwrap_or_default(),
                                )
                            }
                        });
                        result.redirect = Some(RedirectFilter {
                            scheme: redirect.scheme.clone(),
                            hostname: redirect.hostname.clone(),
                            port: redirect.port,
                            path,
                            status_code: redirect.status_code as u16,
                        });
                        has_filters = true;
                    }
                }
                HTTPRouteFilterType::URLRewrite => {
                    if let Some(ref rewrite) = filter.url_rewrite {
                        let path = rewrite.path.as_ref().map(|p| match p.type_ {
                            crate::crds::HTTPPathModifierType::ReplaceFullPath => {
                                PathModifier::ReplaceFullPath(
                                    p.replace_full_path.clone().unwrap_or_default(),
                                )
                            }
                            crate::crds::HTTPPathModifierType::ReplacePrefixMatch => {
                                PathModifier::ReplacePrefixMatch(
                                    p.replace_prefix_match.clone().unwrap_or_default(),
                                )
                            }
                        });
                        result.url_rewrite = Some(UrlRewriteFilter {
                            hostname: rewrite.hostname.clone(),
                            path,
                        });
                        has_filters = true;
                    }
                }
                HTTPRouteFilterType::RequestMirror => {
                    if let Some(ref mirror) = filter.request_mirror {
                        let backend_ns =
                            mirror.backend_ref.namespace.as_deref().unwrap_or(route_ns);
                        let mirror_upstream_name =
                            format!("mirror-{}-{}", backend_ns, mirror.backend_ref.name);

                        // Create upstream for mirror backend
                        let backend_key = Self::key(backend_ns, &mirror.backend_ref.name);
                        let backends = if let Some(endpoints) = service_endpoints.get(&backend_key)
                        {
                            endpoints.endpoints.clone()
                        } else {
                            let port = mirror.backend_ref.port.unwrap_or(80);
                            vec![format!(
                                "{}.{}.svc.cluster.local:{}",
                                mirror.backend_ref.name, backend_ns, port
                            )]
                        };

                        upstreams.insert(
                            mirror_upstream_name.clone(),
                            UpstreamConfig {
                                backends,
                                strategy: "round_robin".to_string(),
                                health_check: None,
                            },
                        );

                        result.mirror = Some(MirrorFilter {
                            upstream: mirror_upstream_name,
                            percent: mirror.percent.map(|p| p as u8).unwrap_or(100),
                        });
                        has_filters = true;
                    }
                }
                HTTPRouteFilterType::ExtensionRef => {
                    // Extension filters not supported yet
                }
            }
        }

        if has_filters {
            Some(result)
        } else {
            None
        }
    }

    /// Parse Duration string to seconds.
    fn parse_duration_to_secs(duration: &str) -> Option<u64> {
        // Gateway API uses Go duration format like "10s", "1m", "1h"
        let duration = duration.trim();
        if duration.is_empty() {
            return None;
        }

        let (num, unit) = duration.split_at(duration.len() - 1);
        let num: u64 = num.parse().ok()?;

        match unit {
            "s" => Some(num),
            "m" => Some(num * 60),
            "h" => Some(num * 3600),
            _ => None,
        }
    }

    /// Generate Wicket configuration from the current state.
    pub fn generate_config(&self) -> WicketConfig {
        let mut config = WicketConfig::default();
        let mut upstreams = HashMap::new();
        let mut routes = Vec::new();
        let mut tls_certs = Vec::new();
        let mut stream_config: Option<StreamConfig> = None;

        // Determine listeners from gateways
        let mut http_listeners: Vec<(String, &Listener)> = Vec::new();
        let mut tcp_listeners: Vec<(String, &Listener)> = Vec::new();

        for (gw_key, gateway) in &self.gateways {
            for listener in &gateway.spec.listeners {
                match listener.protocol {
                    ProtocolType::HTTP | ProtocolType::HTTPS => {
                        http_listeners.push((gw_key.clone(), listener));
                    }
                    ProtocolType::TCP | ProtocolType::TLS => {
                        tcp_listeners.push((gw_key.clone(), listener));
                    }
                    _ => {}
                }
            }
        }

        // Set server listen address from first HTTP listener
        if let Some((_, listener)) = http_listeners.first() {
            config.server.listen = format!("0.0.0.0:{}", listener.port);
        }

        // Process HTTPRoutes
        for (route_key, route) in &self.http_routes {
            let route_ns = route.metadata.namespace.as_deref().unwrap_or("default");
            let route_name = route.metadata.name.as_deref().unwrap_or("unknown");

            for (rule_idx, rule) in route.spec.rules.iter().enumerate() {
                // Create upstream from backend refs
                let upstream_name = format!("{}-{}-rule{}", route_ns, route_name, rule_idx);

                let mut backend_addrs = Vec::new();
                for backend_ref in &rule.backend_refs {
                    let backend_ns = backend_ref
                        .backend_ref
                        .namespace
                        .as_deref()
                        .unwrap_or(route_ns);
                    let backend_key = Self::key(backend_ns, &backend_ref.backend_ref.name);

                    if let Some(endpoints) = self.service_endpoints.get(&backend_key) {
                        backend_addrs.extend(endpoints.endpoints.clone());
                    } else {
                        // Fallback to DNS name
                        let port = backend_ref.backend_ref.port.unwrap_or(80);
                        backend_addrs.push(format!(
                            "{}.{}.svc.cluster.local:{}",
                            backend_ref.backend_ref.name, backend_ns, port
                        ));
                    }
                }

                if !backend_addrs.is_empty() {
                    upstreams.insert(
                        upstream_name.clone(),
                        UpstreamConfig {
                            backends: backend_addrs,
                            strategy: "round_robin".to_string(),
                            health_check: None,
                        },
                    );

                    // Convert filters from the rule
                    let filters = Self::convert_filters(
                        &rule.filters,
                        route_ns,
                        &mut upstreams,
                        &self.service_endpoints,
                    );

                    // Parse timeout from rule
                    let timeout = rule.timeouts.as_ref().and_then(|t| {
                        t.request
                            .as_ref()
                            .and_then(|d| Self::parse_duration_to_secs(d))
                    });

                    // Create routes from matches
                    if rule.matches.is_empty() {
                        // Default match - all traffic
                        let route_config = RouteConfig {
                            name: format!("{}-{}-rule{}", route_ns, route_name, rule_idx),
                            upstream: upstream_name.clone(),
                            route_match: RouteMatchConfig {
                                host: route.spec.hostnames.first().cloned(),
                                path: None,
                                path_prefix: Some("/".to_string()),
                                path_regex: None,
                                methods: vec![],
                                headers: HashMap::new(),
                            },
                            tls: None,
                            filters: filters.clone(),
                            timeout,
                        };
                        routes.push(route_config);
                    } else {
                        for (match_idx, route_match) in rule.matches.iter().enumerate() {
                            let (path, path_prefix, path_regex) = if let Some(ref path_match) =
                                route_match.path
                            {
                                match path_match.type_ {
                                    crate::crds::PathMatchType::Exact => {
                                        (Some(path_match.value.clone()), None, None)
                                    }
                                    crate::crds::PathMatchType::PathPrefix => {
                                        (None, Some(path_match.value.clone()), None)
                                    }
                                    crate::crds::PathMatchType::RegularExpression => {
                                        // Validate regex pattern for ReDoS vulnerability
                                        match validate_regex_pattern(&path_match.value) {
                                            Some(validated_pattern) => {
                                                (None, None, Some(validated_pattern))
                                            }
                                            None => {
                                                warn!(
                                                    route = %format!("{}/{}", route_ns, route_name),
                                                    rule_idx = rule_idx,
                                                    match_idx = match_idx,
                                                    pattern = %path_match.value,
                                                    "Skipping route match due to invalid regex pattern"
                                                );
                                                continue;
                                            }
                                        }
                                    }
                                }
                            } else {
                                (None, Some("/".to_string()), None)
                            };

                            let methods: Vec<String> = route_match
                                .method
                                .iter()
                                .map(|m| format!("{:?}", m))
                                .collect();

                            let headers: HashMap<String, String> = route_match
                                .headers
                                .iter()
                                .map(|h| (h.name.clone(), h.value.clone()))
                                .collect();

                            let route_config = RouteConfig {
                                name: format!(
                                    "{}-{}-rule{}-match{}",
                                    route_ns, route_name, rule_idx, match_idx
                                ),
                                upstream: upstream_name.clone(),
                                route_match: RouteMatchConfig {
                                    host: route.spec.hostnames.first().cloned(),
                                    path,
                                    path_prefix,
                                    path_regex,
                                    methods,
                                    headers,
                                },
                                tls: None,
                                filters: filters.clone(),
                                timeout,
                            };
                            routes.push(route_config);
                        }
                    }
                }
            }
        }

        // Process TLS configuration from Gateway listeners
        for (gw_key, gateway) in &self.gateways {
            let gw_ns = gateway.metadata.namespace.as_deref().unwrap_or("default");

            for listener in &gateway.spec.listeners {
                if let Some(ref tls_config) = listener.tls {
                    for cert_ref in &tls_config.certificate_refs {
                        let cert_ns = cert_ref.namespace.as_deref().unwrap_or(gw_ns);
                        let cert_key = Self::key(cert_ns, &cert_ref.name);

                        if let Some((cert_path, key_path)) = self.tls_secrets.get(&cert_key) {
                            tls_certs.push(CertConfig {
                                name: cert_ref.name.clone(),
                                cert: cert_path.clone(),
                                key: key_path.clone(),
                                domains: listener.hostname.iter().cloned().collect(),
                            });
                        }
                    }
                }
            }
        }

        // Process TCPRoutes and TLSRoutes for stream config
        if !self.tcp_routes.is_empty() || !self.tls_routes.is_empty() {
            let mut sni_routes = HashMap::new();
            let mut stream_upstreams = Vec::new();

            for (route_key, route) in &self.tls_routes {
                let route_ns = route.metadata.namespace.as_deref().unwrap_or("default");
                let route_name = route.metadata.name.as_deref().unwrap_or("unknown");

                for hostname in &route.spec.hostnames {
                    for rule in &route.spec.rules {
                        for backend_ref in &rule.backend_refs {
                            let upstream_name = format!("{}-{}", route_ns, backend_ref.name);
                            let backend_ns = backend_ref.namespace.as_deref().unwrap_or(route_ns);
                            let backend_key = Self::key(backend_ns, &backend_ref.name);

                            let servers =
                                if let Some(endpoints) = self.service_endpoints.get(&backend_key) {
                                    endpoints.endpoints.clone()
                                } else {
                                    let port = backend_ref.port.unwrap_or(443);
                                    vec![format!(
                                        "{}.{}.svc.cluster.local:{}",
                                        backend_ref.name, backend_ns, port
                                    )]
                                };

                            stream_upstreams.push(StreamUpstreamConfig {
                                name: upstream_name.clone(),
                                servers,
                            });

                            sni_routes.insert(hostname.clone(), upstream_name);
                        }
                    }
                }
            }

            // Set stream config if we have TCP listeners
            if let Some((_, listener)) = tcp_listeners.first() {
                stream_config = Some(StreamConfig {
                    listen: format!("0.0.0.0:{}", listener.port),
                    backlog: 8000,
                    reuseport: true,
                    proxy_protocol: None,
                    sni_routes,
                    default_upstream: None,
                    upstreams: stream_upstreams,
                });
            }
        }

        // Set TLS config if we have certificates
        if !tls_certs.is_empty() {
            config.tls = Some(TlsConfig {
                mode: "file".to_string(),
                file: Some(FileTlsConfig {
                    watch: true,
                    poll_interval_secs: 30,
                    certs: tls_certs,
                }),
                acme: None,
            });
        }

        config.upstreams = upstreams;
        config.routes = routes;
        config.stream = stream_config;

        config
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crds::{
        GatewaySpec, HTTPBackendRef, HTTPRouteRule, HTTPRouteSpec, Listener, ParentReference,
        ProtocolType,
    };
    use kube::core::ObjectMeta;

    #[test]
    fn test_generate_basic_config() {
        let mut state = GatewayState::default();

        // Add a gateway
        let gateway = Gateway {
            metadata: ObjectMeta {
                name: Some("test-gateway".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            },
            spec: GatewaySpec {
                gateway_class_name: "wicket".to_string(),
                listeners: vec![Listener {
                    name: "http".to_string(),
                    hostname: Some("*.example.com".to_string()),
                    port: 8080,
                    protocol: ProtocolType::HTTP,
                    tls: None,
                    allowed_routes: None,
                }],
                addresses: vec![],
                infrastructure: None,
            },
            status: None,
        };
        state
            .gateways
            .insert(GatewayState::key("default", "test-gateway"), gateway);

        // Add an HTTPRoute
        let route = HTTPRoute {
            metadata: ObjectMeta {
                name: Some("test-route".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            },
            spec: HTTPRouteSpec {
                parent_refs: vec![],
                hostnames: vec!["api.example.com".to_string()],
                rules: vec![HTTPRouteRule {
                    name: None,
                    matches: vec![],
                    filters: vec![],
                    backend_refs: vec![HTTPBackendRef {
                        backend_ref: crate::crds::BackendRef {
                            group: "".to_string(),
                            kind: "Service".to_string(),
                            name: "api-svc".to_string(),
                            namespace: None,
                            port: Some(80),
                            weight: 1,
                        },
                        filters: vec![],
                    }],
                    timeouts: None,
                }],
            },
            status: None,
        };
        state
            .http_routes
            .insert(GatewayState::key("default", "test-route"), route);

        // Add service endpoints
        state.service_endpoints.insert(
            GatewayState::key("default", "api-svc"),
            ServiceEndpoints {
                namespace: "default".to_string(),
                name: "api-svc".to_string(),
                port: 80,
                endpoints: vec!["10.0.0.1:80".to_string(), "10.0.0.2:80".to_string()],
            },
        );

        let config = state.generate_config();

        assert_eq!(config.server.listen, "0.0.0.0:8080");
        assert_eq!(config.upstreams.len(), 1);
        assert_eq!(config.routes.len(), 1);

        let upstream = config.upstreams.get("default-test-route-rule0").unwrap();
        assert_eq!(upstream.backends.len(), 2);
        assert!(upstream.backends.contains(&"10.0.0.1:80".to_string()));
    }

    #[test]
    fn test_validate_regex_pattern_valid() {
        // Valid simple patterns should pass
        assert!(validate_regex_pattern("^/api/.*").is_some());
        assert!(validate_regex_pattern("^/users/[0-9]+$").is_some());
        assert!(validate_regex_pattern(".*\\.json$").is_some());
    }

    #[test]
    fn test_validate_regex_pattern_nested_quantifiers() {
        // Nested quantifiers should be rejected
        assert!(validate_regex_pattern("(a+)+").is_none());
        assert!(validate_regex_pattern("(a*)*").is_none());
        assert!(validate_regex_pattern("(a+)*").is_none());
        assert!(validate_regex_pattern("(a*)+").is_none());
    }

    #[test]
    fn test_validate_regex_pattern_too_long() {
        // Pattern exceeding max length should be rejected
        let long_pattern = "a".repeat(1001);
        assert!(validate_regex_pattern(&long_pattern).is_none());
    }

    #[test]
    fn test_validate_regex_pattern_max_length_boundary() {
        // Pattern at exactly max length should pass
        let max_pattern = "a".repeat(1000);
        assert!(validate_regex_pattern(&max_pattern).is_some());
    }

    #[test]
    fn test_validate_regex_pattern_invalid_syntax() {
        // Invalid regex syntax should be rejected
        assert!(validate_regex_pattern("[invalid").is_none());
        assert!(validate_regex_pattern("(?P<invalid").is_none());
    }

    /// Test: Config generation with valid Gateway + HTTPRoute + backends.
    #[test]
    fn test_config_generation_integration_with_valid_resources() {
        let mut state = GatewayState::default();

        // Add a Wicket-managed Gateway
        let gateway = Gateway {
            metadata: ObjectMeta {
                name: Some("test-gateway".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            },
            spec: GatewaySpec {
                gateway_class_name: "wicket".to_string(),
                listeners: vec![Listener {
                    name: "http".to_string(),
                    hostname: Some("*.example.com".to_string()),
                    port: 8080,
                    protocol: ProtocolType::HTTP,
                    tls: None,
                    allowed_routes: None,
                }],
                addresses: vec![],
                infrastructure: None,
            },
            status: None,
        };
        state
            .gateways
            .insert(GatewayState::key("default", "test-gateway"), gateway);

        // Add an HTTPRoute
        let route = HTTPRoute {
            metadata: ObjectMeta {
                name: Some("test-route".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            },
            spec: HTTPRouteSpec {
                parent_refs: vec![ParentReference {
                    group: "gateway.networking.k8s.io".to_string(),
                    kind: "Gateway".to_string(),
                    name: "test-gateway".to_string(),
                    namespace: None,
                    section_name: None,
                    port: None,
                }],
                hostnames: vec!["api.example.com".to_string()],
                rules: vec![HTTPRouteRule {
                    name: None,
                    matches: vec![],
                    filters: vec![],
                    backend_refs: vec![HTTPBackendRef {
                        backend_ref: crate::crds::BackendRef {
                            group: "".to_string(),
                            kind: "Service".to_string(),
                            name: "api-svc".to_string(),
                            namespace: None,
                            port: Some(80),
                            weight: 1,
                        },
                        filters: vec![],
                    }],
                    timeouts: None,
                }],
            },
            status: None,
        };
        state
            .http_routes
            .insert(GatewayState::key("default", "test-route"), route);

        // Add service endpoints
        state.service_endpoints.insert(
            GatewayState::key("default", "api-svc"),
            ServiceEndpoints {
                namespace: "default".to_string(),
                name: "api-svc".to_string(),
                port: 80,
                endpoints: vec!["10.0.0.1:80".to_string(), "10.0.0.2:80".to_string()],
            },
        );

        // Generate config
        let config = state.generate_config();

        // Verify server config from Gateway listener
        assert_eq!(config.server.listen, "0.0.0.0:8080");

        // Verify upstreams from HTTPRoute backend
        assert_eq!(config.upstreams.len(), 1);
        let upstream = config.upstreams.get("default-test-route-rule0").unwrap();
        assert_eq!(upstream.backends.len(), 2);
        assert!(upstream.backends.contains(&"10.0.0.1:80".to_string()));
        assert!(upstream.backends.contains(&"10.0.0.2:80".to_string()));

        // Verify routes from HTTPRoute
        assert_eq!(config.routes.len(), 1);
        let route_config = &config.routes[0];
        assert_eq!(route_config.name, "default-test-route-rule0");
        assert_eq!(route_config.upstream, "default-test-route-rule0");
        assert_eq!(
            route_config.route_match.host,
            Some("api.example.com".to_string())
        );
        assert_eq!(route_config.route_match.path_prefix, Some("/".to_string()));
    }

    /// Test: Config generation with multiple routes and upstreams.
    #[test]
    fn test_config_generation_with_multiple_routes() {
        let mut state = GatewayState::default();

        // Add a Gateway
        let gateway = Gateway {
            metadata: ObjectMeta {
                name: Some("test-gateway".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            },
            spec: GatewaySpec {
                gateway_class_name: "wicket".to_string(),
                listeners: vec![Listener {
                    name: "http".to_string(),
                    hostname: None,
                    port: 8080,
                    protocol: ProtocolType::HTTP,
                    tls: None,
                    allowed_routes: None,
                }],
                addresses: vec![],
                infrastructure: None,
            },
            status: None,
        };
        state
            .gateways
            .insert(GatewayState::key("default", "test-gateway"), gateway);

        // Add two HTTPRoutes with different backends
        for (i, (route_name, backend_name)) in
            [("frontend-route", "frontend-svc"), ("api-route", "api-svc")]
                .iter()
                .enumerate()
        {
            let route = HTTPRoute {
                metadata: ObjectMeta {
                    name: Some(route_name.to_string()),
                    namespace: Some("default".to_string()),
                    ..Default::default()
                },
                spec: HTTPRouteSpec {
                    parent_refs: vec![ParentReference {
                        group: "gateway.networking.k8s.io".to_string(),
                        kind: "Gateway".to_string(),
                        name: "test-gateway".to_string(),
                        namespace: None,
                        section_name: None,
                        port: None,
                    }],
                    hostnames: vec![],
                    rules: vec![HTTPRouteRule {
                        name: None,
                        matches: vec![],
                        filters: vec![],
                        backend_refs: vec![HTTPBackendRef {
                            backend_ref: crate::crds::BackendRef {
                                group: "".to_string(),
                                kind: "Service".to_string(),
                                name: backend_name.to_string(),
                                namespace: None,
                                port: Some(80),
                                weight: 1,
                            },
                            filters: vec![],
                        }],
                        timeouts: None,
                    }],
                },
                status: None,
            };
            state
                .http_routes
                .insert(GatewayState::key("default", route_name), route);

            // Add service endpoints
            state.service_endpoints.insert(
                GatewayState::key("default", backend_name),
                ServiceEndpoints {
                    namespace: "default".to_string(),
                    name: backend_name.to_string(),
                    port: 80,
                    endpoints: vec![format!("10.0.{}.1:80", i + 1)],
                },
            );
        }

        // Generate config
        let config = state.generate_config();

        // Verify multiple upstreams and routes
        assert_eq!(config.upstreams.len(), 2);
        assert_eq!(config.routes.len(), 2);
    }

    /// Test: Config generation with path match types.
    #[test]
    fn test_config_generation_with_path_matches() {
        let mut state = GatewayState::default();

        // Add minimal resources
        let gateway = Gateway {
            metadata: ObjectMeta {
                name: Some("test-gateway".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            },
            spec: GatewaySpec {
                gateway_class_name: "wicket".to_string(),
                listeners: vec![Listener {
                    name: "http".to_string(),
                    hostname: None,
                    port: 8080,
                    protocol: ProtocolType::HTTP,
                    tls: None,
                    allowed_routes: None,
                }],
                addresses: vec![],
                infrastructure: None,
            },
            status: None,
        };
        state
            .gateways
            .insert(GatewayState::key("default", "test-gateway"), gateway);

        let route = HTTPRoute {
            metadata: ObjectMeta {
                name: Some("test-route".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            },
            spec: HTTPRouteSpec {
                parent_refs: vec![ParentReference {
                    group: "gateway.networking.k8s.io".to_string(),
                    kind: "Gateway".to_string(),
                    name: "test-gateway".to_string(),
                    namespace: None,
                    section_name: None,
                    port: None,
                }],
                hostnames: vec![],
                rules: vec![
                    // Exact path match
                    HTTPRouteRule {
                        name: None,
                        matches: vec![crate::crds::HTTPRouteMatch {
                            path: Some(crate::crds::HTTPPathMatch {
                                type_: crate::crds::PathMatchType::Exact,
                                value: "/health".to_string(),
                            }),
                            headers: vec![],
                            query_params: vec![],
                            method: Some(crate::crds::HTTPMethod::GET),
                        }],
                        filters: vec![],
                        backend_refs: vec![HTTPBackendRef {
                            backend_ref: crate::crds::BackendRef {
                                group: "".to_string(),
                                kind: "Service".to_string(),
                                name: "backend".to_string(),
                                namespace: None,
                                port: Some(80),
                                weight: 1,
                            },
                            filters: vec![],
                        }],
                        timeouts: None,
                    },
                    // Prefix path match
                    HTTPRouteRule {
                        name: None,
                        matches: vec![crate::crds::HTTPRouteMatch {
                            path: Some(crate::crds::HTTPPathMatch {
                                type_: crate::crds::PathMatchType::PathPrefix,
                                value: "/api".to_string(),
                            }),
                            headers: vec![],
                            query_params: vec![],
                            method: None,
                        }],
                        filters: vec![],
                        backend_refs: vec![HTTPBackendRef {
                            backend_ref: crate::crds::BackendRef {
                                group: "".to_string(),
                                kind: "Service".to_string(),
                                name: "backend".to_string(),
                                namespace: None,
                                port: Some(80),
                                weight: 1,
                            },
                            filters: vec![],
                        }],
                        timeouts: None,
                    },
                ],
            },
            status: None,
        };
        state
            .http_routes
            .insert(GatewayState::key("default", "test-route"), route);

        state.service_endpoints.insert(
            GatewayState::key("default", "backend"),
            ServiceEndpoints {
                namespace: "default".to_string(),
                name: "backend".to_string(),
                port: 80,
                endpoints: vec!["10.0.0.1:80".to_string()],
            },
        );

        // Generate config
        let config = state.generate_config();

        // Verify routes with different path match types
        assert_eq!(config.routes.len(), 2);

        // First route: exact path match
        let exact_route = config
            .routes
            .iter()
            .find(|r| r.route_match.path.as_deref() == Some("/health"))
            .unwrap();
        assert_eq!(exact_route.route_match.path, Some("/health".to_string()));

        // Second route: path prefix match
        let prefix_route = config
            .routes
            .iter()
            .find(|r| r.route_match.path_prefix.as_deref() == Some("/api"))
            .unwrap();
        assert_eq!(
            prefix_route.route_match.path_prefix,
            Some("/api".to_string())
        );
    }
}
