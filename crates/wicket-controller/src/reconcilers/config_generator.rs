//! Configuration generator that converts Gateway API resources to Wicket TOML config.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use tracing::warn;

use crate::crds::{
    Gateway, HTTPRoute, Listener, ProtocolType, RouteParentStatus, TCPRoute, TLSRoute,
    WICKET_CONTROLLER_NAME,
};

use wicket_config::{RouteConfig, RouteMatch};

/// Generated Wicket configuration that matches wicket-config format.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct WicketConfig {
    pub server: ServerConfig,

    /// Upstream clusters keyed by name.  Uses `BTreeMap` so that TOML
    /// serialization is deterministic (keys are emitted in sorted order).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub upstreams: BTreeMap<String, UpstreamConfig>,

    /// Routes using the canonical wicket-config RouteConfig type.
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

    /// SNI routing table.  Uses `BTreeMap` so that TOML serialization is
    /// deterministic (keys are emitted in sorted order).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub sni_routes: BTreeMap<String, String>,

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
///
/// The `endpoints` vec contains pre-formatted `ip:port` addresses extracted
/// from EndpointSlice resources.  Ports come from the slice itself, so there
/// is no separate `port` field here.
#[derive(Clone, Debug)]
pub struct ServiceEndpoints {
    pub namespace: String,
    pub name: String,
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

/// Returns `true` if `parents` contains at least one entry where
/// `controller_name == WICKET_CONTROLLER_NAME` and the `Accepted` condition
/// status is `"True"`.
///
/// This is the single authoritative implementation of the render-time
/// accepted-parent check.  All three route-type wrappers
/// (`http_route_is_accepted`, `tcp_route_is_accepted`, `tls_route_is_accepted`)
/// delegate here so the semantics are identical across route types.
///
/// Exposed as `pub(crate)` so `context.rs` can reuse it in the fallback path
/// instead of maintaining three separate copies.
pub(crate) fn parents_accepted_by_wicket(parents: &[RouteParentStatus]) -> bool {
    parents.iter().any(|p| {
        p.controller_name == WICKET_CONTROLLER_NAME
            && p.conditions
                .iter()
                .any(|c| c.type_ == "Accepted" && c.status == "True")
    })
}

impl GatewayState {
    /// Create a key from namespace and name.
    pub fn key(namespace: &str, name: &str) -> String {
        format!("{}/{}", namespace, name)
    }

    /// Returns `true` if the HTTPRoute has at least one `status.parents` entry
    /// where `controller_name == WICKET_CONTROLLER_NAME` and the `Accepted`
    /// condition is `True`.
    ///
    /// Fail-closed: routes with no status (not yet reconciled) are excluded.
    fn http_route_is_accepted(route: &HTTPRoute) -> bool {
        let parents = match &route.status {
            Some(s) => s.parents.as_slice(),
            None => return false,
        };
        parents_accepted_by_wicket(parents)
    }

    /// Returns `true` if the TCPRoute has at least one `status.parents` entry
    /// where `controller_name == WICKET_CONTROLLER_NAME` and the `Accepted`
    /// condition is `True`.
    ///
    /// Fail-closed: routes with no status (not yet reconciled) are excluded.
    fn tcp_route_is_accepted(route: &TCPRoute) -> bool {
        let parents = match &route.status {
            Some(s) => s.parents.as_slice(),
            None => return false,
        };
        parents_accepted_by_wicket(parents)
    }

    /// Returns `true` if the TLSRoute has at least one `status.parents` entry
    /// where `controller_name == WICKET_CONTROLLER_NAME` and the `Accepted`
    /// condition is `True`.
    ///
    /// This is the render-time parity guard: routes that were never accepted by
    /// this controller (or whose status has not yet been written) are excluded
    /// from the generated stream config.  The store already only holds accepted
    /// routes, so in normal operation this is belt-and-suspenders; it becomes
    /// the primary guard if a route is injected into the store by other means.
    fn tls_route_is_accepted(route: &TLSRoute) -> bool {
        let parents = match &route.status {
            Some(s) => s.parents.as_slice(),
            // No status written yet → fail-closed: do not render.
            None => return false,
        };
        parents_accepted_by_wicket(parents)
    }

    /// Generate Wicket configuration with deterministic output.
    ///
    /// Identical to [`generate_config`] but iterates all internal `HashMap`
    /// fields in sorted key order so that the resulting `WicketConfig` --
    /// and therefore the serialized TOML -- is identical for the same logical
    /// state regardless of `HashMap` insertion order.
    ///
    /// Use this method whenever the output will be hashed or compared for
    /// change detection.
    pub fn generate_config_deterministic(&self) -> WicketConfig {
        // Build a temporary GatewayState whose maps are backed by sorted
        // iteration.  We do this by constructing a new GatewayState whose
        // HashMap fields contain the same entries but were inserted in sorted
        // key order.  Because HashMap does not guarantee insertion-order
        // iteration, we instead shadow the fields with BTreeMap-ordered
        // iterators inside generate_config by building a wrapper that
        // iterates in sorted order.
        //
        // The cleanest approach without duplicating generate_config logic is
        // to build a new GatewayState with the same entries inserted in
        // sorted key order.  HashMap iteration order is not stable across
        // runs, but inserting in a fixed order does not help either.
        //
        // Instead we call a private sorted-iteration variant directly.
        self.generate_config_sorted()
    }

    /// Internal: generate config by iterating all maps in sorted key order.
    fn generate_config_sorted(&self) -> WicketConfig {
        let mut config = WicketConfig::default();
        let mut upstreams: BTreeMap<String, UpstreamConfig> = BTreeMap::new();
        let mut routes = Vec::new();
        let mut tls_certs = Vec::new();
        let mut stream_config: Option<StreamConfig> = None;

        // Collect and sort gateway entries.
        let mut gw_entries: Vec<(&String, &Gateway)> = self.gateways.iter().collect();
        gw_entries.sort_by_key(|(k, _)| k.as_str());

        // Determine listeners from gateways (sorted).
        let mut http_listeners: Vec<(String, &Listener)> = Vec::new();
        let mut tcp_listeners: Vec<(String, &Listener)> = Vec::new();

        for (gw_key, gateway) in &gw_entries {
            for listener in &gateway.spec.listeners {
                match listener.protocol {
                    ProtocolType::HTTP | ProtocolType::HTTPS => {
                        http_listeners.push(((*gw_key).clone(), listener));
                    }
                    ProtocolType::TCP | ProtocolType::TLS => {
                        tcp_listeners.push(((*gw_key).clone(), listener));
                    }
                    _ => {}
                }
            }
        }

        // Set server listen address from first HTTP listener.
        if let Some((_, listener)) = http_listeners.first() {
            config.server.listen = format!("0.0.0.0:{}", listener.port);
        }

        // Process HTTPRoutes in sorted key order.
        let mut http_route_entries: Vec<(&String, &HTTPRoute)> = self.http_routes.iter().collect();
        http_route_entries.sort_by_key(|(k, _)| k.as_str());

        for (route_key, route) in &http_route_entries {
            // ── Parity guard: only render routes accepted by this controller ──
            if !Self::http_route_is_accepted(route) {
                tracing::warn!(
                    route = %route_key,
                    "HTTPRoute in store has no Accepted=True parent for this controller; \
                     skipping render (fail-closed)"
                );
                continue;
            }

            let route_ns = route.metadata.namespace.as_deref().unwrap_or("default");
            let route_name = route.metadata.name.as_deref().unwrap_or("unknown");

            for (rule_idx, rule) in route.spec.rules.iter().enumerate() {
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
                        // Sort endpoints for determinism.
                        let mut sorted = endpoints.endpoints.clone();
                        sorted.sort();
                        backend_addrs.extend(sorted);
                    } else {
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

                    if !rule.filters.is_empty() {
                        tracing::warn!(
                            route = %format!("{}/{}", route_ns, route_name),
                            rule_idx = rule_idx,
                            filter_count = rule.filters.len(),
                            "HTTPRoute rule has filters which are not yet supported and will be \
                             skipped; generated route will have no filters applied"
                        );
                    }

                    let timeout = rule.timeouts.as_ref().and_then(|t| {
                        t.request
                            .as_ref()
                            .and_then(|d| Self::parse_duration_to_secs(d))
                    });

                    if rule.matches.is_empty() {
                        let route_config = wicket_config::RouteConfig {
                            name: Some(format!("{}-{}-rule{}", route_ns, route_name, rule_idx)),
                            upstream: upstream_name.clone(),
                            match_rules: wicket_config::RouteMatch {
                                host: route.spec.hostnames.first().cloned(),
                                path: None,
                                path_prefix: Some("/".to_string()),
                                methods: vec![],
                                headers: BTreeMap::new(),
                            },
                            tls: None,
                            filters: None,
                            timeout,
                        };
                        routes.push(route_config);
                    } else {
                        for (match_idx, route_match) in rule.matches.iter().enumerate() {
                            let (path, path_prefix) = if let Some(ref path_match) = route_match.path
                            {
                                match path_match.type_ {
                                    crate::crds::PathMatchType::Exact => {
                                        (Some(path_match.value.clone()), None)
                                    }
                                    crate::crds::PathMatchType::PathPrefix => {
                                        (None, Some(path_match.value.clone()))
                                    }
                                    crate::crds::PathMatchType::RegularExpression => {
                                        tracing::warn!(
                                            route = %format!("{}/{}", route_ns, route_name),
                                            rule_idx = rule_idx,
                                            match_idx = match_idx,
                                            pattern = %path_match.value,
                                            "Skipping route match: RegularExpression path \
                                             matching is not yet supported in wicket-config \
                                             RouteMatch (tracked in bd-89m)"
                                        );
                                        continue;
                                    }
                                }
                            } else {
                                (None, Some("/".to_string()))
                            };

                            let methods: Vec<String> = route_match
                                .method
                                .iter()
                                .map(|m| format!("{:?}", m))
                                .collect();

                            // BTreeMap preserves sorted key order for deterministic serialization.
                            let headers: BTreeMap<String, String> = route_match
                                .headers
                                .iter()
                                .map(|h| (h.name.clone(), h.value.clone()))
                                .collect();

                            let route_config = wicket_config::RouteConfig {
                                name: Some(format!(
                                    "{}-{}-rule{}-match{}",
                                    route_ns, route_name, rule_idx, match_idx
                                )),
                                upstream: upstream_name.clone(),
                                match_rules: wicket_config::RouteMatch {
                                    host: route.spec.hostnames.first().cloned(),
                                    path,
                                    path_prefix,
                                    methods,
                                    headers,
                                },
                                tls: None,
                                filters: None,
                                timeout,
                            };
                            routes.push(route_config);
                        }
                    }
                }
            }
        }

        // Process TLS configuration from Gateway listeners (sorted).
        for (gw_key, gateway) in &gw_entries {
            let gw_ns = gateway.metadata.namespace.as_deref().unwrap_or("default");
            let _ = gw_key; // key used only for sort order

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

        // Process TCPRoutes and TLSRoutes for stream config (sorted).
        if !self.tcp_routes.is_empty() || !self.tls_routes.is_empty() {
            // sni_routes_ordered: (hostname, upstream_name) pairs in sorted
            // route-key order.  Duplicate SNI detection uses a BTreeMap so
            // that the first-writer (lowest sort key) wins deterministically.
            let mut sni_routes_ordered: Vec<(String, String)> = Vec::new();
            let mut stream_upstreams = Vec::new();
            // Track which upstream name already owns each SNI hostname so we
            // can warn on collisions without silently overwriting.
            let mut sni_owner: BTreeMap<String, String> = BTreeMap::new();
            // The first accepted TLSRoute with empty hostnames becomes the
            // catch-all default_upstream.
            let mut catch_all_upstream: Option<String> = None;

            let mut tls_route_entries: Vec<(&String, &TLSRoute)> = self.tls_routes.iter().collect();
            tls_route_entries.sort_by_key(|(k, _)| k.as_str());

            for (route_key, route) in &tls_route_entries {
                let route_ns = route.metadata.namespace.as_deref().unwrap_or("default");

                // ── Parity guard: only render routes accepted by this controller ──
                if !Self::tls_route_is_accepted(route) {
                    tracing::warn!(
                        route = %route_key,
                        "TLSRoute in store has no Accepted=True parent for this controller; \
                         skipping render (fail-closed)"
                    );
                    continue;
                }

                // Build the upstream entry from the first rule's first backend.
                // (Multi-backend weighting is not yet supported in stream config.)
                for rule in &route.spec.rules {
                    for backend_ref in &rule.backend_refs {
                        let upstream_name = format!("{}-{}", route_ns, backend_ref.name);
                        let backend_ns = backend_ref.namespace.as_deref().unwrap_or(route_ns);
                        let backend_key = Self::key(backend_ns, &backend_ref.name);

                        let servers =
                            if let Some(endpoints) = self.service_endpoints.get(&backend_key) {
                                let mut sorted = endpoints.endpoints.clone();
                                sorted.sort();
                                sorted
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

                        if route.spec.hostnames.is_empty() {
                            // Empty hostnames → catch-all / default upstream.
                            // First accepted route with empty hostnames wins.
                            if catch_all_upstream.is_none() {
                                tracing::debug!(
                                    route = %route_key,
                                    upstream = %upstream_name,
                                    "TLSRoute has no hostnames; using as stream default_upstream"
                                );
                                catch_all_upstream = Some(upstream_name.clone());
                            } else {
                                tracing::warn!(
                                    route = %route_key,
                                    upstream = %upstream_name,
                                    existing = %catch_all_upstream.as_deref().unwrap_or(""),
                                    "Multiple TLSRoutes with empty hostnames; \
                                     first-accepted route keeps default_upstream slot"
                                );
                            }
                        } else {
                            for hostname in &route.spec.hostnames {
                                if let Some(existing) = sni_owner.get(hostname) {
                                    tracing::warn!(
                                        hostname = %hostname,
                                        existing_upstream = %existing,
                                        new_upstream = %upstream_name,
                                        route = %route_key,
                                        "Duplicate SNI hostname across TLSRoutes; \
                                         first-accepted route keeps the SNI slot (deterministic)"
                                    );
                                    // Do NOT overwrite — first-writer wins.
                                } else {
                                    sni_owner.insert(hostname.clone(), upstream_name.clone());
                                    sni_routes_ordered
                                        .push((hostname.clone(), upstream_name.clone()));
                                }
                            }
                        }
                    }
                }
            }

            // Process TCPRoutes in sorted key order.
            // TCPRoutes produce plain stream upstreams (no SNI routing).
            let mut tcp_route_entries: Vec<(&String, &TCPRoute)> = self.tcp_routes.iter().collect();
            tcp_route_entries.sort_by_key(|(k, _)| k.as_str());

            for (route_key, route) in &tcp_route_entries {
                let route_ns = route.metadata.namespace.as_deref().unwrap_or("default");

                // ── Parity guard: only render routes accepted by this controller ──
                if !Self::tcp_route_is_accepted(route) {
                    tracing::warn!(
                        route = %route_key,
                        "TCPRoute in store has no Accepted=True parent for this controller; \
                         skipping render (fail-closed)"
                    );
                    continue;
                }

                for rule in &route.spec.rules {
                    for backend_ref in &rule.backend_refs {
                        let upstream_name = format!("{}-{}", route_ns, backend_ref.name);
                        let backend_ns = backend_ref.namespace.as_deref().unwrap_or(route_ns);
                        let backend_key = Self::key(backend_ns, &backend_ref.name);

                        let servers =
                            if let Some(endpoints) = self.service_endpoints.get(&backend_key) {
                                let mut sorted = endpoints.endpoints.clone();
                                sorted.sort();
                                sorted
                            } else {
                                let port = backend_ref.port.unwrap_or(9000);
                                vec![format!(
                                    "{}.{}.svc.cluster.local:{}",
                                    backend_ref.name, backend_ns, port
                                )]
                            };

                        stream_upstreams.push(StreamUpstreamConfig {
                            name: upstream_name,
                            servers,
                        });
                    }
                }
            }

            // Sort SNI routes for determinism, then collect into BTreeMap.
            sni_routes_ordered.sort_by_key(|(k, _)| k.clone());
            let sni_routes_map: BTreeMap<String, String> = sni_routes_ordered.into_iter().collect();

            if let Some((_, listener)) = tcp_listeners.first() {
                stream_config = Some(StreamConfig {
                    listen: format!("0.0.0.0:{}", listener.port),
                    backlog: 8000,
                    reuseport: true,
                    proxy_protocol: None,
                    sni_routes: sni_routes_map,
                    default_upstream: catch_all_upstream,
                    upstreams: stream_upstreams,
                });
            }
        }

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
        let mut upstreams: BTreeMap<String, UpstreamConfig> = BTreeMap::new();
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
            // ── Parity guard: only render routes accepted by this controller ──
            if !Self::http_route_is_accepted(route) {
                tracing::warn!(
                    route = %route_key,
                    "HTTPRoute in store has no Accepted=True parent for this controller; \
                     skipping render (fail-closed)"
                );
                continue;
            }

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

                    // Filters are not yet supported; warn once per rule and skip.
                    if !rule.filters.is_empty() {
                        warn!(
                            route = %format!("{}/{}", route_ns, route_name),
                            rule_idx = rule_idx,
                            filter_count = rule.filters.len(),
                            "HTTPRoute rule has filters which are not yet supported and will be \
                             skipped; generated route will have no filters applied"
                        );
                    }

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
                            name: Some(format!("{}-{}-rule{}", route_ns, route_name, rule_idx)),
                            upstream: upstream_name.clone(),
                            match_rules: RouteMatch {
                                host: route.spec.hostnames.first().cloned(),
                                path: None,
                                path_prefix: Some("/".to_string()),
                                methods: vec![],
                                headers: BTreeMap::new(),
                            },
                            tls: None,
                            filters: None,
                            timeout,
                        };
                        routes.push(route_config);
                    } else {
                        for (match_idx, route_match) in rule.matches.iter().enumerate() {
                            let (path, path_prefix) = if let Some(ref path_match) = route_match.path
                            {
                                match path_match.type_ {
                                    crate::crds::PathMatchType::Exact => {
                                        (Some(path_match.value.clone()), None)
                                    }
                                    crate::crds::PathMatchType::PathPrefix => {
                                        (None, Some(path_match.value.clone()))
                                    }
                                    crate::crds::PathMatchType::RegularExpression => {
                                        // path_regex is not supported in the canonical RouteMatch.
                                        // Log a warning and skip this match entirely.
                                        warn!(
                                            route = %format!("{}/{}", route_ns, route_name),
                                            rule_idx = rule_idx,
                                            match_idx = match_idx,
                                            pattern = %path_match.value,
                                            "Skipping route match: RegularExpression path \
                                             matching is not yet supported in wicket-config \
                                             RouteMatch (tracked in bd-89m)"
                                        );
                                        continue;
                                    }
                                }
                            } else {
                                (None, Some("/".to_string()))
                            };

                            let methods: Vec<String> = route_match
                                .method
                                .iter()
                                .map(|m| format!("{:?}", m))
                                .collect();

                            // BTreeMap preserves sorted key order for deterministic serialization.
                            let headers: BTreeMap<String, String> = route_match
                                .headers
                                .iter()
                                .map(|h| (h.name.clone(), h.value.clone()))
                                .collect();

                            let route_config = RouteConfig {
                                name: Some(format!(
                                    "{}-{}-rule{}-match{}",
                                    route_ns, route_name, rule_idx, match_idx
                                )),
                                upstream: upstream_name.clone(),
                                match_rules: RouteMatch {
                                    host: route.spec.hostnames.first().cloned(),
                                    path,
                                    path_prefix,
                                    methods,
                                    headers,
                                },
                                tls: None,
                                filters: None,
                                timeout,
                            };
                            routes.push(route_config);
                        }
                    }
                }
            }
        }

        // Process TLS configuration from Gateway listeners
        for gateway in self.gateways.values() {
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
            let mut sni_routes: BTreeMap<String, String> = BTreeMap::new();
            let mut stream_upstreams = Vec::new();
            let mut catch_all_upstream: Option<String> = None;

            for (route_key, route) in &self.tls_routes {
                let route_ns = route.metadata.namespace.as_deref().unwrap_or("default");

                // ── Parity guard: only render routes accepted by this controller ──
                if !Self::tls_route_is_accepted(route) {
                    tracing::warn!(
                        route = %route_key,
                        "TLSRoute in store has no Accepted=True parent for this controller; \
                         skipping render (fail-closed)"
                    );
                    continue;
                }

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

                        if route.spec.hostnames.is_empty() {
                            if catch_all_upstream.is_none() {
                                catch_all_upstream = Some(upstream_name.clone());
                            } else {
                                tracing::warn!(
                                    route = %route_key,
                                    upstream = %upstream_name,
                                    existing = %catch_all_upstream.as_deref().unwrap_or(""),
                                    "Multiple TLSRoutes with empty hostnames; \
                                     first-accepted route keeps default_upstream slot"
                                );
                            }
                        } else {
                            for hostname in &route.spec.hostnames {
                                if let Some(existing) = sni_routes.get(hostname) {
                                    tracing::warn!(
                                        hostname = %hostname,
                                        existing_upstream = %existing,
                                        new_upstream = %upstream_name,
                                        route = %route_key,
                                        "Duplicate SNI hostname across TLSRoutes; \
                                         first-accepted route keeps the SNI slot (deterministic)"
                                    );
                                    // Do NOT overwrite — first-writer wins.
                                } else {
                                    sni_routes.insert(hostname.clone(), upstream_name.clone());
                                }
                            }
                        }
                    }
                }
            }

            // Process TCPRoutes.
            // TCPRoutes produce plain stream upstreams (no SNI routing).
            for (route_key, route) in &self.tcp_routes {
                let route_ns = route.metadata.namespace.as_deref().unwrap_or("default");

                // ── Parity guard: only render routes accepted by this controller ──
                if !Self::tcp_route_is_accepted(route) {
                    tracing::warn!(
                        route = %route_key,
                        "TCPRoute in store has no Accepted=True parent for this controller; \
                         skipping render (fail-closed)"
                    );
                    continue;
                }

                for rule in &route.spec.rules {
                    for backend_ref in &rule.backend_refs {
                        let upstream_name = format!("{}-{}", route_ns, backend_ref.name);
                        let backend_ns = backend_ref.namespace.as_deref().unwrap_or(route_ns);
                        let backend_key = Self::key(backend_ns, &backend_ref.name);

                        let servers =
                            if let Some(endpoints) = self.service_endpoints.get(&backend_key) {
                                endpoints.endpoints.clone()
                            } else {
                                let port = backend_ref.port.unwrap_or(9000);
                                vec![format!(
                                    "{}.{}.svc.cluster.local:{}",
                                    backend_ref.name, backend_ns, port
                                )]
                            };

                        stream_upstreams.push(StreamUpstreamConfig {
                            name: upstream_name,
                            servers,
                        });
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
                    default_upstream: catch_all_upstream,
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
        BackendRef, Condition, GatewaySpec, HTTPBackendRef, HTTPRouteRule, HTTPRouteSpec,
        HTTPRouteStatus, Listener, ParentReference, ProtocolType, RouteParentStatus, TCPRoute,
        TCPRouteSpec, TCPRouteStatus, TLSRoute, TLSRouteRule, TLSRouteSpec, TLSRouteStatus,
        WICKET_CONTROLLER_NAME,
    };
    use kube::core::ObjectMeta;

    /// Build an `HTTPRouteStatus` with a single `Accepted=True` parent entry
    /// for the Wicket controller.  Used by pre-existing tests that need a route
    /// to pass the render-time accepted guard.
    fn wicket_accepted_http_status() -> HTTPRouteStatus {
        HTTPRouteStatus {
            parents: vec![RouteParentStatus {
                parent_ref: ParentReference {
                    group: "gateway.networking.k8s.io".to_string(),
                    kind: "Gateway".to_string(),
                    namespace: None,
                    name: "test-gateway".to_string(),
                    section_name: None,
                    port: None,
                },
                controller_name: WICKET_CONTROLLER_NAME.to_string(),
                conditions: vec![Condition::accepted()],
            }],
        }
    }

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
            status: Some(wicket_accepted_http_status()),
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
            status: Some(wicket_accepted_http_status()),
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

        // Verify routes from HTTPRoute — use canonical field names
        assert_eq!(config.routes.len(), 1);
        let route_config = &config.routes[0];
        assert_eq!(
            route_config.name,
            Some("default-test-route-rule0".to_string())
        );
        assert_eq!(route_config.upstream, "default-test-route-rule0");
        assert_eq!(
            route_config.match_rules.host,
            Some("api.example.com".to_string())
        );
        assert_eq!(route_config.match_rules.path_prefix, Some("/".to_string()));
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
                status: Some(wicket_accepted_http_status()),
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
            status: Some(wicket_accepted_http_status()),
        };
        state
            .http_routes
            .insert(GatewayState::key("default", "test-route"), route);

        state.service_endpoints.insert(
            GatewayState::key("default", "backend"),
            ServiceEndpoints {
                namespace: "default".to_string(),
                name: "backend".to_string(),
                endpoints: vec!["10.0.0.1:80".to_string()],
            },
        );

        // Generate config
        let config = state.generate_config();

        // Verify routes with different path match types
        assert_eq!(config.routes.len(), 2);

        // First route: exact path match — use canonical field name match_rules
        let exact_route = config
            .routes
            .iter()
            .find(|r| r.match_rules.path.as_deref() == Some("/health"))
            .unwrap();
        assert_eq!(exact_route.match_rules.path, Some("/health".to_string()));

        // Second route: path prefix match
        let prefix_route = config
            .routes
            .iter()
            .find(|r| r.match_rules.path_prefix.as_deref() == Some("/api"))
            .unwrap();
        assert_eq!(
            prefix_route.match_rules.path_prefix,
            Some("/api".to_string())
        );
    }

    /// Test: RegularExpression path matches are skipped with a warning.
    #[test]
    fn test_regex_path_match_skipped() {
        let mut state = GatewayState::default();

        let gateway = Gateway {
            metadata: ObjectMeta {
                name: Some("gw".to_string()),
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
            .insert(GatewayState::key("default", "gw"), gateway);

        let route = HTTPRoute {
            metadata: ObjectMeta {
                name: Some("regex-route".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            },
            spec: HTTPRouteSpec {
                parent_refs: vec![],
                hostnames: vec![],
                rules: vec![HTTPRouteRule {
                    name: None,
                    matches: vec![crate::crds::HTTPRouteMatch {
                        path: Some(crate::crds::HTTPPathMatch {
                            type_: crate::crds::PathMatchType::RegularExpression,
                            value: "^/api/.*".to_string(),
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
                }],
            },
            status: Some(wicket_accepted_http_status()),
        };
        state
            .http_routes
            .insert(GatewayState::key("default", "regex-route"), route);

        state.service_endpoints.insert(
            GatewayState::key("default", "backend"),
            ServiceEndpoints {
                namespace: "default".to_string(),
                name: "backend".to_string(),
                endpoints: vec!["10.0.0.1:80".to_string()],
            },
        );

        let config = state.generate_config();

        // Regex match must be skipped — no routes generated
        assert_eq!(config.routes.len(), 0, "regex path match should be skipped");
    }

    /// Test: HTTPRoute rule filters are not emitted into generated RouteConfig.
    #[test]
    fn test_filters_not_emitted_into_generated_config() {
        use crate::crds::{
            HTTPHeader, HTTPHeaderFilter, HTTPPathModifier, HTTPPathModifierType,
            HTTPRequestRedirectFilter, HTTPRouteFilter, HTTPRouteFilterType,
        };

        let mut state = GatewayState::default();

        let gateway = Gateway {
            metadata: ObjectMeta {
                name: Some("gw".to_string()),
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
            .insert(GatewayState::key("default", "gw"), gateway);

        // Route with a redirect filter and a header modifier filter
        let route = HTTPRoute {
            metadata: ObjectMeta {
                name: Some("filter-route".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            },
            spec: HTTPRouteSpec {
                parent_refs: vec![],
                hostnames: vec!["example.com".to_string()],
                rules: vec![
                    // Rule with filters and no explicit matches (default match)
                    HTTPRouteRule {
                        name: None,
                        matches: vec![],
                        filters: vec![
                            HTTPRouteFilter {
                                type_: HTTPRouteFilterType::RequestRedirect,
                                request_header_modifier: None,
                                response_header_modifier: None,
                                request_redirect: Some(HTTPRequestRedirectFilter {
                                    scheme: Some("https".to_string()),
                                    hostname: None,
                                    port: None,
                                    path: None,
                                    status_code: 301,
                                }),
                                url_rewrite: None,
                                request_mirror: None,
                                extension_ref: None,
                            },
                            HTTPRouteFilter {
                                type_: HTTPRouteFilterType::RequestHeaderModifier,
                                request_header_modifier: Some(HTTPHeaderFilter {
                                    add: vec![HTTPHeader {
                                        name: "X-Custom".to_string(),
                                        value: "value".to_string(),
                                    }],
                                    set: vec![],
                                    remove: vec![],
                                }),
                                response_header_modifier: None,
                                request_redirect: None,
                                url_rewrite: None,
                                request_mirror: None,
                                extension_ref: None,
                            },
                        ],
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
                    // Rule with explicit path match and a filter
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
                        filters: vec![HTTPRouteFilter {
                            type_: HTTPRouteFilterType::URLRewrite,
                            request_header_modifier: None,
                            response_header_modifier: None,
                            request_redirect: None,
                            url_rewrite: Some(crate::crds::HTTPURLRewriteFilter {
                                hostname: Some("internal.example.com".to_string()),
                                path: Some(HTTPPathModifier {
                                    type_: HTTPPathModifierType::ReplacePrefixMatch,
                                    replace_full_path: None,
                                    replace_prefix_match: Some("/".to_string()),
                                }),
                            }),
                            request_mirror: None,
                            extension_ref: None,
                        }],
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
            status: Some(wicket_accepted_http_status()),
        };
        state
            .http_routes
            .insert(GatewayState::key("default", "filter-route"), route);

        state.service_endpoints.insert(
            GatewayState::key("default", "backend"),
            ServiceEndpoints {
                namespace: "default".to_string(),
                name: "backend".to_string(),
                endpoints: vec!["10.0.0.1:80".to_string()],
            },
        );

        let config = state.generate_config();

        // Both rules produce routes (one default match, one path match)
        assert_eq!(config.routes.len(), 2, "expected 2 routes");

        // Filters must NOT be emitted into any generated RouteConfig
        for route_cfg in &config.routes {
            assert!(
                route_cfg.filters.is_none(),
                "route '{}' must not have filters in generated config",
                route_cfg.name.as_deref().unwrap_or("<unnamed>")
            );
        }
    }

    /// Test: header matches are serialized in deterministic (sorted) key order.
    ///
    /// Inserts headers in reverse-alphabetical order in the CRD match spec and
    /// verifies that both `generate_config` and `generate_config_deterministic`
    /// produce identical TOML output regardless of insertion order, and that the
    /// TOML keys appear in sorted order.
    #[test]
    fn test_header_match_serialization_is_deterministic() {
        use crate::crds::{HTTPHeaderMatch, HTTPRouteMatch, PathMatchType};

        let mut state = GatewayState::default();

        let gateway = Gateway {
            metadata: ObjectMeta {
                name: Some("gw".to_string()),
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
            .insert(GatewayState::key("default", "gw"), gateway);

        // Headers listed in reverse-alphabetical order to expose any HashMap
        // nondeterminism: if the map is iterated in insertion order the TOML
        // would emit "z-header" before "a-header".
        let route = HTTPRoute {
            metadata: ObjectMeta {
                name: Some("header-route".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            },
            spec: HTTPRouteSpec {
                parent_refs: vec![],
                hostnames: vec!["example.com".to_string()],
                rules: vec![HTTPRouteRule {
                    name: None,
                    matches: vec![HTTPRouteMatch {
                        path: Some(crate::crds::HTTPPathMatch {
                            type_: PathMatchType::PathPrefix,
                            value: "/api".to_string(),
                        }),
                        headers: vec![
                            HTTPHeaderMatch {
                                type_: crate::crds::HeaderMatchType::Exact,
                                name: "z-header".to_string(),
                                value: "z-value".to_string(),
                            },
                            HTTPHeaderMatch {
                                type_: crate::crds::HeaderMatchType::Exact,
                                name: "m-header".to_string(),
                                value: "m-value".to_string(),
                            },
                            HTTPHeaderMatch {
                                type_: crate::crds::HeaderMatchType::Exact,
                                name: "a-header".to_string(),
                                value: "a-value".to_string(),
                            },
                        ],
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
                }],
            },
            status: Some(wicket_accepted_http_status()),
        };
        state
            .http_routes
            .insert(GatewayState::key("default", "header-route"), route);

        state.service_endpoints.insert(
            GatewayState::key("default", "backend"),
            ServiceEndpoints {
                namespace: "default".to_string(),
                name: "backend".to_string(),
                endpoints: vec!["10.0.0.1:80".to_string()],
            },
        );

        // Both paths must produce the same TOML.
        let cfg_a = state.generate_config();
        let cfg_b = state.generate_config_deterministic();

        let toml_a = toml::to_string(&cfg_a).expect("serialize cfg_a");
        let toml_b = toml::to_string(&cfg_b).expect("serialize cfg_b");
        assert_eq!(
            toml_a, toml_b,
            "generate_config and generate_config_deterministic must produce identical TOML"
        );

        // Headers in the generated RouteMatch must be in sorted key order.
        assert_eq!(cfg_a.routes.len(), 1);
        let headers = &cfg_a.routes[0].match_rules.headers;
        let keys: Vec<&str> = headers.keys().map(String::as_str).collect();
        let mut sorted = keys.clone();
        sorted.sort_unstable();
        assert_eq!(
            keys, sorted,
            "header keys must be in sorted order in the generated RouteMatch"
        );

        // Verify all three headers are present with correct values.
        assert_eq!(headers.get("a-header").map(String::as_str), Some("a-value"));
        assert_eq!(headers.get("m-header").map(String::as_str), Some("m-value"));
        assert_eq!(headers.get("z-header").map(String::as_str), Some("z-value"));

        // The serialized TOML must contain the keys in sorted order.
        let a_pos = toml_a.find("a-header").expect("a-header in TOML");
        let m_pos = toml_a.find("m-header").expect("m-header in TOML");
        let z_pos = toml_a.find("z-header").expect("z-header in TOML");
        assert!(
            a_pos < m_pos && m_pos < z_pos,
            "TOML header keys must appear in sorted order"
        );
    }

    // ── TLS runtime parity tests ──────────────────────────────────────────────

    /// Build a TLSRoute with an explicit status.
    fn make_tls_route_with_status(
        ns: &str,
        name: &str,
        hostnames: Vec<&str>,
        backend_name: &str,
        backend_port: u16,
        status: Option<TLSRouteStatus>,
    ) -> TLSRoute {
        TLSRoute {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some(ns.to_string()),
                ..Default::default()
            },
            spec: TLSRouteSpec {
                parent_refs: vec![],
                hostnames: hostnames.into_iter().map(str::to_string).collect(),
                rules: vec![TLSRouteRule {
                    name: None,
                    backend_refs: vec![BackendRef {
                        group: "".to_string(),
                        kind: "Service".to_string(),
                        name: backend_name.to_string(),
                        namespace: None,
                        port: Some(backend_port),
                        weight: 1,
                    }],
                }],
            },
            status,
        }
    }

    /// Accepted status written by this controller.
    fn accepted_status() -> TLSRouteStatus {
        TLSRouteStatus {
            parents: vec![RouteParentStatus {
                parent_ref: ParentReference {
                    group: "gateway.networking.k8s.io".to_string(),
                    kind: "Gateway".to_string(),
                    namespace: None,
                    name: "my-gw".to_string(),
                    section_name: None,
                    port: None,
                },
                controller_name: WICKET_CONTROLLER_NAME.to_string(),
                conditions: vec![Condition::accepted()],
            }],
        }
    }

    /// Rejected status written by this controller.
    fn rejected_status() -> TLSRouteStatus {
        TLSRouteStatus {
            parents: vec![RouteParentStatus {
                parent_ref: ParentReference {
                    group: "gateway.networking.k8s.io".to_string(),
                    kind: "Gateway".to_string(),
                    namespace: None,
                    name: "my-gw".to_string(),
                    section_name: None,
                    port: None,
                },
                controller_name: WICKET_CONTROLLER_NAME.to_string(),
                conditions: vec![Condition::new(
                    "Accepted",
                    false,
                    "NoMatchingListener",
                    "Gateway has no TLS passthrough listener",
                )],
            }],
        }
    }

    /// Build a minimal Gateway with a TLS listener for stream config generation.
    fn make_tls_gateway(ns: &str, name: &str, port: u16) -> Gateway {
        Gateway {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some(ns.to_string()),
                ..Default::default()
            },
            spec: GatewaySpec {
                gateway_class_name: "wicket".to_string(),
                listeners: vec![Listener {
                    name: "tls".to_string(),
                    hostname: None,
                    port,
                    protocol: ProtocolType::TLS,
                    tls: None,
                    allowed_routes: None,
                }],
                addresses: vec![],
                infrastructure: None,
            },
            status: None,
        }
    }

    /// Integration test: only the accepted TLSRoute is rendered; the rejected
    /// one must not appear in sni_routes or stream upstreams.
    #[test]
    fn tls_parity_only_accepted_route_is_rendered() {
        let mut state = GatewayState::default();

        state.gateways.insert(
            GatewayState::key("default", "gw"),
            make_tls_gateway("default", "gw", 8443),
        );

        // Accepted route — should appear in stream config.
        let accepted = make_tls_route_with_status(
            "default",
            "accepted-route",
            vec!["db.example.com"],
            "db-svc",
            5432,
            Some(accepted_status()),
        );
        state
            .tls_routes
            .insert(GatewayState::key("default", "accepted-route"), accepted);

        // Rejected route — must NOT appear in stream config.
        let rejected = make_tls_route_with_status(
            "default",
            "rejected-route",
            vec!["redis.example.com"],
            "redis-svc",
            6379,
            Some(rejected_status()),
        );
        state
            .tls_routes
            .insert(GatewayState::key("default", "rejected-route"), rejected);

        let config = state.generate_config_deterministic();

        let stream = config.stream.expect("stream config must be present");

        // Only the accepted hostname must appear.
        assert!(
            stream.sni_routes.contains_key("db.example.com"),
            "accepted SNI must be present"
        );
        assert!(
            !stream.sni_routes.contains_key("redis.example.com"),
            "rejected SNI must not be present"
        );

        // Only one upstream (for the accepted route).
        assert_eq!(
            stream.upstreams.len(),
            1,
            "only the accepted route's upstream must be rendered"
        );
        assert_eq!(stream.upstreams[0].name, "default-db-svc");
    }

    /// Integration test: accepted TLSRoute with empty hostnames becomes the
    /// stream default_upstream (catch-all).
    #[test]
    fn tls_parity_empty_hostnames_becomes_default_upstream() {
        let mut state = GatewayState::default();

        state.gateways.insert(
            GatewayState::key("default", "gw"),
            make_tls_gateway("default", "gw", 8443),
        );

        // Accepted route with no hostnames → should become default_upstream.
        let catch_all = make_tls_route_with_status(
            "default",
            "catch-all-route",
            vec![],
            "fallback-svc",
            443,
            Some(accepted_status()),
        );
        state
            .tls_routes
            .insert(GatewayState::key("default", "catch-all-route"), catch_all);

        let config = state.generate_config_deterministic();

        let stream = config.stream.expect("stream config must be present");

        assert!(
            stream.sni_routes.is_empty(),
            "no explicit SNI routes expected"
        );
        assert_eq!(
            stream.default_upstream.as_deref(),
            Some("default-fallback-svc"),
            "empty-hostname accepted route must become default_upstream"
        );
    }

    /// Integration test: route with no status (None) is fail-closed — not rendered.
    #[test]
    fn tls_parity_no_status_is_fail_closed() {
        let mut state = GatewayState::default();

        state.gateways.insert(
            GatewayState::key("default", "gw"),
            make_tls_gateway("default", "gw", 8443),
        );

        // Route with no status written yet.
        let no_status = make_tls_route_with_status(
            "default",
            "no-status-route",
            vec!["db.example.com"],
            "db-svc",
            5432,
            None, // no status
        );
        state
            .tls_routes
            .insert(GatewayState::key("default", "no-status-route"), no_status);

        let config = state.generate_config_deterministic();

        // No stream config at all since no routes were rendered.
        // (tcp_routes is also empty, so stream is None)
        assert!(
            config.stream.is_none()
                || config
                    .stream
                    .as_ref()
                    .map(|s| s.sni_routes.is_empty())
                    .unwrap_or(true),
            "route with no status must not be rendered"
        );
    }

    // ── Shared status helpers ─────────────────────────────────────────────────

    fn make_accepted_parent_status() -> RouteParentStatus {
        RouteParentStatus {
            parent_ref: ParentReference {
                group: "gateway.networking.k8s.io".to_string(),
                kind: "Gateway".to_string(),
                namespace: None,
                name: "my-gw".to_string(),
                section_name: None,
                port: None,
            },
            controller_name: WICKET_CONTROLLER_NAME.to_string(),
            conditions: vec![Condition::accepted()],
        }
    }

    fn make_rejected_parent_status() -> RouteParentStatus {
        RouteParentStatus {
            parent_ref: ParentReference {
                group: "gateway.networking.k8s.io".to_string(),
                kind: "Gateway".to_string(),
                namespace: None,
                name: "my-gw".to_string(),
                section_name: None,
                port: None,
            },
            controller_name: WICKET_CONTROLLER_NAME.to_string(),
            conditions: vec![Condition::not_accepted()],
        }
    }

    fn make_http_route_for_render(
        ns: &str,
        name: &str,
        backend_name: &str,
        status: Option<HTTPRouteStatus>,
    ) -> HTTPRoute {
        HTTPRoute {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some(ns.to_string()),
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
                        backend_ref: BackendRef {
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
            status,
        }
    }

    fn make_tcp_route_for_render(
        ns: &str,
        name: &str,
        backend_name: &str,
        status: Option<TCPRouteStatus>,
    ) -> TCPRoute {
        TCPRoute {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some(ns.to_string()),
                ..Default::default()
            },
            spec: TCPRouteSpec {
                parent_refs: vec![],
                rules: vec![crate::crds::TCPRouteRule {
                    name: None,
                    backend_refs: vec![BackendRef {
                        group: "".to_string(),
                        kind: "Service".to_string(),
                        name: backend_name.to_string(),
                        namespace: None,
                        port: Some(9000),
                        weight: 1,
                    }],
                }],
            },
            status,
        }
    }

    fn make_http_gateway(ns: &str, name: &str, port: u16) -> Gateway {
        Gateway {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some(ns.to_string()),
                ..Default::default()
            },
            spec: GatewaySpec {
                gateway_class_name: "wicket".to_string(),
                listeners: vec![Listener {
                    name: "http".to_string(),
                    hostname: None,
                    port,
                    protocol: ProtocolType::HTTP,
                    tls: None,
                    allowed_routes: None,
                }],
                addresses: vec![],
                infrastructure: None,
            },
            status: None,
        }
    }

    // ── parents_accepted_by_wicket unit tests ─────────────────────────────────

    #[test]
    fn parents_accepted_empty_slice_returns_false() {
        assert!(!parents_accepted_by_wicket(&[]));
    }

    #[test]
    fn parents_accepted_wicket_accepted_returns_true() {
        assert!(parents_accepted_by_wicket(&[make_accepted_parent_status()]));
    }

    #[test]
    fn parents_accepted_wicket_rejected_returns_false() {
        assert!(!parents_accepted_by_wicket(
            &[make_rejected_parent_status()]
        ));
    }

    #[test]
    fn parents_accepted_other_controller_accepted_returns_false() {
        let other = RouteParentStatus {
            parent_ref: ParentReference {
                group: "gateway.networking.k8s.io".to_string(),
                kind: "Gateway".to_string(),
                namespace: None,
                name: "gw".to_string(),
                section_name: None,
                port: None,
            },
            controller_name: "other.io/controller".to_string(),
            conditions: vec![Condition::accepted()],
        };
        assert!(!parents_accepted_by_wicket(&[other]));
    }

    #[test]
    fn parents_accepted_mixed_parents_returns_true_when_wicket_accepts() {
        let other = RouteParentStatus {
            parent_ref: ParentReference {
                group: "gateway.networking.k8s.io".to_string(),
                kind: "Gateway".to_string(),
                namespace: None,
                name: "gw".to_string(),
                section_name: None,
                port: None,
            },
            controller_name: "other.io/controller".to_string(),
            conditions: vec![Condition::not_accepted()],
        };
        assert!(parents_accepted_by_wicket(&[
            other,
            make_accepted_parent_status()
        ]));
    }

    // ── HTTPRoute render-time accepted guard ──────────────────────────────────

    /// Accepted HTTPRoute must produce routes in generated config.
    #[test]
    fn http_parity_accepted_route_is_rendered() {
        let mut state = GatewayState::default();

        state.gateways.insert(
            GatewayState::key("default", "gw"),
            make_http_gateway("default", "gw", 8080),
        );

        let route = make_http_route_for_render(
            "default",
            "accepted-route",
            "api-svc",
            Some(HTTPRouteStatus {
                parents: vec![make_accepted_parent_status()],
            }),
        );
        state
            .http_routes
            .insert(GatewayState::key("default", "accepted-route"), route);

        state.service_endpoints.insert(
            GatewayState::key("default", "api-svc"),
            ServiceEndpoints {
                namespace: "default".to_string(),
                name: "api-svc".to_string(),
                endpoints: vec!["10.0.0.1:80".to_string()],
            },
        );

        let config = state.generate_config_deterministic();
        assert_eq!(
            config.routes.len(),
            1,
            "accepted HTTPRoute must be rendered"
        );
        assert_eq!(config.upstreams.len(), 1);
    }

    /// Rejected HTTPRoute must be excluded from generated config (fail-closed).
    #[test]
    fn http_parity_rejected_route_is_not_rendered() {
        let mut state = GatewayState::default();

        state.gateways.insert(
            GatewayState::key("default", "gw"),
            make_http_gateway("default", "gw", 8080),
        );

        let route = make_http_route_for_render(
            "default",
            "rejected-route",
            "api-svc",
            Some(HTTPRouteStatus {
                parents: vec![make_rejected_parent_status()],
            }),
        );
        state
            .http_routes
            .insert(GatewayState::key("default", "rejected-route"), route);

        state.service_endpoints.insert(
            GatewayState::key("default", "api-svc"),
            ServiceEndpoints {
                namespace: "default".to_string(),
                name: "api-svc".to_string(),
                endpoints: vec!["10.0.0.1:80".to_string()],
            },
        );

        let config = state.generate_config_deterministic();
        assert_eq!(
            config.routes.len(),
            0,
            "rejected HTTPRoute must not be rendered"
        );
        assert_eq!(config.upstreams.len(), 0);
    }

    /// HTTPRoute with no status must be excluded (fail-closed).
    #[test]
    fn http_parity_no_status_is_fail_closed() {
        let mut state = GatewayState::default();

        state.gateways.insert(
            GatewayState::key("default", "gw"),
            make_http_gateway("default", "gw", 8080),
        );

        let route = make_http_route_for_render("default", "no-status-route", "api-svc", None);
        state
            .http_routes
            .insert(GatewayState::key("default", "no-status-route"), route);

        state.service_endpoints.insert(
            GatewayState::key("default", "api-svc"),
            ServiceEndpoints {
                namespace: "default".to_string(),
                name: "api-svc".to_string(),
                endpoints: vec!["10.0.0.1:80".to_string()],
            },
        );

        let config = state.generate_config_deterministic();
        assert_eq!(
            config.routes.len(),
            0,
            "HTTPRoute with no status must not be rendered"
        );
    }

    /// Mixed: one accepted, one rejected HTTPRoute — only the accepted one renders.
    #[test]
    fn http_parity_only_accepted_route_is_rendered_among_mixed() {
        let mut state = GatewayState::default();

        state.gateways.insert(
            GatewayState::key("default", "gw"),
            make_http_gateway("default", "gw", 8080),
        );

        let accepted = make_http_route_for_render(
            "default",
            "accepted-route",
            "api-svc",
            Some(HTTPRouteStatus {
                parents: vec![make_accepted_parent_status()],
            }),
        );
        let rejected = make_http_route_for_render(
            "default",
            "rejected-route",
            "other-svc",
            Some(HTTPRouteStatus {
                parents: vec![make_rejected_parent_status()],
            }),
        );

        state
            .http_routes
            .insert(GatewayState::key("default", "accepted-route"), accepted);
        state
            .http_routes
            .insert(GatewayState::key("default", "rejected-route"), rejected);

        for svc in &["api-svc", "other-svc"] {
            state.service_endpoints.insert(
                GatewayState::key("default", svc),
                ServiceEndpoints {
                    namespace: "default".to_string(),
                    name: svc.to_string(),
                    endpoints: vec!["10.0.0.1:80".to_string()],
                },
            );
        }

        let config = state.generate_config_deterministic();
        assert_eq!(
            config.routes.len(),
            1,
            "only the accepted HTTPRoute must be rendered"
        );
        // The accepted route's upstream name is default-accepted-route-rule0.
        assert!(
            config
                .upstreams
                .contains_key("default-accepted-route-rule0"),
            "accepted route upstream must be present"
        );
        assert!(
            !config
                .upstreams
                .contains_key("default-rejected-route-rule0"),
            "rejected route upstream must not be present"
        );
    }

    // ── TCPRoute render-time accepted guard ───────────────────────────────────
    //
    // TCPRoutes are processed in the stream-config block alongside TLSRoutes.
    // The guard must exclude unaccepted TCPRoutes from the stream upstreams.

    /// Accepted TCPRoute must appear in stream upstreams.
    #[test]
    fn tcp_parity_accepted_route_is_rendered() {
        let mut state = GatewayState::default();

        state.gateways.insert(
            GatewayState::key("default", "gw"),
            make_tls_gateway("default", "gw", 9000),
        );

        let route = make_tcp_route_for_render(
            "default",
            "accepted-tcp",
            "db-svc",
            Some(TCPRouteStatus {
                parents: vec![make_accepted_parent_status()],
            }),
        );
        state
            .tcp_routes
            .insert(GatewayState::key("default", "accepted-tcp"), route);

        state.service_endpoints.insert(
            GatewayState::key("default", "db-svc"),
            ServiceEndpoints {
                namespace: "default".to_string(),
                name: "db-svc".to_string(),
                endpoints: vec!["10.0.0.5:9000".to_string()],
            },
        );

        let config = state.generate_config_deterministic();
        // TCPRoutes produce stream upstreams (no SNI routing).
        let stream = config
            .stream
            .expect("stream config must be present for TCPRoute");
        assert_eq!(
            stream.upstreams.len(),
            1,
            "accepted TCPRoute must produce a stream upstream"
        );
    }

    /// Rejected TCPRoute must be excluded from stream upstreams (fail-closed).
    #[test]
    fn tcp_parity_rejected_route_is_not_rendered() {
        let mut state = GatewayState::default();

        state.gateways.insert(
            GatewayState::key("default", "gw"),
            make_tls_gateway("default", "gw", 9000),
        );

        let route = make_tcp_route_for_render(
            "default",
            "rejected-tcp",
            "db-svc",
            Some(TCPRouteStatus {
                parents: vec![make_rejected_parent_status()],
            }),
        );
        state
            .tcp_routes
            .insert(GatewayState::key("default", "rejected-tcp"), route);

        state.service_endpoints.insert(
            GatewayState::key("default", "db-svc"),
            ServiceEndpoints {
                namespace: "default".to_string(),
                name: "db-svc".to_string(),
                endpoints: vec!["10.0.0.5:9000".to_string()],
            },
        );

        let config = state.generate_config_deterministic();
        // No accepted routes → stream may be None or have empty upstreams.
        let no_upstreams = config
            .stream
            .as_ref()
            .map(|s| s.upstreams.is_empty())
            .unwrap_or(true);
        assert!(
            no_upstreams,
            "rejected TCPRoute must not produce stream upstreams"
        );
    }

    /// TCPRoute with no status must be excluded (fail-closed).
    #[test]
    fn tcp_parity_no_status_is_fail_closed() {
        let mut state = GatewayState::default();

        state.gateways.insert(
            GatewayState::key("default", "gw"),
            make_tls_gateway("default", "gw", 9000),
        );

        let route = make_tcp_route_for_render("default", "no-status-tcp", "db-svc", None);
        state
            .tcp_routes
            .insert(GatewayState::key("default", "no-status-tcp"), route);

        let config = state.generate_config_deterministic();
        let no_upstreams = config
            .stream
            .as_ref()
            .map(|s| s.upstreams.is_empty())
            .unwrap_or(true);
        assert!(no_upstreams, "TCPRoute with no status must not be rendered");
    }

    // ── Cross-type symmetry: generate_config vs generate_config_deterministic ─

    /// Both code paths must apply the same accepted guard for HTTPRoutes.
    #[test]
    fn http_parity_both_paths_agree_on_rejected_route() {
        let mut state = GatewayState::default();

        state.gateways.insert(
            GatewayState::key("default", "gw"),
            make_http_gateway("default", "gw", 8080),
        );

        let route = make_http_route_for_render(
            "default",
            "rejected-route",
            "api-svc",
            Some(HTTPRouteStatus {
                parents: vec![make_rejected_parent_status()],
            }),
        );
        state
            .http_routes
            .insert(GatewayState::key("default", "rejected-route"), route);

        state.service_endpoints.insert(
            GatewayState::key("default", "api-svc"),
            ServiceEndpoints {
                namespace: "default".to_string(),
                name: "api-svc".to_string(),
                endpoints: vec!["10.0.0.1:80".to_string()],
            },
        );

        let cfg_sorted = state.generate_config_deterministic();
        let cfg_unsorted = state.generate_config();

        assert_eq!(
            cfg_sorted.routes.len(),
            0,
            "generate_config_deterministic: rejected HTTPRoute must not be rendered"
        );
        assert_eq!(
            cfg_unsorted.routes.len(),
            0,
            "generate_config: rejected HTTPRoute must not be rendered"
        );
    }

    /// Both code paths must apply the same accepted guard for TLSRoutes.
    #[test]
    fn tls_parity_both_paths_agree_on_rejected_route() {
        let mut state = GatewayState::default();

        state.gateways.insert(
            GatewayState::key("default", "gw"),
            make_tls_gateway("default", "gw", 8443),
        );

        let rejected = make_tls_route_with_status(
            "default",
            "rejected-route",
            vec!["db.example.com"],
            "db-svc",
            5432,
            Some(rejected_status()),
        );
        state
            .tls_routes
            .insert(GatewayState::key("default", "rejected-route"), rejected);

        let cfg_sorted = state.generate_config_deterministic();
        let cfg_unsorted = state.generate_config();

        let sorted_empty = cfg_sorted
            .stream
            .as_ref()
            .map(|s| s.sni_routes.is_empty() && s.upstreams.is_empty())
            .unwrap_or(true);
        let unsorted_empty = cfg_unsorted
            .stream
            .as_ref()
            .map(|s| s.sni_routes.is_empty() && s.upstreams.is_empty())
            .unwrap_or(true);

        assert!(
            sorted_empty,
            "generate_config_deterministic: rejected TLSRoute must not be rendered"
        );
        assert!(
            unsorted_empty,
            "generate_config: rejected TLSRoute must not be rendered"
        );
    }

    /// Integration test: duplicate SNI hostnames — first-accepted route wins,
    /// second is silently dropped (but warned).
    #[test]
    fn tls_parity_duplicate_sni_first_writer_wins() {
        let mut state = GatewayState::default();

        state.gateways.insert(
            GatewayState::key("default", "gw"),
            make_tls_gateway("default", "gw", 8443),
        );

        // Two accepted routes claiming the same SNI.
        // "aaa-route" sorts before "zzz-route" so it wins.
        let first = make_tls_route_with_status(
            "default",
            "aaa-route",
            vec!["shared.example.com"],
            "first-svc",
            443,
            Some(accepted_status()),
        );
        let second = make_tls_route_with_status(
            "default",
            "zzz-route",
            vec!["shared.example.com"],
            "second-svc",
            443,
            Some(accepted_status()),
        );

        state
            .tls_routes
            .insert(GatewayState::key("default", "aaa-route"), first);
        state
            .tls_routes
            .insert(GatewayState::key("default", "zzz-route"), second);

        let config = state.generate_config_deterministic();
        let stream = config.stream.expect("stream config must be present");

        // The SNI must be present exactly once.
        assert_eq!(
            stream.sni_routes.len(),
            1,
            "duplicate SNI must appear only once"
        );
        // First-sorted route (aaa-route → default-first-svc) must win.
        assert_eq!(
            stream
                .sni_routes
                .get("shared.example.com")
                .map(String::as_str),
            Some("default-first-svc"),
            "first-accepted (lowest sort key) route must own the SNI slot"
        );
    }
}
