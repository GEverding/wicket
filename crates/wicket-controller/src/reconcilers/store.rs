//! Shared resource cache/index for controller reconcilers.
//!
//! Provides a synchronized in-memory store of Gateway API resources that
//! reconcilers can read without issuing repeated full-list API calls.
//!
//! ## Warm-up / readiness
//!
//! The store starts in an *unready* state.  Callers should check
//! [`SharedStore::is_ready`] before using snapshot data for config
//! generation.  When not ready, callers fall back to the existing
//! API-list path.
//!
//! ## Stale-cache safety
//!
//! All accessors return `Option` or empty collections — never panic on a
//! missing entry.  The synthesis path treats a cache miss as a signal to
//! fall back to the API-list path.
//!
//! ## Index
//!
//! [`SharedStore::is_service_referenced`] answers "is this service used by
//! any route?" in O(1) via a pre-built reverse index, replacing the
//! previous full-list scans in `service.rs`.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use tokio::sync::RwLock;

use crate::crds::{Gateway, GatewayClass, HTTPRoute, ReferenceGrant, TCPRoute, TLSRoute};
use crate::reconcilers::config_generator::{GatewayState, ServiceEndpoints};

// ─────────────────────────────────────────────────────────────────────────────
// Inner state
// ─────────────────────────────────────────────────────────────────────────────

/// Raw resource maps held inside the store.
#[derive(Clone, Debug, Default)]
pub struct StoreInner {
    pub gateways: HashMap<String, Gateway>,
    pub gateway_classes: HashMap<String, GatewayClass>,
    pub http_routes: HashMap<String, HTTPRoute>,
    pub tcp_routes: HashMap<String, TCPRoute>,
    pub tls_routes: HashMap<String, TLSRoute>,
    pub service_endpoints: HashMap<String, ServiceEndpoints>,
    /// TLS secrets by namespace/name → (cert_path, key_path).
    pub tls_secrets: HashMap<String, (String, String)>,
    pub reference_grants: HashMap<String, ReferenceGrant>,

    /// Reverse index: "namespace/service-name" → true if referenced by ≥1 route.
    /// Rebuilt on every write to any route map.
    pub service_ref_index: HashSet<String>,

    /// True once the store has been populated at least once.
    pub ready: bool,
}

impl StoreInner {
    /// Rebuild the service reference index from current route maps.
    pub fn rebuild_service_index(&mut self) {
        let mut index = HashSet::new();

        for route in self.http_routes.values() {
            let route_ns = route
                .metadata
                .namespace
                .as_deref()
                .unwrap_or("default")
                .to_string();
            for rule in &route.spec.rules {
                for backend_ref in &rule.backend_refs {
                    let ns = backend_ref
                        .backend_ref
                        .namespace
                        .as_deref()
                        .unwrap_or(&route_ns);
                    index.insert(GatewayState::key(ns, &backend_ref.backend_ref.name));
                }
            }
        }

        for route in self.tcp_routes.values() {
            let route_ns = route
                .metadata
                .namespace
                .as_deref()
                .unwrap_or("default")
                .to_string();
            for rule in &route.spec.rules {
                for backend_ref in &rule.backend_refs {
                    let ns = backend_ref.namespace.as_deref().unwrap_or(&route_ns);
                    index.insert(GatewayState::key(ns, &backend_ref.name));
                }
            }
        }

        for route in self.tls_routes.values() {
            let route_ns = route
                .metadata
                .namespace
                .as_deref()
                .unwrap_or("default")
                .to_string();
            for rule in &route.spec.rules {
                for backend_ref in &rule.backend_refs {
                    let ns = backend_ref.namespace.as_deref().unwrap_or(&route_ns);
                    index.insert(GatewayState::key(ns, &backend_ref.name));
                }
            }
        }

        self.service_ref_index = index;
    }

    /// Build a [`GatewayState`] snapshot from the current store contents.
    pub fn to_gateway_state(&self) -> GatewayState {
        GatewayState {
            gateways: self.gateways.clone(),
            http_routes: self.http_routes.clone(),
            tcp_routes: self.tcp_routes.clone(),
            tls_routes: self.tls_routes.clone(),
            service_endpoints: self.service_endpoints.clone(),
            tls_secrets: self.tls_secrets.clone(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Public handle
// ─────────────────────────────────────────────────────────────────────────────

/// Thread-safe shared store of Gateway API resources.
///
/// Clone is cheap — it clones the inner `Arc`.
#[derive(Clone, Debug)]
pub struct SharedStore {
    inner: Arc<RwLock<StoreInner>>,
}

impl Default for SharedStore {
    fn default() -> Self {
        Self::new()
    }
}

impl SharedStore {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(StoreInner::default())),
        }
    }

    // ── Readiness ────────────────────────────────────────────────────────────

    /// Returns `true` once the store has been populated at least once.
    pub async fn is_ready(&self) -> bool {
        self.inner.read().await.ready
    }

    /// Mark the store as ready (called after initial population).
    pub async fn mark_ready(&self) {
        self.inner.write().await.ready = true;
    }

    // ── Snapshot ─────────────────────────────────────────────────────────────

    /// Return a full [`GatewayState`] snapshot for config generation.
    ///
    /// Returns `None` when the store is not yet ready.
    pub async fn snapshot(&self) -> Option<GatewayState> {
        let inner = self.inner.read().await;
        if !inner.ready {
            return None;
        }
        Some(inner.to_gateway_state())
    }

    // ── Index lookup ─────────────────────────────────────────────────────────

    /// Returns `true` if the given service is referenced by at least one route.
    ///
    /// When the store is not ready this returns `None` so callers can fall
    /// back to the API-list path.
    pub async fn is_service_referenced(&self, namespace: &str, name: &str) -> Option<bool> {
        let inner = self.inner.read().await;
        if !inner.ready {
            return None;
        }
        let key = GatewayState::key(namespace, name);
        Some(inner.service_ref_index.contains(&key))
    }

    // ── Typed counts (for metrics) ────────────────────────────────────────────

    /// Returns per-namespace counts of Gateways grouped by gateway class.
    pub async fn gateway_counts(&self) -> HashMap<(String, String), i64> {
        let inner = self.inner.read().await;
        let mut counts = HashMap::new();
        for gw in inner.gateways.values() {
            let ns = gw
                .metadata
                .namespace
                .clone()
                .unwrap_or_else(|| "default".to_string());
            let class = gw.spec.gateway_class_name.clone();
            *counts.entry((ns, class)).or_insert(0) += 1;
        }
        counts
    }

    /// Returns per-namespace counts of HTTPRoutes.
    pub async fn httproute_counts(&self) -> HashMap<String, i64> {
        let inner = self.inner.read().await;
        let mut counts: HashMap<String, i64> = HashMap::new();
        for route in inner.http_routes.values() {
            let ns = route
                .metadata
                .namespace
                .clone()
                .unwrap_or_else(|| "default".to_string());
            *counts.entry(ns).or_insert(0) += 1;
        }
        counts
    }

    /// Returns per-namespace counts of TCPRoutes.
    pub async fn tcproute_counts(&self) -> HashMap<String, i64> {
        let inner = self.inner.read().await;
        let mut counts: HashMap<String, i64> = HashMap::new();
        for route in inner.tcp_routes.values() {
            let ns = route
                .metadata
                .namespace
                .clone()
                .unwrap_or_else(|| "default".to_string());
            *counts.entry(ns).or_insert(0) += 1;
        }
        counts
    }

    /// Returns per-namespace counts of TLSRoutes.
    pub async fn tlsroute_counts(&self) -> HashMap<String, i64> {
        let inner = self.inner.read().await;
        let mut counts: HashMap<String, i64> = HashMap::new();
        for route in inner.tls_routes.values() {
            let ns = route
                .metadata
                .namespace
                .clone()
                .unwrap_or_else(|| "default".to_string());
            *counts.entry(ns).or_insert(0) += 1;
        }
        counts
    }

    /// Returns per-namespace counts of ReferenceGrants.
    pub async fn reference_grant_counts(&self) -> HashMap<String, i64> {
        let inner = self.inner.read().await;
        let mut counts: HashMap<String, i64> = HashMap::new();
        for grant in inner.reference_grants.values() {
            let ns = grant
                .metadata
                .namespace
                .clone()
                .unwrap_or_else(|| "default".to_string());
            *counts.entry(ns).or_insert(0) += 1;
        }
        counts
    }

    // ── Write accessors ───────────────────────────────────────────────────────

    /// Upsert a Gateway.
    pub async fn upsert_gateway(&self, key: String, gateway: Gateway) {
        self.inner.write().await.gateways.insert(key, gateway);
    }

    /// Remove a Gateway.
    pub async fn remove_gateway(&self, key: &str) {
        self.inner.write().await.gateways.remove(key);
    }

    /// Upsert a GatewayClass.
    pub async fn upsert_gateway_class(&self, key: String, gc: GatewayClass) {
        self.inner.write().await.gateway_classes.insert(key, gc);
    }

    /// Upsert an HTTPRoute and rebuild the service index.
    pub async fn upsert_http_route(&self, key: String, route: HTTPRoute) {
        let mut inner = self.inner.write().await;
        inner.http_routes.insert(key, route);
        inner.rebuild_service_index();
    }

    /// Remove an HTTPRoute and rebuild the service index.
    pub async fn remove_http_route(&self, key: &str) {
        let mut inner = self.inner.write().await;
        inner.http_routes.remove(key);
        inner.rebuild_service_index();
    }

    /// Upsert a TCPRoute and rebuild the service index.
    pub async fn upsert_tcp_route(&self, key: String, route: TCPRoute) {
        let mut inner = self.inner.write().await;
        inner.tcp_routes.insert(key, route);
        inner.rebuild_service_index();
    }

    /// Remove a TCPRoute and rebuild the service index.
    pub async fn remove_tcp_route(&self, key: &str) {
        let mut inner = self.inner.write().await;
        inner.tcp_routes.remove(key);
        inner.rebuild_service_index();
    }

    /// Upsert a TLSRoute and rebuild the service index.
    pub async fn upsert_tls_route(&self, key: String, route: TLSRoute) {
        let mut inner = self.inner.write().await;
        inner.tls_routes.insert(key, route);
        inner.rebuild_service_index();
    }

    /// Remove a TLSRoute and rebuild the service index.
    pub async fn remove_tls_route(&self, key: &str) {
        let mut inner = self.inner.write().await;
        inner.tls_routes.remove(key);
        inner.rebuild_service_index();
    }

    /// Upsert service endpoints.
    pub async fn upsert_endpoints(&self, key: String, endpoints: ServiceEndpoints) {
        self.inner
            .write()
            .await
            .service_endpoints
            .insert(key, endpoints);
    }

    /// Remove service endpoints.
    pub async fn remove_endpoints(&self, key: &str) {
        self.inner.write().await.service_endpoints.remove(key);
    }

    /// Upsert a TLS secret (cert_path, key_path).
    pub async fn upsert_tls_secret(&self, key: String, cert_path: String, key_path: String) {
        self.inner
            .write()
            .await
            .tls_secrets
            .insert(key, (cert_path, key_path));
    }

    /// Remove a GatewayClass.
    pub async fn remove_gateway_class(&self, key: &str) {
        self.inner.write().await.gateway_classes.remove(key);
    }

    /// Remove a TLS secret.
    pub async fn remove_tls_secret(&self, key: &str) {
        self.inner.write().await.tls_secrets.remove(key);
    }

    /// Upsert a ReferenceGrant.
    pub async fn upsert_reference_grant(&self, key: String, grant: ReferenceGrant) {
        self.inner.write().await.reference_grants.insert(key, grant);
    }

    /// Remove a ReferenceGrant.
    pub async fn remove_reference_grant(&self, key: &str) {
        self.inner.write().await.reference_grants.remove(key);
    }

    /// Bulk-replace all store contents atomically (used for initial population).
    pub async fn replace_all(&self, inner: StoreInner) {
        *self.inner.write().await = inner;
    }

    /// Ingest a [`GatewayState`] snapshot into the store atomically and mark
    /// it ready.
    ///
    /// **Callers must only call this when all core API lists succeeded.**
    /// A partial snapshot would lock in missing resources and prevent future
    /// fallback retries (see `trigger_config_update` for the guard).
    ///
    /// Existing TLS secret entries are preserved — the snapshot may not carry
    /// them (they are written by the secret reconciler).
    pub async fn ingest_gateway_state(&self, state: GatewayState) {
        let mut inner = self.inner.write().await;

        // Merge routes/gateways from the snapshot.  We do NOT overwrite tls_secrets
        // because those are written by the secret reconciler with real on-disk paths.
        inner.gateways = state.gateways;
        inner.http_routes = state.http_routes;
        inner.tcp_routes = state.tcp_routes;
        inner.tls_routes = state.tls_routes;
        inner.service_endpoints = state.service_endpoints;

        // Merge tls_secrets: snapshot entries fill gaps; existing entries win.
        for (k, v) in state.tls_secrets {
            inner.tls_secrets.entry(k).or_insert(v);
        }

        inner.rebuild_service_index();
        inner.ready = true;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crds::{
        BackendRef, GatewaySpec, HTTPBackendRef, HTTPRouteRule, HTTPRouteSpec, Listener,
        ParentReference, ProtocolType,
    };
    use kube::core::ObjectMeta;

    fn make_http_route(name: &str, ns: &str, backend_ns: Option<&str>, backend: &str) -> HTTPRoute {
        HTTPRoute {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some(ns.to_string()),
                ..Default::default()
            },
            spec: HTTPRouteSpec {
                parent_refs: vec![],
                hostnames: vec![],
                rules: vec![HTTPRouteRule {
                    name: None,
                    matches: vec![],
                    filters: vec![],
                    backend_refs: vec![HTTPBackendRef {
                        backend_ref: BackendRef {
                            group: "".to_string(),
                            kind: "Service".to_string(),
                            name: backend.to_string(),
                            namespace: backend_ns.map(str::to_string),
                            port: Some(80),
                            weight: 1,
                        },
                        filters: vec![],
                    }],
                    timeouts: None,
                }],
            },
            status: None,
        }
    }

    // ── Readiness ─────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_store_starts_unready() {
        let store = SharedStore::new();
        assert!(!store.is_ready().await);
    }

    #[tokio::test]
    async fn test_store_mark_ready() {
        let store = SharedStore::new();
        store.mark_ready().await;
        assert!(store.is_ready().await);
    }

    // ── Snapshot returns None when not ready ──────────────────────────────────

    #[tokio::test]
    async fn test_snapshot_none_when_not_ready() {
        let store = SharedStore::new();
        assert!(store.snapshot().await.is_none());
    }

    #[tokio::test]
    async fn test_snapshot_some_when_ready() {
        let store = SharedStore::new();
        store.mark_ready().await;
        assert!(store.snapshot().await.is_some());
    }

    // ── Service reference index ───────────────────────────────────────────────

    #[tokio::test]
    async fn test_is_service_referenced_none_when_not_ready() {
        let store = SharedStore::new();
        // Insert a route but don't mark ready
        let route = make_http_route("r", "default", None, "my-svc");
        store
            .upsert_http_route("default/r".to_string(), route)
            .await;
        // Should return None (not ready)
        assert_eq!(store.is_service_referenced("default", "my-svc").await, None);
    }

    #[tokio::test]
    async fn test_is_service_referenced_true_after_ready() {
        let store = SharedStore::new();
        let route = make_http_route("r", "default", None, "my-svc");
        store
            .upsert_http_route("default/r".to_string(), route)
            .await;
        store.mark_ready().await;
        assert_eq!(
            store.is_service_referenced("default", "my-svc").await,
            Some(true)
        );
    }

    #[tokio::test]
    async fn test_is_service_referenced_false_for_unknown_service() {
        let store = SharedStore::new();
        store.mark_ready().await;
        assert_eq!(
            store.is_service_referenced("default", "unknown-svc").await,
            Some(false)
        );
    }

    #[tokio::test]
    async fn test_is_service_referenced_cross_namespace() {
        let store = SharedStore::new();
        // Route in ns-a references backend in ns-b
        let route = make_http_route("r", "ns-a", Some("ns-b"), "cross-svc");
        store.upsert_http_route("ns-a/r".to_string(), route).await;
        store.mark_ready().await;
        // Should be found under ns-b
        assert_eq!(
            store.is_service_referenced("ns-b", "cross-svc").await,
            Some(true)
        );
        // Should NOT be found under ns-a
        assert_eq!(
            store.is_service_referenced("ns-a", "cross-svc").await,
            Some(false)
        );
    }

    #[tokio::test]
    async fn test_index_rebuilt_on_route_removal() {
        let store = SharedStore::new();
        let route = make_http_route("r", "default", None, "my-svc");
        store
            .upsert_http_route("default/r".to_string(), route)
            .await;
        store.mark_ready().await;

        // Referenced before removal
        assert_eq!(
            store.is_service_referenced("default", "my-svc").await,
            Some(true)
        );

        // Remove the route
        store.remove_http_route("default/r").await;

        // No longer referenced
        assert_eq!(
            store.is_service_referenced("default", "my-svc").await,
            Some(false)
        );
    }

    // ── Snapshot contents ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_snapshot_contains_upserted_route() {
        let store = SharedStore::new();
        let route = make_http_route("my-route", "default", None, "svc");
        store
            .upsert_http_route("default/my-route".to_string(), route)
            .await;
        store.mark_ready().await;

        let snap = store.snapshot().await.expect("store should be ready");
        assert!(snap.http_routes.contains_key("default/my-route"));
    }

    #[tokio::test]
    async fn test_snapshot_contains_endpoints() {
        let store = SharedStore::new();
        store
            .upsert_endpoints(
                "default/my-svc".to_string(),
                ServiceEndpoints {
                    namespace: "default".to_string(),
                    name: "my-svc".to_string(),
                    port: 80,
                    endpoints: vec!["10.0.0.1:80".to_string()],
                },
            )
            .await;
        store.mark_ready().await;

        let snap = store.snapshot().await.expect("store should be ready");
        assert!(snap.service_endpoints.contains_key("default/my-svc"));
    }

    // ── Counts ────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_httproute_counts() {
        let store = SharedStore::new();
        store
            .upsert_http_route(
                "ns-a/r1".to_string(),
                make_http_route("r1", "ns-a", None, "svc"),
            )
            .await;
        store
            .upsert_http_route(
                "ns-a/r2".to_string(),
                make_http_route("r2", "ns-a", None, "svc"),
            )
            .await;
        store
            .upsert_http_route(
                "ns-b/r3".to_string(),
                make_http_route("r3", "ns-b", None, "svc"),
            )
            .await;

        let counts = store.httproute_counts().await;
        assert_eq!(counts.get("ns-a"), Some(&2));
        assert_eq!(counts.get("ns-b"), Some(&1));
    }

    // ── ingest_gateway_state ──────────────────────────────────────────────────

    #[tokio::test]
    async fn test_ingest_gateway_state_marks_ready() {
        let store = SharedStore::new();
        assert!(!store.is_ready().await);

        let state = GatewayState::default();
        store.ingest_gateway_state(state).await;

        assert!(store.is_ready().await);
    }

    #[tokio::test]
    async fn test_ingest_gateway_state_populates_routes() {
        let store = SharedStore::new();
        let mut state = GatewayState::default();

        let route = make_http_route("r", "default", None, "svc");
        state.http_routes.insert("default/r".to_string(), route);

        store.ingest_gateway_state(state).await;

        let snap = store.snapshot().await.expect("store should be ready");
        assert!(snap.http_routes.contains_key("default/r"));
    }

    #[tokio::test]
    async fn test_ingest_gateway_state_rebuilds_service_index() {
        let store = SharedStore::new();
        let mut state = GatewayState::default();

        let route = make_http_route("r", "default", None, "ingested-svc");
        state.http_routes.insert("default/r".to_string(), route);

        store.ingest_gateway_state(state).await;

        assert_eq!(
            store.is_service_referenced("default", "ingested-svc").await,
            Some(true)
        );
    }

    #[tokio::test]
    async fn test_ingest_gateway_state_preserves_existing_tls_secrets() {
        let store = SharedStore::new();

        // Pre-populate a TLS secret (as the secret reconciler would).
        store
            .upsert_tls_secret(
                "default/my-cert".to_string(),
                "/var/run/wicket/tls/default-my-cert.crt".to_string(),
                "/var/run/wicket/tls/default-my-cert.key".to_string(),
            )
            .await;

        // Ingest a GatewayState that does NOT carry the secret.
        let state = GatewayState::default();
        store.ingest_gateway_state(state).await;

        // The pre-existing secret must still be present.
        let snap = store.snapshot().await.expect("store should be ready");
        assert!(
            snap.tls_secrets.contains_key("default/my-cert"),
            "pre-existing TLS secret should be preserved after ingest"
        );
    }

    #[tokio::test]
    async fn test_ingest_gateway_state_does_not_overwrite_existing_tls_secret() {
        let store = SharedStore::new();

        // Pre-populate with real on-disk paths.
        store
            .upsert_tls_secret(
                "default/cert".to_string(),
                "/real/cert.crt".to_string(),
                "/real/cert.key".to_string(),
            )
            .await;

        // Ingest a snapshot that carries a different (stale) path for the same key.
        let mut state = GatewayState::default();
        state.tls_secrets.insert(
            "default/cert".to_string(),
            ("/stale/cert.crt".to_string(), "/stale/cert.key".to_string()),
        );
        store.ingest_gateway_state(state).await;

        // The existing (real) path must win.
        let snap = store.snapshot().await.expect("store should be ready");
        let (cert, _key) = snap.tls_secrets.get("default/cert").expect("key present");
        assert_eq!(
            cert, "/real/cert.crt",
            "existing TLS path should not be overwritten"
        );
    }

    // ── remove_gateway_class ──────────────────────────────────────────────────

    #[tokio::test]
    async fn test_remove_gateway_class() {
        use crate::crds::{GatewayClassSpec, GatewayClassStatus};
        let store = SharedStore::new();
        store.mark_ready().await;

        let gc = GatewayClass {
            metadata: ObjectMeta {
                name: Some("wicket".to_string()),
                ..Default::default()
            },
            spec: GatewayClassSpec {
                controller_name: "wicket.io/gateway-controller".to_string(),
                parameters_ref: None,
                description: None,
            },
            status: None,
        };
        store.upsert_gateway_class("wicket".to_string(), gc).await;

        // Verify it's present
        {
            let inner = store.inner.read().await;
            assert!(inner.gateway_classes.contains_key("wicket"));
        }

        // Remove it
        store.remove_gateway_class("wicket").await;

        // Verify it's gone
        {
            let inner = store.inner.read().await;
            assert!(!inner.gateway_classes.contains_key("wicket"));
        }
    }

    // ── remove_tls_secret ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_remove_tls_secret() {
        let store = SharedStore::new();
        store.mark_ready().await;

        store
            .upsert_tls_secret(
                "default/my-cert".to_string(),
                "/tls/default-my-cert.crt".to_string(),
                "/tls/default-my-cert.key".to_string(),
            )
            .await;

        // Verify present in snapshot
        let snap = store.snapshot().await.expect("ready");
        assert!(snap.tls_secrets.contains_key("default/my-cert"));

        // Remove it
        store.remove_tls_secret("default/my-cert").await;

        // Verify gone from snapshot
        let snap = store.snapshot().await.expect("ready");
        assert!(!snap.tls_secrets.contains_key("default/my-cert"));
    }

    // ── remove_reference_grant ────────────────────────────────────────────────

    #[tokio::test]
    async fn test_remove_reference_grant() {
        use crate::crds::{ReferenceGrantFrom, ReferenceGrantSpec, ReferenceGrantTo};
        let store = SharedStore::new();
        store.mark_ready().await;

        let grant = ReferenceGrant {
            metadata: ObjectMeta {
                name: Some("allow-secret".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            },
            spec: ReferenceGrantSpec {
                from: vec![ReferenceGrantFrom {
                    group: "gateway.networking.k8s.io".to_string(),
                    kind: "Gateway".to_string(),
                    namespace: "other-ns".to_string(),
                }],
                to: vec![ReferenceGrantTo {
                    group: "".to_string(),
                    kind: "Secret".to_string(),
                    name: None,
                }],
            },
        };
        store
            .upsert_reference_grant("default/allow-secret".to_string(), grant)
            .await;

        // Verify present
        {
            let inner = store.inner.read().await;
            assert!(inner.reference_grants.contains_key("default/allow-secret"));
        }

        // Remove it
        store.remove_reference_grant("default/allow-secret").await;

        // Verify gone
        {
            let inner = store.inner.read().await;
            assert!(!inner.reference_grants.contains_key("default/allow-secret"));
        }
    }

    // ── replace_all ───────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_replace_all_marks_ready() {
        let store = SharedStore::new();
        assert!(!store.is_ready().await);

        let mut inner = StoreInner::default();
        inner.ready = true;
        store.replace_all(inner).await;

        assert!(store.is_ready().await);
    }

    #[tokio::test]
    async fn test_replace_all_rebuilds_index() {
        let store = SharedStore::new();

        let mut inner = StoreInner::default();
        inner.ready = true;
        let route = make_http_route("r", "default", None, "bulk-svc");
        inner.http_routes.insert("default/r".to_string(), route);
        inner.rebuild_service_index();
        store.replace_all(inner).await;

        assert_eq!(
            store.is_service_referenced("default", "bulk-svc").await,
            Some(true)
        );
    }
}
