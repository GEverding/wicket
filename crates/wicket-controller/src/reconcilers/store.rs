//! Shared resource cache/index for controller reconcilers.
//!
//! Provides a synchronized in-memory store of Gateway API resources that
//! reconcilers can read without issuing repeated full-list API calls.
//!
//! ## Warm-up / readiness
//!
//! The store starts in an *unready* state.  The store is considered *complete*
//! (and therefore ready for planner use) only when **all** of the following
//! resource classes have been populated at least once:
//!
//! - Gateways
//! - GatewayClasses
//! - HTTPRoutes / TCPRoutes / TLSRoutes
//! - ReferenceGrants
//!
//! [`SharedStore::is_ready`] reflects this completeness check.  Callers that
//! only need the basic gateway/route data may use [`SharedStore::snapshot`];
//! planners that need policy/class data must use
//! [`SharedStore::planner_snapshot`], which returns [`SnapshotResult::NotReady`]
//! until all resource classes are present.
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
//!
//! ## Planner-friendly API
//!
//! [`SharedStore::planner_snapshot`] returns a [`SnapshotResult`] that
//! explicitly distinguishes *not ready* (bootstrap/recovery gap) from
//! *ready* (steady-state).  Planners must check for `SnapshotResult::NotReady`
//! and return [`crate::reconcilers::contracts::PlanError::StoreNotReady`]
//! rather than proceeding with incomplete data.
//!
//! Targeted accessors (`gateway`, `gateway_class`, `tls_secret`,
//! `reference_grants_in_namespace`, `http_routes_for_gateway`, etc.) let
//! planners look up individual resources without cloning the full state.
//!
//! ## Determinism
//!
//! All planner-facing accessors that return `Vec` sort their output by a
//! stable key (typically `namespace/name` from `metadata`).  This ensures
//! planners produce identical output for identical store contents regardless
//! of `HashMap` iteration order.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;

use tokio::sync::RwLock;

use crate::crds::{Gateway, GatewayClass, HTTPRoute, ReferenceGrant, TCPRoute, TLSRoute};
use crate::reconcilers::config_generator::{GatewayState, ServiceEndpoints};

// ─────────────────────────────────────────────────────────────────────────────
// Snapshot result
// ─────────────────────────────────────────────────────────────────────────────

/// The result of a planner snapshot read.
///
/// Callers must handle `NotReady` explicitly — it signals a bootstrap or
/// recovery gap where the store has not yet been fully populated.  Planners
/// should return [`crate::reconcilers::contracts::PlanError::StoreNotReady`]
/// when they receive this variant.
///
/// Using an explicit enum (rather than `Option`) makes the two states
/// self-documenting at call sites and prevents accidental `unwrap_or_default`
/// patterns that would silently plan against an empty store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnapshotResult<T> {
    /// The store has not yet been fully populated.  Do not use cached data.
    NotReady,
    /// The store is in steady state.  The inner value is a consistent snapshot.
    Ready(T),
}

impl<T> SnapshotResult<T> {
    /// Returns `true` if the store is ready.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        matches!(self, Self::Ready(_))
    }

    /// Converts to `Option`, discarding the readiness distinction.
    ///
    /// # Warning
    ///
    /// This method erases the `NotReady` signal.  **Do not use in planner
    /// code** — match on the enum directly so that `NotReady` is handled
    /// explicitly and the caller is forced to return
    /// [`crate::reconcilers::contracts::PlanError::StoreNotReady`].
    ///
    /// Acceptable uses: metrics helpers, test assertions, and non-planner
    /// code that has already checked readiness through another path.
    #[doc(hidden)]
    pub fn into_option(self) -> Option<T> {
        match self {
            Self::Ready(v) => Some(v),
            Self::NotReady => None,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Planner snapshot
// ─────────────────────────────────────────────────────────────────────────────

/// A typed, planner-friendly snapshot of the store contents.
///
/// This is the primary input type for planners.  It is a consistent point-in-
/// time copy taken under a single read lock, so planners see a coherent view
/// of all resources without holding the lock during planning.
///
/// ## What is included
///
/// All resource maps needed to compute a `ReconcilePlan` for any Gateway:
/// - Gateways and GatewayClasses (identity and class membership)
/// - HTTPRoutes, TCPRoutes, TLSRoutes (attachment and backend resolution)
/// - ServiceEndpoints (backend address resolution)
/// - TLS secrets (cert/key paths for TLS listeners)
/// - ReferenceGrants (cross-namespace permission checks)
/// - The service reference index (O(1) "is this service used?" queries)
///
/// ## What is NOT included
///
/// Kubernetes object metadata beyond what is needed for planning (e.g., no
/// `managedFields`, no `resourceVersion`).  The planner must not use this
/// snapshot to issue Kubernetes API calls.
#[derive(Clone, Debug)]
pub struct PlannerSnapshot {
    /// Gateways by `namespace/name`.
    pub gateways: HashMap<String, Gateway>,
    /// GatewayClasses by name (cluster-scoped).
    pub gateway_classes: HashMap<String, GatewayClass>,
    /// HTTPRoutes by `namespace/name`.
    pub http_routes: HashMap<String, HTTPRoute>,
    /// TCPRoutes by `namespace/name`.
    pub tcp_routes: HashMap<String, TCPRoute>,
    /// TLSRoutes by `namespace/name`.
    pub tls_routes: HashMap<String, TLSRoute>,
    /// Service endpoints by `namespace/name`.
    pub service_endpoints: HashMap<String, ServiceEndpoints>,
    /// TLS secrets by `namespace/name` -> `(cert_path, key_path)`.
    pub tls_secrets: HashMap<String, (String, String)>,
    /// ReferenceGrants by `namespace/name`.
    pub reference_grants: HashMap<String, ReferenceGrant>,
    /// Reverse index: `namespace/service-name` -> referenced by >= 1 route.
    pub service_ref_index: HashSet<String>,
    /// Namespace labels by namespace name.
    ///
    /// Used by the attachment planner to evaluate `AllowedRoutes.namespaces.from
    /// = Selector` policies.  Populated by the namespace watch reconciler.
    /// When absent for a given namespace, `Selector` policies are denied
    /// conservatively.
    pub namespace_labels: HashMap<String, BTreeMap<String, String>>,
}

impl PlannerSnapshot {
    // ── Targeted accessors ────────────────────────────────────────────────────

    /// Look up a single Gateway by namespace and name.
    #[must_use]
    pub fn gateway(&self, namespace: &str, name: &str) -> Option<&Gateway> {
        self.gateways.get(&GatewayState::key(namespace, name))
    }

    /// Look up a GatewayClass by name.
    #[must_use]
    pub fn gateway_class(&self, name: &str) -> Option<&GatewayClass> {
        self.gateway_classes.get(name)
    }

    /// Look up a TLS secret by namespace and name.
    ///
    /// Returns `(cert_path, key_path)` if the secret is known.
    #[must_use]
    pub fn tls_secret(&self, namespace: &str, name: &str) -> Option<&(String, String)> {
        self.tls_secrets.get(&GatewayState::key(namespace, name))
    }

    /// Returns all ReferenceGrants whose *target* namespace matches `namespace`.
    ///
    /// The Gateway API spec places ReferenceGrants in the namespace of the
    /// *target* resource (e.g., the namespace that owns the Secret or Service
    /// being referenced).  Planners checking cross-namespace permissions should
    /// call this with the target resource's namespace.
    ///
    /// Results are sorted by `namespace/name` for deterministic planner output.
    #[must_use]
    pub fn reference_grants_in_namespace(&self, namespace: &str) -> Vec<&ReferenceGrant> {
        let mut grants: Vec<&ReferenceGrant> = self
            .reference_grants
            .iter()
            .filter(|(_, g)| g.metadata.namespace.as_deref().unwrap_or("default") == namespace)
            .map(|(_, g)| g)
            .collect();
        // Sort by name for deterministic output.
        grants.sort_by_key(|g| g.metadata.name.as_deref().unwrap_or(""));
        grants
    }

    /// Returns all HTTPRoutes whose `spec.parentRefs` reference the given Gateway.
    ///
    /// A route is considered attached when at least one `parentRef` matches
    /// `gateway_namespace/gateway_name` (group `gateway.networking.k8s.io`,
    /// kind `Gateway`).  Routes that omit `namespace` in the parentRef are
    /// assumed to reference a Gateway in the same namespace as the route.
    ///
    /// Results are sorted by `namespace/name` for deterministic planner output.
    #[must_use]
    pub fn http_routes_for_gateway(
        &self,
        gateway_namespace: &str,
        gateway_name: &str,
    ) -> Vec<&HTTPRoute> {
        let mut routes: Vec<&HTTPRoute> = self
            .http_routes
            .values()
            .filter(|r| {
                route_references_gateway(
                    r.metadata.namespace.as_deref().unwrap_or("default"),
                    &r.spec.parent_refs,
                    gateway_namespace,
                    gateway_name,
                )
            })
            .collect();
        routes.sort_by_key(|r| {
            (
                r.metadata.namespace.as_deref().unwrap_or(""),
                r.metadata.name.as_deref().unwrap_or(""),
            )
        });
        routes
    }

    /// Returns all TCPRoutes whose `spec.parentRefs` reference the given Gateway.
    ///
    /// Results are sorted by `namespace/name` for deterministic planner output.
    #[must_use]
    pub fn tcp_routes_for_gateway(
        &self,
        gateway_namespace: &str,
        gateway_name: &str,
    ) -> Vec<&TCPRoute> {
        let mut routes: Vec<&TCPRoute> = self
            .tcp_routes
            .values()
            .filter(|r| {
                route_references_gateway(
                    r.metadata.namespace.as_deref().unwrap_or("default"),
                    &r.spec.parent_refs,
                    gateway_namespace,
                    gateway_name,
                )
            })
            .collect();
        routes.sort_by_key(|r| {
            (
                r.metadata.namespace.as_deref().unwrap_or(""),
                r.metadata.name.as_deref().unwrap_or(""),
            )
        });
        routes
    }

    /// Returns all TLSRoutes whose `spec.parentRefs` reference the given Gateway.
    ///
    /// Results are sorted by `namespace/name` for deterministic planner output.
    #[must_use]
    pub fn tls_routes_for_gateway(
        &self,
        gateway_namespace: &str,
        gateway_name: &str,
    ) -> Vec<&TLSRoute> {
        let mut routes: Vec<&TLSRoute> = self
            .tls_routes
            .values()
            .filter(|r| {
                route_references_gateway(
                    r.metadata.namespace.as_deref().unwrap_or("default"),
                    &r.spec.parent_refs,
                    gateway_namespace,
                    gateway_name,
                )
            })
            .collect();
        routes.sort_by_key(|r| {
            (
                r.metadata.namespace.as_deref().unwrap_or(""),
                r.metadata.name.as_deref().unwrap_or(""),
            )
        });
        routes
    }

    /// Returns `true` if the given service is referenced by at least one route.
    ///
    /// O(1) via the pre-built reverse index.
    #[must_use]
    pub fn is_service_referenced(&self, namespace: &str, name: &str) -> bool {
        self.service_ref_index
            .contains(&GatewayState::key(namespace, name))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Returns `true` if any entry in `parent_refs` references the given Gateway.
///
/// Matches on group `gateway.networking.k8s.io` (or empty string, which the
/// Gateway API spec treats as equivalent) and kind `Gateway`.  The namespace
/// defaults to the route's own namespace when absent.
fn route_references_gateway(
    route_namespace: &str,
    parent_refs: &[crate::crds::ParentReference],
    gateway_namespace: &str,
    gateway_name: &str,
) -> bool {
    parent_refs.iter().any(|p| {
        let group_matches = p.group.is_empty() || p.group == "gateway.networking.k8s.io";
        let kind_matches = p.kind == "Gateway";
        let ns_matches = p.namespace.as_deref().unwrap_or(route_namespace) == gateway_namespace;
        let name_matches = p.name == gateway_name;
        group_matches && kind_matches && ns_matches && name_matches
    })
}

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
    /// TLS secrets by namespace/name -> (cert_path, key_path).
    pub tls_secrets: HashMap<String, (String, String)>,
    pub reference_grants: HashMap<String, ReferenceGrant>,

    /// Reverse index: "namespace/service-name" -> true if referenced by >=1 route.
    /// Rebuilt on every write to any route map.
    pub service_ref_index: HashSet<String>,

    /// Namespace labels by namespace name.
    ///
    /// Populated by the namespace watch reconciler.  Used by the attachment
    /// planner to evaluate `AllowedRoutes.namespaces.from = Selector` policies.
    pub namespace_labels: HashMap<String, BTreeMap<String, String>>,

    /// Phase of the store bootstrap lifecycle.
    phase: StorePhase,
}

/// Phase of the store's initial-list bootstrap.
///
/// The store transitions from `Warming` to `Ready` once every resource
/// class has completed its initial `api.list()`. Once `Ready`, the
/// store never goes back to `Warming`.
#[derive(Debug, Clone)]
enum StorePhase {
    /// Initial list operations are in progress.
    Warming(WarmingProgress),
    /// All resource classes have been listed. Safe for planner snapshots.
    Ready,
}

impl Default for StorePhase {
    fn default() -> Self {
        Self::Warming(WarmingProgress::default())
    }
}

/// Tracks which resource classes have completed their initial list.
#[derive(Debug, Clone, Default)]
struct WarmingProgress {
    listed: HashSet<ResourceClass>,
}

impl WarmingProgress {
    fn is_complete(&self) -> bool {
        ResourceClass::ALL.iter().all(|rc| self.listed.contains(rc))
    }

    fn remaining(&self) -> Vec<ResourceClass> {
        ResourceClass::ALL
            .iter()
            .filter(|rc| !self.listed.contains(rc))
            .copied()
            .collect()
    }
}

/// Identifies a resource class that must complete its initial list
/// before the store is considered ready.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum ResourceClass {
    GatewayClasses,
    ReferenceGrants,
    Gateways,
    HttpRoutes,
    TcpRoutes,
    TlsRoutes,
    Services,
    Endpoints,
    Secrets,
}

impl ResourceClass {
    pub(crate) const ALL: &'static [Self] = &[
        Self::GatewayClasses,
        Self::ReferenceGrants,
        Self::Gateways,
        Self::HttpRoutes,
        Self::TcpRoutes,
        Self::TlsRoutes,
        Self::Services,
        Self::Endpoints,
        Self::Secrets,
    ];
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Returns `true` when a backend ref's `group` and `kind` identify a core
/// Kubernetes `Service`.
///
/// Per the Gateway API spec:
/// - `group` must be `""` (the core API group).
/// - `kind` must be `"Service"` or `""` (the spec default, which is `Service`).
///
/// Both fields are checked to prevent non-core resources that happen to have
/// `kind = "Service"` (e.g. `group = "custom.io"`) from being misclassified.
fn is_core_service_ref(group: &str, kind: &str) -> bool {
    let group_is_core = group.is_empty();
    let kind_is_service = kind.is_empty() || kind == "Service";
    group_is_core && kind_is_service
}

impl StoreInner {
    /// Rebuild the service reference index from current route maps.
    pub fn rebuild_service_index(&mut self) {
        let mut index = HashSet::new();

        // HTTPBackendRef wraps BackendRef; the kind defaults to "Service" per the
        // Gateway API spec (see BackendRef::default_service_kind).  We index only
        // refs that are core-group Services: kind is "Service" or empty AND group
        // is "" (core group).  Checking both fields prevents non-core resources
        // with kind "Service" (e.g. group "custom.io", kind "Service") from being
        // misclassified as core Services.
        for route in self.http_routes.values() {
            let route_ns = route
                .metadata
                .namespace
                .as_deref()
                .unwrap_or("default")
                .to_string();
            for rule in &route.spec.rules {
                for backend_ref in &rule.backend_refs {
                    let br = &backend_ref.backend_ref;
                    if !is_core_service_ref(&br.group, &br.kind) {
                        continue;
                    }
                    let ns = br.namespace.as_deref().unwrap_or(&route_ns);
                    index.insert(GatewayState::key(ns, &br.name));
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
                    if !is_core_service_ref(&backend_ref.group, &backend_ref.kind) {
                        continue;
                    }
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
                    if !is_core_service_ref(&backend_ref.group, &backend_ref.kind) {
                        continue;
                    }
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

    /// Returns `true` when the store is ready for planner use.
    ///
    /// All resource classes (gateways, gateway_classes, reference_grants) must
    /// have been populated at least once.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        matches!(self.phase, StorePhase::Ready)
    }

    /// Build a [`PlannerSnapshot`] from the current store contents.
    pub fn to_planner_snapshot(&self) -> PlannerSnapshot {
        PlannerSnapshot {
            gateways: self.gateways.clone(),
            gateway_classes: self.gateway_classes.clone(),
            http_routes: self.http_routes.clone(),
            tcp_routes: self.tcp_routes.clone(),
            tls_routes: self.tls_routes.clone(),
            service_endpoints: self.service_endpoints.clone(),
            tls_secrets: self.tls_secrets.clone(),
            reference_grants: self.reference_grants.clone(),
            service_ref_index: self.service_ref_index.clone(),
            namespace_labels: self.namespace_labels.clone(),
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

    /// Returns `true` once all required resource classes have been populated.
    ///
    /// "Ready" requires that every watched resource class has completed its
    /// initial list at least once.  This prevents planners from operating on a
    /// partially warmed cache.
    pub async fn is_ready(&self) -> bool {
        self.inner.read().await.is_complete()
    }

    /// Mark a resource class as having completed its initial list.
    ///
    /// Once all resource classes are marked, the store transitions to
    /// `Ready` and stays there permanently. Calling this on an already-ready
    /// store is a no-op.
    pub(crate) async fn mark_listed(&self, rc: ResourceClass) {
        let mut inner = self.inner.write().await;
        match &mut inner.phase {
            StorePhase::Warming(progress) => {
                progress.listed.insert(rc);
                if progress.is_complete() {
                    inner.phase = StorePhase::Ready;
                    tracing::info!("Store ready: all resource classes listed");
                } else {
                    let remaining = progress.remaining();
                    tracing::debug!(?rc, ?remaining, "Resource class listed");
                }
            }
            StorePhase::Ready => {}
        }
    }

    /// Mark the store as fully ready (all resource classes populated).
    ///
    /// Convenience method for tests and initial-population paths that have
    /// already ensured all resource classes are present.
    pub async fn mark_ready(&self) {
        self.inner.write().await.phase = StorePhase::Ready;
    }

    // ── Snapshot ─────────────────────────────────────────────────────────────

    /// Return a full [`GatewayState`] snapshot for config generation.
    ///
    /// Returns `None` when the initial Gateway list has not yet completed.
    /// This is a lighter check than [`planner_snapshot`] — it does not require
    /// every resource class to be present.
    pub async fn snapshot(&self) -> Option<GatewayState> {
        let inner = self.inner.read().await;
        let gateways_listed = match &inner.phase {
            StorePhase::Ready => true,
            StorePhase::Warming(progress) => progress.listed.contains(&ResourceClass::Gateways),
        };
        if !gateways_listed {
            return None;
        }
        Some(inner.to_gateway_state())
    }

    /// Return a [`PlannerSnapshot`] for use by planners.
    ///
    /// The returned [`SnapshotResult`] explicitly distinguishes *not ready*
    /// (bootstrap/recovery gap) from *ready* (steady-state).  Planners must
    /// match on `NotReady` and return
    /// [`crate::reconcilers::contracts::PlanError::StoreNotReady`] rather than
    /// proceeding with incomplete data.
    ///
    /// Unlike [`snapshot`](Self::snapshot), this snapshot requires **all**
    /// watched resource classes to have been populated.  It returns `NotReady`
    /// until that condition is met, preventing planners from silently
    /// operating on a partially warmed cache.
    pub async fn planner_snapshot(&self) -> SnapshotResult<PlannerSnapshot> {
        let inner = self.inner.read().await;
        if !inner.is_complete() {
            return SnapshotResult::NotReady;
        }
        SnapshotResult::Ready(inner.to_planner_snapshot())
    }

    // ── Targeted lookups ──────────────────────────────────────────────────────

    /// Look up a GatewayClass by name from the store.
    ///
    /// Returns `Some(gc)` when the store has been populated and the class exists.
    /// Returns `None` when the class is not found or the gateway-classes resource
    /// class has not yet been listed (the caller should fall back to the API).
    pub async fn get_gateway_class(&self, name: &str) -> Option<GatewayClass> {
        let inner = self.inner.read().await;
        let gateway_classes_listed = match &inner.phase {
            StorePhase::Ready => true,
            StorePhase::Warming(progress) => {
                progress.listed.contains(&ResourceClass::GatewayClasses)
            }
        };
        if !gateway_classes_listed {
            return None;
        }
        inner.gateway_classes.get(name).cloned()
    }

    // ── Index lookup ─────────────────────────────────────────────────────────

    /// Returns `true` if the given service is referenced by at least one route.
    ///
    /// When the store is not ready this returns `None` so callers can fall
    /// back to the API-list path.
    pub async fn is_service_referenced(&self, namespace: &str, name: &str) -> Option<bool> {
        let inner = self.inner.read().await;
        if !inner.is_complete() {
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

    /// Upsert namespace labels for a single namespace.
    ///
    /// Called by the namespace watch reconciler when a namespace is created or
    /// its labels change.  The attachment planner uses these labels to evaluate
    /// `AllowedRoutes.namespaces.from = Selector` policies.
    pub async fn upsert_namespace_labels(
        &self,
        namespace: String,
        labels: BTreeMap<String, String>,
    ) {
        self.inner
            .write()
            .await
            .namespace_labels
            .insert(namespace, labels);
    }

    /// Remove namespace labels for a namespace (called on namespace deletion).
    pub async fn remove_namespace_labels(&self, namespace: &str) {
        self.inner.write().await.namespace_labels.remove(namespace);
    }

    /// Bulk-replace all store contents atomically (used for initial population).
    ///
    /// The `service_ref_index` field of the supplied [`StoreInner`] is
    /// **ignored** — the index is always rebuilt from the route maps to
    /// ensure consistency regardless of what the caller supplied.
    pub async fn replace_all(&self, mut new_inner: StoreInner) {
        new_inner.rebuild_service_index();
        *self.inner.write().await = new_inner;
    }

    /// Ingest a [`GatewayState`] snapshot into the store atomically.
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
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crds::{
        BackendRef, Gateway, GatewaySpec, HTTPBackendRef, HTTPRouteRule, HTTPRouteSpec, Listener,
        ParentReference, ProtocolType, TCPRoute, TLSRoute,
    };
    use crate::reconcilers::attachment_planner::{AttachmentPlanInput, AttachmentPlanner};
    use crate::reconcilers::contracts::Planner;
    use crate::reconcilers::runtime_plan::{
        ControllerConfig, GatewayRuntimePlanner, ObservedRuntimeState, RuntimePlanInput,
    };
    use kube::core::ObjectMeta;

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn make_parent_ref(gateway_ns: &str, gateway_name: &str) -> ParentReference {
        ParentReference {
            group: "gateway.networking.k8s.io".to_string(),
            kind: "Gateway".to_string(),
            namespace: Some(gateway_ns.to_string()),
            name: gateway_name.to_string(),
            section_name: None,
            port: None,
        }
    }

    fn make_gateway(name: &str, namespace: &str) -> Gateway {
        Gateway {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some(namespace.to_string()),
                uid: Some(format!("{namespace}-{name}-uid")),
                generation: Some(7),
                ..Default::default()
            },
            spec: GatewaySpec {
                gateway_class_name: "wicket".to_string(),
                listeners: vec![Listener {
                    name: "http".to_string(),
                    hostname: None,
                    port: 80,
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

    fn ready_gateway_state(name: &str, namespace: &str) -> GatewayState {
        let mut state = GatewayState::default();
        let gateway = make_gateway(name, namespace);
        state
            .gateways
            .insert(GatewayState::key(namespace, name), gateway);
        state
    }

    async fn mark_all_resource_lists_listed(store: &SharedStore) {
        for &rc in ResourceClass::ALL {
            store.mark_listed(rc).await;
        }
    }

    fn all_ready_phase() -> StorePhase {
        StorePhase::Ready
    }

    fn make_gateway_class(name: &str) -> GatewayClass {
        use crate::crds::GatewayClassSpec;

        GatewayClass {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                ..Default::default()
            },
            spec: GatewayClassSpec {
                controller_name: "wicket.io/gateway-controller".to_string(),
                parameters_ref: None,
                description: None,
            },
            status: None,
        }
    }

    fn make_reference_grant(namespace: &str, name: &str) -> ReferenceGrant {
        use crate::crds::{ReferenceGrantFrom, ReferenceGrantSpec, ReferenceGrantTo};

        ReferenceGrant {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some(namespace.to_string()),
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
        }
    }

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

    #[tokio::test]
    async fn store_readiness_requires_all_resource_classes() {
        for &excluded in ResourceClass::ALL {
            let store = SharedStore::new();
            for &rc in ResourceClass::ALL {
                if rc != excluded {
                    store.mark_listed(rc).await;
                }
            }
            assert!(
                !store.is_ready().await,
                "Store should NOT be ready when {:?} is missing",
                excluded
            );
        }

        let store = SharedStore::new();
        for &rc in ResourceClass::ALL {
            store.mark_listed(rc).await;
        }
        assert!(store.is_ready().await);
    }

    #[tokio::test]
    async fn mark_listed_is_idempotent() {
        let store = SharedStore::new();
        for &rc in ResourceClass::ALL {
            store.mark_listed(rc).await;
        }
        assert!(store.is_ready().await);

        for &rc in ResourceClass::ALL {
            store.mark_listed(rc).await;
        }
        assert!(store.is_ready().await);
    }

    #[tokio::test]
    async fn empty_initial_list_still_marks_listed() {
        let store = SharedStore::new();
        for &rc in ResourceClass::ALL {
            store.mark_listed(rc).await;
        }

        assert!(store.is_ready().await);
        assert!(matches!(
            store.planner_snapshot().await,
            SnapshotResult::Ready(_)
        ));
    }

    #[tokio::test]
    async fn upsert_gateway_class_does_not_advance_readiness() {
        let store = SharedStore::new();
        store
            .upsert_gateway_class("wicket".to_string(), make_gateway_class("wicket"))
            .await;

        assert!(
            !store.is_ready().await,
            "upsert alone should not make store ready"
        );
    }

    #[tokio::test]
    async fn upsert_reference_grant_does_not_advance_readiness() {
        let store = SharedStore::new();
        store
            .upsert_reference_grant(
                "default/test".to_string(),
                make_reference_grant("default", "test"),
            )
            .await;

        assert!(
            !store.is_ready().await,
            "upsert alone should not make store ready"
        );
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
    async fn test_ingest_gateway_state_does_not_mark_fully_ready() {
        // ingest_gateway_state updates cached objects only; readiness comes
        // from the explicit initial-list signals.
        let store = SharedStore::new();
        assert!(!store.is_ready().await);

        let state = GatewayState::default();
        store.ingest_gateway_state(state).await;

        assert!(
            !store.is_ready().await,
            "store must not be ready until all resource classes are populated"
        );
    }

    #[tokio::test]
    async fn test_ingest_gateway_state_ready_after_all_classes_populated() {
        let store = SharedStore::new();
        store.ingest_gateway_state(GatewayState::default()).await;
        mark_all_resource_lists_listed(&store).await;
        assert!(store.is_ready().await);
    }

    #[tokio::test]
    async fn test_ingest_gateway_state_populates_routes() {
        let store = SharedStore::new();
        let mut state = GatewayState::default();

        let route = make_http_route("r", "default", None, "svc");
        state.http_routes.insert("default/r".to_string(), route);

        store.ingest_gateway_state(state).await;
        store.mark_listed(ResourceClass::Gateways).await;

        // snapshot() only requires the Gateway list, not full readiness.
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
        mark_all_resource_lists_listed(&store).await;

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
        store.mark_listed(ResourceClass::Gateways).await;

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
        store.mark_listed(ResourceClass::Gateways).await;

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
        use crate::crds::GatewayClassSpec;
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
        inner.phase = all_ready_phase();
        store.replace_all(inner).await;

        assert!(store.is_ready().await);
    }

    #[tokio::test]
    async fn test_replace_all_rebuilds_index() {
        let store = SharedStore::new();

        let mut inner = StoreInner::default();
        inner.phase = all_ready_phase();
        let route = make_http_route("r", "default", None, "bulk-svc");
        inner.http_routes.insert("default/r".to_string(), route);
        // Intentionally do NOT call rebuild_service_index() here --
        // replace_all() must rebuild it regardless.
        store.replace_all(inner).await;

        assert_eq!(
            store.is_service_referenced("default", "bulk-svc").await,
            Some(true)
        );
    }

    #[tokio::test]
    async fn test_replace_all_ignores_caller_supplied_index() {
        // Caller supplies a stale/wrong index; replace_all must rebuild it.
        let store = SharedStore::new();

        let mut inner = StoreInner::default();
        inner.phase = all_ready_phase();
        let route = make_http_route("r", "default", None, "real-svc");
        inner.http_routes.insert("default/r".to_string(), route);
        // Inject a stale index that claims "fake-svc" is referenced.
        inner
            .service_ref_index
            .insert("default/fake-svc".to_string());
        store.replace_all(inner).await;

        // "real-svc" must be in the index (rebuilt from routes).
        assert_eq!(
            store.is_service_referenced("default", "real-svc").await,
            Some(true)
        );
        // "fake-svc" must NOT be in the index (stale entry discarded).
        assert_eq!(
            store.is_service_referenced("default", "fake-svc").await,
            Some(false)
        );
    }

    // ── mark_listed empty-list readiness ──────────────────────────────────────

    /// An empty GatewayClass list is a valid observation; the store must become
    /// ready once every other resource class is also listed, even if no items were
    /// ever upserted.
    #[tokio::test]
    async fn test_mark_listed_gateway_classes_enables_readiness_with_empty_list() {
        let store = SharedStore::new();
        store.mark_listed(ResourceClass::Gateways).await;
        store.mark_listed(ResourceClass::HttpRoutes).await;
        store.mark_listed(ResourceClass::TcpRoutes).await;
        store.mark_listed(ResourceClass::TlsRoutes).await;
        store.mark_listed(ResourceClass::Services).await;
        store.mark_listed(ResourceClass::Endpoints).await;
        store.mark_listed(ResourceClass::Secrets).await;
        store.mark_listed(ResourceClass::ReferenceGrants).await;
        // Not yet ready -- GatewayClasses has not been listed.
        assert!(!store.is_ready().await);

        store.mark_listed(ResourceClass::GatewayClasses).await;
        assert!(store.is_ready().await);
    }

    /// An empty ReferenceGrant list is a valid observation; the store must
    /// become ready once every other resource class is also listed, even if no
    /// grants exist.
    #[tokio::test]
    async fn test_mark_listed_reference_grants_enables_readiness_with_empty_list() {
        let store = SharedStore::new();
        store.mark_listed(ResourceClass::GatewayClasses).await;
        store.mark_listed(ResourceClass::Gateways).await;
        store.mark_listed(ResourceClass::HttpRoutes).await;
        store.mark_listed(ResourceClass::TcpRoutes).await;
        store.mark_listed(ResourceClass::TlsRoutes).await;
        store.mark_listed(ResourceClass::Services).await;
        store.mark_listed(ResourceClass::Endpoints).await;
        store.mark_listed(ResourceClass::Secrets).await;
        // Not yet ready -- ReferenceGrants has not been listed.
        assert!(!store.is_ready().await);

        store.mark_listed(ResourceClass::ReferenceGrants).await;
        assert!(store.is_ready().await);
    }

    /// planner_snapshot must return Ready after all mark_* calls, even
    /// with no actual resources in the store.
    #[tokio::test]
    async fn test_planner_snapshot_ready_after_all_mark_calls_empty_store() {
        let store = SharedStore::new();
        mark_all_resource_lists_listed(&store).await;

        assert!(matches!(
            store.planner_snapshot().await,
            SnapshotResult::Ready(_)
        ));
    }

    // ── rebuild_service_index: Service-kind filtering ─────────────────────────

    /// Backend refs with a non-Service kind must NOT be indexed.
    #[tokio::test]
    async fn test_service_index_ignores_non_service_kind_in_tcp_route() {
        use crate::crds::{BackendRef, TCPRouteRule, TCPRouteSpec};

        let store = SharedStore::new();

        // TCPRoute with a backend ref whose kind is NOT "Service".
        let route = TCPRoute {
            metadata: ObjectMeta {
                name: Some("r".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            },
            spec: TCPRouteSpec {
                parent_refs: vec![],
                rules: vec![TCPRouteRule {
                    name: None,
                    backend_refs: vec![BackendRef {
                        group: "example.io".to_string(),
                        kind: "CustomBackend".to_string(),
                        name: "custom-backend".to_string(),
                        namespace: None,
                        port: Some(9000),
                        weight: 1,
                    }],
                }],
            },
            status: None,
        };
        store.upsert_tcp_route("default/r".to_string(), route).await;
        store.mark_ready().await;

        // "custom-backend" must NOT appear in the service index.
        assert_eq!(
            store
                .is_service_referenced("default", "custom-backend")
                .await,
            Some(false)
        );
    }

    /// Backend refs with a non-Service kind must NOT be indexed in TLS routes.
    #[tokio::test]
    async fn test_service_index_ignores_non_service_kind_in_tls_route() {
        use crate::crds::{BackendRef, TLSRouteRule, TLSRouteSpec};

        let store = SharedStore::new();

        let route = TLSRoute {
            metadata: ObjectMeta {
                name: Some("r".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            },
            spec: TLSRouteSpec {
                parent_refs: vec![],
                hostnames: vec![],
                rules: vec![TLSRouteRule {
                    name: None,
                    backend_refs: vec![BackendRef {
                        group: "example.io".to_string(),
                        kind: "CustomBackend".to_string(),
                        name: "custom-backend".to_string(),
                        namespace: None,
                        port: Some(9000),
                        weight: 1,
                    }],
                }],
            },
            status: None,
        };
        store.upsert_tls_route("default/r".to_string(), route).await;
        store.mark_ready().await;

        assert_eq!(
            store
                .is_service_referenced("default", "custom-backend")
                .await,
            Some(false)
        );
    }

    /// Backend refs with kind "Service" (explicit) ARE indexed.
    #[tokio::test]
    async fn test_service_index_includes_explicit_service_kind_in_tcp_route() {
        use crate::crds::{BackendRef, TCPRouteRule, TCPRouteSpec};

        let store = SharedStore::new();

        let route = TCPRoute {
            metadata: ObjectMeta {
                name: Some("r".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            },
            spec: TCPRouteSpec {
                parent_refs: vec![],
                rules: vec![TCPRouteRule {
                    name: None,
                    backend_refs: vec![BackendRef {
                        group: "".to_string(),
                        kind: "Service".to_string(),
                        name: "my-svc".to_string(),
                        namespace: None,
                        port: Some(5432),
                        weight: 1,
                    }],
                }],
            },
            status: None,
        };
        store.upsert_tcp_route("default/r".to_string(), route).await;
        store.mark_ready().await;

        assert_eq!(
            store.is_service_referenced("default", "my-svc").await,
            Some(true)
        );
    }

    /// Backend refs with an empty kind (Gateway API default = Service) ARE indexed.
    #[tokio::test]
    async fn test_service_index_includes_empty_kind_in_tls_route() {
        use crate::crds::{BackendRef, TLSRouteRule, TLSRouteSpec};

        let store = SharedStore::new();

        let route = TLSRoute {
            metadata: ObjectMeta {
                name: Some("r".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            },
            spec: TLSRouteSpec {
                parent_refs: vec![],
                hostnames: vec![],
                rules: vec![TLSRouteRule {
                    name: None,
                    backend_refs: vec![BackendRef {
                        group: "".to_string(),
                        kind: "".to_string(), // empty = Service per spec
                        name: "implicit-svc".to_string(),
                        namespace: None,
                        port: Some(443),
                        weight: 1,
                    }],
                }],
            },
            status: None,
        };
        store.upsert_tls_route("default/r".to_string(), route).await;
        store.mark_ready().await;

        assert_eq!(
            store.is_service_referenced("default", "implicit-svc").await,
            Some(true)
        );
    }

    // ── Service index: group+kind both checked (Issue 2 fix) ──────────────────

    /// A backend with kind="Service" but a non-core group must NOT be indexed.
    /// Previously only `kind` was checked; this test catches the regression.
    #[tokio::test]
    async fn test_service_index_excludes_non_core_group_with_service_kind_in_http_route() {
        let store = SharedStore::new();

        let route = HTTPRoute {
            metadata: ObjectMeta {
                name: Some("r".to_string()),
                namespace: Some("default".to_string()),
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
                            // Non-core group with kind "Service" -- must NOT be indexed.
                            group: "custom.example.com".to_string(),
                            kind: "Service".to_string(),
                            name: "custom-svc".to_string(),
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
        store
            .upsert_http_route("default/r".to_string(), route)
            .await;
        store.mark_ready().await;

        assert_eq!(
            store.is_service_referenced("default", "custom-svc").await,
            Some(false),
            "non-core group backend with kind=Service must not be indexed"
        );
    }

    /// A backend with kind="Service" but a non-core group must NOT be indexed
    /// in TCPRoutes either.
    #[tokio::test]
    async fn test_service_index_excludes_non_core_group_with_service_kind_in_tcp_route() {
        use crate::crds::{TCPRouteRule, TCPRouteSpec};

        let store = SharedStore::new();

        let route = TCPRoute {
            metadata: ObjectMeta {
                name: Some("r".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            },
            spec: TCPRouteSpec {
                parent_refs: vec![],
                rules: vec![TCPRouteRule {
                    name: None,
                    backend_refs: vec![BackendRef {
                        group: "custom.example.com".to_string(),
                        kind: "Service".to_string(),
                        name: "custom-svc".to_string(),
                        namespace: None,
                        port: Some(9000),
                        weight: 1,
                    }],
                }],
            },
            status: None,
        };
        store.upsert_tcp_route("default/r".to_string(), route).await;
        store.mark_ready().await;

        assert_eq!(
            store.is_service_referenced("default", "custom-svc").await,
            Some(false),
            "non-core group backend with kind=Service must not be indexed in TCPRoute"
        );
    }

    /// A backend with kind="Service" but a non-core group must NOT be indexed
    /// in TLSRoutes either.
    #[tokio::test]
    async fn test_service_index_excludes_non_core_group_with_service_kind_in_tls_route() {
        use crate::crds::{TLSRouteRule, TLSRouteSpec};

        let store = SharedStore::new();

        let route = TLSRoute {
            metadata: ObjectMeta {
                name: Some("r".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            },
            spec: TLSRouteSpec {
                parent_refs: vec![],
                hostnames: vec![],
                rules: vec![TLSRouteRule {
                    name: None,
                    backend_refs: vec![BackendRef {
                        group: "custom.example.com".to_string(),
                        kind: "Service".to_string(),
                        name: "custom-svc".to_string(),
                        namespace: None,
                        port: Some(443),
                        weight: 1,
                    }],
                }],
            },
            status: None,
        };
        store.upsert_tls_route("default/r".to_string(), route).await;
        store.mark_ready().await;

        assert_eq!(
            store.is_service_referenced("default", "custom-svc").await,
            Some(false),
            "non-core group backend with kind=Service must not be indexed in TLSRoute"
        );
    }

    /// Core-group Service (group="", kind="Service") IS still indexed.
    #[tokio::test]
    async fn test_service_index_includes_core_group_service_kind() {
        let store = SharedStore::new();
        let route = make_http_route("r", "default", None, "core-svc");
        store
            .upsert_http_route("default/r".to_string(), route)
            .await;
        store.mark_ready().await;

        assert_eq!(
            store.is_service_referenced("default", "core-svc").await,
            Some(true),
            "core-group Service must still be indexed"
        );
    }

    // ── SnapshotResult ────────────────────────────────────────────────────────

    #[test]
    fn snapshot_result_not_ready_is_not_ready() {
        let r: SnapshotResult<u32> = SnapshotResult::NotReady;
        assert!(!r.is_ready());
        assert!(r.into_option().is_none());
    }

    #[test]
    fn snapshot_result_ready_is_ready() {
        let r = SnapshotResult::Ready(42u32);
        assert!(r.is_ready());
        assert_eq!(r.into_option(), Some(42));
    }

    // ── planner_snapshot readiness ────────────────────────────────────────────

    #[tokio::test]
    async fn test_planner_snapshot_not_ready_when_store_unready() {
        let store = SharedStore::new();
        assert!(matches!(
            store.planner_snapshot().await,
            SnapshotResult::NotReady
        ));
    }

    #[tokio::test]
    async fn test_planner_snapshot_ready_after_mark_ready() {
        let store = SharedStore::new();
        store.mark_ready().await;
        assert!(matches!(
            store.planner_snapshot().await,
            SnapshotResult::Ready(_)
        ));
    }

    // ── PlannerSnapshot completeness ──────────────────────────────────────────

    #[tokio::test]
    async fn test_planner_snapshot_includes_gateway_classes() {
        use crate::crds::GatewayClassSpec;
        let store = SharedStore::new();

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
        store.mark_ready().await;

        let snap = match store.planner_snapshot().await {
            SnapshotResult::Ready(s) => s,
            SnapshotResult::NotReady => panic!("expected ready"),
        };
        assert!(snap.gateway_classes.contains_key("wicket"));
    }

    #[tokio::test]
    async fn test_planner_snapshot_includes_reference_grants() {
        use crate::crds::{ReferenceGrantFrom, ReferenceGrantSpec, ReferenceGrantTo};
        let store = SharedStore::new();

        let grant = ReferenceGrant {
            metadata: ObjectMeta {
                name: Some("allow-secret".to_string()),
                namespace: Some("tls-ns".to_string()),
                ..Default::default()
            },
            spec: ReferenceGrantSpec {
                from: vec![ReferenceGrantFrom {
                    group: "gateway.networking.k8s.io".to_string(),
                    kind: "Gateway".to_string(),
                    namespace: "gw-ns".to_string(),
                }],
                to: vec![ReferenceGrantTo {
                    group: "".to_string(),
                    kind: "Secret".to_string(),
                    name: None,
                }],
            },
        };
        store
            .upsert_reference_grant("tls-ns/allow-secret".to_string(), grant)
            .await;
        store.mark_ready().await;

        let snap = match store.planner_snapshot().await {
            SnapshotResult::Ready(s) => s,
            SnapshotResult::NotReady => panic!("expected ready"),
        };
        assert!(snap.reference_grants.contains_key("tls-ns/allow-secret"));
    }

    #[tokio::test]
    async fn test_planner_snapshot_includes_service_ref_index() {
        let store = SharedStore::new();
        let route = make_http_route("r", "default", None, "indexed-svc");
        store
            .upsert_http_route("default/r".to_string(), route)
            .await;
        store.mark_ready().await;

        let snap = match store.planner_snapshot().await {
            SnapshotResult::Ready(s) => s,
            SnapshotResult::NotReady => panic!("expected ready"),
        };
        assert!(snap.is_service_referenced("default", "indexed-svc"));
        assert!(!snap.is_service_referenced("default", "other-svc"));
    }

    // ── PlannerSnapshot targeted accessors ────────────────────────────────────

    #[tokio::test]
    async fn test_planner_snapshot_gateway_accessor() {
        use crate::crds::{GatewaySpec, Listener, ProtocolType};
        let store = SharedStore::new();

        let gw = Gateway {
            metadata: ObjectMeta {
                name: Some("my-gw".to_string()),
                namespace: Some("prod".to_string()),
                ..Default::default()
            },
            spec: GatewaySpec {
                gateway_class_name: "wicket".to_string(),
                listeners: vec![Listener {
                    name: "http".to_string(),
                    hostname: None,
                    port: 80,
                    protocol: ProtocolType::HTTP,
                    tls: None,
                    allowed_routes: None,
                }],
                addresses: vec![],
                infrastructure: None,
            },
            status: None,
        };
        store.upsert_gateway("prod/my-gw".to_string(), gw).await;
        store.mark_ready().await;

        let snap = match store.planner_snapshot().await {
            SnapshotResult::Ready(s) => s,
            SnapshotResult::NotReady => panic!("expected ready"),
        };

        assert!(snap.gateway("prod", "my-gw").is_some());
        assert!(snap.gateway("prod", "missing").is_none());
        assert!(snap.gateway("other-ns", "my-gw").is_none());
    }

    #[tokio::test]
    async fn test_planner_snapshot_tls_secret_accessor() {
        let store = SharedStore::new();
        store
            .upsert_tls_secret(
                "default/my-cert".to_string(),
                "/tls/cert.crt".to_string(),
                "/tls/cert.key".to_string(),
            )
            .await;
        store.mark_ready().await;

        let snap = match store.planner_snapshot().await {
            SnapshotResult::Ready(s) => s,
            SnapshotResult::NotReady => panic!("expected ready"),
        };

        let paths = snap
            .tls_secret("default", "my-cert")
            .expect("should be present");
        assert_eq!(paths.0, "/tls/cert.crt");
        assert_eq!(paths.1, "/tls/cert.key");
        assert!(snap.tls_secret("default", "missing").is_none());
    }

    #[tokio::test]
    async fn test_planner_snapshot_reference_grants_in_namespace() {
        use crate::crds::{ReferenceGrantFrom, ReferenceGrantSpec, ReferenceGrantTo};
        let store = SharedStore::new();

        // Grant in tls-ns (target namespace)
        let grant_a = ReferenceGrant {
            metadata: ObjectMeta {
                name: Some("grant-a".to_string()),
                namespace: Some("tls-ns".to_string()),
                ..Default::default()
            },
            spec: ReferenceGrantSpec {
                from: vec![ReferenceGrantFrom {
                    group: "gateway.networking.k8s.io".to_string(),
                    kind: "Gateway".to_string(),
                    namespace: "gw-ns".to_string(),
                }],
                to: vec![ReferenceGrantTo {
                    group: "".to_string(),
                    kind: "Secret".to_string(),
                    name: None,
                }],
            },
        };
        // Grant in other-ns
        let grant_b = ReferenceGrant {
            metadata: ObjectMeta {
                name: Some("grant-b".to_string()),
                namespace: Some("other-ns".to_string()),
                ..Default::default()
            },
            spec: ReferenceGrantSpec {
                from: vec![ReferenceGrantFrom {
                    group: "gateway.networking.k8s.io".to_string(),
                    kind: "Gateway".to_string(),
                    namespace: "gw-ns".to_string(),
                }],
                to: vec![ReferenceGrantTo {
                    group: "".to_string(),
                    kind: "Secret".to_string(),
                    name: None,
                }],
            },
        };
        store
            .upsert_reference_grant("tls-ns/grant-a".to_string(), grant_a)
            .await;
        store
            .upsert_reference_grant("other-ns/grant-b".to_string(), grant_b)
            .await;
        store.mark_ready().await;

        let snap = match store.planner_snapshot().await {
            SnapshotResult::Ready(s) => s,
            SnapshotResult::NotReady => panic!("expected ready"),
        };

        let tls_grants = snap.reference_grants_in_namespace("tls-ns");
        assert_eq!(tls_grants.len(), 1);
        assert_eq!(tls_grants[0].metadata.name.as_deref(), Some("grant-a"));

        let other_grants = snap.reference_grants_in_namespace("other-ns");
        assert_eq!(other_grants.len(), 1);

        let empty_grants = snap.reference_grants_in_namespace("no-ns");
        assert!(empty_grants.is_empty());
    }

    // ── routes_for_gateway accessors ──────────────────────────────────────────

    fn make_tcp_route_with_parent(
        name: &str,
        ns: &str,
        backend: &str,
        parent_ns: &str,
        parent_name: &str,
    ) -> TCPRoute {
        use crate::crds::{TCPRouteRule, TCPRouteSpec};
        TCPRoute {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some(ns.to_string()),
                ..Default::default()
            },
            spec: TCPRouteSpec {
                parent_refs: vec![make_parent_ref(parent_ns, parent_name)],
                rules: vec![TCPRouteRule {
                    name: None,
                    backend_refs: vec![BackendRef {
                        group: "".to_string(),
                        kind: "Service".to_string(),
                        name: backend.to_string(),
                        namespace: None,
                        port: Some(5432),
                        weight: 1,
                    }],
                }],
            },
            status: None,
        }
    }

    fn make_tls_route_with_parent(
        name: &str,
        ns: &str,
        backend: &str,
        parent_ns: &str,
        parent_name: &str,
    ) -> TLSRoute {
        use crate::crds::{TLSRouteRule, TLSRouteSpec};
        TLSRoute {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some(ns.to_string()),
                ..Default::default()
            },
            spec: TLSRouteSpec {
                parent_refs: vec![make_parent_ref(parent_ns, parent_name)],
                hostnames: vec![],
                rules: vec![TLSRouteRule {
                    name: None,
                    backend_refs: vec![BackendRef {
                        group: "".to_string(),
                        kind: "Service".to_string(),
                        name: backend.to_string(),
                        namespace: None,
                        port: Some(443),
                        weight: 1,
                    }],
                }],
            },
            status: None,
        }
    }

    fn make_http_route_with_parent(
        name: &str,
        ns: &str,
        backend: &str,
        parent_ns: &str,
        parent_name: &str,
    ) -> HTTPRoute {
        HTTPRoute {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some(ns.to_string()),
                ..Default::default()
            },
            spec: HTTPRouteSpec {
                parent_refs: vec![make_parent_ref(parent_ns, parent_name)],
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
        }
    }

    #[tokio::test]
    async fn test_http_routes_for_gateway_returns_attached_routes() {
        let store = SharedStore::new();

        // Route attached to prod/my-gw
        let r1 = make_http_route_with_parent("r1", "prod", "svc-a", "prod", "my-gw");
        // Route attached to prod/other-gw
        let r2 = make_http_route_with_parent("r2", "prod", "svc-b", "prod", "other-gw");
        // Route attached to my-gw but in a different namespace
        let r3 = make_http_route_with_parent("r3", "staging", "svc-c", "prod", "my-gw");

        store.upsert_http_route("prod/r1".to_string(), r1).await;
        store.upsert_http_route("prod/r2".to_string(), r2).await;
        store.upsert_http_route("staging/r3".to_string(), r3).await;
        store.mark_ready().await;

        let snap = match store.planner_snapshot().await {
            SnapshotResult::Ready(s) => s,
            SnapshotResult::NotReady => panic!("expected ready"),
        };

        let routes = snap.http_routes_for_gateway("prod", "my-gw");
        assert_eq!(
            routes.len(),
            2,
            "r1 and r3 should be attached to prod/my-gw"
        );

        let names: Vec<_> = routes
            .iter()
            .map(|r| r.metadata.name.as_deref().unwrap_or(""))
            .collect();
        assert!(names.contains(&"r1"));
        assert!(names.contains(&"r3"));
        assert!(!names.contains(&"r2"));
    }

    #[tokio::test]
    async fn test_http_routes_for_gateway_empty_when_no_match() {
        let store = SharedStore::new();
        let r = make_http_route_with_parent("r", "default", "svc", "default", "other-gw");
        store.upsert_http_route("default/r".to_string(), r).await;
        store.mark_ready().await;

        let snap = match store.planner_snapshot().await {
            SnapshotResult::Ready(s) => s,
            SnapshotResult::NotReady => panic!("expected ready"),
        };

        let routes = snap.http_routes_for_gateway("default", "my-gw");
        assert!(routes.is_empty());
    }

    #[tokio::test]
    async fn test_http_routes_for_gateway_namespace_defaults_to_route_ns() {
        // A parentRef without an explicit namespace should default to the route's namespace.
        let store = SharedStore::new();

        let route = HTTPRoute {
            metadata: ObjectMeta {
                name: Some("r".to_string()),
                namespace: Some("prod".to_string()),
                ..Default::default()
            },
            spec: HTTPRouteSpec {
                parent_refs: vec![ParentReference {
                    group: "gateway.networking.k8s.io".to_string(),
                    kind: "Gateway".to_string(),
                    namespace: None, // omitted -- defaults to route ns "prod"
                    name: "my-gw".to_string(),
                    section_name: None,
                    port: None,
                }],
                hostnames: vec![],
                rules: vec![],
            },
            status: None,
        };
        store.upsert_http_route("prod/r".to_string(), route).await;
        store.mark_ready().await;

        let snap = match store.planner_snapshot().await {
            SnapshotResult::Ready(s) => s,
            SnapshotResult::NotReady => panic!("expected ready"),
        };

        // Should match prod/my-gw (namespace defaulted to route ns)
        assert_eq!(snap.http_routes_for_gateway("prod", "my-gw").len(), 1);
        // Should NOT match staging/my-gw
        assert!(snap.http_routes_for_gateway("staging", "my-gw").is_empty());
    }

    // ── TCP/TLS route attachment helpers ─────────────────────────────────────

    #[tokio::test]
    async fn test_tcp_routes_for_gateway_returns_attached_routes() {
        let store = SharedStore::new();

        // Route attached to prod/my-gw
        let r1 = make_tcp_route_with_parent("t1", "prod", "db-a", "prod", "my-gw");
        // Route attached to prod/other-gw
        let r2 = make_tcp_route_with_parent("t2", "prod", "db-b", "prod", "other-gw");
        // Route attached to my-gw from a different namespace
        let r3 = make_tcp_route_with_parent("t3", "staging", "db-c", "prod", "my-gw");

        store.upsert_tcp_route("prod/t1".to_string(), r1).await;
        store.upsert_tcp_route("prod/t2".to_string(), r2).await;
        store.upsert_tcp_route("staging/t3".to_string(), r3).await;
        store.mark_ready().await;

        let snap = match store.planner_snapshot().await {
            SnapshotResult::Ready(s) => s,
            SnapshotResult::NotReady => panic!("expected ready"),
        };

        let routes = snap.tcp_routes_for_gateway("prod", "my-gw");
        assert_eq!(
            routes.len(),
            2,
            "t1 and t3 should be attached to prod/my-gw"
        );

        let names: Vec<_> = routes
            .iter()
            .map(|r| r.metadata.name.as_deref().unwrap_or(""))
            .collect();
        assert!(names.contains(&"t1"));
        assert!(names.contains(&"t3"));
        assert!(!names.contains(&"t2"));
    }

    #[tokio::test]
    async fn test_tcp_routes_for_gateway_empty_when_no_match() {
        let store = SharedStore::new();
        let r = make_tcp_route_with_parent("t", "default", "db", "default", "other-gw");
        store.upsert_tcp_route("default/t".to_string(), r).await;
        store.mark_ready().await;

        let snap = match store.planner_snapshot().await {
            SnapshotResult::Ready(s) => s,
            SnapshotResult::NotReady => panic!("expected ready"),
        };

        assert!(snap.tcp_routes_for_gateway("default", "my-gw").is_empty());
    }

    #[tokio::test]
    async fn test_tcp_routes_for_gateway_namespace_defaults_to_route_ns() {
        use crate::crds::TCPRouteSpec;
        let store = SharedStore::new();

        let route = TCPRoute {
            metadata: ObjectMeta {
                name: Some("t".to_string()),
                namespace: Some("prod".to_string()),
                ..Default::default()
            },
            spec: TCPRouteSpec {
                parent_refs: vec![ParentReference {
                    group: "gateway.networking.k8s.io".to_string(),
                    kind: "Gateway".to_string(),
                    namespace: None, // defaults to route ns "prod"
                    name: "my-gw".to_string(),
                    section_name: None,
                    port: None,
                }],
                rules: vec![],
            },
            status: None,
        };
        store.upsert_tcp_route("prod/t".to_string(), route).await;
        store.mark_ready().await;

        let snap = match store.planner_snapshot().await {
            SnapshotResult::Ready(s) => s,
            SnapshotResult::NotReady => panic!("expected ready"),
        };

        assert_eq!(snap.tcp_routes_for_gateway("prod", "my-gw").len(), 1);
        assert!(snap.tcp_routes_for_gateway("staging", "my-gw").is_empty());
    }

    #[tokio::test]
    async fn test_tls_routes_for_gateway_returns_attached_routes() {
        let store = SharedStore::new();

        let r1 = make_tls_route_with_parent("s1", "prod", "svc-a", "prod", "my-gw");
        let r2 = make_tls_route_with_parent("s2", "prod", "svc-b", "prod", "other-gw");
        let r3 = make_tls_route_with_parent("s3", "staging", "svc-c", "prod", "my-gw");

        store.upsert_tls_route("prod/s1".to_string(), r1).await;
        store.upsert_tls_route("prod/s2".to_string(), r2).await;
        store.upsert_tls_route("staging/s3".to_string(), r3).await;
        store.mark_ready().await;

        let snap = match store.planner_snapshot().await {
            SnapshotResult::Ready(s) => s,
            SnapshotResult::NotReady => panic!("expected ready"),
        };

        let routes = snap.tls_routes_for_gateway("prod", "my-gw");
        assert_eq!(
            routes.len(),
            2,
            "s1 and s3 should be attached to prod/my-gw"
        );

        let names: Vec<_> = routes
            .iter()
            .map(|r| r.metadata.name.as_deref().unwrap_or(""))
            .collect();
        assert!(names.contains(&"s1"));
        assert!(names.contains(&"s3"));
        assert!(!names.contains(&"s2"));
    }

    #[tokio::test]
    async fn test_tls_routes_for_gateway_empty_when_no_match() {
        let store = SharedStore::new();
        let r = make_tls_route_with_parent("s", "default", "svc", "default", "other-gw");
        store.upsert_tls_route("default/s".to_string(), r).await;
        store.mark_ready().await;

        let snap = match store.planner_snapshot().await {
            SnapshotResult::Ready(s) => s,
            SnapshotResult::NotReady => panic!("expected ready"),
        };

        assert!(snap.tls_routes_for_gateway("default", "my-gw").is_empty());
    }

    #[tokio::test]
    async fn test_tls_routes_for_gateway_namespace_defaults_to_route_ns() {
        use crate::crds::TLSRouteSpec;
        let store = SharedStore::new();

        let route = TLSRoute {
            metadata: ObjectMeta {
                name: Some("s".to_string()),
                namespace: Some("prod".to_string()),
                ..Default::default()
            },
            spec: TLSRouteSpec {
                parent_refs: vec![ParentReference {
                    group: "gateway.networking.k8s.io".to_string(),
                    kind: "Gateway".to_string(),
                    namespace: None, // defaults to route ns "prod"
                    name: "my-gw".to_string(),
                    section_name: None,
                    port: None,
                }],
                hostnames: vec![],
                rules: vec![],
            },
            status: None,
        };
        store.upsert_tls_route("prod/s".to_string(), route).await;
        store.mark_ready().await;

        let snap = match store.planner_snapshot().await {
            SnapshotResult::Ready(s) => s,
            SnapshotResult::NotReady => panic!("expected ready"),
        };

        assert_eq!(snap.tls_routes_for_gateway("prod", "my-gw").len(), 1);
        assert!(snap.tls_routes_for_gateway("staging", "my-gw").is_empty());
    }

    // ── Deterministic sort order ──────────────────────────────────────────────

    #[tokio::test]
    async fn test_http_routes_for_gateway_sorted_by_ns_name() {
        let store = SharedStore::new();

        // Insert in reverse alphabetical order to expose any HashMap ordering.
        let rc = make_http_route_with_parent("rc", "prod", "svc", "prod", "my-gw");
        let ra = make_http_route_with_parent("ra", "prod", "svc", "prod", "my-gw");
        let rb = make_http_route_with_parent("rb", "prod", "svc", "prod", "my-gw");

        store.upsert_http_route("prod/rc".to_string(), rc).await;
        store.upsert_http_route("prod/ra".to_string(), ra).await;
        store.upsert_http_route("prod/rb".to_string(), rb).await;
        store.mark_ready().await;

        let snap = match store.planner_snapshot().await {
            SnapshotResult::Ready(s) => s,
            SnapshotResult::NotReady => panic!("expected ready"),
        };

        let names: Vec<_> = snap
            .http_routes_for_gateway("prod", "my-gw")
            .iter()
            .map(|r| r.metadata.name.as_deref().unwrap_or(""))
            .collect();
        assert_eq!(
            names,
            vec!["ra", "rb", "rc"],
            "routes must be sorted by name"
        );
    }

    #[tokio::test]
    async fn test_tcp_routes_for_gateway_sorted_by_ns_name() {
        let store = SharedStore::new();

        let tc = make_tcp_route_with_parent("tc", "prod", "db", "prod", "my-gw");
        let ta = make_tcp_route_with_parent("ta", "prod", "db", "prod", "my-gw");
        let tb = make_tcp_route_with_parent("tb", "prod", "db", "prod", "my-gw");

        store.upsert_tcp_route("prod/tc".to_string(), tc).await;
        store.upsert_tcp_route("prod/ta".to_string(), ta).await;
        store.upsert_tcp_route("prod/tb".to_string(), tb).await;
        store.mark_ready().await;

        let snap = match store.planner_snapshot().await {
            SnapshotResult::Ready(s) => s,
            SnapshotResult::NotReady => panic!("expected ready"),
        };

        let names: Vec<_> = snap
            .tcp_routes_for_gateway("prod", "my-gw")
            .iter()
            .map(|r| r.metadata.name.as_deref().unwrap_or(""))
            .collect();
        assert_eq!(
            names,
            vec!["ta", "tb", "tc"],
            "routes must be sorted by name"
        );
    }

    #[tokio::test]
    async fn test_tls_routes_for_gateway_sorted_by_ns_name() {
        let store = SharedStore::new();

        let sc = make_tls_route_with_parent("sc", "prod", "svc", "prod", "my-gw");
        let sa = make_tls_route_with_parent("sa", "prod", "svc", "prod", "my-gw");
        let sb = make_tls_route_with_parent("sb", "prod", "svc", "prod", "my-gw");

        store.upsert_tls_route("prod/sc".to_string(), sc).await;
        store.upsert_tls_route("prod/sa".to_string(), sa).await;
        store.upsert_tls_route("prod/sb".to_string(), sb).await;
        store.mark_ready().await;

        let snap = match store.planner_snapshot().await {
            SnapshotResult::Ready(s) => s,
            SnapshotResult::NotReady => panic!("expected ready"),
        };

        let names: Vec<_> = snap
            .tls_routes_for_gateway("prod", "my-gw")
            .iter()
            .map(|r| r.metadata.name.as_deref().unwrap_or(""))
            .collect();
        assert_eq!(
            names,
            vec!["sa", "sb", "sc"],
            "routes must be sorted by name"
        );
    }

    #[tokio::test]
    async fn test_reference_grants_in_namespace_sorted_by_name() {
        use crate::crds::{ReferenceGrantFrom, ReferenceGrantSpec, ReferenceGrantTo};
        let store = SharedStore::new();

        for name in &["gc", "ga", "gb"] {
            let grant = ReferenceGrant {
                metadata: ObjectMeta {
                    name: Some((*name).to_string()),
                    namespace: Some("tls-ns".to_string()),
                    ..Default::default()
                },
                spec: ReferenceGrantSpec {
                    from: vec![ReferenceGrantFrom {
                        group: "gateway.networking.k8s.io".to_string(),
                        kind: "Gateway".to_string(),
                        namespace: "gw-ns".to_string(),
                    }],
                    to: vec![ReferenceGrantTo {
                        group: "".to_string(),
                        kind: "Secret".to_string(),
                        name: None,
                    }],
                },
            };
            store
                .upsert_reference_grant(format!("tls-ns/{}", name), grant)
                .await;
        }
        store.mark_ready().await;

        let snap = match store.planner_snapshot().await {
            SnapshotResult::Ready(s) => s,
            SnapshotResult::NotReady => panic!("expected ready"),
        };

        let names: Vec<_> = snap
            .reference_grants_in_namespace("tls-ns")
            .iter()
            .map(|g| g.metadata.name.as_deref().unwrap_or(""))
            .collect();
        assert_eq!(
            names,
            vec!["ga", "gb", "gc"],
            "grants must be sorted by name"
        );
    }

    // ── planner_snapshot completeness (readiness semantics) ───────────────────

    #[tokio::test]
    async fn test_planner_snapshot_not_ready_without_gateway_classes() {
        // Every resource class except GatewayClasses is listed.
        let store = SharedStore::new();
        store.mark_listed(ResourceClass::Gateways).await;
        store.mark_listed(ResourceClass::HttpRoutes).await;
        store.mark_listed(ResourceClass::TcpRoutes).await;
        store.mark_listed(ResourceClass::TlsRoutes).await;
        store.mark_listed(ResourceClass::Services).await;
        store.mark_listed(ResourceClass::Endpoints).await;
        store.mark_listed(ResourceClass::Secrets).await;
        store.mark_listed(ResourceClass::ReferenceGrants).await;
        assert!(
            matches!(store.planner_snapshot().await, SnapshotResult::NotReady),
            "planner snapshot must be NotReady when gateway_classes not populated"
        );
    }

    #[tokio::test]
    async fn test_planner_snapshot_not_ready_without_reference_grants() {
        // Every resource class except ReferenceGrants is listed.
        let store = SharedStore::new();
        store.mark_listed(ResourceClass::Gateways).await;
        store.mark_listed(ResourceClass::GatewayClasses).await;
        store.mark_listed(ResourceClass::HttpRoutes).await;
        store.mark_listed(ResourceClass::TcpRoutes).await;
        store.mark_listed(ResourceClass::TlsRoutes).await;
        store.mark_listed(ResourceClass::Services).await;
        store.mark_listed(ResourceClass::Endpoints).await;
        store.mark_listed(ResourceClass::Secrets).await;
        assert!(
            matches!(store.planner_snapshot().await, SnapshotResult::NotReady),
            "planner snapshot must be NotReady when reference_grants not populated"
        );
    }

    #[tokio::test]
    async fn test_planner_snapshot_ready_after_all_three_flags() {
        let store = SharedStore::new();
        mark_all_resource_lists_listed(&store).await;
        assert!(
            matches!(store.planner_snapshot().await, SnapshotResult::Ready(_)),
            "planner snapshot must be Ready once all resource classes are populated"
        );
    }

    #[tokio::test]
    async fn test_planner_snapshot_not_ready_while_gateway_is_observed_but_lists_are_still_warming()
    {
        let store = SharedStore::new();

        store
            .ingest_gateway_state(ready_gateway_state("gw", "default"))
            .await;
        store.mark_listed(ResourceClass::Gateways).await;
        store.mark_listed(ResourceClass::HttpRoutes).await;
        store.mark_listed(ResourceClass::TcpRoutes).await;
        store.mark_listed(ResourceClass::TlsRoutes).await;
        store.mark_listed(ResourceClass::Services).await;
        store.mark_listed(ResourceClass::Endpoints).await;
        store.mark_listed(ResourceClass::Secrets).await;
        store.mark_listed(ResourceClass::GatewayClasses).await;

        assert!(!store.is_ready().await);
        assert!(matches!(
            store.planner_snapshot().await,
            SnapshotResult::NotReady
        ));
    }

    #[tokio::test]
    async fn test_planner_snapshot_ready_after_remaining_list_complete_signals_keeps_gateway_lookup(
    ) {
        let store = SharedStore::new();

        store
            .ingest_gateway_state(ready_gateway_state("gw", "default"))
            .await;
        store.mark_listed(ResourceClass::Gateways).await;
        store.mark_listed(ResourceClass::HttpRoutes).await;
        store.mark_listed(ResourceClass::TcpRoutes).await;
        store.mark_listed(ResourceClass::TlsRoutes).await;
        store.mark_listed(ResourceClass::Services).await;
        store.mark_listed(ResourceClass::Endpoints).await;
        store.mark_listed(ResourceClass::Secrets).await;
        store.mark_listed(ResourceClass::GatewayClasses).await;

        assert!(matches!(
            store.planner_snapshot().await,
            SnapshotResult::NotReady
        ));

        store.mark_listed(ResourceClass::ReferenceGrants).await;
        assert!(store.is_ready().await);

        let snap = match store.planner_snapshot().await {
            SnapshotResult::Ready(s) => s,
            SnapshotResult::NotReady => panic!("expected ready"),
        };

        assert!(snap.gateway("default", "gw").is_some());
    }

    #[tokio::test]
    async fn test_ready_planner_snapshot_supports_attachment_and_runtime_planning_for_observed_gateway(
    ) {
        let store = SharedStore::new();

        store
            .ingest_gateway_state(ready_gateway_state("gw", "default"))
            .await;
        store.mark_listed(ResourceClass::Gateways).await;
        store.mark_listed(ResourceClass::HttpRoutes).await;
        store.mark_listed(ResourceClass::TcpRoutes).await;
        store.mark_listed(ResourceClass::TlsRoutes).await;
        store.mark_listed(ResourceClass::Services).await;
        store.mark_listed(ResourceClass::Endpoints).await;
        store.mark_listed(ResourceClass::Secrets).await;
        store.mark_listed(ResourceClass::GatewayClasses).await;
        store.mark_listed(ResourceClass::ReferenceGrants).await;

        let snapshot = match store.planner_snapshot().await {
            SnapshotResult::Ready(s) => s,
            SnapshotResult::NotReady => panic!("expected ready"),
        };

        let attachment = AttachmentPlanner
            .plan(&AttachmentPlanInput {
                gateway_namespace: "default".to_string(),
                gateway_name: "gw".to_string(),
                gateway_generation: 7,
                snapshot: snapshot.clone(),
            })
            .expect("attachment planning should see the gateway in snapshot");
        assert_eq!(attachment.gateway_name, "gw");

        let runtime = GatewayRuntimePlanner
            .plan(&RuntimePlanInput {
                gateway_namespace: "default".to_string(),
                gateway_name: "gw".to_string(),
                snapshot,
                controller_config: ControllerConfig::default(),
                observed: ObservedRuntimeState::default(),
            })
            .expect("runtime planning should see the gateway in snapshot");
        assert_eq!(runtime.gateway_name, "gw");
    }

    // ── mark_listed must NOT be called on list failure ───────────────────────
    //
    // These tests document the contract: readiness must remain false
    // when the initial list fails.  The run_*_controller functions are
    // responsible for only calling mark_listed(...) inside the Ok arm.

    /// If GatewayClasses is not marked listed (simulating a list failure),
    /// the store must remain not-ready even after every other readiness signal
    /// is populated.
    #[tokio::test]
    async fn test_store_not_ready_when_gateway_classes_flag_not_set() {
        let store = SharedStore::new();
        store.mark_listed(ResourceClass::Gateways).await;
        store.mark_listed(ResourceClass::HttpRoutes).await;
        store.mark_listed(ResourceClass::TcpRoutes).await;
        store.mark_listed(ResourceClass::TlsRoutes).await;
        store.mark_listed(ResourceClass::Services).await;
        store.mark_listed(ResourceClass::Endpoints).await;
        store.mark_listed(ResourceClass::Secrets).await;
        store.mark_listed(ResourceClass::ReferenceGrants).await;
        // Deliberately do NOT call mark_listed(ResourceClass::GatewayClasses).
        assert!(
            !store.is_ready().await,
            "store must remain not-ready when GatewayClasses is absent"
        );
        assert!(
            matches!(store.planner_snapshot().await, SnapshotResult::NotReady),
            "planner snapshot must be NotReady when GatewayClasses is absent"
        );
    }

    /// If ReferenceGrants is not marked listed (simulating a list failure),
    /// the store must remain not-ready even after every other readiness signal
    /// is populated.
    #[tokio::test]
    async fn test_store_not_ready_when_reference_grants_flag_not_set() {
        let store = SharedStore::new();
        store.mark_listed(ResourceClass::Gateways).await;
        store.mark_listed(ResourceClass::GatewayClasses).await;
        store.mark_listed(ResourceClass::HttpRoutes).await;
        store.mark_listed(ResourceClass::TcpRoutes).await;
        store.mark_listed(ResourceClass::TlsRoutes).await;
        store.mark_listed(ResourceClass::Services).await;
        store.mark_listed(ResourceClass::Endpoints).await;
        store.mark_listed(ResourceClass::Secrets).await;
        // Deliberately do NOT call mark_listed(ResourceClass::ReferenceGrants).
        assert!(
            !store.is_ready().await,
            "store must remain not-ready when ReferenceGrants is absent"
        );
        assert!(
            matches!(store.planner_snapshot().await, SnapshotResult::NotReady),
            "planner snapshot must be NotReady when ReferenceGrants is absent"
        );
    }

    // ── route_references_gateway helper ───────────────────────────────────────

    #[test]
    fn test_route_references_gateway_matches_explicit_ns() {
        let refs = vec![make_parent_ref("prod", "my-gw")];
        assert!(route_references_gateway("prod", &refs, "prod", "my-gw"));
        assert!(!route_references_gateway("prod", &refs, "prod", "other-gw"));
        assert!(!route_references_gateway("prod", &refs, "staging", "my-gw"));
    }

    #[test]
    fn test_route_references_gateway_defaults_ns_to_route_ns() {
        let refs = vec![ParentReference {
            group: "gateway.networking.k8s.io".to_string(),
            kind: "Gateway".to_string(),
            namespace: None,
            name: "my-gw".to_string(),
            section_name: None,
            port: None,
        }];
        // Route is in "prod" -- namespace defaults to "prod"
        assert!(route_references_gateway("prod", &refs, "prod", "my-gw"));
        assert!(!route_references_gateway("prod", &refs, "staging", "my-gw"));
    }

    #[test]
    fn test_route_references_gateway_empty_group_matches() {
        // Empty group is treated as gateway.networking.k8s.io per Gateway API spec.
        let refs = vec![ParentReference {
            group: "".to_string(),
            kind: "Gateway".to_string(),
            namespace: Some("prod".to_string()),
            name: "my-gw".to_string(),
            section_name: None,
            port: None,
        }];
        assert!(route_references_gateway("prod", &refs, "prod", "my-gw"));
    }

    #[test]
    fn test_route_references_gateway_wrong_kind_no_match() {
        let refs = vec![ParentReference {
            group: "gateway.networking.k8s.io".to_string(),
            kind: "HTTPRoute".to_string(), // wrong kind
            namespace: Some("prod".to_string()),
            name: "my-gw".to_string(),
            section_name: None,
            port: None,
        }];
        assert!(!route_references_gateway("prod", &refs, "prod", "my-gw"));
    }
}
