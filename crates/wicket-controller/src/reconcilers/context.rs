//! Shared context for reconcilers.
//!
//! ## Config regeneration flow
//!
//! Config generation is now split into a pure planning step and a side-effecting
//! apply step:
//!
//! ```text
//!   GatewayState (from store snapshot or API-list fallback)
//!         |
//!         v
//!   GlobalConfigPlanner::plan()   -- pure, sync, no I/O
//!         |
//!         v
//!   ConfigPlan { Update { toml_content, config_hash } | NoOp }
//!         |
//!         v
//!   apply_config_plan()           -- async, patches ConfigMap + updates metrics
//! ```
//!
//! `update_config` and `trigger_config_update` preserve their existing public
//! signatures and behavior; they now delegate to the planner/applier pair.
//!
//! ## Fallback path safety (bootstrap/recovery parity)
//!
//! The API-list fallback path (used when the shared store is not yet ready)
//! applies the following safety rules:
//!
//! 1. **Fail-closed on list errors**: if any core list/classification step
//!    fails, the fallback does NOT apply a partial config.  The last-good
//!    in-memory config is kept instead.
//!
//! 2. **Accepted-only routes**: only routes with `Accepted=True` for this
//!    controller are included in the fallback `GatewayState`.
//!
//! 3. **Bulk GatewayClass classification**: a single GatewayClass list is
//!    fetched upfront and used to classify all Gateways, replacing the
//!    per-Gateway `get(...).unwrap_or(false)` pattern.  A failure to list
//!    GatewayClasses is treated as a hard error (no fallback applied).
//!
//! 4. **Namespace scope**: list APIs respect `ctx.watch_all_namespaces` and
//!    `ctx.controller_namespace` instead of always using `Api::all`.

use std::sync::Arc;

use kube::Client;
use tokio::sync::RwLock;

use super::config_applier::{apply_config_plan, read_current_config_hash, ConfigApplierInput};
use super::config_generator::{parents_accepted_by_wicket, GatewayState, WicketConfig};
use super::config_planner::{GlobalConfigPlanInput, GlobalConfigPlanner};
use super::store::SharedStore;
use crate::crds::{Gateway, GatewayClass, HTTPRoute, TCPRoute, TLSRoute, WICKET_CONTROLLER_NAME};
use crate::reconcilers::contracts::{ConfigApplyResult, ConfigPlan, Planner};

/// Shared context passed to all reconcilers.
#[derive(Clone)]
pub struct Context {
    /// Kubernetes client.
    pub client: Client,

    /// Current generated Wicket configuration.
    pub config: Arc<RwLock<WicketConfig>>,

    /// Shared resource cache/index.  Reconcilers read from this store
    /// instead of issuing repeated full-list API calls.
    pub store: Arc<SharedStore>,

    /// Controller name for status updates.
    pub controller_name: String,

    /// Namespace the controller is deployed in (for leader election).
    pub controller_namespace: String,

    /// Whether to watch all namespaces or just the controller namespace.
    pub watch_all_namespaces: bool,

    /// Name of the ConfigMap to update with proxy configuration.
    pub config_configmap_name: String,

    /// Namespace of the ConfigMap to update.
    pub config_configmap_namespace: String,

    /// Directory for storing TLS certificates extracted from Kubernetes secrets.
    /// Defaults to /var/run/wicket/tls for security (not world-readable /tmp).
    pub tls_cert_dir: String,

    /// Controller-level configuration injected into the managed-runtime planner.
    ///
    /// Defaults to `ControllerConfig::default()` (suitable for development /
    /// single-node clusters).  In production this should be populated from
    /// flags, environment variables, or a controller ConfigMap before the
    /// controller starts.
    pub controller_config: super::runtime_plan::ControllerConfig,
}

/// Default directory for TLS certificates (more secure than /tmp).
pub const DEFAULT_TLS_CERT_DIR: &str = "/var/run/wicket/tls";

impl Context {
    pub fn new(
        client: Client,
        controller_namespace: String,
        watch_all_namespaces: bool,
        config_configmap_name: String,
        config_configmap_namespace: String,
    ) -> Self {
        Self::with_tls_dir(
            client,
            controller_namespace,
            watch_all_namespaces,
            config_configmap_name,
            config_configmap_namespace,
            DEFAULT_TLS_CERT_DIR.to_string(),
        )
    }

    pub fn with_tls_dir(
        client: Client,
        controller_namespace: String,
        watch_all_namespaces: bool,
        config_configmap_name: String,
        config_configmap_namespace: String,
        tls_cert_dir: String,
    ) -> Self {
        Self {
            client,
            config: Arc::new(RwLock::new(WicketConfig::default())),
            store: Arc::new(SharedStore::new()),
            controller_name: WICKET_CONTROLLER_NAME.to_string(),
            controller_namespace,
            watch_all_namespaces,
            config_configmap_name,
            config_configmap_namespace,
            tls_cert_dir,
            controller_config: super::runtime_plan::ControllerConfig::default(),
        }
    }

    /// Explicit constructor for callsites that supply a fully-built
    /// `ControllerConfig`.  Prefer this over `new` / `with_tls_dir` in
    /// production paths so the effective managed-runtime defaults are always
    /// injected explicitly rather than silently defaulted.
    pub fn with_controller_config(
        client: Client,
        controller_namespace: String,
        watch_all_namespaces: bool,
        config_configmap_name: String,
        config_configmap_namespace: String,
        tls_cert_dir: String,
        controller_config: super::runtime_plan::ControllerConfig,
    ) -> Self {
        Self {
            client,
            config: Arc::new(RwLock::new(WicketConfig::default())),
            store: Arc::new(SharedStore::new()),
            controller_name: WICKET_CONTROLLER_NAME.to_string(),
            controller_namespace,
            watch_all_namespaces,
            config_configmap_name,
            config_configmap_namespace,
            tls_cert_dir,
            controller_config,
        }
    }

    /// Update the Wicket configuration by patching the ConfigMap.
    ///
    /// Delegates to the planner/applier pair:
    /// 1. `GlobalConfigPlanner::plan()` serializes `config` to TOML and
    ///    computes the hash (always `Update` since no current hash is supplied).
    /// 2. `apply_config_plan()` patches the ConfigMap, updates in-memory state,
    ///    and increments metrics.
    pub async fn update_config(&self, config: WicketConfig) -> Result<(), ConfigUpdateError> {
        // Build a minimal GatewayState from the WicketConfig.  Because
        // WicketConfig is already the rendered output (not raw Gateway API
        // objects), we cannot reconstruct a GatewayState from it.  Instead we
        // serialize it directly to TOML and wrap it in a ConfigPlan::Update,
        // bypassing the planner's generate_config step.
        //
        // This preserves the existing `update_config` contract: callers pass
        // an already-generated WicketConfig and expect it to be applied as-is.
        let toml_content = toml::to_string_pretty(&config)
            .map_err(|e| ConfigUpdateError::Serialization(e.to_string()))?;

        let config_hash = super::runtime_plan::sha256_hex(&toml_content);

        let plan = ConfigPlan::Update {
            toml_content,
            config_hash,
        };

        let applier_input = ConfigApplierInput {
            client: &self.client,
            configmap_name: &self.config_configmap_name,
            configmap_namespace: &self.config_configmap_namespace,
            in_memory_config: &self.config,
        };

        apply_config_plan(&plan, &applier_input)
            .await
            .map_err(map_apply_error)?;

        Ok(())
    }

    /// Get the current configuration.
    pub async fn get_config(&self) -> WicketConfig {
        self.config.read().await.clone()
    }
}

/// Errors that can occur during configuration updates.
#[derive(Debug, thiserror::Error)]
pub enum ConfigUpdateError {
    /// A planning-phase error (pure logic; no I/O involved).
    #[error("Config planning error: {0}")]
    Planning(String),

    /// TOML serialization or deserialization failed.
    #[error("Failed to serialize configuration: {0}")]
    Serialization(String),

    /// A Kubernetes API call failed during the apply phase.
    #[error("Kubernetes API error: {0}")]
    KubeApi(String),
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Map an `ApplyError` to the appropriate `ConfigUpdateError` variant,
/// preserving the planner-vs-apply distinction.
fn map_apply_error(e: crate::reconcilers::contracts::ApplyError) -> ConfigUpdateError {
    use crate::reconcilers::contracts::ApplyError;
    match e {
        ApplyError::Serialization(msg) => ConfigUpdateError::Serialization(msg),
        ApplyError::KubeApi(msg) => ConfigUpdateError::KubeApi(msg),
        ApplyError::Filesystem(msg) => ConfigUpdateError::KubeApi(msg),
        ApplyError::NotOwned { namespace, name } => ConfigUpdateError::KubeApi(format!(
            "object {}/{} is not owned by wicket-controller",
            namespace, name
        )),
    }
}

/// Trigger a full configuration update by loading all resources and regenerating config.
///
/// ## Cache-first strategy
///
/// When the shared store is ready, we use its snapshot directly -- no API
/// list calls needed.  When the store is not yet ready (startup warm-up),
/// we fall back to the full-list API path.
///
/// ## Fallback safety (bootstrap/recovery parity)
///
/// The fallback path is fail-closed:
///
/// 1. A single GatewayClass list is fetched upfront (fix 3).  If it fails,
///    the fallback aborts and the last-good in-memory config is kept.
/// 2. Only routes with `Accepted=True` for this controller are included (fix 2).
/// 3. If any core list step fails, the fallback aborts without applying a
///    partial config (fix 1).  The last-good config is preserved.
/// 4. List APIs respect `ctx.watch_all_namespaces` / `ctx.controller_namespace`
///    instead of always using `Api::all` (fix 4).
///
/// ## Store readiness
///
/// The store is only marked ready after every watch controller has completed
/// its own initial list. A partial snapshot is never ingested.
///
/// ## Planner/applier split
///
/// Config generation is split:
/// - `GlobalConfigPlanner::plan()` is the pure step (snapshot -> `ConfigPlan`).
/// - `apply_config_plan()` is the side-effecting step (ConfigMap patch + metrics).
pub async fn trigger_config_update(ctx: &Context, reason: &str) -> Result<(), ConfigUpdateError> {
    use super::service::load_all_service_endpoints;

    tracing::debug!(reason = %reason, "Triggering configuration update");

    // ── Cache-first path ──────────────────────────────────────────────────────
    if let Some(state) = ctx.store.snapshot().await {
        tracing::debug!(reason = %reason, "Using shared store snapshot for config generation");
        apply_from_gateway_state(ctx, state).await?;
        tracing::debug!(reason = %reason, "Configuration update completed (cache path)");
        return Ok(());
    }

    // ── Fallback: full API-list path ──────────────────────────────────────────
    tracing::info!(
        reason = %reason,
        "Shared store not ready; falling back to full API-list for config generation"
    );

    // Fix (4): build namespaced or cluster-wide API handles based on the
    // controller's namespace scope setting.
    let make_gw_api = |client: &kube::Client| -> kube::api::Api<Gateway> {
        if ctx.watch_all_namespaces {
            kube::api::Api::all(client.clone())
        } else {
            kube::api::Api::namespaced(client.clone(), &ctx.controller_namespace)
        }
    };
    let make_http_api = |client: &kube::Client| -> kube::api::Api<HTTPRoute> {
        if ctx.watch_all_namespaces {
            kube::api::Api::all(client.clone())
        } else {
            kube::api::Api::namespaced(client.clone(), &ctx.controller_namespace)
        }
    };
    let make_tcp_api = |client: &kube::Client| -> kube::api::Api<TCPRoute> {
        if ctx.watch_all_namespaces {
            kube::api::Api::all(client.clone())
        } else {
            kube::api::Api::namespaced(client.clone(), &ctx.controller_namespace)
        }
    };
    let make_tls_api = |client: &kube::Client| -> kube::api::Api<TLSRoute> {
        if ctx.watch_all_namespaces {
            kube::api::Api::all(client.clone())
        } else {
            kube::api::Api::namespaced(client.clone(), &ctx.controller_namespace)
        }
    };

    // Fix (3): bulk-list GatewayClasses once upfront.  A failure here is a
    // hard error: we cannot safely classify Gateways without this map, so we
    // abort and keep the last-good config rather than applying a partial state.
    //
    // GatewayClass is cluster-scoped, so Api::all is always correct here.
    let wicket_class_names: std::collections::HashSet<String> = {
        let gc_api: kube::api::Api<GatewayClass> = kube::api::Api::all(ctx.client.clone());
        match gc_api.list(&Default::default()).await {
            Ok(list) => list
                .items
                .into_iter()
                .filter(|gc| gc.is_wicket_managed())
                .filter_map(|gc| gc.metadata.name.clone())
                .collect(),
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    reason = %reason,
                    "Fallback: failed to list GatewayClasses; \
                     keeping last-good config (fail-closed)"
                );
                // Fix (1): abort without applying partial config.
                return Ok(());
            }
        }
    };

    let mut state = GatewayState::default();
    let mut all_lists_ok = true;

    // Load Gateways (only Wicket-managed ones, using bulk class map).
    let gw_api = make_gw_api(&ctx.client);
    match gw_api.list(&Default::default()).await {
        Ok(gateways) => {
            for gateway in gateways.items {
                if wicket_class_names.contains(&gateway.spec.gateway_class_name) {
                    let gw_key = GatewayState::key(
                        gateway.metadata.namespace.as_deref().unwrap_or("default"),
                        &kube::ResourceExt::name_any(&gateway),
                    );
                    state.gateways.insert(gw_key, gateway);
                }
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "Fallback: failed to list Gateways");
            all_lists_ok = false;
        }
    }

    // Fix (2): load HTTPRoutes, keeping only those Accepted=True by this controller.
    let http_api = make_http_api(&ctx.client);
    match http_api.list(&Default::default()).await {
        Ok(routes) => {
            for route in routes.items {
                if !is_http_route_accepted_by_wicket(&route) {
                    tracing::debug!(
                        name = route.metadata.name.as_deref().unwrap_or(""),
                        namespace = route.metadata.namespace.as_deref().unwrap_or(""),
                        "Fallback: skipping HTTPRoute with no Accepted=True parent for this controller"
                    );
                    continue;
                }
                let route_key = GatewayState::key(
                    route.metadata.namespace.as_deref().unwrap_or("default"),
                    &kube::ResourceExt::name_any(&route),
                );
                state.http_routes.insert(route_key, route);
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "Fallback: failed to list HTTPRoutes");
            all_lists_ok = false;
        }
    }

    // Fix (2): load TCPRoutes, keeping only those Accepted=True by this controller.
    let tcp_api = make_tcp_api(&ctx.client);
    match tcp_api.list(&Default::default()).await {
        Ok(routes) => {
            for route in routes.items {
                if !is_tcp_route_accepted_by_wicket(&route) {
                    tracing::debug!(
                        name = route.metadata.name.as_deref().unwrap_or(""),
                        namespace = route.metadata.namespace.as_deref().unwrap_or(""),
                        "Fallback: skipping TCPRoute with no Accepted=True parent for this controller"
                    );
                    continue;
                }
                let route_key = GatewayState::key(
                    route.metadata.namespace.as_deref().unwrap_or("default"),
                    &kube::ResourceExt::name_any(&route),
                );
                state.tcp_routes.insert(route_key, route);
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "Fallback: failed to list TCPRoutes");
            all_lists_ok = false;
        }
    }

    // Fix (2): load TLSRoutes, keeping only those Accepted=True by this controller.
    let tls_api = make_tls_api(&ctx.client);
    match tls_api.list(&Default::default()).await {
        Ok(routes) => {
            for route in routes.items {
                if !is_tls_route_accepted_by_wicket(&route) {
                    tracing::debug!(
                        name = route.metadata.name.as_deref().unwrap_or(""),
                        namespace = route.metadata.namespace.as_deref().unwrap_or(""),
                        "Fallback: skipping TLSRoute with no Accepted=True parent for this controller"
                    );
                    continue;
                }
                let route_key = GatewayState::key(
                    route.metadata.namespace.as_deref().unwrap_or("default"),
                    &kube::ResourceExt::name_any(&route),
                );
                state.tls_routes.insert(route_key, route);
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "Fallback: failed to list TLSRoutes");
            all_lists_ok = false;
        }
    }

    // Fix (1): if any core list failed, abort without applying partial config.
    // Keep the last-good in-memory config instead of overwriting it with
    // incomplete data.
    if !all_lists_ok {
        tracing::warn!(
            reason = %reason,
            "Fallback: one or more core list calls failed; \
             keeping last-good config (fail-closed). \
             Store remains not-ready for future fallback retries."
        );
        return Ok(());
    }

    // All lists succeeded: load service endpoints and ingest into the store.
    load_all_service_endpoints(&ctx.client, &mut state).await;

    // Ingest into the shared store so future calls use the cache path.
    ctx.store.ingest_gateway_state(state.clone()).await;

    // Generate and apply config from the complete state.
    apply_from_gateway_state(ctx, state).await?;

    tracing::debug!(reason = %reason, "Configuration update completed (API-list fallback path)");
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Fallback accepted-route helpers
//
// These thin wrappers extract the `parents` slice from each route's status and
// delegate to `parents_accepted_by_wicket` in `config_generator`, which is the
// single authoritative implementation of the Accepted=True check.  Keeping the
// logic in one place ensures the fallback path and the render-time guard in
// `config_generator` are always consistent.
// ─────────────────────────────────────────────────────────────────────────────

/// Returns `true` if the HTTPRoute has at least one `status.parents` entry
/// where `controller_name == WICKET_CONTROLLER_NAME` and the `Accepted`
/// condition is `True`.
///
/// Fail-closed: routes with no status (not yet reconciled) are excluded.
fn is_http_route_accepted_by_wicket(route: &HTTPRoute) -> bool {
    match &route.status {
        Some(s) => parents_accepted_by_wicket(&s.parents),
        None => false,
    }
}

/// Returns `true` if the TCPRoute has at least one `status.parents` entry
/// where `controller_name == WICKET_CONTROLLER_NAME` and the `Accepted`
/// condition is `True`.
///
/// Fail-closed: routes with no status (not yet reconciled) are excluded.
fn is_tcp_route_accepted_by_wicket(route: &TCPRoute) -> bool {
    match &route.status {
        Some(s) => parents_accepted_by_wicket(&s.parents),
        None => false,
    }
}

/// Returns `true` if the TLSRoute has at least one `status.parents` entry
/// where `controller_name == WICKET_CONTROLLER_NAME` and the `Accepted`
/// condition is `True`.
///
/// Fail-closed: routes with no status (not yet reconciled) are excluded.
fn is_tls_route_accepted_by_wicket(route: &TLSRoute) -> bool {
    match &route.status {
        Some(s) => parents_accepted_by_wicket(&s.parents),
        None => false,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal: plan + apply from a GatewayState
// ─────────────────────────────────────────────────────────────────────────────

/// Plan and apply config from a `GatewayState`.
///
/// This is the shared inner step used by both the cache-first path and the
/// API-list fallback path in `trigger_config_update`.
///
/// ## Steps
///
/// 1. Read the current `wicket.io/config-revision` annotation from the
///    ConfigMap (one lightweight GET).  This is the only I/O before planning.
/// 2. Run the pure planner.  When the generated hash matches the annotation
///    the planner returns `ConfigPlan::NoOp` and the ConfigMap patch is
///    skipped; the in-memory view is still synced from the plan content.
/// 3. Apply the plan (ConfigMap patch + in-memory sync + metrics).
async fn apply_from_gateway_state(
    ctx: &Context,
    state: GatewayState,
) -> Result<(), ConfigUpdateError> {
    // ── 1. Read current revision from ConfigMap annotation ────────────────────
    // A 404 (ConfigMap not yet created) is treated as "no current hash" so the
    // planner always returns Update on first run.  Hard API errors are surfaced
    // as KubeApi so the reconcile cycle requeues with backoff.
    let current_config_hash = read_current_config_hash(
        &ctx.client,
        &ctx.config_configmap_name,
        &ctx.config_configmap_namespace,
    )
    .await
    .map_err(|e| ConfigUpdateError::KubeApi(e.to_string()))?;

    // ── 2. Pure planning step ─────────────────────────────────────────────────
    let planner = GlobalConfigPlanner;
    let plan_input = GlobalConfigPlanInput {
        gateway_state: state,
        current_config_hash,
    };
    let plan: ConfigPlan = planner
        .plan(&plan_input)
        .map_err(|e| ConfigUpdateError::Planning(e.to_string()))?;

    // ── 3. Apply step ─────────────────────────────────────────────────────────
    let applier_input = ConfigApplierInput {
        client: &ctx.client,
        configmap_name: &ctx.config_configmap_name,
        configmap_namespace: &ctx.config_configmap_namespace,
        in_memory_config: &ctx.config,
    };

    let result = apply_config_plan(&plan, &applier_input)
        .await
        .map_err(map_apply_error)?;

    match result {
        ConfigApplyResult::Updated { ref config_hash } => {
            tracing::debug!(config_hash = %config_hash, "Config applied");
        }
        ConfigApplyResult::NoOp => {
            tracing::debug!("Config apply was a no-op (hash unchanged); in-memory view synced");
        }
    }

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crds::{
        Condition, HTTPRoute, HTTPRouteSpec, ParentReference, RouteParentStatus, TCPRoute,
        TCPRouteSpec, TLSRoute, TLSRouteSpec, WICKET_CONTROLLER_NAME,
    };
    use kube::core::ObjectMeta;

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn accepted_parent_status(controller: &str) -> RouteParentStatus {
        RouteParentStatus {
            parent_ref: ParentReference {
                group: "gateway.networking.k8s.io".to_string(),
                kind: "Gateway".to_string(),
                namespace: Some("default".to_string()),
                name: "my-gw".to_string(),
                section_name: None,
                port: None,
            },
            controller_name: controller.to_string(),
            conditions: vec![Condition::accepted()],
        }
    }

    fn rejected_parent_status(controller: &str) -> RouteParentStatus {
        RouteParentStatus {
            parent_ref: ParentReference {
                group: "gateway.networking.k8s.io".to_string(),
                kind: "Gateway".to_string(),
                namespace: Some("default".to_string()),
                name: "my-gw".to_string(),
                section_name: None,
                port: None,
            },
            controller_name: controller.to_string(),
            conditions: vec![Condition::not_accepted()],
        }
    }

    fn make_http_route_with_status(
        name: &str,
        parents: Option<Vec<RouteParentStatus>>,
    ) -> HTTPRoute {
        use crate::crds::HTTPRouteStatus;
        HTTPRoute {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            },
            spec: HTTPRouteSpec {
                parent_refs: vec![],
                hostnames: vec![],
                rules: vec![],
            },
            status: parents.map(|p| HTTPRouteStatus { parents: p }),
        }
    }

    fn make_tcp_route_with_status(name: &str, parents: Option<Vec<RouteParentStatus>>) -> TCPRoute {
        use crate::crds::TCPRouteStatus;
        TCPRoute {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            },
            spec: TCPRouteSpec {
                parent_refs: vec![],
                rules: vec![],
            },
            status: parents.map(|p| TCPRouteStatus { parents: p }),
        }
    }

    fn make_tls_route_with_status(name: &str, parents: Option<Vec<RouteParentStatus>>) -> TLSRoute {
        use crate::crds::TLSRouteStatus;
        TLSRoute {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            },
            spec: TLSRouteSpec {
                parent_refs: vec![],
                hostnames: vec![],
                rules: vec![],
            },
            status: parents.map(|p| TLSRouteStatus { parents: p }),
        }
    }

    // ── is_http_route_accepted_by_wicket ──────────────────────────────────────

    #[test]
    fn http_route_no_status_is_fail_closed() {
        let route = make_http_route_with_status("r", None);
        assert!(!is_http_route_accepted_by_wicket(&route));
    }

    #[test]
    fn http_route_empty_parents_is_fail_closed() {
        let route = make_http_route_with_status("r", Some(vec![]));
        assert!(!is_http_route_accepted_by_wicket(&route));
    }

    #[test]
    fn http_route_accepted_by_wicket_returns_true() {
        let route = make_http_route_with_status(
            "r",
            Some(vec![accepted_parent_status(WICKET_CONTROLLER_NAME)]),
        );
        assert!(is_http_route_accepted_by_wicket(&route));
    }

    #[test]
    fn http_route_accepted_by_other_controller_returns_false() {
        let route = make_http_route_with_status(
            "r",
            Some(vec![accepted_parent_status("other.io/controller")]),
        );
        assert!(!is_http_route_accepted_by_wicket(&route));
    }

    #[test]
    fn http_route_rejected_by_wicket_returns_false() {
        let route = make_http_route_with_status(
            "r",
            Some(vec![rejected_parent_status(WICKET_CONTROLLER_NAME)]),
        );
        assert!(!is_http_route_accepted_by_wicket(&route));
    }

    #[test]
    fn http_route_accepted_by_wicket_among_multiple_parents() {
        // One rejected parent from another controller, one accepted from wicket.
        let route = make_http_route_with_status(
            "r",
            Some(vec![
                rejected_parent_status("other.io/controller"),
                accepted_parent_status(WICKET_CONTROLLER_NAME),
            ]),
        );
        assert!(is_http_route_accepted_by_wicket(&route));
    }

    // ── is_tcp_route_accepted_by_wicket ──────────────────────────────────────

    #[test]
    fn tcp_route_no_status_is_fail_closed() {
        let route = make_tcp_route_with_status("r", None);
        assert!(!is_tcp_route_accepted_by_wicket(&route));
    }

    #[test]
    fn tcp_route_accepted_by_wicket_returns_true() {
        let route = make_tcp_route_with_status(
            "r",
            Some(vec![accepted_parent_status(WICKET_CONTROLLER_NAME)]),
        );
        assert!(is_tcp_route_accepted_by_wicket(&route));
    }

    #[test]
    fn tcp_route_accepted_by_other_controller_returns_false() {
        let route = make_tcp_route_with_status(
            "r",
            Some(vec![accepted_parent_status("other.io/controller")]),
        );
        assert!(!is_tcp_route_accepted_by_wicket(&route));
    }

    #[test]
    fn tcp_route_rejected_by_wicket_returns_false() {
        let route = make_tcp_route_with_status(
            "r",
            Some(vec![rejected_parent_status(WICKET_CONTROLLER_NAME)]),
        );
        assert!(!is_tcp_route_accepted_by_wicket(&route));
    }

    // ── is_tls_route_accepted_by_wicket ──────────────────────────────────────

    #[test]
    fn tls_route_no_status_is_fail_closed() {
        let route = make_tls_route_with_status("r", None);
        assert!(!is_tls_route_accepted_by_wicket(&route));
    }

    #[test]
    fn tls_route_accepted_by_wicket_returns_true() {
        let route = make_tls_route_with_status(
            "r",
            Some(vec![accepted_parent_status(WICKET_CONTROLLER_NAME)]),
        );
        assert!(is_tls_route_accepted_by_wicket(&route));
    }

    #[test]
    fn tls_route_accepted_by_other_controller_returns_false() {
        let route = make_tls_route_with_status(
            "r",
            Some(vec![accepted_parent_status("other.io/controller")]),
        );
        assert!(!is_tls_route_accepted_by_wicket(&route));
    }

    #[test]
    fn tls_route_rejected_by_wicket_returns_false() {
        let route = make_tls_route_with_status(
            "r",
            Some(vec![rejected_parent_status(WICKET_CONTROLLER_NAME)]),
        );
        assert!(!is_tls_route_accepted_by_wicket(&route));
    }

    // ── Cross-type symmetry ───────────────────────────────────────────────────

    /// All three helpers must agree: a route with no status is fail-closed.
    #[test]
    fn all_route_types_fail_closed_with_no_status() {
        let http = make_http_route_with_status("r", None);
        let tcp = make_tcp_route_with_status("r", None);
        let tls = make_tls_route_with_status("r", None);
        assert!(!is_http_route_accepted_by_wicket(&http));
        assert!(!is_tcp_route_accepted_by_wicket(&tcp));
        assert!(!is_tls_route_accepted_by_wicket(&tls));
    }

    /// All three helpers must agree: a route accepted by wicket passes.
    #[test]
    fn all_route_types_pass_when_accepted_by_wicket() {
        let http = make_http_route_with_status(
            "r",
            Some(vec![accepted_parent_status(WICKET_CONTROLLER_NAME)]),
        );
        let tcp = make_tcp_route_with_status(
            "r",
            Some(vec![accepted_parent_status(WICKET_CONTROLLER_NAME)]),
        );
        let tls = make_tls_route_with_status(
            "r",
            Some(vec![accepted_parent_status(WICKET_CONTROLLER_NAME)]),
        );
        assert!(is_http_route_accepted_by_wicket(&http));
        assert!(is_tcp_route_accepted_by_wicket(&tcp));
        assert!(is_tls_route_accepted_by_wicket(&tls));
    }
}
