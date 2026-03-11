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

use std::sync::Arc;

use kube::Client;
use tokio::sync::RwLock;

use super::config_applier::{apply_config_plan, read_current_config_hash, ConfigApplierInput};
use super::config_generator::{GatewayState, WicketConfig};
use super::config_planner::{GlobalConfigPlanInput, GlobalConfigPlanner};
use super::store::SharedStore;
use crate::crds::{Gateway, GatewayClass, HTTPRoute, TCPRoute, TLSRoute};
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
            controller_name: "wicket.io/gateway-controller".to_string(),
            controller_namespace,
            watch_all_namespaces,
            config_configmap_name,
            config_configmap_namespace,
            tls_cert_dir,
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
/// we fall back to the existing full-list API path.
///
/// ## Store readiness safety
///
/// The store is only marked ready (via `ingest_gateway_state`) when **all**
/// core list calls succeed.  If any list fails, we still generate config
/// from whatever partial data we have (existing behavior), but we do NOT
/// promote the store to ready -- so future calls continue to fall back to
/// the API-list path until a fully-successful list completes.
///
/// ## Planner/applier split
///
/// Config generation is now split:
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

    let mut state = GatewayState::default();
    let mut all_lists_ok = true;

    // Load all Gateways (only Wicket-managed ones)
    let gw_api: kube::api::Api<Gateway> = kube::api::Api::all(ctx.client.clone());
    match gw_api.list(&Default::default()).await {
        Ok(gateways) => {
            for gateway in gateways.items {
                let gc_api: kube::api::Api<GatewayClass> = kube::api::Api::all(ctx.client.clone());
                let is_wicket = gc_api
                    .get(&gateway.spec.gateway_class_name)
                    .await
                    .map(|gc| gc.is_wicket_managed())
                    .unwrap_or(false);

                if is_wicket {
                    let gw_key = GatewayState::key(
                        gateway.metadata.namespace.as_deref().unwrap_or("default"),
                        &kube::ResourceExt::name_any(&gateway),
                    );
                    state.gateways.insert(gw_key, gateway);
                }
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "Failed to list Gateways; store will not be marked ready");
            all_lists_ok = false;
        }
    }

    // Load all HTTPRoutes
    let route_api: kube::api::Api<HTTPRoute> = kube::api::Api::all(ctx.client.clone());
    match route_api.list(&Default::default()).await {
        Ok(routes) => {
            for route in routes.items {
                let route_key = GatewayState::key(
                    route.metadata.namespace.as_deref().unwrap_or("default"),
                    &kube::ResourceExt::name_any(&route),
                );
                state.http_routes.insert(route_key, route);
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "Failed to list HTTPRoutes; store will not be marked ready");
            all_lists_ok = false;
        }
    }

    // Load all TCPRoutes
    let tcp_route_api: kube::api::Api<TCPRoute> = kube::api::Api::all(ctx.client.clone());
    match tcp_route_api.list(&Default::default()).await {
        Ok(routes) => {
            for route in routes.items {
                let route_key = GatewayState::key(
                    route.metadata.namespace.as_deref().unwrap_or("default"),
                    &kube::ResourceExt::name_any(&route),
                );
                state.tcp_routes.insert(route_key, route);
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "Failed to list TCPRoutes; store will not be marked ready");
            all_lists_ok = false;
        }
    }

    // Load all TLSRoutes
    let tls_route_api: kube::api::Api<TLSRoute> = kube::api::Api::all(ctx.client.clone());
    match tls_route_api.list(&Default::default()).await {
        Ok(routes) => {
            for route in routes.items {
                let route_key = GatewayState::key(
                    route.metadata.namespace.as_deref().unwrap_or("default"),
                    &kube::ResourceExt::name_any(&route),
                );
                state.tls_routes.insert(route_key, route);
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "Failed to list TLSRoutes; store will not be marked ready");
            all_lists_ok = false;
        }
    }

    // Load service endpoints
    load_all_service_endpoints(&ctx.client, &mut state).await;

    // Only populate the shared store when ALL core lists succeeded.
    // A partial snapshot would lock in missing resources and prevent
    // future fallback retries.
    if all_lists_ok {
        ctx.store.ingest_gateway_state(state.clone()).await;
    } else {
        tracing::warn!(
            reason = %reason,
            "Skipping store ingestion due to partial list failures; \
             store remains not-ready for future fallback retries"
        );
    }

    // Generate and apply config from whatever we got (preserves existing behavior).
    apply_from_gateway_state(ctx, state).await?;

    tracing::debug!(reason = %reason, "Configuration update completed (API-list fallback path)");
    Ok(())
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
