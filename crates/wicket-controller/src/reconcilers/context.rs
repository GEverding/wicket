//! Shared context for reconcilers.
//!
//! ## Config regeneration flow
//!
//! Config generation is split into a pure planning step and a side-effecting
//! apply step:
//!
//! ```text
//!   GatewayState (from store snapshot)
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
//! `trigger_config_update` reads the shared store snapshot. If the store is
//! still warming up, the update is skipped and the next reconcile retries.

use std::sync::Arc;

use kube::Client;
use tokio::sync::RwLock;

use super::config_applier::{apply_config_plan, read_current_config_hash, ConfigApplierInput};
use super::config_generator::{GatewayState, WicketConfig};
use super::config_planner::{GlobalConfigPlanInput, GlobalConfigPlanner};
use super::store::SharedStore;
use crate::crds::WICKET_CONTROLLER_NAME;
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

/// Trigger a configuration update from the shared store snapshot.
pub async fn trigger_config_update(ctx: &Context, reason: &str) -> Result<(), ConfigUpdateError> {
    tracing::debug!(reason = %reason, "Triggering configuration update");

    let state = match ctx.store.snapshot().await {
        Some(state) => state,
        None => {
            tracing::debug!(
                reason = %reason,
                "Store snapshot not available; skipping config update (will retry)"
            );
            return Ok(());
        }
    };

    apply_from_gateway_state(ctx, state).await?;
    tracing::debug!(reason = %reason, "Configuration update completed");
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal: plan + apply from a GatewayState
// ─────────────────────────────────────────────────────────────────────────────

/// Plan and apply config from a `GatewayState`.
///
/// This is the shared inner step used by `trigger_config_update`.
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
