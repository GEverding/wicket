//! Config applier: applies a `ConfigPlan` to the cluster and in-memory state.
//!
//! # Overview
//!
//! This module contains the *apply* half of config regeneration.  It consumes
//! a `ConfigPlan` produced by `GlobalConfigPlanner` (or any other planner that
//! emits `ConfigPlan`) and performs the side-effecting steps:
//!
//! 1. Patch the Kubernetes ConfigMap with the new TOML content.
//! 2. Persist the config hash as the annotation `wicket.io/config-revision`
//!    on the ConfigMap so revision semantics exist end-to-end.
//! 3. Update the in-memory `WicketConfig` held by `Context`.
//! 4. Increment Prometheus metrics.
//!
//! # Invariants
//!
//! - The applier is idempotent: applying the same `ConfigPlan::Update` twice
//!   produces no observable change on the second call (server-side apply
//!   semantics via `Patch::Merge`).
//! - The applier does not re-read the store or re-generate config.  It only
//!   reads the plan it was given.
//! - `ConfigPlan::NoOp` skips the ConfigMap patch but still syncs the
//!   in-memory `WicketConfig` from the plan content so that a process restart
//!   (which clears the in-memory view) does not leave the view stale.

use std::collections::BTreeMap;

use k8s_openapi::api::core::v1::ConfigMap;
use kube::api::{Api, Patch, PatchParams};
use kube::Client;

use crate::reconcilers::config_generator::WicketConfig;
use crate::reconcilers::contracts::{ApplyError, ConfigApplyResult, ConfigPlan};

/// Annotation key used to persist the config hash on the ConfigMap.
pub const CONFIG_REVISION_ANNOTATION: &str = "wicket.io/config-revision";

// ─────────────────────────────────────────────────────────────────────────────
// Hash reader
// ─────────────────────────────────────────────────────────────────────────────

/// Read the current `wicket.io/config-revision` annotation from the ConfigMap.
///
/// Returns `Ok(Some(hash))` when the annotation is present, `Ok(None)` when
/// the ConfigMap exists but the annotation is absent or the ConfigMap does not
/// yet exist, and `Err(ApplyError::KubeApi)` on a hard API error.
///
/// This is used by `context.rs` to wire the live hash into the planner so
/// that `ConfigPlan::NoOp` can fire when the cluster is already up-to-date.
pub async fn read_current_config_hash(
    client: &Client,
    configmap_name: &str,
    configmap_namespace: &str,
) -> Result<Option<String>, ApplyError> {
    let api: Api<ConfigMap> = Api::namespaced(client.clone(), configmap_namespace);
    match api.get(configmap_name).await {
        Ok(cm) => {
            let hash = cm
                .metadata
                .annotations
                .as_ref()
                .and_then(|a| a.get(CONFIG_REVISION_ANNOTATION))
                .cloned();
            Ok(hash)
        }
        Err(kube::Error::Api(ae)) if ae.code == 404 => Ok(None),
        Err(e) => Err(ApplyError::KubeApi(e.to_string())),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Applier input
// ─────────────────────────────────────────────────────────────────────────────

/// Everything the config applier needs to apply a `ConfigPlan`.
///
/// Keeping these as explicit fields (rather than a `&Context` reference) makes
/// the applier boundary clear and testable without constructing a full
/// `Context`.
pub struct ConfigApplierInput<'a> {
    /// Kubernetes client for ConfigMap patches.
    pub client: &'a Client,
    /// Name of the ConfigMap to patch.
    pub configmap_name: &'a str,
    /// Namespace of the ConfigMap.
    pub configmap_namespace: &'a str,
    /// In-memory config handle.  Updated after a successful ConfigMap patch.
    pub in_memory_config: &'a tokio::sync::RwLock<WicketConfig>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Applier
// ─────────────────────────────────────────────────────────────────────────────

/// Apply a `ConfigPlan` to the cluster and in-memory state.
///
/// ## Steps (for `ConfigPlan::Update`)
///
/// 1. Deserialize `toml_content` back into `WicketConfig` so the in-memory
///    state stays in sync with the ConfigMap.
/// 2. Patch the ConfigMap `data` and the `wicket.io/config-revision` annotation
///    via `Patch::Merge`.
/// 3. Update the in-memory `WicketConfig`.
/// 4. Increment Prometheus metrics.
///
/// ## `ConfigPlan::NoOp`
///
/// Skips the ConfigMap patch but still deserializes `toml_content` and syncs
/// the in-memory `WicketConfig`.  This ensures that a process restart (which
/// clears the in-memory view) does not leave the view stale when the ConfigMap
/// is already current.
///
/// # Errors
///
/// Returns `ApplyError` when the ConfigMap patch fails or TOML deserialization
/// fails.  The in-memory state is only updated after a successful patch (for
/// `Update`) so that it never diverges from the ConfigMap.
pub async fn apply_config_plan(
    plan: &ConfigPlan,
    input: &ConfigApplierInput<'_>,
) -> Result<ConfigApplyResult, ApplyError> {
    match plan {
        // ── NoOp: skip the patch but sync in-memory view ──────────────────────
        ConfigPlan::NoOp {
            toml_content,
            config_hash,
        } => {
            // Deserialize and sync so a post-restart in-memory view is correct.
            let synced: WicketConfig = toml::from_str(toml_content)
                .map_err(|e| ApplyError::Serialization(e.to_string()))?;
            {
                let mut current = input.in_memory_config.write().await;
                *current = synced;
            }
            tracing::debug!(
                configmap = %input.configmap_name,
                config_hash = %config_hash,
                "Config no-op: ConfigMap already at desired revision; in-memory view synced"
            );
            Ok(ConfigApplyResult::NoOp)
        }

        // ── Update: patch ConfigMap + annotation + in-memory view ─────────────
        ConfigPlan::Update {
            toml_content,
            config_hash,
        } => {
            // ── 1. Deserialize TOML -> WicketConfig ───────────────────────────
            // We deserialize here (rather than accepting a WicketConfig directly)
            // so that the applier boundary is purely `ConfigPlan`-typed and the
            // planner does not need to carry a WicketConfig alongside the TOML.
            let new_config: WicketConfig = toml::from_str(toml_content)
                .map_err(|e| ApplyError::Serialization(e.to_string()))?;

            // ── 2. Patch the ConfigMap (data + revision annotation) ───────────
            let api: Api<ConfigMap> =
                Api::namespaced(input.client.clone(), input.configmap_namespace);

            let mut data = BTreeMap::new();
            data.insert("wicket.toml".to_string(), toml_content.clone());

            let mut annotations = BTreeMap::new();
            annotations.insert(CONFIG_REVISION_ANNOTATION.to_string(), config_hash.clone());

            let patch = serde_json::json!({
                "metadata": { "annotations": annotations },
                "data": data,
            });

            let patch_result = api
                .patch(
                    input.configmap_name,
                    &PatchParams::apply("wicket-controller"),
                    &Patch::Merge(&patch),
                )
                .await;

            match patch_result {
                Ok(_) => {
                    // ── 3. Update in-memory config ────────────────────────────
                    {
                        let mut current = input.in_memory_config.write().await;
                        *current = new_config;
                    }

                    // ── 4. Update metrics ─────────────────────────────────────
                    crate::metrics::CONFIG_UPDATES_TOTAL
                        .with_label_values(&["success"])
                        .inc();
                    crate::metrics::CONFIG_LAST_UPDATE_TIMESTAMP
                        .set(chrono::Utc::now().timestamp());
                    crate::metrics::CONFIG_GENERATION.inc();

                    tracing::info!(
                        configmap = %input.configmap_name,
                        namespace = %input.configmap_namespace,
                        config_hash = %config_hash,
                        "Configuration applied to ConfigMap"
                    );

                    Ok(ConfigApplyResult::Updated {
                        config_hash: config_hash.clone(),
                    })
                }
                Err(kube::Error::Api(ae)) if ae.code == 404 => {
                    // Central ConfigMap doesn't exist — likely running in
                    // managed-runtime-only mode where per-Gateway ConfigMaps
                    // are used instead.  Sync in-memory config so generation
                    // metrics still work, but skip the patch silently.
                    {
                        let mut current = input.in_memory_config.write().await;
                        *current = new_config;
                    }
                    tracing::debug!(
                        configmap = %input.configmap_name,
                        namespace = %input.configmap_namespace,
                        "Central ConfigMap not found; skipping (managed-runtime-only mode?)"
                    );
                    Ok(ConfigApplyResult::NoOp)
                }
                Err(e) => Err(ApplyError::KubeApi(e.to_string())),
            }
        }
    }
}
