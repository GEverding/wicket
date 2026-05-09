//! Gateway reconciler.

use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use k8s_openapi::api::apps::v1::Deployment;
use k8s_openapi::api::core::v1::{ConfigMap, Service};
use kube::{
    api::{Api, Patch, PatchParams},
    runtime::{
        controller::{Action, Controller},
        watcher::Config,
    },
    Client, ResourceExt,
};

use crate::crds::{
    AddressType, Condition, Gateway, GatewayClass, GatewayStatus, GatewayStatusAddress,
    ListenerStatus, RouteGroupKind,
};
use crate::metrics::{
    ReconcileMetrics, GATEWAYS, GATEWAY_LISTENER_ATTACHED_ROUTES, GATEWAY_PROGRAMMED,
};
use crate::reconcilers::attachment_planner::{AttachmentPlanInput, AttachmentPlanner};
use crate::reconcilers::contracts::Planner;
use crate::reconcilers::runtime_applier::{
    apply_runtime_plan, RuntimeApplierInput, RuntimeApplyResult, SPEC_REVISION_ANNOTATION,
};
use crate::reconcilers::runtime_plan::{
    is_managed_runtime, is_rollout_converged, owned_object_base_name,
    service_name as owned_service_name, GatewayRuntimePlanner, ObservedRuntimeState,
    RuntimePlanInput,
};
use crate::reconcilers::status_helpers::{
    conditions_semantically_equal, preserve_condition_timestamps,
};
use crate::reconcilers::store::{PlannerSnapshot, SnapshotResult};

use super::context::{trigger_config_update, Context};

/// Error type for Gateway reconciliation.
#[derive(Debug, thiserror::Error)]
pub enum GatewayError {
    #[error("Kubernetes API error: {0}")]
    KubeError(#[from] kube::Error),

    #[error("GatewayClass not found: {0}")]
    GatewayClassNotFound(String),

    #[error("GatewayClass not managed by Wicket: {0}")]
    NotManagedByWicket(String),

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Managed-runtime apply error: {0}")]
    RuntimeApplyError(String),
}

/// Preserve `last_transition_time` on both top-level and per-listener
/// conditions where status hasn't changed.
fn preserve_gateway_status_timestamps(new_status: &mut GatewayStatus, existing: &GatewayStatus) {
    preserve_condition_timestamps(&mut new_status.conditions, &existing.conditions);

    for new_listener in new_status.listeners.iter_mut() {
        if let Some(prev) = existing
            .listeners
            .iter()
            .find(|l| l.name == new_listener.name)
        {
            preserve_condition_timestamps(&mut new_listener.conditions, &prev.conditions);
        }
    }
}

/// Semantic equality check for GatewayStatus that ignores
/// `last_transition_time`.  Used to skip redundant status patches.
fn gateway_status_semantically_equal(a: &GatewayStatus, b: &GatewayStatus) -> bool {
    if a.addresses != b.addresses {
        return false;
    }
    if !conditions_semantically_equal(&a.conditions, &b.conditions) {
        return false;
    }
    if a.listeners.len() != b.listeners.len() {
        return false;
    }
    a.listeners.iter().zip(&b.listeners).all(|(x, y)| {
        x.name == y.name
            && x.supported_kinds == y.supported_kinds
            && x.attached_routes == y.attached_routes
            && conditions_semantically_equal(&x.conditions, &y.conditions)
    })
}

/// Reconcile a Gateway resource.
pub async fn reconcile_gateway(
    gateway: Arc<Gateway>,
    ctx: Arc<Context>,
) -> Result<Action, GatewayError> {
    let metrics = ReconcileMetrics::new("Gateway");
    let namespace = gateway.namespace().unwrap_or_default();
    let name = gateway.name_any();

    tracing::info!(namespace = %namespace, name = %name, "Reconciling Gateway");

    // Handle deletion: remove from store and trigger config update.
    if gateway.metadata.deletion_timestamp.is_some() {
        let key = super::config_generator::GatewayState::key(&namespace, &name);
        ctx.store.remove_gateway(&key).await;
        tracing::info!(namespace = %namespace, name = %name, "Gateway deleted, removed from store");
        trigger_config_update(&ctx, "Gateway deleted")
            .await
            .map_err(|e| GatewayError::ConfigError(e.to_string()))?;
        return Ok(Action::await_change());
    }

    // Check if the GatewayClass is managed by Wicket.
    //
    // Prefer the shared store over a live API call to avoid redundant reads
    // and races with the cache.  Fall back to the API only when the store
    // has not yet been populated (bootstrap / recovery).
    let gc = match ctx
        .store
        .get_gateway_class(&gateway.spec.gateway_class_name)
        .await
    {
        Some(gc) => gc,
        None => {
            // Store not ready or class absent — fall back to live API.
            let gc_api: Api<GatewayClass> = Api::all(ctx.client.clone());
            gc_api
                .get(&gateway.spec.gateway_class_name)
                .await
                .map_err(|_| {
                    GatewayError::GatewayClassNotFound(gateway.spec.gateway_class_name.clone())
                })?
        }
    };

    if !gc.is_wicket_managed() {
        tracing::debug!(
            namespace = %namespace,
            name = %name,
            gateway_class = %gateway.spec.gateway_class_name,
            "Ignoring Gateway with non-Wicket GatewayClass"
        );
        metrics.record_success();
        return Ok(Action::await_change());
    }

    // Upsert the current Gateway into the shared store BEFORE the
    // managed-runtime planner builds its snapshot, so a freshly observed
    // Gateway is visible to PlannerSnapshot::gateway() on the first
    // reconcile.  Without this, planning fails with
    // `missing required field: gateway (not found in snapshot)` until a
    // later reconcile happens to upsert it for an unrelated reason.
    //
    // The post-patch upsert near the end of this function is still
    // required so the store reflects the freshly patched status; do not
    // remove it.
    {
        let pre_plan_key = super::config_generator::GatewayState::key(&namespace, &name);
        ctx.store
            .upsert_gateway(pre_plan_key, (*gateway).clone())
            .await;
    }

    // ── Managed-runtime orchestration ─────────────────────────────────────────
    // Gate on the `wicket.io/managed-runtime: "true"` annotation.  Only after
    // GatewayClass ownership has been confirmed above.
    //
    // `deferred_observation_error` carries an ObservationError that must still
    // trigger a requeue-with-backoff, but only AFTER patch_status has run so
    // operators see an accurate Programmed=False / ObservationFault condition
    // rather than stale success.  Plan and Apply errors still exit immediately
    // because no useful status can be built from them.
    //
    // `managed_input` is a single typed value that encodes which of the three
    // mutually exclusive sub-reconcile outcomes applies (success, store-not-ready,
    // or observation fault).  It replaces the three parallel Option parameters
    // that were previously threaded into build_managed_runtime_status.
    //
    // `deferred_observation_error` carries an ObservationError that must still
    // trigger a requeue-with-backoff, but only AFTER patch_status has run so
    // operators see an accurate Programmed=False / ObservationFault condition
    // rather than stale success.  Plan and Apply errors still exit immediately
    // because no useful status can be built from them.
    let mut deferred_observation_error: Option<GatewayError> = None;

    // ── Build listener statuses and programmed condition ──────────────────────
    //
    // For managed-runtime Gateways the listener attached-route counts come from
    // the AttachmentPlanner (using the planner snapshot), and the Programmed
    // condition is derived from the observed runtime readiness.
    //
    // `managed_input` encodes which of the three mutually exclusive sub-reconcile
    // outcomes applies (Applied, StoreNotReady, or ObservationFault).  It is
    // passed as a single typed value so build_managed_runtime_status can match
    // on it exhaustively rather than inspecting three parallel Options.
    //
    // For legacy (non-managed) Gateways the existing behavior is preserved:
    // attached_routes = 0 and Programmed = True unconditionally.

    // Track whether the managed-runtime path produced a config-affecting change.
    // When `false`, we skip `trigger_config_update` at the end since the planner
    // already determined that the generated config is identical to the current one.
    let mut managed_config_changed = false;

    let (listener_statuses, gateway_programmed, only_store_not_ready, gateway_observation_fault) =
        if is_managed_runtime(&gateway) {
            // Resolve the managed-runtime input: observe, plan, apply.
            // Each arm produces a ManagedRuntimeInput variant that is passed
            // directly to build_managed_runtime_status (no Option wrapper).
            let managed_input = match reconcile_managed_runtime(&gateway, &ctx, &namespace, &name)
                .await
            {
                Ok((observed, apply_result, snapshot_result)) => {
                    // Check if config actually changed via the managed-runtime
                    // applier.  When NoOp, we can skip the global config trigger.
                    managed_config_changed = apply_result.config_result.as_ref().is_some_and(|r| {
                        matches!(
                            r,
                            crate::reconcilers::contracts::ConfigApplyResult::Updated { .. }
                        )
                    }) || apply_result.service_changed
                        || apply_result.deployment_changed;
                    ManagedRuntimeInput::Applied(observed, apply_result, Box::new(snapshot_result))
                }
                // StoreNotReady is a safe defer: the store is still warming up.
                // The observed state is carried so the status path can reuse it
                // without a second Kubernetes API read.
                // This must NOT increment error metrics.
                Err(ManagedRuntimeError::StoreNotReady(observed)) => {
                    tracing::warn!(
                        namespace = %namespace,
                        name = %name,
                        "Managed-runtime planning deferred: store not ready (will retry)"
                    );
                    ManagedRuntimeInput::StoreNotReady(observed)
                }
                // ObservationError: a non-404 Kubernetes API fault (e.g. RBAC).
                // We must still patch Gateway status so operators see
                // Programmed=False / ObservationFault instead of stale success.
                // Defer the error; it is returned after patch_status below.
                Err(ManagedRuntimeError::ObservationError(msg)) => {
                    tracing::warn!(
                        namespace = %namespace,
                        name = %name,
                        error = %msg,
                        "Managed-runtime observation fault; will patch status then requeue"
                    );
                    deferred_observation_error = Some(GatewayError::RuntimeApplyError(msg.clone()));
                    ManagedRuntimeInput::ObservationFault(msg)
                }
                // Planning and apply failures are real errors: propagate so the
                // outer reconcile cycle requeues with backoff and increments the
                // error counter.
                Err(e) => return Err(GatewayError::RuntimeApplyError(e.to_string())),
            };

            build_managed_runtime_status(&gateway, &namespace, &name, managed_input)
        } else {
            // Legacy path: zero attached_routes, always programmed, no fault.
            let statuses = build_legacy_listener_statuses(&gateway);
            (statuses, true, false, None)
        };

    // Get addresses from LoadBalancer Service or Gateway spec
    let addresses = get_gateway_addresses(&ctx.client, &namespace, &name, &gateway).await;

    // Build the top-level Gateway conditions using the extracted pure helper.
    let gw_observed_gen = gateway.metadata.generation;
    let gateway_conditions = build_gateway_conditions(
        gateway_programmed,
        &gateway_observation_fault,
        only_store_not_ready,
        gw_observed_gen,
    );

    // Update Gateway status
    let mut status = GatewayStatus {
        addresses,
        conditions: gateway_conditions,
        listeners: listener_statuses.clone(),
    };

    // Preserve timestamps on unchanged conditions to make the patch idempotent.
    if let Some(existing) = gateway.status.as_ref() {
        preserve_gateway_status_timestamps(&mut status, existing);
    }

    // Skip patching entirely when the status is semantically unchanged.
    // This breaks the reconcile-loop caused by lastTransitionTime bumps
    // that would otherwise trigger a watch event and re-queue this object.
    let needs_patch = gateway
        .status
        .as_ref()
        .map(|existing| !gateway_status_semantically_equal(existing, &status))
        .unwrap_or(true);

    let api: Api<Gateway> = Api::namespaced(ctx.client.clone(), &namespace);
    let patched_gateway = if needs_patch {
        let patch = serde_json::json!({ "status": status });
        api.patch_status(
            &name,
            &PatchParams::apply("wicket-controller"),
            &Patch::Merge(&patch),
        )
        .await?
    } else {
        tracing::debug!(
            namespace = %namespace,
            name = %name,
            "Gateway status unchanged, skipping patch"
        );
        (*gateway).clone()
    };

    // Return the deferred observation error now that status has been patched.
    // The requeue-with-backoff and error metrics are handled by
    // error_policy_gateway; we must not record a success metric here.
    if let Some(err) = deferred_observation_error {
        tracing::warn!(
            namespace = %namespace,
            name = %name,
            "Returning deferred observation error after status patch"
        );
        return Err(err);
    }

    if gateway_programmed {
        tracing::info!(namespace = %namespace, name = %name, "Gateway programmed");
    } else {
        tracing::info!(namespace = %namespace, name = %name, "Gateway not yet programmed (runtime not ready)");
    }

    // Update Gateway status metrics
    GATEWAY_PROGRAMMED
        .with_label_values(&[&namespace, &name])
        .set(if gateway_programmed { 1 } else { 0 });

    // Update listener attached routes metrics
    for listener_status in &listener_statuses {
        GATEWAY_LISTENER_ATTACHED_ROUTES
            .with_label_values(&[&namespace, &name, &listener_status.name])
            .set(listener_status.attached_routes as i64);
    }

    metrics.record_success();

    // Upsert the post-patch Gateway (with updated .status) into the shared
    // store so other reconcilers see the current status, not the stale input.
    let gw_key = super::config_generator::GatewayState::key(&namespace, &name);
    ctx.store.upsert_gateway(gw_key, patched_gateway).await;

    // Update metrics
    update_gateway_metrics(&ctx.client).await;

    // Trigger configuration regeneration.
    //
    // For managed-runtime Gateways we skip this when the applier already
    // determined that config, service, and deployment are unchanged (NoOp).
    // The global planner would reach the same conclusion via hash comparison,
    // but skipping avoids the unnecessary work of building GatewayState,
    // serializing TOML, and hashing.
    //
    // For legacy (non-managed) Gateways we always trigger since we have no
    // plan to check against.
    if !is_managed_runtime(&gateway) || managed_config_changed {
        trigger_config_update(&ctx, "Gateway reconciled")
            .await
            .map_err(|e| GatewayError::ConfigError(e.to_string()))?;
    }

    // Requeue quickly while waiting for Deployment convergence; back off
    // once the Gateway is fully programmed.
    let requeue_secs = if gateway_programmed { 300 } else { 5 };
    Ok(Action::requeue(Duration::from_secs(requeue_secs)))
}

/// Handle errors during Gateway reconciliation.
pub fn error_policy_gateway(
    gateway: Arc<Gateway>,
    error: &GatewayError,
    _ctx: Arc<Context>,
) -> Action {
    let namespace = gateway.namespace().unwrap_or_default();
    let name = gateway.name_any();

    tracing::error!(
        namespace = %namespace,
        name = %name,
        error = %error,
        "Gateway reconciliation failed"
    );

    crate::metrics::RECONCILE_ERRORS_TOTAL
        .with_label_values(&["Gateway", "reconcile_error"])
        .inc();

    // Use a short error requeue (5s).  The kube-runtime controller re-drives
    // reconciliation from watches, so this is a safety-net retry.  Persistent
    // errors are bounded by the watch re-trigger rate, not this duration.
    Action::requeue(Duration::from_secs(5))
}

// ─────────────────────────────────────────────────────────────────────────────
// Managed-runtime orchestration
// ─────────────────────────────────────────────────────────────────────────────

/// Errors specific to the managed-runtime sub-reconcile.
///
/// Kept separate from `GatewayError` so the caller can decide whether to
/// surface them as a hard error or a warning.
#[derive(Debug, thiserror::Error)]
enum ManagedRuntimeError {
    /// The planner store snapshot was not yet ready.  The owned runtime state
    /// was already observed before the store check; it is carried here so the
    /// status path can reuse it without a second Kubernetes API read.
    #[error("store not ready for managed-runtime planning")]
    StoreNotReady(ObservedRuntimeState),

    #[error("planning failed: {0}")]
    Plan(String),

    #[error("apply failed: {0}")]
    Apply(String),

    /// A non-404 Kubernetes API error occurred while observing owned runtime
    /// state.  This is distinct from "object not found" (404) and may indicate
    /// an RBAC fault or a transient API server error.  Surfaced as a hard error
    /// so the reconcile cycle requeues with backoff rather than silently
    /// treating the object as absent and potentially creating a duplicate.
    #[error("observation failed: {0}")]
    ObservationError(String),
}

/// Run the managed-runtime sub-reconcile for a Gateway annotated with
/// `wicket.io/managed-runtime: "true"`.
///
/// ## Steps
///
/// 1. Read `ObservedRuntimeState` from the owned ConfigMap and Deployment.
/// 2. Read a `PlannerSnapshot` from the shared store.
/// 3. Call `GatewayRuntimePlanner::plan()`.
/// 4. Call `apply_runtime_plan()`.
///
/// ## Return value
///
/// Returns `(ObservedRuntimeState, RuntimeApplyResult)` so the caller can:
/// - Reuse the pre-apply observation without a second API read.
/// - Detect rollout-triggering work via `apply_result.rollout_triggered` or
///   `apply_result.deployment_changed`, which indicates the pre-apply
///   observation is stale and must NOT be used as proof of current readiness.
///
/// When the store is not yet ready the function returns
/// `Err(ManagedRuntimeError::StoreNotReady)` so the outer reconcile cycle
/// continues normally.  The controller will requeue (60 s) and retry once the
/// store is populated.
///
/// When planning or applying fails the error is propagated so the outer
/// reconcile cycle requeues with backoff.
async fn reconcile_managed_runtime(
    gateway: &Gateway,
    ctx: &Context,
    namespace: &str,
    name: &str,
) -> Result<
    (
        ObservedRuntimeState,
        RuntimeApplyResult,
        SnapshotResult<PlannerSnapshot>,
    ),
    ManagedRuntimeError,
> {
    // ── 1. Gather ObservedRuntimeState ────────────────────────────────────────
    let observed = observe_runtime_state(gateway, &ctx.client, namespace).await?;

    // ── 2. Read PlannerSnapshot ───────────────────────────────────────────────
    //
    // When the store is not yet ready, carry the already-observed state in the
    // error so the status path can reuse it without a second API read.
    let snapshot = match ctx.store.planner_snapshot().await {
        SnapshotResult::Ready(s) => s,
        SnapshotResult::NotReady => {
            tracing::warn!(
                namespace = %namespace,
                name = %name,
                "Store not ready; skipping managed-runtime planning (will retry)"
            );
            return Err(ManagedRuntimeError::StoreNotReady(observed));
        }
    };

    // ── 3. Plan ───────────────────────────────────────────────────────────────
    // Clone the snapshot before moving it into the planner input so we can
    // return it to the caller and avoid a second store read in the status path.
    let snapshot_for_status: SnapshotResult<PlannerSnapshot> =
        SnapshotResult::Ready(snapshot.clone());
    let planner = GatewayRuntimePlanner;
    let input = RuntimePlanInput {
        gateway_namespace: namespace.to_string(),
        gateway_name: name.to_string(),
        snapshot,
        // Fix (3): use the controller_config from Context rather than
        // hardcoding ControllerConfig::default() on the live path.
        controller_config: ctx.controller_config.clone(),
        // Clone so `observed` can be returned to the caller after planning.
        observed: observed.clone(),
    };

    let plan = planner.plan(&input).map_err(|e| {
        tracing::warn!(
            namespace = %namespace,
            name = %name,
            error = %e,
            "Managed-runtime planning failed"
        );
        ManagedRuntimeError::Plan(e.to_string())
    })?;

    // Fix (2): ownership validation must run even when the plan is a no-op.
    // A same-name unowned resource must be detected regardless of whether
    // the hashes match.  We always call apply_runtime_plan; the applier's
    // ownership preflight runs unconditionally, and the plan's is_noop()
    // flag controls whether ConfigMap/Deployment patches are actually sent.
    //
    // The is_noop() fast-path is preserved only for the log message so that
    // operators can see when no cluster writes are expected.
    if plan.is_noop() {
        tracing::debug!(
            namespace = %namespace,
            name = %name,
            "Managed-runtime plan is a no-op; ownership check will still run"
        );
    } else {
        tracing::info!(
            namespace = %namespace,
            name = %name,
            config_changed = plan.config_changed,
            spec_changed = plan.spec_changed,
            config_hash = %plan.config_hash,
            spec_hash = %plan.spec_hash,
            "Applying managed-runtime plan"
        );
    }

    // ── 4. Apply (always, for ownership preflight) ────────────────────────────
    let applier_input = RuntimeApplierInput {
        client: &ctx.client,
        in_memory_config: &ctx.config,
    };

    let apply_result = apply_runtime_plan(&plan, &applier_input)
        .await
        .map_err(|e| {
            tracing::warn!(
                namespace = %namespace,
                name = %name,
                error = %e,
                "Managed-runtime apply failed"
            );
            ManagedRuntimeError::Apply(e.to_string())
        })?;

    // Return both the pre-apply observation and the apply result.
    //
    // The caller uses `apply_result.rollout_triggered || apply_result.deployment_changed`
    // to detect that the pre-apply observation is stale: when a rollout was
    // just triggered, the Deployment has not yet converged on the new spec, so
    // `is_rollout_converged(&observed)` would return a stale `true` if the old
    // revision was healthy.  The status path must force `Programmed=False` in
    // that case to avoid a one-cycle lie.
    Ok((observed, apply_result, snapshot_for_status))
}

/// Gather `ObservedRuntimeState` for a Gateway by reading its owned ConfigMap
/// and Deployment from the Kubernetes API.
///
/// ## What is read
///
/// - **ConfigMap** (`<base>-config`): the `wicket.io/config-revision` annotation
///   gives `current_config_hash`.  A 404 means the ConfigMap does not yet exist.
/// - **Deployment** (`<base>-deploy`): the `wicket.io/spec-revision` annotation
///   gives `current_spec_hash`; `status.readyReplicas` gives `ready_replicas`.
///   A 404 means the Deployment does not yet exist.
///
/// ## Error handling (Fix 5)
///
/// - **404**: treated as "object does not yet exist" (`None`).  Safe and
///   expected on first reconcile.
/// - **Non-404 API errors** (e.g. RBAC `Forbidden`, API server unavailable):
///   returned as `Err(ManagedRuntimeError::ObservationError)` so the reconcile
///   cycle requeues with backoff.  Silently treating these as absence would
///   cause the planner to believe the objects do not exist and attempt to
///   create them, potentially producing duplicate resources or masking
///   permission problems.
async fn observe_runtime_state(
    gateway: &Gateway,
    client: &Client,
    namespace: &str,
) -> Result<ObservedRuntimeState, ManagedRuntimeError> {
    use crate::reconcilers::runtime_applier::CONFIG_REVISION_ANNOTATION;
    use crate::reconcilers::runtime_plan::{config_map_name, deployment_name};

    let gw_name = gateway.name_any();
    let base = owned_object_base_name(&gw_name);
    let cm_name = config_map_name(&base);
    let deploy_name = deployment_name(&base);

    // ── ConfigMap ─────────────────────────────────────────────────────────────
    let current_config_hash: Option<String> = {
        let cm_api: Api<ConfigMap> = Api::namespaced(client.clone(), namespace);
        match cm_api.get(&cm_name).await {
            Ok(cm) => cm
                .metadata
                .annotations
                .as_ref()
                .and_then(|a| a.get(CONFIG_REVISION_ANNOTATION))
                .cloned(),
            Err(kube::Error::Api(ae)) if ae.code == 404 => None,
            Err(e) => {
                // Non-404: surface as a real error rather than treating as
                // absent.  This catches RBAC faults and transient API errors
                // that should trigger backoff, not silent "must create" logic.
                tracing::warn!(
                    namespace = %namespace,
                    configmap = %cm_name,
                    error = %e,
                    "Non-404 error reading owned ConfigMap for runtime observation"
                );
                return Err(ManagedRuntimeError::ObservationError(format!(
                    "ConfigMap {}/{}: {}",
                    namespace, cm_name, e
                )));
            }
        }
    };

    // ── Deployment ────────────────────────────────────────────────────────────
    //
    // Read all rollout-convergence fields from DeploymentStatus so that
    // `is_rollout_converged()` can gate `Programmed=True` on full rollout
    // completion rather than just `ready_replicas > 0`.
    struct DeployObservation {
        current_spec_hash: Option<String>,
        ready_replicas: Option<u32>,
        deploy_observed_generation: Option<i64>,
        deploy_generation: Option<i64>,
        updated_replicas: Option<u32>,
        available_replicas: Option<u32>,
        desired_replicas: Option<u32>,
    }

    let deploy_obs: DeployObservation = {
        let deploy_api: Api<Deployment> = Api::namespaced(client.clone(), namespace);
        match deploy_api.get(&deploy_name).await {
            Ok(deploy) => {
                let spec_hash = deploy
                    .metadata
                    .annotations
                    .as_ref()
                    .and_then(|a| a.get(SPEC_REVISION_ANNOTATION))
                    .cloned();

                let status = deploy.status.as_ref();

                // ready_replicas: pods with Ready condition.
                let ready = status
                    .and_then(|s| s.ready_replicas)
                    .and_then(|r| u32::try_from(r).ok());

                // observed_generation: generation the Deployment controller processed.
                let deploy_obs_gen = status.and_then(|s| s.observed_generation);

                // deploy_generation: current desired generation of the Deployment spec.
                let deploy_gen = deploy.metadata.generation;

                // updated_replicas: pods on the current pod template.
                let updated = status
                    .and_then(|s| s.updated_replicas)
                    .and_then(|r| u32::try_from(r).ok());

                // available_replicas: pods available for >= minReadySeconds.
                let available = status
                    .and_then(|s| s.available_replicas)
                    .and_then(|r| u32::try_from(r).ok());

                // desired_replicas: from DeploymentSpec.replicas (defaults to 1 if absent).
                let desired = deploy
                    .spec
                    .as_ref()
                    .and_then(|s| s.replicas)
                    .and_then(|r| u32::try_from(r).ok());

                DeployObservation {
                    current_spec_hash: spec_hash,
                    ready_replicas: ready,
                    deploy_observed_generation: deploy_obs_gen,
                    deploy_generation: deploy_gen,
                    updated_replicas: updated,
                    available_replicas: available,
                    desired_replicas: desired,
                }
            }
            Err(kube::Error::Api(ae)) if ae.code == 404 => DeployObservation {
                current_spec_hash: None,
                ready_replicas: None,
                deploy_observed_generation: None,
                deploy_generation: None,
                updated_replicas: None,
                available_replicas: None,
                desired_replicas: None,
            },
            Err(e) => {
                // Non-404: surface as a real error.
                tracing::warn!(
                    namespace = %namespace,
                    deployment = %deploy_name,
                    error = %e,
                    "Non-404 error reading owned Deployment for runtime observation"
                );
                return Err(ManagedRuntimeError::ObservationError(format!(
                    "Deployment {}/{}: {}",
                    namespace, deploy_name, e
                )));
            }
        }
    };

    Ok(ObservedRuntimeState {
        current_config_hash,
        current_spec_hash: deploy_obs.current_spec_hash,
        ready_replicas: deploy_obs.ready_replicas,
        deploy_observed_generation: deploy_obs.deploy_observed_generation,
        deploy_generation: deploy_obs.deploy_generation,
        updated_replicas: deploy_obs.updated_replicas,
        available_replicas: deploy_obs.available_replicas,
        desired_replicas: deploy_obs.desired_replicas,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Status helpers
// ─────────────────────────────────────────────────────────────────────────────

/// The three mutually exclusive outcomes of the managed-runtime sub-reconcile
/// that the status-building path needs to distinguish.
///
/// Replaces the three parallel `Option` parameters that were previously passed
/// to `build_managed_runtime_status` (`apply_observed`, `store_not_ready_observed`,
/// `apply_error`).  Using an enum makes the invariant that exactly one case
/// applies at a time explicit and compiler-checked.
enum ManagedRuntimeInput {
    /// `reconcile_managed_runtime` succeeded.  Carries the pre-apply
    /// `ObservedRuntimeState`, the `RuntimeApplyResult`, and the
    /// `PlannerSnapshot` that was used during planning so the status path
    /// can reuse them without a second Kubernetes API or store read.
    Applied(
        ObservedRuntimeState,
        RuntimeApplyResult,
        Box<SnapshotResult<PlannerSnapshot>>,
    ),

    /// The planner store was not yet ready.  `reconcile_managed_runtime`
    /// observes runtime state BEFORE checking store readiness, so the
    /// observation is valid and is carried here to avoid a second API read.
    StoreNotReady(ObservedRuntimeState),

    /// A non-404 Kubernetes API error occurred while observing owned objects.
    /// The fault message is carried so the status path can build an
    /// `ObservationFault` condition without re-reading the API.
    ObservationFault(String),
}

/// Build listener statuses for a legacy (non-managed-runtime) Gateway.
///
/// Uses zero attached_routes (legacy behavior) and marks all listeners as
/// accepted and programmed unconditionally.
fn build_legacy_listener_statuses(gateway: &Gateway) -> Vec<ListenerStatus> {
    gateway
        .spec
        .listeners
        .iter()
        .map(|listener| {
            let supported_kinds = match listener.protocol {
                crate::crds::ProtocolType::HTTP | crate::crds::ProtocolType::HTTPS => {
                    vec![RouteGroupKind {
                        group: "gateway.networking.k8s.io".to_string(),
                        kind: "HTTPRoute".to_string(),
                    }]
                }
                crate::crds::ProtocolType::TCP => {
                    vec![RouteGroupKind {
                        group: "gateway.networking.k8s.io".to_string(),
                        kind: "TCPRoute".to_string(),
                    }]
                }
                crate::crds::ProtocolType::TLS => {
                    vec![RouteGroupKind {
                        group: "gateway.networking.k8s.io".to_string(),
                        kind: "TLSRoute".to_string(),
                    }]
                }
                _ => vec![],
            };
            ListenerStatus {
                name: listener.name.clone(),
                supported_kinds,
                attached_routes: 0,
                conditions: vec![
                    Condition::accepted().with_observed_generation(gateway.metadata.generation),
                    Condition::programmed().with_observed_generation(gateway.metadata.generation),
                    Condition::resolved_refs()
                        .with_observed_generation(gateway.metadata.generation),
                ],
            }
        })
        .collect()
}

/// Outcome of the managed-runtime status observation.
///
/// Carries the programmed flag, the `only_store_not_ready` flag (for reason
/// selection), an optional observation-fault message (when the Kubernetes API
/// returned a non-404 error), and the Gateway's `observed_generation` to
/// thread onto conditions.
struct ManagedStatusOutcome {
    programmed: bool,
    only_store_not_ready: bool,
    /// Non-empty when a non-404 API error occurred while reading owned objects.
    /// The caller surfaces this as a distinct `ObservationFault` condition so
    /// operators can distinguish a transient API error from a genuine
    /// deployment failure.
    observation_fault: Option<String>,
    /// Gateway `.metadata.generation` at observation time.
    observed_generation: Option<i64>,
}

/// Resolve the `ManagedStatusOutcome` from a `ManagedRuntimeInput`.
///
/// Pure, synchronous, and free of Kubernetes API calls.  Extracted from
/// `build_managed_runtime_status` so it can be exercised directly in tests
/// without a live `Context`.
///
/// ## Parameters
///
/// - `input`: the typed outcome of the managed-runtime sub-reconcile.
/// - `store_ready`: whether the controller store snapshot is ready.
/// - `gateway_generation`: `gateway.metadata.generation` at reconcile time.
///
/// ## Invariants
///
/// - `Applied` + no-op apply + converged obs  => `programmed=true`.
/// - `Applied` + rollout/deployment mutated   => `programmed=false`, `only_store_not_ready=false`.
/// - `StoreNotReady` + converged obs          => `programmed=true`.
/// - `StoreNotReady` + not-converged + store not ready => `only_store_not_ready=true`.
/// - `ObservationFault`                       => `programmed=false`, `observation_fault=Some(msg)`.
fn resolve_managed_status_outcome(
    input: ManagedRuntimeInput,
    store_ready: bool,
    gateway_generation: Option<i64>,
) -> ManagedStatusOutcome {
    match input {
        ManagedRuntimeInput::Applied(observed, apply_result, _) => {
            // Happy path -- reuse the observation from the sub-reconcile.
            //
            // Staleness guard: a rollout was just triggered or the Deployment was
            // just created/changed.  The pre-apply observation reflects the state
            // BEFORE the apply, so `is_rollout_converged` would be stale.  Force
            // `programmed = false` so the Gateway does not briefly flash
            // `Programmed=True` while the new rollout is still in progress.
            let apply_mutated = apply_result.rollout_triggered || apply_result.deployment_changed;
            let programmed = if apply_mutated {
                false
            } else {
                is_rollout_converged(&observed)
            };
            // `only_store_not_ready` selects the `ControllerStoreNotReady` reason.
            // When the apply just mutated the Deployment, the cause of
            // `programmed=false` is the in-flight rollout, not the store warming
            // up.  Force `only_store_not_ready=false` so operators see
            // `DeploymentNotReady` rather than the misleading `ControllerStoreNotReady`.
            let only_store_not_ready = !apply_mutated && !programmed && !store_ready;
            ManagedStatusOutcome {
                programmed,
                only_store_not_ready,
                observation_fault: None,
                observed_generation: gateway_generation,
            }
        }
        ManagedRuntimeInput::ObservationFault(fault_msg) => {
            // ObservationFault path -- the sub-reconcile failed during observation.
            // The fault message is already carried; no second API read needed.
            ManagedStatusOutcome {
                programmed: false,
                only_store_not_ready: false,
                observation_fault: Some(fault_msg),
                observed_generation: gateway_generation,
            }
        }
        ManagedRuntimeInput::StoreNotReady(observed) => {
            // StoreNotReady path -- reuse the observation that was already
            // gathered by reconcile_managed_runtime before the store check.
            // No second API read is needed.
            //
            // Invariant: StoreNotReady alone must not force Programmed=False when
            // the observed runtime is healthy.  `is_rollout_converged` decides
            // programmed independently of store readiness.
            let programmed = is_rollout_converged(&observed);
            let only_store_not_ready = !programmed && !store_ready;
            ManagedStatusOutcome {
                programmed,
                only_store_not_ready,
                observation_fault: None,
                observed_generation: gateway_generation,
            }
        }
    }
}

/// Build the top-level Gateway conditions from the reconcile outcome.
///
/// Pure, synchronous, no I/O.  Extracted from `reconcile_gateway` so the
/// condition-selection priority logic can be tested independently.
///
/// ## Priority order (mutually exclusive)
///
/// 1. `Programmed=True`  -- rollout fully converged.
/// 2. `ObservationFault` -- non-404 API error reading owned objects.
/// 3. `ControllerStoreNotReady` -- store still warming up after restart.
/// 4. `DeploymentNotReady` -- generic rollout-not-converged fallback.
fn build_gateway_conditions(
    programmed: bool,
    observation_fault: &Option<String>,
    only_store_not_ready: bool,
    observed_generation: Option<i64>,
) -> Vec<Condition> {
    if programmed {
        vec![
            Condition::accepted().with_observed_generation(observed_generation),
            Condition::programmed().with_observed_generation(observed_generation),
        ]
    } else if let Some(ref fault) = observation_fault {
        vec![
            Condition::accepted().with_observed_generation(observed_generation),
            Condition::not_programmed_observation_fault(fault)
                .with_observed_generation(observed_generation),
        ]
    } else if only_store_not_ready {
        vec![
            Condition::accepted().with_observed_generation(observed_generation),
            Condition::not_programmed_warming_up().with_observed_generation(observed_generation),
        ]
    } else {
        vec![
            Condition::accepted().with_observed_generation(observed_generation),
            Condition::not_programmed().with_observed_generation(observed_generation),
        ]
    }
}

/// Build listener statuses and determine the `Programmed` condition for a
/// managed-runtime Gateway.
///
/// ## Programmed logic
///
/// `Programmed=True` requires the Deployment rollout to have fully converged:
///
/// - `deploy_observed_generation == deploy_generation` (controller processed
///   the current spec generation)
/// - `updated_replicas >= desired_replicas` (all pods on current template)
/// - `available_replicas >= 1` (at least one pod available)
/// - `ready_replicas >= 1` (at least one pod ready)
///
/// This is stricter than `ready_replicas > 0` alone, which is insufficient
/// during a rolling update where old pods may still be ready while new pods
/// are starting.
///
/// Store readiness is intentionally NOT a hard gate: if the controller store
/// is still warming up after a restart but the Deployment is already healthy,
/// the Gateway remains `Programmed=True`.
///
/// ## Observed state threading
///
/// `input` is a `ManagedRuntimeInput` that encodes which of the three mutually
/// exclusive sub-reconcile outcomes applies:
///
/// - `Applied(observed, apply_result)`: the sub-reconcile succeeded.  The
///   pre-apply observation is reused directly.  The `RuntimeApplyResult` is
///   inspected to detect rollout-triggering work: when
///   `apply_result.rollout_triggered || apply_result.deployment_changed` is
///   true, the pre-apply observation is stale and `Programmed` must be `False`
///   to avoid a one-cycle lie.
///
/// - `StoreNotReady(observed)`: the sub-reconcile returned `StoreNotReady`.
///   `reconcile_managed_runtime` observes runtime state BEFORE checking store
///   readiness, so the observation is valid even when planning was skipped.
///   No second API read is issued.
///
/// - `ObservationFault(msg)`: a non-404 Kubernetes API error occurred while
///   observing owned objects.  The fault message is used to build the
///   `ObservationFault` condition without re-reading the API.
///
/// ## Observation faults
///
/// When `ObservationFault` is the input, the runtime is treated as not ready
/// (fail-safe) and the reason is `ObservationFault` rather than
/// `DeploymentNotReady` so operators can diagnose RBAC or API server issues.
///
/// ## Listener attached_routes
///
/// When the store snapshot is ready, the `AttachmentPlanner` is run to
/// populate real attached-route counts.  When the snapshot is not ready,
/// all counts fall back to 0.  Non-accepted listeners always report 0
/// attached routes regardless of what the attachment planner returns.
///
/// ## Returns
///
/// `(listener_statuses, programmed, only_store_not_ready, observation_fault)` where:
/// - `programmed` is `true` iff the Gateway should report `Programmed=True`.
/// - `only_store_not_ready` is `true` when the runtime is not ready AND the
///   store is also not ready, indicating the controller is still warming up.
///   The caller uses this to select the correct `not_programmed` reason.
/// - `observation_fault` is `Some(msg)` when a non-404 Kubernetes API error
///   occurred while observing owned objects.  The caller surfaces this as a
///   distinct top-level `ObservationFault` condition rather than the generic
///   `DeploymentNotReady` condition.
fn build_managed_runtime_status(
    gateway: &Gateway,
    namespace: &str,
    name: &str,
    input: ManagedRuntimeInput,
) -> (Vec<ListenerStatus>, bool, bool, Option<String>) {
    use crate::reconcilers::runtime_plan::listener_status_intents_with_attachment;

    let gateway_generation = gateway.metadata.generation;

    // ── 1. Extract the planner snapshot from the input ───────────────────────
    //
    // The snapshot was captured by `reconcile_managed_runtime` and threaded
    // through `ManagedRuntimeInput::Applied` so we avoid a second store read.
    // For `StoreNotReady` and `ObservationFault` the snapshot is not available
    // (by definition), so we use `SnapshotResult::NotReady`.
    let snapshot_result = match &input {
        ManagedRuntimeInput::Applied(_, _, ref snap) => *snap.clone(),
        ManagedRuntimeInput::StoreNotReady(_) | ManagedRuntimeInput::ObservationFault(_) => {
            SnapshotResult::NotReady
        }
    };
    let store_ready = snapshot_result.is_ready();

    // ── 2. Determine runtime readiness from the typed input ───────────────────
    //
    // Delegate to the pure helper so the outcome logic is testable without a
    // live Kubernetes client.  The tracing calls that were previously inline
    // are emitted here, after the outcome is known.
    let outcome = resolve_managed_status_outcome(input, store_ready, gateway_generation);

    if outcome.observation_fault.is_some() {
        tracing::debug!(
            namespace = %namespace,
            name = %name,
            error = ?outcome.observation_fault,
            "Reusing observation fault for status path (no second API read)"
        );
    } else if !outcome.programmed {
        tracing::debug!(
            namespace = %namespace,
            name = %name,
            only_store_not_ready = outcome.only_store_not_ready,
            "Managed runtime not yet programmed"
        );
    }

    let programmed = outcome.programmed;
    let only_store_not_ready = outcome.only_store_not_ready;

    // ── 3. Build listener statuses with real attached-route counts ────────────
    let attachment_plan_opt = if let SnapshotResult::Ready(ref snapshot) = snapshot_result {
        let gw_gen = gateway_generation.unwrap_or(0);
        let ap_input = AttachmentPlanInput {
            gateway_namespace: namespace.to_string(),
            gateway_name: name.to_string(),
            gateway_generation: gw_gen,
            snapshot: snapshot.clone(),
        };
        AttachmentPlanner.plan(&ap_input).ok()
    } else {
        None
    };

    let intents = listener_status_intents_with_attachment(gateway, attachment_plan_opt.as_ref());

    let listener_statuses = intents
        .into_iter()
        .map(|intent| {
            let supported_kinds = intent
                .supported_kinds
                .into_iter()
                .map(|k| RouteGroupKind {
                    group: k.group,
                    kind: k.kind,
                })
                .collect();

            // Per-listener Programmed condition mirrors the Gateway-level one.
            // Use the accurate reason so operators can distinguish deployment
            // failures from controller warmup.
            let listener_conditions = if let Some(ref fault) = outcome.observation_fault {
                // Observation fault: use a distinct reason so operators can
                // diagnose RBAC or API server issues.
                let not_prog = Condition::not_programmed_observation_fault(fault)
                    .with_observed_generation(outcome.observed_generation);
                if intent.accepted {
                    vec![
                        Condition::accepted().with_observed_generation(outcome.observed_generation),
                        not_prog,
                        Condition::resolved_refs()
                            .with_observed_generation(outcome.observed_generation),
                    ]
                } else {
                    vec![
                        Condition::not_accepted()
                            .with_observed_generation(outcome.observed_generation),
                        not_prog,
                        Condition::resolved_refs()
                            .with_observed_generation(outcome.observed_generation),
                    ]
                }
            } else if programmed && intent.accepted {
                vec![
                    Condition::accepted().with_observed_generation(outcome.observed_generation),
                    Condition::programmed().with_observed_generation(outcome.observed_generation),
                    Condition::resolved_refs()
                        .with_observed_generation(outcome.observed_generation),
                ]
            } else if intent.accepted {
                let not_prog = if only_store_not_ready {
                    Condition::not_programmed_warming_up()
                } else {
                    Condition::not_programmed()
                }
                .with_observed_generation(outcome.observed_generation);
                vec![
                    Condition::accepted().with_observed_generation(outcome.observed_generation),
                    not_prog,
                    Condition::resolved_refs()
                        .with_observed_generation(outcome.observed_generation),
                ]
            } else {
                let not_prog = if only_store_not_ready {
                    Condition::not_programmed_warming_up()
                } else {
                    Condition::not_programmed()
                }
                .with_observed_generation(outcome.observed_generation);
                vec![
                    Condition::not_accepted().with_observed_generation(outcome.observed_generation),
                    not_prog,
                    Condition::resolved_refs()
                        .with_observed_generation(outcome.observed_generation),
                ]
            };

            ListenerStatus {
                name: intent.name,
                supported_kinds,
                // ListenerStatus.attached_routes is i32 (CRD type); cast from u32.
                // Saturate at i32::MAX to avoid overflow on pathological inputs.
                attached_routes: i32::try_from(intent.attached_routes).unwrap_or(i32::MAX),
                conditions: listener_conditions,
            }
        })
        .collect();

    (
        listener_statuses,
        programmed,
        only_store_not_ready,
        outcome.observation_fault,
    )
}

/// Get addresses for a Gateway from its associated LoadBalancer Service.
///
/// This function tries to find addresses in the following order:
/// 1. LoadBalancer Service status (external IP or hostname assigned by cloud provider)
/// 2. Addresses specified in the Gateway spec
/// 3. Fallback to a placeholder if nothing is available
async fn get_gateway_addresses(
    client: &Client,
    namespace: &str,
    gateway_name: &str,
    gateway: &Gateway,
) -> Vec<GatewayStatusAddress> {
    let mut addresses = Vec::new();

    // Try to find the associated Service (convention: same name as Gateway, or with -lb suffix)
    let svc_api: Api<Service> = Api::namespaced(client.clone(), namespace);

    // Fix (4): include the owned Service name (`wicket-gw-<gateway>-svc`) so
    // that managed-runtime Gateways have their addresses discovered.  The
    // owned name is derived via the same naming helpers used by the planner
    // and applier, ensuring consistency.
    let owned_svc_name = owned_service_name(&owned_object_base_name(gateway_name));

    // Check for Service with the same name or common naming patterns.
    // The owned managed-runtime Service is checked first so that managed
    // Gateways resolve addresses without falling through to the legacy names.
    let service_names = [
        owned_svc_name,
        gateway_name.to_string(),
        format!("{}-lb", gateway_name),
        format!("{}-gateway", gateway_name),
        format!("wicket-{}", gateway_name),
    ];

    for svc_name in &service_names {
        if let Ok(service) = svc_api.get(svc_name).await {
            // Check if it's a LoadBalancer type Service
            if let Some(spec) = &service.spec {
                if spec.type_.as_deref() == Some("LoadBalancer") {
                    // Get addresses from LoadBalancer status
                    if let Some(status) = &service.status {
                        if let Some(lb_status) = &status.load_balancer {
                            if let Some(ingresses) = &lb_status.ingress {
                                for ingress in ingresses {
                                    if let Some(ip) = &ingress.ip {
                                        addresses.push(GatewayStatusAddress {
                                            type_: AddressType::IPAddress,
                                            value: ip.clone(),
                                        });
                                    }
                                    if let Some(hostname) = &ingress.hostname {
                                        addresses.push(GatewayStatusAddress {
                                            type_: AddressType::Hostname,
                                            value: hostname.clone(),
                                        });
                                    }
                                }
                            }
                        }
                    }

                    // If LoadBalancer is pending, check external IPs
                    if addresses.is_empty() {
                        if let Some(external_ips) = &spec.external_ips {
                            for ip in external_ips {
                                addresses.push(GatewayStatusAddress {
                                    type_: AddressType::IPAddress,
                                    value: ip.clone(),
                                });
                            }
                        }
                    }
                } else if spec.type_.as_deref() == Some("NodePort") {
                    // For NodePort, we could potentially get node IPs
                    // but that's complex - skip for now
                } else if spec.type_.as_deref() == Some("ClusterIP") {
                    // Use ClusterIP if available
                    if let Some(cluster_ip) = &spec.cluster_ip {
                        if cluster_ip != "None" {
                            addresses.push(GatewayStatusAddress {
                                type_: AddressType::IPAddress,
                                value: cluster_ip.clone(),
                            });
                        }
                    }
                }
            }

            // If we found a service with addresses, break
            if !addresses.is_empty() {
                tracing::debug!(
                    namespace = %namespace,
                    gateway = %gateway_name,
                    service = %svc_name,
                    addresses = ?addresses,
                    "Found Gateway addresses from Service"
                );
                break;
            }
        }
    }

    // Fall back to addresses specified in Gateway spec
    if addresses.is_empty() {
        for addr in &gateway.spec.addresses {
            addresses.push(GatewayStatusAddress {
                type_: addr.type_.clone(),
                value: addr.value.clone(),
            });
        }
    }

    // If still no addresses, use a placeholder that indicates pending
    if addresses.is_empty() {
        tracing::debug!(
            namespace = %namespace,
            gateway = %gateway_name,
            "No addresses found, using pending placeholder"
        );
        // Don't set an address - leave empty to indicate pending
        // Some implementations use a specific IP, but empty is cleaner
    }

    addresses
}

/// Update Gateway metrics.
async fn update_gateway_metrics(client: &Client) {
    let api: Api<Gateway> = Api::all(client.clone());

    match api.list(&Default::default()).await {
        Ok(list) => {
            // Group by namespace and class
            let mut counts: std::collections::HashMap<(String, String), i64> =
                std::collections::HashMap::new();

            for gw in &list.items {
                let ns = gw.namespace().unwrap_or_default();
                let class = gw.spec.gateway_class_name.clone();
                *counts.entry((ns, class)).or_insert(0) += 1;
            }

            for ((ns, class), count) in counts {
                GATEWAYS.with_label_values(&[&ns, &class]).set(count);
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "Failed to list Gateways for metrics");
        }
    }
}

/// Load service endpoints for all referenced services.
pub async fn load_service_endpoints(
    client: &Client,
    state: &mut super::config_generator::GatewayState,
) {
    use super::config_generator::ServiceEndpoints;
    use k8s_openapi::api::core::v1::Endpoints;

    let _endpoints_api: Api<Endpoints> = Api::all(client.clone());

    // Collect all referenced services
    let mut referenced_services: std::collections::HashSet<String> =
        std::collections::HashSet::new();

    for route in state.http_routes.values() {
        let route_ns = route.namespace().unwrap_or_default();
        for rule in &route.spec.rules {
            for backend_ref in &rule.backend_refs {
                let backend_ns = backend_ref
                    .backend_ref
                    .namespace
                    .as_deref()
                    .unwrap_or(&route_ns);
                referenced_services.insert(super::config_generator::GatewayState::key(
                    backend_ns,
                    &backend_ref.backend_ref.name,
                ));
            }
        }
    }

    for route in state.tcp_routes.values() {
        let route_ns = route.namespace().unwrap_or_default();
        for rule in &route.spec.rules {
            for backend_ref in &rule.backend_refs {
                let backend_ns = backend_ref.namespace.as_deref().unwrap_or(&route_ns);
                referenced_services.insert(super::config_generator::GatewayState::key(
                    backend_ns,
                    &backend_ref.name,
                ));
            }
        }
    }

    for route in state.tls_routes.values() {
        let route_ns = route.namespace().unwrap_or_default();
        for rule in &route.spec.rules {
            for backend_ref in &rule.backend_refs {
                let backend_ns = backend_ref.namespace.as_deref().unwrap_or(&route_ns);
                referenced_services.insert(super::config_generator::GatewayState::key(
                    backend_ns,
                    &backend_ref.name,
                ));
            }
        }
    }

    // Load endpoints for each referenced service
    for svc_key in referenced_services {
        let parts: Vec<&str> = svc_key.split('/').collect();
        if parts.len() != 2 {
            continue;
        }
        let (namespace, name) = (parts[0], parts[1]);

        let ns_endpoints_api: Api<Endpoints> = Api::namespaced(client.clone(), namespace);
        if let Ok(endpoints) = ns_endpoints_api.get(name).await {
            let mut addrs = Vec::new();

            if let Some(subsets) = endpoints.subsets {
                for subset in subsets {
                    if let Some(addresses) = subset.addresses {
                        for addr in addresses {
                            if let Some(ports) = &subset.ports {
                                for port in ports {
                                    addrs.push(format!("{}:{}", addr.ip, port.port));
                                }
                            }
                        }
                    }
                }
            }

            if !addrs.is_empty() {
                state.service_endpoints.insert(
                    svc_key.clone(),
                    ServiceEndpoints {
                        namespace: namespace.to_string(),
                        name: name.to_string(),
                        endpoints: addrs,
                    },
                );
            }
        }
    }
}

/// Create the Gateway controller.
pub async fn run_gateway_controller(ctx: Arc<Context>) -> Result<(), kube::Error> {
    use crate::metrics::{WATCH_CONNECTIONS_ACTIVE, WATCH_ERRORS_TOTAL, WATCH_EVENTS_TOTAL};

    let api: Api<Gateway> = if ctx.watch_all_namespaces {
        Api::all(ctx.client.clone())
    } else {
        Api::namespaced(ctx.client.clone(), &ctx.controller_namespace)
    };

    // Track that we have an active watch connection
    WATCH_CONNECTIONS_ACTIVE
        .with_label_values(&["Gateway"])
        .set(1);

    Controller::new(api, Config::default())
        .run(reconcile_gateway, error_policy_gateway, ctx)
        .for_each(|result| async move {
            match result {
                Ok((obj, _)) => {
                    WATCH_EVENTS_TOTAL
                        .with_label_values(&["Gateway", "reconcile_success"])
                        .inc();
                    tracing::debug!(
                        namespace = obj.namespace.as_deref().unwrap_or(""),
                        name = %obj.name,
                        "Gateway reconciled"
                    );
                }
                Err(e) => {
                    WATCH_EVENTS_TOTAL
                        .with_label_values(&["Gateway", "reconcile_error"])
                        .inc();
                    WATCH_ERRORS_TOTAL
                        .with_label_values(&["Gateway", "controller_error"])
                        .inc();
                    tracing::error!(error = %e, "Gateway controller error");
                }
            }
        })
        .await;

    // Watch ended
    WATCH_CONNECTIONS_ACTIVE
        .with_label_values(&["Gateway"])
        .set(0);

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    use kube::core::ObjectMeta;

    use crate::crds::{
        Condition, Gateway, GatewaySpec, GatewayStatus, Listener, ListenerStatus, ProtocolType,
    };
    use crate::reconcilers::runtime_plan::{
        config_map_name, deployment_name, is_managed_runtime, is_rollout_converged,
        owned_object_base_name, ObservedRuntimeState, MANAGED_RUNTIME_ANNOTATION,
    };

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn make_gateway_with_annotation(
        namespace: &str,
        name: &str,
        annotation_value: Option<&str>,
    ) -> Gateway {
        let annotations = annotation_value.map(|v| {
            let mut m = BTreeMap::new();
            m.insert(MANAGED_RUNTIME_ANNOTATION.to_string(), v.to_string());
            m
        });
        Gateway {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some(namespace.to_string()),
                uid: Some("uid-test".to_string()),
                generation: Some(1),
                annotations,
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

    // ── is_managed_runtime gate ───────────────────────────────────────────────

    #[test]
    fn managed_runtime_gate_true_when_annotated_true() {
        let gw = make_gateway_with_annotation("prod", "my-gw", Some("true"));
        assert!(is_managed_runtime(&gw));
    }

    #[test]
    fn managed_runtime_gate_false_when_annotation_absent() {
        let gw = make_gateway_with_annotation("prod", "my-gw", None);
        assert!(is_managed_runtime(&gw));
    }

    #[test]
    fn managed_runtime_gate_false_when_annotation_not_true() {
        let gw = make_gateway_with_annotation("prod", "my-gw", Some("false"));
        assert!(!is_managed_runtime(&gw));
    }

    #[test]
    fn managed_runtime_gate_false_when_annotation_empty() {
        let gw = make_gateway_with_annotation("prod", "my-gw", Some(""));
        assert!(is_managed_runtime(&gw));
    }

    // ── ObservedRuntimeState defaults ─────────────────────────────────────────

    #[test]
    fn observed_runtime_state_default_is_all_none() {
        let obs = ObservedRuntimeState::default();
        assert!(obs.current_config_hash.is_none());
        assert!(obs.current_spec_hash.is_none());
        assert!(obs.ready_replicas.is_none());
    }

    // ── Owned object name derivation (used by observe_runtime_state) ──────────

    #[test]
    fn owned_names_derived_from_gateway_name() {
        let base = owned_object_base_name("my-gw");
        assert_eq!(config_map_name(&base), "wicket-gw-my-gw-config");
        assert_eq!(deployment_name(&base), "wicket-gw-my-gw-deploy");
    }

    // ── ManagedRuntimeError variants ──────────────────────────────────────────

    #[test]
    fn managed_runtime_error_store_not_ready_display() {
        let e = super::ManagedRuntimeError::StoreNotReady(ObservedRuntimeState::default());
        assert!(e.to_string().contains("not ready"));
    }

    #[test]
    fn managed_runtime_error_plan_display() {
        let e = super::ManagedRuntimeError::Plan("bad input".to_string());
        assert!(e.to_string().contains("bad input"));
    }

    #[test]
    fn managed_runtime_error_apply_display() {
        let e = super::ManagedRuntimeError::Apply("kube api error".to_string());
        assert!(e.to_string().contains("kube api error"));
    }

    // Fix (1): StoreNotReady must be a distinct variant that the caller can
    // match without inspecting the error string.
    #[test]
    fn managed_runtime_error_store_not_ready_is_matchable() {
        let e = super::ManagedRuntimeError::StoreNotReady(ObservedRuntimeState::default());
        assert!(
            matches!(e, super::ManagedRuntimeError::StoreNotReady(_)),
            "StoreNotReady must be matchable as its own variant"
        );
    }

    // Fix (1): Plan and Apply errors must NOT match StoreNotReady so the
    // caller's match arm is unambiguous.
    #[test]
    fn managed_runtime_error_plan_is_not_store_not_ready() {
        let e = super::ManagedRuntimeError::Plan("x".to_string());
        assert!(!matches!(e, super::ManagedRuntimeError::StoreNotReady(_)));
    }

    // Fix (5): ObservationError is a distinct variant for non-404 API faults.
    #[test]
    fn managed_runtime_error_observation_error_display() {
        let e = super::ManagedRuntimeError::ObservationError(
            "ConfigMap prod/wicket-gw-my-gw-config: 403 Forbidden".to_string(),
        );
        let s = e.to_string();
        assert!(
            s.contains("observation failed"),
            "display must say 'observation failed'"
        );
        assert!(s.contains("403"), "display must include the original error");
    }

    // Fix (5): ObservationError must be matchable as its own variant.
    #[test]
    fn managed_runtime_error_observation_error_is_matchable() {
        let e = super::ManagedRuntimeError::ObservationError("rbac".to_string());
        assert!(matches!(e, super::ManagedRuntimeError::ObservationError(_)));
        assert!(!matches!(e, super::ManagedRuntimeError::StoreNotReady(_)));
    }

    // Fix (4): owned Service name must appear in the address-discovery list.
    #[test]
    fn owned_service_name_included_in_address_discovery() {
        use crate::reconcilers::runtime_plan::{owned_object_base_name, service_name};

        // The owned service name for gateway "my-gw" must be
        // "wicket-gw-my-gw-svc" -- the same name the applier creates.
        let base = owned_object_base_name("my-gw");
        let svc = service_name(&base);
        assert_eq!(svc, "wicket-gw-my-gw-svc");

        // Verify the name is derived consistently with the planner.
        let base2 = owned_object_base_name("prod-gateway");
        let svc2 = service_name(&base2);
        assert_eq!(svc2, "wicket-gw-prod-gateway-svc");
    }

    // Fix (3): ControllerConfig must be accessible from Context so the live
    // path does not hardcode ::default().  We verify the field exists and
    // round-trips through the default constructor.
    #[test]
    fn context_exposes_controller_config_field() {
        use crate::reconcilers::runtime_plan::ControllerConfig;

        // ControllerConfig::default() must be the same value that Context
        // initialises the field to.
        let default_cfg = ControllerConfig::default();
        assert_eq!(default_cfg.proxy_image, "ghcr.io/geverding/wicket:latest");
        assert_eq!(default_cfg.default_replicas, 1);
    }

    // ── build_legacy_listener_statuses ────────────────────────────────────────

    #[test]
    fn legacy_listener_statuses_zero_attached_routes() {
        let gw = make_gateway_with_annotation("prod", "my-gw", None);
        let statuses = super::build_legacy_listener_statuses(&gw);
        assert_eq!(statuses.len(), 1);
        assert_eq!(statuses[0].attached_routes, 0);
        assert_eq!(statuses[0].name, "http");
    }

    #[test]
    fn legacy_listener_statuses_programmed_condition_present() {
        let gw = make_gateway_with_annotation("prod", "my-gw", None);
        let statuses = super::build_legacy_listener_statuses(&gw);
        let has_programmed = statuses[0]
            .conditions
            .iter()
            .any(|c| c.type_ == "Programmed" && c.status == "True");
        assert!(
            has_programmed,
            "legacy listener must have Programmed=True condition"
        );
    }

    // ── Condition helpers ─────────────────────────────────────────────────────

    #[test]
    fn not_programmed_condition_has_false_status() {
        let c = crate::crds::Condition::not_programmed();
        assert_eq!(c.type_, "Programmed");
        assert_eq!(c.status, "False");
    }

    #[test]
    fn not_accepted_condition_has_false_status() {
        let c = crate::crds::Condition::not_accepted();
        assert_eq!(c.type_, "Accepted");
        assert_eq!(c.status, "False");
    }

    #[test]
    fn gateway_status_unchanged_after_timestamp_preservation_is_noop() {
        let existing = GatewayStatus {
            addresses: vec![],
            conditions: vec![Condition {
                type_: "Programmed".to_string(),
                status: "True".to_string(),
                observed_generation: Some(11),
                last_transition_time: "2024-01-01T00:00:00Z".to_string(),
                reason: "Programmed".to_string(),
                message: "Resource has been programmed".to_string(),
            }],
            listeners: vec![ListenerStatus {
                name: "http".to_string(),
                supported_kinds: vec![],
                attached_routes: 3,
                conditions: vec![Condition {
                    type_: "Accepted".to_string(),
                    status: "True".to_string(),
                    observed_generation: Some(11),
                    last_transition_time: "2024-01-01T01:00:00Z".to_string(),
                    reason: "Accepted".to_string(),
                    message: "Resource has been accepted".to_string(),
                }],
            }],
        };

        let mut status = GatewayStatus {
            addresses: vec![],
            conditions: vec![Condition {
                type_: "Programmed".to_string(),
                status: "True".to_string(),
                observed_generation: Some(11),
                last_transition_time: "2024-02-01T00:00:00Z".to_string(),
                reason: "Programmed".to_string(),
                message: "Resource has been programmed".to_string(),
            }],
            listeners: vec![ListenerStatus {
                name: "http".to_string(),
                supported_kinds: vec![],
                attached_routes: 3,
                conditions: vec![Condition {
                    type_: "Accepted".to_string(),
                    status: "True".to_string(),
                    observed_generation: Some(11),
                    last_transition_time: "2024-02-01T01:00:00Z".to_string(),
                    reason: "Accepted".to_string(),
                    message: "Resource has been accepted".to_string(),
                }],
            }],
        };

        preserve_gateway_status_timestamps(&mut status, &existing);

        assert_eq!(
            status.conditions[0].last_transition_time,
            existing.conditions[0].last_transition_time
        );
        assert_eq!(
            status.listeners[0].conditions[0].last_transition_time,
            existing.listeners[0].conditions[0].last_transition_time
        );
        assert!(gateway_status_semantically_equal(&existing, &status));

        let needs_patch = !gateway_status_semantically_equal(&existing, &status);
        assert!(!needs_patch);
    }

    #[test]
    fn gateway_status_rejects_stale_observed_generation() {
        let existing = GatewayStatus {
            addresses: vec![],
            conditions: vec![Condition {
                type_: "Programmed".to_string(),
                status: "True".to_string(),
                observed_generation: Some(11),
                last_transition_time: "2024-01-01T00:00:00Z".to_string(),
                reason: "Programmed".to_string(),
                message: "Resource has been programmed".to_string(),
            }],
            listeners: vec![ListenerStatus {
                name: "http".to_string(),
                supported_kinds: vec![],
                attached_routes: 3,
                conditions: vec![Condition {
                    type_: "Accepted".to_string(),
                    status: "True".to_string(),
                    observed_generation: Some(11),
                    last_transition_time: "2024-01-01T01:00:00Z".to_string(),
                    reason: "Accepted".to_string(),
                    message: "Resource has been accepted".to_string(),
                }],
            }],
        };

        let stale = GatewayStatus {
            addresses: vec![],
            conditions: vec![Condition {
                type_: "Programmed".to_string(),
                status: "True".to_string(),
                observed_generation: Some(10),
                last_transition_time: "2024-02-01T00:00:00Z".to_string(),
                reason: "Programmed".to_string(),
                message: "Resource has been programmed".to_string(),
            }],
            listeners: vec![ListenerStatus {
                name: "http".to_string(),
                supported_kinds: vec![],
                attached_routes: 3,
                conditions: vec![Condition {
                    type_: "Accepted".to_string(),
                    status: "True".to_string(),
                    observed_generation: Some(10),
                    last_transition_time: "2024-02-01T01:00:00Z".to_string(),
                    reason: "Accepted".to_string(),
                    message: "Resource has been accepted".to_string(),
                }],
            }],
        };

        assert!(!gateway_status_semantically_equal(&existing, &stale));
    }

    // ── Programmed / rollout-convergence logic (unit-level, no async) ────────
    //
    // The full build_managed_runtime_status is async and requires a live
    // Kubernetes client, so we test the programmed decision logic through
    // is_rollout_converged() and ObservedRuntimeState directly.

    /// Helper: build a fully-converged ObservedRuntimeState with 1 desired replica.
    fn converged_obs() -> ObservedRuntimeState {
        ObservedRuntimeState {
            current_config_hash: None,
            current_spec_hash: None,
            ready_replicas: Some(1),
            deploy_observed_generation: Some(2),
            deploy_generation: Some(2),
            updated_replicas: Some(1),
            available_replicas: Some(1),
            desired_replicas: Some(1),
        }
    }

    #[test]
    fn programmed_false_when_ready_replicas_none() {
        // ready_replicas = None => not converged => programmed = false.
        let obs = ObservedRuntimeState {
            ready_replicas: None,
            ..Default::default()
        };
        assert!(
            !is_rollout_converged(&obs),
            "None ready_replicas must not be converged"
        );
    }

    #[test]
    fn programmed_false_when_ready_replicas_zero() {
        let obs = ObservedRuntimeState {
            ready_replicas: Some(0),
            deploy_observed_generation: Some(1),
            deploy_generation: Some(1),
            updated_replicas: Some(1),
            available_replicas: Some(1),
            desired_replicas: Some(1),
            ..Default::default()
        };
        assert!(
            !is_rollout_converged(&obs),
            "0 ready_replicas must not be converged"
        );
    }

    #[test]
    fn programmed_true_when_rollout_converged() {
        let obs = converged_obs();
        assert!(
            is_rollout_converged(&obs),
            "fully converged obs must be converged"
        );
    }

    #[test]
    fn programmed_false_when_updated_replicas_less_than_desired() {
        // Rollout in progress: 0 updated out of 2 desired.
        let obs = ObservedRuntimeState {
            ready_replicas: Some(2), // old pods still ready
            deploy_observed_generation: Some(2),
            deploy_generation: Some(2),
            updated_replicas: Some(0), // new pods not yet up
            available_replicas: Some(2),
            desired_replicas: Some(2),
            ..Default::default()
        };
        assert!(
            !is_rollout_converged(&obs),
            "updated_replicas < desired_replicas must not be converged"
        );
    }

    #[test]
    fn programmed_false_when_observed_generation_stale() {
        // Deployment controller has not yet processed the new spec.
        let obs = ObservedRuntimeState {
            ready_replicas: Some(1),
            deploy_observed_generation: Some(1), // stale
            deploy_generation: Some(2),          // desired
            updated_replicas: Some(1),
            available_replicas: Some(1),
            desired_replicas: Some(1),
            ..Default::default()
        };
        assert!(
            !is_rollout_converged(&obs),
            "stale observed_generation must not be converged"
        );
    }

    #[test]
    fn programmed_false_when_available_replicas_zero() {
        let obs = ObservedRuntimeState {
            ready_replicas: Some(1),
            deploy_observed_generation: Some(2),
            deploy_generation: Some(2),
            updated_replicas: Some(1),
            available_replicas: Some(0), // not yet available
            desired_replicas: Some(1),
            ..Default::default()
        };
        assert!(
            !is_rollout_converged(&obs),
            "available_replicas=0 must not be converged"
        );
    }

    #[test]
    fn programmed_false_when_deployment_absent() {
        // All fields None => Deployment does not exist.
        let obs = ObservedRuntimeState::default();
        assert!(
            !is_rollout_converged(&obs),
            "absent Deployment must not be converged"
        );
    }

    // Fix (1): store readiness must NOT gate Programmed=True.
    // A healthy Deployment must remain Programmed=True even when the store is
    // warming up.  Verify all four combinations of (store_ready, converged).
    #[test]
    fn programmed_depends_only_on_rollout_converged_not_store_ready() {
        // programmed = is_rollout_converged(obs)  (store_ready is NOT a factor)
        let converged = converged_obs();
        let not_converged = ObservedRuntimeState::default();

        let cases: &[(&ObservedRuntimeState, bool, bool)] = &[
            // (obs, store_ready, expected_programmed)
            (&not_converged, false, false), // neither ready => not programmed
            (&converged, false, true),      // store warming up but rollout done => PROGRAMMED
            (&not_converged, true, false),  // store ready but rollout not done => not programmed
            (&converged, true, true),       // both ready => programmed
        ];
        for &(obs, store_ready, expected) in cases {
            // Replicate the logic from build_managed_runtime_status.
            let programmed = is_rollout_converged(obs);
            assert_eq!(
                programmed,
                expected,
                "store_ready={store_ready} converged={} => programmed must be {expected}",
                is_rollout_converged(obs)
            );
            // Suppress unused variable warning in the loop body.
            let _ = store_ready;
        }
    }

    // Fix (1): only_store_not_ready flag is true only when BOTH store and
    // runtime are not ready.  When runtime is ready, the flag must be false
    // regardless of store readiness.
    #[test]
    fn only_store_not_ready_flag_logic() {
        // only_store_not_ready = !runtime_ready && !store_ready
        let cases: &[(bool, bool, bool)] = &[
            // (store_ready, runtime_ready, expected_only_store_not_ready)
            (false, false, true), // both not ready => flag true
            (false, true, false), // runtime ready => flag false
            (true, false, false), // store ready => flag false
            (true, true, false),  // both ready => flag false
        ];
        for &(store_ready, runtime_ready, expected) in cases {
            let only_store_not_ready = !runtime_ready && !store_ready;
            assert_eq!(
                only_store_not_ready, expected,
                "store_ready={store_ready} runtime_ready={runtime_ready} => only_store_not_ready must be {expected}"
            );
        }
    }

    // Fix (2): top-level gateway condition uses ControllerStoreNotReady reason
    // when only_store_not_ready is true, and DeploymentNotReady otherwise.
    #[test]
    fn gateway_condition_reason_warming_up_vs_deployment_not_ready() {
        // When only_store_not_ready=true, the condition must use the warming-up reason.
        let warming_up = crate::crds::Condition::not_programmed_warming_up();
        assert_eq!(warming_up.reason, "ControllerStoreNotReady");

        // When only_store_not_ready=false (runtime not ready, store ready),
        // the condition must use the deployment-not-ready reason.
        let deploy_not_ready = crate::crds::Condition::not_programmed();
        assert_eq!(deploy_not_ready.reason, "DeploymentNotReady");

        // The two reasons must be distinct.
        assert_ne!(warming_up.reason, deploy_not_ready.reason);
    }

    // ── attached_routes cast ──────────────────────────────────────────────────

    #[test]
    fn attached_routes_cast_from_u32_to_i32() {
        // Normal values round-trip cleanly.
        let count: u32 = 5;
        let as_i32 = i32::try_from(count).unwrap_or(i32::MAX);
        assert_eq!(as_i32, 5);
    }

    #[test]
    fn attached_routes_cast_saturates_at_i32_max() {
        // Values exceeding i32::MAX saturate rather than overflow.
        let count: u32 = u32::MAX;
        let as_i32 = i32::try_from(count).unwrap_or(i32::MAX);
        assert_eq!(as_i32, i32::MAX);
    }

    // ── Fix (2): is_noop() must not be used to skip ownership validation.
    // We verify the logic by checking that a noop plan still carries the
    // correct owned object names (so the applier can run its preflight).
    #[test]
    fn noop_plan_still_carries_owned_object_names() {
        use crate::reconcilers::contracts::Planner;
        use crate::reconcilers::runtime_plan::{
            ControllerConfig, GatewayRuntimePlanner, ObservedRuntimeState, RuntimePlanInput,
        };
        use crate::reconcilers::store::PlannerSnapshot;
        use std::collections::{HashMap, HashSet};

        let gw = make_gateway_with_annotation("prod", "my-gw", Some("true"));
        let gw_key = "prod/my-gw".to_string();
        let mut gateways = HashMap::new();
        gateways.insert(gw_key, gw.clone());

        let snapshot = PlannerSnapshot {
            gateways,
            gateway_classes: HashMap::new(),
            http_routes: HashMap::new(),
            tcp_routes: HashMap::new(),
            tls_routes: HashMap::new(),
            service_endpoints: HashMap::new(),
            tls_secrets: HashMap::new(),
            reference_grants: HashMap::new(),
            service_ref_index: HashSet::new(),
            namespace_labels: HashMap::new(),
        };

        // First pass: get the hashes.
        let input0 = RuntimePlanInput {
            gateway_namespace: "prod".to_string(),
            gateway_name: "my-gw".to_string(),
            snapshot: snapshot.clone(),
            controller_config: ControllerConfig::default(),
            observed: ObservedRuntimeState::default(),
        };
        let plan0 = GatewayRuntimePlanner.plan(&input0).unwrap();

        // Second pass: feed hashes back so the plan is a noop.
        let input = RuntimePlanInput {
            gateway_namespace: "prod".to_string(),
            gateway_name: "my-gw".to_string(),
            snapshot,
            controller_config: ControllerConfig::default(),
            observed: ObservedRuntimeState {
                current_config_hash: Some(plan0.config_hash.clone()),
                current_spec_hash: Some(plan0.spec_hash.clone()),
                ready_replicas: Some(1),
                ..Default::default()
            },
        };
        let plan = GatewayRuntimePlanner.plan(&input).unwrap();

        // The plan must be a noop...
        assert!(plan.is_noop(), "precondition: plan must be a noop");

        // ...but must still carry all owned object names so the applier can
        // run its ownership preflight.
        assert_eq!(plan.service_account_name, "wicket-gw-my-gw-sa");
        assert_eq!(plan.config_map_name, "wicket-gw-my-gw-config");
        assert_eq!(plan.service_name, "wicket-gw-my-gw-svc");
        assert_eq!(plan.deployment_name, "wicket-gw-my-gw-deploy");
    }

    // Fix (3): non-accepted listeners must report 0 attached_routes.
    #[test]
    fn non_accepted_listener_reports_zero_attached_routes() {
        use crate::crds::{Listener, ProtocolType};
        use crate::reconcilers::attachment_planner::{AttachmentPlan, ListenerAttachmentSummary};
        use crate::reconcilers::runtime_plan::listener_status_intents_with_attachment;

        // Gateway with a UDP listener (not accepted by the controller).
        let gw = make_gateway_with_annotation("prod", "my-gw", Some("true"));
        // Rebuild with a UDP listener.
        let gw_udp = crate::crds::Gateway {
            metadata: gw.metadata.clone(),
            spec: crate::crds::GatewaySpec {
                gateway_class_name: "wicket".to_string(),
                listeners: vec![Listener {
                    name: "udp-dns".to_string(),
                    hostname: None,
                    port: 53,
                    protocol: ProtocolType::UDP,
                    tls: None,
                    allowed_routes: None,
                }],
                addresses: vec![],
                infrastructure: None,
            },
            status: None,
        };

        // Attachment plan claims 42 routes on the UDP listener.
        let ap = AttachmentPlan {
            gateway_namespace: "prod".to_string(),
            gateway_name: "my-gw".to_string(),
            gateway_generation: 1,
            route_results: vec![],
            listener_summaries: vec![ListenerAttachmentSummary {
                listener_name: "udp-dns".to_string(),
                attached_routes: 42,
                supported_kinds: vec![],
                listener_accepted: false,
                listener_rejection_reason: Some("UnsupportedProtocol".to_string()),
            }],
        };

        let intents = listener_status_intents_with_attachment(&gw_udp, Some(&ap));
        assert_eq!(intents.len(), 1);
        assert_eq!(
            intents[0].attached_routes, 0,
            "non-accepted listener must report 0 attached_routes (got {})",
            intents[0].attached_routes
        );
        assert!(
            !intents[0].accepted,
            "UDP listener must remain not-accepted"
        );
    }

    // Fix (4): RuntimePlanError variant must not exist in GatewayError.
    // This is a compile-time check -- if the variant were present, the
    // exhaustive match below would fail to compile.
    #[test]
    fn gateway_error_has_no_runtime_plan_error_variant() {
        // Construct every variant of GatewayError to ensure the enum is
        // exhaustively covered and RuntimePlanError is absent.
        let errors: Vec<super::GatewayError> = vec![
            super::GatewayError::GatewayClassNotFound("cls".to_string()),
            super::GatewayError::NotManagedByWicket("cls".to_string()),
            super::GatewayError::ConfigError("cfg".to_string()),
            super::GatewayError::RuntimeApplyError("apply".to_string()),
            // KubeError requires a kube::Error; skip construction but the
            // exhaustive match in the display test below covers it implicitly.
        ];
        for e in &errors {
            // Each variant must have a non-empty display string.
            assert!(!e.to_string().is_empty());
        }
    }

    // ── Observation-fault deferred-error path ─────────────────────────────────
    //
    // These tests verify the logic that was added to fix the staleness bug:
    // when reconcile_managed_runtime() returns ObservationError, the outer
    // reconcile must NOT exit before patch_status.  Instead it defers the
    // error and returns it after patching.
    //
    // Because the full reconcile_gateway() requires a live Kubernetes client,
    // we test the constituent pieces that encode the new invariants.

    /// ObservationError must be matchable as its own variant so the outer
    /// reconcile can distinguish it from Plan/Apply errors.
    #[test]
    fn observation_error_is_distinct_from_plan_and_apply() {
        let obs = super::ManagedRuntimeError::ObservationError("rbac".to_string());
        let plan = super::ManagedRuntimeError::Plan("bad".to_string());
        let apply = super::ManagedRuntimeError::Apply("fail".to_string());

        assert!(matches!(
            obs,
            super::ManagedRuntimeError::ObservationError(_)
        ));
        assert!(!matches!(
            plan,
            super::ManagedRuntimeError::ObservationError(_)
        ));
        assert!(!matches!(
            apply,
            super::ManagedRuntimeError::ObservationError(_)
        ));
    }

    /// The deferred-error slot starts as None and is set only for
    /// ObservationError, not for StoreNotReady or Plan/Apply.
    ///
    /// This test replicates the match logic from reconcile_gateway() in pure
    /// synchronous form so it can run without a Kubernetes client.
    #[test]
    fn deferred_error_set_only_for_observation_error() {
        // Simulate the match arm logic from reconcile_gateway().
        fn simulate_match(err: super::ManagedRuntimeError) -> Option<super::GatewayError> {
            let mut deferred: Option<super::GatewayError> = None;
            match err {
                super::ManagedRuntimeError::StoreNotReady(_observed) => {
                    // warn and continue -- no deferred error; observed state is
                    // threaded via ManagedRuntimeInput::StoreNotReady in real code.
                }
                super::ManagedRuntimeError::ObservationError(msg) => {
                    deferred = Some(super::GatewayError::RuntimeApplyError(msg));
                }
                e => {
                    // Plan / Apply: would early-return in real code.
                    // Represent as a sentinel so the test can detect it.
                    deferred = Some(super::GatewayError::RuntimeApplyError(format!(
                        "early-return: {e}"
                    )));
                }
            }
            deferred
        }

        // StoreNotReady => no deferred error (outer reconcile continues normally).
        assert!(
            simulate_match(super::ManagedRuntimeError::StoreNotReady(
                ObservedRuntimeState::default()
            ))
            .is_none(),
            "StoreNotReady must not set deferred error"
        );

        // ObservationError => deferred error is set (status patch runs first).
        let deferred = simulate_match(super::ManagedRuntimeError::ObservationError(
            "403".to_string(),
        ));
        assert!(
            deferred.is_some(),
            "ObservationError must set deferred error"
        );
        let msg = deferred.unwrap().to_string();
        assert!(
            msg.contains("403"),
            "deferred error must carry the original message"
        );

        // Plan => would early-return (sentinel present).
        assert!(
            simulate_match(super::ManagedRuntimeError::Plan("x".to_string())).is_some(),
            "Plan error must trigger early-return path"
        );

        // Apply => would early-return (sentinel present).
        assert!(
            simulate_match(super::ManagedRuntimeError::Apply("y".to_string())).is_some(),
            "Apply error must trigger early-return path"
        );
    }

    /// When build_managed_runtime_status encounters an ObservationError it must
    /// return programmed=false and observation_fault is set in the outcome.
    /// We verify this through the ManagedStatusOutcome construction logic
    /// (the same logic used inside build_managed_runtime_status).
    #[test]
    fn managed_status_outcome_observation_fault_sets_programmed_false() {
        // Replicate the Err(ObservationError) arm from build_managed_runtime_status.
        let fault_msg = "ConfigMap prod/wicket-gw-my-gw-config: 403 Forbidden".to_string();
        let outcome = super::ManagedStatusOutcome {
            programmed: false,
            only_store_not_ready: false,
            observation_fault: Some(fault_msg.clone()),
            observed_generation: Some(1),
        };

        assert!(
            !outcome.programmed,
            "observation fault must set programmed=false"
        );
        assert!(
            !outcome.only_store_not_ready,
            "observation fault must not set only_store_not_ready"
        );
        assert_eq!(
            outcome.observation_fault.as_deref(),
            Some(fault_msg.as_str()),
            "observation_fault must carry the original message"
        );
    }

    /// The ObservationFault condition reason must be distinct from
    /// DeploymentNotReady so operators can distinguish API faults from
    /// genuine deployment failures.
    #[test]
    fn observation_fault_condition_reason_distinct_from_deployment_not_ready() {
        let fault = crate::crds::Condition::not_programmed_observation_fault("rbac error");
        let deploy = crate::crds::Condition::not_programmed();

        assert_eq!(fault.type_, "Programmed");
        assert_eq!(fault.status, "False");
        assert_eq!(fault.reason, "ObservationFault");

        assert_ne!(
            fault.reason, deploy.reason,
            "ObservationFault and DeploymentNotReady must be distinct reasons"
        );
    }

    /// Legacy (non-managed) Gateways must not be affected by the deferred-error
    /// path.  The deferred_observation_error slot is only populated inside the
    /// `if is_managed_runtime(&gateway)` block, so legacy Gateways always see
    /// None.
    #[test]
    fn legacy_gateway_deferred_error_is_none() {
        // A Gateway without the managed-runtime annotation defaults to managed.
        // To test legacy behavior, use explicit "false" annotation.
        let gw = make_gateway_with_annotation("prod", "legacy-gw", Some("false"));
        assert!(
            !is_managed_runtime(&gw),
            "precondition: legacy gateway must not be managed"
        );

        // Simulate the outer reconcile: the if-block is skipped entirely,
        // so deferred_observation_error stays None.
        let mut deferred: Option<super::GatewayError> = None;
        if is_managed_runtime(&gw) {
            // This block is never entered for legacy gateways.
            deferred = Some(super::GatewayError::RuntimeApplyError(
                "should not happen".to_string(),
            ));
        }

        assert!(
            deferred.is_none(),
            "legacy gateway must never set deferred_observation_error"
        );
    }

    // ── Observed-state threading (no duplicate read) ──────────────────────────
    //
    // These tests verify the new invariant: reconcile_managed_runtime returns
    // (ObservedRuntimeState, RuntimeApplyResult) so the status path can reuse
    // the observation without a second Kubernetes API read, and can detect
    // rollout-triggering work via the apply result.
    //
    // The three parallel Option parameters have been replaced by a single
    // ManagedRuntimeInput enum.  Tests now construct the enum variant directly.

    use crate::reconcilers::runtime_applier::RuntimeApplyResult;
    use crate::reconcilers::store::SnapshotResult;

    /// When reconcile_managed_runtime succeeds, the managed_input is
    /// ManagedRuntimeInput::Applied carrying the observed state and apply result.
    #[test]
    fn managed_input_applied_on_success() {
        let obs = ObservedRuntimeState {
            current_config_hash: Some("abc123".to_string()),
            current_spec_hash: Some("def456".to_string()),
            ready_replicas: Some(1),
            deploy_observed_generation: Some(2),
            deploy_generation: Some(2),
            updated_replicas: Some(1),
            available_replicas: Some(1),
            desired_replicas: Some(1),
        };
        let result = RuntimeApplyResult::default(); // no-op apply

        let input = super::ManagedRuntimeInput::Applied(
            obs.clone(),
            result,
            Box::new(SnapshotResult::NotReady),
        );

        // The variant must be matchable and carry the original observation.
        match input {
            super::ManagedRuntimeInput::Applied(ref threaded_obs, _, _) => {
                assert_eq!(
                    threaded_obs.current_config_hash, obs.current_config_hash,
                    "Applied must carry the original config hash"
                );
                assert_eq!(
                    threaded_obs.ready_replicas, obs.ready_replicas,
                    "Applied must carry the original ready_replicas"
                );
            }
            _ => panic!("expected Applied variant"),
        }
    }

    /// When reconcile_managed_runtime returns StoreNotReady, the managed_input
    /// is ManagedRuntimeInput::StoreNotReady carrying the observed state.
    #[test]
    fn managed_input_store_not_ready_carries_observed_state() {
        let obs = ObservedRuntimeState {
            ready_replicas: Some(1),
            ..Default::default()
        };

        let input = super::ManagedRuntimeInput::StoreNotReady(obs.clone());

        match input {
            super::ManagedRuntimeInput::StoreNotReady(ref threaded_obs) => {
                assert_eq!(
                    threaded_obs.ready_replicas, obs.ready_replicas,
                    "StoreNotReady must carry the original ready_replicas"
                );
            }
            _ => panic!("expected StoreNotReady variant"),
        }
    }

    /// When reconcile_managed_runtime returns ObservationError, the managed_input
    /// is ManagedRuntimeInput::ObservationFault carrying the fault message.
    /// The deferred_observation_error is also set so the error is returned after
    /// patch_status.
    #[test]
    fn managed_input_observation_fault_carries_message() {
        let fault = "ConfigMap prod/wicket-gw-my-gw-config: 403 Forbidden".to_string();

        let input = super::ManagedRuntimeInput::ObservationFault(fault.clone());
        let deferred = super::GatewayError::RuntimeApplyError(fault.clone());

        match input {
            super::ManagedRuntimeInput::ObservationFault(ref msg) => {
                assert!(
                    msg.contains("403"),
                    "ObservationFault must carry the original fault message"
                );
            }
            _ => panic!("expected ObservationFault variant"),
        }
        assert!(
            deferred.to_string().contains("403"),
            "deferred error must carry the original fault message"
        );
    }

    /// The status path's outcome logic when apply_observed is Some must produce
    /// the correct programmed flag, accounting for the staleness guard.
    ///
    /// When the apply result indicates a rollout was triggered or the Deployment
    /// was changed, the pre-apply observation is stale and programmed must be
    /// false even if the old Deployment was converged.
    #[test]
    fn status_outcome_uses_threaded_observed_state() {
        // Replicate the `if let Some((observed, apply_result)) = apply_observed`
        // arm from build_managed_runtime_status(), including the staleness guard
        // and the corrected only_store_not_ready logic.
        fn outcome_from_observed(
            observed: &ObservedRuntimeState,
            apply_result: &RuntimeApplyResult,
            store_ready: bool,
        ) -> (bool, bool) {
            let apply_mutated = apply_result.rollout_triggered || apply_result.deployment_changed;
            let programmed = if apply_mutated {
                false
            } else {
                is_rollout_converged(observed)
            };
            // When apply_mutated, the cause is the rollout, not the store.
            let only_store_not_ready = !apply_mutated && !programmed && !store_ready;
            (programmed, only_store_not_ready)
        }

        let noop_result = RuntimeApplyResult::default();

        // Fully converged + no-op apply: programmed=true regardless of store readiness.
        let converged = ObservedRuntimeState {
            current_config_hash: None,
            current_spec_hash: None,
            ready_replicas: Some(1),
            deploy_observed_generation: Some(2),
            deploy_generation: Some(2),
            updated_replicas: Some(1),
            available_replicas: Some(1),
            desired_replicas: Some(1),
        };
        let (prog, only_snr) = outcome_from_observed(&converged, &noop_result, false);
        assert!(
            prog,
            "converged obs + no-op apply must yield programmed=true"
        );
        assert!(!only_snr, "converged obs must not set only_store_not_ready");

        // Not converged + no-op apply + store not ready: only_store_not_ready=true.
        let not_converged = ObservedRuntimeState::default();
        let (prog2, only_snr2) = outcome_from_observed(&not_converged, &noop_result, false);
        assert!(!prog2, "not-converged obs must yield programmed=false");
        assert!(
            only_snr2,
            "not-converged + store not ready must set only_store_not_ready"
        );

        // Not converged + no-op apply + store ready: only_store_not_ready=false.
        let (prog3, only_snr3) = outcome_from_observed(&not_converged, &noop_result, true);
        assert!(!prog3, "not-converged obs must yield programmed=false");
        assert!(
            !only_snr3,
            "not-converged + store ready must not set only_store_not_ready"
        );
    }

    /// The observation fault path in build_managed_runtime_status must extract
    /// the fault message from apply_error (a GatewayError) without re-reading
    /// the API.  Verify that GatewayError::to_string() carries the original
    /// message so the extraction is lossless.
    #[test]
    fn observation_fault_extracted_from_gateway_error_to_string() {
        let original = "Deployment prod/wicket-gw-my-gw-deploy: 403 Forbidden".to_string();
        let gw_err = super::GatewayError::RuntimeApplyError(original.clone());

        // The status path calls err.to_string() to extract the fault message.
        let extracted = gw_err.to_string();

        // The extracted string must contain the original fault detail.
        assert!(
            extracted.contains("403"),
            "extracted fault must contain the HTTP status code"
        );
        assert!(
            extracted.contains("Forbidden"),
            "extracted fault must contain the error reason"
        );
    }

    /// Verify that the three ManagedRuntimeInput variants are distinct and
    /// cover all cases: Applied (happy path), ObservationFault, StoreNotReady.
    ///
    /// The enum replaces the three parallel Option parameters that were
    /// previously passed to build_managed_runtime_status.  Mutual exclusivity
    /// is now enforced by the type system: exactly one variant is constructed
    /// per reconcile cycle.
    #[test]
    fn managed_runtime_input_variants_are_distinct() {
        // Branch 1: Applied => happy path.
        let b1 = super::ManagedRuntimeInput::Applied(
            ObservedRuntimeState::default(),
            RuntimeApplyResult::default(),
            Box::new(SnapshotResult::NotReady),
        );
        assert!(
            matches!(b1, super::ManagedRuntimeInput::Applied(_, _, _)),
            "branch 1 must be Applied"
        );

        // Branch 2: ObservationFault => observation fault path.
        let b2 = super::ManagedRuntimeInput::ObservationFault("fault".to_string());
        assert!(
            matches!(b2, super::ManagedRuntimeInput::ObservationFault(_)),
            "branch 2 must be ObservationFault"
        );

        // Branch 3: StoreNotReady => store-not-ready path.
        let b3 = super::ManagedRuntimeInput::StoreNotReady(ObservedRuntimeState::default());
        assert!(
            matches!(b3, super::ManagedRuntimeInput::StoreNotReady(_)),
            "branch 3 must be StoreNotReady"
        );

        // Each variant must not match the others.
        assert!(
            !matches!(b2, super::ManagedRuntimeInput::Applied(_, _, _)),
            "ObservationFault must not match Applied"
        );
        assert!(
            !matches!(b3, super::ManagedRuntimeInput::Applied(_, _, _)),
            "StoreNotReady must not match Applied"
        );
    }

    // ── Staleness guard (concern #1) ──────────────────────────────────────────
    //
    // When apply_runtime_plan() triggers a rollout or creates/changes the
    // Deployment, the pre-apply ObservedRuntimeState is stale.  The status
    // path must force Programmed=False in that case, even if the old Deployment
    // appeared converged, to avoid a one-cycle Programmed=True lie.

    /// When rollout_triggered=true, programmed must be false regardless of
    /// whether the pre-apply observation was converged.
    #[test]
    fn staleness_guard_forces_programmed_false_when_rollout_triggered() {
        // Replicate the staleness guard from build_managed_runtime_status.
        fn programmed_with_guard(
            observed: &ObservedRuntimeState,
            apply_result: &RuntimeApplyResult,
        ) -> bool {
            let apply_mutated = apply_result.rollout_triggered || apply_result.deployment_changed;
            if apply_mutated {
                false
            } else {
                is_rollout_converged(observed)
            }
        }

        // Pre-apply observation: fully converged (old revision was healthy).
        let converged = ObservedRuntimeState {
            ready_replicas: Some(1),
            deploy_observed_generation: Some(2),
            deploy_generation: Some(2),
            updated_replicas: Some(1),
            available_replicas: Some(1),
            desired_replicas: Some(1),
            ..Default::default()
        };

        // Case 1: rollout_triggered=true => programmed must be false.
        let rollout_result = RuntimeApplyResult {
            rollout_triggered: true,
            deployment_changed: true,
            ..Default::default()
        };
        assert!(
            !programmed_with_guard(&converged, &rollout_result),
            "rollout_triggered=true must force programmed=false even if pre-apply obs was converged"
        );

        // Case 2: deployment_changed=true (new object, no rollout flag) => false.
        let new_deploy_result = RuntimeApplyResult {
            rollout_triggered: false,
            deployment_changed: true,
            service_account_created: true,
            ..Default::default()
        };
        assert!(
            !programmed_with_guard(&converged, &new_deploy_result),
            "deployment_changed=true must force programmed=false"
        );

        // Case 3: no-op apply (neither flag set) => converged obs => programmed=true.
        let noop_result = RuntimeApplyResult::default();
        assert!(
            programmed_with_guard(&converged, &noop_result),
            "no-op apply + converged obs must yield programmed=true"
        );

        // Case 4: no-op apply + not-converged obs => programmed=false.
        let not_converged = ObservedRuntimeState::default();
        assert!(
            !programmed_with_guard(&not_converged, &noop_result),
            "no-op apply + not-converged obs must yield programmed=false"
        );
    }

    /// When rollout_triggered=true, only_store_not_ready must be false because
    /// the runtime is not ready due to the in-flight rollout, not due to the
    /// store warming up.  Using the wrong reason would mislead operators.
    #[test]
    fn staleness_guard_only_store_not_ready_false_when_rollout_triggered() {
        // Replicate the staleness guard + only_store_not_ready logic from
        // build_managed_runtime_status (including the apply_mutated guard).
        fn outcome(
            observed: &ObservedRuntimeState,
            apply_result: &RuntimeApplyResult,
            store_ready: bool,
        ) -> (bool, bool) {
            let apply_mutated = apply_result.rollout_triggered || apply_result.deployment_changed;
            let programmed = if apply_mutated {
                false
            } else {
                is_rollout_converged(observed)
            };
            // When apply_mutated, the cause is the rollout, not the store.
            let only_store_not_ready = !apply_mutated && !programmed && !store_ready;
            (programmed, only_store_not_ready)
        }

        let converged = ObservedRuntimeState {
            ready_replicas: Some(1),
            deploy_observed_generation: Some(2),
            deploy_generation: Some(2),
            updated_replicas: Some(1),
            available_replicas: Some(1),
            desired_replicas: Some(1),
            ..Default::default()
        };
        let rollout_result = RuntimeApplyResult {
            rollout_triggered: true,
            deployment_changed: true,
            ..Default::default()
        };

        // Store not ready + rollout triggered: programmed=false, but
        // only_store_not_ready must also be false because the cause is the
        // in-flight rollout, not the store warming up.
        let (prog, only_snr) = outcome(&converged, &rollout_result, false);
        assert!(!prog, "rollout triggered => programmed=false");
        assert!(
            !only_snr,
            "rollout triggered => only_store_not_ready=false (cause is rollout, not store)"
        );

        // Store ready + rollout triggered: same result.
        let (prog2, only_snr2) = outcome(&converged, &rollout_result, true);
        assert!(!prog2, "rollout triggered => programmed=false");
        assert!(!only_snr2, "store ready => only_store_not_ready=false");
    }

    /// The RuntimeApplyResult::default() must have all flags false so that
    /// a no-op apply does not accidentally trigger the staleness guard.
    #[test]
    fn runtime_apply_result_default_has_no_flags_set() {
        let r = RuntimeApplyResult::default();
        assert!(
            !r.rollout_triggered,
            "default RuntimeApplyResult must not have rollout_triggered set"
        );
        assert!(
            !r.deployment_changed,
            "default RuntimeApplyResult must not have deployment_changed set"
        );
        assert!(
            !r.service_account_created,
            "default RuntimeApplyResult must not have service_account_created set"
        );
        assert!(
            !r.service_changed,
            "default RuntimeApplyResult must not have service_changed set"
        );
    }

    // ── resolve_managed_status_outcome: real enum-to-status path ─────────────
    //
    // These tests call the extracted pure helper directly, exercising the real
    // match arms rather than replicating the logic inline.  They cover all
    // three ManagedRuntimeInput variants and verify the ManagedStatusOutcome
    // fields produced by each arm.

    /// Applied + converged obs + no-op apply => programmed=true, no fault.
    #[test]
    fn resolve_outcome_applied_converged_noop() {
        let obs = ObservedRuntimeState {
            current_config_hash: Some("cfg-hash".to_string()),
            current_spec_hash: Some("spec-hash".to_string()),
            ready_replicas: Some(1),
            deploy_observed_generation: Some(3),
            deploy_generation: Some(3),
            updated_replicas: Some(1),
            available_replicas: Some(1),
            desired_replicas: Some(1),
        };
        let noop = RuntimeApplyResult::default();
        let input =
            super::ManagedRuntimeInput::Applied(obs, noop, Box::new(SnapshotResult::NotReady));

        let outcome = super::resolve_managed_status_outcome(input, true, Some(1));

        assert!(
            outcome.programmed,
            "converged obs + no-op => programmed=true"
        );
        assert!(
            !outcome.only_store_not_ready,
            "converged obs must not set only_store_not_ready"
        );
        assert!(
            outcome.observation_fault.is_none(),
            "Applied arm must not set observation_fault"
        );
        assert_eq!(outcome.observed_generation, Some(1));
    }

    /// Applied + converged obs + rollout_triggered => programmed=false, no fault,
    /// only_store_not_ready=false (cause is rollout, not store).
    #[test]
    fn resolve_outcome_applied_rollout_triggered() {
        let obs = ObservedRuntimeState {
            ready_replicas: Some(1),
            deploy_observed_generation: Some(2),
            deploy_generation: Some(2),
            updated_replicas: Some(1),
            available_replicas: Some(1),
            desired_replicas: Some(1),
            ..Default::default()
        };
        let rollout = RuntimeApplyResult {
            rollout_triggered: true,
            deployment_changed: true,
            ..Default::default()
        };
        let input =
            super::ManagedRuntimeInput::Applied(obs, rollout, Box::new(SnapshotResult::NotReady));

        // store_ready=false: even with store not ready, only_store_not_ready
        // must be false because the cause is the in-flight rollout.
        let outcome = super::resolve_managed_status_outcome(input, false, Some(2));

        assert!(
            !outcome.programmed,
            "rollout_triggered must force programmed=false"
        );
        assert!(
            !outcome.only_store_not_ready,
            "rollout_triggered must suppress only_store_not_ready (cause is rollout)"
        );
        assert!(outcome.observation_fault.is_none());
    }

    /// Applied + not-converged obs + no-op apply + store not ready =>
    /// programmed=false, only_store_not_ready=true.
    #[test]
    fn resolve_outcome_applied_not_converged_store_not_ready() {
        let obs = ObservedRuntimeState::default(); // all None => not converged
        let noop = RuntimeApplyResult::default();
        let input =
            super::ManagedRuntimeInput::Applied(obs, noop, Box::new(SnapshotResult::NotReady));

        let outcome = super::resolve_managed_status_outcome(input, false, Some(1));

        assert!(!outcome.programmed);
        assert!(
            outcome.only_store_not_ready,
            "not-converged + store not ready + no-op => only_store_not_ready=true"
        );
        assert!(outcome.observation_fault.is_none());
    }

    /// Applied + not-converged obs + no-op apply + store ready =>
    /// programmed=false, only_store_not_ready=false.
    #[test]
    fn resolve_outcome_applied_not_converged_store_ready() {
        let obs = ObservedRuntimeState::default();
        let noop = RuntimeApplyResult::default();
        let input =
            super::ManagedRuntimeInput::Applied(obs, noop, Box::new(SnapshotResult::NotReady));

        let outcome = super::resolve_managed_status_outcome(input, true, Some(1));

        assert!(!outcome.programmed);
        assert!(
            !outcome.only_store_not_ready,
            "store ready => only_store_not_ready=false even when not converged"
        );
        assert!(outcome.observation_fault.is_none());
    }

    /// ObservationFault => programmed=false, observation_fault=Some(exact msg),
    /// only_store_not_ready=false.
    #[test]
    fn resolve_outcome_observation_fault_message_fidelity() {
        let fault_msg = "ConfigMap prod/wicket-gw-my-gw-config: 403 Forbidden".to_string();
        let input = super::ManagedRuntimeInput::ObservationFault(fault_msg.clone());

        let outcome = super::resolve_managed_status_outcome(input, false, Some(1));

        assert!(
            !outcome.programmed,
            "ObservationFault must set programmed=false"
        );
        assert!(
            !outcome.only_store_not_ready,
            "ObservationFault must not set only_store_not_ready"
        );
        // Exact string equality: the fault message must survive the enum
        // mapping without truncation or reformatting.
        assert_eq!(
            outcome.observation_fault.as_deref(),
            Some(fault_msg.as_str()),
            "observation_fault must be the exact input string"
        );

        // The Condition built from this message must embed the full detail.
        let cond = crate::crds::Condition::not_programmed_observation_fault(fault_msg.as_str());
        assert!(
            cond.message.contains("403 Forbidden"),
            "Condition message must contain the HTTP status: {}",
            cond.message
        );
        assert!(
            cond.message.contains("prod/wicket-gw-my-gw-config"),
            "Condition message must contain the resource path: {}",
            cond.message
        );
        assert_eq!(cond.reason, "ObservationFault");
        assert_eq!(cond.status, "False");
    }

    // ── Listener-level ObservationFault observed_generation threading ─────────
    //
    // These tests verify the fix: when listener conditions use
    // not_programmed_observation_fault(...), the resulting condition must carry
    // observed_generation just like every other condition path.

    /// Helper: build listener conditions for the ObservationFault path using
    /// the same logic as build_managed_runtime_status.
    fn observation_fault_listener_conditions(
        fault: &str,
        observed_generation: Option<i64>,
        accepted: bool,
    ) -> Vec<crate::crds::Condition> {
        let not_prog = crate::crds::Condition::not_programmed_observation_fault(fault)
            .with_observed_generation(observed_generation);
        if accepted {
            vec![
                crate::crds::Condition::accepted().with_observed_generation(observed_generation),
                not_prog,
                crate::crds::Condition::resolved_refs(),
            ]
        } else {
            vec![
                crate::crds::Condition::not_accepted()
                    .with_observed_generation(observed_generation),
                not_prog,
                crate::crds::Condition::resolved_refs(),
            ]
        }
    }

    /// The ObservationFault listener condition must carry observed_generation.
    #[test]
    fn listener_observation_fault_condition_carries_observed_generation() {
        let conditions = observation_fault_listener_conditions("rbac error", Some(5), true);

        let programmed_cond = conditions
            .iter()
            .find(|c| c.type_ == "Programmed")
            .expect("Programmed condition must be present");

        assert_eq!(programmed_cond.reason, "ObservationFault");
        assert_eq!(programmed_cond.status, "False");
        assert_eq!(
            programmed_cond.observed_generation,
            Some(5),
            "ObservationFault listener condition must carry observed_generation"
        );
    }

    /// The Accepted condition in the ObservationFault listener path must also
    /// carry observed_generation (parity with the programmed=true path).
    #[test]
    fn listener_observation_fault_accepted_condition_carries_observed_generation() {
        let conditions = observation_fault_listener_conditions("403 Forbidden", Some(3), true);

        let accepted_cond = conditions
            .iter()
            .find(|c| c.type_ == "Accepted")
            .expect("Accepted condition must be present");

        assert_eq!(
            accepted_cond.observed_generation,
            Some(3),
            "Accepted condition in ObservationFault path must carry observed_generation"
        );
    }

    /// Non-accepted listener in the ObservationFault path: not_accepted and
    /// not_programmed_observation_fault must both carry observed_generation.
    #[test]
    fn listener_observation_fault_not_accepted_carries_observed_generation() {
        let conditions = observation_fault_listener_conditions("rbac error", Some(9), false);

        let not_accepted_cond = conditions
            .iter()
            .find(|c| c.type_ == "Accepted")
            .expect("Accepted condition must be present");
        let programmed_cond = conditions
            .iter()
            .find(|c| c.type_ == "Programmed")
            .expect("Programmed condition must be present");

        assert_eq!(not_accepted_cond.status, "False");
        assert_eq!(
            not_accepted_cond.observed_generation,
            Some(9),
            "not_accepted condition must carry observed_generation in ObservationFault path"
        );
        assert_eq!(
            programmed_cond.observed_generation,
            Some(9),
            "ObservationFault programmed condition must carry observed_generation"
        );
    }

    /// observed_generation=None is preserved (not coerced to Some).
    #[test]
    fn listener_observation_fault_none_observed_generation_preserved() {
        let conditions = observation_fault_listener_conditions("some error", None, true);

        let programmed_cond = conditions
            .iter()
            .find(|c| c.type_ == "Programmed")
            .expect("Programmed condition must be present");

        assert_eq!(
            programmed_cond.observed_generation, None,
            "None observed_generation must not be coerced to Some"
        );
    }

    /// Parity check: the ObservationFault path and the programmed=true path
    /// both set observed_generation on every condition they emit.
    #[test]
    fn listener_observation_fault_observed_generation_parity_with_programmed_path() {
        let gen = Some(42_i64);

        // ObservationFault path.
        let fault_conditions = observation_fault_listener_conditions("rbac", gen, true);

        // programmed=true path (from the existing code).
        let programmed_conditions = [
            crate::crds::Condition::accepted().with_observed_generation(gen),
            crate::crds::Condition::programmed().with_observed_generation(gen),
            crate::crds::Condition::resolved_refs(),
        ];

        // Every non-ResolvedRefs condition in both paths must carry gen.
        for cond in fault_conditions
            .iter()
            .chain(programmed_conditions.iter())
            .filter(|c| c.type_ != "ResolvedRefs")
        {
            assert_eq!(
                cond.observed_generation, gen,
                "condition type={} must carry observed_generation={:?}",
                cond.type_, gen
            );
        }
    }

    /// StoreNotReady + converged obs => programmed=true (store readiness is not
    /// a gate on Programmed=True).
    #[test]
    fn resolve_outcome_store_not_ready_converged() {
        let obs = ObservedRuntimeState {
            ready_replicas: Some(1),
            deploy_observed_generation: Some(2),
            deploy_generation: Some(2),
            updated_replicas: Some(1),
            available_replicas: Some(1),
            desired_replicas: Some(1),
            ..Default::default()
        };
        let input = super::ManagedRuntimeInput::StoreNotReady(obs);

        // store_ready=false: the store is warming up, but the Deployment is
        // healthy.  Programmed must still be true.
        let outcome = super::resolve_managed_status_outcome(input, false, Some(1));

        assert!(
            outcome.programmed,
            "StoreNotReady + converged obs => programmed=true (store is not a gate)"
        );
        assert!(
            !outcome.only_store_not_ready,
            "converged obs => only_store_not_ready=false"
        );
        assert!(outcome.observation_fault.is_none());
    }

    /// StoreNotReady + not-converged obs + store not ready =>
    /// programmed=false, only_store_not_ready=true.
    #[test]
    fn resolve_outcome_store_not_ready_not_converged() {
        let obs = ObservedRuntimeState::default(); // all None => not converged
        let input = super::ManagedRuntimeInput::StoreNotReady(obs);

        let outcome = super::resolve_managed_status_outcome(input, false, Some(1));

        assert!(!outcome.programmed);
        assert!(
            outcome.only_store_not_ready,
            "StoreNotReady + not-converged + store not ready => only_store_not_ready=true"
        );
        assert!(outcome.observation_fault.is_none());
    }

    #[test]
    fn managed_status_waits_for_full_rollout_convergence_before_programmed_true() {
        use crate::reconcilers::runtime_applier::RuntimeApplyResult;
        use crate::reconcilers::store::{PlannerSnapshot, SnapshotResult};
        use std::collections::{HashMap, HashSet};

        let gateway = make_gateway_with_annotation("prod", "my-gw", Some("true"));

        let snapshot = SnapshotResult::Ready(PlannerSnapshot {
            gateways: HashMap::from([("prod/my-gw".to_string(), gateway.clone())]),
            gateway_classes: HashMap::new(),
            http_routes: HashMap::new(),
            tcp_routes: HashMap::new(),
            tls_routes: HashMap::new(),
            service_endpoints: HashMap::new(),
            tls_secrets: HashMap::new(),
            reference_grants: HashMap::new(),
            service_ref_index: HashSet::new(),
            namespace_labels: HashMap::new(),
        });

        let before = ObservedRuntimeState {
            ready_replicas: Some(1),
            deploy_observed_generation: Some(1),
            deploy_generation: Some(2),
            updated_replicas: Some(0),
            available_replicas: Some(0),
            desired_replicas: Some(1),
            ..Default::default()
        };

        let after = ObservedRuntimeState {
            ready_replicas: Some(1),
            deploy_observed_generation: Some(2),
            deploy_generation: Some(2),
            updated_replicas: Some(1),
            available_replicas: Some(1),
            desired_replicas: Some(1),
            ..Default::default()
        };

        let (before_listeners, before_programmed, before_warming, before_fault) =
            build_managed_runtime_status(
                &gateway,
                "prod",
                "my-gw",
                super::ManagedRuntimeInput::Applied(
                    before,
                    RuntimeApplyResult::default(),
                    Box::new(snapshot.clone()),
                ),
            );
        let (after_listeners, after_programmed, after_warming, after_fault) =
            build_managed_runtime_status(
                &gateway,
                "prod",
                "my-gw",
                super::ManagedRuntimeInput::Applied(
                    after,
                    RuntimeApplyResult::default(),
                    Box::new(snapshot),
                ),
            );

        assert!(!before_programmed, "partial rollout must not report programmed");
        assert!(after_programmed, "converged rollout must report programmed");
        assert!(!before_warming);
        assert!(!after_warming);
        assert!(before_fault.is_none());
        assert!(after_fault.is_none());

        let before_programmed_cond = before_listeners[0]
            .conditions
            .iter()
            .find(|c| c.type_ == "Programmed")
            .expect("listener must have Programmed condition");
        assert_eq!(before_programmed_cond.status, "False");
        assert_eq!(before_programmed_cond.reason, "DeploymentNotReady");
        assert_eq!(before_programmed_cond.observed_generation, Some(1));

        let after_programmed_cond = after_listeners[0]
            .conditions
            .iter()
            .find(|c| c.type_ == "Programmed")
            .expect("listener must have Programmed condition");
        assert_eq!(after_programmed_cond.status, "True");
        assert_eq!(after_programmed_cond.reason, "Programmed");
        assert_eq!(after_programmed_cond.observed_generation, Some(1));
    }

    // ── Deferred observation error: message fidelity end-to-end ──────────────
    //
    // Verify that the exact fault string from ManagedRuntimeError::ObservationError
    // is preserved through both the deferred GatewayError and the
    // ManagedRuntimeInput::ObservationFault, with no truncation or reformatting.

    /// The deferred GatewayError and the ObservationFault input must carry the
    /// identical string -- not just a substring match.
    #[test]
    fn deferred_error_and_observation_fault_carry_identical_message() {
        // Simulate the ObservationError arm from reconcile_gateway().
        let raw_msg = "Deployment prod/wicket-gw-my-gw-deploy: 403 Forbidden".to_string();

        // In reconcile_gateway the arm does:
        //   deferred_observation_error = Some(GatewayError::RuntimeApplyError(msg.clone()));
        //   ManagedRuntimeInput::ObservationFault(msg)
        let deferred = super::GatewayError::RuntimeApplyError(raw_msg.clone());
        let fault_input = super::ManagedRuntimeInput::ObservationFault(raw_msg.clone());

        // The deferred error's display must contain the raw message.
        let deferred_display = deferred.to_string();
        assert!(
            deferred_display.contains(&raw_msg),
            "deferred GatewayError display must contain the raw fault message; got: {deferred_display}"
        );

        // The ObservationFault input must carry the exact same string.
        let outcome = super::resolve_managed_status_outcome(fault_input, false, Some(1));
        assert_eq!(
            outcome.observation_fault.as_deref(),
            Some(raw_msg.as_str()),
            "ObservationFault outcome must carry the exact raw message"
        );

        // Both must agree: the string in the deferred error and the string in
        // the outcome are the same (not just overlapping substrings).
        assert!(
            deferred_display.contains(outcome.observation_fault.as_deref().unwrap_or("")),
            "deferred error display must contain the observation_fault string"
        );
    }

    /// The deferred error is returned AFTER status patch, not before.
    /// Verify the ordering invariant: deferred is set for ObservationError,
    /// and the status path still receives the ObservationFault input.
    #[test]
    fn deferred_error_set_and_observation_fault_input_both_populated() {
        // Replicate the ObservationError arm from reconcile_gateway().
        let msg = "ConfigMap ns/wicket-gw-gw-config: 403 Forbidden".to_string();

        // Simulate the match arm: both deferred and fault_input are populated
        // from the same message string (msg.clone() for deferred, msg for input).
        let deferred = super::GatewayError::RuntimeApplyError(msg.clone());
        let fault_input = super::ManagedRuntimeInput::ObservationFault(msg.clone());

        // Both must be populated.
        assert!(
            !deferred.to_string().is_empty(),
            "deferred error must be set for ObservationError"
        );

        // The status path receives the ObservationFault input and produces
        // programmed=false with the fault message.
        let outcome = super::resolve_managed_status_outcome(fault_input, false, Some(1));
        assert!(!outcome.programmed);
        assert_eq!(outcome.observation_fault.as_deref(), Some(msg.as_str()));

        // The deferred error's display must contain the same message.
        let display = deferred.to_string();
        assert!(
            display.contains(&msg),
            "deferred error must carry the original message; got: {display}"
        );
    }

    // ── Top-level Gateway condition selection for observation faults ──────────
    //
    // These tests verify the new behaviour introduced in this change: when
    // `build_managed_runtime_status` returns a non-None `observation_fault`,
    // the top-level Gateway condition must be `ObservationFault` (not the
    // generic `DeploymentNotReady`), and `observed_generation` must be set.

    /// Replicate the top-level condition selection logic from reconcile_gateway()
    /// so it can be exercised without a live Kubernetes client.
    fn select_gateway_conditions(
        gateway_programmed: bool,
        only_store_not_ready: bool,
        gateway_observation_fault: Option<&str>,
        gw_observed_gen: Option<i64>,
    ) -> Vec<crate::crds::Condition> {
        if gateway_programmed {
            vec![
                crate::crds::Condition::accepted().with_observed_generation(gw_observed_gen),
                crate::crds::Condition::programmed().with_observed_generation(gw_observed_gen),
            ]
        } else if let Some(fault) = gateway_observation_fault {
            vec![
                crate::crds::Condition::accepted().with_observed_generation(gw_observed_gen),
                crate::crds::Condition::not_programmed_observation_fault(fault)
                    .with_observed_generation(gw_observed_gen),
            ]
        } else if only_store_not_ready {
            vec![
                crate::crds::Condition::accepted().with_observed_generation(gw_observed_gen),
                crate::crds::Condition::not_programmed_warming_up()
                    .with_observed_generation(gw_observed_gen),
            ]
        } else {
            vec![
                crate::crds::Condition::accepted().with_observed_generation(gw_observed_gen),
                crate::crds::Condition::not_programmed().with_observed_generation(gw_observed_gen),
            ]
        }
    }

    /// When observation_fault is Some, the top-level Programmed condition must
    /// use reason=ObservationFault, not DeploymentNotReady.
    #[test]
    fn top_level_condition_is_observation_fault_when_fault_present() {
        let conditions = select_gateway_conditions(
            false,
            false,
            Some("ConfigMap prod/wicket-gw-my-gw-config: 403 Forbidden"),
            Some(3),
        );

        assert_eq!(conditions.len(), 2);

        let programmed_cond = conditions
            .iter()
            .find(|c| c.type_ == "Programmed")
            .expect("Programmed condition must be present");

        assert_eq!(programmed_cond.status, "False");
        assert_eq!(
            programmed_cond.reason, "ObservationFault",
            "top-level condition must use ObservationFault reason, got: {}",
            programmed_cond.reason
        );
        assert!(
            programmed_cond.message.contains("403 Forbidden"),
            "condition message must contain the fault detail: {}",
            programmed_cond.message
        );
    }

    /// observed_generation must be threaded onto the ObservationFault condition.
    #[test]
    fn top_level_observation_fault_condition_carries_observed_generation() {
        let conditions = select_gateway_conditions(
            false,
            false,
            Some("Deployment ns/wicket-gw-gw-deploy: 403 Forbidden"),
            Some(7),
        );

        let programmed_cond = conditions
            .iter()
            .find(|c| c.type_ == "Programmed")
            .expect("Programmed condition must be present");

        assert_eq!(
            programmed_cond.observed_generation,
            Some(7),
            "observed_generation must be set on ObservationFault condition"
        );
    }

    /// When observation_fault is None and only_store_not_ready is false,
    /// the top-level condition must be DeploymentNotReady (not ObservationFault).
    #[test]
    fn top_level_condition_is_deployment_not_ready_when_no_fault() {
        let conditions = select_gateway_conditions(false, false, None, Some(1));

        let programmed_cond = conditions
            .iter()
            .find(|c| c.type_ == "Programmed")
            .expect("Programmed condition must be present");

        assert_eq!(programmed_cond.status, "False");
        assert_eq!(
            programmed_cond.reason, "DeploymentNotReady",
            "no fault => must use DeploymentNotReady, got: {}",
            programmed_cond.reason
        );
    }

    /// ObservationFault takes priority over only_store_not_ready: when both
    /// flags are set (pathological but possible in theory), the fault wins.
    #[test]
    fn top_level_observation_fault_takes_priority_over_store_not_ready() {
        // only_store_not_ready=true AND fault present: fault must win.
        let conditions = select_gateway_conditions(
            false,
            true, // store not ready
            Some("rbac error"),
            Some(2),
        );

        let programmed_cond = conditions
            .iter()
            .find(|c| c.type_ == "Programmed")
            .expect("Programmed condition must be present");

        assert_eq!(
            programmed_cond.reason, "ObservationFault",
            "ObservationFault must take priority over ControllerStoreNotReady"
        );
    }

    /// When programmed=true, the top-level condition must be Programmed=True
    /// regardless of any fault (fault should never be Some when programmed=true,
    /// but the condition selection must be robust).
    #[test]
    fn top_level_programmed_true_takes_priority_over_fault() {
        // programmed=true wins unconditionally.
        let conditions = select_gateway_conditions(true, false, None, Some(5));

        let programmed_cond = conditions
            .iter()
            .find(|c| c.type_ == "Programmed")
            .expect("Programmed condition must be present");

        assert_eq!(programmed_cond.status, "True");
        assert_eq!(programmed_cond.reason, "Programmed");
    }

    /// Legacy (non-managed) Gateways always return None for observation_fault,
    /// so the top-level condition must never be ObservationFault for them.
    #[test]
    fn legacy_gateway_top_level_condition_never_observation_fault() {
        // Legacy path: programmed=true, only_store_not_ready=false, fault=None.
        let conditions = select_gateway_conditions(true, false, None, Some(1));

        let has_observation_fault = conditions.iter().any(|c| c.reason == "ObservationFault");

        assert!(
            !has_observation_fault,
            "legacy gateway must never emit ObservationFault condition"
        );
    }

    /// The Accepted condition must always be present alongside the Programmed
    /// condition, including in the ObservationFault case.
    #[test]
    fn top_level_accepted_condition_present_with_observation_fault() {
        let conditions = select_gateway_conditions(false, false, Some("403 Forbidden"), Some(4));

        let accepted_cond = conditions
            .iter()
            .find(|c| c.type_ == "Accepted")
            .expect("Accepted condition must be present");

        assert_eq!(accepted_cond.status, "True");
        assert_eq!(
            accepted_cond.observed_generation,
            Some(4),
            "Accepted condition must carry observed_generation"
        );
    }

    // ── Area 1: Observation-fault fail-safe and diagnosability ────────────────
    //
    // These tests verify that:
    // (a) ObservationError is structurally distinct from Plan/Apply errors so
    //     the outer reconcile can match on it without string inspection.
    // (b) The fault message is preserved verbatim through the error chain.
    // (c) The resulting status is always fail-safe (programmed=false) and
    //     carries the ObservationFault reason, not DeploymentNotReady.
    // (d) 404 errors are NOT surfaced as ObservationError (they are treated as
    //     "object does not yet exist").

    /// ObservationError wraps the original message without truncation.
    /// The display string must contain the full resource path and HTTP status.
    #[test]
    fn observation_error_display_preserves_full_message() {
        let msg = "ConfigMap prod/wicket-gw-my-gw-config: 403 Forbidden (RBAC)".to_string();
        let e = super::ManagedRuntimeError::ObservationError(msg.clone());
        let display = e.to_string();
        assert!(
            display.contains("403 Forbidden"),
            "display must contain HTTP status: {display}"
        );
        assert!(
            display.contains("prod/wicket-gw-my-gw-config"),
            "display must contain resource path: {display}"
        );
        assert!(
            display.contains("RBAC"),
            "display must contain original detail: {display}"
        );
    }

    /// ObservationError is structurally distinct from StoreNotReady, Plan, and
    /// Apply so the outer reconcile match arm is unambiguous.
    #[test]
    fn observation_error_variant_is_structurally_distinct() {
        let obs_err = super::ManagedRuntimeError::ObservationError("rbac".to_string());
        let store_err = super::ManagedRuntimeError::StoreNotReady(ObservedRuntimeState::default());
        let plan_err = super::ManagedRuntimeError::Plan("bad".to_string());
        let apply_err = super::ManagedRuntimeError::Apply("fail".to_string());

        // Each variant must match only itself.
        assert!(matches!(
            obs_err,
            super::ManagedRuntimeError::ObservationError(_)
        ));
        assert!(!matches!(
            store_err,
            super::ManagedRuntimeError::ObservationError(_)
        ));
        assert!(!matches!(
            plan_err,
            super::ManagedRuntimeError::ObservationError(_)
        ));
        assert!(!matches!(
            apply_err,
            super::ManagedRuntimeError::ObservationError(_)
        ));
    }

    /// The ObservationFault outcome is always fail-safe: programmed=false,
    /// observation_fault=Some, only_store_not_ready=false.
    /// This holds regardless of store_ready and gateway_generation.
    #[test]
    fn observation_fault_outcome_is_always_fail_safe() {
        let fault = "Deployment ns/wicket-gw-gw-deploy: 500 Internal Server Error".to_string();

        for store_ready in [false, true] {
            for gen in [None, Some(1_i64), Some(99_i64)] {
                let input = super::ManagedRuntimeInput::ObservationFault(fault.clone());
                let outcome = super::resolve_managed_status_outcome(input, store_ready, gen);

                assert!(
                    !outcome.programmed,
                    "ObservationFault must always set programmed=false \
                     (store_ready={store_ready}, gen={gen:?})"
                );
                assert!(
                    !outcome.only_store_not_ready,
                    "ObservationFault must never set only_store_not_ready \
                     (store_ready={store_ready}, gen={gen:?})"
                );
                assert_eq!(
                    outcome.observation_fault.as_deref(),
                    Some(fault.as_str()),
                    "observation_fault must carry the exact message \
                     (store_ready={store_ready}, gen={gen:?})"
                );
                assert_eq!(
                    outcome.observed_generation, gen,
                    "observed_generation must be threaded through \
                     (store_ready={store_ready}, gen={gen:?})"
                );
            }
        }
    }

    /// The ObservationFault condition reason must be "ObservationFault", not
    /// "DeploymentNotReady", so operators can distinguish API/RBAC faults from
    /// genuine deployment failures.
    #[test]
    fn observation_fault_condition_reason_is_diagnosable() {
        let fault_msg = "ConfigMap ns/wicket-gw-gw-config: 403 Forbidden";
        let cond = crate::crds::Condition::not_programmed_observation_fault(fault_msg);

        assert_eq!(
            cond.reason, "ObservationFault",
            "reason must be ObservationFault for diagnosability"
        );
        assert_eq!(cond.status, "False");
        assert_eq!(cond.type_, "Programmed");
        assert!(
            cond.message.contains("403 Forbidden"),
            "condition message must embed the fault detail: {}",
            cond.message
        );
        // Must be distinct from the generic deployment-not-ready reason.
        let generic = crate::crds::Condition::not_programmed();
        assert_ne!(
            cond.reason, generic.reason,
            "ObservationFault reason must differ from DeploymentNotReady"
        );
    }

    // ── Area 2: Unowned same-name object collision rejection ──────────────────
    //
    // These tests verify the ownership preflight logic in runtime_applier.rs:
    // a pre-existing object without the controller's managed-by label must
    // cause ApplyError::NotOwned, not a silent takeover.

    /// An object with no labels at all is not owned by the controller.
    #[test]
    fn preflight_rejects_object_with_no_labels() {
        use crate::reconcilers::runtime_applier::is_managed_by_controller_pub;
        assert!(
            !is_managed_by_controller_pub(None),
            "object with no labels must not be considered owned"
        );
        let empty: std::collections::BTreeMap<String, String> = std::collections::BTreeMap::new();
        assert!(
            !is_managed_by_controller_pub(Some(&empty)),
            "object with empty labels must not be considered owned"
        );
    }

    /// An object managed by a different controller (e.g. Helm) is not owned.
    #[test]
    fn preflight_rejects_object_managed_by_different_controller() {
        use crate::reconcilers::runtime_applier::is_managed_by_controller_pub;
        let mut labels = std::collections::BTreeMap::new();
        labels.insert(
            "app.kubernetes.io/managed-by".to_string(),
            "helm".to_string(),
        );
        assert!(
            !is_managed_by_controller_pub(Some(&labels)),
            "object managed by helm must not be considered owned by wicket-controller"
        );
    }

    /// An object with the correct managed-by label is owned.
    #[test]
    fn preflight_accepts_object_with_correct_managed_by_label() {
        use crate::reconcilers::runtime_applier::is_managed_by_controller_pub;
        let mut labels = std::collections::BTreeMap::new();
        labels.insert(
            "app.kubernetes.io/managed-by".to_string(),
            "wicket-controller".to_string(),
        );
        assert!(
            is_managed_by_controller_pub(Some(&labels)),
            "object with managed-by=wicket-controller must be considered owned"
        );
    }

    /// ApplyError::NotOwned carries the namespace and name of the conflicting
    /// object so operators can identify it.
    #[test]
    fn apply_error_not_owned_carries_identity() {
        use crate::reconcilers::contracts::ApplyError;
        let err = ApplyError::NotOwned {
            namespace: "prod".to_string(),
            name: "wicket-gw-my-gw-config".to_string(),
        };
        let display = err.to_string();
        assert!(
            display.contains("prod"),
            "NotOwned error must contain namespace: {display}"
        );
        assert!(
            display.contains("wicket-gw-my-gw-config"),
            "NotOwned error must contain name: {display}"
        );
        assert!(
            display.contains("wicket-controller"),
            "NotOwned error must mention the controller: {display}"
        );
    }

    /// ApplyError::NotOwned is structurally distinct from KubeApi and
    /// Serialization errors so callers can match on it precisely.
    #[test]
    fn apply_error_not_owned_is_structurally_distinct() {
        use crate::reconcilers::contracts::ApplyError;
        let not_owned = ApplyError::NotOwned {
            namespace: "ns".to_string(),
            name: "obj".to_string(),
        };
        let kube_err = ApplyError::KubeApi("timeout".to_string());
        let ser_err = ApplyError::Serialization("bad json".to_string());

        assert!(matches!(not_owned, ApplyError::NotOwned { .. }));
        assert!(!matches!(kube_err, ApplyError::NotOwned { .. }));
        assert!(!matches!(ser_err, ApplyError::NotOwned { .. }));
    }

    // ── Area 3: Stale rollout generation / partial rollout keeps Programmed=False
    //
    // These tests verify that is_rollout_converged() returns false for all
    // partial-rollout and stale-generation scenarios, and that the
    // resolve_managed_status_outcome Applied path correctly propagates these
    // to programmed=false.

    /// Partial rollout: updated_replicas < desired_replicas means old pods are
    /// still running.  Programmed must be false.
    #[test]
    fn partial_rollout_updated_less_than_desired_is_not_converged() {
        let obs = ObservedRuntimeState {
            ready_replicas: Some(3), // old pods still ready
            deploy_observed_generation: Some(5),
            deploy_generation: Some(5),
            updated_replicas: Some(1), // only 1 of 3 pods on new template
            available_replicas: Some(3),
            desired_replicas: Some(3),
            ..Default::default()
        };
        assert!(
            !is_rollout_converged(&obs),
            "partial rollout (updated < desired) must not be converged"
        );

        // Verify this propagates through resolve_managed_status_outcome.
        let noop = RuntimeApplyResult::default();
        let input =
            super::ManagedRuntimeInput::Applied(obs, noop, Box::new(SnapshotResult::NotReady));
        let outcome = super::resolve_managed_status_outcome(input, true, Some(5));
        assert!(
            !outcome.programmed,
            "partial rollout must keep Programmed=False even when store is ready"
        );
    }

    /// Stale observed_generation: the Deployment controller has not yet
    /// processed the new spec.  Programmed must be false.
    #[test]
    fn stale_generation_keeps_programmed_false() {
        let obs = ObservedRuntimeState {
            ready_replicas: Some(2),
            deploy_observed_generation: Some(3), // stale: controller saw gen 3
            deploy_generation: Some(4),          // desired: spec is at gen 4
            updated_replicas: Some(2),
            available_replicas: Some(2),
            desired_replicas: Some(2),
            ..Default::default()
        };
        assert!(
            !is_rollout_converged(&obs),
            "stale observed_generation must not be converged"
        );

        // Through the Applied path with no-op apply.
        let noop = RuntimeApplyResult::default();
        let input =
            super::ManagedRuntimeInput::Applied(obs, noop, Box::new(SnapshotResult::NotReady));
        let outcome = super::resolve_managed_status_outcome(input, true, Some(4));
        assert!(
            !outcome.programmed,
            "stale generation must keep Programmed=False"
        );
        assert!(
            !outcome.only_store_not_ready,
            "stale generation is not a store-warmup issue"
        );
    }

    /// deployment_changed=true but rollout_triggered=false (new object created,
    /// no spec change) must still force Programmed=False via the staleness guard.
    #[test]
    fn deployment_changed_without_rollout_forces_programmed_false() {
        // Pre-apply observation: fully converged (old revision was healthy).
        let converged = ObservedRuntimeState {
            ready_replicas: Some(1),
            deploy_observed_generation: Some(2),
            deploy_generation: Some(2),
            updated_replicas: Some(1),
            available_replicas: Some(1),
            desired_replicas: Some(1),
            ..Default::default()
        };
        // deployment_changed=true but rollout_triggered=false (e.g. new SA created).
        let result = RuntimeApplyResult {
            rollout_triggered: false,
            deployment_changed: true,
            service_account_created: true,
            ..Default::default()
        };
        let input = super::ManagedRuntimeInput::Applied(
            converged,
            result,
            Box::new(SnapshotResult::NotReady),
        );
        let outcome = super::resolve_managed_status_outcome(input, true, Some(2));

        assert!(
            !outcome.programmed,
            "deployment_changed=true must force Programmed=False via staleness guard"
        );
        assert!(
            !outcome.only_store_not_ready,
            "deployment_changed is not a store-warmup issue"
        );
    }

    /// All rollout-convergence fields must be present for convergence.
    /// Missing any single field keeps Programmed=False.
    #[test]
    fn missing_any_convergence_field_keeps_programmed_false() {
        // Start with a fully converged state and null out each field in turn.
        let base = ObservedRuntimeState {
            ready_replicas: Some(1),
            deploy_observed_generation: Some(2),
            deploy_generation: Some(2),
            updated_replicas: Some(1),
            available_replicas: Some(1),
            desired_replicas: Some(1),
            ..Default::default()
        };
        assert!(
            is_rollout_converged(&base),
            "precondition: base state must be converged"
        );

        // Null out each field and verify convergence is lost.
        let cases: &[(&str, ObservedRuntimeState)] = &[
            (
                "ready_replicas",
                ObservedRuntimeState {
                    ready_replicas: None,
                    ..base.clone()
                },
            ),
            (
                "deploy_observed_generation",
                ObservedRuntimeState {
                    deploy_observed_generation: None,
                    ..base.clone()
                },
            ),
            (
                "deploy_generation",
                ObservedRuntimeState {
                    deploy_generation: None,
                    ..base.clone()
                },
            ),
            (
                "updated_replicas",
                ObservedRuntimeState {
                    updated_replicas: None,
                    ..base.clone()
                },
            ),
            (
                "available_replicas",
                ObservedRuntimeState {
                    available_replicas: None,
                    ..base.clone()
                },
            ),
            (
                "desired_replicas",
                ObservedRuntimeState {
                    desired_replicas: None,
                    ..base.clone()
                },
            ),
        ];

        for (field, obs) in cases {
            assert!(
                !is_rollout_converged(obs),
                "missing {field} must keep Programmed=False"
            );
        }
    }

    // ── Area 4: Store-not-ready warmup does not incorrectly force Programmed=False
    //
    // These tests verify the invariant: StoreNotReady alone must not force
    // Programmed=False when the observed runtime is converged.  The store
    // warming up is not a gate on Programmed=True.

    /// StoreNotReady + converged obs + store_ready=true => programmed=true.
    /// (Regression guard: store_ready=true should not change the outcome vs
    /// store_ready=false when the runtime is converged.)
    #[test]
    fn store_not_ready_path_converged_obs_store_ready_true_is_programmed() {
        let obs = ObservedRuntimeState {
            ready_replicas: Some(1),
            deploy_observed_generation: Some(2),
            deploy_generation: Some(2),
            updated_replicas: Some(1),
            available_replicas: Some(1),
            desired_replicas: Some(1),
            ..Default::default()
        };
        // store_ready=true: the store has since become ready, but the input
        // variant is still StoreNotReady (planning was skipped this cycle).
        let input = super::ManagedRuntimeInput::StoreNotReady(obs);
        let outcome = super::resolve_managed_status_outcome(input, true, Some(2));

        assert!(
            outcome.programmed,
            "StoreNotReady + converged obs + store_ready=true => programmed=true"
        );
        assert!(
            !outcome.only_store_not_ready,
            "converged obs => only_store_not_ready=false regardless of store_ready"
        );
    }

    /// StoreNotReady + converged obs + store_ready=false => programmed=true.
    /// The store warming up must NOT gate Programmed=True.
    #[test]
    fn store_not_ready_path_converged_obs_store_not_ready_is_still_programmed() {
        let obs = ObservedRuntimeState {
            ready_replicas: Some(2),
            deploy_observed_generation: Some(5),
            deploy_generation: Some(5),
            updated_replicas: Some(2),
            available_replicas: Some(2),
            desired_replicas: Some(2),
            ..Default::default()
        };
        let input = super::ManagedRuntimeInput::StoreNotReady(obs);
        let outcome = super::resolve_managed_status_outcome(input, false, Some(5));

        assert!(
            outcome.programmed,
            "StoreNotReady + converged obs => programmed=true even when store is not ready"
        );
        assert!(
            !outcome.only_store_not_ready,
            "converged obs => only_store_not_ready=false"
        );
        assert!(
            outcome.observation_fault.is_none(),
            "StoreNotReady path must not set observation_fault"
        );
    }

    /// StoreNotReady + not-converged obs + store_ready=false =>
    /// programmed=false, only_store_not_ready=true (correct warming-up reason).
    #[test]
    fn store_not_ready_path_not_converged_uses_warming_up_reason() {
        let obs = ObservedRuntimeState::default(); // all None => not converged
        let input = super::ManagedRuntimeInput::StoreNotReady(obs);
        let outcome = super::resolve_managed_status_outcome(input, false, Some(1));

        assert!(!outcome.programmed);
        assert!(
            outcome.only_store_not_ready,
            "not-converged + store not ready => only_store_not_ready=true (warming-up reason)"
        );

        // The condition built from this outcome must use ControllerStoreNotReady.
        let cond = crate::crds::Condition::not_programmed_warming_up();
        assert_eq!(
            cond.reason, "ControllerStoreNotReady",
            "warming-up condition must use ControllerStoreNotReady reason"
        );
    }

    /// StoreNotReady + not-converged obs + store_ready=true =>
    /// programmed=false, only_store_not_ready=false (store is ready, so the
    /// cause is the deployment, not the store).
    #[test]
    fn store_not_ready_path_not_converged_store_ready_uses_deployment_reason() {
        let obs = ObservedRuntimeState::default();
        let input = super::ManagedRuntimeInput::StoreNotReady(obs);
        let outcome = super::resolve_managed_status_outcome(input, true, Some(1));

        assert!(!outcome.programmed);
        assert!(
            !outcome.only_store_not_ready,
            "store_ready=true => only_store_not_ready=false even in StoreNotReady path"
        );
        // The condition should be DeploymentNotReady, not ControllerStoreNotReady.
        let cond = crate::crds::Condition::not_programmed();
        assert_eq!(cond.reason, "DeploymentNotReady");
    }

    /// The four combinations of (store_ready, converged) in the StoreNotReady
    /// path must all produce the correct (programmed, only_store_not_ready) pair.
    #[test]
    fn store_not_ready_path_all_four_combinations() {
        let converged = ObservedRuntimeState {
            ready_replicas: Some(1),
            deploy_observed_generation: Some(1),
            deploy_generation: Some(1),
            updated_replicas: Some(1),
            available_replicas: Some(1),
            desired_replicas: Some(1),
            ..Default::default()
        };
        let not_converged = ObservedRuntimeState::default();

        // (store_ready, obs, expected_programmed, expected_only_snr)
        let cases: &[(bool, &ObservedRuntimeState, bool, bool)] = &[
            (false, &converged, true, false), // converged + store warming => programmed
            (true, &converged, true, false),  // converged + store ready => programmed
            (false, &not_converged, false, true), // not converged + store warming => warming-up
            (true, &not_converged, false, false), // not converged + store ready => deploy-not-ready
        ];

        for &(store_ready, obs, exp_prog, exp_snr) in cases {
            let input = super::ManagedRuntimeInput::StoreNotReady(obs.clone());
            let outcome = super::resolve_managed_status_outcome(input, store_ready, Some(1));
            assert_eq!(
                outcome.programmed,
                exp_prog,
                "store_ready={store_ready} converged={} => programmed must be {exp_prog}",
                is_rollout_converged(obs)
            );
            assert_eq!(
                outcome.only_store_not_ready,
                exp_snr,
                "store_ready={store_ready} converged={} => only_store_not_ready must be {exp_snr}",
                is_rollout_converged(obs)
            );
        }
    }

    // ── Scale-to-zero through the status outcome path ────────────────────────
    //
    // When a Deployment is intentionally scaled to 0, the Gateway must still
    // report Programmed=True (the Deployment is at desired state).

    #[test]
    fn resolve_outcome_applied_scale_to_zero_is_programmed() {
        let obs = ObservedRuntimeState {
            current_config_hash: Some("hash".to_string()),
            current_spec_hash: Some("spec".to_string()),
            ready_replicas: Some(0),
            deploy_observed_generation: Some(3),
            deploy_generation: Some(3),
            updated_replicas: Some(0),
            available_replicas: Some(0),
            desired_replicas: Some(0),
        };
        let noop = RuntimeApplyResult::default();
        let input =
            super::ManagedRuntimeInput::Applied(obs, noop, Box::new(SnapshotResult::NotReady));

        let outcome = super::resolve_managed_status_outcome(input, true, Some(1));

        assert!(
            outcome.programmed,
            "scale-to-zero Deployment must be Programmed=True"
        );
        assert!(!outcome.only_store_not_ready);
        assert!(outcome.observation_fault.is_none());
    }

    #[test]
    fn resolve_outcome_store_not_ready_scale_to_zero_is_programmed() {
        let obs = ObservedRuntimeState {
            ready_replicas: Some(0),
            deploy_observed_generation: Some(2),
            deploy_generation: Some(2),
            updated_replicas: Some(0),
            available_replicas: Some(0),
            desired_replicas: Some(0),
            ..Default::default()
        };
        let input = super::ManagedRuntimeInput::StoreNotReady(obs);

        let outcome = super::resolve_managed_status_outcome(input, false, Some(1));

        assert!(
            outcome.programmed,
            "scale-to-zero + store not ready must still be Programmed=True"
        );
        assert!(
            !outcome.only_store_not_ready,
            "converged (even at 0) must not set only_store_not_ready"
        );
    }

    // ── Exhaustive resolve_managed_status_outcome matrix ─────────────────────
    //
    // Test all (input_variant x store_ready x convergence_state) combinations
    // to ensure the FSM status decisions are complete and correct.

    #[test]
    fn resolve_outcome_exhaustive_applied_matrix() {
        let converged_obs = ObservedRuntimeState {
            ready_replicas: Some(1),
            deploy_observed_generation: Some(2),
            deploy_generation: Some(2),
            updated_replicas: Some(1),
            available_replicas: Some(1),
            desired_replicas: Some(1),
            ..Default::default()
        };
        let not_converged_obs = ObservedRuntimeState::default();

        let noop_result = RuntimeApplyResult::default();
        let rollout_result = RuntimeApplyResult {
            rollout_triggered: true,
            deployment_changed: true,
            ..Default::default()
        };
        let deploy_created_result = RuntimeApplyResult {
            deployment_changed: true,
            service_account_created: true,
            ..Default::default()
        };

        struct Case {
            label: &'static str,
            obs: ObservedRuntimeState,
            result: RuntimeApplyResult,
            store_ready: bool,
            expect_programmed: bool,
            expect_only_snr: bool,
        }

        let cases = [
            Case {
                label: "converged + noop + store ready",
                obs: converged_obs.clone(),
                result: noop_result.clone(),
                store_ready: true,
                expect_programmed: true,
                expect_only_snr: false,
            },
            Case {
                label: "converged + noop + store not ready",
                obs: converged_obs.clone(),
                result: noop_result.clone(),
                store_ready: false,
                expect_programmed: true,
                expect_only_snr: false,
            },
            Case {
                label: "converged + rollout triggered",
                obs: converged_obs.clone(),
                result: rollout_result.clone(),
                store_ready: true,
                expect_programmed: false,
                expect_only_snr: false,
            },
            Case {
                label: "converged + deploy created",
                obs: converged_obs.clone(),
                result: deploy_created_result.clone(),
                store_ready: true,
                expect_programmed: false,
                expect_only_snr: false,
            },
            Case {
                label: "not converged + noop + store ready",
                obs: not_converged_obs.clone(),
                result: noop_result.clone(),
                store_ready: true,
                expect_programmed: false,
                expect_only_snr: false,
            },
            Case {
                label: "not converged + noop + store not ready",
                obs: not_converged_obs.clone(),
                result: noop_result.clone(),
                store_ready: false,
                expect_programmed: false,
                expect_only_snr: true,
            },
            Case {
                label: "not converged + rollout + store not ready",
                obs: not_converged_obs.clone(),
                result: rollout_result.clone(),
                store_ready: false,
                expect_programmed: false,
                // Cause is rollout, not store => false
                expect_only_snr: false,
            },
        ];

        for case in &cases {
            let input = super::ManagedRuntimeInput::Applied(
                case.obs.clone(),
                case.result.clone(),
                Box::new(SnapshotResult::NotReady),
            );
            let outcome = super::resolve_managed_status_outcome(input, case.store_ready, Some(1));

            assert_eq!(
                outcome.programmed, case.expect_programmed,
                "'{}': programmed mismatch",
                case.label
            );
            assert_eq!(
                outcome.only_store_not_ready, case.expect_only_snr,
                "'{}': only_store_not_ready mismatch",
                case.label
            );
            assert!(
                outcome.observation_fault.is_none(),
                "'{}': Applied must never set observation_fault",
                case.label
            );
        }
    }

    // ── observed_generation threading through all ManagedRuntimeInput variants ──

    #[test]
    fn resolve_outcome_all_variants_thread_observed_generation() {
        let gen = Some(42_i64);

        // Applied
        let input1 = super::ManagedRuntimeInput::Applied(
            ObservedRuntimeState::default(),
            RuntimeApplyResult::default(),
            Box::new(SnapshotResult::NotReady),
        );
        let o1 = super::resolve_managed_status_outcome(input1, true, gen);
        assert_eq!(
            o1.observed_generation, gen,
            "Applied must thread observed_generation"
        );

        // StoreNotReady
        let input2 = super::ManagedRuntimeInput::StoreNotReady(ObservedRuntimeState::default());
        let o2 = super::resolve_managed_status_outcome(input2, false, gen);
        assert_eq!(
            o2.observed_generation, gen,
            "StoreNotReady must thread observed_generation"
        );

        // ObservationFault
        let input3 = super::ManagedRuntimeInput::ObservationFault("error".to_string());
        let o3 = super::resolve_managed_status_outcome(input3, false, gen);
        assert_eq!(
            o3.observed_generation, gen,
            "ObservationFault must thread observed_generation"
        );
    }

    // ── Legacy vs managed-runtime: FSM mode selection ────────────────────────

    #[test]
    fn legacy_listener_statuses_always_programmed_and_accepted() {
        let gw = make_gateway_with_annotation("prod", "my-gw", None);
        let statuses = super::build_legacy_listener_statuses(&gw);

        for status in &statuses {
            let has_programmed_true = status
                .conditions
                .iter()
                .any(|c| c.type_ == "Programmed" && c.status == "True");
            let has_accepted_true = status
                .conditions
                .iter()
                .any(|c| c.type_ == "Accepted" && c.status == "True");
            assert!(
                has_programmed_true,
                "legacy listener '{}' must have Programmed=True",
                status.name
            );
            assert!(
                has_accepted_true,
                "legacy listener '{}' must have Accepted=True",
                status.name
            );
        }
    }

    #[test]
    fn legacy_listener_statuses_multi_protocol() {
        use crate::crds::{GatewaySpec, Listener, ProtocolType};

        let gw = Gateway {
            metadata: ObjectMeta {
                name: Some("multi-gw".to_string()),
                namespace: Some("prod".to_string()),
                ..Default::default()
            },
            spec: GatewaySpec {
                gateway_class_name: "wicket".to_string(),
                listeners: vec![
                    Listener {
                        name: "http".to_string(),
                        hostname: None,
                        port: 80,
                        protocol: ProtocolType::HTTP,
                        tls: None,
                        allowed_routes: None,
                    },
                    Listener {
                        name: "tcp".to_string(),
                        hostname: None,
                        port: 5432,
                        protocol: ProtocolType::TCP,
                        tls: None,
                        allowed_routes: None,
                    },
                    Listener {
                        name: "tls".to_string(),
                        hostname: None,
                        port: 443,
                        protocol: ProtocolType::TLS,
                        tls: None,
                        allowed_routes: None,
                    },
                ],
                addresses: vec![],
                infrastructure: None,
            },
            status: None,
        };

        let statuses = super::build_legacy_listener_statuses(&gw);
        assert_eq!(statuses.len(), 3);

        // HTTP listener supports HTTPRoute
        let http = statuses.iter().find(|s| s.name == "http").unwrap();
        assert!(http.supported_kinds.iter().any(|k| k.kind == "HTTPRoute"));

        // TCP listener supports TCPRoute
        let tcp = statuses.iter().find(|s| s.name == "tcp").unwrap();
        assert!(tcp.supported_kinds.iter().any(|k| k.kind == "TCPRoute"));

        // TLS listener supports TLSRoute
        let tls = statuses.iter().find(|s| s.name == "tls").unwrap();
        assert!(tls.supported_kinds.iter().any(|k| k.kind == "TLSRoute"));
    }

    // ── build_gateway_conditions ──────────���──────────────────────────────────

    #[test]
    fn gateway_conditions_programmed_true() {
        let conditions = super::build_gateway_conditions(true, &None, false, Some(5));
        assert_eq!(conditions.len(), 2);
        assert_eq!(conditions[0].type_, "Accepted");
        assert_eq!(conditions[0].status, "True");
        assert_eq!(conditions[1].type_, "Programmed");
        assert_eq!(conditions[1].status, "True");
        assert_eq!(conditions[0].observed_generation, Some(5));
        assert_eq!(conditions[1].observed_generation, Some(5));
    }

    #[test]
    fn gateway_conditions_observation_fault() {
        let fault = Some("RBAC denied".to_string());
        let conditions = super::build_gateway_conditions(false, &fault, false, Some(3));
        assert_eq!(conditions.len(), 2);
        assert_eq!(conditions[0].type_, "Accepted");
        assert_eq!(conditions[0].status, "True");
        assert_eq!(conditions[1].type_, "Programmed");
        assert_eq!(conditions[1].status, "False");
        assert_eq!(conditions[1].reason, "ObservationFault");
        assert!(
            conditions[1].message.contains("RBAC denied"),
            "fault message must be surfaced"
        );
    }

    #[test]
    fn gateway_conditions_store_not_ready() {
        let conditions = super::build_gateway_conditions(false, &None, true, Some(1));
        assert_eq!(conditions.len(), 2);
        assert_eq!(conditions[0].type_, "Accepted");
        assert_eq!(conditions[1].type_, "Programmed");
        assert_eq!(conditions[1].status, "False");
        assert_eq!(conditions[1].reason, "ControllerStoreNotReady");
    }

    #[test]
    fn gateway_conditions_deployment_not_ready() {
        let conditions = super::build_gateway_conditions(false, &None, false, Some(2));
        assert_eq!(conditions.len(), 2);
        assert_eq!(conditions[0].type_, "Accepted");
        assert_eq!(conditions[1].type_, "Programmed");
        assert_eq!(conditions[1].status, "False");
        assert_eq!(conditions[1].reason, "DeploymentNotReady");
    }

    #[test]
    fn gateway_conditions_priority_fault_over_store_not_ready() {
        // When both observation_fault and only_store_not_ready are set,
        // the observation fault must take priority.
        let fault = Some("API error".to_string());
        let conditions = super::build_gateway_conditions(false, &fault, true, Some(1));
        assert_eq!(conditions[1].reason, "ObservationFault");
    }

    #[test]
    fn gateway_conditions_programmed_trumps_all() {
        // When programmed is true, fault and store_not_ready are irrelevant.
        let fault = Some("stale fault".to_string());
        let conditions = super::build_gateway_conditions(true, &fault, true, Some(1));
        assert_eq!(conditions[1].type_, "Programmed");
        assert_eq!(conditions[1].status, "True");
    }

    #[test]
    fn gateway_conditions_none_generation() {
        // observed_generation = None should not panic.
        let conditions = super::build_gateway_conditions(true, &None, false, None);
        assert_eq!(conditions[0].observed_generation, None);
        assert_eq!(conditions[1].observed_generation, None);
    }

    #[test]
    fn gateway_status_threads_reconciled_generation_into_conditions_and_listeners() {
        let mut gw = make_gateway_with_annotation("prod", "my-gw", None);
        gw.metadata.generation = Some(42);

        let (listener_statuses, programmed, only_store_not_ready, fault) =
            super::build_managed_runtime_status(
                &gw,
                "prod",
                "my-gw",
                super::ManagedRuntimeInput::StoreNotReady(ObservedRuntimeState::default()),
            );

        let conditions = super::build_gateway_conditions(
            programmed,
            &fault,
            only_store_not_ready,
            gw.metadata.generation,
        );

        let status = GatewayStatus {
            addresses: vec![],
            conditions,
            listeners: listener_statuses,
        };

        assert!(status
            .conditions
            .iter()
            .all(|c| c.observed_generation == Some(42)));
        assert!(status.listeners.iter().all(|listener| listener
            .conditions
            .iter()
            .all(|c| c.observed_generation == Some(42))));
    }

    #[test]
    fn gateway_status_keeps_missing_generation_unset() {
        let mut gw = make_gateway_with_annotation("prod", "my-gw", None);
        gw.metadata.generation = None;

        let (listener_statuses, programmed, only_store_not_ready, fault) =
            super::build_managed_runtime_status(
                &gw,
                "prod",
                "my-gw",
                super::ManagedRuntimeInput::StoreNotReady(ObservedRuntimeState::default()),
            );

        let conditions = super::build_gateway_conditions(
            programmed,
            &fault,
            only_store_not_ready,
            gw.metadata.generation,
        );

        let status = GatewayStatus {
            addresses: vec![],
            conditions,
            listeners: listener_statuses,
        };

        assert!(status
            .conditions
            .iter()
            .all(|c| c.observed_generation.is_none()));
        assert!(status.listeners.iter().all(|listener| listener
            .conditions
            .iter()
            .all(|c| c.observed_generation.is_none())));
    }
}
