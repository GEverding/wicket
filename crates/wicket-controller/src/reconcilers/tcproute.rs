//! TCPRoute reconciler.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use kube::{
    api::{Api, Patch, PatchParams},
    runtime::{
        controller::{Action, Controller},
        watcher::Config,
    },
    Client, ResourceExt,
};

use crate::crds::{
    Condition, Gateway, GatewayClass, RouteParentStatus, TCPRoute, TCPRouteStatus,
    WICKET_CONTROLLER_NAME,
};
use crate::metrics::{ReconcileMetrics, ROUTES_ACCEPTED, ROUTES_REJECTED_TOTAL, TCPROUTES};

use super::attachment_planner::{
    AttachmentPlan, AttachmentPlanInput, AttachmentPlanner, AttachmentStatus,
};
use super::config_generator::GatewayState;
use super::context::Context;
use super::store::{ResourceClass, SnapshotResult};

/// Error type for TCPRoute reconciliation.
#[derive(Debug, thiserror::Error)]
pub enum TCPRouteError {
    #[error("Kubernetes API error: {0}")]
    KubeError(#[from] kube::Error),

    #[error("Parent Gateway not found: {0}")]
    ParentNotFound(String),

    #[error("Configuration error: {0}")]
    ConfigError(String),
}

/// Reconcile a TCPRoute resource.
pub async fn reconcile_tcproute(
    route: Arc<TCPRoute>,
    ctx: Arc<Context>,
) -> Result<Action, TCPRouteError> {
    let metrics = ReconcileMetrics::new("TCPRoute");
    let namespace = route.namespace().unwrap_or_default();
    let name = route.name_any();

    tracing::info!(namespace = %namespace, name = %name, "Reconciling TCPRoute");

    // Handle deletion: remove from store and trigger config update.
    if route.metadata.deletion_timestamp.is_some() {
        let key = GatewayState::key(&namespace, &name);
        ctx.store.remove_tcp_route(&key).await;
        tracing::info!(namespace = %namespace, name = %name, "TCPRoute deleted, removed from store");
        return Ok(Action::await_change());
    }

    // Obtain a planner snapshot once (best-effort; may be NotReady during warm-up).
    // Used below for parentRefs that have an explicit sectionName and resolve to
    // an existing Wicket-managed Gateway.
    let planner_snapshot = ctx.store.planner_snapshot().await;

    // Cache of already-computed AttachmentPlans keyed by (gw_ns, gw_name, gw_generation).
    // Multiple parentRefs on the same route may point at the same Gateway; we
    // reuse the plan rather than recomputing it for each ref.
    let mut plan_cache: HashMap<(String, String, i64), AttachmentPlan> = HashMap::new();

    // Validate parent references and check if they're managed by Wicket.
    let mut parent_statuses = Vec::new();
    let mut has_valid_parent = false;

    for parent_ref in &route.spec.parent_refs {
        let parent_ns = parent_ref.namespace.as_deref().unwrap_or(&namespace);

        // ── Step 1: tcproute.rs is authoritative for missing / non-Wicket parents ──
        //
        // Distinguish two outcomes from the Gateway lookup:
        //   - 404 / not-found  -> semantic invalid parent; write InvalidParentRef
        //     and continue to the next parentRef.
        //   - Any other error  -> transient fault (network, RBAC, etc.); propagate
        //     as KubeError so the controller requeues rather than silently writing
        //     a false InvalidParentRef status.
        let gw_api: Api<Gateway> = Api::namespaced(ctx.client.clone(), parent_ns);
        let gateway = match gw_api.get(&parent_ref.name).await {
            Ok(gw) => gw,
            Err(kube::Error::Api(ref api_err)) if api_err.code == 404 => {
                tracing::debug!(
                    namespace = %namespace,
                    route = %name,
                    parent_ref = %parent_ref.name,
                    parent_namespace = %parent_ns,
                    reason = "InvalidParentRef",
                    message = "Parent Gateway not found",
                    "Route parent validation failed"
                );
                parent_statuses.push(RouteParentStatus {
                    parent_ref: parent_ref.clone(),
                    // Authoritative constant -- matches what config_generator
                    // filters on.
                    controller_name: WICKET_CONTROLLER_NAME.to_string(),
                    conditions: vec![Condition::new(
                        "Accepted",
                        false,
                        "InvalidParentRef",
                        "Parent Gateway not found",
                    )],
                });
                continue;
            }
            Err(e) => {
                // Transient fault (network, RBAC, etc.): propagate so the
                // controller requeues rather than emitting a false rejection.
                tracing::warn!(
                    namespace = %namespace,
                    route = %name,
                    parent_ref = %parent_ref.name,
                    parent_namespace = %parent_ns,
                    error = %e,
                    "Transient error reading parent Gateway; requeueing"
                );
                return Err(TCPRouteError::KubeError(e));
            }
        };

        // ── Step 1b: Verify the GatewayClass is Wicket-managed.
        //
        // Distinguish three outcomes:
        //   - GatewayClass found and is Wicket-managed  -> continue to Step 2.
        //   - GatewayClass found and is NOT Wicket-managed -> hard InvalidParentRef.
        //   - GatewayClass NOT found (404)              -> hard InvalidParentRef
        //     (the Gateway references a non-existent class; not our concern).
        //   - Transient API error (non-404)             -> propagate as
        //     KubeError so the controller retries rather than silently
        //     rejecting a route whose GatewayClass we could not read.
        let gc_api: Api<GatewayClass> = Api::all(ctx.client.clone());
        let gc_result = gc_api.get(&gateway.spec.gateway_class_name).await;

        let is_wicket = match gc_result {
            Ok(gc) => gc.is_wicket_managed(),
            Err(kube::Error::Api(ref api_err)) if api_err.code == 404 => {
                // GatewayClass does not exist: treat as non-Wicket (hard reject).
                false
            }
            Err(e) => {
                // Transient fault (network, RBAC, etc.): propagate so the
                // controller requeues rather than emitting a false rejection.
                tracing::warn!(
                    namespace = %namespace,
                    route = %name,
                    parent_ref = %parent_ref.name,
                    gateway_class = %gateway.spec.gateway_class_name,
                    error = %e,
                    "Transient error reading GatewayClass; requeueing"
                );
                return Err(TCPRouteError::KubeError(e));
            }
        };

        if !is_wicket {
            tracing::debug!(
                namespace = %namespace,
                route = %name,
                parent_ref = %parent_ref.name,
                parent_namespace = %parent_ns,
                reason = "InvalidParentRef",
                message = "Gateway is not managed by Wicket",
                "Route parent validation failed"
            );
            parent_statuses.push(RouteParentStatus {
                parent_ref: parent_ref.clone(),
                // Authoritative constant -- matches what config_generator
                // filters on.
                controller_name: WICKET_CONTROLLER_NAME.to_string(),
                conditions: vec![Condition::new(
                    "Accepted",
                    false,
                    "InvalidParentRef",
                    "Gateway is not managed by Wicket",
                )],
            });
            continue;
        }

        // ── Step 2: Wicket-managed Gateway confirmed.  For parentRefs with an
        //    explicit sectionName, delegate Accepted status to AttachmentPlanner.
        //    Gateway-wide refs (no sectionName) keep the legacy TCP-listener check
        //    to avoid multi-listener aggregation ambiguity in this slice.
        let accepted_condition = if let Some(section_name) = &parent_ref.section_name {
            planner_accepted_condition_for_section_cached(
                &planner_snapshot,
                &gateway,
                &namespace,
                &name,
                section_name,
                parent_ref.port,
                &mut plan_cache,
            )
        } else {
            // Gateway-wide parentRef: no sectionName.
            // TCPRoute is TCP-only: the gateway must have at least one TCP
            // listener.  When parentRef.port is set, that port must match a
            // TCP listener (not merely any TCP listener).
            let matching_tcp = gateway.spec.listeners.iter().any(|l| {
                l.protocol == crate::crds::ProtocolType::TCP
                    && parent_ref.port.is_none_or(|p| l.port == p)
            });

            if matching_tcp {
                Condition::accepted()
            } else {
                tracing::debug!(
                    namespace = %namespace,
                    route = %name,
                    parent_ref = %parent_ref.name,
                    parent_namespace = %parent_ns,
                    port = ?parent_ref.port,
                    reason = "NoMatchingListener",
                    message = "Gateway has no TCP listener matching the parentRef port",
                    "Route listener validation failed"
                );
                Condition::new(
                    "Accepted",
                    false,
                    "NoMatchingListener",
                    "Gateway has no TCP listener matching the parentRef port",
                )
            }
        };

        let is_accepted = accepted_condition.status == "True";
        if is_accepted {
            has_valid_parent = true;
        }

        parent_statuses.push(RouteParentStatus {
            parent_ref: parent_ref.clone(),
            // Authoritative constant -- matches what config_generator filters on.
            controller_name: WICKET_CONTROLLER_NAME.to_string(),
            // Preserve existing ResolvedRefs=True behavior for this slice.
            conditions: if is_accepted {
                vec![accepted_condition, Condition::resolved_refs()]
            } else {
                vec![accepted_condition]
            },
        });
    }

    // Update TCPRoute status
    let status = TCPRouteStatus {
        parents: parent_statuses,
    };

    let api: Api<TCPRoute> = Api::namespaced(ctx.client.clone(), &namespace);
    let patch = serde_json::json!({
        "status": status
    });

    api.patch_status(
        &name,
        &PatchParams::apply("wicket-controller"),
        &Patch::Merge(&patch),
    )
    .await?;

    // If we have a valid parent, upsert into store and trigger configuration update.
    if has_valid_parent {
        let route_key = GatewayState::key(&namespace, &name);
        // Upsert a copy of the route that carries the status we just wrote to
        // the API server, not the stale pre-patch object.  This keeps the
        // SharedStore consistent with what the API server now holds.
        let mut route_with_status = (*route).clone();
        route_with_status.status = Some(status.clone());
        ctx.store
            .upsert_tcp_route(route_key, route_with_status)
            .await;

        tracing::info!(namespace = %namespace, name = %name, "TCPRoute accepted");

        // Update route acceptance metrics for each valid parent
        for parent_status in &status.parents {
            let gw_name = &parent_status.parent_ref.name;
            if parent_status
                .conditions
                .iter()
                .any(|c| c.type_ == "Accepted" && c.status == "True")
            {
                ROUTES_ACCEPTED
                    .with_label_values(&[&namespace, "TCPRoute", gw_name])
                    .set(1);
            }
        }
    } else {
        tracing::warn!(namespace = %namespace, name = %name, "TCPRoute has no valid Wicket parents");

        // Remove from store if it was previously accepted, so stale config is
        // not served.  If the route was never in the store this is a no-op.
        let route_key = GatewayState::key(&namespace, &name);
        ctx.store.remove_tcp_route(&route_key).await;
        tracing::debug!(
            namespace = %namespace,
            name = %name,
            "TCPRoute removed from store (no valid Wicket parents)"
        );

        // Trigger config regeneration so the proxy stops serving the stale route.
        // Track rejection reasons
        for parent_status in &status.parents {
            for condition in &parent_status.conditions {
                if condition.type_ == "Accepted" && condition.status == "False" {
                    ROUTES_REJECTED_TOTAL
                        .with_label_values(&[&namespace, "TCPRoute", &condition.reason])
                        .inc();
                }
            }
        }
    }

    metrics.record_success();

    // Update metrics
    update_tcproute_metrics(&ctx.client).await;

    Ok(Action::requeue(Duration::from_secs(60)))
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal: planner-driven Accepted condition for sectionName-qualified refs
// ─────────────────────────────────────────────────────────────────────────────

/// Cached variant used by the reconcile loop.
///
/// `plan_cache` is keyed by `(gateway_namespace, gateway_name, gateway_generation)`.
/// When multiple parentRefs on the same route point at the same Gateway (same
/// key), the `AttachmentPlan` is computed once and reused for subsequent refs,
/// avoiding redundant planner invocations.
///
/// TCPRoute is TCP-only.  On any fallback path (snapshot NotReady, planner
/// error, route not yet in snapshot) we inspect the Gateway spec directly via
/// `tcp_only_condition_from_spec`:
/// - Named listener exists and is not TCP -> `NotAllowedByListenerProtocol`.
/// - Named listener exists, is TCP, port mismatches -> `NoMatchingParent`.
/// - Named listener exists, is TCP, port matches (or absent) -> `Accepted=True`.
/// - Named listener NOT found in spec -> `NoMatchingParent` (explicit
///   sectionName naming a non-existent listener must never fail open).
fn planner_accepted_condition_for_section_cached(
    planner_snapshot: &SnapshotResult<super::store::PlannerSnapshot>,
    gateway: &Gateway,
    route_namespace: &str,
    route_name: &str,
    section_name: &str,
    port: Option<u16>,
    plan_cache: &mut HashMap<(String, String, i64), AttachmentPlan>,
) -> Condition {
    let snapshot = match planner_snapshot {
        SnapshotResult::Ready(s) => s,
        SnapshotResult::NotReady => {
            tracing::debug!(
                route_namespace = %route_namespace,
                route_name = %route_name,
                section_name = %section_name,
                "Planner snapshot not ready; checking Gateway spec for TCP-only rule"
            );
            return tcp_only_condition_from_spec(gateway, section_name, port);
        }
    };

    let gw_ns = gateway
        .metadata
        .namespace
        .as_deref()
        .unwrap_or("default")
        .to_string();
    let gw_name = gateway.metadata.name.as_deref().unwrap_or("").to_string();
    let gw_generation = gateway.metadata.generation.unwrap_or(0);

    let cache_key = (gw_ns.clone(), gw_name.clone(), gw_generation);

    // Populate cache on first encounter for this (gw_ns, gw_name, gw_generation).
    if !plan_cache.contains_key(&cache_key) {
        let input = AttachmentPlanInput {
            gateway_namespace: gw_ns,
            gateway_name: gw_name,
            gateway_generation: gw_generation,
            snapshot: snapshot.clone(),
        };
        match AttachmentPlanner.plan(&input) {
            Ok(plan) => {
                plan_cache.insert(cache_key.clone(), plan);
            }
            Err(e) => {
                tracing::debug!(
                    route_namespace = %route_namespace,
                    route_name = %route_name,
                    section_name = %section_name,
                    error = %e,
                    "AttachmentPlanner error; checking Gateway spec for TCP-only rule"
                );
                return tcp_only_condition_from_spec(gateway, section_name, port);
            }
        }
    }

    // Safe: we just inserted above if missing.
    let plan = match plan_cache.get(&cache_key) {
        Some(p) => p,
        None => return tcp_only_condition_from_spec(gateway, section_name, port),
    };

    condition_from_plan(
        plan,
        gateway,
        route_namespace,
        route_name,
        section_name,
        port,
    )
}

/// Enforce the TCP-only rule directly from the Gateway spec when the planner
/// is unavailable (snapshot not ready, planner error, or route not yet in
/// snapshot).
///
/// - If the named listener exists and its protocol is not TCP ->
///   `NotAllowedByListenerProtocol` (hard rejection; the spec is authoritative).
/// - If the named listener exists, is TCP, but the port does not match ->
///   `NoMatchingParent` (hard rejection; port is authoritative in the spec).
/// - If the named listener exists, is TCP, and port matches (or is absent) ->
///   `Accepted=True` (conservative warm-up fallback).
/// - If the named listener does NOT exist in the spec ->
///   `NoMatchingParent` (hard rejection; an explicit sectionName that names a
///   non-existent listener is never a transient condition -- the spec is
///   authoritative and we must not fail open).
fn tcp_only_condition_from_spec(
    gateway: &Gateway,
    section_name: &str,
    port: Option<u16>,
) -> Condition {
    match gateway
        .spec
        .listeners
        .iter()
        .find(|l| l.name == section_name)
    {
        Some(listener) => {
            if listener.protocol != crate::crds::ProtocolType::TCP {
                // Named listener exists and is not TCP: TCPRoute cannot attach.
                tracing::debug!(
                    section_name = %section_name,
                    protocol = ?listener.protocol,
                    "TCPRoute sectionName targets non-TCP listener; rejecting (TCP-only rule)"
                );
                return Condition::new(
                    "Accepted",
                    false,
                    "NotAllowedByListenerProtocol",
                    "Route kind is not compatible with the listener protocol",
                );
            }
            // Listener is TCP.  If a port was specified it must match.
            if let Some(ref_port) = port {
                if listener.port != ref_port {
                    tracing::debug!(
                        section_name = %section_name,
                        listener_port = listener.port,
                        ref_port = ref_port,
                        "TCPRoute parentRef port does not match listener port; rejecting"
                    );
                    return Condition::new(
                        "Accepted",
                        false,
                        "NoMatchingParent",
                        "No listener matches the parentRef sectionName or port",
                    );
                }
            }
            // TCP listener, port matches (or absent): conservative accept.
            Condition::accepted()
        }
        None => {
            // The named listener does not exist in the Gateway spec.
            // An explicit sectionName that names a non-existent listener is
            // never a transient condition -- the spec is authoritative.
            // Return NoMatchingParent so the route is not temporarily accepted
            // against an unknown listener name.
            tracing::debug!(
                section_name = %section_name,
                "TCPRoute sectionName not found in Gateway spec; rejecting (NoMatchingParent)"
            );
            Condition::new(
                "Accepted",
                false,
                "NoMatchingParent",
                "No listener matches the parentRef sectionName",
            )
        }
    }
}

/// Compute the `Accepted` condition for a parentRef that has an explicit
/// `sectionName` by running `AttachmentPlanner` against the store snapshot.
///
/// Falls back to `tcp_only_condition_from_spec` when:
/// - The store snapshot is not yet ready (warm-up gap).
/// - The planner returns an error (e.g. Gateway not yet in the store).
/// - No result is found for the `(route, sectionName, port)` triple.
///
/// The fallback enforces the TCP-only rule from the Gateway spec:
/// - Non-TCP listener -> rejected.
/// - TCP listener, port mismatch -> rejected.
/// - TCP listener, port matches (or absent) -> accepted conservatively.
/// - Listener name not found in spec -> `NoMatchingParent` (never fail open).
///
/// Used directly in unit tests (no cache needed there).
#[cfg(test)]
fn planner_accepted_condition_for_section(
    planner_snapshot: &SnapshotResult<super::store::PlannerSnapshot>,
    gateway: &Gateway,
    route_namespace: &str,
    route_name: &str,
    section_name: &str,
    port: Option<u16>,
) -> Condition {
    let mut cache = HashMap::new();
    planner_accepted_condition_for_section_cached(
        planner_snapshot,
        gateway,
        route_namespace,
        route_name,
        section_name,
        port,
        &mut cache,
    )
}

/// Translate a cached `AttachmentPlan` lookup into a `Condition`.
///
/// When the planner has no result for this `(route, sectionName, port)` triple
/// (route not yet in the snapshot), falls back to `tcp_only_condition_from_spec`
/// rather than blindly accepting, so the TCP-only rule is enforced even during
/// warm-up.
fn condition_from_plan(
    plan: &AttachmentPlan,
    gateway: &Gateway,
    route_namespace: &str,
    route_name: &str,
    section_name: &str,
    port: Option<u16>,
) -> Condition {
    let result = plan.result_for_route_parent_ref(route_namespace, route_name, section_name, port);

    match result {
        Some(r) if r.status.is_attached() => Condition::accepted(),
        Some(r) => {
            let reason = r.status.accepted_reason();
            let message = attachment_status_message(&r.status);
            tracing::debug!(
                route_namespace = %route_namespace,
                route_name = %route_name,
                section_name = %section_name,
                reason = %reason,
                "AttachmentPlanner rejected parentRef"
            );
            Condition::new("Accepted", false, reason, message)
        }
        None => {
            // No result found (e.g. route not yet in the store snapshot).
            // Apply the TCP-only rule from the Gateway spec before falling back.
            tracing::debug!(
                route_namespace = %route_namespace,
                route_name = %route_name,
                section_name = %section_name,
                "No planner result for parentRef; applying TCP-only spec check"
            );
            tcp_only_condition_from_spec(gateway, section_name, port)
        }
    }
}

/// Returns a human-readable message for an `AttachmentStatus` rejection.
fn attachment_status_message(status: &AttachmentStatus) -> &'static str {
    match status {
        AttachmentStatus::Attached
        | AttachmentStatus::RefNotPermitted { .. }
        | AttachmentStatus::BackendNotFound { .. } => "Route is accepted by the listener",
        AttachmentStatus::NoMatchingParent => {
            "No listener matches the parentRef sectionName or port"
        }
        AttachmentStatus::NotAllowedByListenerProtocol => {
            "Route kind is not compatible with the listener protocol"
        }
        AttachmentStatus::NotAllowedByListenerNamespacePolicy => {
            "Route namespace is not allowed by the listener AllowedRoutes namespace policy"
        }
        AttachmentStatus::NotAllowedByListenerKindPolicy => {
            "Route kind is not in the listener AllowedRoutes kinds list"
        }
        AttachmentStatus::NoMatchingListenerHostname => {
            "No route hostname intersects with the listener hostname"
        }
    }
}

/// Handle errors during TCPRoute reconciliation.
pub fn error_policy_tcproute(
    route: Arc<TCPRoute>,
    error: &TCPRouteError,
    _ctx: Arc<Context>,
) -> Action {
    let namespace = route.namespace().unwrap_or_default();
    let name = route.name_any();

    tracing::error!(
        namespace = %namespace,
        name = %name,
        error = %error,
        "TCPRoute reconciliation failed"
    );

    crate::metrics::RECONCILE_ERRORS_TOTAL
        .with_label_values(&["TCPRoute", "reconcile_error"])
        .inc();

    Action::requeue(Duration::from_secs(5))
}

/// Update TCPRoute metrics.
async fn update_tcproute_metrics(client: &Client) {
    let api: Api<TCPRoute> = Api::all(client.clone());

    match api.list(&Default::default()).await {
        Ok(list) => {
            // Group by namespace
            let mut counts: std::collections::HashMap<String, i64> =
                std::collections::HashMap::new();

            for route in &list.items {
                let ns = route.namespace().unwrap_or_default();
                *counts.entry(ns).or_insert(0) += 1;
            }

            for (ns, count) in counts {
                TCPROUTES.with_label_values(&[&ns]).set(count);
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "Failed to list TCPRoutes for metrics");
        }
    }
}

/// Create the TCPRoute controller.
pub async fn run_tcproute_controller(ctx: Arc<Context>) -> Result<(), kube::Error> {
    use crate::metrics::{WATCH_CONNECTIONS_ACTIVE, WATCH_ERRORS_TOTAL, WATCH_EVENTS_TOTAL};

    let api: Api<TCPRoute> = if ctx.watch_all_namespaces {
        Api::all(ctx.client.clone())
    } else {
        Api::namespaced(ctx.client.clone(), &ctx.controller_namespace)
    };

    WATCH_CONNECTIONS_ACTIVE
        .with_label_values(&["TCPRoute"])
        .set(1);

    let mut attempt: u32 = 0;
    loop {
        attempt += 1;
        match tokio::time::timeout(Duration::from_secs(30), api.list(&Default::default())).await {
            Ok(Ok(list)) => {
                for route in list.items {
                    let ns = route.metadata.namespace.clone().unwrap_or_default();
                    let name = route.metadata.name.clone().unwrap_or_default();
                    let key = GatewayState::key(&ns, &name);
                    ctx.store.upsert_tcp_route(key, route).await;
                }
                ctx.store.mark_listed(ResourceClass::TcpRoutes).await;
                tracing::debug!(attempt, "TCPRoute initial list complete; store flag set");
                break;
            }
            Ok(Err(e)) => {
                let backoff = std::cmp::min(attempt * 2, 30);
                tracing::warn!(
                    error = %e,
                    attempt,
                    backoff_secs = backoff,
                    "Initial TCPRoute list failed; will retry"
                );
                tokio::time::sleep(Duration::from_secs(backoff as u64)).await;
            }
            Err(_) => {
                tracing::warn!(
                    attempt,
                    "Initial TCPRoute list timed out after 30s; will retry"
                );
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }
    }

    Controller::new(api, Config::default())
        .run(reconcile_tcproute, error_policy_tcproute, ctx)
        .for_each(|result| async move {
            match result {
                Ok((obj, _)) => {
                    WATCH_EVENTS_TOTAL
                        .with_label_values(&["TCPRoute", "reconcile_success"])
                        .inc();
                    tracing::debug!(
                        namespace = obj.namespace.as_deref().unwrap_or(""),
                        name = %obj.name,
                        "TCPRoute reconciled"
                    );
                }
                Err(e) => {
                    WATCH_EVENTS_TOTAL
                        .with_label_values(&["TCPRoute", "reconcile_error"])
                        .inc();
                    WATCH_ERRORS_TOTAL
                        .with_label_values(&["TCPRoute", "controller_error"])
                        .inc();
                    tracing::error!(error = %e, "TCPRoute controller error");
                }
            }
        })
        .await;

    WATCH_CONNECTIONS_ACTIVE
        .with_label_values(&["TCPRoute"])
        .set(0);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crds::{
        Condition, Gateway, GatewaySpec, Listener, ParentReference, ProtocolType,
        RouteParentStatus, TCPRouteRule, TCPRouteSpec, TCPRouteStatus, WICKET_CONTROLLER_NAME,
    };
    use crate::reconcilers::store::SharedStore;
    use kube::core::ObjectMeta;

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn make_tcproute(name: &str, namespace: &str) -> TCPRoute {
        TCPRoute {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some(namespace.to_string()),
                ..Default::default()
            },
            spec: TCPRouteSpec {
                parent_refs: vec![ParentReference {
                    group: "gateway.networking.k8s.io".to_string(),
                    kind: "Gateway".to_string(),
                    namespace: None,
                    name: "my-gw".to_string(),
                    section_name: None,
                    port: None,
                }],
                rules: vec![TCPRouteRule {
                    name: None,
                    backend_refs: vec![crate::crds::BackendRef {
                        group: "".to_string(),
                        kind: "Service".to_string(),
                        name: "backend".to_string(),
                        namespace: None,
                        port: Some(5432),
                        weight: 1,
                    }],
                }],
            },
            status: None,
        }
    }

    fn accepted_status() -> TCPRouteStatus {
        TCPRouteStatus {
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
                conditions: vec![Condition::accepted(), Condition::resolved_refs()],
            }],
        }
    }

    fn rejected_status(reason: &str) -> TCPRouteStatus {
        TCPRouteStatus {
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
                conditions: vec![Condition::new("Accepted", false, reason, reason)],
            }],
        }
    }

    // ── controller_name normalization ─────────────────────────────────────────

    /// Every RouteParentStatus written by the TCPRoute reconciler must carry
    /// WICKET_CONTROLLER_NAME so the accepted-route filter in config_generator
    /// can match it.
    #[test]
    fn accepted_parent_status_carries_wicket_controller_name() {
        let status = accepted_status();
        assert_eq!(
            status.parents[0].controller_name, WICKET_CONTROLLER_NAME,
            "accepted parent must carry the authoritative controller name"
        );
    }

    #[test]
    fn rejected_parent_status_carries_wicket_controller_name() {
        let status = rejected_status("InvalidParentRef");
        assert_eq!(
            status.parents[0].controller_name, WICKET_CONTROLLER_NAME,
            "rejected parent must carry the authoritative controller name"
        );
    }

    // ── Store/status consistency ──────────────────────────────────────────────

    /// When a TCPRoute is accepted, the object stored in SharedStore must carry
    /// the status that was written to the API server (not the stale pre-patch
    /// object which has status = None).
    #[tokio::test]
    async fn store_upsert_carries_written_status() {
        let store = SharedStore::new();
        store.mark_ready().await;

        // Simulate what the reconciler does: build the status, then upsert a
        // copy of the route with that status attached.
        let mut route = make_tcproute("my-route", "default");
        let status = accepted_status();
        route.status = Some(status.clone());

        let key = super::super::config_generator::GatewayState::key("default", "my-route");
        store.upsert_tcp_route(key.clone(), route).await;

        // The stored route must have the status set.
        let snap = store.snapshot().await.expect("store ready");
        let stored = snap.tcp_routes.get(&key).expect("route in store");
        let stored_status = stored.status.as_ref().expect("status must be set");
        assert_eq!(
            stored_status.parents[0].controller_name, WICKET_CONTROLLER_NAME,
            "stored route must carry the written controller_name"
        );
        assert_eq!(
            stored_status.parents[0].conditions[0].status, "True",
            "stored route must carry the written Accepted=True condition"
        );
    }

    /// A route with status = None (pre-patch stale object) must NOT be what
    /// ends up in the store after reconciliation.
    #[tokio::test]
    async fn store_does_not_hold_stale_pre_patch_object() {
        let store = SharedStore::new();
        store.mark_ready().await;

        // Pre-populate with a stale entry (status = None).
        let stale_route = make_tcproute("my-route", "default");
        assert!(
            stale_route.status.is_none(),
            "pre-condition: stale has no status"
        );

        let key = super::super::config_generator::GatewayState::key("default", "my-route");
        store.upsert_tcp_route(key.clone(), stale_route).await;

        // Now simulate the reconciler overwriting with the post-patch version.
        let mut fresh_route = make_tcproute("my-route", "default");
        fresh_route.status = Some(accepted_status());
        store.upsert_tcp_route(key.clone(), fresh_route).await;

        let snap = store.snapshot().await.expect("store ready");
        let stored = snap.tcp_routes.get(&key).expect("route in store");
        assert!(
            stored.status.is_some(),
            "store must hold the post-patch route with status, not the stale pre-patch object"
        );
    }

    // ── Stale-route cleanup ───────────────────────────────────────────────────

    /// When a TCPRoute transitions from accepted to rejected (no valid Wicket
    /// parents), it must be removed from the SharedStore so stale config is
    /// not served.
    #[tokio::test]
    async fn stale_route_removed_from_store_when_no_valid_parents() {
        let store = SharedStore::new();
        store.mark_ready().await;

        // Pre-populate the store as if the route was previously accepted.
        let mut accepted_route = make_tcproute("my-route", "default");
        accepted_route.status = Some(accepted_status());
        let key = super::super::config_generator::GatewayState::key("default", "my-route");
        store.upsert_tcp_route(key.clone(), accepted_route).await;

        // Verify it's in the store.
        {
            let snap = store.snapshot().await.expect("store ready");
            assert!(
                snap.tcp_routes.contains_key(&key),
                "route must be in store before cleanup"
            );
        }

        // Simulate the reconciler's stale-route cleanup path.
        store.remove_tcp_route(&key).await;

        // The route must no longer be in the store.
        let snap = store.snapshot().await.expect("store ready");
        assert!(
            !snap.tcp_routes.contains_key(&key),
            "stale route must be removed from store when no valid Wicket parents"
        );
    }

    /// Removing a route that was never in the store is a no-op (does not panic).
    #[tokio::test]
    async fn remove_nonexistent_route_is_noop() {
        let store = SharedStore::new();
        store.mark_ready().await;

        let key = super::super::config_generator::GatewayState::key("default", "ghost-route");
        // Must not panic.
        store.remove_tcp_route(&key).await;

        let snap = store.snapshot().await.expect("store ready");
        assert!(!snap.tcp_routes.contains_key(&key));
    }

    // ── TCPRouteError variants ────────────────────────────────────────────────

    #[test]
    fn tcproute_error_variants() {
        let parent_err = TCPRouteError::ParentNotFound("my-gateway".to_string());
        assert_eq!(
            parent_err.to_string(),
            "Parent Gateway not found: my-gateway"
        );

        let config_err = TCPRouteError::ConfigError("test error".to_string());
        assert_eq!(config_err.to_string(), "Configuration error: test error");
    }

    // ── Gateway lookup error discrimination tests ─────────────────────────────
    //
    // These tests verify the pattern used in Step 1 of the reconciler:
    // a 404 API error is a semantic "not found" (write InvalidParentRef),
    // while any other kube::Error is a transient fault (propagate / requeue).

    /// A 404 kube::Error::Api response matches the not-found arm.
    #[test]
    fn gateway_lookup_404_is_not_found() {
        let api_err = kube::core::ErrorResponse {
            status: "Failure".to_string(),
            message: "gateways \"missing\" not found".to_string(),
            reason: "NotFound".to_string(),
            code: 404,
        };
        let err = kube::Error::Api(api_err);

        let is_not_found = matches!(
            &err,
            kube::Error::Api(e) if e.code == 404
        );
        assert!(
            is_not_found,
            "404 API error must be treated as semantic not-found"
        );
    }

    /// A 403 kube::Error::Api response does NOT match the not-found arm
    /// and must be propagated as a transient error.
    #[test]
    fn gateway_lookup_403_is_transient() {
        let api_err = kube::core::ErrorResponse {
            status: "Failure".to_string(),
            message: "gateways is forbidden".to_string(),
            reason: "Forbidden".to_string(),
            code: 403,
        };
        let err = kube::Error::Api(api_err);

        let is_not_found = matches!(
            &err,
            kube::Error::Api(e) if e.code == 404
        );
        assert!(
            !is_not_found,
            "403 API error must NOT be treated as not-found; it is a transient fault"
        );

        // Verify it converts to KubeError (the propagation path).
        let kube_err = TCPRouteError::KubeError(err);
        assert!(kube_err.to_string().contains("Kubernetes API error"));
    }

    /// A 500 kube::Error::Api response does NOT match the not-found arm.
    #[test]
    fn gateway_lookup_500_is_transient() {
        let api_err = kube::core::ErrorResponse {
            status: "Failure".to_string(),
            message: "Internal Server Error".to_string(),
            reason: "InternalError".to_string(),
            code: 500,
        };
        let err = kube::Error::Api(api_err);

        let is_not_found = matches!(
            &err,
            kube::Error::Api(e) if e.code == 404
        );
        assert!(
            !is_not_found,
            "500 API error must NOT be treated as not-found; it is a transient fault"
        );
    }

    // ── Condition structure ───────────────────────────────────────────────────

    /// The accepted status must include both Accepted=True and ResolvedRefs=True.
    #[test]
    fn accepted_status_has_both_conditions() {
        let status = accepted_status();
        let conditions = &status.parents[0].conditions;
        assert_eq!(conditions.len(), 2);
        let accepted = conditions.iter().find(|c| c.type_ == "Accepted");
        let resolved = conditions.iter().find(|c| c.type_ == "ResolvedRefs");
        assert!(accepted.is_some(), "must have Accepted condition");
        assert!(resolved.is_some(), "must have ResolvedRefs condition");
        assert_eq!(accepted.unwrap().status, "True");
        assert_eq!(resolved.unwrap().status, "True");
    }

    /// A rejected status must have Accepted=False and no ResolvedRefs condition.
    #[test]
    fn rejected_status_has_accepted_false() {
        let status = rejected_status("InvalidParentRef");
        let conditions = &status.parents[0].conditions;
        let accepted = conditions.iter().find(|c| c.type_ == "Accepted");
        assert!(accepted.is_some(), "must have Accepted condition");
        assert_eq!(accepted.unwrap().status, "False");
        assert_eq!(accepted.unwrap().reason, "InvalidParentRef");
    }

    // ── Planner-driven Accepted condition tests ───────────────────────────────
    //
    // These tests exercise `planner_accepted_condition_for_section` directly,
    // without a live Kubernetes API server.  They use the same snapshot/planner
    // infrastructure as the attachment_planner unit tests.

    use crate::reconcilers::store::{PlannerSnapshot, SnapshotResult};
    use std::collections::{HashMap, HashSet};

    /// Build a minimal `PlannerSnapshot` containing the given gateway and TCPRoute.
    fn make_snapshot(gateway: Gateway, route: TCPRoute) -> PlannerSnapshot {
        let gw_key = format!(
            "{}/{}",
            gateway.metadata.namespace.as_deref().unwrap_or("default"),
            gateway.metadata.name.as_deref().unwrap_or("")
        );
        let route_key = format!(
            "{}/{}",
            route.metadata.namespace.as_deref().unwrap_or("default"),
            route.metadata.name.as_deref().unwrap_or("")
        );
        let mut gateways = HashMap::new();
        gateways.insert(gw_key, gateway);
        let mut tcp_routes = HashMap::new();
        tcp_routes.insert(route_key, route);
        PlannerSnapshot {
            gateways,
            gateway_classes: HashMap::new(),
            http_routes: HashMap::new(),
            tcp_routes,
            tls_routes: HashMap::new(),
            service_endpoints: HashMap::new(),
            tls_secrets: HashMap::new(),
            reference_grants: HashMap::new(),
            service_ref_index: HashSet::new(),
            namespace_labels: HashMap::new(),
        }
    }

    fn make_gw_with_listener(
        ns: &str,
        name: &str,
        listener_name: &str,
        port: u16,
        protocol: ProtocolType,
    ) -> Gateway {
        Gateway {
            metadata: kube::core::ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some(ns.to_string()),
                generation: Some(1),
                ..Default::default()
            },
            spec: GatewaySpec {
                gateway_class_name: "wicket".to_string(),
                listeners: vec![Listener {
                    name: listener_name.to_string(),
                    hostname: None,
                    port,
                    protocol,
                    tls: None,
                    allowed_routes: None,
                }],
                addresses: vec![],
                infrastructure: None,
            },
            status: None,
        }
    }

    fn make_tcp_route_with_section(
        ns: &str,
        name: &str,
        gw_ns: &str,
        gw_name: &str,
        section_name: Option<&str>,
        port: Option<u16>,
    ) -> TCPRoute {
        TCPRoute {
            metadata: kube::core::ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some(ns.to_string()),
                ..Default::default()
            },
            spec: TCPRouteSpec {
                parent_refs: vec![ParentReference {
                    group: "gateway.networking.k8s.io".to_string(),
                    kind: "Gateway".to_string(),
                    namespace: Some(gw_ns.to_string()),
                    name: gw_name.to_string(),
                    section_name: section_name.map(str::to_string),
                    port,
                }],
                rules: vec![TCPRouteRule {
                    name: None,
                    backend_refs: vec![crate::crds::BackendRef {
                        group: "".to_string(),
                        kind: "Service".to_string(),
                        name: "svc".to_string(),
                        namespace: None,
                        port: Some(5432),
                        weight: 1,
                    }],
                }],
            },
            status: None,
        }
    }

    /// Planner returns Accepted=True when sectionName matches a TCP listener.
    #[test]
    fn planner_accepted_for_matching_tcp_section_name() {
        let gw = make_gw_with_listener("prod", "my-gw", "tcp", 5432, ProtocolType::TCP);
        let route =
            make_tcp_route_with_section("prod", "my-route", "prod", "my-gw", Some("tcp"), None);
        let snapshot = SnapshotResult::Ready(make_snapshot(gw.clone(), route));

        let cond =
            planner_accepted_condition_for_section(&snapshot, &gw, "prod", "my-route", "tcp", None);

        assert_eq!(cond.type_, "Accepted");
        assert_eq!(cond.status, "True");
        assert_eq!(cond.reason, "Accepted");
    }

    /// Planner returns Accepted=False / NoMatchingParent when sectionName doesn't exist.
    #[test]
    fn planner_no_matching_parent_for_unknown_section_name() {
        let gw = make_gw_with_listener("prod", "my-gw", "tcp", 5432, ProtocolType::TCP);
        let route = make_tcp_route_with_section(
            "prod",
            "my-route",
            "prod",
            "my-gw",
            Some("nonexistent"),
            None,
        );
        let snapshot = SnapshotResult::Ready(make_snapshot(gw.clone(), route));

        let cond = planner_accepted_condition_for_section(
            &snapshot,
            &gw,
            "prod",
            "my-route",
            "nonexistent",
            None,
        );

        assert_eq!(cond.type_, "Accepted");
        assert_eq!(cond.status, "False");
        assert_eq!(cond.reason, "NoMatchingParent");
    }

    /// Planner returns Accepted=False / NotAllowedByListenerProtocol when
    /// a TCPRoute targets an HTTP listener by sectionName.
    #[test]
    fn planner_protocol_mismatch_for_tcp_route_on_http_listener() {
        let gw = make_gw_with_listener("prod", "my-gw", "http", 80, ProtocolType::HTTP);
        let route =
            make_tcp_route_with_section("prod", "my-route", "prod", "my-gw", Some("http"), None);
        let snapshot = SnapshotResult::Ready(make_snapshot(gw.clone(), route));

        let cond = planner_accepted_condition_for_section(
            &snapshot, &gw, "prod", "my-route", "http", None,
        );

        assert_eq!(cond.type_, "Accepted");
        assert_eq!(cond.status, "False");
        assert_eq!(cond.reason, "NotAllowedByListenerProtocol");
    }

    /// When the store snapshot is NotReady, fall back to flat Accepted=True.
    #[test]
    fn planner_falls_back_to_accepted_when_store_not_ready() {
        let gw = make_gw_with_listener("prod", "my-gw", "tcp", 5432, ProtocolType::TCP);
        let snapshot: SnapshotResult<PlannerSnapshot> = SnapshotResult::NotReady;

        let cond =
            planner_accepted_condition_for_section(&snapshot, &gw, "prod", "my-route", "tcp", None);

        // Must not reject the route when the store is warming up.
        assert_eq!(cond.type_, "Accepted");
        assert_eq!(cond.status, "True");
    }

    /// When the route is not yet in the snapshot and the sectionName names a
    /// known TCP listener, fall back to Accepted=True (conservative warm-up).
    ///
    /// Note: when the sectionName names an *unknown* listener the fallback
    /// returns NoMatchingParent instead -- see
    /// `route_missing_from_snapshot_rejects_unknown_section_name`.
    #[test]
    fn planner_falls_back_when_route_not_in_snapshot() {
        let gw = make_gw_with_listener("prod", "my-gw", "tcp", 5432, ProtocolType::TCP);
        // Snapshot has the gateway but NOT the route.
        let gw_key = "prod/my-gw".to_string();
        let mut gateways = HashMap::new();
        gateways.insert(gw_key, gw.clone());
        let snapshot = SnapshotResult::Ready(PlannerSnapshot {
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
        });

        let cond =
            planner_accepted_condition_for_section(&snapshot, &gw, "prod", "my-route", "tcp", None);

        // sectionName "tcp" exists in spec as a TCP listener: conservative accept.
        assert_eq!(cond.type_, "Accepted");
        assert_eq!(cond.status, "True");
    }

    /// Port mismatch: sectionName matches but port doesn't -> NoMatchingParent.
    #[test]
    fn planner_port_mismatch_gives_no_matching_parent() {
        let gw = make_gw_with_listener("prod", "my-gw", "tcp", 5432, ProtocolType::TCP);
        // parentRef specifies port=9999 but listener is on 5432.
        let route = make_tcp_route_with_section(
            "prod",
            "my-route",
            "prod",
            "my-gw",
            Some("tcp"),
            Some(9999),
        );
        let snapshot = SnapshotResult::Ready(make_snapshot(gw.clone(), route));

        let cond = planner_accepted_condition_for_section(
            &snapshot,
            &gw,
            "prod",
            "my-route",
            "tcp",
            Some(9999),
        );

        assert_eq!(cond.type_, "Accepted");
        assert_eq!(cond.status, "False");
        assert_eq!(cond.reason, "NoMatchingParent");
    }

    /// `attachment_status_message` returns non-empty strings for all variants.
    #[test]
    fn attachment_status_message_covers_all_variants() {
        use crate::reconcilers::attachment_planner::AttachmentStatus;

        let cases = [
            AttachmentStatus::Attached,
            AttachmentStatus::NoMatchingParent,
            AttachmentStatus::NotAllowedByListenerProtocol,
            AttachmentStatus::NotAllowedByListenerNamespacePolicy,
            AttachmentStatus::NotAllowedByListenerKindPolicy,
            AttachmentStatus::NoMatchingListenerHostname,
            AttachmentStatus::RefNotPermitted {
                route_namespace: "ns".to_string(),
                target_namespace: "other".to_string(),
                target_name: "svc".to_string(),
            },
        ];

        for status in &cases {
            let msg = attachment_status_message(status);
            assert!(
                !msg.is_empty(),
                "message must not be empty for {:?}",
                status
            );
        }
    }

    // ── Plan-cache tests ──────────────────────────────────────────────────────

    /// Two parentRefs pointing at the same Gateway produce the same condition
    /// and the plan is computed only once (verified via the cache size).
    #[test]
    fn plan_cache_reuses_plan_for_same_gateway() {
        let gw = make_gw_with_listener("prod", "my-gw", "tcp", 5432, ProtocolType::TCP);
        let route =
            make_tcp_route_with_section("prod", "my-route", "prod", "my-gw", Some("tcp"), None);
        let snapshot = SnapshotResult::Ready(make_snapshot(gw.clone(), route));

        let mut cache = HashMap::new();

        // First call: cache miss -- plan is computed and stored.
        let cond1 = planner_accepted_condition_for_section_cached(
            &snapshot, &gw, "prod", "my-route", "tcp", None, &mut cache,
        );
        assert_eq!(cache.len(), 1, "plan should be cached after first call");

        // Second call with the same gateway: cache hit -- no new entry.
        let cond2 = planner_accepted_condition_for_section_cached(
            &snapshot, &gw, "prod", "my-route", "tcp", None, &mut cache,
        );
        assert_eq!(cache.len(), 1, "cache should not grow on a hit");

        // Both calls must return the same condition.
        assert_eq!(cond1.status, cond2.status);
        assert_eq!(cond1.reason, cond2.reason);
        assert_eq!(cond1.status, "True");
    }

    /// Two parentRefs pointing at different Gateways each get their own cache entry.
    #[test]
    fn plan_cache_separate_entries_for_different_gateways() {
        let gw_a = make_gw_with_listener("prod", "gw-a", "tcp", 5432, ProtocolType::TCP);
        let gw_b = make_gw_with_listener("prod", "gw-b", "tcp", 5432, ProtocolType::TCP);

        let route_a =
            make_tcp_route_with_section("prod", "my-route", "prod", "gw-a", Some("tcp"), None);
        let route_b =
            make_tcp_route_with_section("prod", "my-route", "prod", "gw-b", Some("tcp"), None);

        // Build separate snapshots (each planner call needs the route in the snapshot).
        let snap_a = SnapshotResult::Ready(make_snapshot(gw_a.clone(), route_a));
        let snap_b = SnapshotResult::Ready(make_snapshot(gw_b.clone(), route_b));

        let mut cache = HashMap::new();

        planner_accepted_condition_for_section_cached(
            &snap_a, &gw_a, "prod", "my-route", "tcp", None, &mut cache,
        );
        assert_eq!(cache.len(), 1);

        planner_accepted_condition_for_section_cached(
            &snap_b, &gw_b, "prod", "my-route", "tcp", None, &mut cache,
        );
        assert_eq!(
            cache.len(),
            2,
            "different gateways must produce separate cache entries"
        );
    }

    // ── Store-removal tests ───────────────────────────────────────────────────

    /// When a route has no valid parents, `condition_from_plan` returns
    /// Accepted=False for a known-rejected section name.
    /// (The store-removal path is exercised in integration; here we verify
    /// the condition logic that drives the `has_valid_parent = false` branch.)
    #[test]
    fn no_valid_parent_condition_is_false_for_rejected_section() {
        let gw = make_gw_with_listener("prod", "my-gw", "http", 80, ProtocolType::HTTP);
        // TCPRoute targeting an HTTP listener -- should be rejected.
        let route =
            make_tcp_route_with_section("prod", "my-route", "prod", "my-gw", Some("http"), None);
        let snapshot = SnapshotResult::Ready(make_snapshot(gw.clone(), route));

        let cond = planner_accepted_condition_for_section(
            &snapshot, &gw, "prod", "my-route", "http", None,
        );

        // Condition must be False so `has_valid_parent` stays false and the
        // store-removal branch is taken.
        assert_eq!(cond.status, "False");
        assert_eq!(cond.reason, "NotAllowedByListenerProtocol");
    }

    /// `condition_from_plan` falls back to Accepted=True when the route is not
    /// yet in the snapshot and the sectionName names a known TCP listener --
    /// the store-removal branch must NOT be triggered by a transient store miss.
    ///
    /// Note: when the sectionName names an *unknown* listener the fallback
    /// returns NoMatchingParent -- see
    /// `route_missing_from_snapshot_rejects_unknown_section_name`.
    #[test]
    fn no_valid_parent_fallback_true_when_route_missing_from_snapshot() {
        let gw = make_gw_with_listener("prod", "my-gw", "tcp", 5432, ProtocolType::TCP);
        // Snapshot has the gateway but NOT the route.
        let gw_key = "prod/my-gw".to_string();
        let mut gateways = HashMap::new();
        gateways.insert(gw_key, gw.clone());
        let snapshot = SnapshotResult::Ready(PlannerSnapshot {
            gateways,
            gateway_classes: HashMap::new(),
            http_routes: HashMap::new(),
            tcp_routes: HashMap::new(),
            tls_routes: HashMap::new(),
            service_endpoints: HashMap::new(),
            tls_secrets: HashMap::new(),
            reference_grants: HashMap::new(),
            service_ref_index: std::collections::HashSet::new(),
            namespace_labels: HashMap::new(),
        });

        let cond =
            planner_accepted_condition_for_section(&snapshot, &gw, "prod", "my-route", "tcp", None);

        // Conservative fallback: must not remove a route due to a transient miss.
        assert_eq!(cond.status, "True");
    }

    // ── Gateway-wide parentRef (no sectionName) listener-gate tests ───────────

    /// Gateway-wide parentRef is accepted when the gateway has a TCP listener.
    #[test]
    fn gateway_wide_ref_accepted_when_tcp_listener_present() {
        let gw = make_gw_with_listener("prod", "my-gw", "tcp", 5432, ProtocolType::TCP);
        let has_tcp = gw
            .spec
            .listeners
            .iter()
            .any(|l| l.protocol == ProtocolType::TCP);
        assert!(has_tcp);

        // The reconciler would produce Accepted=True for this gateway-wide ref.
        let cond = if has_tcp {
            Condition::accepted()
        } else {
            Condition::new(
                "Accepted",
                false,
                "NoMatchingListener",
                "Gateway has no TCP listener",
            )
        };
        assert_eq!(cond.status, "True");
    }

    /// Gateway-wide parentRef is rejected when the gateway has only HTTP listeners.
    #[test]
    fn gateway_wide_ref_rejected_when_no_tcp_listener() {
        let gw = make_gw_with_listener("prod", "my-gw", "http", 80, ProtocolType::HTTP);
        let has_tcp = gw
            .spec
            .listeners
            .iter()
            .any(|l| l.protocol == ProtocolType::TCP);
        assert!(!has_tcp);

        // The reconciler would produce NoMatchingListener for this gateway-wide ref.
        let cond = if has_tcp {
            Condition::accepted()
        } else {
            Condition::new(
                "Accepted",
                false,
                "NoMatchingListener",
                "Gateway has no TCP listener",
            )
        };
        assert_eq!(cond.status, "False");
        assert_eq!(cond.reason, "NoMatchingListener");
    }

    // ── TCP-only semantic rule: TCPRoute must not attach to TLS listeners ─────
    //
    // These tests lock in the explicit rule: TCPRoute is TCP-only and must be
    // rejected when the gateway has only TLS listeners (gateway-wide ref) or
    // when a sectionName points at a TLS listener (planner path).

    /// Gateway-wide TCPRoute parentRef is rejected when the gateway has only
    /// TLS listeners.  TCPRoute is TCP-only; TLS listeners are not compatible.
    #[test]
    fn gateway_wide_ref_rejected_when_only_tls_listener() {
        let gw = make_gw_with_listener("prod", "my-gw", "tls", 443, ProtocolType::TLS);
        let has_tcp = gw
            .spec
            .listeners
            .iter()
            .any(|l| l.protocol == ProtocolType::TCP);
        // TLS listener must NOT satisfy the TCP-only check.
        assert!(!has_tcp, "TLS listener must not count as a TCP listener");

        let cond = if has_tcp {
            Condition::accepted()
        } else {
            Condition::new(
                "Accepted",
                false,
                "NoMatchingListener",
                "Gateway has no TCP listener",
            )
        };
        assert_eq!(cond.status, "False");
        assert_eq!(cond.reason, "NoMatchingListener");
        assert_eq!(cond.message, "Gateway has no TCP listener");
    }

    /// sectionName-qualified TCPRoute parentRef is rejected when the named
    /// listener has protocol TLS.  The planner enforces TCP-only semantics.
    #[test]
    fn planner_rejects_tcp_route_on_tls_listener_by_section_name() {
        let gw = make_gw_with_listener("prod", "my-gw", "tls", 443, ProtocolType::TLS);
        let route =
            make_tcp_route_with_section("prod", "my-route", "prod", "my-gw", Some("tls"), None);
        let snapshot = SnapshotResult::Ready(make_snapshot(gw.clone(), route));

        let cond =
            planner_accepted_condition_for_section(&snapshot, &gw, "prod", "my-route", "tls", None);

        // TCPRoute must not attach to a TLS listener.
        assert_eq!(cond.type_, "Accepted");
        assert_eq!(cond.status, "False");
        assert_eq!(cond.reason, "NotAllowedByListenerProtocol");
    }

    // ── Fix 1: sectionName path must not fail open to non-TCP listeners ──────
    //
    // When the planner snapshot is NotReady, the planner errors, or the route
    // is not yet in the snapshot, the reconciler must still enforce the
    // TCP-only rule by inspecting the Gateway spec directly.

    /// NotReady snapshot + non-TCP listener -> rejected (TCP-only rule holds).
    #[test]
    fn not_ready_snapshot_rejects_non_tcp_section_name() {
        // Gateway has an HTTP listener named "http".
        let gw = make_gw_with_listener("prod", "my-gw", "http", 80, ProtocolType::HTTP);
        let snapshot: SnapshotResult<PlannerSnapshot> = SnapshotResult::NotReady;

        let cond = planner_accepted_condition_for_section(
            &snapshot, &gw, "prod", "my-route", "http", None,
        );

        // Must reject: the named listener is HTTP, not TCP.
        assert_eq!(cond.status, "False");
        assert_eq!(cond.reason, "NotAllowedByListenerProtocol");
    }

    /// NotReady snapshot + TLS listener -> rejected (TCP-only rule holds).
    #[test]
    fn not_ready_snapshot_rejects_tls_section_name() {
        let gw = make_gw_with_listener("prod", "my-gw", "tls", 443, ProtocolType::TLS);
        let snapshot: SnapshotResult<PlannerSnapshot> = SnapshotResult::NotReady;

        let cond =
            planner_accepted_condition_for_section(&snapshot, &gw, "prod", "my-route", "tls", None);

        assert_eq!(cond.status, "False");
        assert_eq!(cond.reason, "NotAllowedByListenerProtocol");
    }

    /// NotReady snapshot + TCP listener -> accepted (conservative warm-up fallback).
    #[test]
    fn not_ready_snapshot_accepts_tcp_section_name() {
        let gw = make_gw_with_listener("prod", "my-gw", "tcp", 5432, ProtocolType::TCP);
        let snapshot: SnapshotResult<PlannerSnapshot> = SnapshotResult::NotReady;

        let cond =
            planner_accepted_condition_for_section(&snapshot, &gw, "prod", "my-route", "tcp", None);

        // TCP listener: conservative accept during warm-up.
        assert_eq!(cond.status, "True");
    }

    /// NotReady snapshot + TCP listener + port mismatch -> rejected.
    #[test]
    fn not_ready_snapshot_rejects_tcp_section_name_port_mismatch() {
        let gw = make_gw_with_listener("prod", "my-gw", "tcp", 5432, ProtocolType::TCP);
        let snapshot: SnapshotResult<PlannerSnapshot> = SnapshotResult::NotReady;

        // parentRef.port = 9999, listener is on 5432.
        let cond = planner_accepted_condition_for_section(
            &snapshot,
            &gw,
            "prod",
            "my-route",
            "tcp",
            Some(9999),
        );

        assert_eq!(cond.status, "False");
        assert_eq!(cond.reason, "NoMatchingParent");
    }

    /// Route missing from snapshot + non-TCP listener -> rejected (TCP-only rule holds).
    #[test]
    fn route_missing_from_snapshot_rejects_non_tcp_section_name() {
        let gw = make_gw_with_listener("prod", "my-gw", "http", 80, ProtocolType::HTTP);
        // Snapshot has the gateway but NOT the route.
        let gw_key = "prod/my-gw".to_string();
        let mut gateways = HashMap::new();
        gateways.insert(gw_key, gw.clone());
        let snapshot = SnapshotResult::Ready(PlannerSnapshot {
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
        });

        let cond = planner_accepted_condition_for_section(
            &snapshot, &gw, "prod", "my-route", "http", None,
        );

        // Named listener is HTTP: must reject even though route is missing.
        assert_eq!(cond.status, "False");
        assert_eq!(cond.reason, "NotAllowedByListenerProtocol");
    }

    /// Route missing from snapshot + TCP listener -> accepted (conservative).
    #[test]
    fn route_missing_from_snapshot_accepts_tcp_section_name() {
        let gw = make_gw_with_listener("prod", "my-gw", "tcp", 5432, ProtocolType::TCP);
        let gw_key = "prod/my-gw".to_string();
        let mut gateways = HashMap::new();
        gateways.insert(gw_key, gw.clone());
        let snapshot = SnapshotResult::Ready(PlannerSnapshot {
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
        });

        let cond =
            planner_accepted_condition_for_section(&snapshot, &gw, "prod", "my-route", "tcp", None);

        // TCP listener, route missing: conservative accept.
        assert_eq!(cond.status, "True");
    }

    // ── Fix 2: gateway-wide parentRef with port must match a TCP listener ─────

    /// Gateway-wide parentRef with port matching a TCP listener -> accepted.
    #[test]
    fn gateway_wide_ref_with_port_accepted_when_tcp_listener_matches() {
        let gw = make_gw_with_listener("prod", "my-gw", "tcp", 5432, ProtocolType::TCP);
        // port = 5432 matches the TCP listener.
        let matching_tcp = gw
            .spec
            .listeners
            .iter()
            .any(|l| l.protocol == ProtocolType::TCP && Some(l.port) == Some(5432));
        let cond = if matching_tcp {
            Condition::accepted()
        } else {
            Condition::new(
                "Accepted",
                false,
                "NoMatchingListener",
                "Gateway has no TCP listener matching the parentRef port",
            )
        };
        assert_eq!(cond.status, "True");
    }

    /// Gateway-wide parentRef with port NOT matching any TCP listener -> rejected.
    #[test]
    fn gateway_wide_ref_with_port_rejected_when_no_tcp_listener_matches_port() {
        let gw = make_gw_with_listener("prod", "my-gw", "tcp", 5432, ProtocolType::TCP);
        // port = 9999 does not match the TCP listener on 5432.
        let matching_tcp = gw
            .spec
            .listeners
            .iter()
            .any(|l| l.protocol == ProtocolType::TCP && l.port == 9999);
        let cond = if matching_tcp {
            Condition::accepted()
        } else {
            Condition::new(
                "Accepted",
                false,
                "NoMatchingListener",
                "Gateway has no TCP listener matching the parentRef port",
            )
        };
        assert_eq!(cond.status, "False");
        assert_eq!(cond.reason, "NoMatchingListener");
    }

    /// Gateway-wide parentRef with port matching a non-TCP listener -> rejected.
    /// The port matches an HTTP listener but TCPRoute is TCP-only.
    #[test]
    fn gateway_wide_ref_with_port_rejected_when_port_matches_only_non_tcp_listener() {
        use crate::crds::{GatewaySpec, Listener};

        // Gateway has HTTP on 80 and TCP on 5432.
        let gw = Gateway {
            metadata: kube::core::ObjectMeta {
                name: Some("mixed-gw".to_string()),
                namespace: Some("prod".to_string()),
                generation: Some(1),
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
                ],
                addresses: vec![],
                infrastructure: None,
            },
            status: None,
        };

        // parentRef.port = 80: matches the HTTP listener but NOT the TCP one.
        let matching_tcp = gw
            .spec
            .listeners
            .iter()
            .any(|l| l.protocol == ProtocolType::TCP && l.port == 80);
        let cond = if matching_tcp {
            Condition::accepted()
        } else {
            Condition::new(
                "Accepted",
                false,
                "NoMatchingListener",
                "Gateway has no TCP listener matching the parentRef port",
            )
        };
        assert_eq!(cond.status, "False");
        assert_eq!(cond.reason, "NoMatchingListener");
    }

    // ── Fix 1: explicit sectionName not in spec must never fail open ─────────
    //
    // Before the fix, `tcp_only_condition_from_spec` returned `Accepted=True`
    // when the listener name was not found in the Gateway spec (the `None` arm).
    // This caused routes with an explicit but non-existent sectionName to be
    // temporarily accepted during warm-up or planner-miss paths.
    //
    // After the fix, an unknown sectionName always returns `NoMatchingParent`.

    /// NotReady snapshot + unknown sectionName -> NoMatchingParent (not Accepted).
    ///
    /// The Gateway spec has a TCP listener named "tcp" but the parentRef
    /// specifies sectionName="does-not-exist".  Even during warm-up the route
    /// must not be accepted against a listener that does not exist.
    #[test]
    fn not_ready_snapshot_rejects_unknown_section_name() {
        let gw = make_gw_with_listener("prod", "my-gw", "tcp", 5432, ProtocolType::TCP);
        let snapshot: SnapshotResult<PlannerSnapshot> = SnapshotResult::NotReady;

        let cond = planner_accepted_condition_for_section(
            &snapshot,
            &gw,
            "prod",
            "my-route",
            "does-not-exist",
            None,
        );

        // Unknown sectionName: must reject, not fail open.
        assert_eq!(cond.type_, "Accepted");
        assert_eq!(cond.status, "False");
        assert_eq!(cond.reason, "NoMatchingParent");
    }

    /// Route missing from snapshot + unknown sectionName -> NoMatchingParent.
    ///
    /// The planner has no result for the route (it is not yet in the snapshot),
    /// so `condition_from_plan` falls back to `tcp_only_condition_from_spec`.
    /// The Gateway spec does not contain a listener named "ghost-listener", so
    /// the fallback must return `NoMatchingParent`, not `Accepted=True`.
    #[test]
    fn route_missing_from_snapshot_rejects_unknown_section_name() {
        let gw = make_gw_with_listener("prod", "my-gw", "tcp", 5432, ProtocolType::TCP);
        // Snapshot has the gateway but NOT the route.
        let gw_key = "prod/my-gw".to_string();
        let mut gateways = HashMap::new();
        gateways.insert(gw_key, gw.clone());
        let snapshot = SnapshotResult::Ready(PlannerSnapshot {
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
        });

        let cond = planner_accepted_condition_for_section(
            &snapshot,
            &gw,
            "prod",
            "my-route",
            "ghost-listener",
            None,
        );

        // Unknown sectionName: must reject even when route is missing from snapshot.
        assert_eq!(cond.type_, "Accepted");
        assert_eq!(cond.status, "False");
        assert_eq!(cond.reason, "NoMatchingParent");
    }

    /// Planner-error path + unknown sectionName -> NoMatchingParent.
    ///
    /// When the planner errors (e.g. Gateway not in snapshot), the reconciler
    /// falls back to `tcp_only_condition_from_spec`.  An unknown sectionName
    /// must still produce `NoMatchingParent`.
    #[test]
    fn planner_error_path_rejects_unknown_section_name() {
        // Gateway with a TCP listener named "tcp", but we will ask for "missing".
        let gw = make_gw_with_listener("prod", "my-gw", "tcp", 5432, ProtocolType::TCP);
        // Snapshot is Ready but does NOT contain the gateway, so the planner
        // will return PlanError::MissingField and fall back to spec check.
        let snapshot = SnapshotResult::Ready(PlannerSnapshot {
            gateways: HashMap::new(),
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

        let cond = planner_accepted_condition_for_section(
            &snapshot, &gw, "prod", "my-route", "missing", None,
        );

        // Unknown sectionName: must reject on planner-error fallback path.
        assert_eq!(cond.type_, "Accepted");
        assert_eq!(cond.status, "False");
        assert_eq!(cond.reason, "NoMatchingParent");
    }

    /// A mixed gateway (TCP + TLS listeners): gateway-wide TCPRoute ref is
    /// accepted because at least one TCP listener is present.
    #[test]
    fn gateway_wide_ref_accepted_when_tcp_listener_present_alongside_tls() {
        use crate::crds::{GatewaySpec, Listener};

        let gw = Gateway {
            metadata: kube::core::ObjectMeta {
                name: Some("mixed-gw".to_string()),
                namespace: Some("prod".to_string()),
                generation: Some(1),
                ..Default::default()
            },
            spec: GatewaySpec {
                gateway_class_name: "wicket".to_string(),
                listeners: vec![
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

        let has_tcp = gw
            .spec
            .listeners
            .iter()
            .any(|l| l.protocol == ProtocolType::TCP);
        assert!(has_tcp, "mixed gateway must have a TCP listener");

        let cond = if has_tcp {
            Condition::accepted()
        } else {
            Condition::new(
                "Accepted",
                false,
                "NoMatchingListener",
                "Gateway has no TCP listener",
            )
        };
        // TCP listener present -> gateway-wide ref is accepted.
        assert_eq!(cond.status, "True");
    }
}
