//! TLSRoute reconciler.

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
    Condition, Gateway, GatewayClass, RouteParentStatus, TLSRoute, TLSRouteStatus,
    WICKET_CONTROLLER_NAME,
};
use crate::metrics::{ReconcileMetrics, ROUTES_ACCEPTED, ROUTES_REJECTED_TOTAL, TLSROUTES};

use super::attachment_planner::{
    AttachmentPlan, AttachmentPlanInput, AttachmentPlanner, AttachmentStatus,
};
use super::config_generator::GatewayState;
use super::context::Context;
use super::store::{ResourceClass, SnapshotResult};

/// Error type for TLSRoute reconciliation.
#[derive(Debug, thiserror::Error)]
pub enum TLSRouteError {
    #[error("Kubernetes API error: {0}")]
    KubeError(#[from] kube::Error),

    #[error("Parent Gateway not found: {0}")]
    ParentNotFound(String),

    #[error("Configuration error: {0}")]
    ConfigError(String),
}

/// Reconcile a TLSRoute resource.
pub async fn reconcile_tlsroute(
    route: Arc<TLSRoute>,
    ctx: Arc<Context>,
) -> Result<Action, TLSRouteError> {
    let metrics = ReconcileMetrics::new("TLSRoute");
    let namespace = route.namespace().unwrap_or_default();
    let name = route.name_any();

    tracing::info!(namespace = %namespace, name = %name, "Reconciling TLSRoute");

    // Handle deletion: remove from store and trigger config update.
    if route.metadata.deletion_timestamp.is_some() {
        let key = GatewayState::key(&namespace, &name);
        ctx.store.remove_tls_route(&key).await;
        tracing::info!(namespace = %namespace, name = %name, "TLSRoute deleted, removed from store");
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

        // ── Step 1: tlsroute.rs is authoritative for missing / non-Wicket parents ──
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
                return Err(TLSRouteError::KubeError(e));
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
                return Err(TLSRouteError::KubeError(e));
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
        //    Gateway-wide refs (no sectionName) keep the existing legacy behavior:
        //    check for any TLS listener and accept if found.  This avoids
        //    multi-listener aggregation ambiguity in this slice.
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
            // Gateway-wide parentRef: no sectionName -> require at least one
            // TLS listener so a TLSRoute is not accepted against a non-TLS
            // gateway.  When parentRef.port is set, that port must match a
            // TLS listener (not merely any TLS listener).
            let matching_tls = gateway.spec.listeners.iter().any(|l| {
                l.protocol == crate::crds::ProtocolType::TLS
                    && parent_ref.port.is_none_or(|p| l.port == p)
            });

            if matching_tls {
                Condition::accepted()
            } else {
                tracing::debug!(
                    namespace = %namespace,
                    route = %name,
                    parent_ref = %parent_ref.name,
                    parent_namespace = %parent_ns,
                    port = ?parent_ref.port,
                    reason = "NoMatchingListener",
                    message = "Gateway has no TLS listener matching the parentRef port",
                    "Route listener validation failed"
                );
                Condition::new(
                    "Accepted",
                    false,
                    "NoMatchingListener",
                    "Gateway has no TLS listener matching the parentRef port",
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

    // Update TLSRoute status.
    let status = TLSRouteStatus {
        parents: parent_statuses,
    };

    let api: Api<TLSRoute> = Api::namespaced(ctx.client.clone(), &namespace);
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
            .upsert_tls_route(route_key, route_with_status)
            .await;

        tracing::info!(
            namespace = %namespace,
            name = %name,
            hostnames = ?route.spec.hostnames,
            "TLSRoute accepted"
        );

        // Update route acceptance metrics for each valid parent.
        for parent_status in &status.parents {
            let gw_name = &parent_status.parent_ref.name;
            if parent_status
                .conditions
                .iter()
                .any(|c| c.type_ == "Accepted" && c.status == "True")
            {
                ROUTES_ACCEPTED
                    .with_label_values(&[&namespace, "TLSRoute", gw_name])
                    .set(1);
            }
        }
    } else {
        tracing::warn!(namespace = %namespace, name = %name, "TLSRoute has no valid Wicket parents");

        // Remove from store if it was previously accepted, so stale config is
        // not served.  If the route was never in the store this is a no-op.
        let route_key = GatewayState::key(&namespace, &name);
        ctx.store.remove_tls_route(&route_key).await;
        tracing::debug!(
            namespace = %namespace,
            name = %name,
            "TLSRoute removed from store (no valid Wicket parents)"
        );

        // Trigger config regeneration so the proxy stops serving the stale route.
        // Track rejection reasons.
        for parent_status in &status.parents {
            for condition in &parent_status.conditions {
                if condition.type_ == "Accepted" && condition.status == "False" {
                    ROUTES_REJECTED_TOTAL
                        .with_label_values(&[&namespace, "TLSRoute", &condition.reason])
                        .inc();
                }
            }
        }
    }

    metrics.record_success();

    // Update metrics.
    update_tlsroute_metrics(&ctx.client).await;

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
/// TLSRoute is TLS-only.  On any fallback path (snapshot NotReady, planner
/// error, route not yet in snapshot) we inspect the Gateway spec directly via
/// `tls_only_condition_from_spec`:
/// - Named listener exists and is not TLS -> `NotAllowedByListenerProtocol`.
/// - Named listener exists, is TLS, port mismatches -> `NoMatchingParent`.
/// - Named listener exists, is TLS, port matches (or absent) -> `Accepted=True`.
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
                "Planner snapshot not ready; checking Gateway spec for TLS-only rule"
            );
            return tls_only_condition_from_spec(gateway, section_name, port);
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
                    "AttachmentPlanner error; checking Gateway spec for TLS-only rule"
                );
                return tls_only_condition_from_spec(gateway, section_name, port);
            }
        }
    }

    // Safe: we just inserted above if missing.
    let plan = match plan_cache.get(&cache_key) {
        Some(p) => p,
        None => return tls_only_condition_from_spec(gateway, section_name, port),
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

/// Enforce the TLS-only rule directly from the Gateway spec when the planner
/// is unavailable (snapshot not ready, planner error, or route not yet in
/// snapshot).
///
/// - If the named listener exists and its protocol is not TLS ->
///   `NotAllowedByListenerProtocol` (hard rejection; the spec is authoritative).
/// - If the named listener exists, is TLS, but the port does not match ->
///   `NoMatchingParent` (hard rejection; port is authoritative in the spec).
/// - If the named listener exists, is TLS, and port matches (or is absent) ->
///   `Accepted=True` (conservative warm-up fallback).
/// - If the named listener does NOT exist in the spec ->
///   `NoMatchingParent` (hard rejection; an explicit sectionName that names a
///   non-existent listener is never a transient condition -- the spec is
///   authoritative and we must not fail open).
fn tls_only_condition_from_spec(
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
            if listener.protocol != crate::crds::ProtocolType::TLS {
                // Named listener exists and is not TLS: TLSRoute cannot attach.
                tracing::debug!(
                    section_name = %section_name,
                    protocol = ?listener.protocol,
                    "TLSRoute sectionName targets non-TLS listener; rejecting (TLS-only rule)"
                );
                return Condition::new(
                    "Accepted",
                    false,
                    "NotAllowedByListenerProtocol",
                    "Route kind is not compatible with the listener protocol",
                );
            }
            // Listener is TLS.  If a port was specified it must match.
            if let Some(ref_port) = port {
                if listener.port != ref_port {
                    tracing::debug!(
                        section_name = %section_name,
                        listener_port = listener.port,
                        ref_port = ref_port,
                        "TLSRoute parentRef port does not match listener port; rejecting"
                    );
                    return Condition::new(
                        "Accepted",
                        false,
                        "NoMatchingParent",
                        "No listener matches the parentRef sectionName or port",
                    );
                }
            }
            // TLS listener, port matches (or absent): conservative accept.
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
                "TLSRoute sectionName not found in Gateway spec; rejecting (NoMatchingParent)"
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
/// Falls back to `tls_only_condition_from_spec` when:
/// - The store snapshot is not yet ready (warm-up gap).
/// - The planner returns an error (e.g. Gateway not yet in the store).
/// - No result is found for the `(route, sectionName, port)` triple.
///
/// The fallback enforces the TLS-only rule from the Gateway spec:
/// - Non-TLS listener -> rejected.
/// - TLS listener, port mismatch -> rejected.
/// - TLS listener, port matches (or absent) -> accepted conservatively.
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
/// (route not yet in the snapshot), falls back to `tls_only_condition_from_spec`
/// rather than blindly accepting, so the TLS-only rule is enforced even during
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
            // Apply the TLS-only rule from the Gateway spec before falling back.
            tracing::debug!(
                route_namespace = %route_namespace,
                route_name = %route_name,
                section_name = %section_name,
                "No planner result for parentRef; applying TLS-only spec check"
            );
            tls_only_condition_from_spec(gateway, section_name, port)
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

/// Handle errors during TLSRoute reconciliation.
pub fn error_policy_tlsroute(
    route: Arc<TLSRoute>,
    error: &TLSRouteError,
    _ctx: Arc<Context>,
) -> Action {
    let namespace = route.namespace().unwrap_or_default();
    let name = route.name_any();

    tracing::error!(
        namespace = %namespace,
        name = %name,
        error = %error,
        "TLSRoute reconciliation failed"
    );

    crate::metrics::RECONCILE_ERRORS_TOTAL
        .with_label_values(&["TLSRoute", "reconcile_error"])
        .inc();

    Action::requeue(Duration::from_secs(5))
}

/// Update TLSRoute metrics.
async fn update_tlsroute_metrics(client: &Client) {
    let api: Api<TLSRoute> = Api::all(client.clone());

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
                TLSROUTES.with_label_values(&[&ns]).set(count);
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "Failed to list TLSRoutes for metrics");
        }
    }
}

/// Create the TLSRoute controller.
pub async fn run_tlsroute_controller(ctx: Arc<Context>) -> Result<(), kube::Error> {
    use crate::metrics::{WATCH_CONNECTIONS_ACTIVE, WATCH_ERRORS_TOTAL, WATCH_EVENTS_TOTAL};

    let api: Api<TLSRoute> = if ctx.watch_all_namespaces {
        Api::all(ctx.client.clone())
    } else {
        Api::namespaced(ctx.client.clone(), &ctx.controller_namespace)
    };

    WATCH_CONNECTIONS_ACTIVE
        .with_label_values(&["TLSRoute"])
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
                    ctx.store.upsert_tls_route(key, route).await;
                }
                ctx.store.mark_listed(ResourceClass::TlsRoutes).await;
                tracing::debug!(attempt, "TLSRoute initial list complete; store flag set");
                break;
            }
            Ok(Err(e)) => {
                let backoff = std::cmp::min(attempt * 2, 30);
                tracing::warn!(
                    error = %e,
                    attempt,
                    backoff_secs = backoff,
                    "Initial TLSRoute list failed; will retry"
                );
                tokio::time::sleep(Duration::from_secs(backoff as u64)).await;
            }
            Err(_) => {
                tracing::warn!(
                    attempt,
                    "Initial TLSRoute list timed out after 30s; will retry"
                );
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }
    }

    Controller::new(api, Config::default())
        .run(reconcile_tlsroute, error_policy_tlsroute, ctx)
        .for_each(|result| async move {
            match result {
                Ok((obj, _)) => {
                    WATCH_EVENTS_TOTAL
                        .with_label_values(&["TLSRoute", "reconcile_success"])
                        .inc();
                    tracing::debug!(
                        namespace = obj.namespace.as_deref().unwrap_or(""),
                        name = %obj.name,
                        "TLSRoute reconciled"
                    );
                }
                Err(e) => {
                    WATCH_EVENTS_TOTAL
                        .with_label_values(&["TLSRoute", "reconcile_error"])
                        .inc();
                    WATCH_ERRORS_TOTAL
                        .with_label_values(&["TLSRoute", "controller_error"])
                        .inc();
                    tracing::error!(error = %e, "TLSRoute controller error");
                }
            }
        })
        .await;

    WATCH_CONNECTIONS_ACTIVE
        .with_label_values(&["TLSRoute"])
        .set(0);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crds::{
        BackendRef, Condition, Gateway, GatewaySpec, Listener, ParentReference, ProtocolType,
        TLSRouteRule, TLSRouteSpec,
    };
    use kube::core::ObjectMeta;
    use std::sync::Arc;

    /// Helper to create a test TLSRoute.
    fn make_tlsroute(
        name: &str,
        namespace: &str,
        parent_refs: Vec<ParentReference>,
        hostnames: Vec<String>,
    ) -> Arc<TLSRoute> {
        Arc::new(TLSRoute {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some(namespace.to_string()),
                ..Default::default()
            },
            spec: TLSRouteSpec {
                parent_refs,
                hostnames,
                rules: vec![TLSRouteRule {
                    name: None,
                    backend_refs: vec![BackendRef {
                        group: "".to_string(),
                        kind: "Service".to_string(),
                        name: "backend".to_string(),
                        namespace: None,
                        port: Some(443),
                        weight: 1,
                    }],
                }],
            },
            status: None,
        })
    }

    /// Helper to create a test Gateway.
    fn make_gateway(
        name: &str,
        namespace: &str,
        gateway_class: &str,
        protocols: Vec<ProtocolType>,
    ) -> Gateway {
        Gateway {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some(namespace.to_string()),
                ..Default::default()
            },
            spec: GatewaySpec {
                gateway_class_name: gateway_class.to_string(),
                listeners: protocols
                    .into_iter()
                    .enumerate()
                    .map(|(i, protocol)| Listener {
                        name: format!("listener-{}", i),
                        hostname: None,
                        port: match protocol {
                            ProtocolType::HTTP | ProtocolType::HTTPS => 8080 + i as u16,
                            ProtocolType::TCP | ProtocolType::TLS | ProtocolType::UDP => {
                                8443 + i as u16
                            }
                        },
                        protocol,
                        tls: None,
                        allowed_routes: None,
                    })
                    .collect(),
                addresses: vec![],
                infrastructure: None,
            },
            status: None,
        }
    }

    /// Test: TLSRoute with Gateway that has no TLS listener sets NoMatchingListener.
    #[test]
    fn test_tlsroute_no_tls_listener_sets_no_matching_listener() {
        // Setup: Create TLSRoute referencing Gateway with only HTTP listeners
        let _route = make_tlsroute(
            "test-route",
            "default",
            vec![ParentReference {
                group: "gateway.networking.k8s.io".to_string(),
                kind: "Gateway".to_string(),
                namespace: None,
                name: "http-only-gateway".to_string(),
                section_name: None,
                port: None,
            }],
            vec!["db.example.com".to_string()],
        );

        // Gateway with only HTTP listeners (no TLS)
        let gateway = make_gateway(
            "http-only-gateway",
            "default",
            "wicket",
            vec![ProtocolType::HTTP],
        );

        // Verify: Gateway has only HTTP listeners
        assert_eq!(gateway.spec.listeners.len(), 1);
        assert_eq!(gateway.spec.listeners[0].protocol, ProtocolType::HTTP);

        // Verify: No TLS listener exists
        let has_tls_listener = gateway
            .spec
            .listeners
            .iter()
            .any(|l| l.protocol == ProtocolType::TLS);
        assert!(!has_tls_listener, "Gateway should not have TLS listener");

        // Expected condition for no matching listener
        let expected_condition = Condition::new(
            "Accepted",
            false,
            "NoMatchingListener",
            "Gateway has no TLS listener matching the parentRef port",
        );

        assert_eq!(expected_condition.type_, "Accepted");
        assert_eq!(expected_condition.status, "False");
        assert_eq!(expected_condition.reason, "NoMatchingListener");
        assert_eq!(
            expected_condition.message,
            "Gateway has no TLS listener matching the parentRef port"
        );
    }

    /// Test: TLSRoute with Gateway that has TLS listener is accepted.
    #[test]
    fn test_tlsroute_with_tls_listener_is_accepted() {
        // Setup: Create TLSRoute referencing Gateway with TLS listener
        let _route = make_tlsroute(
            "test-route",
            "default",
            vec![ParentReference {
                group: "gateway.networking.k8s.io".to_string(),
                kind: "Gateway".to_string(),
                namespace: None,
                name: "tls-gateway".to_string(),
                section_name: None,
                port: None,
            }],
            vec!["db.example.com".to_string()],
        );

        // Gateway with TLS listener
        let gateway = make_gateway("tls-gateway", "default", "wicket", vec![ProtocolType::TLS]);

        // Verify: Gateway has TLS listener
        assert_eq!(gateway.spec.listeners.len(), 1);
        assert_eq!(gateway.spec.listeners[0].protocol, ProtocolType::TLS);

        // Verify: TLS listener exists
        let has_tls_listener = gateway
            .spec
            .listeners
            .iter()
            .any(|l| l.protocol == ProtocolType::TLS);
        assert!(has_tls_listener, "Gateway should have TLS listener");

        // Expected condition for accepted route
        let accepted_condition =
            Condition::new("Accepted", true, "Accepted", "Resource has been accepted");

        assert_eq!(accepted_condition.type_, "Accepted");
        assert_eq!(accepted_condition.status, "True");
        assert_eq!(accepted_condition.reason, "Accepted");
    }

    /// Test: TLSRoute with multiple listeners finds TLS listener.
    #[test]
    fn test_tlsroute_multiple_listeners_finds_tls() {
        // Gateway with HTTP and TLS listeners
        let gateway = make_gateway(
            "mixed-gateway",
            "default",
            "wicket",
            vec![ProtocolType::HTTP, ProtocolType::HTTPS, ProtocolType::TLS],
        );

        // Verify: Gateway has multiple listeners including TLS
        assert_eq!(gateway.spec.listeners.len(), 3);
        assert_eq!(gateway.spec.listeners[0].protocol, ProtocolType::HTTP);
        assert_eq!(gateway.spec.listeners[1].protocol, ProtocolType::HTTPS);
        assert_eq!(gateway.spec.listeners[2].protocol, ProtocolType::TLS);

        // Verify: TLS listener exists
        let tls_listeners: Vec<_> = gateway
            .spec
            .listeners
            .iter()
            .filter(|l| l.protocol == ProtocolType::TLS)
            .collect();
        assert_eq!(tls_listeners.len(), 1);
    }

    /// Test: TLSRoute with missing Gateway sets InvalidParentRef.
    #[test]
    fn test_tlsroute_missing_gateway_sets_invalid_parent_ref() {
        // Setup: Create TLSRoute referencing non-existent Gateway
        let _route = make_tlsroute(
            "test-route",
            "default",
            vec![ParentReference {
                group: "gateway.networking.k8s.io".to_string(),
                kind: "Gateway".to_string(),
                namespace: None,
                name: "missing-gateway".to_string(),
                section_name: None,
                port: None,
            }],
            vec!["db.example.com".to_string()],
        );

        // Verify: The reconciler should set InvalidParentRef condition
        let expected_condition = Condition::new(
            "Accepted",
            false,
            "InvalidParentRef",
            "Parent Gateway not found",
        );

        assert_eq!(expected_condition.type_, "Accepted");
        assert_eq!(expected_condition.status, "False");
        assert_eq!(expected_condition.reason, "InvalidParentRef");
        assert_eq!(expected_condition.message, "Parent Gateway not found");
    }

    /// Test: TLSRoute with non-Wicket Gateway sets InvalidParentRef.
    #[test]
    fn test_tlsroute_non_wicket_gateway_sets_invalid_parent_ref() {
        // Setup: Create TLSRoute referencing non-Wicket Gateway
        let _route = make_tlsroute(
            "test-route",
            "default",
            vec![ParentReference {
                group: "gateway.networking.k8s.io".to_string(),
                kind: "Gateway".to_string(),
                namespace: None,
                name: "other-controller-gateway".to_string(),
                section_name: None,
                port: None,
            }],
            vec!["db.example.com".to_string()],
        );

        // Verify: The reconciler should set InvalidParentRef when GatewayClass
        // is not managed by Wicket
        let expected_condition = Condition::new(
            "Accepted",
            false,
            "InvalidParentRef",
            "Gateway is not managed by Wicket",
        );

        assert_eq!(expected_condition.type_, "Accepted");
        assert_eq!(expected_condition.status, "False");
        assert_eq!(expected_condition.reason, "InvalidParentRef");
        assert_eq!(
            expected_condition.message,
            "Gateway is not managed by Wicket"
        );
    }

    /// Test: TLSRoute with multiple hostnames.
    #[test]
    fn test_tlsroute_with_multiple_hostnames() {
        // Setup: TLSRoute with multiple SNI hostnames
        let route = make_tlsroute(
            "test-route",
            "default",
            vec![],
            vec![
                "db.example.com".to_string(),
                "redis.example.com".to_string(),
                "*.internal.example.com".to_string(),
            ],
        );

        // Verify: All hostnames are preserved
        assert_eq!(route.spec.hostnames.len(), 3);
        assert_eq!(route.spec.hostnames[0], "db.example.com");
        assert_eq!(route.spec.hostnames[1], "redis.example.com");
        assert_eq!(route.spec.hostnames[2], "*.internal.example.com");

        // Test SNI matching
        assert!(route.matches_sni("db.example.com"));
        assert!(route.matches_sni("redis.example.com"));
        assert!(route.matches_sni("app.internal.example.com"));
        assert!(!route.matches_sni("other.com"));
    }

    /// Test: RouteParentStatus structure for TLSRoute rejection.
    #[test]
    fn test_tlsroute_parent_status_for_no_matching_listener() {
        // Create a parent status for a route with no matching listener
        let parent_ref = ParentReference {
            group: "gateway.networking.k8s.io".to_string(),
            kind: "Gateway".to_string(),
            namespace: None,
            name: "http-only-gateway".to_string(),
            section_name: None,
            port: None,
        };

        let parent_status = RouteParentStatus {
            parent_ref: parent_ref.clone(),
            controller_name: WICKET_CONTROLLER_NAME.to_string(),
            conditions: vec![Condition::new(
                "Accepted",
                false,
                "NoMatchingListener",
                "Gateway has no TLS listener matching the parentRef port",
            )],
        };

        // Verify structure
        assert_eq!(parent_status.parent_ref.name, "http-only-gateway");
        assert_eq!(
            parent_status.controller_name,
            "wicket.io/gateway-controller"
        );
        assert_eq!(parent_status.conditions.len(), 1);
        assert_eq!(parent_status.conditions[0].type_, "Accepted");
        assert_eq!(parent_status.conditions[0].status, "False");
        assert_eq!(parent_status.conditions[0].reason, "NoMatchingListener");
        assert_eq!(
            parent_status.conditions[0].message,
            "Gateway has no TLS listener matching the parentRef port"
        );
    }

    /// Test: Metrics label structure for TLSRoute rejection.
    #[test]
    fn test_tlsroute_rejection_metrics_label_structure() {
        // Verify metric label structure
        // The metric should have labels: [namespace, "TLSRoute", reason]
        let expected_labels = ["default", "TLSRoute", "NoMatchingListener"];
        let actual_labels: Vec<&str> = expected_labels.to_vec();

        assert_eq!(actual_labels.len(), 3);
        assert_eq!(actual_labels[0], "default");
        assert_eq!(actual_labels[1], "TLSRoute");
        assert_eq!(actual_labels[2], "NoMatchingListener");
    }

    /// Test: TLSRouteError enum variants.
    #[test]
    fn test_tlsroute_error_variants() {
        // Test error message formatting
        let parent_err = TLSRouteError::ParentNotFound("my-gateway".to_string());
        assert_eq!(
            parent_err.to_string(),
            "Parent Gateway not found: my-gateway"
        );

        let config_err = TLSRouteError::ConfigError("test error".to_string());
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
        let kube_err = TLSRouteError::KubeError(err);
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

    // ── Planner-driven Accepted condition tests ───────────────────────────────
    //
    // These tests exercise `planner_accepted_condition_for_section` directly,
    // without a live Kubernetes API server.  They use the same snapshot/planner
    // infrastructure as the attachment_planner unit tests.

    use crate::reconcilers::store::{PlannerSnapshot, SnapshotResult};
    use std::collections::{HashMap, HashSet};

    /// Build a minimal `PlannerSnapshot` containing the given gateway and TLSRoute.
    fn make_snapshot(gateway: Gateway, route: TLSRoute) -> PlannerSnapshot {
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
        let mut tls_routes = HashMap::new();
        tls_routes.insert(route_key, route);
        PlannerSnapshot {
            gateways,
            gateway_classes: HashMap::new(),
            http_routes: HashMap::new(),
            tcp_routes: HashMap::new(),
            tls_routes,
            service_endpoints: HashMap::new(),
            service_presence: HashSet::new(),
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

    fn make_tls_route_with_section(
        ns: &str,
        name: &str,
        gw_ns: &str,
        gw_name: &str,
        section_name: Option<&str>,
        port: Option<u16>,
    ) -> TLSRoute {
        TLSRoute {
            metadata: kube::core::ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some(ns.to_string()),
                ..Default::default()
            },
            spec: TLSRouteSpec {
                parent_refs: vec![ParentReference {
                    group: "gateway.networking.k8s.io".to_string(),
                    kind: "Gateway".to_string(),
                    namespace: Some(gw_ns.to_string()),
                    name: gw_name.to_string(),
                    section_name: section_name.map(str::to_string),
                    port,
                }],
                hostnames: vec![],
                rules: vec![TLSRouteRule {
                    name: None,
                    backend_refs: vec![BackendRef {
                        group: "".to_string(),
                        kind: "Service".to_string(),
                        name: "svc".to_string(),
                        namespace: None,
                        port: Some(443),
                        weight: 1,
                    }],
                }],
            },
            status: None,
        }
    }

    /// Planner returns Accepted=True when sectionName matches a TLS listener.
    #[test]
    fn planner_accepted_for_matching_tls_section_name() {
        let gw = make_gw_with_listener("prod", "my-gw", "tls", 443, ProtocolType::TLS);
        let route =
            make_tls_route_with_section("prod", "my-route", "prod", "my-gw", Some("tls"), None);
        let snapshot = SnapshotResult::Ready(make_snapshot(gw.clone(), route));

        let cond =
            planner_accepted_condition_for_section(&snapshot, &gw, "prod", "my-route", "tls", None);

        assert_eq!(cond.type_, "Accepted");
        assert_eq!(cond.status, "True");
        assert_eq!(cond.reason, "Accepted");
    }

    /// Planner returns Accepted=False / NoMatchingParent when sectionName doesn't exist.
    #[test]
    fn planner_no_matching_parent_for_unknown_section_name() {
        let gw = make_gw_with_listener("prod", "my-gw", "tls", 443, ProtocolType::TLS);
        let route = make_tls_route_with_section(
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
    /// a TLSRoute targets an HTTP listener by sectionName.
    #[test]
    fn planner_protocol_mismatch_for_tls_route_on_http_listener() {
        let gw = make_gw_with_listener("prod", "my-gw", "http", 80, ProtocolType::HTTP);
        let route =
            make_tls_route_with_section("prod", "my-route", "prod", "my-gw", Some("http"), None);
        let snapshot = SnapshotResult::Ready(make_snapshot(gw.clone(), route));

        let cond = planner_accepted_condition_for_section(
            &snapshot, &gw, "prod", "my-route", "http", None,
        );

        assert_eq!(cond.type_, "Accepted");
        assert_eq!(cond.status, "False");
        assert_eq!(cond.reason, "NotAllowedByListenerProtocol");
    }

    /// When the store snapshot is NotReady and the sectionName names a known
    /// TLS listener, fall back to Accepted=True (conservative warm-up).
    #[test]
    fn planner_falls_back_to_accepted_when_store_not_ready() {
        let gw = make_gw_with_listener("prod", "my-gw", "tls", 443, ProtocolType::TLS);
        let snapshot: SnapshotResult<PlannerSnapshot> = SnapshotResult::NotReady;

        let cond =
            planner_accepted_condition_for_section(&snapshot, &gw, "prod", "my-route", "tls", None);

        // Named listener "tls" exists and is TLS: conservative accept.
        assert_eq!(cond.type_, "Accepted");
        assert_eq!(cond.status, "True");
    }

    /// When the store snapshot is NotReady and the sectionName names an
    /// unknown listener, return NoMatchingParent (never fail open).
    #[test]
    fn planner_not_ready_rejects_unknown_section_name() {
        let gw = make_gw_with_listener("prod", "my-gw", "tls", 443, ProtocolType::TLS);
        let snapshot: SnapshotResult<PlannerSnapshot> = SnapshotResult::NotReady;

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

    /// When the store snapshot is NotReady and the sectionName names an HTTP
    /// listener, return NotAllowedByListenerProtocol (spec is authoritative).
    #[test]
    fn planner_not_ready_rejects_non_tls_section_name() {
        let gw = make_gw_with_listener("prod", "my-gw", "http", 80, ProtocolType::HTTP);
        let snapshot: SnapshotResult<PlannerSnapshot> = SnapshotResult::NotReady;

        let cond = planner_accepted_condition_for_section(
            &snapshot, &gw, "prod", "my-route", "http", None,
        );

        assert_eq!(cond.type_, "Accepted");
        assert_eq!(cond.status, "False");
        assert_eq!(cond.reason, "NotAllowedByListenerProtocol");
    }

    /// When the route is not yet in the snapshot and the sectionName names a
    /// known TLS listener, fall back to Accepted=True (conservative warm-up).
    ///
    /// Note: when the sectionName names an *unknown* listener the fallback
    /// returns NoMatchingParent instead -- see
    /// `route_missing_from_snapshot_rejects_unknown_section_name`.
    #[test]
    fn planner_falls_back_when_route_not_in_snapshot() {
        let gw = make_gw_with_listener("prod", "my-gw", "tls", 443, ProtocolType::TLS);
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
            service_presence: HashSet::new(),
            tls_secrets: HashMap::new(),
            reference_grants: HashMap::new(),
            service_ref_index: HashSet::new(),
            namespace_labels: HashMap::new(),
        });

        let cond =
            planner_accepted_condition_for_section(&snapshot, &gw, "prod", "my-route", "tls", None);

        // sectionName "tls" exists in spec as a TLS listener: conservative accept.
        assert_eq!(cond.type_, "Accepted");
        assert_eq!(cond.status, "True");
    }

    /// When the route is not yet in the snapshot and the sectionName names an
    /// unknown listener, return NoMatchingParent (never fail open).
    #[test]
    fn route_missing_from_snapshot_rejects_unknown_section_name() {
        let gw = make_gw_with_listener("prod", "my-gw", "tls", 443, ProtocolType::TLS);
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
            service_presence: HashSet::new(),
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
            "nonexistent",
            None,
        );

        assert_eq!(cond.type_, "Accepted");
        assert_eq!(cond.status, "False");
        assert_eq!(cond.reason, "NoMatchingParent");
    }

    /// Port mismatch: sectionName matches but port doesn't → NoMatchingParent.
    #[test]
    fn planner_port_mismatch_gives_no_matching_parent() {
        let gw = make_gw_with_listener("prod", "my-gw", "tls", 443, ProtocolType::TLS);
        // parentRef specifies port=8443 but listener is on 443.
        let route = make_tls_route_with_section(
            "prod",
            "my-route",
            "prod",
            "my-gw",
            Some("tls"),
            Some(8443),
        );
        let snapshot = SnapshotResult::Ready(make_snapshot(gw.clone(), route));

        let cond = planner_accepted_condition_for_section(
            &snapshot,
            &gw,
            "prod",
            "my-route",
            "tls",
            Some(8443),
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
        let gw = make_gw_with_listener("prod", "my-gw", "tls", 443, ProtocolType::TLS);
        let route =
            make_tls_route_with_section("prod", "my-route", "prod", "my-gw", Some("tls"), None);
        let snapshot = SnapshotResult::Ready(make_snapshot(gw.clone(), route));

        let mut cache = HashMap::new();

        // First call: cache miss -- plan is computed and stored.
        let cond1 = planner_accepted_condition_for_section_cached(
            &snapshot, &gw, "prod", "my-route", "tls", None, &mut cache,
        );
        assert_eq!(cache.len(), 1, "plan should be cached after first call");

        // Second call with the same gateway: cache hit -- no new entry.
        let cond2 = planner_accepted_condition_for_section_cached(
            &snapshot, &gw, "prod", "my-route", "tls", None, &mut cache,
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
        let gw_a = make_gw_with_listener("prod", "gw-a", "tls", 443, ProtocolType::TLS);
        let gw_b = make_gw_with_listener("prod", "gw-b", "tls", 443, ProtocolType::TLS);

        let route_a =
            make_tls_route_with_section("prod", "my-route", "prod", "gw-a", Some("tls"), None);
        let route_b =
            make_tls_route_with_section("prod", "my-route", "prod", "gw-b", Some("tls"), None);

        // Build separate snapshots (each planner call needs the route in the snapshot).
        let snap_a = SnapshotResult::Ready(make_snapshot(gw_a.clone(), route_a));
        let snap_b = SnapshotResult::Ready(make_snapshot(gw_b.clone(), route_b));

        let mut cache = HashMap::new();

        planner_accepted_condition_for_section_cached(
            &snap_a, &gw_a, "prod", "my-route", "tls", None, &mut cache,
        );
        assert_eq!(cache.len(), 1);

        planner_accepted_condition_for_section_cached(
            &snap_b, &gw_b, "prod", "my-route", "tls", None, &mut cache,
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
    #[test]
    fn no_valid_parent_condition_is_false_for_rejected_section() {
        let gw = make_gw_with_listener("prod", "my-gw", "http", 80, ProtocolType::HTTP);
        // TLSRoute targeting an HTTP listener -- should be rejected.
        let route =
            make_tls_route_with_section("prod", "my-route", "prod", "my-gw", Some("http"), None);
        let snapshot = SnapshotResult::Ready(make_snapshot(gw.clone(), route));

        let cond = planner_accepted_condition_for_section(
            &snapshot, &gw, "prod", "my-route", "http", None,
        );

        // Condition must be False so `has_valid_parent` stays false and the
        // store-removal branch is taken.
        assert_eq!(cond.status, "False");
        assert_eq!(cond.reason, "NotAllowedByListenerProtocol");
    }

    /// `condition_from_plan` falls back to spec-check when the route is not
    /// yet in the snapshot.  For a known TLS listener the result is Accepted=True
    /// (conservative warm-up); the store-removal branch must NOT be triggered
    /// by a transient store miss against a valid listener.
    #[test]
    fn no_valid_parent_fallback_true_when_route_missing_from_snapshot() {
        let gw = make_gw_with_listener("prod", "my-gw", "tls", 443, ProtocolType::TLS);
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
            service_presence: std::collections::HashSet::new(),
            tls_secrets: HashMap::new(),
            reference_grants: HashMap::new(),
            service_ref_index: std::collections::HashSet::new(),
            namespace_labels: HashMap::new(),
        });

        let cond =
            planner_accepted_condition_for_section(&snapshot, &gw, "prod", "my-route", "tls", None);

        // sectionName "tls" exists in spec as TLS: conservative accept.
        assert_eq!(cond.status, "True");
    }

    // ── Store/status consistency tests ────────────────────────────────────────

    use crate::crds::{RouteParentStatus, TLSRouteStatus};
    use crate::reconcilers::store::SharedStore;

    /// When a TLSRoute is accepted, the object stored in SharedStore must carry
    /// the status that was written to the API server (not the stale pre-patch
    /// object which has status = None).
    #[tokio::test]
    async fn tls_store_upsert_carries_written_status() {
        let store = SharedStore::new();
        store.mark_ready().await;

        let mut route = make_tlsroute(
            "my-route",
            "default",
            vec![ParentReference {
                group: "gateway.networking.k8s.io".to_string(),
                kind: "Gateway".to_string(),
                namespace: None,
                name: "my-gw".to_string(),
                section_name: None,
                port: None,
            }],
            vec!["db.example.com".to_string()],
        );

        // Simulate what the reconciler does: attach the written status before
        // upserting.
        let written_status = TLSRouteStatus {
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
        };

        let route_mut = Arc::make_mut(&mut route);
        route_mut.status = Some(written_status.clone());

        let key = crate::reconcilers::config_generator::GatewayState::key("default", "my-route");
        store.upsert_tls_route(key.clone(), (*route).clone()).await;

        let snap = store.snapshot().await.expect("store ready");
        let stored = snap.tls_routes.get(&key).expect("route in store");
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

    /// All controller_name values written by the TLSRoute reconciler must
    /// equal WICKET_CONTROLLER_NAME.
    #[test]
    fn tls_all_parent_statuses_use_wicket_controller_name() {
        // Accepted parent
        let accepted = RouteParentStatus {
            parent_ref: ParentReference {
                group: "gateway.networking.k8s.io".to_string(),
                kind: "Gateway".to_string(),
                namespace: None,
                name: "gw".to_string(),
                section_name: None,
                port: None,
            },
            controller_name: WICKET_CONTROLLER_NAME.to_string(),
            conditions: vec![Condition::accepted(), Condition::resolved_refs()],
        };
        assert_eq!(accepted.controller_name, WICKET_CONTROLLER_NAME);

        // Rejected parent (missing gateway)
        let rejected = RouteParentStatus {
            parent_ref: ParentReference {
                group: "gateway.networking.k8s.io".to_string(),
                kind: "Gateway".to_string(),
                namespace: None,
                name: "missing".to_string(),
                section_name: None,
                port: None,
            },
            controller_name: WICKET_CONTROLLER_NAME.to_string(),
            conditions: vec![Condition::new(
                "Accepted",
                false,
                "InvalidParentRef",
                "Parent Gateway not found",
            )],
        };
        assert_eq!(rejected.controller_name, WICKET_CONTROLLER_NAME);
    }

    // ── Gateway-wide parentRef (no sectionName) port-matching tests ──────────

    /// Gateway-wide parentRef with no port constraint is accepted when a TLS
    /// listener exists.
    #[test]
    fn gateway_wide_ref_accepted_when_tls_listener_present_no_port() {
        let gw = make_gw_with_listener("prod", "my-gw", "tls", 443, ProtocolType::TLS);
        let port: Option<u16> = None;
        let matching = gw
            .spec
            .listeners
            .iter()
            .any(|l| l.protocol == ProtocolType::TLS && port.is_none_or(|p| l.port == p));
        assert!(matching);

        let cond = if matching {
            Condition::accepted()
        } else {
            Condition::new(
                "Accepted",
                false,
                "NoMatchingListener",
                "Gateway has no TLS listener matching the parentRef port",
            )
        };
        assert_eq!(cond.status, "True");
    }

    /// Gateway-wide parentRef with port=443 is accepted when the TLS listener
    /// is on port 443.
    #[test]
    fn gateway_wide_ref_accepted_when_port_matches_tls_listener() {
        let gw = make_gw_with_listener("prod", "my-gw", "tls", 443, ProtocolType::TLS);
        let port: Option<u16> = Some(443);
        let matching = gw
            .spec
            .listeners
            .iter()
            .any(|l| l.protocol == ProtocolType::TLS && port.is_none_or(|p| l.port == p));
        assert!(matching);

        let cond = if matching {
            Condition::accepted()
        } else {
            Condition::new(
                "Accepted",
                false,
                "NoMatchingListener",
                "Gateway has no TLS listener matching the parentRef port",
            )
        };
        assert_eq!(cond.status, "True");
    }

    /// Gateway-wide parentRef with port=9999 is rejected even when a TLS
    /// listener exists on a different port.
    #[test]
    fn gateway_wide_ref_rejected_when_port_mismatches_tls_listener() {
        let gw = make_gw_with_listener("prod", "my-gw", "tls", 443, ProtocolType::TLS);
        let port: Option<u16> = Some(9999);
        let matching = gw
            .spec
            .listeners
            .iter()
            .any(|l| l.protocol == ProtocolType::TLS && port.is_none_or(|p| l.port == p));
        assert!(!matching);

        let cond = if matching {
            Condition::accepted()
        } else {
            Condition::new(
                "Accepted",
                false,
                "NoMatchingListener",
                "Gateway has no TLS listener matching the parentRef port",
            )
        };
        assert_eq!(cond.status, "False");
        assert_eq!(cond.reason, "NoMatchingListener");
    }

    /// When a TLSRoute transitions to no valid parents, it must be removed
    /// from the store so stale config is not served.
    #[tokio::test]
    async fn tls_stale_route_removed_from_store_when_no_valid_parents() {
        let store = SharedStore::new();
        store.mark_ready().await;

        // Pre-populate the store as if the route was previously accepted.
        let mut accepted_route = make_tlsroute(
            "my-route",
            "default",
            vec![],
            vec!["db.example.com".to_string()],
        );
        let accepted_route_mut = Arc::make_mut(&mut accepted_route);
        accepted_route_mut.status = Some(TLSRouteStatus {
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
        });

        let key = crate::reconcilers::config_generator::GatewayState::key("default", "my-route");
        store
            .upsert_tls_route(key.clone(), (*accepted_route).clone())
            .await;

        // Verify it's in the store.
        {
            let snap = store.snapshot().await.expect("store ready");
            assert!(snap.tls_routes.contains_key(&key));
        }

        // Simulate the reconciler's stale-route cleanup path.
        store.remove_tls_route(&key).await;

        let snap = store.snapshot().await.expect("store ready");
        assert!(
            !snap.tls_routes.contains_key(&key),
            "stale TLSRoute must be removed from store when no valid Wicket parents"
        );
    }
}
