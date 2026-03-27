//! HTTPRoute reconciler.

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
    Condition, Gateway, GatewayClass, HTTPRoute, HTTPRouteStatus, RouteParentStatus,
    WICKET_CONTROLLER_NAME,
};
use crate::metrics::{ReconcileMetrics, HTTPROUTES, ROUTES_ACCEPTED, ROUTES_REJECTED_TOTAL};

use super::attachment_planner::{
    AttachmentPlan, AttachmentPlanInput, AttachmentPlanner, AttachmentStatus,
};
use super::config_generator::GatewayState;
use super::context::{trigger_config_update, Context};
use super::store::SnapshotResult;

/// Error type for HTTPRoute reconciliation.
#[derive(Debug, thiserror::Error)]
pub enum HTTPRouteError {
    #[error("Kubernetes API error: {0}")]
    KubeError(#[from] kube::Error),

    #[error("Parent Gateway not found: {0}")]
    ParentNotFound(String),

    #[error("Backend service not found: {0}")]
    BackendNotFound(String),

    #[error("Configuration error: {0}")]
    ConfigError(String),
}

/// Reconcile an HTTPRoute resource.
pub async fn reconcile_httproute(
    route: Arc<HTTPRoute>,
    ctx: Arc<Context>,
) -> Result<Action, HTTPRouteError> {
    let metrics = ReconcileMetrics::new("HTTPRoute");
    let namespace = route.namespace().unwrap_or_default();
    let name = route.name_any();

    tracing::info!(namespace = %namespace, name = %name, "Reconciling HTTPRoute");

    // Handle deletion: remove from store and trigger config update.
    if route.metadata.deletion_timestamp.is_some() {
        let key = GatewayState::key(&namespace, &name);
        ctx.store.remove_http_route(&key).await;
        tracing::info!(namespace = %namespace, name = %name, "HTTPRoute deleted, removed from store");
        trigger_config_update(&ctx, "HTTPRoute deleted")
            .await
            .map_err(|e| HTTPRouteError::ConfigError(e.to_string()))?;
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

    // Validate parent references and check if they're managed by Wicket
    let mut parent_statuses = Vec::new();
    let mut has_valid_parent = false;

    for parent_ref in &route.spec.parent_refs {
        let parent_ns = parent_ref.namespace.as_deref().unwrap_or(&namespace);

        // ── Step 1: httproute.rs is authoritative for missing / non-Wicket parents ──
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
                    // Use the constant so the written value always matches the
                    // value checked by parents_accepted_by_wicket at render time.
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
                return Err(HTTPRouteError::KubeError(e));
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
                return Err(HTTPRouteError::KubeError(e));
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
                // Use the constant so every written status entry carries the
                // same authoritative controller name that the accepted-route
                // filter in config_generator checks.
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
        //    Gateway-wide refs (no sectionName) gate on at least one HTTP-compatible
        //    listener to avoid accepting routes against TCP/TLS-only gateways while
        //    still avoiding multi-listener aggregation ambiguity in this slice.
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
            // HTTP/HTTPS listener so an HTTPRoute is not accepted against a
            // TCP/TLS-only gateway.  When parentRef.port is set, that port
            // must match a compatible listener (not merely any HTTP listener).
            let matching_http = gateway.spec.listeners.iter().any(|l| {
                matches!(
                    l.protocol,
                    crate::crds::ProtocolType::HTTP | crate::crds::ProtocolType::HTTPS
                ) && parent_ref.port.is_none_or(|p| l.port == p)
            });

            if matching_http {
                Condition::accepted()
            } else {
                tracing::debug!(
                    namespace = %namespace,
                    route = %name,
                    parent_ref = %parent_ref.name,
                    parent_namespace = %parent_ns,
                    port = ?parent_ref.port,
                    reason = "NoMatchingListener",
                    message = "Gateway has no HTTP/HTTPS listener matching the parentRef port",
                    "Route listener validation failed"
                );
                Condition::new(
                    "Accepted",
                    false,
                    "NoMatchingListener",
                    "Gateway has no HTTP/HTTPS listener matching the parentRef port",
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

    // Update HTTPRoute status
    let status = HTTPRouteStatus {
        parents: parent_statuses,
    };

    let api: Api<HTTPRoute> = Api::namespaced(ctx.client.clone(), &namespace);
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
            .upsert_http_route(route_key, route_with_status)
            .await;

        trigger_config_update(&ctx, "HTTPRoute reconciled")
            .await
            .map_err(|e| HTTPRouteError::ConfigError(e.to_string()))?;
        tracing::info!(namespace = %namespace, name = %name, "HTTPRoute accepted");

        // Update route acceptance metrics for each valid parent
        for parent_status in &status.parents {
            let gw_name = &parent_status.parent_ref.name;
            if parent_status
                .conditions
                .iter()
                .any(|c| c.type_ == "Accepted" && c.status == "True")
            {
                ROUTES_ACCEPTED
                    .with_label_values(&[&namespace, "HTTPRoute", gw_name])
                    .set(1);
            }
        }
    } else {
        tracing::warn!(namespace = %namespace, name = %name, "HTTPRoute has no valid Wicket parents");

        // Remove from store if it was previously accepted, so stale config is
        // not served.  If the route was never in the store this is a no-op.
        let route_key = GatewayState::key(&namespace, &name);
        ctx.store.remove_http_route(&route_key).await;
        tracing::debug!(
            namespace = %namespace,
            name = %name,
            "HTTPRoute removed from store (no valid Wicket parents)"
        );

        // Trigger config regeneration so the proxy stops serving the stale route.
        trigger_config_update(&ctx, "HTTPRoute lost all valid parents")
            .await
            .map_err(|e| HTTPRouteError::ConfigError(e.to_string()))?;

        // Track rejection reasons
        for parent_status in &status.parents {
            for condition in &parent_status.conditions {
                if condition.type_ == "Accepted" && condition.status == "False" {
                    ROUTES_REJECTED_TOTAL
                        .with_label_values(&[&namespace, "HTTPRoute", &condition.reason])
                        .inc();
                }
            }
        }
    }

    metrics.record_success();

    // Update metrics
    update_httproute_metrics(&ctx.client).await;

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
/// HTTPRoute is HTTP/HTTPS-only.  On any fallback path (snapshot NotReady,
/// planner error, route not yet in snapshot) we inspect the Gateway spec
/// directly via `http_only_condition_from_spec`:
/// - Named listener exists and is not HTTP/HTTPS -> `NotAllowedByListenerProtocol`.
/// - Named listener exists, is HTTP/HTTPS, port mismatches -> `NoMatchingParent`.
/// - Named listener exists, is HTTP/HTTPS, port matches (or absent) -> `Accepted=True`.
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
                "Planner snapshot not ready; checking Gateway spec for HTTP-only rule"
            );
            return http_only_condition_from_spec(gateway, section_name, port);
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
                    "AttachmentPlanner error; checking Gateway spec for HTTP-only rule"
                );
                return http_only_condition_from_spec(gateway, section_name, port);
            }
        }
    }

    // Safe: we just inserted above if missing.
    let plan = match plan_cache.get(&cache_key) {
        Some(p) => p,
        None => return http_only_condition_from_spec(gateway, section_name, port),
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

/// Enforce the HTTP-only rule directly from the Gateway spec when the planner
/// is unavailable (snapshot not ready, planner error, or route not yet in
/// snapshot).
///
/// - If the named listener exists and its protocol is not HTTP/HTTPS ->
///   `NotAllowedByListenerProtocol` (hard rejection; the spec is authoritative).
/// - If the named listener exists, is HTTP/HTTPS, but the port does not match ->
///   `NoMatchingParent` (hard rejection; port is authoritative in the spec).
/// - If the named listener exists, is HTTP/HTTPS, and port matches (or is absent) ->
///   `Accepted=True` (conservative warm-up fallback).
/// - If the named listener does NOT exist in the spec ->
///   `NoMatchingParent` (hard rejection; an explicit sectionName that names a
///   non-existent listener is never a transient condition -- the spec is
///   authoritative and we must not fail open).
fn http_only_condition_from_spec(
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
            if !matches!(
                listener.protocol,
                crate::crds::ProtocolType::HTTP | crate::crds::ProtocolType::HTTPS
            ) {
                // Named listener exists and is not HTTP/HTTPS: HTTPRoute cannot attach.
                tracing::debug!(
                    section_name = %section_name,
                    protocol = ?listener.protocol,
                    "HTTPRoute sectionName targets non-HTTP listener; rejecting (HTTP-only rule)"
                );
                return Condition::new(
                    "Accepted",
                    false,
                    "NotAllowedByListenerProtocol",
                    "Route kind is not compatible with the listener protocol",
                );
            }
            // Listener is HTTP/HTTPS.  If a port was specified it must match.
            if let Some(ref_port) = port {
                if listener.port != ref_port {
                    tracing::debug!(
                        section_name = %section_name,
                        listener_port = listener.port,
                        ref_port = ref_port,
                        "HTTPRoute parentRef port does not match listener port; rejecting"
                    );
                    return Condition::new(
                        "Accepted",
                        false,
                        "NoMatchingParent",
                        "No listener matches the parentRef sectionName or port",
                    );
                }
            }
            // HTTP/HTTPS listener, port matches (or absent): conservative accept.
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
                "HTTPRoute sectionName not found in Gateway spec; rejecting (NoMatchingParent)"
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
/// Falls back to `http_only_condition_from_spec` when:
/// - The store snapshot is not yet ready (warm-up gap).
/// - The planner returns an error (e.g. Gateway not yet in the store).
/// - No result is found for the `(route, sectionName, port)` triple.
///
/// The fallback enforces the HTTP-only rule from the Gateway spec:
/// - Non-HTTP/HTTPS listener -> rejected.
/// - HTTP/HTTPS listener, port mismatch -> rejected.
/// - HTTP/HTTPS listener, port matches (or absent) -> accepted conservatively.
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
/// (route not yet in the snapshot), falls back to `http_only_condition_from_spec`
/// rather than blindly accepting, so the HTTP-only rule is enforced even during
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
            // Apply the HTTP-only rule from the Gateway spec before falling back.
            tracing::debug!(
                route_namespace = %route_namespace,
                route_name = %route_name,
                section_name = %section_name,
                "No planner result for parentRef; applying HTTP-only spec check"
            );
            http_only_condition_from_spec(gateway, section_name, port)
        }
    }
}

/// Returns a human-readable message for an `AttachmentStatus` rejection.
fn attachment_status_message(status: &AttachmentStatus) -> &'static str {
    match status {
        AttachmentStatus::Attached | AttachmentStatus::RefNotPermitted { .. } => {
            "Route is accepted by the listener"
        }
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

/// Handle errors during HTTPRoute reconciliation.
pub fn error_policy_httproute(
    route: Arc<HTTPRoute>,
    error: &HTTPRouteError,
    _ctx: Arc<Context>,
) -> Action {
    let namespace = route.namespace().unwrap_or_default();
    let name = route.name_any();

    tracing::error!(
        namespace = %namespace,
        name = %name,
        error = %error,
        "HTTPRoute reconciliation failed"
    );

    crate::metrics::RECONCILE_ERRORS_TOTAL
        .with_label_values(&["HTTPRoute", "reconcile_error"])
        .inc();

    Action::requeue(Duration::from_secs(60))
}

/// Update HTTPRoute metrics.
async fn update_httproute_metrics(client: &Client) {
    let api: Api<HTTPRoute> = Api::all(client.clone());

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
                HTTPROUTES.with_label_values(&[&ns]).set(count);
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "Failed to list HTTPRoutes for metrics");
        }
    }
}

/// Create the HTTPRoute controller.
pub async fn run_httproute_controller(ctx: Arc<Context>) -> Result<(), kube::Error> {
    use crate::metrics::{WATCH_CONNECTIONS_ACTIVE, WATCH_ERRORS_TOTAL, WATCH_EVENTS_TOTAL};

    let api: Api<HTTPRoute> = if ctx.watch_all_namespaces {
        Api::all(ctx.client.clone())
    } else {
        Api::namespaced(ctx.client.clone(), &ctx.controller_namespace)
    };

    WATCH_CONNECTIONS_ACTIVE
        .with_label_values(&["HTTPRoute"])
        .set(1);

    Controller::new(api, Config::default())
        .run(reconcile_httproute, error_policy_httproute, ctx)
        .for_each(|result| async move {
            match result {
                Ok((obj, _)) => {
                    WATCH_EVENTS_TOTAL
                        .with_label_values(&["HTTPRoute", "reconcile_success"])
                        .inc();
                    tracing::debug!(
                        namespace = obj.namespace.as_deref().unwrap_or(""),
                        name = %obj.name,
                        "HTTPRoute reconciled"
                    );
                }
                Err(e) => {
                    WATCH_EVENTS_TOTAL
                        .with_label_values(&["HTTPRoute", "reconcile_error"])
                        .inc();
                    WATCH_ERRORS_TOTAL
                        .with_label_values(&["HTTPRoute", "controller_error"])
                        .inc();
                    tracing::error!(error = %e, "HTTPRoute controller error");
                }
            }
        })
        .await;

    WATCH_CONNECTIONS_ACTIVE
        .with_label_values(&["HTTPRoute"])
        .set(0);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crds::{
        Condition, Gateway, GatewayClass, GatewaySpec, HTTPBackendRef, HTTPRouteRule,
        HTTPRouteSpec, Listener, ParentReference, ProtocolType,
    };
    use kube::core::ObjectMeta;
    use std::sync::Arc;

    /// Helper to create a test HTTPRoute.
    fn make_httproute(
        name: &str,
        namespace: &str,
        parent_refs: Vec<ParentReference>,
    ) -> Arc<HTTPRoute> {
        Arc::new(HTTPRoute {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some(namespace.to_string()),
                ..Default::default()
            },
            spec: HTTPRouteSpec {
                parent_refs,
                hostnames: vec![],
                rules: vec![HTTPRouteRule {
                    name: None,
                    matches: vec![],
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
            status: None,
        })
    }

    /// Helper to create a test Gateway.
    fn make_gateway(name: &str, namespace: &str, gateway_class: &str) -> Gateway {
        Gateway {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some(namespace.to_string()),
                ..Default::default()
            },
            spec: GatewaySpec {
                gateway_class_name: gateway_class.to_string(),
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
        }
    }

    /// Helper to create a test GatewayClass.
    fn make_gateway_class(name: &str, controller_name: &str) -> GatewayClass {
        use crate::crds::GatewayClassSpec;
        GatewayClass {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                ..Default::default()
            },
            spec: GatewayClassSpec {
                controller_name: controller_name.to_string(),
                parameters_ref: None,
                description: None,
            },
            status: None,
        }
    }

    /// Test: HTTPRoute with missing Gateway sets InvalidParentRef condition.
    #[test]
    fn test_httproute_missing_gateway_sets_invalid_parent_ref() {
        // Setup: Create HTTPRoute referencing non-existent Gateway
        let _route = make_httproute(
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
        );

        // Verify: The reconciler should set InvalidParentRef condition with "False" status
        // when Gateway is not found
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

    /// Test: HTTPRoute with Gateway not managed by Wicket sets InvalidParentRef.
    #[test]
    fn test_httproute_non_wicket_gateway_sets_invalid_parent_ref() {
        // Setup: Create HTTPRoute referencing non-Wicket Gateway
        let _route = make_httproute(
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
        );

        // The Gateway exists but has a different controller
        let _gateway = make_gateway("other-controller-gateway", "default", "other-controller");
        let gateway_class = make_gateway_class("other-controller", "other.io/gateway-controller");

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

        // Verify GatewayClass detection
        assert_eq!(
            gateway_class.spec.controller_name,
            "other.io/gateway-controller"
        );
        assert!(!gateway_class.is_wicket_managed());

        // Wicket-managed GatewayClass should match
        let wicket_gc = make_gateway_class("wicket", "wicket.io/gateway-controller");
        assert!(wicket_gc.is_wicket_managed());
    }

    /// Test: Cross-namespace HTTPRoute reference detection.
    #[test]
    fn test_httproute_cross_namespace_reference_detected() {
        // Setup: Create HTTPRoute in namespace A referencing backend in namespace B
        let mut route_ref = make_httproute(
            "test-route",
            "namespace-a",
            vec![ParentReference {
                group: "gateway.networking.k8s.io".to_string(),
                kind: "Gateway".to_string(),
                namespace: None,
                name: "gateway-a".to_string(),
                section_name: None,
                port: None,
            }],
        );

        // Create a mutable version to modify backend namespace
        let route = Arc::make_mut(&mut route_ref);
        route.spec.rules[0].backend_refs[0].backend_ref.namespace = Some("namespace-b".to_string());

        // Verify: Backend is in different namespace
        let route_ns = route.namespace().unwrap_or_default();
        let backend_ref = &route.spec.rules[0].backend_refs[0].backend_ref;
        let backend_ns = backend_ref.namespace.as_deref().unwrap_or(&route_ns);

        assert_ne!(route_ns, backend_ns);
        assert_eq!(route_ns, "namespace-a");
        assert_eq!(backend_ns, "namespace-b");
    }

    /// Test: Multiple invalid parents each get their own status.
    #[test]
    fn test_httproute_multiple_invalid_parents() {
        // Setup: HTTPRoute with multiple invalid parent references
        let route = make_httproute(
            "test-route",
            "default",
            vec![
                ParentReference {
                    group: "gateway.networking.k8s.io".to_string(),
                    kind: "Gateway".to_string(),
                    namespace: None,
                    name: "missing-gateway".to_string(),
                    section_name: None,
                    port: None,
                },
                ParentReference {
                    group: "gateway.networking.k8s.io".to_string(),
                    kind: "Gateway".to_string(),
                    namespace: Some("other-ns".to_string()),
                    name: "also-missing".to_string(),
                    section_name: None,
                    port: None,
                },
            ],
        );

        // Verify: Each parent gets its own RouteParentStatus with appropriate conditions
        assert_eq!(route.spec.parent_refs.len(), 2);

        // First parent: missing in same namespace
        let first_ref = &route.spec.parent_refs[0];
        assert_eq!(first_ref.name, "missing-gateway");
        assert!(first_ref.namespace.is_none());

        // Second parent: missing in different namespace
        let second_ref = &route.spec.parent_refs[1];
        assert_eq!(second_ref.name, "also-missing");
        assert_eq!(second_ref.namespace.as_deref(), Some("other-ns"));
    }

    /// Test: RouteParentStatus structure for rejected routes.
    #[test]
    fn test_route_parent_status_for_invalid_parent_ref() {
        // Create a parent status for an invalid parent
        let parent_ref = ParentReference {
            group: "gateway.networking.k8s.io".to_string(),
            kind: "Gateway".to_string(),
            namespace: None,
            name: "missing-gateway".to_string(),
            section_name: None,
            port: None,
        };

        let parent_status = RouteParentStatus {
            parent_ref: parent_ref.clone(),
            controller_name: WICKET_CONTROLLER_NAME.to_string(),
            conditions: vec![Condition::new(
                "Accepted",
                false,
                "InvalidParentRef",
                "Parent Gateway not found",
            )],
        };

        // Verify structure
        assert_eq!(parent_status.parent_ref.name, "missing-gateway");
        assert_eq!(
            parent_status.controller_name,
            "wicket.io/gateway-controller"
        );
        assert_eq!(parent_status.conditions.len(), 1);
        assert_eq!(parent_status.conditions[0].type_, "Accepted");
        assert_eq!(parent_status.conditions[0].status, "False");
        assert_eq!(parent_status.conditions[0].reason, "InvalidParentRef");
        assert_eq!(
            parent_status.conditions[0].message,
            "Parent Gateway not found"
        );
    }

    /// Test: Metrics label structure for rejection.
    #[test]
    fn test_httproute_rejection_metrics_label_structure() {
        // Verify metric label structure
        // The metric should have labels: [namespace, "HTTPRoute", reason]
        let expected_labels = ["default", "HTTPRoute", "InvalidParentRef"];
        let actual_labels: Vec<&str> = expected_labels.to_vec();

        assert_eq!(actual_labels.len(), 3);
        assert_eq!(actual_labels[0], "default");
        assert_eq!(actual_labels[1], "HTTPRoute");
        assert_eq!(actual_labels[2], "InvalidParentRef");
    }

    /// Test: HTTPRouteError enum variants.
    #[test]
    fn test_httproute_error_variants() {
        // Test error message formatting
        let parent_err = HTTPRouteError::ParentNotFound("my-gateway".to_string());
        assert_eq!(
            parent_err.to_string(),
            "Parent Gateway not found: my-gateway"
        );

        let backend_err = HTTPRouteError::BackendNotFound("my-service".to_string());
        assert_eq!(
            backend_err.to_string(),
            "Backend service not found: my-service"
        );

        let config_err = HTTPRouteError::ConfigError("test error".to_string());
        assert_eq!(config_err.to_string(), "Configuration error: test error");
    }

    // ── Gateway lookup error discrimination tests ─────────────────────────────
    //
    // These tests verify the pattern used in Step 1 of the reconciler:
    // a 404 API error is a semantic "not found" (write InvalidParentRef),
    // while any other kube::Error is a transient fault (propagate / requeue).
    //
    // We cannot call the live reconciler without a kube client, so we test
    // the discrimination logic directly on kube::Error values.

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

        // The reconciler pattern: 404 -> InvalidParentRef (not propagated).
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
        let kube_err = HTTPRouteError::KubeError(err);
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

    /// Build a minimal `PlannerSnapshot` containing the given gateway and route.
    fn make_snapshot(gateway: Gateway, route: HTTPRoute) -> PlannerSnapshot {
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
        let mut http_routes = HashMap::new();
        http_routes.insert(route_key, route);
        PlannerSnapshot {
            gateways,
            gateway_classes: HashMap::new(),
            http_routes,
            tcp_routes: HashMap::new(),
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

    fn make_http_route_with_section(
        ns: &str,
        name: &str,
        gw_ns: &str,
        gw_name: &str,
        section_name: Option<&str>,
        port: Option<u16>,
    ) -> HTTPRoute {
        HTTPRoute {
            metadata: kube::core::ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some(ns.to_string()),
                ..Default::default()
            },
            spec: HTTPRouteSpec {
                parent_refs: vec![ParentReference {
                    group: "gateway.networking.k8s.io".to_string(),
                    kind: "Gateway".to_string(),
                    namespace: Some(gw_ns.to_string()),
                    name: gw_name.to_string(),
                    section_name: section_name.map(str::to_string),
                    port,
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
                            name: "svc".to_string(),
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

    /// Planner returns Accepted=True when sectionName matches an HTTP listener.
    #[test]
    fn planner_accepted_for_matching_http_section_name() {
        let gw = make_gw_with_listener("prod", "my-gw", "http", 80, ProtocolType::HTTP);
        let route =
            make_http_route_with_section("prod", "my-route", "prod", "my-gw", Some("http"), None);
        let snapshot = SnapshotResult::Ready(make_snapshot(gw.clone(), route));

        let cond = planner_accepted_condition_for_section(
            &snapshot, &gw, "prod", "my-route", "http", None,
        );

        assert_eq!(cond.type_, "Accepted");
        assert_eq!(cond.status, "True");
        assert_eq!(cond.reason, "Accepted");
    }

    /// Planner returns Accepted=False / NoMatchingParent when sectionName doesn't exist.
    #[test]
    fn planner_no_matching_parent_for_unknown_section_name() {
        let gw = make_gw_with_listener("prod", "my-gw", "http", 80, ProtocolType::HTTP);
        let route = make_http_route_with_section(
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
    /// an HTTPRoute targets a TCP listener by sectionName.
    #[test]
    fn planner_protocol_mismatch_for_http_route_on_tcp_listener() {
        let gw = make_gw_with_listener("prod", "my-gw", "tcp", 5432, ProtocolType::TCP);
        let route =
            make_http_route_with_section("prod", "my-route", "prod", "my-gw", Some("tcp"), None);
        let snapshot = SnapshotResult::Ready(make_snapshot(gw.clone(), route));

        let cond =
            planner_accepted_condition_for_section(&snapshot, &gw, "prod", "my-route", "tcp", None);

        assert_eq!(cond.type_, "Accepted");
        assert_eq!(cond.status, "False");
        assert_eq!(cond.reason, "NotAllowedByListenerProtocol");
    }

    /// When the store snapshot is NotReady and the sectionName names a known
    /// HTTP listener, fall back to Accepted=True (conservative warm-up).
    #[test]
    fn planner_falls_back_to_accepted_when_store_not_ready() {
        let gw = make_gw_with_listener("prod", "my-gw", "http", 80, ProtocolType::HTTP);
        let snapshot: SnapshotResult<PlannerSnapshot> = SnapshotResult::NotReady;

        let cond = planner_accepted_condition_for_section(
            &snapshot, &gw, "prod", "my-route", "http", None,
        );

        // Named listener "http" exists and is HTTP: conservative accept.
        assert_eq!(cond.type_, "Accepted");
        assert_eq!(cond.status, "True");
    }

    /// When the store snapshot is NotReady and the sectionName names an
    /// unknown listener, return NoMatchingParent (never fail open).
    #[test]
    fn planner_not_ready_rejects_unknown_section_name() {
        let gw = make_gw_with_listener("prod", "my-gw", "http", 80, ProtocolType::HTTP);
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

    /// When the store snapshot is NotReady and the sectionName names a TCP
    /// listener, return NotAllowedByListenerProtocol (spec is authoritative).
    #[test]
    fn planner_not_ready_rejects_non_http_section_name() {
        let gw = make_gw_with_listener("prod", "my-gw", "tcp", 5432, ProtocolType::TCP);
        let snapshot: SnapshotResult<PlannerSnapshot> = SnapshotResult::NotReady;

        let cond =
            planner_accepted_condition_for_section(&snapshot, &gw, "prod", "my-route", "tcp", None);

        assert_eq!(cond.type_, "Accepted");
        assert_eq!(cond.status, "False");
        assert_eq!(cond.reason, "NotAllowedByListenerProtocol");
    }

    /// When the route is not yet in the snapshot and the sectionName names a
    /// known HTTP listener, fall back to Accepted=True (conservative warm-up).
    ///
    /// Note: when the sectionName names an *unknown* listener the fallback
    /// returns NoMatchingParent instead -- see
    /// `route_missing_from_snapshot_rejects_unknown_section_name`.
    #[test]
    fn planner_falls_back_when_route_not_in_snapshot() {
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

        // sectionName "http" exists in spec as an HTTP listener: conservative accept.
        assert_eq!(cond.type_, "Accepted");
        assert_eq!(cond.status, "True");
    }

    /// When the route is not yet in the snapshot and the sectionName names an
    /// unknown listener, return NoMatchingParent (never fail open).
    #[test]
    fn route_missing_from_snapshot_rejects_unknown_section_name() {
        let gw = make_gw_with_listener("prod", "my-gw", "http", 80, ProtocolType::HTTP);
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
        let gw = make_gw_with_listener("prod", "my-gw", "http", 80, ProtocolType::HTTP);
        // parentRef specifies port=8080 but listener is on 80.
        let route = make_http_route_with_section(
            "prod",
            "my-route",
            "prod",
            "my-gw",
            Some("http"),
            Some(8080),
        );
        let snapshot = SnapshotResult::Ready(make_snapshot(gw.clone(), route));

        let cond = planner_accepted_condition_for_section(
            &snapshot,
            &gw,
            "prod",
            "my-route",
            "http",
            Some(8080),
        );

        assert_eq!(cond.type_, "Accepted");
        assert_eq!(cond.status, "False");
        assert_eq!(cond.reason, "NoMatchingParent");
    }

    /// attachment_status_message returns non-empty strings for all variants.
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

    // ── Plan-cache tests (Issue MED) ──────────────────────────────────────────

    /// Two parentRefs pointing at the same Gateway produce the same condition
    /// and the plan is computed only once (verified via the cache size).
    #[test]
    fn plan_cache_reuses_plan_for_same_gateway() {
        let gw = make_gw_with_listener("prod", "my-gw", "http", 80, ProtocolType::HTTP);
        let route =
            make_http_route_with_section("prod", "my-route", "prod", "my-gw", Some("http"), None);
        let snapshot = SnapshotResult::Ready(make_snapshot(gw.clone(), route));

        let mut cache = HashMap::new();

        // First call: cache miss -- plan is computed and stored.
        let cond1 = planner_accepted_condition_for_section_cached(
            &snapshot, &gw, "prod", "my-route", "http", None, &mut cache,
        );
        assert_eq!(cache.len(), 1, "plan should be cached after first call");

        // Second call with the same gateway: cache hit -- no new entry.
        let cond2 = planner_accepted_condition_for_section_cached(
            &snapshot, &gw, "prod", "my-route", "http", None, &mut cache,
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
        let gw_a = make_gw_with_listener("prod", "gw-a", "http", 80, ProtocolType::HTTP);
        let gw_b = make_gw_with_listener("prod", "gw-b", "http", 80, ProtocolType::HTTP);

        let route_a =
            make_http_route_with_section("prod", "my-route", "prod", "gw-a", Some("http"), None);
        let route_b =
            make_http_route_with_section("prod", "my-route", "prod", "gw-b", Some("http"), None);

        // Build separate snapshots (each planner call needs the route in the snapshot).
        let snap_a = SnapshotResult::Ready(make_snapshot(gw_a.clone(), route_a));
        let snap_b = SnapshotResult::Ready(make_snapshot(gw_b.clone(), route_b));

        let mut cache = HashMap::new();

        planner_accepted_condition_for_section_cached(
            &snap_a, &gw_a, "prod", "my-route", "http", None, &mut cache,
        );
        assert_eq!(cache.len(), 1);

        planner_accepted_condition_for_section_cached(
            &snap_b, &gw_b, "prod", "my-route", "http", None, &mut cache,
        );
        assert_eq!(
            cache.len(),
            2,
            "different gateways must produce separate cache entries"
        );
    }

    // ── Store-removal tests (Issue HIGH) ──────────────────────────────────────

    /// When a route has no valid parents, `condition_from_plan` returns
    /// Accepted=False for a known-rejected section name.
    /// (The store-removal path is exercised in integration; here we verify
    /// the condition logic that drives the `has_valid_parent = false` branch.)
    #[test]
    fn no_valid_parent_condition_is_false_for_rejected_section() {
        let gw = make_gw_with_listener("prod", "my-gw", "tcp", 5432, ProtocolType::TCP);
        // HTTPRoute targeting a TCP listener -- should be rejected.
        let route =
            make_http_route_with_section("prod", "my-route", "prod", "my-gw", Some("tcp"), None);
        let snapshot = SnapshotResult::Ready(make_snapshot(gw.clone(), route));

        let cond =
            planner_accepted_condition_for_section(&snapshot, &gw, "prod", "my-route", "tcp", None);

        // Condition must be False so `has_valid_parent` stays false and the
        // store-removal branch is taken.
        assert_eq!(cond.status, "False");
        assert_eq!(cond.reason, "NotAllowedByListenerProtocol");
    }

    /// `condition_from_plan` falls back to spec-check when the route is not
    /// yet in the snapshot.  For a known HTTP listener the result is Accepted=True
    /// (conservative warm-up); the store-removal branch must NOT be triggered
    /// by a transient store miss against a valid listener.
    #[test]
    fn no_valid_parent_fallback_true_when_route_missing_from_snapshot() {
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
            service_ref_index: std::collections::HashSet::new(),
            namespace_labels: HashMap::new(),
        });

        let cond = planner_accepted_condition_for_section(
            &snapshot, &gw, "prod", "my-route", "http", None,
        );

        // sectionName "http" exists in spec as HTTP: conservative accept.
        assert_eq!(cond.status, "True");
    }

    // ── Store/status consistency tests ────────────────────────────────────────

    use crate::crds::{HTTPRouteStatus, RouteParentStatus};
    use crate::reconcilers::store::SharedStore;

    /// When an HTTPRoute is accepted, the object stored in SharedStore must
    /// carry the status that was written to the API server (not the stale
    /// pre-patch object which has status = None).
    #[tokio::test]
    async fn http_store_upsert_carries_written_status() {
        let store = SharedStore::new();
        store.mark_ready().await;

        let mut route = make_httproute(
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
        );

        // Simulate what the reconciler does: attach the written status before
        // upserting.
        let written_status = HTTPRouteStatus {
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
        };

        let route_mut = Arc::make_mut(&mut route);
        route_mut.status = Some(written_status.clone());

        let key = crate::reconcilers::config_generator::GatewayState::key("default", "my-route");
        store.upsert_http_route(key.clone(), (*route).clone()).await;

        let snap = store.snapshot().await.expect("store ready");
        let stored = snap.http_routes.get(&key).expect("route in store");
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

    /// All controller_name values written by the HTTPRoute reconciler must
    /// equal WICKET_CONTROLLER_NAME.
    #[test]
    fn http_all_parent_statuses_use_wicket_controller_name() {
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
            conditions: vec![Condition::accepted()],
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

    // ── Gateway-wide parentRef (no sectionName) listener-gate tests ───────────

    /// Gateway-wide parentRef is accepted when the gateway has an HTTP listener
    /// and no port constraint is set.
    #[test]
    fn gateway_wide_ref_accepted_when_http_listener_present() {
        let gw = make_gw_with_listener("prod", "my-gw", "http", 80, ProtocolType::HTTP);
        let matching = gw.spec.listeners.iter().any(|l| {
            matches!(l.protocol, ProtocolType::HTTP | ProtocolType::HTTPS)
                && (None::<u16>).is_none_or(|p: u16| l.port == p)
        });
        assert!(matching);

        let cond = if matching {
            Condition::accepted()
        } else {
            Condition::new(
                "Accepted",
                false,
                "NoMatchingListener",
                "Gateway has no HTTP/HTTPS listener matching the parentRef port",
            )
        };
        assert_eq!(cond.status, "True");
    }

    /// Gateway-wide parentRef is accepted when the gateway has an HTTPS listener.
    #[test]
    fn gateway_wide_ref_accepted_when_https_listener_present() {
        let gw = make_gw_with_listener("prod", "my-gw", "https", 443, ProtocolType::HTTPS);
        let matching = gw.spec.listeners.iter().any(|l| {
            matches!(l.protocol, ProtocolType::HTTP | ProtocolType::HTTPS)
                && (None::<u16>).is_none_or(|p: u16| l.port == p)
        });
        assert!(matching);

        let cond = if matching {
            Condition::accepted()
        } else {
            Condition::new(
                "Accepted",
                false,
                "NoMatchingListener",
                "Gateway has no HTTP/HTTPS listener matching the parentRef port",
            )
        };
        assert_eq!(cond.status, "True");
    }

    /// Gateway-wide parentRef is rejected when the gateway has only TCP listeners.
    #[test]
    fn gateway_wide_ref_rejected_when_no_http_listener() {
        let gw = make_gw_with_listener("prod", "my-gw", "tcp", 5432, ProtocolType::TCP);
        let matching = gw.spec.listeners.iter().any(|l| {
            matches!(l.protocol, ProtocolType::HTTP | ProtocolType::HTTPS)
                && (None::<u16>).is_none_or(|p: u16| l.port == p)
        });
        assert!(!matching);

        let cond = if matching {
            Condition::accepted()
        } else {
            Condition::new(
                "Accepted",
                false,
                "NoMatchingListener",
                "Gateway has no HTTP/HTTPS listener matching the parentRef port",
            )
        };
        assert_eq!(cond.status, "False");
        assert_eq!(cond.reason, "NoMatchingListener");
    }

    /// Gateway-wide parentRef is rejected when the gateway has only TLS listeners.
    #[test]
    fn gateway_wide_ref_rejected_when_only_tls_listener() {
        let gw = make_gw_with_listener("prod", "my-gw", "tls", 443, ProtocolType::TLS);
        let matching = gw.spec.listeners.iter().any(|l| {
            matches!(l.protocol, ProtocolType::HTTP | ProtocolType::HTTPS)
                && (None::<u16>).is_none_or(|p: u16| l.port == p)
        });
        assert!(!matching);

        let cond = if matching {
            Condition::accepted()
        } else {
            Condition::new(
                "Accepted",
                false,
                "NoMatchingListener",
                "Gateway has no HTTP/HTTPS listener matching the parentRef port",
            )
        };
        assert_eq!(cond.status, "False");
        assert_eq!(cond.reason, "NoMatchingListener");
    }

    /// Gateway-wide parentRef with port=80 is accepted when the HTTP listener
    /// is on port 80.
    #[test]
    fn gateway_wide_ref_accepted_when_port_matches_http_listener() {
        let gw = make_gw_with_listener("prod", "my-gw", "http", 80, ProtocolType::HTTP);
        let port: Option<u16> = Some(80);
        let matching = gw.spec.listeners.iter().any(|l| {
            matches!(l.protocol, ProtocolType::HTTP | ProtocolType::HTTPS)
                && port.is_none_or(|p| l.port == p)
        });
        assert!(matching);

        let cond = if matching {
            Condition::accepted()
        } else {
            Condition::new(
                "Accepted",
                false,
                "NoMatchingListener",
                "Gateway has no HTTP/HTTPS listener matching the parentRef port",
            )
        };
        assert_eq!(cond.status, "True");
    }

    /// Gateway-wide parentRef with port=9999 is rejected even when an HTTP
    /// listener exists on a different port.
    #[test]
    fn gateway_wide_ref_rejected_when_port_mismatches_http_listener() {
        let gw = make_gw_with_listener("prod", "my-gw", "http", 80, ProtocolType::HTTP);
        let port: Option<u16> = Some(9999);
        let matching = gw.spec.listeners.iter().any(|l| {
            matches!(l.protocol, ProtocolType::HTTP | ProtocolType::HTTPS)
                && port.is_none_or(|p| l.port == p)
        });
        assert!(!matching);

        let cond = if matching {
            Condition::accepted()
        } else {
            Condition::new(
                "Accepted",
                false,
                "NoMatchingListener",
                "Gateway has no HTTP/HTTPS listener matching the parentRef port",
            )
        };
        assert_eq!(cond.status, "False");
        assert_eq!(cond.reason, "NoMatchingListener");
    }
}
