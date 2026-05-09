//! Service and EndpointSlice watcher for dynamic load balancing updates.

use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use k8s_openapi::api::core::v1::Service;
use k8s_openapi::api::discovery::v1::EndpointSlice;
use kube::{
    api::Api,
    runtime::{
        controller::{Action, Controller},
        watcher::Config,
    },
    Client, ResourceExt,
};

use crate::crds::{HTTPRoute, TCPRoute, TLSRoute};
use crate::metrics::{
    ReconcileMetrics, BACKENDS, BACKEND_ENDPOINTS_HEALTHY, BACKEND_ENDPOINTS_UNHEALTHY,
};

use super::config_generator::{GatewayState, ServiceEndpoints};
use super::context::Context;
use super::store::ResourceClass;

/// Error type for Service/Endpoints reconciliation.
#[derive(Debug, thiserror::Error)]
pub enum ServiceError {
    #[error("Kubernetes API error: {0}")]
    KubeError(#[from] kube::Error),

    #[error("Configuration error: {0}")]
    ConfigError(String),
}

/// Reconcile an EndpointSlice resource.
///
/// This is triggered when EndpointSlice changes (pods scale up/down, health changes).
/// Each EndpointSlice is labelled with `kubernetes.io/service-name` to identify its
/// parent Service.  Multiple slices may exist per Service; we aggregate them all.
pub async fn reconcile_endpoint_slice(
    slice: Arc<EndpointSlice>,
    ctx: Arc<Context>,
) -> Result<Action, ServiceError> {
    let metrics = ReconcileMetrics::new("EndpointSlice");
    let namespace = slice.namespace().unwrap_or_default();

    // EndpointSlices carry the owning Service name in a well-known label.
    let service_name = slice
        .labels()
        .get("kubernetes.io/service-name")
        .cloned()
        .unwrap_or_default();

    if service_name.is_empty() {
        tracing::trace!(
            namespace = %namespace,
            slice = %slice.name_any(),
            "EndpointSlice has no service-name label, skipping"
        );
        metrics.record_success();
        return Ok(Action::await_change());
    }

    tracing::debug!(
        namespace = %namespace,
        service = %service_name,
        slice = %slice.name_any(),
        "Reconciling EndpointSlice"
    );

    // Check if this service is referenced by any route
    let is_referenced = is_service_referenced(&ctx, &namespace, &service_name).await;

    if !is_referenced {
        tracing::trace!(
            namespace = %namespace,
            name = %service_name,
            "Service not referenced by any route, skipping"
        );
        metrics.record_success();
        return Ok(Action::await_change());
    }

    // Aggregate all slices for this service to get the full picture.
    let slice_api: Api<EndpointSlice> = Api::namespaced(ctx.client.clone(), &namespace);
    let slices = slice_api
        .list(
            &kube::api::ListParams::default()
                .labels(&format!("kubernetes.io/service-name={}", service_name)),
        )
        .await?;

    let mut healthy_count: i64 = 0;
    let mut unhealthy_count: i64 = 0;
    let mut endpoint_addrs = Vec::new();

    for s in &slices.items {
        // Collect ports from the slice-level ports array.
        let ports: Vec<i32> = s
            .ports
            .as_ref()
            .map(|pp| pp.iter().filter_map(|p| p.port).collect())
            .unwrap_or_default();

        for ep in &s.endpoints {
            let ready = ep.conditions.as_ref().and_then(|c| c.ready).unwrap_or(true);

            if ready {
                for addr in &ep.addresses {
                    if ports.is_empty() {
                        endpoint_addrs.push(addr.clone());
                        healthy_count += 1;
                    } else {
                        for port in &ports {
                            endpoint_addrs.push(format!("{}:{}", addr, port));
                            healthy_count += 1;
                        }
                    }
                }
            } else {
                unhealthy_count += ep.addresses.len() as i64;
            }
        }
    }

    // Update metrics
    BACKEND_ENDPOINTS_HEALTHY
        .with_label_values(&[&namespace, &service_name])
        .set(healthy_count);
    BACKEND_ENDPOINTS_UNHEALTHY
        .with_label_values(&[&namespace, &service_name])
        .set(unhealthy_count);

    tracing::info!(
        namespace = %namespace,
        name = %service_name,
        healthy = healthy_count,
        unhealthy = unhealthy_count,
        endpoints = ?endpoint_addrs,
        "Service endpoints updated (via EndpointSlice)"
    );

    // Update the shared store.
    // When endpoints are empty (scale-to-zero), remove the stale entry so
    // config generation does not keep routing to non-existent backends.
    let key = GatewayState::key(&namespace, &service_name);
    if !endpoint_addrs.is_empty() {
        ctx.store
            .upsert_endpoints(
                key,
                ServiceEndpoints {
                    namespace: namespace.clone(),
                    name: service_name.clone(),
                    endpoints: endpoint_addrs,
                },
            )
            .await;
    } else {
        tracing::info!(
            namespace = %namespace,
            name = %service_name,
            "Endpoints empty (scale-to-zero); removing stale entry from store"
        );
        ctx.store.remove_endpoints(&key).await;
    }

    // Trigger configuration regeneration.
    metrics.record_success();
    Ok(Action::requeue(Duration::from_secs(30)))
}

/// Handle errors during EndpointSlice reconciliation.
pub fn error_policy_endpoint_slice(
    slice: Arc<EndpointSlice>,
    error: &ServiceError,
    _ctx: Arc<Context>,
) -> Action {
    let namespace = slice.namespace().unwrap_or_default();
    let name = slice.name_any();

    tracing::error!(
        namespace = %namespace,
        name = %name,
        error = %error,
        "EndpointSlice reconciliation failed"
    );

    crate::metrics::RECONCILE_ERRORS_TOTAL
        .with_label_values(&["EndpointSlice", "reconcile_error"])
        .inc();

    Action::requeue(Duration::from_secs(30))
}

/// Check if a service is referenced by any Gateway API route.
///
/// ## Cache-first strategy
///
/// When the shared store is ready, we answer in O(1) from the pre-built
/// reverse index.  When the store is not yet ready we fall back to the
/// existing full-list API scan so we never silently skip a referenced
/// service during startup.
async fn is_service_referenced(ctx: &Context, namespace: &str, name: &str) -> bool {
    // ── Cache path ────────────────────────────────────────────────────────────
    if let Some(referenced) = ctx.store.is_service_referenced(namespace, name).await {
        return referenced;
    }

    // ── Fallback: full API-list scan ──────────────────────────────────────────
    tracing::debug!(
        namespace = %namespace,
        name = %name,
        "Store not ready; falling back to API-list scan for is_service_referenced"
    );

    let client = &ctx.client;

    // Check HTTPRoutes
    let route_api: Api<HTTPRoute> = Api::all(client.clone());
    if let Ok(routes) = route_api.list(&Default::default()).await {
        for route in routes.items {
            let route_ns = route.namespace().unwrap_or_default();
            for rule in &route.spec.rules {
                for backend_ref in &rule.backend_refs {
                    let backend_ns = backend_ref
                        .backend_ref
                        .namespace
                        .as_deref()
                        .unwrap_or(&route_ns);
                    if backend_ns == namespace && backend_ref.backend_ref.name == name {
                        return true;
                    }
                }
            }
        }
    }

    // Check TCPRoutes
    let tcp_route_api: Api<TCPRoute> = Api::all(client.clone());
    if let Ok(routes) = tcp_route_api.list(&Default::default()).await {
        for route in routes.items {
            let route_ns = route.namespace().unwrap_or_default();
            for rule in &route.spec.rules {
                for backend_ref in &rule.backend_refs {
                    let backend_ns = backend_ref.namespace.as_deref().unwrap_or(&route_ns);
                    if backend_ns == namespace && backend_ref.name == name {
                        return true;
                    }
                }
            }
        }
    }

    // Check TLSRoutes
    let tls_route_api: Api<TLSRoute> = Api::all(client.clone());
    if let Ok(routes) = tls_route_api.list(&Default::default()).await {
        for route in routes.items {
            let route_ns = route.namespace().unwrap_or_default();
            for rule in &route.spec.rules {
                for backend_ref in &rule.backend_refs {
                    let backend_ns = backend_ref.namespace.as_deref().unwrap_or(&route_ns);
                    if backend_ns == namespace && backend_ref.name == name {
                        return true;
                    }
                }
            }
        }
    }

    false
}

/// Load endpoints for all referenced services via EndpointSlices.
pub async fn load_all_service_endpoints(client: &Client, state: &mut GatewayState) {
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
                referenced_services
                    .insert(GatewayState::key(backend_ns, &backend_ref.backend_ref.name));
            }
        }
    }

    for route in state.tcp_routes.values() {
        let route_ns = route.namespace().unwrap_or_default();
        for rule in &route.spec.rules {
            for backend_ref in &rule.backend_refs {
                let backend_ns = backend_ref.namespace.as_deref().unwrap_or(&route_ns);
                referenced_services.insert(GatewayState::key(backend_ns, &backend_ref.name));
            }
        }
    }

    for route in state.tls_routes.values() {
        let route_ns = route.namespace().unwrap_or_default();
        for rule in &route.spec.rules {
            for backend_ref in &rule.backend_refs {
                let backend_ns = backend_ref.namespace.as_deref().unwrap_or(&route_ns);
                referenced_services.insert(GatewayState::key(backend_ns, &backend_ref.name));
            }
        }
    }

    // Update backend count metric
    let mut ns_counts: std::collections::HashMap<String, i64> = std::collections::HashMap::new();
    for key in &referenced_services {
        let ns = key.split('/').next().unwrap_or("default");
        *ns_counts.entry(ns.to_string()).or_insert(0) += 1;
    }
    for (ns, count) in ns_counts {
        BACKENDS.with_label_values(&[&ns]).set(count);
    }

    // Load endpoints for each referenced service via EndpointSlices
    for svc_key in referenced_services {
        let parts: Vec<&str> = svc_key.split('/').collect();
        if parts.len() != 2 {
            continue;
        }
        let (namespace, name) = (parts[0], parts[1]);

        let slice_api: Api<EndpointSlice> = Api::namespaced(client.clone(), namespace);
        let label_selector = format!("kubernetes.io/service-name={}", name);
        let lp = kube::api::ListParams::default().labels(&label_selector);

        if let Ok(slices) = slice_api.list(&lp).await {
            let mut addrs = Vec::new();

            for slice in &slices.items {
                let ports: Vec<i32> = slice
                    .ports
                    .as_ref()
                    .map(|pp| pp.iter().filter_map(|p| p.port).collect())
                    .unwrap_or_default();

                for ep in &slice.endpoints {
                    let ready = ep.conditions.as_ref().and_then(|c| c.ready).unwrap_or(true);

                    if ready {
                        for addr in &ep.addresses {
                            if ports.is_empty() {
                                addrs.push(addr.clone());
                            } else {
                                for port in &ports {
                                    addrs.push(format!("{}:{}", addr, port));
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

/// Create the EndpointSlice controller for watching service endpoint changes.
///
/// EndpointSlices propagate faster than legacy Endpoints and scale better
/// (each slice holds up to 1000 endpoints vs one monolithic object).
pub async fn run_endpoints_controller(ctx: Arc<Context>) -> Result<(), kube::Error> {
    use crate::metrics::{WATCH_CONNECTIONS_ACTIVE, WATCH_ERRORS_TOTAL, WATCH_EVENTS_TOTAL};

    let api: Api<EndpointSlice> = if ctx.watch_all_namespaces {
        Api::all(ctx.client.clone())
    } else {
        Api::namespaced(ctx.client.clone(), &ctx.controller_namespace)
    };

    WATCH_CONNECTIONS_ACTIVE
        .with_label_values(&["EndpointSlice"])
        .set(1);

    let mut attempt: u32 = 0;
    loop {
        attempt += 1;
        match tokio::time::timeout(Duration::from_secs(30), api.list(&Default::default())).await {
            Ok(Ok(_)) => {
                ctx.store.mark_listed(ResourceClass::Endpoints).await;
                tracing::debug!(
                    attempt,
                    "EndpointSlice initial list complete; store flag set"
                );
                break;
            }
            Ok(Err(e)) => {
                let backoff = std::cmp::min(attempt * 2, 30);
                tracing::warn!(
                    error = %e,
                    attempt,
                    backoff_secs = backoff,
                    "Initial EndpointSlice list failed; will retry"
                );
                tokio::time::sleep(Duration::from_secs(backoff as u64)).await;
            }
            Err(_) => {
                tracing::warn!(
                    attempt,
                    "Initial EndpointSlice list timed out after 30s; will retry"
                );
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }
    }

    Controller::new(api, Config::default())
        .run(reconcile_endpoint_slice, error_policy_endpoint_slice, ctx)
        .for_each(|result| async move {
            match result {
                Ok((obj, _)) => {
                    WATCH_EVENTS_TOTAL
                        .with_label_values(&["EndpointSlice", "reconcile_success"])
                        .inc();
                    tracing::trace!(
                        namespace = obj.namespace.as_deref().unwrap_or(""),
                        name = %obj.name,
                        "EndpointSlice reconciled"
                    );
                }
                Err(e) => {
                    WATCH_EVENTS_TOTAL
                        .with_label_values(&["EndpointSlice", "reconcile_error"])
                        .inc();
                    WATCH_ERRORS_TOTAL
                        .with_label_values(&["EndpointSlice", "controller_error"])
                        .inc();
                    tracing::error!(error = %e, "EndpointSlice controller error");
                }
            }
        })
        .await;

    WATCH_CONNECTIONS_ACTIVE
        .with_label_values(&["EndpointSlice"])
        .set(0);

    Ok(())
}

/// Reconcile a Service resource.
///
/// This is triggered when a Service changes (spec changes like port updates).
/// We check if this service is referenced by any route and regenerate configuration if so.
pub async fn reconcile_service(
    service: Arc<Service>,
    ctx: Arc<Context>,
) -> Result<Action, ServiceError> {
    let metrics = ReconcileMetrics::new("Service");
    let namespace = service.namespace().unwrap_or_default();
    let name = service.name_any();

    tracing::debug!(namespace = %namespace, name = %name, "Reconciling Service");

    // Check if this service is referenced by any route
    let is_referenced = is_service_referenced(&ctx, &namespace, &name).await;

    if !is_referenced {
        tracing::trace!(
            namespace = %namespace,
            name = %name,
            "Service not referenced by any route, skipping"
        );
        metrics.record_success();
        return Ok(Action::await_change());
    }

    // Log service spec details for debugging
    if let Some(ref spec) = service.spec {
        let ports: Vec<String> = spec
            .ports
            .as_ref()
            .map(|ports| {
                ports
                    .iter()
                    .map(|p| format!("{}:{}", p.name.as_deref().unwrap_or("unnamed"), p.port))
                    .collect()
            })
            .unwrap_or_default();

        tracing::info!(
            namespace = %namespace,
            name = %name,
            service_type = ?spec.type_,
            ports = ?ports,
            "Service spec updated, triggering config refresh"
        );
    }

    // Trigger configuration regeneration via the shared path.
    metrics.record_success();
    Ok(Action::requeue(Duration::from_secs(300))) // Recheck every 5 minutes
}

/// Handle errors during Service reconciliation.
pub fn error_policy_service(
    service: Arc<Service>,
    error: &ServiceError,
    _ctx: Arc<Context>,
) -> Action {
    let namespace = service.namespace().unwrap_or_default();
    let name = service.name_any();

    tracing::error!(
        namespace = %namespace,
        name = %name,
        error = %error,
        "Service reconciliation failed"
    );

    crate::metrics::RECONCILE_ERRORS_TOTAL
        .with_label_values(&["Service", "reconcile_error"])
        .inc();

    Action::requeue(Duration::from_secs(30))
}

/// Create the Service controller for watching service spec changes.
pub async fn run_service_controller(ctx: Arc<Context>) -> Result<(), kube::Error> {
    use crate::metrics::{WATCH_CONNECTIONS_ACTIVE, WATCH_ERRORS_TOTAL, WATCH_EVENTS_TOTAL};

    let api: Api<Service> = if ctx.watch_all_namespaces {
        Api::all(ctx.client.clone())
    } else {
        Api::namespaced(ctx.client.clone(), &ctx.controller_namespace)
    };

    WATCH_CONNECTIONS_ACTIVE
        .with_label_values(&["Service"])
        .set(1);

    let mut attempt: u32 = 0;
    loop {
        attempt += 1;
        match tokio::time::timeout(Duration::from_secs(30), api.list(&Default::default())).await {
            Ok(Ok(_)) => {
                ctx.store.mark_listed(ResourceClass::Services).await;
                tracing::debug!(attempt, "Service initial list complete; store flag set");
                break;
            }
            Ok(Err(e)) => {
                let backoff = std::cmp::min(attempt * 2, 30);
                tracing::warn!(
                    error = %e,
                    attempt,
                    backoff_secs = backoff,
                    "Initial Service list failed; will retry"
                );
                tokio::time::sleep(Duration::from_secs(backoff as u64)).await;
            }
            Err(_) => {
                tracing::warn!(
                    attempt,
                    "Initial Service list timed out after 30s; will retry"
                );
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }
    }

    Controller::new(api, Config::default())
        .run(reconcile_service, error_policy_service, ctx)
        .for_each(|result| async move {
            match result {
                Ok((obj, _)) => {
                    WATCH_EVENTS_TOTAL
                        .with_label_values(&["Service", "reconcile_success"])
                        .inc();
                    tracing::trace!(
                        namespace = obj.namespace.as_deref().unwrap_or(""),
                        name = %obj.name,
                        "Service reconciled"
                    );
                }
                Err(e) => {
                    WATCH_EVENTS_TOTAL
                        .with_label_values(&["Service", "reconcile_error"])
                        .inc();
                    WATCH_ERRORS_TOTAL
                        .with_label_values(&["Service", "controller_error"])
                        .inc();
                    tracing::error!(error = %e, "Service controller error");
                }
            }
        })
        .await;

    WATCH_CONNECTIONS_ACTIVE
        .with_label_values(&["Service"])
        .set(0);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reconcilers::store::SharedStore;

    /// The test itself just confirms the store upsert path works in isolation.
    #[tokio::test]
    async fn test_endpoints_upsert_into_store() {
        let store = SharedStore::new();
        store.mark_ready().await;

        // Simulate what reconcile_endpoint_slice does after extracting addresses.
        let key = GatewayState::key("default", "my-svc");
        store
            .upsert_endpoints(
                key.clone(),
                ServiceEndpoints {
                    namespace: "default".to_string(),
                    name: "my-svc".to_string(),
                    endpoints: vec!["10.0.0.1:80".to_string()],
                },
            )
            .await;

        let snap = store.snapshot().await.expect("store should be ready");
        assert!(
            snap.service_endpoints.contains_key(&key),
            "endpoints should be present in store after upsert"
        );
    }

    /// Verify that is_service_referenced returns Some(true) from the store
    /// (cache path) when the store is ready and a route references the service.
    #[tokio::test]
    async fn test_is_service_referenced_uses_store_when_ready() {
        use crate::crds::HTTPRoute;
        use crate::crds::{BackendRef, HTTPBackendRef, HTTPRouteRule, HTTPRouteSpec};
        use kube::core::ObjectMeta;

        let store = SharedStore::new();

        // Insert a route that references "default/target-svc".
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
                            group: "".to_string(),
                            kind: "Service".to_string(),
                            name: "target-svc".to_string(),
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

        // The store-backed check should return Some(true) without any API calls.
        assert_eq!(
            store.is_service_referenced("default", "target-svc").await,
            Some(true)
        );
        assert_eq!(
            store.is_service_referenced("default", "other-svc").await,
            Some(false)
        );
    }
}
