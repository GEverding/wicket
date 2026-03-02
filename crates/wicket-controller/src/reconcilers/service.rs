//! Service and Endpoints watcher for dynamic load balancing updates.

use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use k8s_openapi::api::core::v1::{Endpoints, Service};
use kube::{
    api::Api,
    runtime::{
        controller::{Action, Controller},
        watcher::Config,
    },
    Client, Resource, ResourceExt,
};

use crate::crds::{HTTPRoute, TCPRoute, TLSRoute};
use crate::metrics::{
    ReconcileMetrics, BACKENDS_TOTAL, BACKEND_ENDPOINTS_HEALTHY, BACKEND_ENDPOINTS_UNHEALTHY,
};

use super::config_generator::{GatewayState, ServiceEndpoints};
use super::context::{trigger_config_update, Context};

/// Error type for Service/Endpoints reconciliation.
#[derive(Debug, thiserror::Error)]
pub enum ServiceError {
    #[error("Kubernetes API error: {0}")]
    KubeError(#[from] kube::Error),

    #[error("Configuration error: {0}")]
    ConfigError(String),
}

/// Reconcile an Endpoints resource.
///
/// This is triggered when Service endpoints change (pods scale up/down, health changes).
pub async fn reconcile_endpoints(
    endpoints: Arc<Endpoints>,
    ctx: Arc<Context>,
) -> Result<Action, ServiceError> {
    let metrics = ReconcileMetrics::new("Endpoints");
    let namespace = endpoints.namespace().unwrap_or_default();
    let name = endpoints.name_any();

    tracing::debug!(namespace = %namespace, name = %name, "Reconciling Endpoints");

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

    // Extract endpoint addresses
    let mut healthy_count = 0;
    let mut unhealthy_count = 0;
    let mut endpoint_addrs = Vec::new();

    if let Some(subsets) = &endpoints.subsets {
        for subset in subsets {
            // Ready addresses are healthy
            if let Some(addresses) = &subset.addresses {
                for addr in addresses {
                    if let Some(ports) = &subset.ports {
                        for port in ports {
                            endpoint_addrs.push(format!("{}:{}", addr.ip, port.port));
                            healthy_count += 1;
                        }
                    }
                }
            }

            // NotReady addresses are unhealthy
            if let Some(not_ready) = &subset.not_ready_addresses {
                unhealthy_count += not_ready.len();
            }
        }
    }

    // Update metrics
    BACKEND_ENDPOINTS_HEALTHY
        .with_label_values(&[&namespace, &name])
        .set(healthy_count);
    BACKEND_ENDPOINTS_UNHEALTHY
        .with_label_values(&[&namespace, &name])
        .set(unhealthy_count as i64);

    tracing::info!(
        namespace = %namespace,
        name = %name,
        healthy = healthy_count,
        unhealthy = unhealthy_count,
        endpoints = ?endpoint_addrs,
        "Service endpoints updated"
    );

    // Update the shared store so the cache path reflects this event.
    // When endpoints are empty (scale-to-zero), remove the stale entry so
    // config generation does not keep routing to non-existent backends.
    let key = GatewayState::key(&namespace, &name);
    if !endpoint_addrs.is_empty() {
        ctx.store
            .upsert_endpoints(
                key,
                ServiceEndpoints {
                    namespace: namespace.clone(),
                    name: name.clone(),
                    port: 80,
                    endpoints: endpoint_addrs,
                },
            )
            .await;
    } else {
        tracing::info!(
            namespace = %namespace,
            name = %name,
            "Endpoints empty (scale-to-zero); removing stale entry from store"
        );
        ctx.store.remove_endpoints(&key).await;
    }

    // Trigger configuration regeneration via the shared path.
    trigger_config_update(&ctx, "Endpoints reconciled")
        .await
        .map_err(|e| ServiceError::ConfigError(e.to_string()))?;

    metrics.record_success();
    Ok(Action::requeue(Duration::from_secs(30)))
}

/// Handle errors during Endpoints reconciliation.
pub fn error_policy_endpoints(
    endpoints: Arc<Endpoints>,
    error: &ServiceError,
    _ctx: Arc<Context>,
) -> Action {
    let namespace = endpoints.namespace().unwrap_or_default();
    let name = endpoints.name_any();

    tracing::error!(
        namespace = %namespace,
        name = %name,
        error = %error,
        "Endpoints reconciliation failed"
    );

    crate::metrics::RECONCILE_ERRORS_TOTAL
        .with_label_values(&["Endpoints", "reconcile_error"])
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

/// Load endpoints for all referenced services.
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
        BACKENDS_TOTAL.with_label_values(&[&ns]).set(count);
    }

    // Load endpoints for each referenced service
    for svc_key in referenced_services {
        let parts: Vec<&str> = svc_key.split('/').collect();
        if parts.len() != 2 {
            continue;
        }
        let (namespace, name) = (parts[0], parts[1]);

        let endpoints_api: Api<Endpoints> = Api::namespaced(client.clone(), namespace);
        if let Ok(endpoints) = endpoints_api.get(name).await {
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
                        port: 80,
                        endpoints: addrs,
                    },
                );
            }
        }
    }
}

/// Create the Endpoints controller for watching service changes.
pub async fn run_endpoints_controller(ctx: Arc<Context>) -> Result<(), kube::Error> {
    use crate::metrics::{WATCH_CONNECTIONS_ACTIVE, WATCH_ERRORS_TOTAL, WATCH_EVENTS_TOTAL};

    let api: Api<Endpoints> = if ctx.watch_all_namespaces {
        Api::all(ctx.client.clone())
    } else {
        Api::namespaced(ctx.client.clone(), &ctx.controller_namespace)
    };

    WATCH_CONNECTIONS_ACTIVE
        .with_label_values(&["Endpoints"])
        .set(1);

    Controller::new(api, Config::default())
        .run(reconcile_endpoints, error_policy_endpoints, ctx)
        .for_each(|result| async move {
            match result {
                Ok((obj, _)) => {
                    WATCH_EVENTS_TOTAL
                        .with_label_values(&["Endpoints", "reconcile_success"])
                        .inc();
                    tracing::trace!(
                        namespace = obj.namespace.as_deref().unwrap_or(""),
                        name = %obj.name,
                        "Endpoints reconciled"
                    );
                }
                Err(e) => {
                    WATCH_EVENTS_TOTAL
                        .with_label_values(&["Endpoints", "reconcile_error"])
                        .inc();
                    WATCH_ERRORS_TOTAL
                        .with_label_values(&["Endpoints", "controller_error"])
                        .inc();
                    tracing::error!(error = %e, "Endpoints controller error");
                }
            }
        })
        .await;

    WATCH_CONNECTIONS_ACTIVE
        .with_label_values(&["Endpoints"])
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
    trigger_config_update(&ctx, "Service reconciled")
        .await
        .map_err(|e| ServiceError::ConfigError(e.to_string()))?;

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

    /// Verify that the service module no longer defines its own trigger_config_update.
    ///
    /// This is a compile-time assertion: if a local `trigger_config_update` existed
    /// with the old single-argument signature it would shadow the import and this
    /// module would fail to compile with the two-argument call sites above.
    /// The test itself just confirms the store upsert path works in isolation.
    #[tokio::test]
    async fn test_endpoints_upsert_into_store() {
        let store = SharedStore::new();
        store.mark_ready().await;

        // Simulate what reconcile_endpoints does after extracting addresses.
        let key = GatewayState::key("default", "my-svc");
        store
            .upsert_endpoints(
                key.clone(),
                ServiceEndpoints {
                    namespace: "default".to_string(),
                    name: "my-svc".to_string(),
                    port: 80,
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
        use crate::crds::{
            BackendRef, GatewaySpec, HTTPBackendRef, HTTPRouteRule, HTTPRouteSpec, Listener,
            ProtocolType,
        };
        use crate::crds::{Gateway, GatewayClass, HTTPRoute};
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
