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

use crate::crds::{Gateway, GatewayClass, HTTPRoute, TCPRoute, TLSRoute};
use crate::metrics::{
    ReconcileMetrics, BACKENDS_TOTAL, BACKEND_ENDPOINTS_HEALTHY, BACKEND_ENDPOINTS_UNHEALTHY,
};

use super::config_generator::{GatewayState, ServiceEndpoints};
use super::context::Context;

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
    let service_key = GatewayState::key(&namespace, &name);
    let is_referenced = is_service_referenced(&ctx.client, &namespace, &name).await;

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

    // Trigger configuration regeneration
    trigger_config_update(&ctx).await?;

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
async fn is_service_referenced(client: &Client, namespace: &str, name: &str) -> bool {
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

/// Trigger a full configuration update.
async fn trigger_config_update(ctx: &Context) -> Result<(), ServiceError> {
    let mut state = GatewayState::default();

    // Load all Gateways (only Wicket-managed ones)
    let gw_api: Api<Gateway> = Api::all(ctx.client.clone());
    if let Ok(gateways) = gw_api.list(&Default::default()).await {
        for gateway in gateways.items {
            let gc_api: Api<GatewayClass> = Api::all(ctx.client.clone());
            let is_wicket = gc_api
                .get(&gateway.spec.gateway_class_name)
                .await
                .map(|gc| gc.is_wicket_managed())
                .unwrap_or(false);

            if is_wicket {
                let gw_key = GatewayState::key(
                    gateway.namespace().as_deref().unwrap_or("default"),
                    &gateway.name_any(),
                );
                state.gateways.insert(gw_key, gateway);
            }
        }
    }

    // Load all HTTPRoutes
    let route_api: Api<HTTPRoute> = Api::all(ctx.client.clone());
    if let Ok(routes) = route_api.list(&Default::default()).await {
        for route in routes.items {
            let route_key = GatewayState::key(
                route.namespace().as_deref().unwrap_or("default"),
                &route.name_any(),
            );
            state.http_routes.insert(route_key, route);
        }
    }

    // Load all TCPRoutes
    let tcp_route_api: Api<TCPRoute> = Api::all(ctx.client.clone());
    if let Ok(routes) = tcp_route_api.list(&Default::default()).await {
        for route in routes.items {
            let route_key = GatewayState::key(
                route.namespace().as_deref().unwrap_or("default"),
                &route.name_any(),
            );
            state.tcp_routes.insert(route_key, route);
        }
    }

    // Load all TLSRoutes
    let tls_route_api: Api<TLSRoute> = Api::all(ctx.client.clone());
    if let Ok(routes) = tls_route_api.list(&Default::default()).await {
        for route in routes.items {
            let route_key = GatewayState::key(
                route.namespace().as_deref().unwrap_or("default"),
                &route.name_any(),
            );
            state.tls_routes.insert(route_key, route);
        }
    }

    // Load all service endpoints
    load_all_service_endpoints(&ctx.client, &mut state).await;

    // Generate and update config
    let config = state.generate_config();
    ctx.update_config(config)
        .await
        .map_err(|e| ServiceError::ConfigError(e.to_string()))?;

    Ok(())
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
    let api: Api<Endpoints> = if ctx.watch_all_namespaces {
        Api::all(ctx.client.clone())
    } else {
        Api::namespaced(ctx.client.clone(), &ctx.controller_namespace)
    };

    Controller::new(api, Config::default())
        .run(reconcile_endpoints, error_policy_endpoints, ctx)
        .for_each(|result| async move {
            match result {
                Ok((obj, _)) => {
                    tracing::trace!(
                        namespace = obj.namespace.as_deref().unwrap_or(""),
                        name = %obj.name,
                        "Endpoints reconciled"
                    );
                }
                Err(e) => {
                    tracing::error!(error = %e, "Endpoints controller error");
                }
            }
        })
        .await;

    Ok(())
}
