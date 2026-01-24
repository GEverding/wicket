//! Gateway reconciler.

use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use kube::{
    api::{Api, ListParams, Patch, PatchParams},
    runtime::{
        controller::{Action, Controller},
        watcher::Config,
    },
    Client, Resource, ResourceExt,
};

use crate::crds::{
    Gateway, GatewayClass, GatewayStatus, GatewayStatusAddress, AddressType,
    Condition, ListenerStatus, RouteGroupKind, WICKET_CONTROLLER_NAME,
};
use crate::metrics::{ReconcileMetrics, GATEWAYS_TOTAL};

use super::context::Context;

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

    // Check if the GatewayClass is managed by Wicket
    let gc_api: Api<GatewayClass> = Api::all(ctx.client.clone());
    let gc = gc_api
        .get(&gateway.spec.gateway_class_name)
        .await
        .map_err(|_| GatewayError::GatewayClassNotFound(gateway.spec.gateway_class_name.clone()))?;

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

    // Build listener statuses
    let listener_statuses: Vec<ListenerStatus> = gateway
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
                attached_routes: 0, // Will be updated when routes are reconciled
                conditions: vec![
                    Condition::accepted(),
                    Condition::programmed(),
                    Condition::resolved_refs(),
                ],
            }
        })
        .collect();

    // Update Gateway status
    let status = GatewayStatus {
        addresses: vec![
            GatewayStatusAddress {
                type_: AddressType::IPAddress,
                value: "0.0.0.0".to_string(), // Will be updated with actual address
            },
        ],
        conditions: vec![
            Condition::accepted(),
            Condition::programmed(),
        ],
        listeners: listener_statuses,
    };

    let api: Api<Gateway> = Api::namespaced(ctx.client.clone(), &namespace);
    let patch = serde_json::json!({
        "status": status
    });

    api.patch_status(
        &name,
        &PatchParams::apply("wicket-controller"),
        &Patch::Merge(&patch),
    )
    .await?;

    tracing::info!(namespace = %namespace, name = %name, "Gateway programmed");
    metrics.record_success();

    // Update metrics
    update_gateway_metrics(&ctx.client).await;

    // Trigger configuration regeneration
    trigger_config_update(&ctx, &gateway).await?;

    Ok(Action::requeue(Duration::from_secs(60)))
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

    Action::requeue(Duration::from_secs(60))
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
                GATEWAYS_TOTAL
                    .with_label_values(&[&ns, &class])
                    .set(count);
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "Failed to list Gateways for metrics");
        }
    }
}

/// Trigger a configuration update based on the current Gateway state.
async fn trigger_config_update(ctx: &Context, gateway: &Gateway) -> Result<(), GatewayError> {
    use super::config_generator::GatewayState;

    let mut state = GatewayState::default();

    // Add this gateway to state
    let gw_key = GatewayState::key(
        gateway.namespace().as_deref().unwrap_or("default"),
        &gateway.name_any(),
    );
    state.gateways.insert(gw_key, (*gateway).clone());

    // Load all HTTPRoutes
    let route_api: Api<crate::crds::HTTPRoute> = Api::all(ctx.client.clone());
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
    let tcp_route_api: Api<crate::crds::TCPRoute> = Api::all(ctx.client.clone());
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
    let tls_route_api: Api<crate::crds::TLSRoute> = Api::all(ctx.client.clone());
    if let Ok(routes) = tls_route_api.list(&Default::default()).await {
        for route in routes.items {
            let route_key = GatewayState::key(
                route.namespace().as_deref().unwrap_or("default"),
                &route.name_any(),
            );
            state.tls_routes.insert(route_key, route);
        }
    }

    // Load service endpoints
    load_service_endpoints(&ctx.client, &mut state).await;

    // Generate and update config
    let config = state.generate_config();
    ctx.update_config(config)
        .await
        .map_err(|e| GatewayError::ConfigError(e.to_string()))?;

    Ok(())
}

/// Load service endpoints for all referenced services.
pub async fn load_service_endpoints(client: &Client, state: &mut super::config_generator::GatewayState) {
    use k8s_openapi::api::core::v1::Endpoints;
    use super::config_generator::ServiceEndpoints;

    let endpoints_api: Api<Endpoints> = Api::all(client.clone());

    // Collect all referenced services
    let mut referenced_services: std::collections::HashSet<String> = std::collections::HashSet::new();

    for route in state.http_routes.values() {
        let route_ns = route.namespace().unwrap_or_default();
        for rule in &route.spec.rules {
            for backend_ref in &rule.backend_refs {
                let backend_ns = backend_ref.backend_ref.namespace.as_deref().unwrap_or(&route_ns);
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
                        port: 80, // Default, will be overridden by actual port
                        endpoints: addrs,
                    },
                );
            }
        }
    }
}

/// Create the Gateway controller.
pub async fn run_gateway_controller(ctx: Arc<Context>) -> Result<(), kube::Error> {
    let api: Api<Gateway> = if ctx.watch_all_namespaces {
        Api::all(ctx.client.clone())
    } else {
        Api::namespaced(ctx.client.clone(), &ctx.controller_namespace)
    };

    Controller::new(api, Config::default())
        .run(reconcile_gateway, error_policy_gateway, ctx)
        .for_each(|result| async move {
            match result {
                Ok((obj, _)) => {
                    tracing::debug!(
                        namespace = obj.namespace.as_deref().unwrap_or(""),
                        name = %obj.name,
                        "Gateway reconciled"
                    );
                }
                Err(e) => {
                    tracing::error!(error = %e, "Gateway controller error");
                }
            }
        })
        .await;

    Ok(())
}
