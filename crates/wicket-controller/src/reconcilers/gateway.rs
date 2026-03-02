//! Gateway reconciler.

use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use k8s_openapi::api::core::v1::Service;
use kube::{
    api::{Api, ListParams, Patch, PatchParams},
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
    ReconcileMetrics, GATEWAYS_TOTAL, GATEWAY_LISTENER_ATTACHED_ROUTES, GATEWAY_PROGRAMMED,
};

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

    // Get addresses from LoadBalancer Service or Gateway spec
    let addresses = get_gateway_addresses(&ctx.client, &namespace, &name, &gateway).await;

    // Update Gateway status
    let status = GatewayStatus {
        addresses,
        conditions: vec![Condition::accepted(), Condition::programmed()],
        listeners: listener_statuses.clone(),
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

    // Update Gateway status metrics
    GATEWAY_PROGRAMMED
        .with_label_values(&[&namespace, &name])
        .set(1);

    // Update listener attached routes metrics
    for listener_status in &listener_statuses {
        GATEWAY_LISTENER_ATTACHED_ROUTES
            .with_label_values(&[&namespace, &name, &listener_status.name])
            .set(listener_status.attached_routes as i64);
    }

    metrics.record_success();

    // Upsert into shared store so the cache path reflects this Gateway.
    let gw_key = super::config_generator::GatewayState::key(&namespace, &name);
    ctx.store.upsert_gateway(gw_key, (*gateway).clone()).await;

    // Update metrics
    update_gateway_metrics(&ctx.client).await;

    // Trigger configuration regeneration
    trigger_config_update(&ctx, "Gateway reconciled")
        .await
        .map_err(|e| GatewayError::ConfigError(e.to_string()))?;

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

    // Check for Service with the same name or common naming patterns
    let service_names = [
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
                GATEWAYS_TOTAL.with_label_values(&[&ns, &class]).set(count);
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

    let endpoints_api: Api<Endpoints> = Api::all(client.clone());

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
