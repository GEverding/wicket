//! HTTPRoute reconciler.

use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use kube::{
    api::{Api, Patch, PatchParams},
    runtime::{
        controller::{Action, Controller},
        watcher::Config,
    },
    Client, Resource, ResourceExt,
};

use crate::crds::{
    Gateway, GatewayClass, HTTPRoute, HTTPRouteStatus, RouteParentStatus,
    Condition, ParentReference, WICKET_CONTROLLER_NAME,
};
use crate::metrics::{ReconcileMetrics, HTTPROUTES_TOTAL};

use super::config_generator::GatewayState;
use super::context::Context;

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

    // Validate parent references and check if they're managed by Wicket
    let mut parent_statuses = Vec::new();
    let mut has_valid_parent = false;

    for parent_ref in &route.spec.parent_refs {
        let parent_ns = parent_ref.namespace.as_deref().unwrap_or(&namespace);

        // Get the Gateway
        let gw_api: Api<Gateway> = Api::namespaced(ctx.client.clone(), parent_ns);
        match gw_api.get(&parent_ref.name).await {
            Ok(gateway) => {
                // Check if the Gateway's class is managed by Wicket
                let gc_api: Api<GatewayClass> = Api::all(ctx.client.clone());
                let is_wicket = gc_api
                    .get(&gateway.spec.gateway_class_name)
                    .await
                    .map(|gc| gc.is_wicket_managed())
                    .unwrap_or(false);

                if is_wicket {
                    has_valid_parent = true;
                    parent_statuses.push(RouteParentStatus {
                        parent_ref: parent_ref.clone(),
                        controller_name: ctx.controller_name.clone(),
                        conditions: vec![
                            Condition::accepted(),
                            Condition::resolved_refs(),
                        ],
                    });
                } else {
                    parent_statuses.push(RouteParentStatus {
                        parent_ref: parent_ref.clone(),
                        controller_name: ctx.controller_name.clone(),
                        conditions: vec![Condition::new(
                            "Accepted",
                            false,
                            "InvalidParentRef",
                            "Gateway is not managed by Wicket",
                        )],
                    });
                }
            }
            Err(_) => {
                parent_statuses.push(RouteParentStatus {
                    parent_ref: parent_ref.clone(),
                    controller_name: ctx.controller_name.clone(),
                    conditions: vec![Condition::new(
                        "Accepted",
                        false,
                        "InvalidParentRef",
                        "Parent Gateway not found",
                    )],
                });
            }
        }
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

    // If we have a valid parent, trigger configuration update
    if has_valid_parent {
        trigger_config_update(&ctx).await?;
        tracing::info!(namespace = %namespace, name = %name, "HTTPRoute accepted");
    } else {
        tracing::warn!(namespace = %namespace, name = %name, "HTTPRoute has no valid Wicket parents");
    }

    metrics.record_success();

    // Update metrics
    update_httproute_metrics(&ctx.client).await;

    Ok(Action::requeue(Duration::from_secs(60)))
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
                HTTPROUTES_TOTAL.with_label_values(&[&ns]).set(count);
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "Failed to list HTTPRoutes for metrics");
        }
    }
}

/// Trigger a full configuration update.
async fn trigger_config_update(ctx: &Context) -> Result<(), HTTPRouteError> {
    let mut state = GatewayState::default();

    // Load all Gateways
    let gw_api: Api<Gateway> = Api::all(ctx.client.clone());
    if let Ok(gateways) = gw_api.list(&Default::default()).await {
        for gateway in gateways.items {
            // Only include Wicket-managed gateways
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
    super::gateway::load_service_endpoints(&ctx.client, &mut state).await;

    // Generate and update config
    let config = state.generate_config();
    ctx.update_config(config)
        .await
        .map_err(|e| HTTPRouteError::ConfigError(e.to_string()))?;

    Ok(())
}

/// Create the HTTPRoute controller.
pub async fn run_httproute_controller(ctx: Arc<Context>) -> Result<(), kube::Error> {
    use crate::metrics::{WATCH_CONNECTIONS_ACTIVE, WATCH_EVENTS_TOTAL, WATCH_ERRORS_TOTAL};

    let api: Api<HTTPRoute> = if ctx.watch_all_namespaces {
        Api::all(ctx.client.clone())
    } else {
        Api::namespaced(ctx.client.clone(), &ctx.controller_namespace)
    };

    WATCH_CONNECTIONS_ACTIVE.with_label_values(&["HTTPRoute"]).set(1);

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

    WATCH_CONNECTIONS_ACTIVE.with_label_values(&["HTTPRoute"]).set(0);

    Ok(())
}
