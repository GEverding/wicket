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
    Condition, Gateway, GatewayClass, HTTPRoute, HTTPRouteStatus, ParentReference,
    RouteParentStatus, WICKET_CONTROLLER_NAME,
};
use crate::metrics::{ReconcileMetrics, HTTPROUTES_TOTAL, ROUTES_ACCEPTED, ROUTES_REJECTED_TOTAL};

use super::config_generator::GatewayState;
use super::context::{trigger_config_update, Context};

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
                        conditions: vec![Condition::accepted(), Condition::resolved_refs()],
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
