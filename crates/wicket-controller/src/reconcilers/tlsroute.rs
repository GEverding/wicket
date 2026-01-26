//! TLSRoute reconciler.

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
    Condition, Gateway, GatewayClass, ParentReference, RouteParentStatus, TLSRoute, TLSRouteStatus,
    WICKET_CONTROLLER_NAME,
};
use crate::metrics::{ReconcileMetrics, ROUTES_ACCEPTED, ROUTES_REJECTED_TOTAL, TLSROUTES_TOTAL};

use super::config_generator::GatewayState;
use super::context::{trigger_config_update, Context};

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
                    // Check if gateway has a TLS listener (for passthrough mode)
                    let has_tls_listener = gateway
                        .spec
                        .listeners
                        .iter()
                        .any(|l| l.protocol == crate::crds::ProtocolType::TLS);

                    if has_tls_listener {
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
                                "NoMatchingListener",
                                "Gateway has no TLS passthrough listener",
                            )],
                        });
                    }
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

    // Update TLSRoute status
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

    // If we have a valid parent, trigger configuration update
    if has_valid_parent {
        trigger_config_update(&ctx, "TLSRoute reconciled")
            .await
            .map_err(|e| TLSRouteError::ConfigError(e.to_string()))?;
        tracing::info!(
            namespace = %namespace,
            name = %name,
            hostnames = ?route.spec.hostnames,
            "TLSRoute accepted"
        );

        // Update route acceptance metrics for each valid parent
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

        // Track rejection reasons
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

    // Update metrics
    update_tlsroute_metrics(&ctx.client).await;

    Ok(Action::requeue(Duration::from_secs(60)))
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

    Action::requeue(Duration::from_secs(60))
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
                TLSROUTES_TOTAL.with_label_values(&[&ns]).set(count);
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
