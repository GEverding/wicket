//! GatewayClass reconciler.

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

use crate::crds::{GatewayClass, GatewayClassStatus, WICKET_CONTROLLER_NAME, Condition};
use crate::metrics::{ReconcileMetrics, GATEWAY_CLASSES_TOTAL};

use super::context::Context;

/// Error type for GatewayClass reconciliation.
#[derive(Debug, thiserror::Error)]
pub enum GatewayClassError {
    #[error("Kubernetes API error: {0}")]
    KubeError(#[from] kube::Error),

    #[error("Failed to update status: {0}")]
    StatusUpdateError(String),
}

/// Reconcile a GatewayClass resource.
pub async fn reconcile_gateway_class(
    gc: Arc<GatewayClass>,
    ctx: Arc<Context>,
) -> Result<Action, GatewayClassError> {
    let metrics = ReconcileMetrics::new("GatewayClass");
    let name = gc.name_any();

    tracing::info!(name = %name, "Reconciling GatewayClass");

    // Only process GatewayClasses managed by Wicket
    if !gc.is_wicket_managed() {
        tracing::debug!(
            name = %name,
            controller = %gc.spec.controller_name,
            "Ignoring GatewayClass not managed by Wicket"
        );
        metrics.record_success();
        return Ok(Action::await_change());
    }

    // Update the GatewayClass status
    let api: Api<GatewayClass> = Api::all(ctx.client.clone());

    let status = GatewayClassStatus {
        conditions: vec![
            Condition::accepted(),
            Condition::new(
                "SupportedVersion",
                true,
                "SupportedVersion",
                "Gateway API v1 is supported",
            ),
        ],
        supported_features: vec![
            "HTTPRoute".to_string(),
            "TCPRoute".to_string(),
            "TLSRoute".to_string(),
            "ReferenceGrant".to_string(),
        ],
    };

    let patch = serde_json::json!({
        "status": status
    });

    api.patch_status(
        &name,
        &PatchParams::apply("wicket-controller"),
        &Patch::Merge(&patch),
    )
    .await?;

    tracing::info!(name = %name, "GatewayClass accepted");
    metrics.record_success();

    // Update metrics
    update_gateway_class_metrics(&ctx.client).await;

    Ok(Action::requeue(Duration::from_secs(300)))
}

/// Handle errors during GatewayClass reconciliation.
pub fn error_policy_gateway_class(
    gc: Arc<GatewayClass>,
    error: &GatewayClassError,
    _ctx: Arc<Context>,
) -> Action {
    tracing::error!(
        name = %gc.name_any(),
        error = %error,
        "GatewayClass reconciliation failed"
    );

    crate::metrics::RECONCILE_ERRORS_TOTAL
        .with_label_values(&["GatewayClass", "reconcile_error"])
        .inc();

    Action::requeue(Duration::from_secs(60))
}

/// Update GatewayClass metrics.
async fn update_gateway_class_metrics(client: &Client) {
    let api: Api<GatewayClass> = Api::all(client.clone());

    match api.list(&Default::default()).await {
        Ok(list) => {
            let wicket_managed = list
                .items
                .iter()
                .filter(|gc| gc.is_wicket_managed())
                .count();
            GATEWAY_CLASSES_TOTAL.set(wicket_managed as i64);
        }
        Err(e) => {
            tracing::warn!(error = %e, "Failed to list GatewayClasses for metrics");
        }
    }
}

/// Create the GatewayClass controller.
pub async fn run_gateway_class_controller(ctx: Arc<Context>) -> Result<(), kube::Error> {
    use crate::metrics::{WATCH_CONNECTIONS_ACTIVE, WATCH_EVENTS_TOTAL, WATCH_ERRORS_TOTAL};

    let api: Api<GatewayClass> = Api::all(ctx.client.clone());

    WATCH_CONNECTIONS_ACTIVE.with_label_values(&["GatewayClass"]).set(1);

    Controller::new(api, Config::default())
        .run(reconcile_gateway_class, error_policy_gateway_class, ctx)
        .for_each(|result| async move {
            match result {
                Ok((obj, _)) => {
                    WATCH_EVENTS_TOTAL
                        .with_label_values(&["GatewayClass", "reconcile_success"])
                        .inc();
                    tracing::debug!(name = %obj.name, "GatewayClass reconciled");
                }
                Err(e) => {
                    WATCH_EVENTS_TOTAL
                        .with_label_values(&["GatewayClass", "reconcile_error"])
                        .inc();
                    WATCH_ERRORS_TOTAL
                        .with_label_values(&["GatewayClass", "controller_error"])
                        .inc();
                    tracing::error!(error = %e, "GatewayClass controller error");
                }
            }
        })
        .await;

    WATCH_CONNECTIONS_ACTIVE.with_label_values(&["GatewayClass"]).set(0);

    Ok(())
}
