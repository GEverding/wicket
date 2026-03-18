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
    Client, ResourceExt,
};

use crate::crds::{Condition, GatewayClass, GatewayClassStatus};
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

    // Handle deletion: remove from store.
    if gc.metadata.deletion_timestamp.is_some() {
        ctx.store.remove_gateway_class(&name).await;
        tracing::info!(name = %name, "GatewayClass deleted, removed from store");
        metrics.record_success();
        return Ok(Action::await_change());
    }

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

    // Upsert into shared store so cache reflects this GatewayClass.
    ctx.store
        .upsert_gateway_class(name.clone(), (*gc).clone())
        .await;

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
    use crate::metrics::{WATCH_CONNECTIONS_ACTIVE, WATCH_ERRORS_TOTAL, WATCH_EVENTS_TOTAL};

    let api: Api<GatewayClass> = Api::all(ctx.client.clone());

    // Retry the initial list until it succeeds.  A transient API error must
    // not leave the store permanently stuck in NotReady: the Controller watch
    // loop only fires per-object reconcile events and never re-signals "list
    // complete", so without an explicit retry here the readiness flag would
    // never be set after a startup failure.
    //
    // An empty list is a valid observation (no GatewayClasses exist) and must
    // still set the flag.  Only a successful list (Ok) sets the flag.
    let mut attempt: u32 = 0;
    loop {
        attempt += 1;
        match api.list(&Default::default()).await {
            Ok(list) => {
                for gc in list.items {
                    if gc.is_wicket_managed() {
                        let name = gc.metadata.name.clone().unwrap_or_default();
                        ctx.store.upsert_gateway_class(name, gc).await;
                    }
                }
                // Mark the resource class as listed only after a successful list.
                // An empty list is a valid observation; a failed list is not.
                ctx.store.mark_gateway_classes_listed().await;
                tracing::debug!(
                    attempt,
                    "GatewayClass initial list complete; store flag set"
                );
                break;
            }
            Err(e) => {
                let backoff = std::cmp::min(attempt * 2, 30);
                tracing::warn!(
                    error = %e,
                    attempt,
                    backoff_secs = backoff,
                    "Initial GatewayClass list failed; will retry"
                );
                tokio::time::sleep(Duration::from_secs(backoff as u64)).await;
            }
        }
    }

    WATCH_CONNECTIONS_ACTIVE
        .with_label_values(&["GatewayClass"])
        .set(1);

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

    WATCH_CONNECTIONS_ACTIVE
        .with_label_values(&["GatewayClass"])
        .set(0);

    Ok(())
}
