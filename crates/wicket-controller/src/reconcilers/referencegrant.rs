//! ReferenceGrant reconciler.
//!
//! Watches ReferenceGrant resources and tracks metrics.

use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use kube::{
    api::Api,
    runtime::{
        controller::{Action, Controller},
        watcher::Config,
    },
    Client, ResourceExt,
};

use crate::crds::ReferenceGrant;
use crate::metrics::{
    ReconcileMetrics, REFERENCE_GRANTS_TOTAL, WATCH_CONNECTIONS_ACTIVE, WATCH_EVENTS_TOTAL,
    WATCH_ERRORS_TOTAL,
};

use super::context::Context;

/// Error type for ReferenceGrant reconciliation.
#[derive(Debug, thiserror::Error)]
pub enum ReferenceGrantError {
    #[error("Kubernetes API error: {0}")]
    KubeError(#[from] kube::Error),
}

/// Reconcile a ReferenceGrant resource.
pub async fn reconcile_referencegrant(
    grant: Arc<ReferenceGrant>,
    ctx: Arc<Context>,
) -> Result<Action, ReferenceGrantError> {
    let metrics = ReconcileMetrics::new("ReferenceGrant");
    let namespace = grant.namespace().unwrap_or_default();
    let name = grant.name_any();

    tracing::debug!(namespace = %namespace, name = %name, "Reconciling ReferenceGrant");

    // Update the total count of ReferenceGrants
    update_referencegrant_metrics(&ctx.client).await;

    metrics.record_success();
    Ok(Action::requeue(Duration::from_secs(300)))
}

/// Handle errors during ReferenceGrant reconciliation.
pub fn error_policy_referencegrant(
    grant: Arc<ReferenceGrant>,
    error: &ReferenceGrantError,
    _ctx: Arc<Context>,
) -> Action {
    let namespace = grant.namespace().unwrap_or_default();
    let name = grant.name_any();

    tracing::error!(
        namespace = %namespace,
        name = %name,
        error = %error,
        "ReferenceGrant reconciliation failed"
    );

    crate::metrics::RECONCILE_ERRORS_TOTAL
        .with_label_values(&["ReferenceGrant", "reconcile_error"])
        .inc();

    Action::requeue(Duration::from_secs(60))
}

/// Update ReferenceGrant metrics.
async fn update_referencegrant_metrics(client: &Client) {
    let api: Api<ReferenceGrant> = Api::all(client.clone());

    match api.list(&Default::default()).await {
        Ok(list) => {
            // Group by namespace
            let mut counts: std::collections::HashMap<String, i64> =
                std::collections::HashMap::new();

            for grant in &list.items {
                let ns = grant.namespace().unwrap_or_default();
                *counts.entry(ns).or_insert(0) += 1;
            }

            for (ns, count) in counts {
                REFERENCE_GRANTS_TOTAL.with_label_values(&[&ns]).set(count);
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "Failed to list ReferenceGrants for metrics");
        }
    }
}

/// Create the ReferenceGrant controller.
pub async fn run_referencegrant_controller(ctx: Arc<Context>) -> Result<(), kube::Error> {
    let api: Api<ReferenceGrant> = if ctx.watch_all_namespaces {
        Api::all(ctx.client.clone())
    } else {
        Api::namespaced(ctx.client.clone(), &ctx.controller_namespace)
    };

    WATCH_CONNECTIONS_ACTIVE
        .with_label_values(&["ReferenceGrant"])
        .set(1);

    Controller::new(api, Config::default())
        .run(reconcile_referencegrant, error_policy_referencegrant, ctx)
        .for_each(|result| async move {
            match result {
                Ok((obj, _)) => {
                    WATCH_EVENTS_TOTAL
                        .with_label_values(&["ReferenceGrant", "reconcile_success"])
                        .inc();
                    tracing::trace!(
                        namespace = obj.namespace.as_deref().unwrap_or(""),
                        name = %obj.name,
                        "ReferenceGrant reconciled"
                    );
                }
                Err(e) => {
                    WATCH_EVENTS_TOTAL
                        .with_label_values(&["ReferenceGrant", "reconcile_error"])
                        .inc();
                    WATCH_ERRORS_TOTAL
                        .with_label_values(&["ReferenceGrant", "controller_error"])
                        .inc();
                    tracing::error!(error = %e, "ReferenceGrant controller error");
                }
            }
        })
        .await;

    WATCH_CONNECTIONS_ACTIVE
        .with_label_values(&["ReferenceGrant"])
        .set(0);

    Ok(())
}
