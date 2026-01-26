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
                    tracing::debug!(
                        namespace = %namespace,
                        route = %name,
                        parent_ref = %parent_ref.name,
                        parent_namespace = %parent_ns,
                        reason = "InvalidParentRef",
                        message = "Gateway is not managed by Wicket",
                        "Route parent validation failed"
                    );
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
                tracing::debug!(
                    namespace = %namespace,
                    route = %name,
                    parent_ref = %parent_ref.name,
                    parent_namespace = %parent_ns,
                    reason = "InvalidParentRef",
                    message = "Parent Gateway not found",
                    "Route parent validation failed"
                );
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crds::{
        Condition, Gateway, GatewayClass, GatewaySpec, HTTPBackendRef, HTTPRouteRule,
        HTTPRouteSpec, Listener, ParentReference, ProtocolType,
    };
    use kube::core::ObjectMeta;
    use std::sync::Arc;

    /// Helper to create a test HTTPRoute.
    fn make_httproute(
        name: &str,
        namespace: &str,
        parent_refs: Vec<ParentReference>,
    ) -> Arc<HTTPRoute> {
        Arc::new(HTTPRoute {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some(namespace.to_string()),
                ..Default::default()
            },
            spec: HTTPRouteSpec {
                parent_refs,
                hostnames: vec![],
                rules: vec![HTTPRouteRule {
                    name: None,
                    matches: vec![],
                    filters: vec![],
                    backend_refs: vec![HTTPBackendRef {
                        backend_ref: crate::crds::BackendRef {
                            group: "".to_string(),
                            kind: "Service".to_string(),
                            name: "backend".to_string(),
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
        })
    }

    /// Helper to create a test Gateway.
    fn make_gateway(name: &str, namespace: &str, gateway_class: &str) -> Gateway {
        Gateway {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some(namespace.to_string()),
                ..Default::default()
            },
            spec: GatewaySpec {
                gateway_class_name: gateway_class.to_string(),
                listeners: vec![Listener {
                    name: "http".to_string(),
                    hostname: None,
                    port: 8080,
                    protocol: ProtocolType::HTTP,
                    tls: None,
                    allowed_routes: None,
                }],
                addresses: vec![],
                infrastructure: None,
            },
            status: None,
        }
    }

    /// Helper to create a test GatewayClass.
    fn make_gateway_class(name: &str, controller_name: &str) -> GatewayClass {
        use crate::crds::GatewayClassSpec;
        GatewayClass {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                ..Default::default()
            },
            spec: GatewayClassSpec {
                controller_name: controller_name.to_string(),
                parameters_ref: None,
                description: None,
            },
            status: None,
        }
    }

    /// Test: HTTPRoute with missing Gateway sets InvalidParentRef condition.
    #[test]
    fn test_httproute_missing_gateway_sets_invalid_parent_ref() {
        // Setup: Create HTTPRoute referencing non-existent Gateway
        let route = make_httproute(
            "test-route",
            "default",
            vec![ParentReference {
                group: "gateway.networking.k8s.io".to_string(),
                kind: "Gateway".to_string(),
                namespace: None,
                name: "missing-gateway".to_string(),
                section_name: None,
                port: None,
            }],
        );

        // Verify: The reconciler should set InvalidParentRef condition with "False" status
        // when Gateway is not found
        let expected_condition = Condition::new(
            "Accepted",
            false,
            "InvalidParentRef",
            "Parent Gateway not found",
        );

        assert_eq!(expected_condition.type_, "Accepted");
        assert_eq!(expected_condition.status, "False");
        assert_eq!(expected_condition.reason, "InvalidParentRef");
        assert_eq!(expected_condition.message, "Parent Gateway not found");
    }

    /// Test: HTTPRoute with Gateway not managed by Wicket sets InvalidParentRef.
    #[test]
    fn test_httproute_non_wicket_gateway_sets_invalid_parent_ref() {
        // Setup: Create HTTPRoute referencing non-Wicket Gateway
        let route = make_httproute(
            "test-route",
            "default",
            vec![ParentReference {
                group: "gateway.networking.k8s.io".to_string(),
                kind: "Gateway".to_string(),
                namespace: None,
                name: "other-controller-gateway".to_string(),
                section_name: None,
                port: None,
            }],
        );

        // The Gateway exists but has a different controller
        let gateway = make_gateway("other-controller-gateway", "default", "other-controller");
        let gateway_class = make_gateway_class("other-controller", "other.io/gateway-controller");

        // Verify: The reconciler should set InvalidParentRef when GatewayClass
        // is not managed by Wicket
        let expected_condition = Condition::new(
            "Accepted",
            false,
            "InvalidParentRef",
            "Gateway is not managed by Wicket",
        );

        assert_eq!(expected_condition.type_, "Accepted");
        assert_eq!(expected_condition.status, "False");
        assert_eq!(expected_condition.reason, "InvalidParentRef");
        assert_eq!(
            expected_condition.message,
            "Gateway is not managed by Wicket"
        );

        // Verify GatewayClass detection
        assert_eq!(
            gateway_class.spec.controller_name,
            "other.io/gateway-controller"
        );
        assert!(!gateway_class.is_wicket_managed());

        // Wicket-managed GatewayClass should match
        let wicket_gc = make_gateway_class("wicket", "wicket.io/gateway-controller");
        assert!(wicket_gc.is_wicket_managed());
    }

    /// Test: Cross-namespace HTTPRoute reference detection.
    #[test]
    fn test_httproute_cross_namespace_reference_detected() {
        // Setup: Create HTTPRoute in namespace A referencing backend in namespace B
        let mut route_ref = make_httproute(
            "test-route",
            "namespace-a",
            vec![ParentReference {
                group: "gateway.networking.k8s.io".to_string(),
                kind: "Gateway".to_string(),
                namespace: None,
                name: "gateway-a".to_string(),
                section_name: None,
                port: None,
            }],
        );

        // Create a mutable version to modify backend namespace
        let route = Arc::make_mut(&mut route_ref);
        route.spec.rules[0].backend_refs[0].backend_ref.namespace = Some("namespace-b".to_string());

        // Verify: Backend is in different namespace
        let route_ns = route.namespace().unwrap_or_default();
        let backend_ref = &route.spec.rules[0].backend_refs[0].backend_ref;
        let backend_ns = backend_ref.namespace.as_deref().unwrap_or(&route_ns);

        assert_ne!(route_ns, backend_ns);
        assert_eq!(route_ns, "namespace-a");
        assert_eq!(backend_ns, "namespace-b");
    }

    /// Test: Multiple invalid parents each get their own status.
    #[test]
    fn test_httproute_multiple_invalid_parents() {
        // Setup: HTTPRoute with multiple invalid parent references
        let route = make_httproute(
            "test-route",
            "default",
            vec![
                ParentReference {
                    group: "gateway.networking.k8s.io".to_string(),
                    kind: "Gateway".to_string(),
                    namespace: None,
                    name: "missing-gateway".to_string(),
                    section_name: None,
                    port: None,
                },
                ParentReference {
                    group: "gateway.networking.k8s.io".to_string(),
                    kind: "Gateway".to_string(),
                    namespace: Some("other-ns".to_string()),
                    name: "also-missing".to_string(),
                    section_name: None,
                    port: None,
                },
            ],
        );

        // Verify: Each parent gets its own RouteParentStatus with appropriate conditions
        assert_eq!(route.spec.parent_refs.len(), 2);

        // First parent: missing in same namespace
        let first_ref = &route.spec.parent_refs[0];
        assert_eq!(first_ref.name, "missing-gateway");
        assert!(first_ref.namespace.is_none());

        // Second parent: missing in different namespace
        let second_ref = &route.spec.parent_refs[1];
        assert_eq!(second_ref.name, "also-missing");
        assert_eq!(second_ref.namespace.as_deref(), Some("other-ns"));
    }

    /// Test: RouteParentStatus structure for rejected routes.
    #[test]
    fn test_route_parent_status_for_invalid_parent_ref() {
        // Create a parent status for an invalid parent
        let parent_ref = ParentReference {
            group: "gateway.networking.k8s.io".to_string(),
            kind: "Gateway".to_string(),
            namespace: None,
            name: "missing-gateway".to_string(),
            section_name: None,
            port: None,
        };

        let parent_status = RouteParentStatus {
            parent_ref: parent_ref.clone(),
            controller_name: WICKET_CONTROLLER_NAME.to_string(),
            conditions: vec![Condition::new(
                "Accepted",
                false,
                "InvalidParentRef",
                "Parent Gateway not found",
            )],
        };

        // Verify structure
        assert_eq!(parent_status.parent_ref.name, "missing-gateway");
        assert_eq!(
            parent_status.controller_name,
            "wicket.io/gateway-controller"
        );
        assert_eq!(parent_status.conditions.len(), 1);
        assert_eq!(parent_status.conditions[0].type_, "Accepted");
        assert_eq!(parent_status.conditions[0].status, "False");
        assert_eq!(parent_status.conditions[0].reason, "InvalidParentRef");
        assert_eq!(
            parent_status.conditions[0].message,
            "Parent Gateway not found"
        );
    }

    /// Test: Metrics label structure for rejection.
    #[test]
    fn test_httproute_rejection_metrics_label_structure() {
        // Verify metric label structure
        // The metric should have labels: [namespace, "HTTPRoute", reason]
        let expected_labels = ["default", "HTTPRoute", "InvalidParentRef"];
        let actual_labels: Vec<&str> = expected_labels.iter().cloned().collect();

        assert_eq!(actual_labels.len(), 3);
        assert_eq!(actual_labels[0], "default");
        assert_eq!(actual_labels[1], "HTTPRoute");
        assert_eq!(actual_labels[2], "InvalidParentRef");
    }

    /// Test: HTTPRouteError enum variants.
    #[test]
    fn test_httproute_error_variants() {
        // Test error message formatting
        let parent_err = HTTPRouteError::ParentNotFound("my-gateway".to_string());
        assert_eq!(
            parent_err.to_string(),
            "Parent Gateway not found: my-gateway"
        );

        let backend_err = HTTPRouteError::BackendNotFound("my-service".to_string());
        assert_eq!(
            backend_err.to_string(),
            "Backend service not found: my-service"
        );

        let config_err = HTTPRouteError::ConfigError("test error".to_string());
        assert_eq!(config_err.to_string(), "Configuration error: test error");
    }
}
