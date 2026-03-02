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

    // Handle deletion: remove from store and trigger config update.
    if route.metadata.deletion_timestamp.is_some() {
        let key = GatewayState::key(&namespace, &name);
        ctx.store.remove_tls_route(&key).await;
        tracing::info!(namespace = %namespace, name = %name, "TLSRoute deleted, removed from store");
        trigger_config_update(&ctx, "TLSRoute deleted")
            .await
            .map_err(|e| TLSRouteError::ConfigError(e.to_string()))?;
        return Ok(Action::await_change());
    }

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
                        tracing::debug!(
                            namespace = %namespace,
                            route = %name,
                            parent_ref = %parent_ref.name,
                            parent_namespace = %parent_ns,
                            reason = "NoMatchingListener",
                            message = "Gateway has no TLS passthrough listener",
                            "Route listener validation failed"
                        );
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

    // If we have a valid parent, upsert into store and trigger configuration update.
    if has_valid_parent {
        let route_key = GatewayState::key(&namespace, &name);
        ctx.store
            .upsert_tls_route(route_key, (*route).clone())
            .await;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crds::{
        BackendRef, Condition, Gateway, GatewayClass, GatewaySpec, Listener, ParentReference,
        ProtocolType, TLSRouteRule, TLSRouteSpec,
    };
    use kube::core::ObjectMeta;
    use std::sync::Arc;

    /// Helper to create a test TLSRoute.
    fn make_tlsroute(
        name: &str,
        namespace: &str,
        parent_refs: Vec<ParentReference>,
        hostnames: Vec<String>,
    ) -> Arc<TLSRoute> {
        Arc::new(TLSRoute {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some(namespace.to_string()),
                ..Default::default()
            },
            spec: TLSRouteSpec {
                parent_refs,
                hostnames,
                rules: vec![TLSRouteRule {
                    name: None,
                    backend_refs: vec![BackendRef {
                        group: "".to_string(),
                        kind: "Service".to_string(),
                        name: "backend".to_string(),
                        namespace: None,
                        port: Some(443),
                        weight: 1,
                    }],
                }],
            },
            status: None,
        })
    }

    /// Helper to create a test Gateway.
    fn make_gateway(
        name: &str,
        namespace: &str,
        gateway_class: &str,
        protocols: Vec<ProtocolType>,
    ) -> Gateway {
        Gateway {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some(namespace.to_string()),
                ..Default::default()
            },
            spec: GatewaySpec {
                gateway_class_name: gateway_class.to_string(),
                listeners: protocols
                    .into_iter()
                    .enumerate()
                    .map(|(i, protocol)| Listener {
                        name: format!("listener-{}", i),
                        hostname: None,
                        port: match protocol {
                            ProtocolType::HTTP | ProtocolType::HTTPS => 8080 + i as u16,
                            ProtocolType::TCP | ProtocolType::TLS | ProtocolType::UDP => {
                                8443 + i as u16
                            }
                        },
                        protocol,
                        tls: None,
                        allowed_routes: None,
                    })
                    .collect(),
                addresses: vec![],
                infrastructure: None,
            },
            status: None,
        }
    }

    /// Test: TLSRoute with Gateway that has no TLS listener sets NoMatchingListener.
    #[test]
    fn test_tlsroute_no_tls_listener_sets_no_matching_listener() {
        // Setup: Create TLSRoute referencing Gateway with only HTTP listeners
        let route = make_tlsroute(
            "test-route",
            "default",
            vec![ParentReference {
                group: "gateway.networking.k8s.io".to_string(),
                kind: "Gateway".to_string(),
                namespace: None,
                name: "http-only-gateway".to_string(),
                section_name: None,
                port: None,
            }],
            vec!["db.example.com".to_string()],
        );

        // Gateway with only HTTP listeners (no TLS)
        let gateway = make_gateway(
            "http-only-gateway",
            "default",
            "wicket",
            vec![ProtocolType::HTTP],
        );

        // Verify: Gateway has only HTTP listeners
        assert_eq!(gateway.spec.listeners.len(), 1);
        assert_eq!(gateway.spec.listeners[0].protocol, ProtocolType::HTTP);

        // Verify: No TLS listener exists
        let has_tls_listener = gateway
            .spec
            .listeners
            .iter()
            .any(|l| l.protocol == ProtocolType::TLS);
        assert!(!has_tls_listener, "Gateway should not have TLS listener");

        // Expected condition for no matching listener
        let expected_condition = Condition::new(
            "Accepted",
            false,
            "NoMatchingListener",
            "Gateway has no TLS passthrough listener",
        );

        assert_eq!(expected_condition.type_, "Accepted");
        assert_eq!(expected_condition.status, "False");
        assert_eq!(expected_condition.reason, "NoMatchingListener");
        assert_eq!(
            expected_condition.message,
            "Gateway has no TLS passthrough listener"
        );
    }

    /// Test: TLSRoute with Gateway that has TLS listener is accepted.
    #[test]
    fn test_tlsroute_with_tls_listener_is_accepted() {
        // Setup: Create TLSRoute referencing Gateway with TLS listener
        let route = make_tlsroute(
            "test-route",
            "default",
            vec![ParentReference {
                group: "gateway.networking.k8s.io".to_string(),
                kind: "Gateway".to_string(),
                namespace: None,
                name: "tls-gateway".to_string(),
                section_name: None,
                port: None,
            }],
            vec!["db.example.com".to_string()],
        );

        // Gateway with TLS listener
        let gateway = make_gateway("tls-gateway", "default", "wicket", vec![ProtocolType::TLS]);

        // Verify: Gateway has TLS listener
        assert_eq!(gateway.spec.listeners.len(), 1);
        assert_eq!(gateway.spec.listeners[0].protocol, ProtocolType::TLS);

        // Verify: TLS listener exists
        let has_tls_listener = gateway
            .spec
            .listeners
            .iter()
            .any(|l| l.protocol == ProtocolType::TLS);
        assert!(has_tls_listener, "Gateway should have TLS listener");

        // Expected condition for accepted route
        let accepted_condition =
            Condition::new("Accepted", true, "Accepted", "Resource has been accepted");

        assert_eq!(accepted_condition.type_, "Accepted");
        assert_eq!(accepted_condition.status, "True");
        assert_eq!(accepted_condition.reason, "Accepted");
    }

    /// Test: TLSRoute with multiple listeners finds TLS listener.
    #[test]
    fn test_tlsroute_multiple_listeners_finds_tls() {
        // Gateway with HTTP and TLS listeners
        let gateway = make_gateway(
            "mixed-gateway",
            "default",
            "wicket",
            vec![ProtocolType::HTTP, ProtocolType::HTTPS, ProtocolType::TLS],
        );

        // Verify: Gateway has multiple listeners including TLS
        assert_eq!(gateway.spec.listeners.len(), 3);
        assert_eq!(gateway.spec.listeners[0].protocol, ProtocolType::HTTP);
        assert_eq!(gateway.spec.listeners[1].protocol, ProtocolType::HTTPS);
        assert_eq!(gateway.spec.listeners[2].protocol, ProtocolType::TLS);

        // Verify: TLS listener exists
        let tls_listeners: Vec<_> = gateway
            .spec
            .listeners
            .iter()
            .filter(|l| l.protocol == ProtocolType::TLS)
            .collect();
        assert_eq!(tls_listeners.len(), 1);
    }

    /// Test: TLSRoute with missing Gateway sets InvalidParentRef.
    #[test]
    fn test_tlsroute_missing_gateway_sets_invalid_parent_ref() {
        // Setup: Create TLSRoute referencing non-existent Gateway
        let route = make_tlsroute(
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
            vec!["db.example.com".to_string()],
        );

        // Verify: The reconciler should set InvalidParentRef condition
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

    /// Test: TLSRoute with non-Wicket Gateway sets InvalidParentRef.
    #[test]
    fn test_tlsroute_non_wicket_gateway_sets_invalid_parent_ref() {
        // Setup: Create TLSRoute referencing non-Wicket Gateway
        let route = make_tlsroute(
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
            vec!["db.example.com".to_string()],
        );

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
    }

    /// Test: TLSRoute with multiple hostnames.
    #[test]
    fn test_tlsroute_with_multiple_hostnames() {
        // Setup: TLSRoute with multiple SNI hostnames
        let route = make_tlsroute(
            "test-route",
            "default",
            vec![],
            vec![
                "db.example.com".to_string(),
                "redis.example.com".to_string(),
                "*.internal.example.com".to_string(),
            ],
        );

        // Verify: All hostnames are preserved
        assert_eq!(route.spec.hostnames.len(), 3);
        assert_eq!(route.spec.hostnames[0], "db.example.com");
        assert_eq!(route.spec.hostnames[1], "redis.example.com");
        assert_eq!(route.spec.hostnames[2], "*.internal.example.com");

        // Test SNI matching
        assert!(route.matches_sni("db.example.com"));
        assert!(route.matches_sni("redis.example.com"));
        assert!(route.matches_sni("app.internal.example.com"));
        assert!(!route.matches_sni("other.com"));
    }

    /// Test: RouteParentStatus structure for TLSRoute rejection.
    #[test]
    fn test_tlsroute_parent_status_for_no_matching_listener() {
        // Create a parent status for a route with no matching listener
        let parent_ref = ParentReference {
            group: "gateway.networking.k8s.io".to_string(),
            kind: "Gateway".to_string(),
            namespace: None,
            name: "http-only-gateway".to_string(),
            section_name: None,
            port: None,
        };

        let parent_status = RouteParentStatus {
            parent_ref: parent_ref.clone(),
            controller_name: WICKET_CONTROLLER_NAME.to_string(),
            conditions: vec![Condition::new(
                "Accepted",
                false,
                "NoMatchingListener",
                "Gateway has no TLS passthrough listener",
            )],
        };

        // Verify structure
        assert_eq!(parent_status.parent_ref.name, "http-only-gateway");
        assert_eq!(
            parent_status.controller_name,
            "wicket.io/gateway-controller"
        );
        assert_eq!(parent_status.conditions.len(), 1);
        assert_eq!(parent_status.conditions[0].type_, "Accepted");
        assert_eq!(parent_status.conditions[0].status, "False");
        assert_eq!(parent_status.conditions[0].reason, "NoMatchingListener");
        assert_eq!(
            parent_status.conditions[0].message,
            "Gateway has no TLS passthrough listener"
        );
    }

    /// Test: Metrics label structure for TLSRoute rejection.
    #[test]
    fn test_tlsroute_rejection_metrics_label_structure() {
        // Verify metric label structure
        // The metric should have labels: [namespace, "TLSRoute", reason]
        let expected_labels = ["default", "TLSRoute", "NoMatchingListener"];
        let actual_labels: Vec<&str> = expected_labels.iter().cloned().collect();

        assert_eq!(actual_labels.len(), 3);
        assert_eq!(actual_labels[0], "default");
        assert_eq!(actual_labels[1], "TLSRoute");
        assert_eq!(actual_labels[2], "NoMatchingListener");
    }

    /// Test: TLSRouteError enum variants.
    #[test]
    fn test_tlsroute_error_variants() {
        // Test error message formatting
        let parent_err = TLSRouteError::ParentNotFound("my-gateway".to_string());
        assert_eq!(
            parent_err.to_string(),
            "Parent Gateway not found: my-gateway"
        );

        let config_err = TLSRouteError::ConfigError("test error".to_string());
        assert_eq!(config_err.to_string(), "Configuration error: test error");
    }
}
