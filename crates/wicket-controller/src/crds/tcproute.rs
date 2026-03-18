//! TCPRoute CRD definition.
//!
//! TCPRoute provides a way to route TCP requests.

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::common::{BackendRef, ParentReference, RouteParentStatus};

/// TCPRouteSpec defines the desired state of TCPRoute.
#[derive(CustomResource, Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[kube(
    group = "gateway.networking.k8s.io",
    version = "v1alpha2",
    kind = "TCPRoute",
    plural = "tcproutes",
    shortname = "tcproute",
    namespaced,
    status = "TCPRouteStatus",
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct TCPRouteSpec {
    /// ParentRefs references the resources that can attach to this TCPRoute.
    #[serde(default)]
    pub parent_refs: Vec<ParentReference>,

    /// Rules are a list of TCP matchers and actions.
    #[serde(default)]
    pub rules: Vec<TCPRouteRule>,
}

/// TCPRouteRule is a rule in a TCPRoute.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct TCPRouteRule {
    /// Name is an optional name for the rule.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// BackendRefs defines the backend(s) where matching requests should be sent.
    #[serde(default)]
    pub backend_refs: Vec<BackendRef>,
}

/// TCPRouteStatus defines the observed state of TCPRoute.
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct TCPRouteStatus {
    /// Parents is a list of parent resources (usually Gateways) that are associated with the route.
    #[serde(default)]
    pub parents: Vec<RouteParentStatus>,
}

impl TCPRoute {
    /// Get all backend service references from this route.
    pub fn backend_refs(&self) -> Vec<&BackendRef> {
        self.spec
            .rules
            .iter()
            .flat_map(|rule| rule.backend_refs.iter())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcp_route_backend_refs() {
        let route = TCPRoute::new(
            "test",
            TCPRouteSpec {
                parent_refs: vec![],
                rules: vec![TCPRouteRule {
                    name: Some("rule1".to_string()),
                    backend_refs: vec![BackendRef {
                        group: "".to_string(),
                        kind: "Service".to_string(),
                        name: "backend-1".to_string(),
                        namespace: None,
                        port: Some(5432),
                        weight: 1,
                    }],
                }],
            },
        );

        assert_eq!(route.backend_refs().len(), 1);
        assert_eq!(route.backend_refs()[0].name, "backend-1");
    }
}
