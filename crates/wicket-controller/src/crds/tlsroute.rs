//! TLSRoute CRD definition.
//!
//! TLSRoute provides a way to route TLS requests (SNI-based routing).

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::common::{BackendRef, Condition, Hostname, ParentReference, RouteParentStatus};

/// TLSRouteSpec defines the desired state of TLSRoute.
#[derive(CustomResource, Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[kube(
    group = "gateway.networking.k8s.io",
    version = "v1alpha2",
    kind = "TLSRoute",
    plural = "tlsroutes",
    shortname = "tlsroute",
    namespaced,
    status = "TLSRouteStatus",
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct TLSRouteSpec {
    /// ParentRefs references the resources that can attach to this TLSRoute.
    #[serde(default)]
    pub parent_refs: Vec<ParentReference>,

    /// Hostnames defines a set of SNI names to match against.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hostnames: Vec<Hostname>,

    /// Rules are a list of TLS matchers and actions.
    #[serde(default)]
    pub rules: Vec<TLSRouteRule>,
}

/// TLSRouteRule is a rule in a TLSRoute.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct TLSRouteRule {
    /// Name is an optional name for the rule.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// BackendRefs defines the backend(s) where matching requests should be sent.
    #[serde(default)]
    pub backend_refs: Vec<BackendRef>,
}

/// TLSRouteStatus defines the observed state of TLSRoute.
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct TLSRouteStatus {
    /// Parents is a list of parent resources (usually Gateways) that are associated with the route.
    #[serde(default)]
    pub parents: Vec<RouteParentStatus>,
}

impl TLSRoute {
    /// Get all backend service references from this route.
    pub fn backend_refs(&self) -> Vec<&BackendRef> {
        self.spec.rules.iter()
            .flat_map(|rule| rule.backend_refs.iter())
            .collect()
    }

    /// Get hostnames (SNI names) for this route.
    pub fn hostnames(&self) -> &[Hostname] {
        &self.spec.hostnames
    }

    /// Check if this route matches a given SNI hostname.
    pub fn matches_sni(&self, sni: &str) -> bool {
        if self.spec.hostnames.is_empty() {
            return true; // No hostnames means match all
        }
        self.spec.hostnames.iter().any(|h| {
            if h.starts_with("*.") {
                sni.ends_with(&h[1..])
            } else {
                h == sni
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sni_matching() {
        let route = TLSRoute::new("test", TLSRouteSpec {
            parent_refs: vec![],
            hostnames: vec!["db.example.com".to_string(), "*.internal.com".to_string()],
            rules: vec![],
        });

        assert!(route.matches_sni("db.example.com"));
        assert!(route.matches_sni("postgres.internal.com"));
        assert!(!route.matches_sni("other.com"));
    }
}
