//! ReferenceGrant CRD definition.
//!
//! ReferenceGrant enables cross-namespace references in Gateway API.
//! This allows Gateways to reference Secrets in different namespaces for TLS.

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// ReferenceGrantSpec defines the desired state of ReferenceGrant.
#[derive(CustomResource, Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[kube(
    group = "gateway.networking.k8s.io",
    version = "v1beta1",
    kind = "ReferenceGrant",
    plural = "referencegrants",
    shortname = "refgrant",
    namespaced,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct ReferenceGrantSpec {
    /// From describes the trusted namespaces and kinds that can reference
    /// the resources described in To.
    pub from: Vec<ReferenceGrantFrom>,

    /// To describes the resources that may be referenced by the resources
    /// described in From.
    pub to: Vec<ReferenceGrantTo>,
}

/// ReferenceGrantFrom describes trusted namespaces and kinds.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ReferenceGrantFrom {
    /// Group is the group of the referent.
    pub group: String,

    /// Kind is the kind of the referent.
    pub kind: String,

    /// Namespace is the namespace of the referent.
    pub namespace: String,
}

/// ReferenceGrantTo describes what resources may be referenced.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ReferenceGrantTo {
    /// Group is the group of the referent.
    pub group: String,

    /// Kind is the kind of the referent.
    pub kind: String,

    /// Name is the name of the referent. When unspecified, all resources of the
    /// specified Group and Kind are allowed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

impl ReferenceGrant {
    /// Check if this grant allows a reference from the given source to the given target.
    pub fn allows_reference(
        &self,
        from_group: &str,
        from_kind: &str,
        from_namespace: &str,
        to_group: &str,
        to_kind: &str,
        to_name: Option<&str>,
    ) -> bool {
        // Check if there's a matching "from" entry
        let from_matches =
            self.spec.from.iter().any(|f| {
                f.group == from_group && f.kind == from_kind && f.namespace == from_namespace
            });

        if !from_matches {
            return false;
        }

        // Check if there's a matching "to" entry
        self.spec.to.iter().any(|t| {
            if t.group != to_group || t.kind != to_kind {
                return false;
            }
            // If name is specified in the grant, it must match
            match (&t.name, to_name) {
                (Some(grant_name), Some(ref_name)) => grant_name == ref_name,
                (Some(_), None) => false, // Grant requires specific name but none given
                (None, _) => true,        // Grant allows any name
            }
        })
    }

    /// Check if this grant allows a Gateway to reference a Secret for TLS.
    pub fn allows_tls_secret_reference(
        &self,
        gateway_namespace: &str,
        secret_name: Option<&str>,
    ) -> bool {
        self.allows_reference(
            "gateway.networking.k8s.io",
            "Gateway",
            gateway_namespace,
            "",
            "Secret",
            secret_name,
        )
    }

    /// Check if this grant allows a Route to reference a Service.
    pub fn allows_service_reference(
        &self,
        route_group: &str,
        route_kind: &str,
        route_namespace: &str,
        service_name: Option<&str>,
    ) -> bool {
        self.allows_reference(
            route_group,
            route_kind,
            route_namespace,
            "",
            "Service",
            service_name,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kube::core::ObjectMeta;

    fn create_grant(from: Vec<ReferenceGrantFrom>, to: Vec<ReferenceGrantTo>) -> ReferenceGrant {
        ReferenceGrant {
            metadata: ObjectMeta {
                name: Some("test-grant".to_string()),
                namespace: Some("tls-secrets".to_string()),
                ..Default::default()
            },
            spec: ReferenceGrantSpec { from, to },
        }
    }

    #[test]
    fn test_allows_tls_secret_reference() {
        let grant = create_grant(
            vec![ReferenceGrantFrom {
                group: "gateway.networking.k8s.io".to_string(),
                kind: "Gateway".to_string(),
                namespace: "gateway-ns".to_string(),
            }],
            vec![ReferenceGrantTo {
                group: "".to_string(),
                kind: "Secret".to_string(),
                name: Some("wildcard-cert".to_string()),
            }],
        );

        assert!(grant.allows_tls_secret_reference("gateway-ns", Some("wildcard-cert")));
        assert!(!grant.allows_tls_secret_reference("gateway-ns", Some("other-cert")));
        assert!(!grant.allows_tls_secret_reference("other-ns", Some("wildcard-cert")));
    }

    #[test]
    fn test_allows_any_secret() {
        let grant = create_grant(
            vec![ReferenceGrantFrom {
                group: "gateway.networking.k8s.io".to_string(),
                kind: "Gateway".to_string(),
                namespace: "gateway-ns".to_string(),
            }],
            vec![ReferenceGrantTo {
                group: "".to_string(),
                kind: "Secret".to_string(),
                name: None, // Allow any secret
            }],
        );

        assert!(grant.allows_tls_secret_reference("gateway-ns", Some("any-cert")));
        assert!(grant.allows_tls_secret_reference("gateway-ns", Some("other-cert")));
    }

    #[test]
    fn test_allows_service_reference() {
        let grant = create_grant(
            vec![ReferenceGrantFrom {
                group: "gateway.networking.k8s.io".to_string(),
                kind: "HTTPRoute".to_string(),
                namespace: "app-ns".to_string(),
            }],
            vec![ReferenceGrantTo {
                group: "".to_string(),
                kind: "Service".to_string(),
                name: None,
            }],
        );

        assert!(grant.allows_service_reference(
            "gateway.networking.k8s.io",
            "HTTPRoute",
            "app-ns",
            Some("backend-svc"),
        ));
    }
}
