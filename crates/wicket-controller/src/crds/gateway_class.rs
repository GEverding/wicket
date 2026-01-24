//! GatewayClass CRD definition.
//!
//! GatewayClass defines a set of Gateways that share common configuration and behavior.

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::common::{Condition, GATEWAY_API_GROUP, GATEWAY_API_VERSION};

/// GatewayClassSpec defines the desired state of GatewayClass.
#[derive(CustomResource, Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[kube(
    group = "gateway.networking.k8s.io",
    version = "v1",
    kind = "GatewayClass",
    plural = "gatewayclasses",
    shortname = "gc",
    status = "GatewayClassStatus",
    printcolumn = r#"{"name":"Controller","type":"string","jsonPath":".spec.controllerName"}"#,
    printcolumn = r#"{"name":"Accepted","type":"string","jsonPath":".status.conditions[?(@.type==\"Accepted\")].status"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct GatewayClassSpec {
    /// ControllerName is the name of the controller that is managing Gateways of this class.
    pub controller_name: String,

    /// Description of the GatewayClass.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// ParametersRef is a reference to a resource that contains the configuration
    /// parameters corresponding to this GatewayClass.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameters_ref: Option<ParametersReference>,
}

/// ParametersReference identifies an API object containing controller-specific configuration.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ParametersReference {
    /// Group is the group of the referent.
    pub group: String,

    /// Kind is kind of the referent.
    pub kind: String,

    /// Name is the name of the referent.
    pub name: String,

    /// Namespace is the namespace of the referent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
}

/// GatewayClassStatus defines the observed state of GatewayClass.
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GatewayClassStatus {
    /// Conditions describe the current conditions of the GatewayClass.
    #[serde(default)]
    pub conditions: Vec<Condition>,

    /// SupportedFeatures is the set of features supported by this GatewayClass.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub supported_features: Vec<String>,
}

/// The controller name for Wicket.
pub const WICKET_CONTROLLER_NAME: &str = "wicket.io/gateway-controller";

impl GatewayClass {
    /// Check if this GatewayClass is managed by Wicket.
    pub fn is_wicket_managed(&self) -> bool {
        self.spec.controller_name == WICKET_CONTROLLER_NAME
    }

    /// Get the description, if set.
    pub fn description(&self) -> Option<&str> {
        self.spec.description.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gateway_class_is_wicket_managed() {
        let gc = GatewayClass::new("wicket", GatewayClassSpec {
            controller_name: WICKET_CONTROLLER_NAME.to_string(),
            description: Some("Wicket Gateway Class".to_string()),
            parameters_ref: None,
        });
        assert!(gc.is_wicket_managed());

        let gc = GatewayClass::new("other", GatewayClassSpec {
            controller_name: "other-controller".to_string(),
            description: None,
            parameters_ref: None,
        });
        assert!(!gc.is_wicket_managed());
    }
}
