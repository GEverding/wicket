//! Gateway CRD definition.
//!
//! Gateway represents an instance of a service-traffic handling infrastructure.

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::common::{Condition, Hostname, PortNumber, SecretObjectReference};

/// GatewaySpec defines the desired state of Gateway.
#[derive(CustomResource, Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[kube(
    group = "gateway.networking.k8s.io",
    version = "v1",
    kind = "Gateway",
    plural = "gateways",
    shortname = "gtw",
    namespaced,
    status = "GatewayStatus",
    printcolumn = r#"{"name":"Class","type":"string","jsonPath":".spec.gatewayClassName"}"#,
    printcolumn = r#"{"name":"Address","type":"string","jsonPath":".status.addresses[*].value"}"#,
    printcolumn = r#"{"name":"Programmed","type":"string","jsonPath":".status.conditions[?(@.type==\"Programmed\")].status"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct GatewaySpec {
    /// GatewayClassName is the name of the GatewayClass used by this Gateway.
    pub gateway_class_name: String,

    /// Listeners associated with this Gateway.
    pub listeners: Vec<Listener>,

    /// Addresses requested for this Gateway.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub addresses: Vec<GatewayAddress>,

    /// Infrastructure defines the infrastructure-level attributes for this Gateway.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub infrastructure: Option<GatewayInfrastructure>,
}

/// Listener embodies the concept of a logical endpoint where Gateway accepts network connections.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Listener {
    /// Name is the name of the Listener.
    pub name: String,

    /// Hostname specifies the virtual hostname to match for protocol types that define this concept.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<Hostname>,

    /// Port is the network port.
    pub port: PortNumber,

    /// Protocol specifies the network protocol.
    pub protocol: ProtocolType,

    /// TLS is the TLS configuration for the Listener.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls: Option<GatewayTLSConfig>,

    /// AllowedRoutes defines the types of routes that MAY be attached to this Listener.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_routes: Option<AllowedRoutes>,
}

/// ProtocolType defines the protocol of a Listener.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
pub enum ProtocolType {
    HTTP,
    HTTPS,
    TLS,
    TCP,
    UDP,
}

impl Default for ProtocolType {
    fn default() -> Self {
        ProtocolType::HTTP
    }
}

/// GatewayTLSConfig describes TLS configuration for a Gateway.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct GatewayTLSConfig {
    /// Mode defines the TLS behavior for the TLS session.
    #[serde(default)]
    pub mode: TLSModeType,

    /// CertificateRefs contains references to Kubernetes objects that contain TLS certificates.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub certificate_refs: Vec<SecretObjectReference>,

    /// Options are a set of configuration options for the TLS session.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub options: Option<std::collections::BTreeMap<String, String>>,

    /// FrontendValidation holds configuration for validating client certificates.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frontend_validation: Option<FrontendTLSValidation>,
}

/// TLSModeType type defines behavior of gateway with TLS.
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
pub enum TLSModeType {
    /// Terminate TLS at the Gateway.
    #[default]
    Terminate,
    /// Passthrough TLS to the backend.
    Passthrough,
}

/// FrontendTLSValidation holds configuration for validating frontend (client) TLS certificates.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct FrontendTLSValidation {
    /// CACertificateRefs contains references to Kubernetes objects that contain CA certificates.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ca_certificate_refs: Vec<SecretObjectReference>,
}

/// AllowedRoutes defines which Routes can be attached to this Listener.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AllowedRoutes {
    /// Namespaces indicates namespaces from which Routes may be attached.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespaces: Option<RouteNamespaces>,

    /// Kinds specifies the kinds of Routes that can attach to this Listener.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub kinds: Vec<RouteGroupKind>,
}

/// RouteNamespaces indicates which namespaces Routes should be selected from.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RouteNamespaces {
    /// From indicates where Routes will be selected for this Gateway.
    #[serde(default)]
    pub from: FromNamespaces,

    /// Selector must be specified when From is set to Selector.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selector: Option<LabelSelector>,
}

/// LabelSelector is a label query over a set of resources.
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LabelSelector {
    /// matchLabels is a map of {key,value} pairs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub match_labels: Option<std::collections::BTreeMap<String, String>>,

    /// matchExpressions is a list of label selector requirements.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub match_expressions: Vec<LabelSelectorRequirement>,
}

/// LabelSelectorRequirement is a selector that contains values, a key, and an operator.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
pub struct LabelSelectorRequirement {
    /// key is the label key that the selector applies to.
    pub key: String,

    /// operator represents a key's relationship to a set of values.
    pub operator: String,

    /// values is an array of string values.
    #[serde(default)]
    pub values: Vec<String>,
}

/// FromNamespaces defines how to select namespaces.
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
pub enum FromNamespaces {
    /// All namespaces.
    All,
    /// Same namespace as the Gateway.
    #[default]
    Same,
    /// Namespaces matching the selector.
    Selector,
}

/// RouteGroupKind identifies a particular Kind and Group.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RouteGroupKind {
    /// Group is the group of the Route.
    #[serde(default = "default_gateway_api_group")]
    pub group: String,

    /// Kind is the kind of the Route.
    pub kind: String,
}

fn default_gateway_api_group() -> String {
    "gateway.networking.k8s.io".to_string()
}

/// GatewayAddress describes an address that can be bound to a Gateway.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct GatewayAddress {
    /// Type of the address.
    #[serde(rename = "type", default)]
    pub type_: AddressType,

    /// Value of the address.
    pub value: String,
}

/// AddressType defines the type of address.
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
pub enum AddressType {
    #[default]
    IPAddress,
    Hostname,
    NamedAddress,
}

/// GatewayInfrastructure allows configuring infrastructure-level attributes.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct GatewayInfrastructure {
    /// Labels that should be applied to infrastructure resources.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub labels: Option<std::collections::BTreeMap<String, String>>,

    /// Annotations that should be applied to infrastructure resources.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotations: Option<std::collections::BTreeMap<String, String>>,

    /// ParametersRef is a reference to infrastructure-specific parameters.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameters_ref: Option<LocalParametersReference>,
}

/// LocalParametersReference identifies an API object containing controller-specific configuration.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LocalParametersReference {
    /// Group is the group of the referent.
    pub group: String,

    /// Kind is kind of the referent.
    pub kind: String,

    /// Name is the name of the referent.
    pub name: String,
}

/// GatewayStatus defines the observed state of Gateway.
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GatewayStatus {
    /// Addresses lists the network addresses that have been bound to the Gateway.
    #[serde(default)]
    pub addresses: Vec<GatewayStatusAddress>,

    /// Conditions describe the current conditions of the Gateway.
    #[serde(default)]
    pub conditions: Vec<Condition>,

    /// Listeners provides status for each unique listener port defined in the Spec.
    #[serde(default)]
    pub listeners: Vec<ListenerStatus>,
}

/// GatewayStatusAddress describes a network address that is bound to a Gateway.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct GatewayStatusAddress {
    /// Type of the address.
    #[serde(rename = "type", default)]
    pub type_: AddressType,

    /// Value of the address.
    pub value: String,
}

/// ListenerStatus is the status associated with a Listener.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ListenerStatus {
    /// Name is the name of the Listener.
    pub name: String,

    /// SupportedKinds is the list of supported route kinds.
    #[serde(default)]
    pub supported_kinds: Vec<RouteGroupKind>,

    /// AttachedRoutes represents the total number of Routes attached to this Listener.
    pub attached_routes: i32,

    /// Conditions describe the current condition of this listener.
    #[serde(default)]
    pub conditions: Vec<Condition>,
}

impl Gateway {
    /// Get all HTTP/HTTPS listeners.
    pub fn http_listeners(&self) -> impl Iterator<Item = &Listener> {
        self.spec.listeners.iter().filter(|l| {
            matches!(l.protocol, ProtocolType::HTTP | ProtocolType::HTTPS)
        })
    }

    /// Get all TCP listeners.
    pub fn tcp_listeners(&self) -> impl Iterator<Item = &Listener> {
        self.spec.listeners.iter().filter(|l| {
            matches!(l.protocol, ProtocolType::TCP | ProtocolType::TLS)
        })
    }

    /// Check if TLS is configured for a listener.
    pub fn listener_has_tls(&self, listener_name: &str) -> bool {
        self.spec.listeners.iter()
            .find(|l| l.name == listener_name)
            .map(|l| l.tls.is_some())
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gateway_http_listeners() {
        let gw = Gateway::new("test", GatewaySpec {
            gateway_class_name: "wicket".to_string(),
            listeners: vec![
                Listener {
                    name: "http".to_string(),
                    hostname: None,
                    port: 80,
                    protocol: ProtocolType::HTTP,
                    tls: None,
                    allowed_routes: None,
                },
                Listener {
                    name: "https".to_string(),
                    hostname: None,
                    port: 443,
                    protocol: ProtocolType::HTTPS,
                    tls: Some(GatewayTLSConfig {
                        mode: TLSModeType::Terminate,
                        certificate_refs: vec![],
                        options: None,
                        frontend_validation: None,
                    }),
                    allowed_routes: None,
                },
                Listener {
                    name: "tcp".to_string(),
                    hostname: None,
                    port: 5432,
                    protocol: ProtocolType::TCP,
                    tls: None,
                    allowed_routes: None,
                },
            ],
            addresses: vec![],
            infrastructure: None,
        });

        assert_eq!(gw.http_listeners().count(), 2);
        assert_eq!(gw.tcp_listeners().count(), 1);
    }
}
