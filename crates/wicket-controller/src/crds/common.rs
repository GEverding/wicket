//! Common types shared across Gateway API resources.

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Group name for Gateway API resources.
pub const GATEWAY_API_GROUP: &str = "gateway.networking.k8s.io";

/// API version for Gateway API resources.
pub const GATEWAY_API_VERSION: &str = "v1";

/// Group name for Wicket-specific resources.
pub const WICKET_GROUP: &str = "wicket.io";

/// API version for Wicket resources.
pub const WICKET_VERSION: &str = "v1alpha1";

/// ParentReference identifies an API object that a resource is attached to.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ParentReference {
    /// Group is the group of the referent.
    #[serde(default = "default_gateway_group")]
    pub group: String,

    /// Kind is the kind of the referent.
    #[serde(default = "default_gateway_kind")]
    pub kind: String,

    /// Namespace is the namespace of the referent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,

    /// Name is the name of the referent.
    pub name: String,

    /// SectionName is the name of a section within the target resource.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub section_name: Option<String>,

    /// Port is the network port this Route targets.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
}

fn default_gateway_group() -> String {
    GATEWAY_API_GROUP.to_string()
}

fn default_gateway_kind() -> String {
    "Gateway".to_string()
}

/// BackendRef defines how a Route references a backend.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct BackendRef {
    /// Group is the group of the referent.
    #[serde(default = "default_core_group")]
    pub group: String,

    /// Kind is the kind of the referent.
    #[serde(default = "default_service_kind")]
    pub kind: String,

    /// Name is the name of the referent.
    pub name: String,

    /// Namespace is the namespace of the referent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,

    /// Port specifies the destination port number to use for this resource.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,

    /// Weight specifies the proportion of requests forwarded to the referenced backend.
    #[serde(default = "default_weight")]
    pub weight: u32,
}

fn default_core_group() -> String {
    "".to_string()
}

fn default_service_kind() -> String {
    "Service".to_string()
}

fn default_weight() -> u32 {
    1
}

/// SecretObjectReference identifies a Secret.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SecretObjectReference {
    /// Group is the group of the referent.
    #[serde(default = "default_core_group")]
    pub group: String,

    /// Kind is the kind of the referent.
    #[serde(default = "default_secret_kind")]
    pub kind: String,

    /// Name is the name of the referent.
    pub name: String,

    /// Namespace is the namespace of the referent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
}

fn default_secret_kind() -> String {
    "Secret".to_string()
}

/// RouteParentStatus describes the status of a route with respect to an associated parent.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RouteParentStatus {
    /// ParentRef corresponds with a ParentRef in the spec that this status corresponds to.
    pub parent_ref: ParentReference,

    /// ControllerName is the name of the controller that wrote this status.
    pub controller_name: String,

    /// Conditions describes the status conditions.
    #[serde(default)]
    pub conditions: Vec<Condition>,
}

/// Condition contains details for a resource condition.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Condition {
    /// Type of condition.
    #[serde(rename = "type")]
    pub type_: String,

    /// Status of the condition (True, False, Unknown).
    pub status: String,

    /// ObservedGeneration represents the generation observed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observed_generation: Option<i64>,

    /// LastTransitionTime is the last time the condition transitioned.
    pub last_transition_time: String,

    /// Reason contains a programmatic identifier.
    pub reason: String,

    /// Message is a human readable message.
    #[serde(default)]
    pub message: String,
}

impl Condition {
    pub fn new(type_: &str, status: bool, reason: &str, message: &str) -> Self {
        Self {
            type_: type_.to_string(),
            status: if status { "True" } else { "False" }.to_string(),
            observed_generation: None,
            last_transition_time: chrono::Utc::now().to_rfc3339(),
            reason: reason.to_string(),
            message: message.to_string(),
        }
    }

    pub fn accepted() -> Self {
        Self::new("Accepted", true, "Accepted", "Resource has been accepted")
    }

    pub fn programmed() -> Self {
        Self::new(
            "Programmed",
            true,
            "Programmed",
            "Resource has been programmed",
        )
    }

    pub fn resolved_refs() -> Self {
        Self::new(
            "ResolvedRefs",
            true,
            "ResolvedRefs",
            "All references resolved",
        )
    }

    pub fn invalid(message: &str) -> Self {
        Self::new("Accepted", false, "Invalid", message)
    }
}

/// ConditionStatus represents the status of a condition.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
pub enum ConditionStatus {
    True,
    False,
    Unknown,
}

/// Hostname describes a hostname for matching.
pub type Hostname = String;

/// PreciseHostname is a fully qualified domain name.
pub type PreciseHostname = String;

/// PortNumber is a valid port number (1-65535).
pub type PortNumber = u16;

/// Duration string (e.g., "5s", "1m").
pub type Duration = String;
