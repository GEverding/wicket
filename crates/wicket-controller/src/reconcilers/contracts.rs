//! Planner/applier contracts and reconcile orchestration boundaries.
//!
//! # Overview
//!
//! This module defines the pure boundary types that separate *planning* (what
//! should the world look like?) from *application* (make the world look like
//! that).  Every reconciler in `crates/wicket-controller/` is expected to
//! follow these contracts.
//!
//! ```text
//!   SharedStore snapshot
//!   + observed owned-object state
//!         |
//!         v
//!   [ Planner ]  -- pure, no I/O, deterministic, sync
//!         |
//!         v
//!   Plan types (ConfigPlan / StatusPatch / TlsMaterializationPlan / ReconcilePlan)
//!         |
//!         v
//!   [ Applier ]  -- side-effecting, reads plan, writes k8s / filesystem
//!         |
//!         v
//!   ApplyResult
//! ```
//!
//! # Invariants
//!
//! ## Planner invariants
//!
//! 1. **Determinism** -- given the same inputs a planner always returns the
//!    same plan.  No random values, no timestamps, no I/O.
//! 2. **No side effects** -- planners must not call Kubernetes APIs, write
//!    files, or perform any async I/O.  All inputs arrive via explicit
//!    parameters (store snapshots, observed state structs).
//! 3. **No knowledge of apply** -- a planner does not know whether its output
//!    will be applied, skipped, or diffed.  It only computes intent.
//! 4. **Infallible for well-formed inputs** -- planning errors are represented
//!    as `PlanError` variants, not panics.  Planners must not call `unwrap()`
//!    on inputs.
//!
//! ## Applier invariants
//!
//! 1. **Idempotence** -- applying the same plan twice produces no observable
//!    change on the second call (server-side apply semantics).
//! 2. **Plan-only reads** -- appliers do not read `SharedStore` or Gateway API
//!    objects to decide *what* to apply.  They only read the plan they were
//!    given plus the objects they own (to detect drift).
//! 3. **No status writes** -- appliers do not write Gateway `.status`.  That
//!    is the status observer's responsibility.
//! 4. **Deletion after apply** -- when a plan indicates deletion, the applier
//!    removes the owned object only after the new desired state has been
//!    successfully applied (apply-then-delete ordering).
//!
//! ## Ordering invariants
//!
//! For a single Gateway reconcile cycle the ordering is:
//!
//! ```text
//! 1. Compute plan (pure, sync)
//! 2. Apply config plan  (ConfigMap patch)
//! 3. Apply TLS plan     (filesystem writes)
//! 4. Apply runtime plan (Deployment / Service / ServiceAccount patches)
//! 5. Write Gateway status (status observer, reads owned object state)
//! ```
//!
//! Steps 2-4 may be skipped when the plan indicates no change (`NoOp`).
//! Step 5 always runs so that `observedGeneration` is kept current.
//!
//! ## Error boundary invariants
//!
//! - A planning error (`PlanError`) aborts the reconcile cycle.  The
//!   controller requeues with backoff.  No partial apply is attempted.
//! - An apply error (`ApplyError`) is returned from the applier.  The
//!   controller requeues.  Partial applies are safe because each apply step
//!   is idempotent.
//! - A status-write error does not block future reconcile cycles.  The
//!   controller logs the error and requeues.

use std::collections::BTreeMap;

// ─────────────────────────────────────────────────────────────────────────────
// Error types
// ─────────────────────────────────────────────────────────────────────────────

/// Errors that can occur during the planning phase.
///
/// Planning errors are always logic errors (bad inputs, missing required data).
/// They are never I/O errors.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PlanError {
    /// A required field was absent from the input.
    #[error("missing required field: {field}")]
    MissingField { field: &'static str },

    /// An input value was syntactically or semantically invalid.
    #[error("invalid input: {reason}")]
    InvalidInput { reason: String },

    /// The store snapshot was not ready; planning cannot proceed.
    #[error("store not ready")]
    StoreNotReady,

    /// A cross-namespace reference is not permitted by any ReferenceGrant.
    #[error(
        "cross-namespace reference not permitted: from {from_ns}/{from_kind} to {to_ns}/{to_name}"
    )]
    ReferenceNotPermitted {
        from_ns: String,
        from_kind: String,
        to_ns: String,
        to_name: String,
    },
}

/// Errors that can occur during the apply phase.
///
/// Apply errors are always I/O or API errors.  They are never logic errors
/// (those are caught at planning time).
#[derive(Debug, thiserror::Error)]
pub enum ApplyError {
    /// A Kubernetes API call failed.
    #[error("kubernetes API error: {0}")]
    KubeApi(String),

    /// A filesystem write failed (TLS materialization).
    #[error("filesystem error: {0}")]
    Filesystem(String),

    /// Serialization of a plan field failed.
    #[error("serialization error: {0}")]
    Serialization(String),

    /// A pre-existing object lacks the controller's managed-by label and
    /// cannot be safely adopted.
    #[error("object {namespace}/{name} exists but is not managed by wicket-controller")]
    NotOwned { namespace: String, name: String },
}

// ─────────────────────────────────────────────────────────────────────────────
// Config plan
// ─────────────────────────────────────────────────────────────────────────────

/// Intent for a ConfigMap data update.
///
/// The planner produces this; the applier patches the ConfigMap.
/// The planner must not know the ConfigMap name or namespace -- those are
/// applier concerns.
///
/// Both variants carry `toml_content` and `config_hash` so that the applier
/// can always sync the in-memory `WicketConfig` without an extra Kubernetes
/// read, even when no patch is needed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigPlan {
    /// The ConfigMap data should be updated to the given TOML content.
    ///
    /// `config_hash` is the lowercase hex SHA-256 of `toml_content`.  The
    /// applier stores it as the annotation `wicket.io/config-revision` on the
    /// ConfigMap so that the status observer can compare it to the running
    /// pod's label.
    Update {
        /// Rendered `wicket.toml` content.
        toml_content: String,
        /// Lowercase hex SHA-256 of `toml_content`.
        config_hash: String,
    },

    /// The ConfigMap is already at the desired state; no patch is needed.
    ///
    /// The content fields are carried so the applier can sync the in-memory
    /// `WicketConfig` without an extra Kubernetes read (e.g. after a process
    /// restart where the in-memory view was lost but the ConfigMap is current).
    NoOp {
        /// Rendered `wicket.toml` content (identical to what is in the ConfigMap).
        toml_content: String,
        /// Lowercase hex SHA-256 of `toml_content`.
        config_hash: String,
    },
}

/// Result returned by the config applier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigApplyResult {
    /// The ConfigMap was patched.
    Updated { config_hash: String },
    /// No change was needed.
    NoOp,
}

// ─────────────────────────────────────────────────────────────────────────────
// Status patch
// ─────────────────────────────────────────────────────────────────────────────

/// The type of a Gateway status address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddressKind {
    /// An IPv4 or IPv6 address.
    IPAddress,
    /// A DNS hostname.
    Hostname,
}

/// A single address entry for `Gateway.status.addresses`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedAddress {
    pub kind: AddressKind,
    pub value: String,
}

/// Desired condition value for a Gateway or listener.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConditionStatus {
    True,
    False,
}

/// Reason string for a `Programmed=False` condition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotProgrammedReason {
    /// The owned Deployment does not yet have any ready replicas.
    DeploymentNotReady,
    /// The ready pods are running a different config revision than the plan.
    RevisionMismatch,
    /// The owned Deployment does not exist yet.
    DeploymentMissing,
    /// A custom reason (for future extension).
    Other(String),
}

impl NotProgrammedReason {
    /// Returns the Gateway API condition reason string.
    pub fn as_str(&self) -> &str {
        match self {
            Self::DeploymentNotReady => "DeploymentNotReady",
            Self::DeploymentMissing => "DeploymentMissing",
            Self::RevisionMismatch => "RevisionMismatch",
            Self::Other(s) => s.as_str(),
        }
    }
}

/// Desired status for a single listener.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListenerStatusIntent {
    /// Listener name (matches `Gateway.spec.listeners[*].name`).
    pub name: String,
    /// Number of routes attached to this listener.
    pub attached_routes: u32,
    /// Route group/kind pairs this listener supports.
    pub supported_kinds: Vec<RouteGroupKind>,
    /// Whether the listener is accepted.
    pub accepted: bool,
    /// Reason for rejection, if `accepted` is false.
    pub rejection_reason: Option<String>,
}

/// A (group, kind) pair identifying a route type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteGroupKind {
    pub group: String,
    pub kind: String,
}

/// Intent for a Gateway status patch.
///
/// The planner produces this; the status observer translates it into
/// `patch_status` calls.  The planner must not know the patch format or
/// the Kubernetes condition type strings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusPatch {
    /// Desired `Gateway.status.addresses`.
    pub addresses: Vec<PlannedAddress>,

    /// Whether `Accepted` should be `True`.
    pub accepted: ConditionStatus,

    /// Whether `Programmed` should be `True`.
    pub programmed: ConditionStatus,

    /// Reason for `Programmed=False`, if applicable.
    pub not_programmed_reason: Option<NotProgrammedReason>,

    /// Per-listener status intents.
    pub listeners: Vec<ListenerStatusIntent>,

    /// The Gateway `.metadata.generation` at plan time.
    /// The status observer sets `observedGeneration` to this value.
    pub observed_generation: i64,
}

// ─────────────────────────────────────────────────────────────────────────────
// TLS materialization plan
// ─────────────────────────────────────────────────────────────────────────────

/// A single TLS file pair to write to the filesystem.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsFileIntent {
    /// Absolute path for the certificate PEM file.
    pub cert_path: String,
    /// Absolute path for the private key PEM file.
    pub key_path: String,
    /// PEM-encoded certificate chain.
    pub cert_pem: String,
    /// PEM-encoded private key.
    pub key_pem: String,
}

/// A TLS file that should be removed from the filesystem.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsDeleteIntent {
    /// Absolute path of the certificate file to delete.
    pub cert_path: String,
    /// Absolute path of the key file to delete.
    pub key_path: String,
}

/// Intent for TLS certificate materialization.
///
/// The planner produces this from the store's `tls_secrets` map and the
/// set of secrets referenced by active Gateways.  The applier writes or
/// deletes files on the filesystem.
///
/// ## Invariants
///
/// - A secret key must not appear in both `write` and `delete`.
/// - The planner must not perform any filesystem reads.  It derives desired
///   state purely from the store snapshot.
/// - The applier writes files atomically (write to a temp path, then rename)
///   to avoid partial writes visible to the proxy.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TlsMaterializationPlan {
    /// Files to create or overwrite.
    pub write: Vec<TlsFileIntent>,
    /// Files to delete (secrets no longer referenced by any active Gateway).
    pub delete: Vec<TlsDeleteIntent>,
}

impl TlsMaterializationPlan {
    /// Returns `true` if the plan requires no filesystem changes.
    pub fn is_noop(&self) -> bool {
        self.write.is_empty() && self.delete.is_empty()
    }
}

/// Result returned by the TLS applier.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TlsApplyResult {
    /// Paths of files that were written.
    pub written: Vec<String>,
    /// Paths of files that were deleted.
    pub deleted: Vec<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Reconcile orchestration / deletion handling
// ─────────────────────────────────────────────────────────────────────────────

/// The service type for a Gateway's owned Service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceType {
    ClusterIP,
    LoadBalancer,
    NodePort,
}

impl std::fmt::Display for ServiceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServiceType::ClusterIP => write!(f, "ClusterIP"),
            ServiceType::LoadBalancer => write!(f, "LoadBalancer"),
            ServiceType::NodePort => write!(f, "NodePort"),
        }
    }
}

impl std::str::FromStr for ServiceType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ClusterIP" => Ok(ServiceType::ClusterIP),
            "LoadBalancer" => Ok(ServiceType::LoadBalancer),
            "NodePort" => Ok(ServiceType::NodePort),
            other => Err(format!(
                "invalid service type {:?}; expected one of: ClusterIP, LoadBalancer, NodePort",
                other
            )),
        }
    }
}

/// A single port entry for the owned Service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServicePortSpec {
    /// Port name (e.g. "http", "https", "tcp-8443").
    pub name: String,
    /// Port number exposed on the Service.
    pub port: u16,
    /// Port number on the target pod.
    pub target_port: u16,
    /// Protocol ("TCP" or "UDP").
    pub protocol: String,
}

/// Infrastructure metadata for the owned Deployment.
///
/// These fields control the Deployment spec but are not part of the proxy
/// config payload.  Changes here trigger a Deployment rollout (spec_hash
/// changes); changes to `config_toml` alone do not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeMetadata {
    /// Container image for the proxy.
    pub image: String,
    /// Initial replica count.
    pub replicas: u32,
    /// Optional CPU/memory resource requirements as a key-value map.
    /// Keys follow the Kubernetes convention: "requests.cpu", "limits.memory", etc.
    pub resources: BTreeMap<String, String>,
    /// Node selector labels.
    pub node_selector: BTreeMap<String, String>,
}

impl Default for RuntimeMetadata {
    fn default() -> Self {
        Self {
            image: String::new(),
            replicas: 1,
            resources: BTreeMap::new(),
            node_selector: BTreeMap::new(),
        }
    }
}

/// What the reconcile cycle should do for a given Gateway.
///
/// The planner produces this; the reconcile orchestrator dispatches to the
/// appropriate applier(s).
///
/// `Apply` boxes its payload to keep the enum size uniform across variants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReconcileAction {
    /// Apply the full plan: config, TLS, and runtime objects.
    Apply(Box<ReconcilePlan>),

    /// The Gateway is being deleted.  Owned objects will be garbage-collected
    /// by Kubernetes via owner references.  The controller removes the Gateway
    /// from the store and triggers a config update for remaining Gateways.
    Delete {
        gateway_namespace: String,
        gateway_name: String,
    },

    /// The Gateway's GatewayClass is not managed by this controller.
    /// No action is taken.
    Ignore,
}

/// Full reconcile plan for a single Gateway.
///
/// This is the top-level output of the planner.  The reconcile orchestrator
/// fans it out to the config applier, TLS applier, and (for managed-mode
/// Gateways) the runtime applier.
///
/// ## Managed vs. config-synthesis-only mode
///
/// - `managed_runtime = false`: only `config` and `tls` plans are applied.
///   The runtime objects (Deployment, Service, ServiceAccount) are not owned
///   by the controller.  This is the current default behavior.
/// - `managed_runtime = true`: all three plans are applied.  The controller
///   creates and owns the runtime objects.  Enabled by the annotation
///   `wicket.io/managed-runtime: "true"` on the Gateway.
///
/// ## Hashes
///
/// - `config_hash`: lowercase hex SHA-256 of `config.toml_content` (when
///   `config` is `ConfigPlan::Update`).  Used as the pod template label
///   `wicket.io/config-revision` and the ConfigMap annotation.
/// - `spec_hash`: lowercase hex SHA-256 of the serialized `runtime_metadata`.
///   Changes when image, replicas, or resource requirements change.  Triggers
///   a Deployment rollout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconcilePlan {
    // ── Identity ──────────────────────────────────────────────────────────────
    /// Gateway namespace.
    pub gateway_namespace: String,
    /// Gateway name.
    pub gateway_name: String,
    /// Gateway UID (for owner references on managed objects).
    pub gateway_uid: String,
    /// Gateway `.metadata.generation` at plan time.
    pub gateway_generation: i64,

    // ── Mode ──────────────────────────────────────────────────────────────────
    /// Whether the controller owns and manages runtime objects for this Gateway.
    pub managed_runtime: bool,

    // ── Sub-plans ─────────────────────────────────────────────────────────────
    /// Config (ConfigMap) plan.
    pub config: ConfigPlan,

    /// TLS certificate materialization plan.
    pub tls: TlsMaterializationPlan,

    /// Desired Gateway status.
    pub status: StatusPatch,

    // ── Runtime (managed mode only) ───────────────────────────────────────────
    /// Infrastructure metadata for the owned Deployment.
    /// Ignored when `managed_runtime = false`.
    pub runtime_metadata: RuntimeMetadata,

    /// Service type for the owned Service.
    /// Ignored when `managed_runtime = false`.
    pub service_type: ServiceType,

    /// Port specs for the owned Service.
    /// Ignored when `managed_runtime = false`.
    pub service_ports: Vec<ServicePortSpec>,

    // ── Revision hashes ───────────────────────────────────────────────────────
    /// Lowercase hex SHA-256 of the rendered config TOML.
    /// Empty string when `config` is `ConfigPlan::NoOp`.
    pub config_hash: String,

    /// Lowercase hex SHA-256 of the serialized `runtime_metadata`.
    pub spec_hash: String,
}

/// Aggregate result of applying a `ReconcilePlan`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ReconcileResult {
    /// Result of the config (ConfigMap) apply step.
    pub config: Option<ConfigApplyResult>,
    /// Result of the TLS materialization step.
    pub tls: Option<TlsApplyResult>,
    /// Whether a Deployment rollout was triggered (managed mode only).
    pub rollout_triggered: bool,
}

// ─────────────────────────────────────────────────────────────────────────────
// Planner trait
// ─────────────────────────────────────────────────────────────────────────────

/// A pure, synchronous planner.
///
/// Implementors must satisfy the planner invariants documented at the top of
/// this module:
/// - No I/O, no async, no side effects.
/// - Deterministic: same inputs always produce the same output.
/// - Returns `Err(PlanError)` for invalid or incomplete inputs; never panics.
pub trait Planner {
    /// The input type consumed by this planner.
    type Input;
    /// The plan type produced by this planner.
    type Plan;

    /// Compute the desired plan from the given input.
    ///
    /// # Errors
    ///
    /// Returns `PlanError` when the input is invalid or incomplete.
    fn plan(&self, input: &Self::Input) -> Result<Self::Plan, PlanError>;
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── ConfigPlan ────────────────────────────────────────────────────────────

    #[test]
    fn config_plan_update_carries_hash() {
        let plan = ConfigPlan::Update {
            toml_content: "[server]\nlisten = \"0.0.0.0:8080\"\n".to_string(),
            config_hash: "abc123".to_string(),
        };
        match plan {
            ConfigPlan::Update { config_hash, .. } => assert_eq!(config_hash, "abc123"),
            ConfigPlan::NoOp { .. } => panic!("expected Update"),
        }
    }

    #[test]
    fn config_plan_noop_carries_content() {
        let plan = ConfigPlan::NoOp {
            toml_content: "[server]\nlisten = \"0.0.0.0:8080\"\n".to_string(),
            config_hash: "abc123".to_string(),
        };
        match plan {
            ConfigPlan::NoOp {
                ref toml_content,
                ref config_hash,
            } => {
                assert_eq!(config_hash, "abc123");
                assert!(!toml_content.is_empty());
            }
            _ => panic!("expected NoOp"),
        }
    }

    #[test]
    fn config_plan_noop_equality() {
        let a = ConfigPlan::NoOp {
            toml_content: "x".to_string(),
            config_hash: "h".to_string(),
        };
        let b = ConfigPlan::NoOp {
            toml_content: "x".to_string(),
            config_hash: "h".to_string(),
        };
        assert_eq!(a, b);
    }

    // ── TlsMaterializationPlan ────────────────────────────────────────────────

    #[test]
    fn tls_plan_default_is_noop() {
        let plan = TlsMaterializationPlan::default();
        assert!(plan.is_noop());
    }

    #[test]
    fn tls_plan_with_write_is_not_noop() {
        let plan = TlsMaterializationPlan {
            write: vec![TlsFileIntent {
                cert_path: "/tls/a.crt".to_string(),
                key_path: "/tls/a.key".to_string(),
                cert_pem: "CERT".to_string(),
                key_pem: "KEY".to_string(),
            }],
            delete: vec![],
        };
        assert!(!plan.is_noop());
    }

    #[test]
    fn tls_plan_with_delete_is_not_noop() {
        let plan = TlsMaterializationPlan {
            write: vec![],
            delete: vec![TlsDeleteIntent {
                cert_path: "/tls/old.crt".to_string(),
                key_path: "/tls/old.key".to_string(),
            }],
        };
        assert!(!plan.is_noop());
    }

    // ── NotProgrammedReason ───────────────────────────────────────────────────

    #[test]
    fn not_programmed_reason_strings() {
        assert_eq!(
            NotProgrammedReason::DeploymentNotReady.as_str(),
            "DeploymentNotReady"
        );
        assert_eq!(
            NotProgrammedReason::DeploymentMissing.as_str(),
            "DeploymentMissing"
        );
        assert_eq!(
            NotProgrammedReason::RevisionMismatch.as_str(),
            "RevisionMismatch"
        );
        assert_eq!(
            NotProgrammedReason::Other("CustomReason".to_string()).as_str(),
            "CustomReason"
        );
    }

    // ── PlanError ─────────────────────────────────────────────────────────────

    #[test]
    fn plan_error_missing_field_display() {
        let e = PlanError::MissingField {
            field: "gateway_uid",
        };
        assert!(e.to_string().contains("gateway_uid"));
    }

    #[test]
    fn plan_error_reference_not_permitted_display() {
        let e = PlanError::ReferenceNotPermitted {
            from_ns: "ns-a".to_string(),
            from_kind: "Gateway".to_string(),
            to_ns: "ns-b".to_string(),
            to_name: "my-secret".to_string(),
        };
        let s = e.to_string();
        assert!(s.contains("ns-a"));
        assert!(s.contains("ns-b"));
        assert!(s.contains("my-secret"));
    }

    #[test]
    fn plan_error_store_not_ready_display() {
        let e = PlanError::StoreNotReady;
        assert!(e.to_string().contains("store not ready"));
    }

    // ── ReconcileAction ───────────────────────────────────────────────────────

    #[test]
    fn reconcile_action_ignore_is_not_apply() {
        let action = ReconcileAction::Ignore;
        assert!(matches!(action, ReconcileAction::Ignore));
    }

    #[test]
    fn reconcile_action_delete_carries_identity() {
        let action = ReconcileAction::Delete {
            gateway_namespace: "prod".to_string(),
            gateway_name: "my-gw".to_string(),
        };
        match action {
            ReconcileAction::Delete {
                gateway_namespace,
                gateway_name,
            } => {
                assert_eq!(gateway_namespace, "prod");
                assert_eq!(gateway_name, "my-gw");
            }
            _ => panic!("expected Delete"),
        }
    }

    // ── Planner trait ─────────────────────────────────────────────────────────

    /// A trivial planner used to verify the trait compiles and is callable.
    struct EchoPlanner;

    impl Planner for EchoPlanner {
        type Input = String;
        type Plan = String;

        fn plan(&self, input: &String) -> Result<String, PlanError> {
            if input.is_empty() {
                return Err(PlanError::InvalidInput {
                    reason: "input must not be empty".to_string(),
                });
            }
            Ok(input.clone())
        }
    }

    #[test]
    fn planner_trait_ok() {
        let p = EchoPlanner;
        assert_eq!(p.plan(&"hello".to_string()).unwrap(), "hello");
    }

    #[test]
    fn planner_trait_err_on_empty() {
        let p = EchoPlanner;
        let err = p.plan(&String::new()).unwrap_err();
        assert!(matches!(err, PlanError::InvalidInput { .. }));
    }

    // ── RuntimeMetadata ───────────────────────────────────────────────────────

    #[test]
    fn runtime_metadata_default_replicas() {
        let m = RuntimeMetadata::default();
        assert_eq!(m.replicas, 1);
    }

    // ── ReconcilePlan shape ───────────────────────────────────────────────────

    #[test]
    fn reconcile_plan_managed_false_by_default_construction() {
        // Verify that a plan can be constructed with managed_runtime = false
        // and that the runtime fields are present but ignored by convention.
        let plan = ReconcilePlan {
            gateway_namespace: "default".to_string(),
            gateway_name: "my-gw".to_string(),
            gateway_uid: "uid-abc".to_string(),
            gateway_generation: 1,
            managed_runtime: false,
            config: ConfigPlan::NoOp {
                toml_content: String::new(),
                config_hash: String::new(),
            },
            tls: TlsMaterializationPlan::default(),
            status: StatusPatch {
                addresses: vec![],
                accepted: ConditionStatus::True,
                programmed: ConditionStatus::False,
                not_programmed_reason: Some(NotProgrammedReason::DeploymentMissing),
                listeners: vec![],
                observed_generation: 1,
            },
            runtime_metadata: RuntimeMetadata::default(),
            service_type: ServiceType::ClusterIP,
            service_ports: vec![],
            config_hash: String::new(),
            spec_hash: String::new(),
        };

        assert!(!plan.managed_runtime);
        assert_eq!(plan.gateway_name, "my-gw");
        assert!(matches!(plan.config, ConfigPlan::NoOp { .. }));
        assert!(plan.tls.is_noop());
        assert!(matches!(
            plan.status.not_programmed_reason,
            Some(NotProgrammedReason::DeploymentMissing)
        ));
    }
}
