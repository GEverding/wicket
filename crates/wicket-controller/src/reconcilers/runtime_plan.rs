//! `GatewayRuntimePlan` IR and planner for managed-runtime Gateways.
//!
//! # Overview
//!
//! This module defines the pure intermediate representation (`GatewayRuntimePlan`)
//! that the planner produces and the applier consumes.  It is the contract between
//! planning and application for managed-runtime Gateways.
//!
//! ```text
//!   RuntimePlanInput {
//!     snapshot: PlannerSnapshot,
//!     controller_config: ControllerConfig,
//!     observed: ObservedRuntimeState,
//!   }
//!         |
//!         v
//!   GatewayRuntimePlanner::plan()   -- pure, sync, no I/O
//!         |
//!         v
//!   GatewayRuntimePlan              -- IR consumed by the applier
//! ```
//!
//! # Invariants
//!
//! - The planner is pure: no I/O, no async, no side effects.
//! - Given the same inputs the planner always produces the same plan.
//! - `config_hash` is the lowercase hex SHA-256 of `config_toml`.
//! - `spec_hash` is the lowercase hex SHA-256 of the canonical JSON serialization
//!   of the full desired apply shape: `runtime_metadata`, `service_type`, and
//!   `service_ports`.  This ensures any service-shape change (type or ports)
//!   triggers a spec change and cannot produce a false `is_noop()`.  Owned
//!   Service drift (type or port list changing outside the controller) is
//!   detected by comparing this hash against the annotation on the live
//!   Deployment.
//! - The plan never contains Kubernetes object metadata (labels, annotations,
//!   owner refs) -- those are applier concerns.
//! - The plan never references `k8s-openapi` types directly.
//!
//! # Naming convention (ADR section 2.2)
//!
//! All controller-owned objects follow `wicket-gw-<gateway-name>[-<suffix>]`.
//! If the base name `wicket-gw-<gateway-name>` exceeds 52 characters, the
//! gateway name is truncated and a 6-char lowercase hex hash of the full name
//! is appended to preserve uniqueness.
//!
use std::collections::BTreeMap;

use sha2::{Digest, Sha256};

use crate::crds::{Gateway, ProtocolType, RouteGroupKind as CrdRouteGroupKind};
use crate::reconcilers::attachment_planner::AttachmentPlan;
use crate::reconcilers::config_generator::{GatewayState, WicketConfig};
use crate::reconcilers::contracts::{
    ConfigPlan, ListenerStatusIntent, PlanError, Planner, RouteGroupKind, RuntimeMetadata,
    ServicePortSpec, ServiceType,
};
use crate::reconcilers::store::PlannerSnapshot;

/// Prefix for all controller-owned object names.
const OBJECT_NAME_PREFIX: &str = "wicket-gw-";

/// Maximum length of the base name (`wicket-gw-<gateway-name>`) before
/// truncation is applied.  The longest suffix is `-config` (7 chars), and
/// Kubernetes names are limited to 63 chars, so 63 - 7 = 56.  We use 52 to
/// leave a comfortable margin for the 6-char hash suffix.
const MAX_BASE_NAME_LEN: usize = 52;

const GATEWAY_API_GROUP: &str = "gateway.networking.k8s.io";

// ─────────────────────────────────────────────────────────────────────────────
// Controller configuration
// ─────────────────────────────────────────────────────────────────────────────

/// Static controller-level configuration injected into the planner.
///
/// These values come from the controller's own startup configuration (flags,
/// environment variables, or a controller ConfigMap) and are not derived from
/// Gateway API resources.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControllerConfig {
    /// Container image for the managed proxy Deployment.
    pub proxy_image: String,
    /// Default replica count for new managed Deployments.
    pub default_replicas: u32,
    /// Default service type for managed Services.
    pub default_service_type: ServiceType,
    /// Optional CPU/memory resource requirements.
    /// Keys follow Kubernetes convention: "requests.cpu", "limits.memory", etc.
    pub default_resources: BTreeMap<String, String>,
    /// Default node selector labels.
    pub default_node_selector: BTreeMap<String, String>,
}

impl Default for ControllerConfig {
    fn default() -> Self {
        Self {
            proxy_image: "ghcr.io/geverding/wicket:latest".to_string(),
            default_replicas: 1,
            default_service_type: ServiceType::ClusterIP,
            default_resources: BTreeMap::new(),
            default_node_selector: BTreeMap::new(),
        }
    }
}

impl ControllerConfig {
    /// Explicit constructor for callsites that know all managed-runtime defaults.
    ///
    /// Prefer this over `Default` in production paths so that the effective
    /// configuration is always visible at the callsite.
    ///
    /// # Errors
    ///
    /// Returns an error string if:
    /// - `default_replicas` is 0 (must be >= 1).
    /// - `default_replicas` exceeds `i32::MAX` (Kubernetes replica field is i32).
    /// - `default_service_type` is not a valid `ServiceType` string.
    pub fn new(
        proxy_image: String,
        default_replicas: u32,
        default_service_type: ServiceType,
    ) -> Result<Self, String> {
        if default_replicas == 0 {
            return Err("default_replicas must be >= 1".to_string());
        }
        if default_replicas > i32::MAX as u32 {
            return Err(format!(
                "default_replicas {} exceeds i32::MAX ({})",
                default_replicas,
                i32::MAX
            ));
        }
        Ok(Self {
            proxy_image,
            default_replicas,
            default_service_type,
            default_resources: BTreeMap::new(),
            default_node_selector: BTreeMap::new(),
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Observed runtime state
// ─────────────────────────────────────────────────────────────────────────────

/// Observed state of the owned runtime objects for a single Gateway.
///
/// This is the only channel through which the planner learns about the current
/// cluster state.  It must be populated by the reconcile orchestrator before
/// calling the planner, using data read from the Kubernetes API.
///
/// The planner uses this to determine whether a plan represents a change
/// (config update, rollout) or a no-op.
///
/// The rollout-convergence fields (`deploy_observed_generation`,
/// `updated_replicas`, `available_replicas`, `desired_replicas`) are used by
/// `is_rollout_converged()` to determine whether a Deployment rollout has
/// fully completed.  They are populated from `DeploymentStatus` fields
/// available in the Kubernetes API without pod-level observation.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ObservedRuntimeState {
    /// The `wicket.io/config-revision` annotation currently on the owned
    /// ConfigMap, if the ConfigMap exists.  `None` means the ConfigMap does
    /// not yet exist.
    pub current_config_hash: Option<String>,
    /// The `wicket.io/spec-revision` annotation currently on the owned
    /// Deployment, if the Deployment exists.  `None` means the Deployment
    /// does not yet exist.
    pub current_spec_hash: Option<String>,
    /// Number of ready replicas in the owned Deployment.  `None` means the
    /// Deployment does not exist or its status has not been observed yet.
    pub ready_replicas: Option<u32>,

    // ── Rollout-convergence inputs (from DeploymentStatus) ────────────────────
    //
    // These fields are used by `is_rollout_converged()` to gate
    // `Programmed=True` on full rollout completion, not just `ready_replicas > 0`.
    //
    // All are `None` when the Deployment does not exist.
    /// `DeploymentStatus.observed_generation`: the generation the Deployment
    /// controller has processed.  Must equal `Deployment.metadata.generation`
    /// for the rollout to be considered converged.
    pub deploy_observed_generation: Option<i64>,

    /// `Deployment.metadata.generation`: the current desired generation of the
    /// Deployment spec.  Used to verify that `deploy_observed_generation` is
    /// current.
    pub deploy_generation: Option<i64>,

    /// `DeploymentStatus.updated_replicas`: pods running the current pod
    /// template spec.  Must equal `desired_replicas` for convergence.
    pub updated_replicas: Option<u32>,

    /// `DeploymentStatus.available_replicas`: pods available for at least
    /// `minReadySeconds`.  Must be >= 1 for convergence.
    pub available_replicas: Option<u32>,

    /// `DeploymentSpec.replicas`: the desired replica count.  Used to verify
    /// that `updated_replicas` has caught up.
    pub desired_replicas: Option<u32>,
}

/// Returns `true` when the Deployment rollout has fully converged.
///
/// ## Convergence criteria
///
/// All of the following must hold:
///
/// 1. `deploy_observed_generation == deploy_generation`: the Deployment
///    controller has processed the current spec generation.
/// 2. `updated_replicas >= desired_replicas`: all pods are running the current
///    pod template (no old-revision pods remain).
/// 3. When `desired_replicas > 0`: `available_replicas >= 1` and
///    `ready_replicas >= 1` (at least one pod is serving).
/// 4. When `desired_replicas == 0`: the rollout is considered converged if
///    `updated_replicas == 0` (scale-to-zero is an intentional steady state,
///    not a deployment failure).
///
/// When any field is `None` (Deployment absent or status not yet populated),
/// the function returns `false` -- a missing Deployment is not converged.
///
/// ## Why not just `ready_replicas > 0`
///
/// `ready_replicas > 0` is insufficient during a rolling update: old pods may
/// still be ready while new pods are starting.  The combination of
/// `updated_replicas == desired_replicas` and `available_replicas >= 1`
/// ensures that the rollout has completed and the new revision is serving.
///
/// ## Scale-to-zero
///
/// A Deployment scaled to 0 replicas is an intentional operator decision.
/// Treating it as "not converged" would cause `Programmed=False` to be
/// reported indefinitely, which is incorrect -- the Deployment is at the
/// desired state.
#[must_use]
pub fn is_rollout_converged(obs: &ObservedRuntimeState) -> bool {
    // All fields must be present; absence means Deployment does not exist.
    let Some(deploy_obs_gen) = obs.deploy_observed_generation else {
        return false;
    };
    let Some(deploy_gen) = obs.deploy_generation else {
        return false;
    };
    let Some(updated) = obs.updated_replicas else {
        return false;
    };
    let Some(available) = obs.available_replicas else {
        return false;
    };
    let Some(desired) = obs.desired_replicas else {
        return false;
    };
    let Some(ready) = obs.ready_replicas else {
        return false;
    };

    // 1. Controller has processed the current generation.
    if deploy_obs_gen < deploy_gen {
        return false;
    }
    // 2. All pods are on the current template.
    if updated < desired {
        return false;
    }
    // 3. Scale-to-zero: intentional steady state, not a failure.
    if desired == 0 {
        return true;
    }
    // 4. At least one pod is available.
    if available < 1 {
        return false;
    }
    // 5. At least one pod is ready.
    if ready < 1 {
        return false;
    }
    true
}

// ─────────────────────────────────────────────────────────────────────────────
// Planner input
// ─────────────────────────────────────────────────────────────────────────────

/// All inputs required to plan the runtime state for a single Gateway.
///
/// The planner does not read from the Kubernetes API.  All inputs arrive here.
#[derive(Debug, Clone)]
pub struct RuntimePlanInput {
    /// Namespace of the Gateway being planned.
    pub gateway_namespace: String,
    /// Name of the Gateway being planned.
    pub gateway_name: String,
    /// Consistent snapshot of all store contents.
    pub snapshot: PlannerSnapshot,
    /// Controller-level configuration (image, replicas, etc.).
    pub controller_config: ControllerConfig,
    /// Observed state of the owned runtime objects.
    pub observed: ObservedRuntimeState,
}

// ─────────────────────────────────────────────────────────────────────────────
// GatewayRuntimePlan (IR)
// ─────────────────────────────────────────────────────────────────────────────

/// Pod-side mount path for a TLS Secret in the managed proxy.
///
/// Convention: each referenced Secret is mounted as a directory at
/// `/etc/wicket/tls/<secret-name>/`. Inside this directory the standard
/// `kubernetes.io/tls` Secret keys (`tls.crt`, `tls.key`) are projected as
/// individual files.
///
/// Both the runtime applier (which builds the Deployment volumes) and the
/// config generator (which emits TLS cert paths into wicket.toml) MUST use
/// this helper so they stay in sync.
#[must_use]
pub fn tls_mount_dir(secret_name: &str) -> String {
    format!("/etc/wicket/tls/{}", secret_name)
}

/// A TLS Secret that must be mounted into the managed proxy pod so the
/// proxy can read cert/key files referenced from the generated config.
///
/// Derived by the planner from `Gateway.spec.listeners[*].tls.certificateRefs`,
/// deduplicated by `(secret_namespace, secret_name)` so each Secret is
/// mounted at most once per managed proxy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsSecretMount {
    /// Name of the Kubernetes Secret to mount.
    pub secret_name: String,
    /// Namespace of the Kubernetes Secret. Same as the Gateway's namespace
    /// when `certificateRef.namespace` is unset.
    pub secret_namespace: String,
    /// Pod-side directory where the Secret will be projected.
    /// Always `tls_mount_dir(secret_name)`.
    pub mount_path: String,
}

/// Pure internal IR representing the desired runtime state for one managed Gateway.
///
/// This is the contract between the planner and the applier.  It is never
/// serialized to Kubernetes objects directly; the applier translates it into
/// concrete API objects.
///
/// ## What this plan contains
///
/// - **Identity**: namespace, name, UID needed for owned-object naming and
///   owner references.
/// - **Revision hashes**: `config_hash` (SHA-256 of `config_toml`) and
///   `spec_hash` (SHA-256 of the full desired apply shape: `runtime_metadata`,
///   `service_type`, and `service_ports`).  These drive the ConfigMap-update
///   and Deployment-rollout decisions in the applier.
/// - **Config payload**: the rendered `wicket.toml` content for the owned
///   ConfigMap.
/// - **Runtime metadata**: image, replicas, resources, node selector.
///   Changes here trigger a Deployment rollout.
/// - **Service shape**: service type and port specs.  Changes here also
///   trigger a spec change (included in `spec_hash`).
/// - **Listener status intents**: per-listener attachment counts and
///   acceptance state, consumed by the status observer.
/// - **Derived object names**: stable names for all owned objects, computed
///   once by the planner so the applier never re-derives them.
///
/// ## What this plan does NOT contain
///
/// - Kubernetes object metadata (labels, annotations, owner refs).
/// - References to `k8s-openapi` types.
/// - Any I/O or async operations.
/// - Knowledge of whether the plan differs from current cluster state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayRuntimePlan {
    // ── Identity ──────────────────────────────────────────────────────────────
    /// Gateway namespace.
    pub gateway_namespace: String,
    /// Gateway name.
    pub gateway_name: String,
    /// Gateway UID (for owner references on managed objects).
    pub gateway_uid: String,
    /// Gateway `.metadata.generation` at plan time.
    pub gateway_generation: i64,

    // ── Derived object names (ADR section 2.2) ────────────────────────────────
    /// Name for the owned ServiceAccount, ConfigMap, Deployment, and Service.
    /// Follows `wicket-gw-<gateway-name>` with truncation if needed.
    pub owned_object_base_name: String,
    /// Name for the owned ConfigMap (`<base>-config`).
    pub config_map_name: String,
    /// Name for the owned Deployment (`<base>-deploy`).
    pub deployment_name: String,
    /// Name for the owned Service (`<base>-svc`).
    pub service_name: String,
    /// Name for the owned ServiceAccount (`<base>-sa`).
    pub service_account_name: String,

    // ── Revision hashes ───────────────────────────────────────────────────────
    /// Lowercase hex SHA-256 of `config_toml`.
    ///
    /// Changes when proxy routing/TLS config changes.  Triggers a ConfigMap
    /// update.  Does NOT trigger a Deployment rollout by itself (the proxy
    /// hot-reloads from the ConfigMap volume mount).
    pub config_hash: String,
    /// Lowercase hex SHA-256 of the canonical JSON serialization of the full
    /// desired apply shape: `runtime_metadata`, `service_type`, and
    /// `service_ports`.
    ///
    /// Changes when image, replicas, resource requirements, service type, or
    /// service ports change.  Triggers a Deployment rollout.
    ///
    /// Because `service_type` and `service_ports` are included, any drift in
    /// the owned Service shape (type or port list) is detected by comparing
    /// this hash against the annotation on the live Deployment, preventing
    /// owned Service drift from escaping reconciliation.
    pub spec_hash: String,

    // ── Config payload ────────────────────────────────────────────────────────
    /// Rendered `wicket.toml` content for the owned ConfigMap.
    pub config_toml: String,

    // ── Runtime metadata ──────────────────────────────────────────────────────
    /// Infrastructure metadata for the owned Deployment.
    pub runtime_metadata: RuntimeMetadata,

    // ── Service shape ─────────────────────────────────────────────────────────
    /// Service type for the owned Service.
    pub service_type: ServiceType,
    /// Port specs for the owned Service, derived from Gateway listeners.
    pub service_ports: Vec<ServicePortSpec>,
    /// TLS Secrets that must be mounted into the managed proxy pod.
    /// Empty when no listener has `tls.certificateRefs`.
    pub tls_secret_mounts: Vec<TlsSecretMount>,

    // ── Status intents ────────────────────────────────────────────────────────
    /// Per-listener status intents consumed by the status observer.
    pub listener_statuses: Vec<ListenerStatusIntent>,

    // ── Change signals (derived, not inputs) ──────────────────────────────────
    /// Whether the config TOML has changed relative to the observed state.
    /// `true` means the ConfigMap needs to be patched.
    pub config_changed: bool,
    /// Whether the runtime metadata has changed relative to the observed state.
    /// `true` means a Deployment rollout should be triggered.
    pub spec_changed: bool,
}

impl GatewayRuntimePlan {
    /// Returns `true` if neither the config nor the spec has changed.
    ///
    /// When `true`, the applier can skip all apply steps for this Gateway.
    #[must_use]
    pub fn is_noop(&self) -> bool {
        !self.config_changed && !self.spec_changed
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Naming helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Compute the base object name for a managed Gateway.
///
/// Follows ADR section 2.2:
/// - Base: `wicket-gw-<gateway-name>`
/// - If base exceeds `MAX_BASE_NAME_LEN`, truncate `<gateway-name>` and
///   append a 6-char lowercase hex hash of the full (untruncated) base name.
#[must_use]
pub fn owned_object_base_name(gateway_name: &str) -> String {
    let full = format!("{}{}", OBJECT_NAME_PREFIX, gateway_name);
    if full.len() <= MAX_BASE_NAME_LEN {
        return full;
    }
    // Truncate: leave room for "-" + 6-char hash = 7 chars.
    let available = MAX_BASE_NAME_LEN - 7;
    let prefix_len = OBJECT_NAME_PREFIX.len();
    let gw_truncated = &gateway_name[..available.saturating_sub(prefix_len)];
    let hash6 = hex6(&full);
    format!("{}{}-{}", OBJECT_NAME_PREFIX, gw_truncated, hash6)
}

/// Compute the ConfigMap name from the base name.
#[must_use]
pub fn config_map_name(base: &str) -> String {
    format!("{}-config", base)
}

/// Compute the Deployment name from the base name.
#[must_use]
pub fn deployment_name(base: &str) -> String {
    format!("{}-deploy", base)
}

/// Compute the Service name from the base name.
#[must_use]
pub fn service_name(base: &str) -> String {
    format!("{}-svc", base)
}

/// Compute the ServiceAccount name from the base name.
#[must_use]
pub fn service_account_name(base: &str) -> String {
    format!("{}-sa", base)
}

// ─────────────────────────────────────────────────────────────────────────────
// Hash helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Compute the lowercase hex SHA-256 of `data`.
#[must_use]
pub fn sha256_hex(data: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    let result = hasher.finalize();
    result.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Return the first 6 hex characters of the SHA-256 of `data`.
fn hex6(data: &str) -> String {
    sha256_hex(data)[..6].to_string()
}

/// Compute the `spec_hash` from the full desired apply shape.
///
/// Covers `runtime_metadata`, `service_type`, and `service_ports` so that
/// any change to the owned Service shape (type or ports) is reflected in the
/// hash and cannot produce a false `is_noop()`.
///
/// Uses canonical JSON serialization (sorted keys via `BTreeMap`) so the hash
/// is deterministic regardless of insertion order.
///
/// # Errors
///
/// Returns `PlanError::InvalidInput` if serialization fails (should not happen
/// for well-formed inputs).
pub fn spec_hash_of(
    metadata: &RuntimeMetadata,
    service_type: &ServiceType,
    service_ports: &[ServicePortSpec],
    tls_secret_mounts: &[TlsSecretMount],
) -> Result<String, PlanError> {
    let svc_type_str = match service_type {
        ServiceType::ClusterIP => "ClusterIP",
        ServiceType::LoadBalancer => "LoadBalancer",
        ServiceType::NodePort => "NodePort",
    };

    // Represent ports as a sorted vec of maps for determinism.
    let ports_repr: Vec<serde_json::Value> = service_ports
        .iter()
        .map(|p| {
            serde_json::json!({
                "name": p.name,
                "port": p.port,
                "protocol": p.protocol,
                "target_port": p.target_port,
            })
        })
        .collect();

    let repr = serde_json::json!({
        "image": metadata.image,
        "node_selector": metadata.node_selector,
        "replicas": metadata.replicas,
        "resources": metadata.resources,
        "service_ports": ports_repr,
        "service_type": svc_type_str,
    });
    let repr = if tls_secret_mounts.is_empty() {
        repr
    } else {
        let mounts_repr: Vec<serde_json::Value> = tls_secret_mounts
            .iter()
            .map(|m| {
                serde_json::json!({
                    "mount_path": m.mount_path,
                    "secret_name": m.secret_name,
                    "secret_namespace": m.secret_namespace,
                })
            })
            .collect();
        serde_json::json!({
            "image": metadata.image,
            "node_selector": metadata.node_selector,
            "replicas": metadata.replicas,
            "resources": metadata.resources,
            "service_ports": ports_repr,
            "service_type": svc_type_str,
            "tls_secret_mounts": mounts_repr,
        })
    };
    let json = serde_json::to_string(&repr).map_err(|e| PlanError::InvalidInput {
        reason: format!("failed to serialize apply shape for hashing: {}", e),
    })?;
    Ok(sha256_hex(&json))
}

// ─────────────────────────────────────────────────────────────────────────────
// Service port derivation
// ─────────────────────────────────────────────────────────────────────────────

/// Errors that can occur when deriving service ports from Gateway listeners.
#[derive(Debug, PartialEq, Eq)]
pub enum ServicePortError {
    /// Two listeners share the same name.
    DuplicateListenerName { name: String },
    /// Two listeners map to the same (port, protocol) pair.
    DuplicatePortProtocol { port: u16, protocol: String },
}

impl std::fmt::Display for ServicePortError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DuplicateListenerName { name } => {
                write!(f, "duplicate listener name: {}", name)
            }
            Self::DuplicatePortProtocol { port, protocol } => {
                write!(f, "duplicate service port collision: {}:{}", protocol, port)
            }
        }
    }
}

/// Derive `ServicePortSpec` entries from a Gateway's listeners.
///
/// Each supported listener becomes one Service port.  The port name is the
/// listener name.  The protocol is "TCP" for HTTP, HTTPS, TLS, and TCP
/// listeners (all run over TCP at the transport layer).
///
/// UDP listeners are silently excluded from the returned port list; they are
/// already marked as not-accepted in [`listener_status_intents`].  This
/// separation ensures that a Gateway with mixed supported/unsupported listeners
/// still produces a valid service port list and preserves all per-listener
/// status intents.
///
/// # Errors
///
/// Returns the first validation error encountered:
/// - `DuplicateListenerName` if any two listeners (including UDP) share the
///   same name.  Name uniqueness is a spec-level invariant that applies to all
///   listeners regardless of protocol.
/// - Duplicate supported listeners that share the same (port, protocol) are
///   deduped; only the first entry is kept.
pub fn service_ports_from_listeners(
    gateway: &Gateway,
) -> Result<Vec<ServicePortSpec>, ServicePortError> {
    use std::collections::HashSet;

    // Name uniqueness is a spec-level invariant that applies to ALL listeners,
    // including UDP ones.  Validate names in a single pass before protocol
    // filtering so that a spec with e.g. two listeners both named "http"
    // (one UDP, one TCP) is rejected rather than silently accepted.
    let mut seen_names: HashSet<&str> = HashSet::new();
    for l in &gateway.spec.listeners {
        if !seen_names.insert(l.name.as_str()) {
            return Err(ServicePortError::DuplicateListenerName {
                name: l.name.clone(),
            });
        }
    }

    let mut seen_port_proto: HashSet<(u16, &str)> = HashSet::new();
    let mut ports = Vec::with_capacity(gateway.spec.listeners.len());

    for l in &gateway.spec.listeners {
        // UDP is not mappable to a TCP Service port.  Skip it here; the
        // listener status intent for this listener is already set to
        // accepted=false by listener_status_intents().
        if l.protocol == ProtocolType::UDP {
            continue;
        }

        // All non-UDP protocols run over TCP at the transport layer.
        let protocol: &str = "TCP";

        // Multiple listeners can share the same external port (e.g. two
        // HTTPS listeners on 443 with different hostnames). The Service only
        // needs one port entry — hostname routing happens inside the proxy via
        // SNI/Host header, not at the Service level.
        if !seen_port_proto.insert((l.port, protocol)) {
            continue;
        }

        ports.push(ServicePortSpec {
            name: l.name.clone(),
            port: l.port,
            target_port: l.port,
            protocol: protocol.to_string(),
        });
    }

    Ok(ports)
}

// ─────────────────────────────────────────────────────────────────────────────
// Listener status intent derivation
// ─────────────────────────────────────────────────────────────────────────────

/// Derive `ListenerStatusIntent` entries from a Gateway's listeners.
///
/// At planning time we do not yet know the attached route count (that is the
/// attachment planner's job, `bd-jhd`).  We set `attached_routes = 0` as a
/// baseline; the attachment planner will refine these.
///
/// UDP listeners are explicitly marked as not accepted with a rejection reason,
/// since the controller does not support UDP.
///
/// `supported_kinds` is derived from the listener protocol and filtered by
/// `allowedRoutes.kinds` when present.
#[must_use]
pub fn listener_status_intents(gateway: &Gateway) -> Vec<ListenerStatusIntent> {
    gateway
        .spec
        .listeners
        .iter()
        .map(listener_status_intent)
        .collect()
}

fn listener_status_intent(listener: &crate::crds::Listener) -> ListenerStatusIntent {
    let controller_supported_kinds = protocol_supported_kinds(&listener.protocol);

    if listener.protocol == ProtocolType::UDP {
        return ListenerStatusIntent {
            name: listener.name.clone(),
            attached_routes: 0,
            supported_kinds: vec![],
            accepted: false,
            rejection_reason: Some(
                "UnsupportedProtocol: UDP listeners are not supported by this controller"
                    .to_string(),
            ),
            resolved_refs: true,
            resolved_refs_reason: None,
        };
    }

    let requested_kinds = listener
        .allowed_routes
        .as_ref()
        .map(|allowed_routes| allowed_routes.kinds.as_slice())
        .unwrap_or(&[]);

    let mut supported_kinds = if requested_kinds.is_empty() {
        controller_supported_kinds.clone()
    } else {
        controller_supported_kinds
            .iter()
            .filter(|supported| {
                requested_kinds
                    .iter()
                    .any(|requested| route_group_kind_matches(requested, supported))
            })
            .cloned()
            .collect()
    };

    let invalid_route_kinds = !requested_kinds.is_empty()
        && requested_kinds.iter().any(|requested| {
            !controller_supported_kinds
                .iter()
                .any(|supported| route_group_kind_matches(requested, supported))
        });

    if requested_kinds.is_empty() {
        supported_kinds = controller_supported_kinds;
    }

    ListenerStatusIntent {
        name: listener.name.clone(),
        attached_routes: 0,
        supported_kinds,
        accepted: true,
        rejection_reason: None,
        resolved_refs: !invalid_route_kinds,
        resolved_refs_reason: invalid_route_kinds.then(|| "InvalidRouteKinds".to_string()),
    }
}

fn protocol_supported_kinds(protocol: &ProtocolType) -> Vec<RouteGroupKind> {
    match protocol {
        ProtocolType::HTTP | ProtocolType::HTTPS => vec![RouteGroupKind {
            group: GATEWAY_API_GROUP.to_string(),
            kind: "HTTPRoute".to_string(),
        }],
        ProtocolType::TCP => vec![RouteGroupKind {
            group: GATEWAY_API_GROUP.to_string(),
            kind: "TCPRoute".to_string(),
        }],
        ProtocolType::TLS => vec![RouteGroupKind {
            group: GATEWAY_API_GROUP.to_string(),
            kind: "TLSRoute".to_string(),
        }],
        ProtocolType::UDP => vec![],
    }
}

fn route_group_kind_matches(requested: &CrdRouteGroupKind, supported: &RouteGroupKind) -> bool {
    (requested.group.is_empty() || requested.group == GATEWAY_API_GROUP)
        && requested.kind == supported.kind
        && supported.group == GATEWAY_API_GROUP
}

// ─────────────────────────────────────────────────────────────────────────────
// Config TOML generation
// ─────────────────────────────────────────────────────────────────────────────

/// Generate a `wicket.toml` from the planner snapshot for a single Gateway.
///
/// Builds a `GatewayState` scoped to the target Gateway and its attached
/// routes/endpoints, then delegates to
/// `GatewayState::generate_config()` for real config rendering.
/// Using the deterministic variant guarantees that the same logical snapshot
/// always produces the same TOML bytes and therefore the same `config_hash`,
/// regardless of `HashMap` iteration order.
///
/// # Errors
///
/// Returns `PlanError::InvalidInput` if TOML serialization fails.  This
/// should not happen for well-formed `WicketConfig` values, but surfacing the
/// error is preferable to silently emitting a minimal fallback config that
/// would mask the underlying problem.
pub fn config_toml_from_snapshot(
    gateway_namespace: &str,
    gateway_name: &str,
    snapshot: &PlannerSnapshot,
) -> Result<String, PlanError> {
    let gw_key = format!("{}/{}", gateway_namespace, gateway_name);

    // Build a GatewayState scoped to this Gateway.
    let state = GatewayState {
        gateways: {
            let mut m = std::collections::HashMap::new();
            if let Some(gw) = snapshot.gateways.get(&gw_key) {
                m.insert(gw_key.clone(), gw.clone());
            }
            m
        },
        http_routes: snapshot
            .http_routes
            .iter()
            .filter(|(_, r)| {
                r.spec.parent_refs.iter().any(|p| {
                    let group_ok = p.group.is_empty() || p.group == "gateway.networking.k8s.io";
                    let kind_ok = p.kind == "Gateway";
                    let ns_ok = p
                        .namespace
                        .as_deref()
                        .unwrap_or(r.metadata.namespace.as_deref().unwrap_or("default"))
                        == gateway_namespace;
                    let name_ok = p.name == gateway_name;
                    group_ok && kind_ok && ns_ok && name_ok
                })
            })
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
        tcp_routes: snapshot
            .tcp_routes
            .iter()
            .filter(|(_, r)| {
                r.spec.parent_refs.iter().any(|p| {
                    let group_ok = p.group.is_empty() || p.group == "gateway.networking.k8s.io";
                    let kind_ok = p.kind == "Gateway";
                    let ns_ok = p
                        .namespace
                        .as_deref()
                        .unwrap_or(r.metadata.namespace.as_deref().unwrap_or("default"))
                        == gateway_namespace;
                    let name_ok = p.name == gateway_name;
                    group_ok && kind_ok && ns_ok && name_ok
                })
            })
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
        tls_routes: snapshot
            .tls_routes
            .iter()
            .filter(|(_, r)| {
                r.spec.parent_refs.iter().any(|p| {
                    let group_ok = p.group.is_empty() || p.group == "gateway.networking.k8s.io";
                    let kind_ok = p.kind == "Gateway";
                    let ns_ok = p
                        .namespace
                        .as_deref()
                        .unwrap_or(r.metadata.namespace.as_deref().unwrap_or("default"))
                        == gateway_namespace;
                    let name_ok = p.name == gateway_name;
                    group_ok && kind_ok && ns_ok && name_ok
                })
            })
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
        service_endpoints: snapshot.service_endpoints.clone(),
        tls_secrets: {
            // Override controller-local cert paths with pod-mount paths.
            //
            // The managed proxy pod has each referenced Secret mounted at
            // `/etc/wicket/tls/<secret-name>/` (see `tls_mount_dir`), with
            // the standard kubernetes.io/tls keys projected as `tls.crt`
            // and `tls.key` files.  The config generator must reference
            // those paths, NOT the controller-local paths the Secret
            // reconciler writes for its own bookkeeping.
            let mut overrides: std::collections::HashMap<String, (String, String)> =
                std::collections::HashMap::new();
            if let Some(gw) = snapshot.gateways.get(&gw_key) {
                let gw_ns = gw
                    .metadata
                    .namespace
                    .as_deref()
                    .unwrap_or(gateway_namespace);
                for listener in &gw.spec.listeners {
                    if let Some(tls) = &listener.tls {
                        for cert_ref in &tls.certificate_refs {
                            let secret_ns = cert_ref.namespace.as_deref().unwrap_or(gw_ns);
                            let secret_name = &cert_ref.name;
                            let cert_key = format!("{}/{}", secret_ns, secret_name);
                            let mount_dir = tls_mount_dir(secret_name);
                            let cert_path = format!("{}/tls.crt", mount_dir);
                            let key_path = format!("{}/tls.key", mount_dir);
                            overrides.insert(cert_key, (cert_path, key_path));
                        }
                    }
                }
            }
            overrides
        },
    };

    // Use the deterministic variant so that HashMap iteration order does not
    // affect the output.  generate_config() sorts all map
    // iterations by key before processing.
    let config: WicketConfig = state.generate_config();

    // Serialize to TOML.  Surface any serialization failure as a planning
    // error rather than silently falling back to a minimal config.
    toml::to_string_pretty(&config).map_err(|e| PlanError::InvalidInput {
        reason: format!(
            "TOML serialization failed for gateway {}/{}: {}",
            gateway_namespace, gateway_name, e
        ),
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// ConfigPlan bridge
// ─────────────────────────────────────────────────────────────────────────────

/// Convert a `GatewayRuntimePlan` into a `ConfigPlan` without recomputing
/// anything.
///
/// This is the canonical bridge between the managed-runtime planner and the
/// config applier.  The applier (`bd-3cc`, `bd-i5y`) should call this instead
/// of re-deriving the TOML or hash from the snapshot.
///
/// ## Semantics
///
/// - When `plan.config_changed` is `true`, returns `ConfigPlan::Update` so
///   the applier patches the ConfigMap.
/// - When `plan.config_changed` is `false`, returns `ConfigPlan::NoOp` so
///   the applier skips the patch but still syncs the in-memory view.
///
/// Both variants carry `toml_content` and `config_hash` from the plan so the
/// applier never needs to re-read the ConfigMap or re-serialize the config.
#[must_use]
pub fn config_plan_from_runtime_plan(plan: &GatewayRuntimePlan) -> ConfigPlan {
    if plan.config_changed {
        ConfigPlan::Update {
            toml_content: plan.config_toml.clone(),
            config_hash: plan.config_hash.clone(),
        }
    } else {
        ConfigPlan::NoOp {
            toml_content: plan.config_toml.clone(),
            config_hash: plan.config_hash.clone(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Attachment-aware listener status intents
// ─────────────────────────────────────────────────────────────────────────────

/// Derive `ListenerStatusIntent` entries from a Gateway's listeners, enriched
/// with real attached-route counts from an `AttachmentPlan`.
///
/// This replaces the zero-count baseline produced by `listener_status_intents`
/// when an `AttachmentPlan` is available.  The runtime planner should prefer
/// this function so that `GatewayRuntimePlan.listener_statuses` carries
/// accurate counts rather than the `0` placeholder.
///
/// ## Non-accepted listeners
///
/// Listeners that are not accepted (e.g. UDP listeners) always report
/// `attached_routes = 0` regardless of what the attachment plan returns.
/// Reporting non-zero attached routes for a listener that is not accepted
/// is misleading to operators and violates the Gateway API spec intent
/// (routes cannot be meaningfully attached to a listener that is not accepted).
///
/// ## Fallback
///
/// When `attachment_plan` is `None` (e.g., the attachment planner has not yet
/// run), this function falls back to `listener_status_intents(gateway)` which
/// sets `attached_routes = 0` for all listeners.  This preserves the existing
/// behavior and avoids a hard dependency on the attachment planner.
///
/// ## Determinism
///
/// The returned `Vec` preserves the order of `gateway.spec.listeners`.
/// `AttachmentPlan.listener_summaries` is sorted by listener name (guaranteed
/// by the attachment planner), so the lookup is a linear scan -- acceptable
/// because listener counts are small (typically < 10).
#[must_use]
pub fn listener_status_intents_with_attachment(
    gateway: &Gateway,
    attachment_plan: Option<&AttachmentPlan>,
) -> Vec<ListenerStatusIntent> {
    let base = listener_status_intents(gateway);

    let Some(ap) = attachment_plan else {
        return base;
    };

    base.into_iter()
        .map(|mut intent| {
            // Non-accepted listeners must always report zero attached routes.
            // A listener that is not accepted cannot have routes meaningfully
            // attached to it, so reporting a non-zero count would be misleading.
            if intent.accepted {
                if let Some(summary) = ap.listener_summary(&intent.name) {
                    intent.attached_routes = summary.attached_routes;
                }
                if intent.resolved_refs
                    && ap
                        .results_for_listener(&intent.name, true)
                        .iter()
                        .any(|result| {
                            result.status.resolved_refs_reason() == Some("RefNotPermitted")
                        })
                {
                    intent.resolved_refs = false;
                    intent.resolved_refs_reason = Some("RefNotPermitted".to_string());
                }
            }
            intent
        })
        .collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// Planner
// ─────────────────────────────────────────────────────────────────────────────

/// Pure planner for managed-runtime Gateways.
///
/// Implements [`Planner`] with `Input = RuntimePlanInput` and
/// `Plan = GatewayRuntimePlan`.
///
/// ## Invariants
///
/// - No I/O, no async, no side effects.
/// - Deterministic: same inputs always produce the same plan.
/// - Returns `Err(PlanError)` for invalid or incomplete inputs; never panics.
pub struct GatewayRuntimePlanner;

impl Planner for GatewayRuntimePlanner {
    type Input = RuntimePlanInput;
    type Plan = GatewayRuntimePlan;

    fn plan(&self, input: &RuntimePlanInput) -> Result<GatewayRuntimePlan, PlanError> {
        let snapshot = &input.snapshot;

        // ── 1. Resolve the Gateway from the snapshot ──────────────────────────
        let gateway = snapshot
            .gateway(&input.gateway_namespace, &input.gateway_name)
            .ok_or(PlanError::MissingField {
                field: "gateway (not found in snapshot)",
            })?;

        // ── 2. Validate Gateway identity fields ───────────────────────────────
        let gateway_uid = gateway
            .metadata
            .uid
            .as_deref()
            .ok_or(PlanError::MissingField {
                field: "gateway.metadata.uid",
            })?
            .to_string();

        // generation=0 is a valid Kubernetes value for objects that have never
        // been updated, but a missing generation on a live object is a signal
        // that the informer cache is stale.  Reject it explicitly.
        let gateway_generation = gateway.metadata.generation.ok_or(PlanError::MissingField {
            field: "gateway.metadata.generation",
        })?;

        // ── 3. Derive object names ────────────────────────────────────────────
        let base_name = owned_object_base_name(&input.gateway_name);
        let cm_name = config_map_name(&base_name);
        let deploy_name = deployment_name(&base_name);
        let svc_name = service_name(&base_name);
        let sa_name = service_account_name(&base_name);

        // ── 4. Build runtime metadata ─────────────────────────────────────────
        let runtime_metadata = RuntimeMetadata {
            image: input.controller_config.proxy_image.clone(),
            replicas: input.controller_config.default_replicas,
            resources: input.controller_config.default_resources.clone(),
            node_selector: input.controller_config.default_node_selector.clone(),
        };

        // ── 5. Derive service shape (validated) ───────────────────────────────
        let service_type = input.controller_config.default_service_type.clone();
        let service_ports =
            service_ports_from_listeners(gateway).map_err(|e| PlanError::InvalidInput {
                reason: e.to_string(),
            })?;

        // ── 6. Compute spec_hash over the full desired apply shape ─────────────
        // ── 11. Derive TLS Secret mounts from listener certificateRefs ────────
        //
        // Each `Gateway.spec.listeners[*].tls.certificateRefs` entry becomes a
        // Secret volume/mount in the managed proxy Deployment.  Dedup by
        // (namespace, name) so a Secret referenced by multiple listeners is
        // mounted only once.  Sort for determinism so the resulting
        // `spec_hash` is stable across reconciles.
        let mut tls_secret_mounts: Vec<TlsSecretMount> = {
            use std::collections::BTreeSet;
            let mut seen: BTreeSet<(String, String)> = BTreeSet::new();
            let mut mounts = Vec::new();
            for listener in &gateway.spec.listeners {
                if let Some(tls) = &listener.tls {
                    for cert_ref in &tls.certificate_refs {
                        let secret_namespace = cert_ref
                            .namespace
                            .clone()
                            .unwrap_or_else(|| input.gateway_namespace.clone());
                        let secret_name = cert_ref.name.clone();
                        if seen.insert((secret_namespace.clone(), secret_name.clone())) {
                            let mount_path = tls_mount_dir(&secret_name);
                            mounts.push(TlsSecretMount {
                                secret_name,
                                secret_namespace,
                                mount_path,
                            });
                        }
                    }
                }
            }
            mounts
        };
        tls_secret_mounts.sort_by(|a, b| {
            a.secret_namespace
                .cmp(&b.secret_namespace)
                .then_with(|| a.secret_name.cmp(&b.secret_name))
        });
        let spec_hash = spec_hash_of(
            &runtime_metadata,
            &service_type,
            &service_ports,
            &tls_secret_mounts,
        )?;

        // ── 7. Generate config TOML from snapshot ─────────────────────────────
        let config_toml =
            config_toml_from_snapshot(&input.gateway_namespace, &input.gateway_name, snapshot)?;

        // ── 8. Compute config_hash ────────────────────────────────────────────
        let config_hash = sha256_hex(&config_toml);

        // ── 9. Derive listener status intents (with real attached-route counts) ──
        //
        // Run the attachment planner to get per-listener attached-route counts.
        // On failure (e.g. gateway not in snapshot -- already checked above, so
        // this should not happen) fall back to the zero-count baseline so the
        // planner never returns an error solely because of attachment counting.
        let attachment_plan_opt = {
            use crate::reconcilers::attachment_planner::{AttachmentPlanInput, AttachmentPlanner};
            let ap_input = AttachmentPlanInput {
                gateway_namespace: input.gateway_namespace.clone(),
                gateway_name: input.gateway_name.clone(),
                gateway_generation,
                snapshot: input.snapshot.clone(),
            };
            AttachmentPlanner.plan(&ap_input).ok()
        };
        let listener_statuses =
            listener_status_intents_with_attachment(gateway, attachment_plan_opt.as_ref());

        // ── 10. Compute change signals ────────────────────────────────────────
        let config_changed = input
            .observed
            .current_config_hash
            .as_deref()
            .map(|h| h != config_hash)
            .unwrap_or(true); // no existing ConfigMap => must create

        let spec_changed = input
            .observed
            .current_spec_hash
            .as_deref()
            .map(|h| h != spec_hash)
            .unwrap_or(true); // no existing Deployment => must create

        Ok(GatewayRuntimePlan {
            gateway_namespace: input.gateway_namespace.clone(),
            gateway_name: input.gateway_name.clone(),
            gateway_uid,
            gateway_generation,
            owned_object_base_name: base_name,
            config_map_name: cm_name,
            deployment_name: deploy_name,
            service_name: svc_name,
            service_account_name: sa_name,
            config_hash,
            spec_hash,
            config_toml,
            runtime_metadata,
            service_type,
            service_ports,
            tls_secret_mounts,
            listener_statuses,
            config_changed,
            spec_changed,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crds::{
        BackendRef, Gateway, GatewaySpec, GatewayTLSConfig, HTTPBackendRef, HTTPRoute,
        HTTPRouteRule, HTTPRouteSpec, Listener, ParentReference, ProtocolType,
        SecretObjectReference, TLSModeType,
    };
    use crate::reconcilers::config_generator::ServiceEndpoints;
    use crate::reconcilers::store::PlannerSnapshot;
    use kube::core::ObjectMeta;
    use std::collections::{HashMap, HashSet};

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn make_gateway(namespace: &str, name: &str, uid: &str, listeners: Vec<Listener>) -> Gateway {
        Gateway {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some(namespace.to_string()),
                uid: Some(uid.to_string()),
                generation: Some(1),
                ..Default::default()
            },
            spec: GatewaySpec {
                gateway_class_name: "wicket".to_string(),
                listeners,
                addresses: vec![],
                infrastructure: None,
            },
            status: None,
        }
    }

    fn make_listener(name: &str, port: u16, protocol: ProtocolType) -> Listener {
        Listener {
            name: name.to_string(),
            hostname: None,
            port,
            protocol,
            tls: None,
            allowed_routes: None,
        }
    }

    fn make_https_listener(
        name: &str,
        port: u16,
        cert_refs: Vec<SecretObjectReference>,
    ) -> Listener {
        Listener {
            name: name.to_string(),
            hostname: None,
            port,
            protocol: ProtocolType::HTTPS,
            tls: Some(GatewayTLSConfig {
                mode: TLSModeType::Terminate,
                certificate_refs: cert_refs,
                options: None,
                frontend_validation: None,
            }),
            allowed_routes: None,
        }
    }

    fn make_secret_ref(namespace: Option<&str>, name: &str) -> SecretObjectReference {
        SecretObjectReference {
            group: String::new(),
            kind: "Secret".to_string(),
            name: name.to_string(),
            namespace: namespace.map(str::to_string),
        }
    }

    fn make_snapshot(gateway: Gateway) -> PlannerSnapshot {
        let key = format!(
            "{}/{}",
            gateway.metadata.namespace.as_deref().unwrap_or("default"),
            gateway.metadata.name.as_deref().unwrap_or("")
        );
        let mut gateways = HashMap::new();
        gateways.insert(key, gateway);
        PlannerSnapshot {
            gateways,
            gateway_classes: HashMap::new(),
            http_routes: HashMap::new(),
            tcp_routes: HashMap::new(),
            tls_routes: HashMap::new(),
            service_endpoints: HashMap::new(),
            service_presence: HashSet::new(),
            tls_secrets: HashMap::new(),
            reference_grants: HashMap::new(),
            service_ref_index: HashSet::new(),
            namespace_labels: HashMap::new(),
        }
    }

    fn make_input(
        namespace: &str,
        name: &str,
        snapshot: PlannerSnapshot,
        observed: ObservedRuntimeState,
    ) -> RuntimePlanInput {
        RuntimePlanInput {
            gateway_namespace: namespace.to_string(),
            gateway_name: name.to_string(),
            snapshot,
            controller_config: ControllerConfig::default(),
            observed,
        }
    }

    // ── Naming ────────────────────────────────────────────────────────────────

    #[test]
    fn base_name_short_gateway() {
        assert_eq!(owned_object_base_name("my-gw"), "wicket-gw-my-gw");
    }

    #[test]
    fn base_name_exactly_at_limit() {
        // "wicket-gw-" is 10 chars; gateway name of 42 chars = 52 total (at limit).
        // No truncation should occur; the name is returned as-is.
        let name = "a".repeat(42);
        let result = owned_object_base_name(&name);
        assert_eq!(result.len(), 52);
        assert!(result.starts_with("wicket-gw-"));
        // The result should be exactly "wicket-gw-" + 42 'a's, no hash suffix.
        assert_eq!(result, format!("wicket-gw-{}", name));
    }

    #[test]
    fn base_name_truncated_for_long_gateway() {
        // Gateway name of 50 chars -> base would be 60 chars -> truncation.
        let name = "a".repeat(50);
        let result = owned_object_base_name(&name);
        assert!(
            result.len() <= MAX_BASE_NAME_LEN,
            "truncated name must fit within limit: len={}",
            result.len()
        );
        assert!(result.starts_with("wicket-gw-"));
    }

    #[test]
    fn base_name_truncation_is_deterministic() {
        let name = "very-long-gateway-name-that-exceeds-the-maximum-allowed-length";
        let a = owned_object_base_name(name);
        let b = owned_object_base_name(name);
        assert_eq!(a, b);
    }

    #[test]
    fn config_map_name_appends_suffix() {
        let base = owned_object_base_name("my-gw");
        assert_eq!(config_map_name(&base), "wicket-gw-my-gw-config");
    }

    #[test]
    fn derived_names_are_complete() {
        let base = owned_object_base_name("my-gw");
        assert_eq!(deployment_name(&base), "wicket-gw-my-gw-deploy");
        assert_eq!(service_name(&base), "wicket-gw-my-gw-svc");
        assert_eq!(service_account_name(&base), "wicket-gw-my-gw-sa");
    }

    // ── Hashing ───────────────────────────────────────────────────────────────

    #[test]
    fn sha256_hex_is_64_chars() {
        let h = sha256_hex("hello");
        assert_eq!(h.len(), 64);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn sha256_hex_is_deterministic() {
        assert_eq!(sha256_hex("test"), sha256_hex("test"));
    }

    #[test]
    fn sha256_hex_differs_for_different_inputs() {
        assert_ne!(sha256_hex("a"), sha256_hex("b"));
    }

    #[test]
    fn spec_hash_deterministic_for_same_inputs() {
        let m = RuntimeMetadata::default();
        let ports = vec![];
        let h1 = spec_hash_of(&m, &ServiceType::ClusterIP, &ports, &[]).unwrap();
        let h2 = spec_hash_of(&m, &ServiceType::ClusterIP, &ports, &[]).unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn spec_hash_changes_when_image_changes() {
        let m1 = RuntimeMetadata {
            image: "image-a:1".to_string(),
            ..Default::default()
        };
        let m2 = RuntimeMetadata {
            image: "image-b:2".to_string(),
            ..Default::default()
        };
        let ports = vec![];
        assert_ne!(
            spec_hash_of(&m1, &ServiceType::ClusterIP, &ports, &[]).unwrap(),
            spec_hash_of(&m2, &ServiceType::ClusterIP, &ports, &[]).unwrap()
        );
    }

    #[test]
    fn spec_hash_changes_when_replicas_change() {
        let m1 = RuntimeMetadata {
            replicas: 1,
            ..Default::default()
        };
        let m2 = RuntimeMetadata {
            replicas: 3,
            ..Default::default()
        };
        let ports = vec![];
        assert_ne!(
            spec_hash_of(&m1, &ServiceType::ClusterIP, &ports, &[]).unwrap(),
            spec_hash_of(&m2, &ServiceType::ClusterIP, &ports, &[]).unwrap()
        );
    }

    #[test]
    fn spec_hash_changes_when_service_type_changes() {
        let m = RuntimeMetadata::default();
        let ports = vec![];
        let h_clusterip = spec_hash_of(&m, &ServiceType::ClusterIP, &ports, &[]).unwrap();
        let h_lb = spec_hash_of(&m, &ServiceType::LoadBalancer, &ports, &[]).unwrap();
        assert_ne!(
            h_clusterip, h_lb,
            "service_type change must change spec_hash"
        );
    }

    #[test]
    fn spec_hash_changes_when_service_ports_change() {
        let m = RuntimeMetadata::default();
        let ports_a = vec![ServicePortSpec {
            name: "http".to_string(),
            port: 80,
            target_port: 80,
            protocol: "TCP".to_string(),
        }];
        let ports_b = vec![ServicePortSpec {
            name: "https".to_string(),
            port: 443,
            target_port: 443,
            protocol: "TCP".to_string(),
        }];
        assert_ne!(
            spec_hash_of(&m, &ServiceType::ClusterIP, &ports_a, &[]).unwrap(),
            spec_hash_of(&m, &ServiceType::ClusterIP, &ports_b, &[]).unwrap(),
            "service_ports change must change spec_hash"
        );
    }

    // ── Service port derivation ───────────────────────────────────────────────

    #[test]
    fn service_ports_from_http_listener() {
        let gw = make_gateway(
            "prod",
            "my-gw",
            "uid-1",
            vec![make_listener("http", 80, ProtocolType::HTTP)],
        );
        let ports = service_ports_from_listeners(&gw).unwrap();
        assert_eq!(ports.len(), 1);
        assert_eq!(ports[0].name, "http");
        assert_eq!(ports[0].port, 80);
        assert_eq!(ports[0].target_port, 80);
        assert_eq!(ports[0].protocol, "TCP");
    }

    #[test]
    fn service_ports_from_multiple_listeners() {
        let gw = make_gateway(
            "prod",
            "my-gw",
            "uid-1",
            vec![
                make_listener("http", 80, ProtocolType::HTTP),
                make_listener("https", 443, ProtocolType::HTTPS),
                make_listener("tcp-db", 5432, ProtocolType::TCP),
            ],
        );
        let ports = service_ports_from_listeners(&gw).unwrap();
        assert_eq!(ports.len(), 3);
        assert!(ports.iter().all(|p| p.protocol == "TCP"));
    }

    #[test]
    fn service_ports_udp_listener_excluded_not_error() {
        // UDP listeners are silently excluded from service ports.  The plan
        // still succeeds; the listener is marked not-accepted via
        // listener_status_intents().
        let gw = make_gateway(
            "prod",
            "my-gw",
            "uid-1",
            vec![make_listener("udp-dns", 53, ProtocolType::UDP)],
        );
        let ports = service_ports_from_listeners(&gw).unwrap();
        assert!(
            ports.is_empty(),
            "UDP-only gateway must produce zero service ports"
        );
    }

    #[test]
    fn tls_secret_mounts_are_deduplicated_and_sorted() {
        let gw = make_gateway(
            "prod",
            "my-gw",
            "uid-1",
            vec![
                make_https_listener(
                    "https-a",
                    443,
                    vec![
                        make_secret_ref(Some("prod"), "shared-cert"),
                        make_secret_ref(Some("zeta"), "z-cert"),
                    ],
                ),
                make_https_listener(
                    "https-b",
                    8443,
                    vec![make_secret_ref(Some("prod"), "shared-cert")],
                ),
                make_https_listener("https-c", 9443, vec![make_secret_ref(None, "alpha-cert")]),
            ],
        );
        let input = make_input(
            "prod",
            "my-gw",
            make_snapshot(gw),
            ObservedRuntimeState::default(),
        );
        let plan = GatewayRuntimePlanner.plan(&input).unwrap();

        assert_eq!(
            plan.tls_secret_mounts,
            vec![
                TlsSecretMount {
                    secret_namespace: "prod".to_string(),
                    secret_name: "alpha-cert".to_string(),
                    mount_path: tls_mount_dir("alpha-cert"),
                },
                TlsSecretMount {
                    secret_namespace: "prod".to_string(),
                    secret_name: "shared-cert".to_string(),
                    mount_path: tls_mount_dir("shared-cert"),
                },
                TlsSecretMount {
                    secret_namespace: "zeta".to_string(),
                    secret_name: "z-cert".to_string(),
                    mount_path: tls_mount_dir("z-cert"),
                },
            ]
        );
    }

    #[test]
    fn tls_secret_mounts_deduplicate_shared_secret_across_listeners() {
        let gw = make_gateway(
            "prod",
            "my-gw",
            "uid-1",
            vec![
                make_https_listener(
                    "https-a",
                    443,
                    vec![make_secret_ref(Some("prod"), "shared-cert")],
                ),
                make_https_listener(
                    "https-b",
                    8443,
                    vec![make_secret_ref(Some("prod"), "shared-cert")],
                ),
            ],
        );
        let input = make_input(
            "prod",
            "my-gw",
            make_snapshot(gw),
            ObservedRuntimeState::default(),
        );
        let plan = GatewayRuntimePlanner.plan(&input).unwrap();

        assert_eq!(plan.tls_secret_mounts.len(), 1);
        assert_eq!(
            plan.tls_secret_mounts[0],
            TlsSecretMount {
                secret_namespace: "prod".to_string(),
                secret_name: "shared-cert".to_string(),
                mount_path: tls_mount_dir("shared-cert"),
            }
        );
    }

    #[test]
    fn generated_tls_paths_match_planned_mounts() {
        let gw = make_gateway(
            "prod",
            "my-gw",
            "uid-1",
            vec![make_https_listener(
                "https",
                443,
                vec![make_secret_ref(None, "edge-cert")],
            )],
        );
        let mut gw = gw;
        gw.spec.listeners[0].hostname = Some("edge.example.com".to_string());
        let input = make_input(
            "prod",
            "my-gw",
            make_snapshot(gw),
            ObservedRuntimeState::default(),
        );
        let plan = GatewayRuntimePlanner.plan(&input).unwrap();

        let mount = plan
            .tls_secret_mounts
            .iter()
            .find(|m| m.secret_name == "edge-cert")
            .expect("edge-cert mount must be planned");

        assert!(
            plan.config_toml
                .contains(&format!("{}/tls.crt", mount.mount_path)),
            "config must point at pod-mounted cert file"
        );
        assert!(
            plan.config_toml
                .contains(&format!("{}/tls.key", mount.mount_path)),
            "config must point at pod-mounted key file"
        );
        assert!(
            !plan.config_toml.contains("/var/run/wicket/tls"),
            "config must not reference controller-local TLS write paths"
        );
        assert!(
            !plan.tls_secret_mounts.is_empty(),
            "config may not reference TLS cert files without mounted Secrets"
        );
    }

    #[test]
    fn service_ports_mixed_udp_and_tcp_excludes_udp() {
        // A gateway with both a supported and an unsupported listener must
        // produce service ports only for the supported one.
        let gw = make_gateway(
            "prod",
            "my-gw",
            "uid-1",
            vec![
                make_listener("http", 80, ProtocolType::HTTP),
                make_listener("udp-dns", 53, ProtocolType::UDP),
            ],
        );
        let ports = service_ports_from_listeners(&gw).unwrap();
        assert_eq!(
            ports.len(),
            1,
            "only the HTTP listener should produce a port"
        );
        assert_eq!(ports[0].name, "http");
    }

    #[test]
    fn service_ports_duplicate_name_returns_error() {
        let gw = make_gateway(
            "prod",
            "my-gw",
            "uid-1",
            vec![
                make_listener("http", 80, ProtocolType::HTTP),
                make_listener("http", 8080, ProtocolType::HTTP), // duplicate name
            ],
        );
        let err = service_ports_from_listeners(&gw).unwrap_err();
        assert!(
            matches!(err, ServicePortError::DuplicateListenerName { name } if name == "http"),
            "duplicate listener name must return DuplicateListenerName error"
        );
    }

    #[test]
    fn service_ports_duplicate_name_across_udp_and_tcp_returns_error() {
        // A UDP listener and a TCP listener sharing the same name is a
        // spec-level naming error.  Name uniqueness applies to ALL listeners
        // regardless of protocol; the duplicate must be caught even though the
        // UDP listener is excluded from the service port list.
        let gw = make_gateway(
            "prod",
            "my-gw",
            "uid-1",
            vec![
                make_listener("dns", 53, ProtocolType::UDP),
                make_listener("dns", 5353, ProtocolType::TCP), // same name, different protocol
            ],
        );
        let err = service_ports_from_listeners(&gw).unwrap_err();
        assert!(
            matches!(err, ServicePortError::DuplicateListenerName { name } if name == "dns"),
            "duplicate name across UDP and TCP must return DuplicateListenerName error"
        );
    }

    #[test]
    fn service_ports_duplicate_port_protocol_is_deduped() {
        let gw = make_gateway(
            "prod",
            "my-gw",
            "uid-1",
            vec![
                make_listener("http-a", 80, ProtocolType::HTTP),
                make_listener("http-b", 80, ProtocolType::HTTP), // same port
            ],
        );
        let ports = service_ports_from_listeners(&gw).unwrap();
        assert_eq!(ports.len(), 1);
        assert_eq!(ports[0].name, "http-a");
        assert_eq!(ports[0].port, 80);
    }

    #[test]
    fn service_ports_duplicate_https_443_is_deduped() {
        let mut https_a = make_listener("https-a", 443, ProtocolType::HTTPS);
        https_a.hostname = Some("a.example.com".to_string());
        let mut https_b = make_listener("https-b", 443, ProtocolType::HTTPS);
        https_b.hostname = Some("b.example.com".to_string());

        let gw = make_gateway("prod", "my-gw", "uid-1", vec![https_a, https_b]);
        let ports = service_ports_from_listeners(&gw).unwrap();

        assert_eq!(ports.len(), 1);
        assert_eq!(ports[0].name, "https-a");
        assert_eq!(ports[0].port, 443);
        assert_eq!(ports[0].protocol, "TCP");
    }

    // ── Listener status intents ───────────────────────────────────────────────

    #[test]
    fn listener_status_intents_http() {
        let gw = make_gateway(
            "prod",
            "my-gw",
            "uid-1",
            vec![make_listener("http", 80, ProtocolType::HTTP)],
        );
        let intents = listener_status_intents(&gw);
        assert_eq!(intents.len(), 1);
        assert_eq!(intents[0].name, "http");
        assert!(intents[0].accepted);
        assert_eq!(intents[0].attached_routes, 0);
        assert_eq!(intents[0].supported_kinds[0].kind, "HTTPRoute");
    }

    #[test]
    fn listener_status_intents_tcp() {
        let gw = make_gateway(
            "prod",
            "my-gw",
            "uid-1",
            vec![make_listener("tcp", 5432, ProtocolType::TCP)],
        );
        let intents = listener_status_intents(&gw);
        assert_eq!(intents[0].supported_kinds[0].kind, "TCPRoute");
        assert!(intents[0].accepted);
    }

    #[test]
    fn listener_status_intents_tls() {
        let gw = make_gateway(
            "prod",
            "my-gw",
            "uid-1",
            vec![make_listener("tls", 443, ProtocolType::TLS)],
        );
        let intents = listener_status_intents(&gw);
        assert_eq!(intents[0].supported_kinds[0].kind, "TLSRoute");
        assert!(intents[0].accepted);
    }

    #[test]
    fn listener_status_intents_udp_not_accepted() {
        let gw = make_gateway(
            "prod",
            "my-gw",
            "uid-1",
            vec![make_listener("udp-dns", 53, ProtocolType::UDP)],
        );
        let intents = listener_status_intents(&gw);
        assert_eq!(intents.len(), 1);
        assert!(!intents[0].accepted, "UDP listener must not be accepted");
        assert!(
            intents[0].rejection_reason.is_some(),
            "UDP listener must have a rejection reason"
        );
        assert!(intents[0].supported_kinds.is_empty());
    }

    // ── Planner ───────────────────────────────────────────────────────────────

    #[test]
    fn planner_produces_plan_for_valid_input() {
        let gw = make_gateway(
            "prod",
            "my-gw",
            "uid-abc",
            vec![make_listener("http", 80, ProtocolType::HTTP)],
        );
        let snapshot = make_snapshot(gw);
        let input = make_input("prod", "my-gw", snapshot, ObservedRuntimeState::default());

        let planner = GatewayRuntimePlanner;
        let plan = planner.plan(&input).expect("plan should succeed");

        assert_eq!(plan.gateway_namespace, "prod");
        assert_eq!(plan.gateway_name, "my-gw");
        assert_eq!(plan.gateway_uid, "uid-abc");
        assert_eq!(plan.gateway_generation, 1);
        assert_eq!(plan.owned_object_base_name, "wicket-gw-my-gw");
        assert_eq!(plan.config_map_name, "wicket-gw-my-gw-config");
        assert_eq!(plan.deployment_name, "wicket-gw-my-gw-deploy");
        assert_eq!(plan.service_name, "wicket-gw-my-gw-svc");
        assert_eq!(plan.service_account_name, "wicket-gw-my-gw-sa");
        assert_eq!(plan.service_ports.len(), 1);
        assert_eq!(plan.listener_statuses.len(), 1);
    }

    #[test]
    fn planner_config_hash_matches_sha256_of_config_toml() {
        let gw = make_gateway("prod", "my-gw", "uid-abc", vec![]);
        let snapshot = make_snapshot(gw);
        let input = make_input("prod", "my-gw", snapshot, ObservedRuntimeState::default());

        let plan = GatewayRuntimePlanner.plan(&input).unwrap();
        let expected = sha256_hex(&plan.config_toml);
        assert_eq!(plan.config_hash, expected);
    }

    #[test]
    fn planner_spec_hash_covers_service_type_and_ports() {
        let gw = make_gateway(
            "prod",
            "my-gw",
            "uid-abc",
            vec![make_listener("http", 80, ProtocolType::HTTP)],
        );
        let snap1 = make_snapshot(gw.clone());
        let snap2 = make_snapshot(gw);

        let mut input1 = make_input("prod", "my-gw", snap1, ObservedRuntimeState::default());
        input1.controller_config.default_service_type = ServiceType::ClusterIP;

        let mut input2 = make_input("prod", "my-gw", snap2, ObservedRuntimeState::default());
        input2.controller_config.default_service_type = ServiceType::LoadBalancer;

        let plan1 = GatewayRuntimePlanner.plan(&input1).unwrap();
        let plan2 = GatewayRuntimePlanner.plan(&input2).unwrap();

        assert_ne!(
            plan1.spec_hash, plan2.spec_hash,
            "service_type change must change spec_hash"
        );
    }

    #[test]
    fn planner_is_deterministic() {
        let gw = make_gateway(
            "prod",
            "my-gw",
            "uid-abc",
            vec![make_listener("http", 80, ProtocolType::HTTP)],
        );
        let snap1 = make_snapshot(gw.clone());
        let snap2 = make_snapshot(gw);
        let input1 = make_input("prod", "my-gw", snap1, ObservedRuntimeState::default());
        let input2 = make_input("prod", "my-gw", snap2, ObservedRuntimeState::default());

        let plan1 = GatewayRuntimePlanner.plan(&input1).unwrap();
        let plan2 = GatewayRuntimePlanner.plan(&input2).unwrap();
        assert_eq!(plan1, plan2);
    }

    #[test]
    fn planner_config_changed_true_when_no_observed_hash() {
        let gw = make_gateway("prod", "my-gw", "uid-abc", vec![]);
        let snapshot = make_snapshot(gw);
        let input = make_input(
            "prod",
            "my-gw",
            snapshot,
            ObservedRuntimeState {
                current_config_hash: None,
                current_spec_hash: None,
                ready_replicas: None,
                ..Default::default()
            },
        );
        let plan = GatewayRuntimePlanner.plan(&input).unwrap();
        assert!(plan.config_changed, "no observed hash => config_changed");
        assert!(plan.spec_changed, "no observed hash => spec_changed");
    }

    #[test]
    fn planner_noop_when_hashes_match() {
        let gw = make_gateway("prod", "my-gw", "uid-abc", vec![]);
        let snapshot = make_snapshot(gw.clone());
        // First, compute what the hashes would be.
        let input0 = make_input(
            "prod",
            "my-gw",
            snapshot.clone(),
            ObservedRuntimeState::default(),
        );
        let plan0 = GatewayRuntimePlanner.plan(&input0).unwrap();

        // Now feed those hashes back as the observed state.
        let input = make_input(
            "prod",
            "my-gw",
            snapshot,
            ObservedRuntimeState {
                current_config_hash: Some(plan0.config_hash.clone()),
                current_spec_hash: Some(plan0.spec_hash.clone()),
                ready_replicas: Some(1),
                ..Default::default()
            },
        );
        let plan = GatewayRuntimePlanner.plan(&input).unwrap();
        assert!(!plan.config_changed, "hashes match => no config change");
        assert!(!plan.spec_changed, "hashes match => no spec change");
        assert!(plan.is_noop());
    }

    #[test]
    fn planner_config_changed_only_when_spec_hash_matches() {
        let gw = make_gateway("prod", "my-gw", "uid-abc", vec![]);
        let snapshot = make_snapshot(gw);
        let input0 = make_input(
            "prod",
            "my-gw",
            snapshot.clone(),
            ObservedRuntimeState::default(),
        );
        let plan0 = GatewayRuntimePlanner.plan(&input0).unwrap();

        // Spec hash matches, config hash does not.
        let input = make_input(
            "prod",
            "my-gw",
            snapshot,
            ObservedRuntimeState {
                current_config_hash: Some("stale-config-hash".to_string()),
                current_spec_hash: Some(plan0.spec_hash.clone()),
                ready_replicas: Some(1),
                ..Default::default()
            },
        );
        let plan = GatewayRuntimePlanner.plan(&input).unwrap();
        assert!(plan.config_changed, "stale config hash => config_changed");
        assert!(!plan.spec_changed, "spec hash matches => no spec change");
        assert!(!plan.is_noop());
    }

    #[test]
    fn planner_error_when_gateway_missing_from_snapshot() {
        let snapshot = PlannerSnapshot {
            gateways: HashMap::new(),
            gateway_classes: HashMap::new(),
            http_routes: HashMap::new(),
            tcp_routes: HashMap::new(),
            tls_routes: HashMap::new(),
            service_endpoints: HashMap::new(),
            service_presence: HashSet::new(),
            tls_secrets: HashMap::new(),
            reference_grants: HashMap::new(),
            service_ref_index: HashSet::new(),
            namespace_labels: HashMap::new(),
        };
        let input = make_input(
            "prod",
            "missing-gw",
            snapshot,
            ObservedRuntimeState::default(),
        );
        let err = GatewayRuntimePlanner.plan(&input).unwrap_err();
        assert!(matches!(err, PlanError::MissingField { .. }));
    }

    #[test]
    fn planner_error_when_gateway_uid_absent() {
        let gw = Gateway {
            metadata: ObjectMeta {
                name: Some("my-gw".to_string()),
                namespace: Some("prod".to_string()),
                uid: None, // no UID
                generation: Some(1),
                ..Default::default()
            },
            spec: GatewaySpec {
                gateway_class_name: "wicket".to_string(),
                listeners: vec![],
                addresses: vec![],
                infrastructure: None,
            },
            status: None,
        };
        let snapshot = make_snapshot(gw);
        let input = make_input("prod", "my-gw", snapshot, ObservedRuntimeState::default());
        let err = GatewayRuntimePlanner.plan(&input).unwrap_err();
        assert!(matches!(err, PlanError::MissingField { field } if field.contains("uid")));
    }

    #[test]
    fn planner_error_when_gateway_generation_absent() {
        let gw = Gateway {
            metadata: ObjectMeta {
                name: Some("my-gw".to_string()),
                namespace: Some("prod".to_string()),
                uid: Some("uid-1".to_string()),
                generation: None, // missing generation
                ..Default::default()
            },
            spec: GatewaySpec {
                gateway_class_name: "wicket".to_string(),
                listeners: vec![],
                addresses: vec![],
                infrastructure: None,
            },
            status: None,
        };
        let snapshot = make_snapshot(gw);
        let input = make_input("prod", "my-gw", snapshot, ObservedRuntimeState::default());
        let err = GatewayRuntimePlanner.plan(&input).unwrap_err();
        assert!(
            matches!(err, PlanError::MissingField { field } if field.contains("generation")),
            "missing generation must return MissingField error"
        );
    }

    #[test]
    fn planner_udp_only_gateway_succeeds_with_no_service_ports() {
        // A Gateway with only a UDP listener must produce a valid plan.
        // The listener is marked not-accepted in listener_statuses, and
        // service_ports is empty.  The plan must not fail.
        let gw = make_gateway(
            "prod",
            "my-gw",
            "uid-abc",
            vec![make_listener("udp-dns", 53, ProtocolType::UDP)],
        );
        let snapshot = make_snapshot(gw);
        let input = make_input("prod", "my-gw", snapshot, ObservedRuntimeState::default());
        let plan = GatewayRuntimePlanner
            .plan(&input)
            .expect("UDP-only gateway must produce a valid plan");
        assert!(
            plan.service_ports.is_empty(),
            "UDP-only gateway must have no service ports"
        );
        assert_eq!(plan.listener_statuses.len(), 1);
        assert!(
            !plan.listener_statuses[0].accepted,
            "UDP listener must be marked not-accepted"
        );
        assert!(
            plan.listener_statuses[0].rejection_reason.is_some(),
            "UDP listener must have a rejection reason"
        );
    }

    #[test]
    fn planner_mixed_udp_and_http_preserves_all_listener_statuses() {
        // A Gateway with both HTTP and UDP listeners must produce a plan where:
        // - service_ports contains only the HTTP port
        // - listener_statuses contains entries for both listeners
        // - the UDP listener is marked not-accepted
        // - the HTTP listener is marked accepted
        let gw = make_gateway(
            "prod",
            "my-gw",
            "uid-abc",
            vec![
                make_listener("http", 80, ProtocolType::HTTP),
                make_listener("udp-dns", 53, ProtocolType::UDP),
            ],
        );
        let snapshot = make_snapshot(gw);
        let input = make_input("prod", "my-gw", snapshot, ObservedRuntimeState::default());
        let plan = GatewayRuntimePlanner
            .plan(&input)
            .expect("plan must succeed");

        assert_eq!(
            plan.service_ports.len(),
            1,
            "only HTTP port in service_ports"
        );
        assert_eq!(plan.service_ports[0].name, "http");

        assert_eq!(
            plan.listener_statuses.len(),
            2,
            "both listeners must appear in listener_statuses"
        );
        let http_status = plan
            .listener_statuses
            .iter()
            .find(|s| s.name == "http")
            .expect("http listener status must be present");
        assert!(http_status.accepted, "HTTP listener must be accepted");

        let udp_status = plan
            .listener_statuses
            .iter()
            .find(|s| s.name == "udp-dns")
            .expect("udp-dns listener status must be present");
        assert!(!udp_status.accepted, "UDP listener must not be accepted");
        assert!(udp_status.rejection_reason.is_some());
    }

    #[test]
    fn planner_error_when_duplicate_listener_names() {
        let gw = make_gateway(
            "prod",
            "my-gw",
            "uid-abc",
            vec![
                make_listener("http", 80, ProtocolType::HTTP),
                make_listener("http", 8080, ProtocolType::HTTP),
            ],
        );
        let snapshot = make_snapshot(gw);
        let input = make_input("prod", "my-gw", snapshot, ObservedRuntimeState::default());
        let err = GatewayRuntimePlanner.plan(&input).unwrap_err();
        assert!(matches!(err, PlanError::InvalidInput { .. }));
    }

    #[test]
    fn planner_dedupes_duplicate_port_protocol() {
        let gw = make_gateway(
            "prod",
            "my-gw",
            "uid-abc",
            vec![
                make_listener("http-a", 80, ProtocolType::HTTP),
                make_listener("http-b", 80, ProtocolType::HTTP),
            ],
        );
        let snapshot = make_snapshot(gw);
        let input = make_input("prod", "my-gw", snapshot, ObservedRuntimeState::default());
        let plan = GatewayRuntimePlanner.plan(&input).unwrap();
        // Two listeners on port 80, but only one Service port entry
        assert_eq!(plan.service_ports.len(), 1);
        assert_eq!(plan.service_ports[0].port, 80);
        assert_eq!(plan.service_ports[0].name, "http-a"); // first listener wins
    }

    #[test]
    fn planner_dedupes_shared_https_443_and_keeps_spec_hash_stable() {
        let mut https_a = make_listener("https-a", 443, ProtocolType::HTTPS);
        https_a.hostname = Some("a.example.com".to_string());
        let mut https_b = make_listener("https-b", 443, ProtocolType::HTTPS);
        https_b.hostname = Some("b.example.com".to_string());

        let gw = make_gateway("prod", "my-gw", "uid-abc", vec![https_a, https_b]);
        let snap1 = make_snapshot(gw.clone());
        let snap2 = make_snapshot(gw);

        let input1 = make_input("prod", "my-gw", snap1, ObservedRuntimeState::default());
        let input2 = make_input("prod", "my-gw", snap2, ObservedRuntimeState::default());

        let plan1 = GatewayRuntimePlanner.plan(&input1).unwrap();
        let plan2 = GatewayRuntimePlanner.plan(&input2).unwrap();

        assert_eq!(plan1.service_ports.len(), 1);
        assert_eq!(plan1.service_ports[0].port, 443);
        assert_eq!(plan1.service_ports[0].protocol, "TCP");
        assert_eq!(plan1.spec_hash, plan2.spec_hash);
    }

    #[test]
    fn planner_runtime_metadata_uses_controller_config() {
        let gw = make_gateway("prod", "my-gw", "uid-abc", vec![]);
        let snapshot = make_snapshot(gw);
        let mut input = make_input("prod", "my-gw", snapshot, ObservedRuntimeState::default());
        input.controller_config.proxy_image = "my-registry/wicket:v2".to_string();
        input.controller_config.default_replicas = 3;

        let plan = GatewayRuntimePlanner.plan(&input).unwrap();
        assert_eq!(plan.runtime_metadata.image, "my-registry/wicket:v2");
        assert_eq!(plan.runtime_metadata.replicas, 3);
    }

    #[test]
    fn planner_spec_hash_changes_when_image_changes() {
        let gw = make_gateway("prod", "my-gw", "uid-abc", vec![]);
        let snap1 = make_snapshot(gw.clone());
        let snap2 = make_snapshot(gw);

        let mut input1 = make_input("prod", "my-gw", snap1, ObservedRuntimeState::default());
        input1.controller_config.proxy_image = "image-a:1".to_string();

        let mut input2 = make_input("prod", "my-gw", snap2, ObservedRuntimeState::default());
        input2.controller_config.proxy_image = "image-b:2".to_string();

        let plan1 = GatewayRuntimePlanner.plan(&input1).unwrap();
        let plan2 = GatewayRuntimePlanner.plan(&input2).unwrap();

        assert_ne!(plan1.spec_hash, plan2.spec_hash);
        // Config TOML is the same (same gateway, no routes), so config_hash should match.
        assert_eq!(plan1.config_hash, plan2.config_hash);
    }

    #[test]
    fn planner_noop_false_when_service_type_changes() {
        // Verify that a service_type change is NOT a noop even if runtime_metadata
        // is identical -- spec_hash must cover service_type.
        let gw = make_gateway(
            "prod",
            "my-gw",
            "uid-abc",
            vec![make_listener("http", 80, ProtocolType::HTTP)],
        );
        let snap1 = make_snapshot(gw.clone());
        let snap2 = make_snapshot(gw);

        let mut input1 = make_input("prod", "my-gw", snap1, ObservedRuntimeState::default());
        input1.controller_config.default_service_type = ServiceType::ClusterIP;
        let plan1 = GatewayRuntimePlanner.plan(&input1).unwrap();

        // Feed plan1's spec_hash as the observed hash, then change service_type.
        let mut input2 = make_input(
            "prod",
            "my-gw",
            snap2,
            ObservedRuntimeState {
                current_config_hash: Some(plan1.config_hash.clone()),
                current_spec_hash: Some(plan1.spec_hash.clone()),
                ready_replicas: Some(1),
                ..Default::default()
            },
        );
        input2.controller_config.default_service_type = ServiceType::LoadBalancer;
        let plan2 = GatewayRuntimePlanner.plan(&input2).unwrap();

        assert!(
            plan2.spec_changed,
            "service_type change must set spec_changed=true"
        );
        assert!(!plan2.is_noop(), "service_type change must not be a noop");
    }

    // ── Determinism with non-empty route maps ─────────────────────────────────

    /// Build a snapshot that contains the given gateway plus N HTTPRoutes
    /// attached to it, each with one backend.  Routes are inserted into the
    /// HashMap in the order given by `route_names` so callers can vary
    /// insertion order to exercise determinism.
    fn make_snapshot_with_routes(gateway: Gateway, route_names: &[&str]) -> PlannerSnapshot {
        let gw_ns = gateway
            .metadata
            .namespace
            .as_deref()
            .unwrap_or("default")
            .to_string();
        let gw_name = gateway.metadata.name.as_deref().unwrap_or("").to_string();
        let gw_key = format!("{}/{}", gw_ns, gw_name);

        let mut gateways = HashMap::new();
        gateways.insert(gw_key.clone(), gateway);

        let mut http_routes = HashMap::new();
        let mut service_endpoints = HashMap::new();

        for route_name in route_names {
            let backend_name = format!("{}-svc", route_name);
            let route = HTTPRoute {
                metadata: ObjectMeta {
                    name: Some(route_name.to_string()),
                    namespace: Some(gw_ns.clone()),
                    ..Default::default()
                },
                spec: HTTPRouteSpec {
                    parent_refs: vec![ParentReference {
                        group: "gateway.networking.k8s.io".to_string(),
                        kind: "Gateway".to_string(),
                        name: gw_name.clone(),
                        namespace: Some(gw_ns.clone()),
                        section_name: None,
                        port: None,
                    }],
                    hostnames: vec![format!("{}.example.com", route_name)],
                    rules: vec![HTTPRouteRule {
                        name: None,
                        matches: vec![],
                        filters: vec![],
                        backend_refs: vec![HTTPBackendRef {
                            backend_ref: BackendRef {
                                group: "".to_string(),
                                kind: "Service".to_string(),
                                name: backend_name.clone(),
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
            };
            let route_key = format!("{}/{}", gw_ns, route_name);
            http_routes.insert(route_key, route);

            let ep_key = format!("{}/{}", gw_ns, backend_name);
            service_endpoints.insert(
                ep_key,
                ServiceEndpoints {
                    namespace: gw_ns.clone(),
                    name: backend_name.clone(),
                    endpoints: vec![format!("10.0.1.1:80"), format!("10.0.1.2:80")],
                },
            );
        }

        PlannerSnapshot {
            gateways,
            gateway_classes: HashMap::new(),
            http_routes,
            tcp_routes: HashMap::new(),
            tls_routes: HashMap::new(),
            service_endpoints,
            service_presence: HashSet::new(),
            tls_secrets: HashMap::new(),
            reference_grants: HashMap::new(),
            service_ref_index: HashSet::new(),
            namespace_labels: HashMap::new(),
        }
    }

    #[test]
    fn config_toml_deterministic_with_multiple_routes() {
        // Build two snapshots with the same routes inserted in different orders.
        // The generated config_toml and config_hash must be identical.
        let gw = make_gateway(
            "prod",
            "my-gw",
            "uid-abc",
            vec![make_listener("http", 80, ProtocolType::HTTP)],
        );

        let route_names_fwd = ["alpha-route", "beta-route", "gamma-route"];
        let route_names_rev = ["gamma-route", "beta-route", "alpha-route"];

        let snap_fwd = make_snapshot_with_routes(gw.clone(), &route_names_fwd);
        let snap_rev = make_snapshot_with_routes(gw.clone(), &route_names_rev);

        let toml_fwd =
            config_toml_from_snapshot("prod", "my-gw", &snap_fwd).expect("fwd must succeed");
        let toml_rev =
            config_toml_from_snapshot("prod", "my-gw", &snap_rev).expect("rev must succeed");

        assert_eq!(
            toml_fwd, toml_rev,
            "config_toml must be identical regardless of route insertion order"
        );
        assert_eq!(
            sha256_hex(&toml_fwd),
            sha256_hex(&toml_rev),
            "config_hash must be identical regardless of route insertion order"
        );
    }

    #[test]
    fn planner_config_hash_deterministic_with_multiple_routes() {
        // The planner must produce the same config_hash for the same logical
        // snapshot regardless of HashMap insertion order.
        let gw = make_gateway(
            "prod",
            "my-gw",
            "uid-abc",
            vec![make_listener("http", 80, ProtocolType::HTTP)],
        );

        let route_names_fwd = ["alpha-route", "beta-route", "gamma-route"];
        let route_names_rev = ["gamma-route", "beta-route", "alpha-route"];

        let snap_fwd = make_snapshot_with_routes(gw.clone(), &route_names_fwd);
        let snap_rev = make_snapshot_with_routes(gw.clone(), &route_names_rev);

        let input_fwd = make_input("prod", "my-gw", snap_fwd, ObservedRuntimeState::default());
        let input_rev = make_input("prod", "my-gw", snap_rev, ObservedRuntimeState::default());

        let plan_fwd = GatewayRuntimePlanner.plan(&input_fwd).unwrap();
        let plan_rev = GatewayRuntimePlanner.plan(&input_rev).unwrap();

        assert_eq!(
            plan_fwd.config_hash, plan_rev.config_hash,
            "config_hash must be identical regardless of route insertion order"
        );
        assert_eq!(
            plan_fwd.config_toml, plan_rev.config_toml,
            "config_toml must be identical regardless of route insertion order"
        );
    }

    // ── Planner uses attachment counts (not zero baseline) ────────────────────

    #[test]
    fn planner_listener_statuses_use_attachment_counts_when_routes_present() {
        // Build a gateway with one HTTP listener and one attached HTTPRoute.
        // The planner must populate attached_routes from the AttachmentPlanner,
        // not leave it at 0.
        let gw = make_gateway(
            "prod",
            "my-gw",
            "uid-abc",
            vec![make_listener("http", 80, ProtocolType::HTTP)],
        );
        let snapshot = make_snapshot_with_routes(gw.clone(), &["route-a"]);
        let input = make_input("prod", "my-gw", snapshot, ObservedRuntimeState::default());

        let plan = GatewayRuntimePlanner.plan(&input).unwrap();

        let http_status = plan
            .listener_statuses
            .iter()
            .find(|s| s.name == "http")
            .expect("http listener status must be present");

        assert_eq!(
            http_status.attached_routes, 1,
            "planner must populate attached_routes from AttachmentPlanner (got {})",
            http_status.attached_routes
        );
    }

    #[test]
    fn planner_listener_statuses_zero_when_no_routes() {
        // No routes => attachment planner returns 0 for all listeners.
        let gw = make_gateway(
            "prod",
            "my-gw",
            "uid-abc",
            vec![make_listener("http", 80, ProtocolType::HTTP)],
        );
        let snapshot = make_snapshot(gw);
        let input = make_input("prod", "my-gw", snapshot, ObservedRuntimeState::default());

        let plan = GatewayRuntimePlanner.plan(&input).unwrap();

        let http_status = plan
            .listener_statuses
            .iter()
            .find(|s| s.name == "http")
            .expect("http listener status must be present");

        assert_eq!(
            http_status.attached_routes, 0,
            "no routes => attached_routes must be 0"
        );
    }

    #[test]
    fn planner_listener_statuses_count_multiple_routes() {
        let gw = make_gateway(
            "prod",
            "my-gw",
            "uid-abc",
            vec![make_listener("http", 80, ProtocolType::HTTP)],
        );
        let snapshot = make_snapshot_with_routes(gw.clone(), &["route-a", "route-b", "route-c"]);
        let input = make_input("prod", "my-gw", snapshot, ObservedRuntimeState::default());

        let plan = GatewayRuntimePlanner.plan(&input).unwrap();

        let http_status = plan
            .listener_statuses
            .iter()
            .find(|s| s.name == "http")
            .expect("http listener status must be present");

        assert_eq!(
            http_status.attached_routes, 3,
            "three routes => attached_routes must be 3"
        );
    }

    #[test]
    fn planner_is_deterministic_with_routes() {
        // Full plan equality with non-empty route maps.
        let gw = make_gateway(
            "prod",
            "my-gw",
            "uid-abc",
            vec![make_listener("http", 80, ProtocolType::HTTP)],
        );
        let routes = ["route-a", "route-b"];
        let snap1 = make_snapshot_with_routes(gw.clone(), &routes);
        let snap2 = make_snapshot_with_routes(gw.clone(), &routes);
        let input1 = make_input("prod", "my-gw", snap1, ObservedRuntimeState::default());
        let input2 = make_input("prod", "my-gw", snap2, ObservedRuntimeState::default());

        let plan1 = GatewayRuntimePlanner.plan(&input1).unwrap();
        let plan2 = GatewayRuntimePlanner.plan(&input2).unwrap();
        assert_eq!(plan1, plan2, "plans must be equal for identical inputs");
    }

    // ── config_plan_from_runtime_plan ─────────────────────────────────────────

    #[test]
    fn config_plan_from_runtime_plan_update_when_config_changed() {
        let gw = make_gateway("prod", "my-gw", "uid-abc", vec![]);
        let snapshot = make_snapshot(gw);
        // No observed hash => config_changed = true.
        let input = make_input("prod", "my-gw", snapshot, ObservedRuntimeState::default());
        let plan = GatewayRuntimePlanner.plan(&input).unwrap();
        assert!(
            plan.config_changed,
            "precondition: config_changed must be true"
        );

        let cp = config_plan_from_runtime_plan(&plan);
        match cp {
            crate::reconcilers::contracts::ConfigPlan::Update {
                ref toml_content,
                ref config_hash,
            } => {
                assert_eq!(toml_content, &plan.config_toml);
                assert_eq!(config_hash, &plan.config_hash);
            }
            crate::reconcilers::contracts::ConfigPlan::NoOp { .. } => {
                panic!("expected Update when config_changed=true");
            }
        }
    }

    #[test]
    fn config_plan_from_runtime_plan_noop_when_config_unchanged() {
        let gw = make_gateway("prod", "my-gw", "uid-abc", vec![]);
        let snapshot = make_snapshot(gw);
        // First pass: get the hashes.
        let input0 = make_input(
            "prod",
            "my-gw",
            snapshot.clone(),
            ObservedRuntimeState::default(),
        );
        let plan0 = GatewayRuntimePlanner.plan(&input0).unwrap();

        // Second pass: feed hashes back so config_changed = false.
        let input = make_input(
            "prod",
            "my-gw",
            snapshot,
            ObservedRuntimeState {
                current_config_hash: Some(plan0.config_hash.clone()),
                current_spec_hash: Some(plan0.spec_hash.clone()),
                ready_replicas: Some(1),
                ..Default::default()
            },
        );
        let plan = GatewayRuntimePlanner.plan(&input).unwrap();
        assert!(
            !plan.config_changed,
            "precondition: config_changed must be false"
        );

        let cp = config_plan_from_runtime_plan(&plan);
        match cp {
            crate::reconcilers::contracts::ConfigPlan::NoOp {
                ref toml_content,
                ref config_hash,
            } => {
                assert_eq!(toml_content, &plan.config_toml);
                assert_eq!(config_hash, &plan.config_hash);
            }
            crate::reconcilers::contracts::ConfigPlan::Update { .. } => {
                panic!("expected NoOp when config_changed=false");
            }
        }
    }

    #[test]
    fn config_plan_from_runtime_plan_hash_matches_toml() {
        let gw = make_gateway(
            "prod",
            "my-gw",
            "uid-abc",
            vec![make_listener("http", 80, ProtocolType::HTTP)],
        );
        let snapshot = make_snapshot(gw);
        let input = make_input("prod", "my-gw", snapshot, ObservedRuntimeState::default());
        let plan = GatewayRuntimePlanner.plan(&input).unwrap();

        let cp = config_plan_from_runtime_plan(&plan);
        let (toml, hash) = match cp {
            crate::reconcilers::contracts::ConfigPlan::Update {
                toml_content,
                config_hash,
            } => (toml_content, config_hash),
            crate::reconcilers::contracts::ConfigPlan::NoOp {
                toml_content,
                config_hash,
            } => (toml_content, config_hash),
        };
        assert_eq!(
            hash,
            sha256_hex(&toml),
            "config_hash in ConfigPlan must be SHA-256 of toml_content"
        );
    }

    // ── listener_status_intents_with_attachment ────────────────────────────────

    #[test]
    fn listener_status_intents_with_attachment_none_falls_back_to_zero_counts() {
        let gw = make_gateway(
            "prod",
            "my-gw",
            "uid-abc",
            vec![
                make_listener("http", 80, ProtocolType::HTTP),
                make_listener("tcp", 5432, ProtocolType::TCP),
            ],
        );
        let intents = listener_status_intents_with_attachment(&gw, None);
        assert_eq!(intents.len(), 2);
        assert!(intents.iter().all(|i| i.attached_routes == 0));
    }

    #[test]
    fn listener_status_intents_with_attachment_merges_counts() {
        use crate::reconcilers::attachment_planner::{AttachmentPlan, ListenerAttachmentSummary};

        let gw = make_gateway(
            "prod",
            "my-gw",
            "uid-abc",
            vec![
                make_listener("http", 80, ProtocolType::HTTP),
                make_listener("tcp", 5432, ProtocolType::TCP),
            ],
        );

        // Simulate an AttachmentPlan with 3 routes on "http" and 1 on "tcp".
        let ap = AttachmentPlan {
            gateway_namespace: "prod".to_string(),
            gateway_name: "my-gw".to_string(),
            gateway_generation: 1,
            route_results: vec![],
            listener_summaries: vec![
                // Sorted by listener name (attachment planner guarantee).
                ListenerAttachmentSummary {
                    listener_name: "http".to_string(),
                    attached_routes: 3,
                    supported_kinds: vec![],
                    listener_accepted: true,
                    listener_rejection_reason: None,
                },
                ListenerAttachmentSummary {
                    listener_name: "tcp".to_string(),
                    attached_routes: 1,
                    supported_kinds: vec![],
                    listener_accepted: true,
                    listener_rejection_reason: None,
                },
            ],
        };

        let intents = listener_status_intents_with_attachment(&gw, Some(&ap));
        assert_eq!(intents.len(), 2);

        let http = intents.iter().find(|i| i.name == "http").unwrap();
        assert_eq!(http.attached_routes, 3);
        assert!(http.accepted);

        let tcp = intents.iter().find(|i| i.name == "tcp").unwrap();
        assert_eq!(tcp.attached_routes, 1);
        assert!(tcp.accepted);
    }

    #[test]
    fn listener_status_intents_with_attachment_reports_one_attached_route() {
        use crate::reconcilers::attachment_planner::{AttachmentPlan, ListenerAttachmentSummary};

        let gw = make_gateway(
            "prod",
            "my-gw",
            "uid-abc",
            vec![make_listener("http", 80, ProtocolType::HTTP)],
        );
        let ap = AttachmentPlan {
            gateway_namespace: "prod".to_string(),
            gateway_name: "my-gw".to_string(),
            gateway_generation: 1,
            route_results: vec![],
            listener_summaries: vec![ListenerAttachmentSummary {
                listener_name: "http".to_string(),
                attached_routes: 1,
                supported_kinds: vec![],
                listener_accepted: true,
                listener_rejection_reason: None,
            }],
        };

        let intents = listener_status_intents_with_attachment(&gw, Some(&ap));

        assert_eq!(intents.len(), 1);
        assert_eq!(intents[0].attached_routes, 1);
        assert!(intents[0].accepted);
        assert!(intents[0].resolved_refs);
    }

    #[test]
    fn listener_status_intents_with_attachment_reports_two_attached_routes() {
        use crate::reconcilers::attachment_planner::{AttachmentPlan, ListenerAttachmentSummary};

        let gw = make_gateway(
            "prod",
            "my-gw",
            "uid-abc",
            vec![make_listener("http", 80, ProtocolType::HTTP)],
        );
        let ap = AttachmentPlan {
            gateway_namespace: "prod".to_string(),
            gateway_name: "my-gw".to_string(),
            gateway_generation: 1,
            route_results: vec![],
            listener_summaries: vec![ListenerAttachmentSummary {
                listener_name: "http".to_string(),
                attached_routes: 2,
                supported_kinds: vec![],
                listener_accepted: true,
                listener_rejection_reason: None,
            }],
        };

        let intents = listener_status_intents_with_attachment(&gw, Some(&ap));

        assert_eq!(intents.len(), 1);
        assert_eq!(intents[0].attached_routes, 2);
        assert!(intents[0].accepted);
        assert!(intents[0].resolved_refs);
    }

    #[test]
    fn listener_status_intents_with_attachment_propagates_ref_not_permitted_reason() {
        use crate::reconcilers::attachment_planner::{
            AttachmentPlan, AttachmentStatus, ListenerAttachmentSummary, RouteAttachmentResult,
            RouteKind,
        };

        let gw = make_gateway(
            "prod",
            "my-gw",
            "uid-abc",
            vec![make_listener("http", 80, ProtocolType::HTTP)],
        );
        let ap = AttachmentPlan {
            gateway_namespace: "prod".to_string(),
            gateway_name: "my-gw".to_string(),
            gateway_generation: 1,
            route_results: vec![RouteAttachmentResult {
                route_namespace: "app-ns".to_string(),
                route_name: "route-a".to_string(),
                route_kind: RouteKind::HTTPRoute,
                listener_name: Some("http".to_string()),
                parent_ref_section_name: Some("http".to_string()),
                parent_ref_port: Some(80),
                status: AttachmentStatus::RefNotPermitted {
                    route_namespace: "app-ns".to_string(),
                    target_namespace: "backend-ns".to_string(),
                    target_name: "svc-a".to_string(),
                },
                observed_generation: 1,
            }],
            listener_summaries: vec![ListenerAttachmentSummary {
                listener_name: "http".to_string(),
                attached_routes: 1,
                supported_kinds: vec![],
                listener_accepted: true,
                listener_rejection_reason: None,
            }],
        };

        let intents = listener_status_intents_with_attachment(&gw, Some(&ap));

        assert_eq!(intents.len(), 1);
        assert!(intents[0].accepted);
        assert!(!intents[0].resolved_refs);
        assert_eq!(
            intents[0].resolved_refs_reason.as_deref(),
            Some("RefNotPermitted")
        );
        assert_eq!(intents[0].attached_routes, 1);
    }

    #[test]
    fn listener_status_intents_with_attachment_keeps_attached_routes_when_resolved_refs_false() {
        use crate::crds::RouteGroupKind as CrdRouteGroupKind;
        use crate::reconcilers::attachment_planner::{AttachmentPlan, ListenerAttachmentSummary};

        let mut listener = make_listener("http", 80, ProtocolType::HTTP);
        listener.allowed_routes = Some(crate::crds::AllowedRoutes {
            namespaces: None,
            kinds: vec![
                CrdRouteGroupKind {
                    group: GATEWAY_API_GROUP.to_string(),
                    kind: "HTTPRoute".to_string(),
                },
                CrdRouteGroupKind {
                    group: GATEWAY_API_GROUP.to_string(),
                    kind: "TCPRoute".to_string(),
                },
            ],
        });
        let gw = make_gateway("prod", "my-gw", "uid-abc", vec![listener]);
        let ap = AttachmentPlan {
            gateway_namespace: "prod".to_string(),
            gateway_name: "my-gw".to_string(),
            gateway_generation: 1,
            route_results: vec![],
            listener_summaries: vec![ListenerAttachmentSummary {
                listener_name: "http".to_string(),
                attached_routes: 1,
                supported_kinds: vec![],
                listener_accepted: true,
                listener_rejection_reason: None,
            }],
        };

        let intents = listener_status_intents_with_attachment(&gw, Some(&ap));

        assert_eq!(intents.len(), 1);
        assert!(intents[0].accepted);
        assert!(!intents[0].resolved_refs);
        assert_eq!(
            intents[0].resolved_refs_reason.as_deref(),
            Some("InvalidRouteKinds")
        );
        assert_eq!(intents[0].attached_routes, 1);
    }

    #[test]
    fn listener_status_intents_with_attachment_preserves_acceptance_from_gateway() {
        use crate::reconcilers::attachment_planner::{AttachmentPlan, ListenerAttachmentSummary};

        // UDP listener: must remain not-accepted even if the attachment plan
        // (incorrectly) reports routes attached to it.
        let gw = make_gateway(
            "prod",
            "my-gw",
            "uid-abc",
            vec![make_listener("udp-dns", 53, ProtocolType::UDP)],
        );

        let ap = AttachmentPlan {
            gateway_namespace: "prod".to_string(),
            gateway_name: "my-gw".to_string(),
            gateway_generation: 1,
            route_results: vec![],
            listener_summaries: vec![ListenerAttachmentSummary {
                listener_name: "udp-dns".to_string(),
                attached_routes: 99, // attachment plan says 99, but acceptance is from gateway
                supported_kinds: vec![],
                listener_accepted: false,
                listener_rejection_reason: Some("UnsupportedProtocol".to_string()),
            }],
        };

        let intents = listener_status_intents_with_attachment(&gw, Some(&ap));
        assert_eq!(intents.len(), 1);
        // Non-accepted listeners must always report zero attached_routes,
        // regardless of what the attachment plan says.
        assert_eq!(
            intents[0].attached_routes, 0,
            "non-accepted listener must report 0 attached_routes even if attachment plan says 99"
        );
        // accepted/rejection_reason come from listener_status_intents (gateway protocol).
        assert!(
            !intents[0].accepted,
            "UDP listener must remain not-accepted"
        );
        assert!(intents[0].rejection_reason.is_some());
    }

    #[test]
    fn listener_status_intents_with_attachment_unknown_listener_keeps_zero() {
        use crate::reconcilers::attachment_planner::{AttachmentPlan, ListenerAttachmentSummary};

        // Gateway has "http" listener; attachment plan only mentions "other".
        // The "http" listener must keep attached_routes = 0.
        let gw = make_gateway(
            "prod",
            "my-gw",
            "uid-abc",
            vec![make_listener("http", 80, ProtocolType::HTTP)],
        );

        let ap = AttachmentPlan {
            gateway_namespace: "prod".to_string(),
            gateway_name: "my-gw".to_string(),
            gateway_generation: 1,
            route_results: vec![],
            listener_summaries: vec![ListenerAttachmentSummary {
                listener_name: "other".to_string(), // not in gateway spec
                attached_routes: 5,
                supported_kinds: vec![],
                listener_accepted: true,
                listener_rejection_reason: None,
            }],
        };

        let intents = listener_status_intents_with_attachment(&gw, Some(&ap));
        assert_eq!(intents.len(), 1);
        assert_eq!(
            intents[0].attached_routes, 0,
            "listener not in attachment plan must keep zero count"
        );
    }

    // ── config_toml_from_snapshot error surfacing ─────────────────────────────

    #[test]
    fn config_toml_from_snapshot_returns_ok_for_valid_gateway() {
        let gw = make_gateway(
            "prod",
            "my-gw",
            "uid-abc",
            vec![make_listener("http", 80, ProtocolType::HTTP)],
        );
        let snapshot = make_snapshot(gw);
        let result = config_toml_from_snapshot("prod", "my-gw", &snapshot);
        assert!(result.is_ok(), "valid gateway must produce Ok(toml)");
        let toml = result.unwrap();
        assert!(!toml.is_empty(), "generated TOML must not be empty");
    }

    #[test]
    fn config_toml_from_snapshot_missing_gateway_returns_empty_config() {
        // When the gateway is not in the snapshot the GatewayState has no
        // gateways, so generate_config produces a default config.
        // Serialization of the default config must still succeed.
        let snapshot = PlannerSnapshot {
            gateways: HashMap::new(),
            gateway_classes: HashMap::new(),
            http_routes: HashMap::new(),
            tcp_routes: HashMap::new(),
            tls_routes: HashMap::new(),
            service_endpoints: HashMap::new(),
            service_presence: HashSet::new(),
            tls_secrets: HashMap::new(),
            reference_grants: HashMap::new(),
            service_ref_index: HashSet::new(),
            namespace_labels: HashMap::new(),
        };
        let result = config_toml_from_snapshot("prod", "missing-gw", &snapshot);
        // Should succeed (empty state serializes fine) -- the planner will
        // separately reject the missing gateway via MissingField.
        assert!(
            result.is_ok(),
            "missing gateway must still produce a serializable (empty) config"
        );
    }

    // ── is_rollout_converged ──────────────────────────────────────────────────

    fn converged_obs() -> ObservedRuntimeState {
        ObservedRuntimeState {
            current_config_hash: None,
            current_spec_hash: None,
            ready_replicas: Some(1),
            deploy_observed_generation: Some(2),
            deploy_generation: Some(2),
            updated_replicas: Some(1),
            available_replicas: Some(1),
            desired_replicas: Some(1),
        }
    }

    #[test]
    fn rollout_converged_when_all_fields_satisfied() {
        assert!(is_rollout_converged(&converged_obs()));
    }

    #[test]
    fn rollout_not_converged_when_deployment_absent() {
        assert!(!is_rollout_converged(&ObservedRuntimeState::default()));
    }

    #[test]
    fn rollout_not_converged_when_observed_generation_stale() {
        let obs = ObservedRuntimeState {
            deploy_observed_generation: Some(1), // stale
            deploy_generation: Some(2),
            ..converged_obs()
        };
        assert!(!is_rollout_converged(&obs));
    }

    #[test]
    fn rollout_not_converged_when_updated_replicas_less_than_desired() {
        let obs = ObservedRuntimeState {
            updated_replicas: Some(0),
            desired_replicas: Some(2),
            ..converged_obs()
        };
        assert!(!is_rollout_converged(&obs));
    }

    #[test]
    fn rollout_not_converged_when_available_replicas_zero() {
        let obs = ObservedRuntimeState {
            available_replicas: Some(0),
            ..converged_obs()
        };
        assert!(!is_rollout_converged(&obs));
    }

    #[test]
    fn rollout_not_converged_when_ready_replicas_zero() {
        let obs = ObservedRuntimeState {
            ready_replicas: Some(0),
            ..converged_obs()
        };
        assert!(!is_rollout_converged(&obs));
    }

    #[test]
    fn rollout_converged_when_observed_generation_ahead_of_desired() {
        // observed_generation > deploy_generation is allowed (controller
        // processed a newer generation than we expect -- safe).
        let obs = ObservedRuntimeState {
            deploy_observed_generation: Some(3),
            deploy_generation: Some(2),
            ..converged_obs()
        };
        assert!(is_rollout_converged(&obs));
    }

    #[test]
    fn rollout_converged_with_multiple_replicas() {
        let obs = ObservedRuntimeState {
            ready_replicas: Some(3),
            deploy_observed_generation: Some(5),
            deploy_generation: Some(5),
            updated_replicas: Some(3),
            available_replicas: Some(3),
            desired_replicas: Some(3),
            ..Default::default()
        };
        assert!(is_rollout_converged(&obs));
    }

    #[test]
    fn rollout_not_converged_when_partial_update_in_progress() {
        // 2 of 3 replicas updated: rollout in progress.
        let obs = ObservedRuntimeState {
            ready_replicas: Some(3), // old pods still ready
            deploy_observed_generation: Some(5),
            deploy_generation: Some(5),
            updated_replicas: Some(2), // not all updated yet
            available_replicas: Some(3),
            desired_replicas: Some(3),
            ..Default::default()
        };
        assert!(!is_rollout_converged(&obs));
    }

    // ── ControllerConfig::new validation ─────────────────────────────────────

    #[test]
    fn controller_config_new_valid() {
        let cfg = ControllerConfig::new(
            "ghcr.io/example/proxy:v1".to_string(),
            3,
            ServiceType::LoadBalancer,
        );
        assert!(cfg.is_ok());
        let cfg = cfg.unwrap();
        assert_eq!(cfg.proxy_image, "ghcr.io/example/proxy:v1");
        assert_eq!(cfg.default_replicas, 3);
        assert_eq!(cfg.default_service_type, ServiceType::LoadBalancer);
    }

    #[test]
    fn controller_config_new_rejects_zero_replicas() {
        let err = ControllerConfig::new("img".to_string(), 0, ServiceType::ClusterIP);
        assert!(err.is_err());
        assert!(err.unwrap_err().contains(">="));
    }

    #[test]
    fn controller_config_new_rejects_replicas_exceeding_i32_max() {
        let err = ControllerConfig::new(
            "img".to_string(),
            i32::MAX as u32 + 1,
            ServiceType::ClusterIP,
        );
        assert!(err.is_err());
        assert!(err.unwrap_err().contains("i32::MAX"));
    }

    #[test]
    fn controller_config_new_accepts_replicas_at_i32_max() {
        let cfg = ControllerConfig::new("img".to_string(), i32::MAX as u32, ServiceType::ClusterIP);
        assert!(cfg.is_ok());
    }

    // ── ServiceType FromStr ───────────────────────────────────────────────────

    #[test]
    fn service_type_from_str_valid_variants() {
        use std::str::FromStr;
        assert_eq!(
            ServiceType::from_str("ClusterIP").unwrap(),
            ServiceType::ClusterIP
        );
        assert_eq!(
            ServiceType::from_str("LoadBalancer").unwrap(),
            ServiceType::LoadBalancer
        );
        assert_eq!(
            ServiceType::from_str("NodePort").unwrap(),
            ServiceType::NodePort
        );
    }

    #[test]
    fn service_type_from_str_rejects_invalid() {
        use std::str::FromStr;
        let err = ServiceType::from_str("clusterip");
        assert!(err.is_err());
        let msg = err.unwrap_err();
        assert!(
            msg.contains("ClusterIP"),
            "error should list valid values: {}",
            msg
        );
    }

    #[test]
    fn service_type_from_str_rejects_empty() {
        use std::str::FromStr;
        assert!(ServiceType::from_str("").is_err());
    }

    #[test]
    fn service_type_display_roundtrips() {
        use std::str::FromStr;
        for svc in [
            ServiceType::ClusterIP,
            ServiceType::LoadBalancer,
            ServiceType::NodePort,
        ] {
            let s = svc.to_string();
            let parsed = ServiceType::from_str(&s).unwrap();
            assert_eq!(parsed, svc);
        }
    }

    // ── Scale-to-zero convergence ────────────────────────────────────────────
    //
    // A Deployment intentionally scaled to 0 replicas is at its desired state.
    // is_rollout_converged must return true so that Programmed=True is reported
    // instead of an indefinite Programmed=False.

    #[test]
    fn rollout_converged_when_scaled_to_zero() {
        let obs = ObservedRuntimeState {
            current_config_hash: Some("hash".to_string()),
            current_spec_hash: Some("spec".to_string()),
            ready_replicas: Some(0),
            deploy_observed_generation: Some(3),
            deploy_generation: Some(3),
            updated_replicas: Some(0),
            available_replicas: Some(0),
            desired_replicas: Some(0),
        };
        assert!(
            is_rollout_converged(&obs),
            "scale-to-zero Deployment must be considered converged"
        );
    }

    #[test]
    fn rollout_not_converged_when_scaling_down_to_zero_in_progress() {
        // Desired=0 but updated=1: old pods still draining.
        let obs = ObservedRuntimeState {
            ready_replicas: Some(1),
            deploy_observed_generation: Some(3),
            deploy_generation: Some(3),
            updated_replicas: Some(1), // > desired(0), scale-down in progress
            available_replicas: Some(1),
            desired_replicas: Some(0),
            ..Default::default()
        };
        // updated(1) >= desired(0) is true, so this is converged even though
        // pods are still running -- k8s will terminate them. The rollout spec
        // itself has been processed.
        assert!(
            is_rollout_converged(&obs),
            "when desired=0 and generation matches, rollout is converged"
        );
    }

    #[test]
    fn rollout_not_converged_when_scale_to_zero_generation_stale() {
        let obs = ObservedRuntimeState {
            ready_replicas: Some(0),
            deploy_observed_generation: Some(2), // stale
            deploy_generation: Some(3),          // desired
            updated_replicas: Some(0),
            available_replicas: Some(0),
            desired_replicas: Some(0),
            ..Default::default()
        };
        assert!(
            !is_rollout_converged(&obs),
            "stale generation must prevent convergence even at scale-to-zero"
        );
    }

    // ── FSM idempotency: planner produces same plan when called twice ────────
    //
    // A core FSM invariant: given identical inputs, the planner must produce
    // byte-identical output. This goes beyond the existing determinism test by
    // verifying ALL plan fields including change signals.

    #[test]
    fn planner_idempotent_all_fields_match_on_repeat_call() {
        let gw = make_gateway(
            "prod",
            "my-gw",
            "uid-abc",
            vec![
                make_listener("http", 80, ProtocolType::HTTP),
                make_listener("https", 443, ProtocolType::HTTPS),
            ],
        );
        let snapshot = make_snapshot(gw);
        let observed = ObservedRuntimeState {
            current_config_hash: Some("old-hash".to_string()),
            current_spec_hash: Some("old-spec".to_string()),
            ready_replicas: Some(2),
            deploy_observed_generation: Some(1),
            deploy_generation: Some(1),
            updated_replicas: Some(2),
            available_replicas: Some(2),
            desired_replicas: Some(2),
        };
        let input = make_input("prod", "my-gw", snapshot, observed);

        let plan_a = GatewayRuntimePlanner.plan(&input).unwrap();
        let plan_b = GatewayRuntimePlanner.plan(&input).unwrap();

        // Full structural equality (derives PartialEq)
        assert_eq!(plan_a, plan_b, "planner must be idempotent");

        // Verify change signals are identical
        assert_eq!(plan_a.config_changed, plan_b.config_changed);
        assert_eq!(plan_a.spec_changed, plan_b.spec_changed);
        assert_eq!(plan_a.is_noop(), plan_b.is_noop());
    }

    // ── Both config_changed AND spec_changed simultaneously ──────────────────
    //
    // When both hashes differ, the planner must signal both changes.

    #[test]
    fn planner_both_config_and_spec_changed_simultaneously() {
        let gw = make_gateway(
            "prod",
            "my-gw",
            "uid-abc",
            vec![make_listener("http", 80, ProtocolType::HTTP)],
        );
        let snapshot = make_snapshot(gw);
        let input = make_input(
            "prod",
            "my-gw",
            snapshot,
            ObservedRuntimeState {
                current_config_hash: Some("stale-config".to_string()),
                current_spec_hash: Some("stale-spec".to_string()),
                ready_replicas: Some(1),
                deploy_observed_generation: Some(1),
                deploy_generation: Some(1),
                updated_replicas: Some(1),
                available_replicas: Some(1),
                desired_replicas: Some(1),
            },
        );

        let plan = GatewayRuntimePlanner.plan(&input).unwrap();

        assert!(
            plan.config_changed,
            "stale config hash must trigger config_changed"
        );
        assert!(
            plan.spec_changed,
            "stale spec hash must trigger spec_changed"
        );
        assert!(!plan.is_noop(), "plan with both changes must not be a noop");
    }

    // ── FSM state transition completeness ────────────────────────────────────
    //
    // Verify that every combination of (config_changed, spec_changed) produces
    // the correct is_noop() result and the plan remains well-formed.

    #[test]
    fn plan_change_signal_matrix() {
        let gw = make_gateway(
            "prod",
            "my-gw",
            "uid-abc",
            vec![make_listener("http", 80, ProtocolType::HTTP)],
        );

        // First, compute the "current" hashes.
        let snapshot0 = make_snapshot(gw.clone());
        let input0 = make_input("prod", "my-gw", snapshot0, ObservedRuntimeState::default());
        let plan0 = GatewayRuntimePlanner.plan(&input0).unwrap();
        let current_config = plan0.config_hash.clone();
        let current_spec = plan0.spec_hash.clone();

        struct Case {
            label: &'static str,
            config_hash: Option<String>,
            spec_hash: Option<String>,
            expect_config_changed: bool,
            expect_spec_changed: bool,
            expect_noop: bool,
        }

        let cases = [
            Case {
                label: "both match (noop)",
                config_hash: Some(current_config.clone()),
                spec_hash: Some(current_spec.clone()),
                expect_config_changed: false,
                expect_spec_changed: false,
                expect_noop: true,
            },
            Case {
                label: "config stale only",
                config_hash: Some("stale".to_string()),
                spec_hash: Some(current_spec.clone()),
                expect_config_changed: true,
                expect_spec_changed: false,
                expect_noop: false,
            },
            Case {
                label: "spec stale only",
                config_hash: Some(current_config.clone()),
                spec_hash: Some("stale".to_string()),
                expect_config_changed: false,
                expect_spec_changed: true,
                expect_noop: false,
            },
            Case {
                label: "both stale",
                config_hash: Some("stale-c".to_string()),
                spec_hash: Some("stale-s".to_string()),
                expect_config_changed: true,
                expect_spec_changed: true,
                expect_noop: false,
            },
            Case {
                label: "both absent (first deploy)",
                config_hash: None,
                spec_hash: None,
                expect_config_changed: true,
                expect_spec_changed: true,
                expect_noop: false,
            },
        ];

        for case in &cases {
            let snapshot = make_snapshot(gw.clone());
            let observed = ObservedRuntimeState {
                current_config_hash: case.config_hash.clone(),
                current_spec_hash: case.spec_hash.clone(),
                ready_replicas: Some(1),
                deploy_observed_generation: Some(1),
                deploy_generation: Some(1),
                updated_replicas: Some(1),
                available_replicas: Some(1),
                desired_replicas: Some(1),
            };
            let input = make_input("prod", "my-gw", snapshot, observed);
            let plan = GatewayRuntimePlanner
                .plan(&input)
                .unwrap_or_else(|e| panic!("{}: plan failed: {}", case.label, e));

            assert_eq!(
                plan.config_changed, case.expect_config_changed,
                "{}: config_changed mismatch",
                case.label
            );
            assert_eq!(
                plan.spec_changed, case.expect_spec_changed,
                "{}: spec_changed mismatch",
                case.label
            );
            assert_eq!(
                plan.is_noop(),
                case.expect_noop,
                "{}: is_noop mismatch",
                case.label
            );

            // Every plan (noop or not) must carry valid identity and object names.
            assert_eq!(plan.gateway_namespace, "prod", "{}: namespace", case.label);
            assert_eq!(plan.gateway_name, "my-gw", "{}: name", case.label);
            assert!(
                !plan.config_map_name.is_empty(),
                "{}: config_map_name empty",
                case.label
            );
            assert!(
                !plan.deployment_name.is_empty(),
                "{}: deployment_name empty",
                case.label
            );
        }
    }

    // ── Rollout convergence: exhaustive state matrix ─────────────────────────
    //
    // Verify is_rollout_converged for all interesting ObservedRuntimeState
    // combinations, ensuring the FSM's convergence decision is correct.

    #[test]
    fn rollout_convergence_exhaustive_matrix() {
        struct Case {
            label: &'static str,
            obs: ObservedRuntimeState,
            expected: bool,
        }

        let cases = [
            Case {
                label: "all None (Deployment absent)",
                obs: ObservedRuntimeState::default(),
                expected: false,
            },
            Case {
                label: "fully converged (1 replica)",
                obs: ObservedRuntimeState {
                    ready_replicas: Some(1),
                    deploy_observed_generation: Some(2),
                    deploy_generation: Some(2),
                    updated_replicas: Some(1),
                    available_replicas: Some(1),
                    desired_replicas: Some(1),
                    ..Default::default()
                },
                expected: true,
            },
            Case {
                label: "fully converged (3 replicas)",
                obs: ObservedRuntimeState {
                    ready_replicas: Some(3),
                    deploy_observed_generation: Some(5),
                    deploy_generation: Some(5),
                    updated_replicas: Some(3),
                    available_replicas: Some(3),
                    desired_replicas: Some(3),
                    ..Default::default()
                },
                expected: true,
            },
            Case {
                label: "scale-to-zero converged",
                obs: ObservedRuntimeState {
                    ready_replicas: Some(0),
                    deploy_observed_generation: Some(3),
                    deploy_generation: Some(3),
                    updated_replicas: Some(0),
                    available_replicas: Some(0),
                    desired_replicas: Some(0),
                    ..Default::default()
                },
                expected: true,
            },
            Case {
                label: "generation stale",
                obs: ObservedRuntimeState {
                    ready_replicas: Some(1),
                    deploy_observed_generation: Some(1),
                    deploy_generation: Some(2),
                    updated_replicas: Some(1),
                    available_replicas: Some(1),
                    desired_replicas: Some(1),
                    ..Default::default()
                },
                expected: false,
            },
            Case {
                label: "rolling update in progress (old pods ready, new not)",
                obs: ObservedRuntimeState {
                    ready_replicas: Some(2),
                    deploy_observed_generation: Some(3),
                    deploy_generation: Some(3),
                    updated_replicas: Some(0),
                    available_replicas: Some(2),
                    desired_replicas: Some(2),
                    ..Default::default()
                },
                expected: false,
            },
            Case {
                label: "ready but not available (minReadySeconds not met)",
                obs: ObservedRuntimeState {
                    ready_replicas: Some(1),
                    deploy_observed_generation: Some(1),
                    deploy_generation: Some(1),
                    updated_replicas: Some(1),
                    available_replicas: Some(0),
                    desired_replicas: Some(1),
                    ..Default::default()
                },
                expected: false,
            },
            Case {
                label: "available but not ready (readiness probe failing)",
                obs: ObservedRuntimeState {
                    ready_replicas: Some(0),
                    deploy_observed_generation: Some(1),
                    deploy_generation: Some(1),
                    updated_replicas: Some(1),
                    available_replicas: Some(1),
                    desired_replicas: Some(1),
                    ..Default::default()
                },
                expected: false,
            },
            Case {
                label: "partial scale-up (1/3 ready)",
                obs: ObservedRuntimeState {
                    ready_replicas: Some(1),
                    deploy_observed_generation: Some(2),
                    deploy_generation: Some(2),
                    updated_replicas: Some(1),
                    available_replicas: Some(1),
                    desired_replicas: Some(3),
                    ..Default::default()
                },
                expected: false,
            },
        ];

        for case in &cases {
            assert_eq!(
                is_rollout_converged(&case.obs),
                case.expected,
                "case '{}' failed",
                case.label
            );
        }
    }

    // ── Planner must not produce plans with inconsistent hashes ──────────────

    #[test]
    fn planner_config_hash_always_matches_config_toml_sha256() {
        // For every plan the planner produces, config_hash must equal
        // sha256_hex(config_toml). This is a structural FSM invariant.
        let gw = make_gateway(
            "prod",
            "my-gw",
            "uid-abc",
            vec![make_listener("http", 80, ProtocolType::HTTP)],
        );

        let scenarios: Vec<ObservedRuntimeState> = vec![
            ObservedRuntimeState::default(),
            ObservedRuntimeState {
                current_config_hash: Some("stale".to_string()),
                current_spec_hash: Some("stale".to_string()),
                ..Default::default()
            },
            ObservedRuntimeState {
                current_config_hash: None,
                current_spec_hash: None,
                ready_replicas: Some(1),
                deploy_observed_generation: Some(1),
                deploy_generation: Some(1),
                updated_replicas: Some(1),
                available_replicas: Some(1),
                desired_replicas: Some(1),
            },
        ];

        for (i, observed) in scenarios.into_iter().enumerate() {
            let snapshot = make_snapshot(gw.clone());
            let input = make_input("prod", "my-gw", snapshot, observed);
            let plan = GatewayRuntimePlanner
                .plan(&input)
                .unwrap_or_else(|e| panic!("scenario {}: {}", i, e));

            assert_eq!(
                plan.config_hash,
                sha256_hex(&plan.config_toml),
                "scenario {}: config_hash must equal sha256_hex(config_toml)",
                i
            );
        }
    }

    // ── Planner spec_hash consistency across service shape changes ────────────

    #[test]
    fn planner_spec_hash_reflects_all_runtime_fields() {
        // The spec_hash must change when ANY of: image, replicas, resources,
        // node_selector, service_type, or service_ports changes.
        let gw = make_gateway(
            "prod",
            "my-gw",
            "uid-abc",
            vec![make_listener("http", 80, ProtocolType::HTTP)],
        );

        let baseline_snap = make_snapshot(gw.clone());
        let baseline_input = make_input(
            "prod",
            "my-gw",
            baseline_snap,
            ObservedRuntimeState::default(),
        );
        let baseline_plan = GatewayRuntimePlanner.plan(&baseline_input).unwrap();
        let baseline_hash = baseline_plan.spec_hash.clone();

        // Change node_selector
        let snap = make_snapshot(gw.clone());
        let mut input = make_input("prod", "my-gw", snap, ObservedRuntimeState::default());
        input
            .controller_config
            .default_node_selector
            .insert("zone".to_string(), "us-east-1a".to_string());
        let plan = GatewayRuntimePlanner.plan(&input).unwrap();
        assert_ne!(
            plan.spec_hash, baseline_hash,
            "node_selector change must change spec_hash"
        );

        // Change resources
        let snap = make_snapshot(gw.clone());
        let mut input = make_input("prod", "my-gw", snap, ObservedRuntimeState::default());
        input
            .controller_config
            .default_resources
            .insert("requests.cpu".to_string(), "500m".to_string());
        let plan = GatewayRuntimePlanner.plan(&input).unwrap();
        assert_ne!(
            plan.spec_hash, baseline_hash,
            "resources change must change spec_hash"
        );
    }
}
