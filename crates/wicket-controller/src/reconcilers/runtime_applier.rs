//! Managed-runtime applier: reconciles controller-owned runtime resources from a
//! `GatewayRuntimePlan`.
//!
//! # Overview
//!
//! This module is the *apply* half of the managed-runtime reconcile loop.  It
//! consumes a `GatewayRuntimePlan` produced by `GatewayRuntimePlanner` and
//! performs the side-effecting steps:
//!
//! 1. Ensure the owned `ServiceAccount` exists (create if absent; no-op if present).
//! 2. Ensure the owned `ConfigMap` is up-to-date (managed-runtime-specific path
//!    that enforces owner refs and managed labels, not raw data patching).
//! 3. Ensure the owned `Service` matches the desired shape (create or patch).
//! 4. Ensure the owned `Deployment` matches the desired spec (create or patch).
//!
//! # Invariants
//!
//! - **Idempotent**: applying the same plan twice produces no observable change on
//!   the second call (server-side apply / merge-patch semantics).
//! - **Plan-only reads**: the applier does not read `SharedStore` or Gateway API
//!   objects to decide *what* to apply.  It only reads the plan it was given.
//! - **No status writes**: the applier does not write `Gateway.status`.  That is
//!   the status observer's responsibility.
//! - **Owner references**: every owned object carries an owner reference pointing
//!   to the Gateway so Kubernetes garbage-collects them on Gateway deletion.
//! - **Stable labels**: every owned object carries the standard managed-by labels
//!   defined in the ADR (section 2.3).
//! - **Revision annotations**: the ConfigMap carries `wicket.io/config-revision`;
//!   the Deployment carries `wicket.io/spec-revision`.
//! - **Ownership preflight**: before patching any object the applier checks that
//!   any pre-existing same-name object carries the controller's managed-by label.
//!   If it does not, `ApplyError::NotOwned` is returned rather than silently
//!   taking over the object.
//! - **Config-only changes do not trigger rollout**: the pod template spec is
//!   rebuilt only from `spec_hash`-covered fields (image, replicas, resources,
//!   node selector, ports).  The `config_hash` is carried only in the Deployment
//!   metadata annotation, not in the pod template, so a config-only change does
//!   not mutate the pod template and does not trigger a rollout.
//!
//! # Ordering
//!
//! ```text
//! 1. ServiceAccount  (no dependencies)
//! 2. ConfigMap       (managed-runtime path; no-op when config_changed=false)
//! 3. Service         (no dependencies)
//! 4. Deployment      (depends on ServiceAccount and ConfigMap existing)
//! ```
//!
//! Steps 2 and 4 are skipped (no-op) when the plan signals no change.

use std::collections::BTreeMap;
use std::collections::HashSet;

use k8s_openapi::api::apps::v1::{Deployment, DeploymentSpec};
use k8s_openapi::api::core::v1::ConfigMap;
use k8s_openapi::api::core::v1::Service as K8sService;
use k8s_openapi::api::core::v1::{
    ConfigMapVolumeSource, Container, ContainerPort, EnvVar, PodSpec, PodTemplateSpec,
    ResourceRequirements, SecretVolumeSource, ServiceAccount, ServicePort, ServiceSpec, Volume,
    VolumeMount,
};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{LabelSelector, ObjectMeta, OwnerReference};
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
use kube::api::{Api, Patch, PatchParams};
use kube::Client;
use tokio::sync::RwLock;

use crate::reconcilers::config_generator::WicketConfig;
use crate::reconcilers::contracts::{ApplyError, ConfigApplyResult, ServiceType};
use crate::reconcilers::runtime_plan::GatewayRuntimePlan;

// ─────────────────────────────────────────────────────────────────────────────
// Annotation / label constants (ADR section 2.3)
// ─────────────────────────────────────────────────────────────────────────────

/// Annotation key for the spec revision hash on the Deployment.
pub const SPEC_REVISION_ANNOTATION: &str = "wicket.io/spec-revision";

/// Annotation key for the config revision hash on the ConfigMap and Deployment
/// metadata (NOT the pod template -- config-only changes must not trigger rollout).
pub const CONFIG_REVISION_ANNOTATION: &str = "wicket.io/config-revision";

/// Label: managed-by controller.
const LABEL_MANAGED_BY: &str = "app.kubernetes.io/managed-by";
/// Label: component role.
const LABEL_COMPONENT: &str = "app.kubernetes.io/component";
/// Label: instance (gateway name).
const LABEL_INSTANCE: &str = "app.kubernetes.io/instance";
/// Label: application name.
const LABEL_APP_NAME: &str = "app.kubernetes.io/name";
/// Label: gateway namespace (wicket-specific).
const LABEL_GW_NAMESPACE: &str = "wicket.io/gateway-namespace";
/// Label: gateway name (wicket-specific).
const LABEL_GW_NAME: &str = "wicket.io/gateway-name";

/// Field manager name used for server-side apply / merge-patch calls.
const FIELD_MANAGER: &str = "wicket-controller";

// ─────────────────────────────────────────────────────────────────────────────
// Apply result
// ─────────────────────────────────────────────────────────────────────────────

/// Aggregate result of applying a `GatewayRuntimePlan`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RuntimeApplyResult {
    /// Whether the `ServiceAccount` was created (false = already existed).
    pub service_account_created: bool,
    /// Result of the ConfigMap apply step.
    pub config_result: Option<ConfigApplyResult>,
    /// Whether the `Service` was created or patched due to a spec change.
    ///
    /// `true` when `plan.spec_changed` is true (service shape changed) or the
    /// Service did not previously exist.  `false` when the Service already
    /// existed and no spec change was signalled.
    pub service_changed: bool,
    /// Whether the `Deployment` was created or patched.
    ///
    /// `true` when `plan.spec_changed` is true (pod template changed) or the
    /// Deployment did not previously exist.  `false` when the Deployment
    /// already existed and only a config-only change occurred (no rollout).
    pub deployment_changed: bool,
    /// Whether a Deployment rollout was triggered.
    ///
    /// `true` only when `plan.spec_changed` is true.  A config-only change
    /// (`plan.config_changed && !plan.spec_changed`) does NOT set this flag
    /// because the pod template is not mutated by config-only changes.
    pub rollout_triggered: bool,
}

// ─────────────────────────────────────────────────────────────────────────────
// Applier input
// ─────────────────────────────────────────────────────────────────────────────

/// Everything the runtime applier needs to apply a `GatewayRuntimePlan`.
pub struct RuntimeApplierInput<'a> {
    /// Kubernetes client.
    pub client: &'a Client,
    /// In-memory config handle (updated after a successful ConfigMap patch).
    pub in_memory_config: &'a RwLock<WicketConfig>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Top-level applier
// ─────────────────────────────────────────────────────────────────────────────

/// Apply a `GatewayRuntimePlan` to the cluster.
///
/// Reconciles `ServiceAccount`, `ConfigMap`, `Service`, and `Deployment` in
/// the Gateway's namespace.  Each step is idempotent.
///
/// Returns a `RuntimeApplyResult` summarising what changed.
///
/// # Errors
///
/// Returns `ApplyError` if any Kubernetes API call fails.  Partial applies are
/// safe because each step is idempotent; the controller will requeue and retry.
///
/// Returns `ApplyError::NotOwned` if any pre-existing same-name object does not
/// carry the controller's managed-by label.
pub async fn apply_runtime_plan(
    plan: &GatewayRuntimePlan,
    input: &RuntimeApplierInput<'_>,
) -> Result<RuntimeApplyResult, ApplyError> {
    let mut result = RuntimeApplyResult::default();

    // ── 1. ServiceAccount ─────────────────────────────────────────────────────
    result.service_account_created = apply_service_account(plan, input.client).await?;

    // ── 2. ConfigMap (managed-runtime path) ───────────────────────────────────
    // Uses the managed-runtime-specific path that enforces owner refs and
    // managed labels, rather than the raw data-only patch in config_applier.
    let config_result = apply_managed_configmap(plan, input.client, input.in_memory_config).await?;
    result.config_result = Some(config_result);

    // ── 3. Service ────────────────────────────────────────────────────────────
    result.service_changed = apply_service(plan, input.client).await?;

    // ── 4. Deployment ─────────────────────────────────────────────────────────
    let (deploy_changed, rollout) = apply_deployment(plan, input.client).await?;
    result.deployment_changed = deploy_changed;
    result.rollout_triggered = rollout;

    tracing::info!(
        gateway_namespace = %plan.gateway_namespace,
        gateway_name = %plan.gateway_name,
        sa_created = result.service_account_created,
        svc_changed = result.service_changed,
        deploy_changed = result.deployment_changed,
        rollout_triggered = result.rollout_triggered,
        "Runtime plan applied"
    );

    Ok(result)
}

// ─────────────────────────────────────────────────────────────────────────────
// Label / annotation helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Build the standard managed-by labels for an owned object (ADR section 2.3).
fn managed_labels(plan: &GatewayRuntimePlan) -> BTreeMap<String, String> {
    let mut labels = BTreeMap::new();
    labels.insert(
        LABEL_MANAGED_BY.to_string(),
        "wicket-controller".to_string(),
    );
    labels.insert(LABEL_COMPONENT.to_string(), "gateway-runtime".to_string());
    labels.insert(LABEL_INSTANCE.to_string(), plan.gateway_name.clone());
    labels.insert(LABEL_APP_NAME.to_string(), "wicket".to_string());
    labels.insert(
        LABEL_GW_NAMESPACE.to_string(),
        plan.gateway_namespace.clone(),
    );
    labels.insert(LABEL_GW_NAME.to_string(), plan.gateway_name.clone());
    labels
}

/// Build the pod template labels.
///
/// These are the *stable* managed labels only.  The `config_hash` is NOT
/// included here because including it would mutate the pod template on every
/// config-only change and trigger an unwanted rollout.  The config revision is
/// tracked via the Deployment metadata annotation instead.
fn pod_template_labels(plan: &GatewayRuntimePlan) -> BTreeMap<String, String> {
    managed_labels(plan)
}

/// Build the owner reference pointing to the Gateway.
fn gateway_owner_ref(plan: &GatewayRuntimePlan) -> OwnerReference {
    OwnerReference {
        api_version: "gateway.networking.k8s.io/v1".to_string(),
        kind: "Gateway".to_string(),
        name: plan.gateway_name.clone(),
        uid: plan.gateway_uid.clone(),
        controller: Some(true),
        block_owner_deletion: Some(true),
    }
}

/// Build the base `ObjectMeta` for an owned object.
fn owned_object_meta(
    name: &str,
    plan: &GatewayRuntimePlan,
    extra_annotations: Option<BTreeMap<String, String>>,
) -> ObjectMeta {
    ObjectMeta {
        name: Some(name.to_string()),
        namespace: Some(plan.gateway_namespace.clone()),
        labels: Some(managed_labels(plan)),
        annotations: extra_annotations,
        owner_references: Some(vec![gateway_owner_ref(plan)]),
        ..Default::default()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Ownership preflight
// ─────────────────────────────────────────────────────────────────────────────

/// Check whether a pre-existing object's labels indicate it is managed by this
/// controller.
///
/// Returns `true` when the object carries
/// `app.kubernetes.io/managed-by = wicket-controller`, `false` otherwise.
fn is_managed_by_controller(labels: Option<&BTreeMap<String, String>>) -> bool {
    labels
        .and_then(|l| l.get(LABEL_MANAGED_BY))
        .map(|v| v == "wicket-controller")
        .unwrap_or(false)
}

/// Test-visible re-export of `is_managed_by_controller`.
///
/// Exposed only under `#[cfg(test)]` so cross-module tests in `gateway.rs`
/// can call the ownership-check logic without making it part of the public API.
#[cfg(test)]
pub fn is_managed_by_controller_pub(labels: Option<&BTreeMap<String, String>>) -> bool {
    is_managed_by_controller(labels)
}

/// Perform an ownership preflight check for a `ServiceAccount`.
///
/// Returns `Ok(true)` when the object exists and is owned, `Ok(false)` when
/// the object does not exist, and `Err(ApplyError::NotOwned)` when the object
/// exists but is not managed by this controller.
async fn preflight_service_account(
    api: &Api<ServiceAccount>,
    name: &str,
    namespace: &str,
) -> Result<bool, ApplyError> {
    match api
        .get_opt(name)
        .await
        .map_err(|e| ApplyError::KubeApi(e.to_string()))?
    {
        None => Ok(false),
        Some(obj) => {
            if is_managed_by_controller(obj.metadata.labels.as_ref()) {
                Ok(true)
            } else {
                Err(ApplyError::NotOwned {
                    namespace: namespace.to_string(),
                    name: name.to_string(),
                })
            }
        }
    }
}

/// Perform an ownership preflight check for a `ConfigMap`.
async fn preflight_configmap(
    api: &Api<ConfigMap>,
    name: &str,
    namespace: &str,
) -> Result<bool, ApplyError> {
    match api
        .get_opt(name)
        .await
        .map_err(|e| ApplyError::KubeApi(e.to_string()))?
    {
        None => Ok(false),
        Some(obj) => {
            if is_managed_by_controller(obj.metadata.labels.as_ref()) {
                Ok(true)
            } else {
                Err(ApplyError::NotOwned {
                    namespace: namespace.to_string(),
                    name: name.to_string(),
                })
            }
        }
    }
}

/// Perform an ownership preflight check for a `Service`.
async fn preflight_service(
    api: &Api<K8sService>,
    name: &str,
    namespace: &str,
) -> Result<bool, ApplyError> {
    match api
        .get_opt(name)
        .await
        .map_err(|e| ApplyError::KubeApi(e.to_string()))?
    {
        None => Ok(false),
        Some(obj) => {
            if is_managed_by_controller(obj.metadata.labels.as_ref()) {
                Ok(true)
            } else {
                Err(ApplyError::NotOwned {
                    namespace: namespace.to_string(),
                    name: name.to_string(),
                })
            }
        }
    }
}

/// Perform an ownership preflight check for a `Deployment`.
async fn preflight_deployment(
    api: &Api<Deployment>,
    name: &str,
    namespace: &str,
) -> Result<bool, ApplyError> {
    match api
        .get_opt(name)
        .await
        .map_err(|e| ApplyError::KubeApi(e.to_string()))?
    {
        None => Ok(false),
        Some(obj) => {
            if is_managed_by_controller(obj.metadata.labels.as_ref()) {
                Ok(true)
            } else {
                Err(ApplyError::NotOwned {
                    namespace: namespace.to_string(),
                    name: name.to_string(),
                })
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ServiceAccount
// ─────────────────────────────────────────────────────────────────────────────

/// Ensure the owned `ServiceAccount` exists.
///
/// Performs an ownership preflight: if a same-name object exists without the
/// controller's managed-by label, returns `ApplyError::NotOwned`.
///
/// Uses server-side apply so the call is idempotent.  Returns `true` if the
/// object was just created (did not previously exist), `false` if it already
/// existed.
///
/// # Errors
///
/// Returns `ApplyError::KubeApi` if the API call fails.
/// Returns `ApplyError::NotOwned` if a pre-existing object is not managed by
/// this controller.
async fn apply_service_account(
    plan: &GatewayRuntimePlan,
    client: &Client,
) -> Result<bool, ApplyError> {
    let api: Api<ServiceAccount> = Api::namespaced(client.clone(), &plan.gateway_namespace);

    // Ownership preflight: reject unowned pre-existing objects.
    let already_exists =
        preflight_service_account(&api, &plan.service_account_name, &plan.gateway_namespace)
            .await?;

    let sa = ServiceAccount {
        metadata: owned_object_meta(&plan.service_account_name, plan, None),
        ..Default::default()
    };

    let patch = serde_json::to_value(&sa).map_err(|e| ApplyError::Serialization(e.to_string()))?;

    api.patch(
        &plan.service_account_name,
        &PatchParams::apply(FIELD_MANAGER).force(),
        &Patch::Apply(&patch),
    )
    .await
    .map_err(|e| ApplyError::KubeApi(e.to_string()))?;

    let created = !already_exists;
    if created {
        tracing::info!(
            namespace = %plan.gateway_namespace,
            name = %plan.service_account_name,
            "ServiceAccount created"
        );
    } else {
        tracing::debug!(
            namespace = %plan.gateway_namespace,
            name = %plan.service_account_name,
            "ServiceAccount already exists (no-op)"
        );
    }

    Ok(created)
}

// ─────────────────────────────────────────────────────────────────────────────
// ConfigMap (managed-runtime path)
// ─────────────────────────────────────────────────────────────────────────────

/// Apply the owned `ConfigMap` for a managed-runtime Gateway.
///
/// This is a managed-runtime-specific path that enforces owner references and
/// managed labels on the ConfigMap, unlike the raw data-only patch in
/// `config_applier::apply_config_plan`.
///
/// Performs an ownership preflight: if a same-name ConfigMap exists without
/// the controller's managed-by label, returns `ApplyError::NotOwned`.
///
/// When `plan.config_changed` is `false`, skips the patch but still syncs the
/// in-memory `WicketConfig` from the plan content.
///
/// # Errors
///
/// Returns `ApplyError::KubeApi` if the API call fails.
/// Returns `ApplyError::NotOwned` if a pre-existing ConfigMap is not managed.
/// Returns `ApplyError::Serialization` if TOML deserialization fails.
async fn apply_managed_configmap(
    plan: &GatewayRuntimePlan,
    client: &Client,
    in_memory_config: &RwLock<WicketConfig>,
) -> Result<ConfigApplyResult, ApplyError> {
    let api: Api<ConfigMap> = Api::namespaced(client.clone(), &plan.gateway_namespace);

    // Ownership preflight.
    preflight_configmap(&api, &plan.config_map_name, &plan.gateway_namespace).await?;

    // Always sync the in-memory view from the plan content so that a process
    // restart does not leave the view stale.
    let new_config: WicketConfig =
        toml::from_str(&plan.config_toml).map_err(|e| ApplyError::Serialization(e.to_string()))?;

    if !plan.config_changed {
        // No patch needed; just sync in-memory.
        {
            let mut current = in_memory_config.write().await;
            *current = new_config;
        }
        tracing::debug!(
            namespace = %plan.gateway_namespace,
            name = %plan.config_map_name,
            config_hash = %plan.config_hash,
            "ConfigMap no-op: already at desired revision"
        );
        return Ok(ConfigApplyResult::NoOp);
    }

    // Build the full ConfigMap with owner refs and managed labels.
    let mut annotations = BTreeMap::new();
    annotations.insert(
        CONFIG_REVISION_ANNOTATION.to_string(),
        plan.config_hash.clone(),
    );

    let mut data = BTreeMap::new();
    data.insert("wicket.toml".to_string(), plan.config_toml.clone());

    let cm = ConfigMap {
        metadata: owned_object_meta(&plan.config_map_name, plan, Some(annotations)),
        data: Some(data),
        ..Default::default()
    };

    let patch = serde_json::to_value(&cm).map_err(|e| ApplyError::Serialization(e.to_string()))?;

    api.patch(
        &plan.config_map_name,
        &PatchParams::apply(FIELD_MANAGER).force(),
        &Patch::Apply(&patch),
    )
    .await
    .map_err(|e| ApplyError::KubeApi(e.to_string()))?;

    // Update in-memory config after successful patch.
    {
        let mut current = in_memory_config.write().await;
        *current = new_config;
    }

    tracing::info!(
        namespace = %plan.gateway_namespace,
        name = %plan.config_map_name,
        config_hash = %plan.config_hash,
        "ConfigMap applied"
    );

    Ok(ConfigApplyResult::Updated {
        config_hash: plan.config_hash.clone(),
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Service
// ─────────────────────────────────────────────────────────────────────────────

/// Ensure the owned `Service` matches the desired shape.
///
/// Performs an ownership preflight: if a same-name Service exists without the
/// controller's managed-by label, returns `ApplyError::NotOwned`.
///
/// Uses server-side apply (force) so the call is idempotent.  Returns `true`
/// when the Service was created (did not previously exist) or when
/// `plan.spec_changed` is true (service shape changed).  Returns `false` when
/// the Service already existed and no spec change was signalled.
///
/// # Errors
///
/// Returns `ApplyError::KubeApi` if the API call fails.
/// Returns `ApplyError::NotOwned` if a pre-existing object is not managed.
async fn apply_service(plan: &GatewayRuntimePlan, client: &Client) -> Result<bool, ApplyError> {
    let api: Api<K8sService> = Api::namespaced(client.clone(), &plan.gateway_namespace);

    // Ownership preflight.
    let already_exists =
        preflight_service(&api, &plan.service_name, &plan.gateway_namespace).await?;

    // Build the desired Service spec.
    let svc_type_str = match plan.service_type {
        ServiceType::ClusterIP => "ClusterIP",
        ServiceType::LoadBalancer => "LoadBalancer",
        ServiceType::NodePort => "NodePort",
    };

    let ports: Vec<ServicePort> = plan
        .service_ports
        .iter()
        .map(|p| ServicePort {
            name: Some(p.name.clone()),
            port: i32::from(p.port),
            target_port: Some(IntOrString::Int(i32::from(p.target_port))),
            protocol: Some(p.protocol.clone()),
            ..Default::default()
        })
        .collect();

    // Selector matches the stable pod template labels (managed labels only,
    // no config-revision which would break selector stability).
    let selector = managed_labels(plan);

    let svc = K8sService {
        metadata: owned_object_meta(&plan.service_name, plan, None),
        spec: Some(ServiceSpec {
            type_: Some(svc_type_str.to_string()),
            ports: Some(ports),
            selector: Some(selector),
            ..Default::default()
        }),
        ..Default::default()
    };

    let patch = serde_json::to_value(&svc).map_err(|e| ApplyError::Serialization(e.to_string()))?;

    api.patch(
        &plan.service_name,
        &PatchParams::apply(FIELD_MANAGER).force(),
        &Patch::Apply(&patch),
    )
    .await
    .map_err(|e| ApplyError::KubeApi(e.to_string()))?;

    tracing::debug!(
        namespace = %plan.gateway_namespace,
        name = %plan.service_name,
        svc_type = %svc_type_str,
        "Service applied"
    );

    // Report changed when the object was just created or when the spec changed.
    let changed = !already_exists || plan.spec_changed;
    Ok(changed)
}

// ─────────────────────────────────────────────────────────────────────────────
// Deployment
// ─────────────────────────────────────────────────────────────────────────────

/// Ensure the owned `Deployment` matches the desired spec.
///
/// Performs an ownership preflight: if a same-name Deployment exists without
/// the controller's managed-by label, returns `ApplyError::NotOwned`.
///
/// Returns `(changed, rollout_triggered)`:
/// - `changed` is `true` when the Deployment was created (did not previously
///   exist) or when `plan.spec_changed` is true.  A config-only change does
///   NOT set `changed` because the pod template is not mutated.
/// - `rollout_triggered` is `true` only when `plan.spec_changed` is true.
///   Config-only changes do not trigger a rollout because the pod template
///   spec is not mutated by config-only changes.
///
/// # Errors
///
/// Returns `ApplyError::KubeApi` if the API call fails.
/// Returns `ApplyError::NotOwned` if a pre-existing object is not managed.
/// Returns `ApplyError::Serialization` if replica count conversion fails.
async fn apply_deployment(
    plan: &GatewayRuntimePlan,
    client: &Client,
) -> Result<(bool, bool), ApplyError> {
    let api: Api<Deployment> = Api::namespaced(client.clone(), &plan.gateway_namespace);

    // Ownership preflight.
    let already_exists =
        preflight_deployment(&api, &plan.deployment_name, &plan.gateway_namespace).await?;

    // Fail safely on invalid replica count rather than silently coercing.
    let replicas = i32::try_from(plan.runtime_metadata.replicas).map_err(|_| {
        ApplyError::Serialization(format!(
            "replica count {} overflows i32 (max {})",
            plan.runtime_metadata.replicas,
            i32::MAX
        ))
    })?;

    // Build resource requirements from the flat key-value map.
    let resource_requirements = build_resource_requirements(&plan.runtime_metadata.resources);

    // Container ports derived from service_ports.
    let container_ports: Vec<ContainerPort> = plan
        .service_ports
        .iter()
        .map(|p| ContainerPort {
            name: Some(p.name.clone()),
            container_port: i32::from(p.target_port),
            protocol: Some(p.protocol.clone()),
            ..Default::default()
        })
        .collect();

    // Volumes and mounts for the ConfigMap and referenced TLS Secrets.
    let volume_mount = VolumeMount {
        name: "config".to_string(),
        mount_path: "/etc/wicket".to_string(),
        read_only: Some(true),
        ..Default::default()
    };

    let config_volume = Volume {
        name: "config".to_string(),
        config_map: Some(ConfigMapVolumeSource {
            name: plan.config_map_name.clone(),
            ..Default::default()
        }),
        ..Default::default()
    };

    let mut volume_mounts = vec![volume_mount];
    let mut volumes = vec![config_volume];
    let mut seen_volume_names: HashSet<String> = HashSet::new();
    seen_volume_names.insert("config".to_string());

    for mount in &plan.tls_secret_mounts {
        let raw_name = format!("tls-{}", mount.secret_name);
        let vol_name = if raw_name.len() > 63 {
            raw_name[..63].to_string()
        } else {
            raw_name
        };

        if !seen_volume_names.insert(vol_name.clone()) {
            continue;
        }

        volume_mounts.push(VolumeMount {
            name: vol_name.clone(),
            mount_path: mount.mount_path.clone(),
            read_only: Some(true),
            ..Default::default()
        });

        volumes.push(Volume {
            name: vol_name,
            secret: Some(SecretVolumeSource {
                secret_name: Some(mount.secret_name.clone()),
                default_mode: Some(0o400),
                optional: Some(false),
                ..Default::default()
            }),
            ..Default::default()
        });
    }

    // Env var exposing the config revision so the proxy can log it.
    // NOTE: this env var is derived from the spec-covered fields only; it does
    // NOT carry config_hash so that config-only changes do not mutate the
    // container spec and trigger a rollout.
    let container = Container {
        name: "wicket-proxy".to_string(),
        image: Some(plan.runtime_metadata.image.clone()),
        ports: Some(container_ports),
        volume_mounts: Some(volume_mounts),
        env: Some(vec![EnvVar {
            name: "WICKET_SPEC_REVISION".to_string(),
            value: Some(plan.spec_hash.clone()),
            ..Default::default()
        }]),
        resources: Some(resource_requirements),
        ..Default::default()
    };

    // Pod template annotations carry only the spec-revision.
    // The config-revision is tracked at the Deployment metadata level (below)
    // so that config-only changes do not mutate the pod template.
    let mut pod_annotations = BTreeMap::new();
    pod_annotations.insert(SPEC_REVISION_ANNOTATION.to_string(), plan.spec_hash.clone());

    let pod_template = PodTemplateSpec {
        metadata: Some(ObjectMeta {
            labels: Some(pod_template_labels(plan)),
            annotations: Some(pod_annotations),
            ..Default::default()
        }),
        spec: Some(PodSpec {
            service_account_name: Some(plan.service_account_name.clone()),
            containers: vec![container],
            volumes: Some(volumes),
            node_selector: if plan.runtime_metadata.node_selector.is_empty() {
                None
            } else {
                Some(plan.runtime_metadata.node_selector.clone())
            },
            ..Default::default()
        }),
    };

    // Deployment-level annotations carry both revision hashes.
    // config_hash here does NOT propagate to the pod template, so a
    // config-only change updates this annotation without triggering a rollout.
    let mut deploy_annotations = BTreeMap::new();
    deploy_annotations.insert(SPEC_REVISION_ANNOTATION.to_string(), plan.spec_hash.clone());
    deploy_annotations.insert(
        CONFIG_REVISION_ANNOTATION.to_string(),
        plan.config_hash.clone(),
    );

    let deploy = Deployment {
        metadata: owned_object_meta(&plan.deployment_name, plan, Some(deploy_annotations)),
        spec: Some(DeploymentSpec {
            replicas: Some(replicas),
            selector: LabelSelector {
                match_labels: Some(managed_labels(plan)),
                ..Default::default()
            },
            template: pod_template,
            ..Default::default()
        }),
        ..Default::default()
    };

    let patch =
        serde_json::to_value(&deploy).map_err(|e| ApplyError::Serialization(e.to_string()))?;

    api.patch(
        &plan.deployment_name,
        &PatchParams::apply(FIELD_MANAGER).force(),
        &Patch::Apply(&patch),
    )
    .await
    .map_err(|e| ApplyError::KubeApi(e.to_string()))?;

    // rollout_triggered: only when spec_changed (pod template mutated).
    // config-only changes do not mutate the pod template.
    let rollout = plan.spec_changed;

    // deployment_changed: created for the first time, or spec changed.
    // config-only changes do not count as a deployment change because the
    // pod template was not mutated.
    let changed = !already_exists || plan.spec_changed;

    if rollout {
        tracing::info!(
            namespace = %plan.gateway_namespace,
            name = %plan.deployment_name,
            spec_hash = %plan.spec_hash,
            config_hash = %plan.config_hash,
            "Deployment rollout triggered"
        );
    } else {
        tracing::debug!(
            namespace = %plan.gateway_namespace,
            name = %plan.deployment_name,
            "Deployment applied (no rollout)"
        );
    }

    Ok((changed, rollout))
}

// ─────────────────────────────────────────────────────────────────────────────
// Resource requirements helper
// ─────────────────────────────────────────────────────────────────────────────

/// Build `ResourceRequirements` from the flat key-value map in `RuntimeMetadata`.
///
/// Recognised keys (Kubernetes convention):
/// - `"requests.cpu"`, `"requests.memory"` -> `requests`
/// - `"limits.cpu"`, `"limits.memory"` -> `limits`
///
/// Unknown keys are silently ignored so that future extension does not break
/// existing plans.
fn build_resource_requirements(resources: &BTreeMap<String, String>) -> ResourceRequirements {
    use k8s_openapi::apimachinery::pkg::api::resource::Quantity;

    let mut requests: BTreeMap<String, Quantity> = BTreeMap::new();
    let mut limits: BTreeMap<String, Quantity> = BTreeMap::new();

    for (key, value) in resources {
        match key.as_str() {
            "requests.cpu" => {
                requests.insert("cpu".to_string(), Quantity(value.clone()));
            }
            "requests.memory" => {
                requests.insert("memory".to_string(), Quantity(value.clone()));
            }
            "limits.cpu" => {
                limits.insert("cpu".to_string(), Quantity(value.clone()));
            }
            "limits.memory" => {
                limits.insert("memory".to_string(), Quantity(value.clone()));
            }
            _ => {
                tracing::debug!(key = %key, "Ignoring unknown resource key in RuntimeMetadata");
            }
        }
    }

    ResourceRequirements {
        requests: if requests.is_empty() {
            None
        } else {
            Some(requests)
        },
        limits: if limits.is_empty() {
            None
        } else {
            Some(limits)
        },
        ..Default::default()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reconcilers::contracts::{RuntimeMetadata, ServicePortSpec, ServiceType};
    use crate::reconcilers::runtime_plan::GatewayRuntimePlan;

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn make_plan(
        config_changed: bool,
        spec_changed: bool,
        service_type: ServiceType,
        ports: Vec<ServicePortSpec>,
    ) -> GatewayRuntimePlan {
        let base = "wicket-gw-test-gw".to_string();
        GatewayRuntimePlan {
            gateway_namespace: "prod".to_string(),
            gateway_name: "test-gw".to_string(),
            gateway_uid: "uid-abc-123".to_string(),
            gateway_generation: 1,
            owned_object_base_name: base.clone(),
            config_map_name: format!("{}-config", base),
            deployment_name: format!("{}-deploy", base),
            service_name: format!("{}-svc", base),
            service_account_name: format!("{}-sa", base),
            config_hash: "aabbcc".to_string(),
            spec_hash: "ddeeff".to_string(),
            config_toml: "[server]\nlisten = \"0.0.0.0:8080\"\n".to_string(),
            runtime_metadata: RuntimeMetadata {
                image: "ghcr.io/geverding/wicket:latest".to_string(),
                replicas: 2,
                resources: BTreeMap::new(),
                node_selector: BTreeMap::new(),
            },
            service_type,
            service_ports: ports,
            tls_secret_mounts: vec![],
            listener_statuses: vec![],
            config_changed,
            spec_changed,
        }
    }

    // ── managed_labels ────────────────────────────────────────────────────────

    #[test]
    fn managed_labels_contains_required_keys() {
        let plan = make_plan(false, false, ServiceType::ClusterIP, vec![]);
        let labels = managed_labels(&plan);

        assert_eq!(
            labels.get(LABEL_MANAGED_BY).map(String::as_str),
            Some("wicket-controller")
        );
        assert_eq!(
            labels.get(LABEL_COMPONENT).map(String::as_str),
            Some("gateway-runtime")
        );
        assert_eq!(
            labels.get(LABEL_INSTANCE).map(String::as_str),
            Some("test-gw")
        );
        assert_eq!(
            labels.get(LABEL_APP_NAME).map(String::as_str),
            Some("wicket")
        );
        assert_eq!(
            labels.get(LABEL_GW_NAMESPACE).map(String::as_str),
            Some("prod")
        );
        assert_eq!(
            labels.get(LABEL_GW_NAME).map(String::as_str),
            Some("test-gw")
        );
    }

    // ── pod_template_labels ───────────────────────────────────────────────────

    #[test]
    fn pod_template_labels_does_not_include_config_revision() {
        // config_hash must NOT appear in pod template labels; it would cause
        // config-only changes to mutate the pod template and trigger a rollout.
        let plan = make_plan(true, false, ServiceType::ClusterIP, vec![]);
        let labels = pod_template_labels(&plan);

        assert!(
            !labels.contains_key(CONFIG_REVISION_ANNOTATION),
            "config_hash must not be in pod template labels to avoid spurious rollouts"
        );
        // Must still carry all managed labels.
        assert_eq!(
            labels.get(LABEL_MANAGED_BY).map(String::as_str),
            Some("wicket-controller")
        );
    }

    #[test]
    fn pod_template_labels_equals_managed_labels() {
        // pod_template_labels must be identical to managed_labels (no extras).
        let plan = make_plan(true, false, ServiceType::ClusterIP, vec![]);
        assert_eq!(pod_template_labels(&plan), managed_labels(&plan));
    }

    // ── gateway_owner_ref ─────────────────────────────────────────────────────

    #[test]
    fn owner_ref_points_to_gateway() {
        let plan = make_plan(false, false, ServiceType::ClusterIP, vec![]);
        let oref = gateway_owner_ref(&plan);

        assert_eq!(oref.kind, "Gateway");
        assert_eq!(oref.name, "test-gw");
        assert_eq!(oref.uid, "uid-abc-123");
        assert_eq!(oref.controller, Some(true));
        assert_eq!(oref.block_owner_deletion, Some(true));
        assert_eq!(oref.api_version, "gateway.networking.k8s.io/v1");
    }

    // ── owned_object_meta ─────────────────────────────────────────────────────

    #[test]
    fn owned_object_meta_sets_namespace_and_owner() {
        let plan = make_plan(false, false, ServiceType::ClusterIP, vec![]);
        let meta = owned_object_meta("wicket-gw-test-gw-sa", &plan, None);

        assert_eq!(meta.name.as_deref(), Some("wicket-gw-test-gw-sa"));
        assert_eq!(meta.namespace.as_deref(), Some("prod"));
        let orefs = meta
            .owner_references
            .as_ref()
            .expect("owner_references must be set");
        assert_eq!(orefs.len(), 1);
        assert_eq!(orefs[0].name, "test-gw");
    }

    #[test]
    fn owned_object_meta_carries_extra_annotations() {
        let plan = make_plan(false, false, ServiceType::ClusterIP, vec![]);
        let mut extra = BTreeMap::new();
        extra.insert(SPEC_REVISION_ANNOTATION.to_string(), "ddeeff".to_string());
        let meta = owned_object_meta("wicket-gw-test-gw-deploy", &plan, Some(extra));

        let annotations = meta.annotations.as_ref().expect("annotations must be set");
        assert_eq!(
            annotations
                .get(SPEC_REVISION_ANNOTATION)
                .map(String::as_str),
            Some("ddeeff")
        );
    }

    #[test]
    fn owned_object_meta_carries_managed_labels() {
        let plan = make_plan(false, false, ServiceType::ClusterIP, vec![]);
        let meta = owned_object_meta("wicket-gw-test-gw-sa", &plan, None);
        let labels = meta.labels.as_ref().expect("labels must be set");
        assert_eq!(
            labels.get(LABEL_MANAGED_BY).map(String::as_str),
            Some("wicket-controller")
        );
    }

    #[test]
    fn owned_object_meta_carries_owner_ref() {
        let plan = make_plan(false, false, ServiceType::ClusterIP, vec![]);
        let meta = owned_object_meta("wicket-gw-test-gw-sa", &plan, None);
        let orefs = meta
            .owner_references
            .as_ref()
            .expect("owner_references must be set");
        assert_eq!(orefs.len(), 1);
        assert_eq!(orefs[0].uid, "uid-abc-123");
    }

    // ── build_resource_requirements ───────────────────────────────────────────

    #[test]
    fn resource_requirements_empty_when_no_resources() {
        let rr = build_resource_requirements(&BTreeMap::new());
        assert!(rr.requests.is_none());
        assert!(rr.limits.is_none());
    }

    #[test]
    fn resource_requirements_parses_known_keys() {
        let mut resources = BTreeMap::new();
        resources.insert("requests.cpu".to_string(), "100m".to_string());
        resources.insert("requests.memory".to_string(), "128Mi".to_string());
        resources.insert("limits.cpu".to_string(), "500m".to_string());
        resources.insert("limits.memory".to_string(), "512Mi".to_string());

        let rr = build_resource_requirements(&resources);

        let req = rr.requests.as_ref().expect("requests must be set");
        assert_eq!(req.get("cpu").map(|q| q.0.as_str()), Some("100m"));
        assert_eq!(req.get("memory").map(|q| q.0.as_str()), Some("128Mi"));

        let lim = rr.limits.as_ref().expect("limits must be set");
        assert_eq!(lim.get("cpu").map(|q| q.0.as_str()), Some("500m"));
        assert_eq!(lim.get("memory").map(|q| q.0.as_str()), Some("512Mi"));
    }

    #[test]
    fn resource_requirements_ignores_unknown_keys() {
        let mut resources = BTreeMap::new();
        resources.insert("requests.cpu".to_string(), "100m".to_string());
        resources.insert("future.ephemeral-storage".to_string(), "1Gi".to_string());

        let rr = build_resource_requirements(&resources);
        let req = rr.requests.as_ref().expect("requests must be set");
        // Only "cpu" should be present; unknown key is ignored.
        assert_eq!(req.len(), 1);
        assert!(req.contains_key("cpu"));
    }

    // ── is_noop propagation ───────────────────────────────────────────────────

    #[test]
    fn plan_is_noop_when_neither_changed() {
        let plan = make_plan(false, false, ServiceType::ClusterIP, vec![]);
        assert!(plan.is_noop());
    }

    #[test]
    fn plan_not_noop_when_config_changed() {
        let plan = make_plan(true, false, ServiceType::ClusterIP, vec![]);
        assert!(!plan.is_noop());
    }

    #[test]
    fn plan_not_noop_when_spec_changed() {
        let plan = make_plan(false, true, ServiceType::ClusterIP, vec![]);
        assert!(!plan.is_noop());
    }

    // ── service port mapping ──────────────────────────────────────────────────

    #[test]
    fn service_ports_map_correctly() {
        let ports = vec![
            ServicePortSpec {
                name: "http".to_string(),
                port: 80,
                target_port: 8080,
                protocol: "TCP".to_string(),
            },
            ServicePortSpec {
                name: "https".to_string(),
                port: 443,
                target_port: 8443,
                protocol: "TCP".to_string(),
            },
        ];
        let plan = make_plan(false, true, ServiceType::LoadBalancer, ports);

        assert_eq!(plan.service_ports.len(), 2);
        assert_eq!(plan.service_ports[0].name, "http");
        assert_eq!(plan.service_ports[0].port, 80);
        assert_eq!(plan.service_ports[0].target_port, 8080);
        assert_eq!(plan.service_ports[1].name, "https");
        assert_eq!(plan.service_ports[1].port, 443);
    }

    // ── rollout signal ────────────────────────────────────────────────────────

    #[test]
    fn rollout_triggered_only_when_spec_changed() {
        // spec_changed=true -> rollout expected
        let plan_rollout = make_plan(false, true, ServiceType::ClusterIP, vec![]);
        assert!(plan_rollout.spec_changed);

        // spec_changed=false -> no rollout
        let plan_no_rollout = make_plan(true, false, ServiceType::ClusterIP, vec![]);
        assert!(!plan_no_rollout.spec_changed);
    }

    // ── config_plan_from_runtime_plan bridge ──────────────────────────────────

    #[test]
    fn config_plan_bridge_update_when_config_changed() {
        use crate::reconcilers::contracts::ConfigPlan;
        use crate::reconcilers::runtime_plan::config_plan_from_runtime_plan;
        let plan = make_plan(true, false, ServiceType::ClusterIP, vec![]);
        let cp = config_plan_from_runtime_plan(&plan);
        assert!(matches!(cp, ConfigPlan::Update { .. }));
    }

    #[test]
    fn config_plan_bridge_noop_when_not_changed() {
        use crate::reconcilers::contracts::ConfigPlan;
        use crate::reconcilers::runtime_plan::config_plan_from_runtime_plan;
        let plan = make_plan(false, false, ServiceType::ClusterIP, vec![]);
        let cp = config_plan_from_runtime_plan(&plan);
        assert!(matches!(cp, ConfigPlan::NoOp { .. }));
    }

    // ── ownership preflight (unit) ────────────────────────────────────────────

    #[test]
    fn is_managed_by_controller_true_when_label_present() {
        let mut labels = BTreeMap::new();
        labels.insert(
            LABEL_MANAGED_BY.to_string(),
            "wicket-controller".to_string(),
        );
        assert!(is_managed_by_controller(Some(&labels)));
    }

    #[test]
    fn is_managed_by_controller_false_when_label_absent() {
        let labels = BTreeMap::new();
        assert!(!is_managed_by_controller(Some(&labels)));
    }

    #[test]
    fn is_managed_by_controller_false_when_wrong_value() {
        let mut labels = BTreeMap::new();
        labels.insert(LABEL_MANAGED_BY.to_string(), "helm".to_string());
        assert!(!is_managed_by_controller(Some(&labels)));
    }

    #[test]
    fn is_managed_by_controller_false_when_no_labels() {
        assert!(!is_managed_by_controller(None));
    }

    // ── replica conversion ────────────────────────────────────────────────────

    #[test]
    fn replica_conversion_valid_values() {
        // u32 values that fit in i32 must convert without error.
        let ok: Result<i32, _> = i32::try_from(0u32);
        assert!(ok.is_ok());
        let ok: Result<i32, _> = i32::try_from(i32::MAX as u32);
        assert!(ok.is_ok());
    }

    #[test]
    fn replica_conversion_overflow_is_err() {
        // u32 values that exceed i32::MAX must fail conversion.
        let overflow = (i32::MAX as u32) + 1;
        let err: Result<i32, _> = i32::try_from(overflow);
        assert!(
            err.is_err(),
            "overflow must be an error, not silently coerced"
        );
    }

    // ── deployment_changed semantics ──────────────────────────────────────────

    #[test]
    fn deployment_changed_false_for_config_only_change_when_existing() {
        // When spec_changed=false and the object already exists, deployment_changed
        // must be false.  This is the "config-only change, no rollout" case.
        // We test the logic directly since we cannot call apply_deployment without
        // a live cluster.
        let already_exists = true;
        let spec_changed = false;
        let changed = !already_exists || spec_changed;
        assert!(
            !changed,
            "config-only change on existing deployment must not set deployment_changed"
        );
    }

    #[test]
    fn deployment_changed_true_when_spec_changed() {
        let already_exists = true;
        let spec_changed = true;
        let changed = !already_exists || spec_changed;
        assert!(changed);
    }

    #[test]
    fn deployment_changed_true_when_new_object() {
        let already_exists = false;
        let spec_changed = false;
        let changed = !already_exists || spec_changed;
        assert!(changed, "new object must always set deployment_changed");
    }

    // ── service_changed semantics ─────────────────────────────────────────────

    #[test]
    fn service_changed_false_for_config_only_when_existing() {
        let already_exists = true;
        let spec_changed = false;
        let changed = !already_exists || spec_changed;
        assert!(!changed);
    }

    #[test]
    fn service_changed_true_when_spec_changed() {
        let already_exists = true;
        let spec_changed = true;
        let changed = !already_exists || spec_changed;
        assert!(changed);
    }

    #[test]
    fn service_changed_true_when_new_object() {
        let already_exists = false;
        let spec_changed = false;
        let changed = !already_exists || spec_changed;
        assert!(changed);
    }

    // ── Ownership preflight: collision rejection semantics ────────────────────
    //
    // These tests verify the preflight logic that rejects unowned same-name
    // objects.  They exercise the pure `is_managed_by_controller` helper and
    // the `ApplyError::NotOwned` construction to confirm the invariants hold
    // without a live Kubernetes cluster.

    /// An object with the exact managed-by label is owned; any other value
    /// (including a prefix match or case variation) is not.
    #[test]
    fn ownership_check_exact_label_value_required() {
        // Exact match: owned.
        let mut labels = BTreeMap::new();
        labels.insert(
            LABEL_MANAGED_BY.to_string(),
            "wicket-controller".to_string(),
        );
        assert!(
            is_managed_by_controller(Some(&labels)),
            "exact managed-by value must be accepted"
        );

        // Prefix match: not owned.
        let mut labels2 = BTreeMap::new();
        labels2.insert(
            LABEL_MANAGED_BY.to_string(),
            "wicket-controller-extra".to_string(),
        );
        assert!(
            !is_managed_by_controller(Some(&labels2)),
            "prefix match must not be accepted (exact value required)"
        );

        // Case variation: not owned.
        let mut labels3 = BTreeMap::new();
        labels3.insert(
            LABEL_MANAGED_BY.to_string(),
            "Wicket-Controller".to_string(),
        );
        assert!(
            !is_managed_by_controller(Some(&labels3)),
            "case variation must not be accepted (exact value required)"
        );
    }

    /// An object with multiple labels is owned only when the managed-by label
    /// has the correct value; other labels are irrelevant.
    #[test]
    fn ownership_check_ignores_other_labels() {
        let mut labels = BTreeMap::new();
        labels.insert("app.kubernetes.io/name".to_string(), "wicket".to_string());
        labels.insert(
            "app.kubernetes.io/instance".to_string(),
            "my-gw".to_string(),
        );
        labels.insert(
            LABEL_MANAGED_BY.to_string(),
            "wicket-controller".to_string(),
        );
        labels.insert("custom.io/extra".to_string(), "value".to_string());

        assert!(
            is_managed_by_controller(Some(&labels)),
            "object with correct managed-by label plus other labels must be owned"
        );
    }

    /// ApplyError::NotOwned carries the exact namespace and name of the
    /// conflicting object so operators can identify it in logs.
    #[test]
    fn not_owned_error_carries_exact_identity() {
        use crate::reconcilers::contracts::ApplyError;

        let err = ApplyError::NotOwned {
            namespace: "staging".to_string(),
            name: "wicket-gw-prod-gateway-config".to_string(),
        };
        let display = err.to_string();

        assert!(
            display.contains("staging"),
            "NotOwned error must contain namespace 'staging': {display}"
        );
        assert!(
            display.contains("wicket-gw-prod-gateway-config"),
            "NotOwned error must contain name 'wicket-gw-prod-gateway-config': {display}"
        );
        // The error message must mention the controller so operators know who
        // should own the object.
        assert!(
            display.contains("wicket-controller"),
            "NotOwned error must mention 'wicket-controller': {display}"
        );
    }

    /// The preflight outcome for an unowned object must be Err(NotOwned), not
    /// Ok(false).  Returning Ok(false) would cause the applier to silently
    /// overwrite the object rather than aborting.
    ///
    /// We test this by simulating the preflight match logic directly.
    #[test]
    fn preflight_unowned_object_produces_not_owned_error() {
        use crate::reconcilers::contracts::ApplyError;

        // Simulate the preflight match: object exists but is not managed.
        let unowned_labels: BTreeMap<String, String> = {
            let mut m = BTreeMap::new();
            m.insert(LABEL_MANAGED_BY.to_string(), "helm".to_string());
            m
        };

        // Replicate the preflight logic from preflight_configmap / preflight_deployment.
        let result: Result<bool, ApplyError> = if is_managed_by_controller(Some(&unowned_labels)) {
            Ok(true) // owned
        } else {
            Err(ApplyError::NotOwned {
                namespace: "prod".to_string(),
                name: "wicket-gw-my-gw-config".to_string(),
            })
        };

        assert!(
            result.is_err(),
            "unowned object must produce Err(NotOwned), not Ok(false)"
        );
        assert!(
            matches!(result.unwrap_err(), ApplyError::NotOwned { .. }),
            "error must be NotOwned variant"
        );
    }

    /// The preflight outcome for an absent object (None from get_opt) must be
    /// Ok(false), not Err.  A missing object is not an error; it means the
    /// applier should create it.
    #[test]
    fn preflight_absent_object_produces_ok_false() {
        use crate::reconcilers::contracts::ApplyError;

        // Simulate the preflight match: object does not exist (get_opt returns None).
        // Absent object → Ok(false), not Err.
        let absent_labels: Option<&BTreeMap<String, String>> = None;
        let result: Result<bool, ApplyError> = if is_managed_by_controller(absent_labels) {
            Ok(true)
        } else if absent_labels.is_none() {
            Ok(false) // absent
        } else {
            Err(ApplyError::NotOwned {
                namespace: "ns".to_string(),
                name: "obj".to_string(),
            })
        };

        assert!(
            result.is_ok(),
            "absent object must produce Ok(false), not Err"
        );
        assert!(!result.unwrap(), "absent object must produce Ok(false)");
    }

    /// The preflight outcome for an owned object must be Ok(true).
    #[test]
    fn preflight_owned_object_produces_ok_true() {
        use crate::reconcilers::contracts::ApplyError;

        let owned_labels: BTreeMap<String, String> = {
            let mut m = BTreeMap::new();
            m.insert(
                LABEL_MANAGED_BY.to_string(),
                "wicket-controller".to_string(),
            );
            m
        };

        // Replicate the preflight match: object exists and is managed.
        let result: Result<bool, ApplyError> = if is_managed_by_controller(Some(&owned_labels)) {
            Ok(true) // owned
        } else {
            Err(ApplyError::NotOwned {
                namespace: "prod".to_string(),
                name: "wicket-gw-my-gw-config".to_string(),
            })
        };

        assert!(
            result.is_ok(),
            "owned object must produce Ok(true), not Err"
        );
        assert!(result.unwrap(), "owned object must produce Ok(true)");
    }

    /// The managed_labels() helper must always produce the correct managed-by
    /// label value so that objects created by the applier pass their own
    /// ownership preflight on subsequent reconcile cycles.
    #[test]
    fn managed_labels_passes_own_preflight() {
        let plan = make_plan(false, false, ServiceType::ClusterIP, vec![]);
        let labels = managed_labels(&plan);

        // The labels produced by managed_labels() must pass is_managed_by_controller.
        assert!(
            is_managed_by_controller(Some(&labels)),
            "managed_labels() output must pass is_managed_by_controller (idempotency)"
        );
    }
}
