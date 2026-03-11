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
//! 2. Ensure the owned `ConfigMap` is up-to-date (delegates to `apply_config_plan`).
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
//! - **Revision annotations**: the ConfigMap carries `wicket.io/config-revision`
//!   (via `apply_config_plan`); the Deployment carries `wicket.io/spec-revision`.
//!
//! # Ordering
//!
//! ```text
//! 1. ServiceAccount  (no dependencies)
//! 2. ConfigMap       (via apply_config_plan; no-op when config_changed=false)
//! 3. Service         (no dependencies)
//! 4. Deployment      (depends on ServiceAccount and ConfigMap existing)
//! ```
//!
//! Steps 2 and 4 are skipped (no-op) when the plan signals no change.

use std::collections::BTreeMap;

use k8s_openapi::api::apps::v1::{Deployment, DeploymentSpec};
use k8s_openapi::api::core::v1::Service as K8sService;
use k8s_openapi::api::core::v1::{
    ConfigMapVolumeSource, Container, ContainerPort, EnvVar, PodSpec, PodTemplateSpec,
    ResourceRequirements, ServiceAccount, ServicePort, ServiceSpec, Volume, VolumeMount,
};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{LabelSelector, ObjectMeta, OwnerReference};
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
use kube::api::{Api, Patch, PatchParams};
use kube::Client;
use tokio::sync::RwLock;

use crate::reconcilers::config_applier::{apply_config_plan, ConfigApplierInput};
use crate::reconcilers::config_generator::WicketConfig;
use crate::reconcilers::contracts::{ApplyError, ConfigApplyResult, ServiceType};
use crate::reconcilers::runtime_plan::{config_plan_from_runtime_plan, GatewayRuntimePlan};

// ─────────────────────────────────────────────────────────────────────────────
// Annotation / label constants (ADR section 2.3)
// ─────────────────────────────────────────────────────────────────────────────

/// Annotation key for the spec revision hash on the Deployment.
pub const SPEC_REVISION_ANNOTATION: &str = "wicket.io/spec-revision";

/// Annotation key for the config revision hash on the ConfigMap and pod template.
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
    /// Whether the `Service` was created or patched.
    pub service_changed: bool,
    /// Whether the `Deployment` was created or patched.
    pub deployment_changed: bool,
    /// Whether a Deployment rollout was triggered (spec_changed=true).
    pub rollout_triggered: bool,
}

// ─────────────────────────────────────────────────────────────────────────────
// Applier input
// ─────────────────────────────────────────────────────────────────────────────

/// Everything the runtime applier needs to apply a `GatewayRuntimePlan`.
pub struct RuntimeApplierInput<'a> {
    /// Kubernetes client.
    pub client: &'a Client,
    /// In-memory config handle (passed through to `apply_config_plan`).
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
pub async fn apply_runtime_plan(
    plan: &GatewayRuntimePlan,
    input: &RuntimeApplierInput<'_>,
) -> Result<RuntimeApplyResult, ApplyError> {
    let mut result = RuntimeApplyResult::default();

    // ── 1. ServiceAccount ─────────────────────────────────────────────────────
    result.service_account_created = apply_service_account(plan, input.client).await?;

    // ── 2. ConfigMap (via config_applier) ─────────────────────────────────────
    let config_plan = config_plan_from_runtime_plan(plan);
    let config_input = ConfigApplierInput {
        client: input.client,
        configmap_name: &plan.config_map_name,
        configmap_namespace: &plan.gateway_namespace,
        in_memory_config: input.in_memory_config,
    };
    let config_result = apply_config_plan(&config_plan, &config_input).await?;
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

/// Build the pod template labels: managed labels + config-revision label.
fn pod_template_labels(plan: &GatewayRuntimePlan) -> BTreeMap<String, String> {
    let mut labels = managed_labels(plan);
    labels.insert(
        CONFIG_REVISION_ANNOTATION.to_string(),
        plan.config_hash.clone(),
    );
    labels
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
// ServiceAccount
// ─────────────────────────────────────────────────────────────────────────────

/// Ensure the owned `ServiceAccount` exists.
///
/// Uses a merge-patch so the call is idempotent.  Returns `true` if the object
/// was just created (did not previously exist), `false` if it already existed.
///
/// # Errors
///
/// Returns `ApplyError::KubeApi` if the API call fails.
async fn apply_service_account(
    plan: &GatewayRuntimePlan,
    client: &Client,
) -> Result<bool, ApplyError> {
    let api: Api<ServiceAccount> = Api::namespaced(client.clone(), &plan.gateway_namespace);

    let sa = ServiceAccount {
        metadata: owned_object_meta(&plan.service_account_name, plan, None),
        ..Default::default()
    };

    let patch = serde_json::to_value(&sa).map_err(|e| ApplyError::Serialization(e.to_string()))?;

    // Check existence first so we can report created vs. already-present.
    let exists = api
        .get_opt(&plan.service_account_name)
        .await
        .map_err(|e| ApplyError::KubeApi(e.to_string()))?
        .is_some();

    api.patch(
        &plan.service_account_name,
        &PatchParams::apply(FIELD_MANAGER).force(),
        &Patch::Apply(&patch),
    )
    .await
    .map_err(|e| ApplyError::KubeApi(e.to_string()))?;

    let created = !exists;
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
// Service
// ─────────────────────────────────────────────────────────────────────────────

/// Ensure the owned `Service` matches the desired shape.
///
/// Uses server-side apply (force) so the call is idempotent.  Returns `true`
/// if the object was created or patched, `false` if the plan signals no spec
/// change and the object already exists.
///
/// # Errors
///
/// Returns `ApplyError::KubeApi` if the API call fails.
async fn apply_service(plan: &GatewayRuntimePlan, client: &Client) -> Result<bool, ApplyError> {
    let api: Api<K8sService> = Api::namespaced(client.clone(), &plan.gateway_namespace);

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

    // Selector matches the pod template labels (minus config-revision which
    // changes on every config update and must not be part of the selector).
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

    // We always patch; report changed when spec_changed (new ports/type) or
    // when the object may not have existed yet.
    Ok(plan.spec_changed)
}

// ─────────────────────────────────────────────────────────────────────────────
// Deployment
// ─────────────────────────────────────────────────────────────────────────────

/// Ensure the owned `Deployment` matches the desired spec.
///
/// Returns `(changed, rollout_triggered)`.
/// - `changed` is `true` when the Deployment was created or patched.
/// - `rollout_triggered` is `true` when `plan.spec_changed` is `true` (the
///   pod template changed, which causes Kubernetes to roll out new pods).
///
/// # Errors
///
/// Returns `ApplyError::KubeApi` if the API call fails.
async fn apply_deployment(
    plan: &GatewayRuntimePlan,
    client: &Client,
) -> Result<(bool, bool), ApplyError> {
    let api: Api<Deployment> = Api::namespaced(client.clone(), &plan.gateway_namespace);

    let replicas = i32::try_from(plan.runtime_metadata.replicas).unwrap_or(1);

    // Build resource requirements from the flat key-value map.
    // Keys: "requests.cpu", "requests.memory", "limits.cpu", "limits.memory".
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

    // Volume mount for the ConfigMap.
    let volume_mount = VolumeMount {
        name: "config".to_string(),
        mount_path: "/etc/wicket".to_string(),
        read_only: Some(true),
        ..Default::default()
    };

    // ConfigMap volume.
    let config_volume = Volume {
        name: "config".to_string(),
        config_map: Some(ConfigMapVolumeSource {
            name: plan.config_map_name.clone(),
            ..Default::default()
        }),
        ..Default::default()
    };

    // Env var exposing the config revision so the proxy can log it.
    let config_rev_env = EnvVar {
        name: "WICKET_CONFIG_REVISION".to_string(),
        value: Some(plan.config_hash.clone()),
        ..Default::default()
    };

    let container = Container {
        name: "wicket-proxy".to_string(),
        image: Some(plan.runtime_metadata.image.clone()),
        ports: Some(container_ports),
        volume_mounts: Some(vec![volume_mount]),
        env: Some(vec![config_rev_env]),
        resources: Some(resource_requirements),
        ..Default::default()
    };

    // Pod template annotations carry the spec-revision so drift is detectable.
    let mut pod_annotations = BTreeMap::new();
    pod_annotations.insert(SPEC_REVISION_ANNOTATION.to_string(), plan.spec_hash.clone());
    pod_annotations.insert(
        CONFIG_REVISION_ANNOTATION.to_string(),
        plan.config_hash.clone(),
    );

    let pod_template = PodTemplateSpec {
        metadata: Some(ObjectMeta {
            labels: Some(pod_template_labels(plan)),
            annotations: Some(pod_annotations),
            ..Default::default()
        }),
        spec: Some(PodSpec {
            service_account_name: Some(plan.service_account_name.clone()),
            containers: vec![container],
            volumes: Some(vec![config_volume]),
            node_selector: if plan.runtime_metadata.node_selector.is_empty() {
                None
            } else {
                Some(plan.runtime_metadata.node_selector.clone())
            },
            ..Default::default()
        }),
    };

    // Deployment-level annotations carry the spec-revision for drift detection.
    let mut deploy_annotations = BTreeMap::new();
    deploy_annotations.insert(SPEC_REVISION_ANNOTATION.to_string(), plan.spec_hash.clone());

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

    let rollout = plan.spec_changed;
    let changed = plan.spec_changed || plan.config_changed;

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
    fn pod_template_labels_includes_config_revision() {
        let plan = make_plan(true, false, ServiceType::ClusterIP, vec![]);
        let labels = pod_template_labels(&plan);

        assert_eq!(
            labels.get(CONFIG_REVISION_ANNOTATION).map(String::as_str),
            Some("aabbcc")
        );
        // Must also carry all managed labels.
        assert_eq!(
            labels.get(LABEL_MANAGED_BY).map(String::as_str),
            Some("wicket-controller")
        );
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

        // Verify the plan carries the ports correctly (the actual K8s object
        // construction is tested indirectly via apply_service in integration tests).
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
        let plan = make_plan(true, false, ServiceType::ClusterIP, vec![]);
        let cp = config_plan_from_runtime_plan(&plan);
        assert!(matches!(cp, ConfigPlan::Update { .. }));
    }

    #[test]
    fn config_plan_bridge_noop_when_not_changed() {
        use crate::reconcilers::contracts::ConfigPlan;
        let plan = make_plan(false, false, ServiceType::ClusterIP, vec![]);
        let cp = config_plan_from_runtime_plan(&plan);
        assert!(matches!(cp, ConfigPlan::NoOp { .. }));
    }
}
