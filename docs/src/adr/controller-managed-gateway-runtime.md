# ADR: Managed Gateway Runtime Operator for Wicket (Phase 1)

**Status:** Proposed
**Date:** 2026-03-11
**Issue:** `bd-8qz` (epic: `bd-0p7`, foundational: `bd-hkn`)

---

## 1. Context

### Current state

`crates/wicket-controller/` is a config-synthesizing Gateway API controller. It watches
Gateway, HTTPRoute, TCPRoute, TLSRoute, Secret, and ReferenceGrant resources, builds a
`GatewayState` snapshot, and writes a `wicket.toml` into a pre-existing `ConfigMap`. The
Wicket proxy Deployment is deployed externally via static manifests in `deploy/k8s/` and
reads that ConfigMap from a volume mount. The controller does not own, create, or manage
any runtime workload objects.

### Why this is insufficient

An Envoy-Gateway-style managed operator owns the data-plane runtime for each Gateway it
manages. The controller is the source of truth for what runtime objects exist, what they
contain, and when they are updated. The current model has several structural gaps:

**No lifecycle ownership.** The proxy Deployment, Service, and ServiceAccount are created
by operators via static manifests. The controller has no way to enforce naming, labels,
owner references, or resource constraints. Drift between the manifest and the controller's
expectations is undetectable.

**Address heuristics instead of ownership.** `gateway.rs` resolves Gateway addresses by
guessing Service names (`<name>`, `<name>-lb`, `<name>-gateway`, `wicket-<name>`). This
is fragile and incorrect. The Gateway API spec requires addresses to reflect actual
listener endpoints. A managed operator derives addresses from the Service it owns.

**`Programmed=True` is unconditional.** The current reconciler sets `Programmed=True`
immediately after writing the ConfigMap, regardless of whether any proxy Pod is running,
healthy, or has loaded the new config. This violates the Gateway API conformance
requirement that `Programmed` reflects actual data-plane readiness.

**No revision tracking.** The controller has no concept of which config version a running
Pod has loaded. There is no way to distinguish "config written but not yet reloaded" from
"config loaded and serving traffic."

**No garbage collection.** If a Gateway is deleted, the controller removes it from the
store and regenerates config, but the proxy Deployment and Service remain. Operators must
clean them up manually.

**No extension points for PDB/HPA.** There is no place in the current model to attach
disruption budgets or autoscaling policy to a Gateway's runtime.

### What we need to solve in phase 1

1. Controller owns and reconciles `ServiceAccount`, `ConfigMap`, `Deployment`, and
   `Service` for each managed Gateway.
2. Stable naming, labeling, and owner-reference conventions for all owned objects.
3. A pure internal IR (`GatewayRuntimePlan`) that separates planning from apply.
4. A revision/hash strategy that distinguishes config-only hot reloads from Deployment
   rollouts.
5. `Programmed=True` gated on actual rollout readiness at the intended revision.
6. Gateway addresses derived from the owned Service, not from name guessing.
7. Coexistence with today's externally deployed static manifests during migration.
8. No new CRD in phase 1.

---

## 2. Decision

### 2.1 Per-Gateway Deployment topology

Each managed Gateway gets its own set of controller-owned runtime objects:

```
Gateway "my-gw" (namespace: "prod")
  |
  +-- ServiceAccount  wicket-gw-my-gw          (prod)
  +-- ConfigMap       wicket-gw-my-gw-config    (prod)
  +-- Deployment      wicket-gw-my-gw           (prod)
  +-- Service         wicket-gw-my-gw           (prod)
```

Rationale: per-Gateway isolation is the correct initial topology. It matches the Gateway
API model (one Gateway = one logical data-plane instance), simplifies owner-reference
garbage collection, and avoids the cross-Gateway blast radius of a shared Deployment.
Shared-Deployment-per-GatewayClass is explicitly deferred (see Alternatives).

### 2.2 Naming convention

All controller-owned objects follow the pattern:

```
wicket-gw-<gateway-name>[-<suffix>]
```

where `<gateway-name>` is the Gateway's `.metadata.name` (truncated to fit Kubernetes
name length limits; max 63 chars total for the full name). The suffix is:

| Object       | Suffix    | Example                          |
|--------------|-----------|----------------------------------|
| ServiceAccount | (none)  | `wicket-gw-my-gw`               |
| ConfigMap    | `-config`  | `wicket-gw-my-gw-config`        |
| Deployment   | (none)    | `wicket-gw-my-gw`               |
| Service      | (none)    | `wicket-gw-my-gw`               |

All owned objects are created in the same namespace as the Gateway.

Name truncation rule: if `wicket-gw-<gateway-name>` exceeds 52 characters (leaving 11
chars for the longest suffix `-config`), truncate `<gateway-name>` and append a 6-char
lowercase hex hash of the full name to preserve uniqueness:

```
wicket-gw-<truncated-name>-<6-char-hash>[-suffix]
```

### 2.3 Labels and annotations on owned objects

Every controller-owned object carries these labels:

```yaml
app.kubernetes.io/managed-by: wicket-controller
app.kubernetes.io/component: gateway-runtime
app.kubernetes.io/instance: <gateway-name>
app.kubernetes.io/name: wicket
wicket.io/gateway-namespace: <gateway-namespace>
wicket.io/gateway-name: <gateway-name>
```

The Deployment's pod template carries the same labels plus:

```yaml
wicket.io/config-revision: <config-hash>
```

This label is the rollout trigger (see section 2.6).

### 2.4 Owner references

Every controller-owned object has an owner reference pointing to the Gateway:

```yaml
ownerReferences:
- apiVersion: gateway.networking.k8s.io/v1
  kind: Gateway
  name: <gateway-name>
  uid: <gateway-uid>
  controller: true
  blockOwnerDeletion: true
```

Consequence: when the Gateway is deleted, Kubernetes garbage-collects all owned objects
automatically. The controller does not need explicit deletion logic for the happy path.
The controller must still handle finalizer-based cleanup if it needs to drain traffic
before deletion (deferred to a follow-on task; not in phase 1).

### 2.5 Extension seams for PDB and HPA

The Deployment spec is constructed from the `GatewayRuntimePlan` (see section 2.7). The
plan includes a `runtime_metadata` section that carries fields the applier uses to
configure the Deployment but that are not part of the proxy config payload:

- `replicas: u32` -- initial replica count (default 1)
- `image: String` -- proxy container image
- `resources: Option<ResourceRequirements>` -- CPU/memory requests and limits
- `node_selector: BTreeMap<String, String>`
- `tolerations: Vec<Toleration>`

`PodDisruptionBudget` and `HorizontalPodAutoscaler` are NOT created in phase 1. The
naming convention (`wicket-gw-<name>`) is reserved for them. The applier is structured
so adding PDB/HPA support requires adding new apply steps, not restructuring existing
ones.

---

## 3. Planner / Applier / Status-Observer Boundaries

### 3.1 Overview

The reconcile flow is split into three layers with explicit input/output contracts. No
layer may call into another layer's concerns.

```
  SharedStore snapshot
  + owned-object observations
        |
        v
  [ Planner ]  -- pure, no I/O, deterministic
        |
        v
  GatewayRuntimePlan (IR)
        |
        v
  [ Applier ]  -- side-effecting, reads plan, writes k8s objects
        |
        v
  owned object state (Deployment rollout status, Service IPs)
        |
        v
  [ Status Observer ]  -- reads owned state, writes Gateway status
```

### 3.2 Planner

**Inputs:**
- `SharedStore` snapshot (Gateways, Routes, Secrets, ReferenceGrants, Endpoints)
- Controller configuration (image, default replicas, controller namespace)
- Observed owned-object state (current ConfigMap hash, current Deployment revision)

**Outputs:**
- `GatewayRuntimePlan` (see section 2.7)
- No Kubernetes API calls
- No filesystem writes
- No async I/O

**Invariants:**
- Given the same inputs, the planner always produces the same plan (deterministic).
- The planner does not read from the Kubernetes API. All inputs arrive via the store
  snapshot or explicit parameters.
- The planner does not know whether the plan will be applied or skipped.

### 3.3 Applier

**Inputs:**
- `GatewayRuntimePlan`
- Kubernetes client

**Outputs:**
- Creates or patches owned objects via server-side apply.
- Returns `ApplyResult` indicating which objects changed and whether a rollout was
  triggered.
- Does not compute what the desired state should be; that is the planner's job.

**Invariants:**
- The applier is idempotent: applying the same plan twice produces no change on the
  second call.
- The applier does not read `SharedStore` or Gateway API objects. It only reads the
  objects it owns (to detect drift) and the plan it was given.
- The applier does not write Gateway status. That is the status observer's job.
- Garbage collection: the applier deletes owned objects that are no longer referenced by
  any active plan for this Gateway (e.g., if a listener is removed). Deletion is
  performed after successful apply of the new desired state.

### 3.4 Status Observer

**Inputs:**
- Owned `Deployment` rollout status (observed generation, ready replicas, conditions)
- Owned `Service` status (load balancer ingress IPs/hostnames, cluster IP)
- `GatewayRuntimePlan` (to know the intended config revision)
- Current Gateway object (to read `.metadata.generation`)

**Outputs:**
- Gateway `.status.addresses` -- derived from owned Service (see section 2.8)
- Gateway `.status.conditions` -- `Accepted` and `Programmed`
- Gateway `.status.listeners[*].attachedRoutes` -- from attachment planner output
- Gateway `.metadata.observedGeneration` -- from `.metadata.generation`

**Invariants:**
- The status observer does not modify owned objects.
- The status observer does not call the planner or applier.
- `Programmed=True` is only set when the Deployment's ready replicas are >= 1 AND the
  pod template's `wicket.io/config-revision` label matches the plan's `config_hash`
  (see section 2.6).

---

## 4. GatewayRuntimePlan (Internal IR)

### 4.1 Purpose

`GatewayRuntimePlan` is a pure internal intermediate representation of the desired
runtime state for one Gateway. It is the contract between the planner and the applier.
It is never serialized to Kubernetes objects directly; the applier translates it into
concrete API objects.

### 4.2 Conceptual structure

```
GatewayRuntimePlan {
    // Identity
    gateway_namespace: String,
    gateway_name:      String,
    gateway_uid:       String,   // for owner references

    // Revision
    config_hash:       String,   // hex SHA-256 of rendered config payload (see 2.6)
    spec_hash:         String,   // hex SHA-256 of runtime metadata (image, replicas, etc.)

    // Config payload
    config_toml:       String,   // rendered wicket.toml content for the ConfigMap

    // Runtime metadata (infrastructure concerns, not proxy config)
    runtime_metadata: RuntimeMetadata {
        image:         String,
        replicas:      u32,
        resources:     Option<ResourceRequirements>,
        node_selector: BTreeMap<String, String>,
        tolerations:   Vec<Toleration>,
        // ... future: affinity, topology spread, etc.
    },

    // Service shape
    service_type:      ServiceType,   // ClusterIP | LoadBalancer | NodePort
    service_ports:     Vec<ServicePort>,

    // Status intents (computed by planner, consumed by status observer)
    listener_statuses: Vec<ListenerStatusIntent> {
        name:            String,
        attached_routes: u32,
        supported_kinds: Vec<RouteGroupKind>,
        accepted:        bool,
        reason:          Option<String>,
    },
}
```

### 4.3 What the plan must NOT contain

- Kubernetes object metadata (labels, annotations, owner refs) -- the applier adds these.
- References to Kubernetes API types from `k8s-openapi` -- the plan uses plain Rust types.
- Any I/O or async operations.
- Knowledge of whether the plan differs from the current cluster state -- that is the
  applier's job.
- Gateway API status condition strings -- the status observer translates `ListenerStatusIntent`
  into Gateway API condition types.

### 4.4 Plan equality and hashing

The plan exposes two hashes:

- `config_hash`: SHA-256 of `config_toml`. Changes when proxy routing/TLS config changes.
  Triggers a ConfigMap update. Does NOT trigger a Deployment rollout by itself (the proxy
  hot-reloads from the ConfigMap).
- `spec_hash`: SHA-256 of `runtime_metadata` fields. Changes when image, replicas, or
  resource requirements change. Triggers a Deployment rollout.

The pod template label `wicket.io/config-revision` is set to `config_hash`. When the
proxy reloads config from the ConfigMap, it is expected to update a readiness probe or
status endpoint that reflects the loaded config version. Until that mechanism exists
(phase 2), the status observer uses Deployment ready-replica count as a proxy for
readiness (see Open Questions).

---

## 5. Revision and Hash Strategy

### 5.1 What triggers what

| Change type                        | config_hash | spec_hash | ConfigMap update | Deployment rollout |
|------------------------------------|-------------|-----------|------------------|--------------------|
| Route added/removed/modified       | changes     | unchanged | yes              | no (hot reload)    |
| TLS cert reference changed         | changes     | unchanged | yes              | no (hot reload)    |
| Proxy image changed                | unchanged   | changes   | no               | yes                |
| Replica count changed              | unchanged   | changes   | no               | yes                |
| Resource limits changed            | unchanged   | changes   | no               | yes                |
| Both config and image changed      | changes     | changes   | yes              | yes                |

### 5.2 How revisions propagate

1. Planner computes `config_hash` and `spec_hash` from plan inputs.
2. Applier compares `config_hash` to the current ConfigMap annotation
   `wicket.io/config-revision`. If different, patches the ConfigMap data and updates the
   annotation.
3. Applier compares `spec_hash` to the current Deployment annotation
   `wicket.io/spec-revision`. If different, patches the Deployment pod template label
   `wicket.io/config-revision` (to `config_hash`) and updates the Deployment spec. This
   triggers a rolling update.
4. If only `config_hash` changed (not `spec_hash`), the applier patches the ConfigMap
   but does NOT touch the Deployment. The proxy hot-reloads via its existing file-watch
   path.
5. Status observer reads the Deployment's pod template label `wicket.io/config-revision`
   from the ready pods and compares it to the plan's `config_hash`. If they match and
   ready replicas >= 1, `Programmed=True`.

### 5.3 Annotations on owned objects

```
wicket.io/config-revision: <config_hash>   -- on ConfigMap and Deployment pod template
wicket.io/spec-revision:   <spec_hash>     -- on Deployment
wicket.io/managed-by-generation: <n>       -- Gateway .metadata.generation at plan time
```

---

## 6. Status and Readiness Source of Truth

### 6.1 Gateway addresses

Gateway `.status.addresses` is populated exclusively from the owned Service:

- If `Service.spec.type == LoadBalancer`: use `Service.status.loadBalancer.ingress[*].ip`
  and `Service.status.loadBalancer.ingress[*].hostname`.
- If `Service.spec.type == ClusterIP`: use `Service.spec.clusterIP`.
- If `Service.spec.type == NodePort`: leave addresses empty (node IPs are not tracked in
  phase 1; this is an open question).
- If the Service does not yet have an assigned address (e.g., LoadBalancer pending):
  leave `.status.addresses` empty. Do NOT use placeholder IPs or name-guessing fallbacks.

The current `get_gateway_addresses` heuristic in `gateway.rs` (which guesses Service
names) is removed when a Gateway transitions to managed mode.

### 6.2 Programmed condition

`Programmed=True` requires ALL of:

1. The owned Deployment exists.
2. `Deployment.status.readyReplicas >= 1`.
3. The ready pods' pod template label `wicket.io/config-revision` equals the plan's
   `config_hash`.

If any condition is false, `Programmed=False` with reason `DeploymentNotReady` or
`RevisionMismatch` as appropriate.

`Accepted=True` is set when the Gateway's GatewayClass is managed by this controller and
the plan was successfully computed (no planning errors). `Accepted` does not depend on
runtime readiness.

### 6.3 observedGeneration

The status observer always sets `Gateway.status.observedGeneration` to
`Gateway.metadata.generation` after writing status, regardless of whether `Programmed`
is true or false.

---

## 7. Migration and Coexistence

### 7.1 Current state

Today, Gateways managed by Wicket have their proxy runtime deployed via static manifests
in `deploy/k8s/wicket.yaml`. The controller writes to a pre-existing ConfigMap
(`wicket-config` in namespace `wicket-poc`). The proxy Deployment is not owned by the
controller.

### 7.2 Opt-in annotation

Phase 1 introduces managed mode as opt-in. A Gateway is managed (controller creates and
owns runtime objects) only if it carries the annotation:

```
wicket.io/managed-runtime: "true"
```

Gateways without this annotation continue to use the existing config-synthesis-only path.
The controller writes to the pre-existing ConfigMap as before. No behavior change for
unannotated Gateways.

### 7.3 Migration path for an existing Gateway

1. Operator removes the static Deployment and Service from `deploy/k8s/wicket.yaml` (or
   scales the Deployment to 0 and removes the Service).
2. Operator adds `wicket.io/managed-runtime: "true"` to the Gateway.
3. Controller detects the annotation, computes a plan, and creates the owned
   ServiceAccount, ConfigMap, Deployment, and Service.
4. Once the new Deployment is ready and `Programmed=True`, the migration is complete.

There is no automated migration. The operator controls the cutover timing.

### 7.4 Coexistence invariants

- A Gateway is either in managed mode or config-synthesis-only mode. Never both.
- The controller does not attempt to adopt pre-existing objects (Deployments, Services)
  that lack the controller's owner reference. Adoption is out of scope for phase 1.
- The pre-existing ConfigMap path (`context.rs` / `trigger_config_update`) remains
  unchanged for unannotated Gateways.

---

## 8. Alternatives Considered

### A. Stay config-synthesis-only (no owned runtime objects)

Rejected. The address-heuristic problem and unconditional `Programmed=True` are
correctness violations that cannot be fixed without owning the Service. Lifecycle
management (garbage collection, image updates, resource constraints) requires ownership.
The current model is a dead end for a production-grade operator.

### B. Introduce an intermediate CRD (e.g., `GatewayRuntime`) now

Rejected for phase 1. A CRD adds API surface, RBAC, versioning, and conversion webhook
concerns before we have validated the runtime model. The internal `GatewayRuntimePlan`
IR provides the same planning/apply separation without the API surface. A CRD can be
introduced in a later phase if external observability of the runtime plan is needed.

### C. Shared Deployment per GatewayClass first

Rejected. A shared Deployment means all Gateways in a GatewayClass share one proxy
process. This complicates config isolation, rollout safety, and resource attribution.
Per-Gateway Deployment is the correct initial topology. Shared-Deployment can be
introduced as an optimization later if resource density is a concern.

### D. Use Helm or a separate operator framework for runtime management

Rejected. The controller is already a kube-rs operator. Adding Helm or a separate
framework for runtime object management would split the reconcile loop across two systems
with no clear benefit. All runtime object management stays in `wicket-controller`.

---

## 9. Risks and Open Questions

### Risks

**R1: Name collision with pre-existing objects.**
If an operator has a pre-existing Deployment named `wicket-gw-<name>` in the same
namespace, the controller will attempt to adopt it via server-side apply. This could
overwrite operator-managed fields. Mitigation: the controller checks for the
`app.kubernetes.io/managed-by: wicket-controller` label before applying. If the label is
absent, the controller logs an error and does not apply. This is a manual resolution
path; no automated adoption.

**R2: Config-revision readiness is approximate in phase 1.**
The status observer uses Deployment ready-replica count as a proxy for "config loaded."
A pod can be ready (passing health checks) while still loading a new config version. This
means `Programmed=True` may be set before the new config is fully active. Mitigation:
the proxy's hot-reload path is fast (file watch, in-memory swap). The window is small.
A proper fix (proxy reports loaded config version via a status endpoint) is tracked as a
follow-on task.

**R3: Owner-reference garbage collection is namespace-scoped.**
Kubernetes only garbage-collects owned objects in the same namespace as the owner. All
owned objects are created in the Gateway's namespace, so this is not a problem for the
initial design. Cross-namespace owned objects are not used.

**R4: Leader election and concurrent reconciles.**
If two controller replicas both reconcile the same Gateway simultaneously, they may both
attempt server-side apply. Server-side apply is idempotent for the same field manager, so
this is safe. The leader election gate (from `bd-hkn` / `bd-e3g`) should be in place
before managed mode is enabled in production.

### Open Questions

**Q1: How does the proxy report its loaded config version?**
Phase 1 uses Deployment ready-replica count as a readiness proxy. A proper solution
requires the proxy to expose a `/readyz` or metrics endpoint that includes the loaded
`config_hash`. This is deferred to phase 2.

**Q2: NodePort address reporting.**
For `Service.spec.type == NodePort`, the controller does not report addresses in phase 1.
Node IPs require a node watch and are cluster-topology-dependent. Decision: leave
addresses empty for NodePort in phase 1 and document the limitation.

**Q3: Multi-listener Gateways with mixed protocols.**
A Gateway can have both HTTP and TCP listeners. Phase 1 creates one Deployment and one
Service per Gateway. The Service must expose ports for all listeners. The Deployment runs
one proxy process that handles all listeners. This is the existing behavior. If a Gateway
needs protocol-isolated Deployments, that is a phase 2 concern.

**Q4: What happens to the pre-existing ConfigMap when a Gateway transitions to managed mode?**
The controller creates a new owned ConfigMap (`wicket-gw-<name>-config`). The pre-existing
ConfigMap (`wicket-config`) is not deleted or modified. The operator is responsible for
removing the pre-existing ConfigMap after migration. The controller does not touch objects
it does not own.

**Q5: Rollout strategy.**
Phase 1 uses the Deployment's default rolling update strategy. Configurable rollout
strategy (e.g., `maxUnavailable`, `maxSurge`) is a follow-on concern.

---

## 10. Implementation Order

Tasks are ordered by dependency. Each is independently mergeable.

1. `bd-hkn` subtasks -- planner/applier boundary cleanup (prerequisite)
2. `bd-6tw` -- `GatewayRuntimePlan` IR and planner contracts
3. `bd-jhd` -- attachment/reference resolution planner
4. `bd-3cc` -- applier for ServiceAccount, ConfigMap, Service, Deployment
5. `bd-rgw` -- status observer (addresses from Service, Programmed from rollout)
6. Migration annotation support and coexistence path (no separate issue yet)

---

## 11. Acceptance Criteria

- [ ] A Gateway with `wicket.io/managed-runtime: "true"` causes the controller to create
      `ServiceAccount`, `ConfigMap`, `Deployment`, and `Service` with stable names,
      labels, and owner references as specified in section 2.
- [ ] Deleting the Gateway causes all owned objects to be garbage-collected by Kubernetes
      (owner reference cascade).
- [ ] `Gateway.status.addresses` is populated from the owned Service, not from name
      guessing.
- [ ] `Programmed=True` is only set when `Deployment.status.readyReplicas >= 1` and the
      pod template config-revision label matches the plan's `config_hash`.
- [ ] A route-only change (no image/replica change) updates the ConfigMap but does NOT
      trigger a Deployment rollout.
- [ ] An image change triggers a Deployment rollout.
- [ ] Gateways without `wicket.io/managed-runtime: "true"` continue to use the existing
      config-synthesis-only path with no behavior change.
- [ ] Planner is pure (no I/O, no async, deterministic) and unit-tested.
- [ ] Applier is isolated from planning logic and tested for create/update/no-op cases.
- [ ] Status observer is isolated from apply logic and tested for Programmed/NotReady
      transitions.
