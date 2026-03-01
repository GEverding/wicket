# ADR: kube-rs Controller Architecture Strategy

**Status:** Accepted  
**Date:** 2026-03-01  
**Issue:** `bd-u3z` (parent epic: `bd-e3g`)

---

## 1. Context

Wicket implements the Kubernetes Gateway API using a controller built on [kube-rs](https://github.com/kube-rs/kube). The controller watches Gateway, HTTPRoute, TCPRoute, Service, Endpoints, Secret, and ReferenceGrant resources and synthesizes a Wicket `ConfigMap` that the data-plane proxy reads.

The controller is functional but has accumulated several structural pain points that create correctness risk and operational friction:

### Observed pain points

**Duplicated config synthesis paths**  
`config_generator.rs` contains the primary synthesis logic, but individual reconcilers (`gateway.rs`, `httproute.rs`, `secret.rs`) each perform partial config assembly before calling into the generator. There is no single entry point that owns the full config snapshot. This means a change to how a field is mapped (e.g., TLS mode, upstream weights) must be applied in multiple places or it silently diverges.

**Full-list / rebuild reconciliation pattern**  
On every reconcile event — regardless of which resource changed — the controller lists all Gateways, all HTTPRoutes, all Services, and all Secrets from the API server. This is correct but expensive. Under moderate cluster churn (rolling deployments, cert rotations) it generates unnecessary API server load and makes reconcile latency proportional to cluster size rather than change size.

**Leader-election state not strictly gating all writes**  
`leader_election.rs` tracks whether this pod holds the lease, but the check is advisory: reconcilers can proceed to write ConfigMaps and status subresources even when the lease check races or returns stale state. In a split-brain window (e.g., lease renewal lag) two pods can emit conflicting ConfigMap versions.

**Model drift between controller-generated config and parser/runtime**  
The controller model (`config_generator.rs`) emits fields — `path_regex`, `filters`, `timeout` — that the config parser (`wicket-config/lib.rs`) and routing runtime (`wicket-core/routing.rs`) do not yet consume. The YAML is written but silently ignored downstream. This creates a false sense of completeness and makes it easy to ship a Gateway API feature that appears to work (no error) but has no runtime effect.

---

## 2. Decision

**We stay on kube-rs and deepen its usage.** We do not replace it.

kube-rs is already the foundation of the controller. It provides the `Controller` builder, `Store`/`Writer` reflectors, `WatcherConfig`, and the `kube::runtime::controller` reconcile loop. These are the right primitives for what we need. The pain points above are not caused by kube-rs; they are caused by how we use it.

The target architecture:

1. **Shared cache/index layer** — All reconcilers read from `kube::runtime::reflector` stores rather than issuing live list calls. Indexes (e.g., routes-by-gateway, secrets-by-namespace) are built once and shared via `Arc<SharedState>`.

2. **Single synthesis pipeline** — One function, `synthesize_config(&SharedState) -> WicketConfig`, owns the full config snapshot. All reconcilers call it; none assemble partial configs independently.

3. **Leader-enforced writes** — ConfigMap writes and status patches are gated behind a hard check on the leader lease. Non-leaders reconcile state into memory but do not write to the API server.

4. **Model parity discipline** — No field is emitted by the controller unless the parser and runtime consume it. Fields that are not yet wired are stripped at synthesis time and tracked in the feature contract matrix as `Unsupported`.

---

## 3. Alternatives Considered

### A. Replace kube-rs with controller-runtime (Go)

Rejected. The entire data-plane is Rust. A Go controller would require a separate binary, separate deployment, and cross-language config serialization. The operational complexity outweighs any benefit from the Go ecosystem's more mature controller-runtime.

### B. Replace kube-rs with a hand-rolled watch loop

Rejected. kube-rs already provides reflectors, backoff, leader election, and status patching. Reimplementing these correctly is significant work with no upside.

### C. Keep current architecture, add point fixes

Rejected. The pain points are structural. Patching individual reconcilers without addressing the shared-state and synthesis-path problems will continue to produce drift and correctness gaps.

### D. Adopt Operator SDK (Rust bindings)

Not mature enough. kube-rs is the de facto standard for Rust Kubernetes controllers and has active maintenance. No compelling reason to switch.

---

## 4. Consequences

**Positive**
- Reconcile latency becomes O(change) not O(cluster size).
- Config synthesis bugs are localized to one function, not spread across reconcilers.
- Leader election becomes a hard gate; split-brain ConfigMap writes are eliminated.
- Model drift is caught at synthesis time, not discovered in production.

**Negative / risks**
- Migrating to shared reflector stores requires careful initialization ordering (stores must be populated before reconcilers start).
- The single synthesis pipeline is a larger blast radius per bug — a panic in synthesis stops all config updates. Needs robust error handling and fallback.
- Leader-gated writes mean non-leader pods do no useful work on writes; this is correct behavior but requires operators to understand the single-active-writer model.

---

## 5. Migration Stages

Stages are ordered by dependency. Each stage is independently mergeable and testable.

### Stage 0 — Baseline instrumentation (prerequisite)

Add metrics and structured logs to the current reconcile path so we have a baseline for:
- Reconcile duration per resource type
- API server list call count per reconcile cycle
- ConfigMap write count and conflict rate
- Leader lease hold/loss events

This gives us regression detection for subsequent stages.

**Exit criteria:** Grafana dashboard shows reconcile duration, list call rate, and write conflict rate. No behavior change.

### Stage 1 — Shared cache/index layer (`bd-44h`)

Introduce `SharedState` holding `kube::runtime::reflector::Store<T>` for each watched resource type. Build indexes:
- `routes_by_gateway: HashMap<NamespacedName, Vec<Arc<HTTPRoute>>>`
- `secrets_by_namespace: HashMap<String, Vec<Arc<Secret>>>`
- `endpoints_by_service: HashMap<NamespacedName, Arc<Endpoints>>`

Reconcilers switch from `client.list()` to `state.routes_by_gateway.get(...)`. Live list calls are removed from the hot path.

**Exit criteria:** Zero `client.list()` calls in reconciler hot path (verified by removing list RBAC in integration test and confirming no 403s). Reconcile duration p99 does not increase.

### Stage 2 — Single synthesis pipeline (`bd-0kh`)

Extract `synthesize_config(state: &SharedState) -> Result<WicketConfig>` as the sole config assembly function. Remove partial assembly from individual reconcilers. All reconcilers call `synthesize_config` and pass the result to the write path.

Add a property test: given any combination of Gateway/Route/Service/Secret fixtures, `synthesize_config` is deterministic (same inputs → same output, regardless of call order).

**Exit criteria:** `config_generator.rs` has one public synthesis entry point. No reconciler assembles a partial config independently. Property test passes.

### Stage 3 — Leader-enforced write gate

Wrap the ConfigMap write and status patch calls in a `LeaderGuard` that returns `Err(NotLeader)` if the lease is not held. Non-leader pods log a trace event and return `Ok(())` without writing.

Add a chaos test: kill the leader pod mid-reconcile and verify the new leader's first write wins without a conflict error.

**Exit criteria:** Integration test confirms only one pod writes ConfigMap during a leader failover. No `Conflict` errors in controller logs during rolling restart.

### Stage 4 — Model parity enforcement

Add a compile-time or synthesis-time assertion: any field emitted by `synthesize_config` must have a corresponding parser test in `wicket-config` and a routing/proxy test in `wicket-core`. Fields without coverage are stripped and logged as `unsupported_field_stripped`.

Update `FEATURE_CONTRACT_MATRIX.yaml` to reflect actual synthesis-time behavior, not aspirational model fields.

**Exit criteria:** `check_feature_contract.py` passes with no drift. No `Unsupported` field is emitted in synthesized ConfigMap output.

### Stage 5 — Debounce and event storm protection

Add a debounce window (configurable, default 500ms) between the last reconcile trigger and the ConfigMap write. Coalesce multiple rapid events (e.g., rolling deployment updating 10 pods) into a single synthesis+write cycle.

**Exit criteria:** Under a simulated 50-pod rolling deployment, ConfigMap write count ≤ 3 (start, mid, end of rollout). API server write QPS stays below configured limit.

---

## 6. Rollback Strategy

### Feature flags

Each stage introduces a feature flag in the controller's config (environment variable or ConfigMap key):

| Flag | Default | Controls |
|------|---------|----------|
| `WICKET_CTRL_USE_SHARED_CACHE` | `false` (Stage 1) → `true` after validation | Use reflector stores vs. live list |
| `WICKET_CTRL_SINGLE_SYNTHESIS` | `false` (Stage 2) → `true` after validation | Use unified synthesis pipeline |
| `WICKET_CTRL_LEADER_GATE_WRITES` | `false` (Stage 3) → `true` after validation | Hard-gate writes on leader lease |
| `WICKET_CTRL_DEBOUNCE_MS` | `0` (disabled) → `500` after Stage 5 | Debounce window in milliseconds |

Flags default to `false` (current behavior) until the stage is validated. This means a rollback is a config change, not a code rollback.

### Canarying

For each stage:
1. Deploy new controller version with flag `false` (no behavior change). Verify metrics baseline unchanged.
2. Enable flag on a single non-production cluster. Monitor for 24h.
3. Enable flag on production. Monitor reconcile duration, write conflict rate, and error rate for 48h.
4. If any metric regresses beyond threshold (reconcile p99 +20%, write conflicts +any, error rate +0.1%), flip flag back to `false` immediately.

### Fallback to current behavior

If a stage flag is flipped back to `false`:
- Stage 1 (`USE_SHARED_CACHE=false`): reconcilers revert to `client.list()` calls. No data loss; next reconcile rebuilds state from API server.
- Stage 2 (`SINGLE_SYNTHESIS=false`): reconcilers revert to partial assembly. Config correctness is the same as before the migration.
- Stage 3 (`LEADER_GATE_WRITES=false`): writes are no longer gated. Reverts to current advisory-check behavior.
- Stage 5 (`DEBOUNCE_MS=0`): debounce disabled; every event triggers immediate synthesis+write.

Rollback does not require a pod restart for flag changes delivered via ConfigMap (controller watches its own config). Environment variable changes require a rolling restart.

---

## 7. Acceptance / Exit Criteria

The migration is complete when all of the following are true:

- [ ] `WICKET_CTRL_USE_SHARED_CACHE=true` in production for ≥ 30 days with no incidents.
- [ ] `WICKET_CTRL_SINGLE_SYNTHESIS=true` in production for ≥ 30 days with no incidents.
- [ ] `WICKET_CTRL_LEADER_GATE_WRITES=true` in production for ≥ 30 days with no incidents.
- [ ] Zero `client.list()` calls in reconciler hot path (verified by RBAC test).
- [ ] `synthesize_config` is the sole config assembly entry point (verified by code review + grep).
- [ ] No `Unsupported` field appears in synthesized ConfigMap output (verified by `check_feature_contract.py`).
- [ ] Reconcile duration p99 ≤ 200ms under steady-state cluster (no active rollouts).
- [ ] ConfigMap write count during a 50-pod rolling deployment ≤ 5.
- [ ] Leader failover produces zero write conflicts (verified by chaos test).
- [ ] All feature flags removed from codebase (no dead code paths).
