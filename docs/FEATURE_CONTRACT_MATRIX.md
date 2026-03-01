# Feature Contract Matrix

This matrix defines the current feature contract for Wicket and maps each capability to a support status and owner modules.

- **As of:** 2026-03-01
- **Source of truth issue:** `bd-bvb`
- **Legend:**
  - **GA**: Implemented and enforced in runtime path; expected stable behavior
  - **Beta**: Implemented partially or behavior still evolving
  - **Unsupported**: Not implemented in runtime path; must be validation-rejected or treated as roadmap

## HTTP Routing

| Capability | Status | Owner modules | Notes |
|---|---|---|---|
| Exact host match | GA | `wicket-config/lib.rs`, `wicket-core/routing.rs` | Runtime-enforced |
| Wildcard host match (`*.example.com`) | GA | `wicket-core/routing.rs` | Single-label wildcard semantics |
| Path exact match | GA | `wicket-config/lib.rs`, `wicket-core/routing.rs` | Runtime-enforced |
| Path prefix match | GA | `wicket-config/lib.rs`, `wicket-core/routing.rs` | Runtime-enforced |
| Method match | GA | `wicket-config/lib.rs`, `wicket-core/routing.rs` | Uppercased exact matching |
| Header exact match | GA | `wicket-config/lib.rs`, `wicket-core/routing.rs` | Runtime-enforced |
| Path regex match | Unsupported | `wicket-controller/config_generator.rs`, `wicket-config/lib.rs`, `wicket-core/routing.rs` | Controller model has field; parser/runtime parity missing |

## Route Filters and Timeouts

| Capability | Status | Owner modules | Notes |
|---|---|---|---|
| Request/response header modifiers | Unsupported | `wicket-config/lib.rs`, `wicket-core/proxy.rs` | Schema exists; execution pipeline missing |
| Redirect filter | Unsupported | `wicket-config/lib.rs`, `wicket-core/proxy.rs` | Modeled only |
| URL rewrite filter | Unsupported | `wicket-config/lib.rs`, `wicket-core/proxy.rs` | Modeled only |
| Request mirroring | Unsupported | `wicket-config/lib.rs`, `wicket-core/proxy.rs` | Modeled only |
| Per-route timeout | Unsupported | `wicket-config/lib.rs`, `wicket-core/proxy.rs` | Config field exists; runtime mapping missing |

## Upstreams

| Capability | Status | Owner modules | Notes |
|---|---|---|---|
| Round-robin load balancing | GA | `wicket-config/lib.rs`, `wicket-core/proxy.rs` | Runtime-enforced |
| Consistent-hash load balancing | GA | `wicket-config/lib.rs`, `wicket-core/proxy.rs` | Runtime-enforced |
| Active health checks | Beta | `wicket-config/lib.rs`, `wicket-core/proxy.rs` | TCP checks wired; HTTP path/threshold parity incomplete |

## TLS

| Capability | Status | Owner modules | Notes |
|---|---|---|---|
| File-based certs | Beta | `wicket-tls/config.rs`, `wicket/main.rs` | Served, but not fully unified with dynamic resolver path |
| ACME cert management | Beta | `wicket-tls/acme/mod.rs`, `wicket-tls/cert_manager.rs`, `wicket/main.rs` | Manager exists; listener integration hardening pending |
| Mixed mode (file + ACME) | Beta | `wicket-tls/config.rs`, `wicket/main.rs` | Config exists; precedence/serving behavior needs hardening |
| Route-level TLS modes (`auto`, provider, cert ref) | Beta | `wicket-config/lib.rs`, `wicket-controller/config_generator.rs`, `wicket-core/proxy.rs` | Modeled end-to-end, enforcement still partial |

## Stream (L4)

| Capability | Status | Owner modules | Notes |
|---|---|---|---|
| TCP proxying | GA | `wicket-stream/proxy.rs`, `wicket/main.rs` | Implemented accept/connect/proxy path |
| SNI-based routing | Beta | `wicket-stream/sni.rs`, `wicket-stream/router.rs` | Works; semantics normalization/alignment pending |
| PROXY protocol support | Beta | `wicket-config/lib.rs`, `wicket-stream/proxy.rs` | Config modeled; runtime completion pending |
| Source IP pool for ephemeral ports | Beta | `wicket-config/lib.rs`, `wicket-stream/pool.rs` | Implemented abstraction; production hardening pending |
| eBPF acceleration | Beta | `wicket-stream/ebpf.rs`, `wicket-stream/proxy.rs` | Capability path exists; fallback hardening pending |

## Controller (Gateway API)

| Capability | Status | Owner modules | Notes |
|---|---|---|---|
| Gateway API reconciliation | Beta | `wicket-controller/reconcilers/*`, `wicket-controller/main.rs` | Broad coverage with architecture work remaining |
| ConfigMap generation/publish | Beta | `wicket-controller/reconcilers/context.rs`, `config_generator.rs` | Works; dedup/debounce/single-orchestrator pending |
| Leader election | Beta | `wicket-controller/leader_election.rs`, `main.rs` | State exists; strict write-gating needs closure |
| ReferenceGrant enforcement | Beta | `wicket-controller/reconcilers/referencegrant.rs`, `secret.rs`, `config_generator.rs` | Validation present, synthesis-time closure pending |

## Observability

| Capability | Status | Owner modules | Notes |
|---|---|---|---|
| Data-plane Prometheus metrics | Beta | `wicket-core/metrics.rs` | Large surface; some orphaned/unwired metrics |
| Controller Prometheus metrics | Beta | `wicket-controller/metrics/mod.rs` | Endpoint + families exist; wiring parity pending |
| Request IDs + structured logs | GA | `wicket-core/proxy.rs`, `wicket/main.rs` | Runtime-integrated |

- Architecture direction for the controller is captured in [ADR_KUBE_RS_CONTROLLER_STRATEGY.md](ADR_KUBE_RS_CONTROLLER_STRATEGY.md): deepen kube-rs usage via shared cache/index layer, single synthesis pipeline, and leader-enforced writes (epic `bd-e3g`).

## Contract Rules

1. Capabilities marked **Unsupported** must fail validation before runtime.
2. **Beta** capabilities require explicit caveats in user docs and examples.
3. Any new controller-emitted field must be mapped to parser + runtime behavior in the same change.
4. This document and `FEATURE_CONTRACT_MATRIX.yaml` must be kept in lockstep.
