# Standalone Graceful HTTP Binary Upgrades (v1)

## Status

Accepted (implementation contract for `wicket-cj8.2+`).

## Scope

- Applies only to standalone runtime (`crates/wicket`) and packaging/service assets.
- No controller/Kubernetes coupling in this design.
- v1 covers HTTP graceful binary replacement only.
- Stream listener fd handoff is explicitly out of scope in v1.

## Goals

- Define a concrete runtime contract for graceful binary replacement.
- Keep incumbent process serving until replacement validates and is ready.
- Make operator UX a single command: `systemctl reload wicket`.
- Use Pingora native fd transfer for HTTP listeners.

## Non-goals

- Config hot reload behavior changes (separate feature).
- Any guarantee that `systemctl restart wicket` is graceful.
- Stream listener handoff.
- Controller-driven rollout/orchestration.

## Terminology

- **Config hot reload**: existing process reloads config in-place, no process replacement.
- **Binary upgrade**: systemd reload helper starts the replacement child, transfers HTTP listener fds, then the incumbent exits only after successful takeover.
- **Restart**: service manager stops and starts process (`systemctl restart wicket`); may drop connections and is not required to be graceful.

## Runtime Contract

All paths below are owned by the service unit and writable by the wicket runtime user.

- **PID file**: single file representing incumbent PID (used by runtime + packaging checks).
- **Upgrade socket**: Unix domain socket used only for Pingora native HTTP fd transfer.
- **Service model**: systemd starts `/usr/bin/wicket` directly; reloads are handled by a small helper asset (`/usr/lib/wicket/wicket-upgrade`) rather than a long-lived wrapper supervisor.
- **Replacement invocation**: the helper starts a replacement `wicket --upgrade` child with the same config/pid/sock paths and inherited context needed for fd handoff.

Contract requirements:

- Runtime must create/update PID file only for successfully started serving process.
- Replacement `--upgrade` child listens on the upgrade socket during bootstrap; stale socket paths may be removed by the reload helper before launch.
- Replacement process must be started by the systemd reload helper (not by the incumbent) during reload-based binary upgrade.
- Service assets must ensure `systemctl reload wicket` routes to wicket binary-upgrade path, not generic restart.

## Startup Validation and Takeover Ordering

Required ordering for binary upgrade:

1. `systemctl reload wicket` runs the reload helper.
2. Helper starts replacement process in `--upgrade` mode.
3. Replacement loads config and performs startup validation before takeover commit.
4. If validation fails, replacement exits non-zero; incumbent keeps serving unchanged.
5. If validation succeeds, replacement completes Pingora HTTP listener fd attach/activation.
6. Replacement publishes `READY=1` and `MAINPID=<childpid>` to systemd after takeover commit.
7. Helper signals the incumbent to drain and exit.
8. Runtime ownership artifacts (PID file, upgrade socket state) converge to replacement process.

Invariant: invalid startup state in replacement must never evict a healthy incumbent.

## Operator Sequence (`reload` semantics)

- Operator replaces binary on disk (or package tooling does so later).
- Operator runs `systemctl reload wicket`.
- Reload triggers incumbent-coordinated graceful binary replacement.
- Successful reload means replacement is serving and incumbent has exited.
- Failed reload means incumbent continues serving; service remains available.

## Process Behavior: Success vs Failure

Success path:

- Helper: start child, wait for upgrade socket, signal incumbent, confirm takeover.
- Replacement: validate config, attach HTTP listener fds, begin serving, become authoritative runtime process.

Failure path (examples: invalid config, child startup failure, failed exec):

- Replacement exits; must not partially take over.
- Helper logs failure reason and incumbent continues serving prior config/binary.
- Reload command is reported failed (non-success exit/status from reload action), but service availability is preserved.

## Failure Modes and Mitigations

- **Invalid config at upgrade time**
  - Mitigation: replacement validates before takeover commit; incumbent keeps serving.
- **Failed exec/startup of replacement**
  - Mitigation: helper times out/waits for explicit child readiness; on failure it aborts upgrade and incumbent remains active.
- **Stale runtime files (PID file, upgrade socket)**
  - Mitigation: startup/upgrade must verify ownership + liveness before trusting files; stale artifacts are removed/recreated safely.
- **PID ownership and systemd MAINPID drift**
  - Mitigation: service integration must update MAINPID to the replacement process as part of successful takeover (or equivalent notify semantics); do not leave unit pointing to exited incumbent.
- **Rollback expectations**
  - Mitigation: v1 rollback is operational, not automatic process reversion. If new binary cannot take over, incumbent remains. If takeover already completed and new process later fails, operator performs normal systemd recovery (restart/redeploy prior binary).

## Isolation and Implementation Boundaries

- v1 implementation changes should stay isolated to:
  - `crates/wicket` runtime process/upgrade orchestration
  - packaging + systemd service assets needed for reload contract
- Do not couple this work to controller or Kubernetes components.

## Explicit v1 Exclusion

- Stream protocol graceful binary upgrade (stream listener fd transfer) is not covered by this design and is deferred.
