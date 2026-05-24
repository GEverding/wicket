# Standalone Packaged Filesystem Layout (v1)

## Status

Accepted (implementation contract for `wicket-cj8.4+`).

## Scope

- Standalone packaged installs only (Debian/RPM).
- systemd service model only in v1.
- No controller/Kubernetes path coupling.

## Decision

Packaged standalone installs MUST use this filesystem/runtime layout:

Mode/ownership values below are recommended packaging/systemd defaults for Debian/RPM.

### Immutable package-owned files (`/usr`)

- Main binary: `/usr/bin/wicket`
- Upgrade helper assets: `/usr/lib/wicket/wicket-upgrade`
- Docs/examples: `/usr/share/doc/wicket/examples/`

Ownership/mode:

- Package-managed, root-owned (`root:root`), not runtime-writable.

### Operator-managed config (`/etc`)

- Primary config: `/etc/wicket/wicket.toml`
- Static TLS assets: `/etc/wicket/tls/`

Ownership/mode:

- `/etc/wicket`: `root:wicket`, mode `0750`.
- `/etc/wicket/wicket.toml`: `root:wicket`, mode `0640`.
- `/etc/wicket/tls`: `root:wicket`, mode `0750`.
- `/etc/wicket/tls/*`:
  - private keys: `root:wicket`, mode `0640` (or stricter if group-read is not needed)
  - certs/chains: `root:wicket`, mode `0644` or `0640`
- Runtime must have read access and must not mutate `/etc/wicket/*`.

### Persistent runtime state (`/var/lib`)

- State root: `/var/lib/wicket/`
- ACME state: `/var/lib/wicket/acme/`

Ownership/mode:

- `/var/lib/wicket`: `wicket:wicket`, mode `0750`.
- `/var/lib/wicket/acme`: `wicket:wicket`, mode `0750`.
- Package creates directory roots; runtime owns/mutates live state contents.

### Transient runtime artifacts (`/run`)

- Runtime dir: `/run/wicket/`
- PID file: `/run/wicket/wicket.pid`
- Upgrade socket: `/run/wicket/upgrade.sock`

Ownership/mode:

- `/run/wicket`: `wicket:wicket`, mode `0750`, created at service start.
- PID/socket files are runtime-owned; package must not treat as persistent.

## Service Identity

- Service user/group: `wicket:wicket`.
- systemd unit must run wicket under this identity and ensure readable access to `/etc/wicket/*` plus writable access to `/var/lib/wicket` and `/run/wicket`.
- Preferred systemd helpers: `StateDirectory=wicket` and `RuntimeDirectory=wicket`.

## Service Invocation Contract

Packaged service MUST execute wicket with explicit config path:

- `--config /etc/wicket/wicket.toml`

Packaged service MUST NOT rely on CWD-based standalone/dev defaults (`./wicket.toml`).

## Upgrade and Ownership Semantics

- Package upgrades may replace `/usr/bin/wicket` and `/usr/lib/wicket/*` only.
- Package upgrades must preserve operator-managed `/etc/wicket/*` and runtime state under `/var/lib/wicket/*`.
- `/run/wicket/*` is always ephemeral and recreated by service startup/runtime.

## Explicit Non-Use of Controller Paths

This standalone packaged layout does not use controller extraction/temp paths such as `/var/run/wicket/tls`.

## Relationship to Graceful Binary Upgrades

This layout provides the concrete path contract required by
`standalone-graceful-http-binary-upgrades.md`, specifically for PID and upgrade-socket locations.
The systemd unit and reload helper are expected to consume those paths directly.
