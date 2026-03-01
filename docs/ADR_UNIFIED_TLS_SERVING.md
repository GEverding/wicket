# ADR: Unified TLS Serving Architecture and Selection Policy

**Status:** Accepted  
**Date:** 2026-03-01  
**Issue:** `bd-xih` (parent epic: `bd-baf`)

---

## 1. Context and Current Gaps

Wicket supports three TLS modes (`file`, `acme`, `mixed`) but the serving path is not unified across them. Two structural gaps create correctness risk:

### Gap 1 — Static `add_tls` path bypasses `CertManager`

`main.rs` (lines 293–324) wires HTTPS listeners via Pingora's `proxy_service.add_tls(addr, cert_path, key_path)`. This path:

- Reads the **first** cert from `file.certs` and passes it as a static file path to Pingora.
- Is completely separate from the `CertManager` / `CertStore` resolver that was built for dynamic SNI resolution.
- Means file-based certs are served via a static TLS context, not through the `ResolvesServerCert` trait implementation on `CertManager`.

Consequence: SNI-based cert selection, wildcard matching, and hot-reload via `FileWatcher` are all bypassed for the HTTPS listener. The `CertManager` is wired to `WicketProxy` (line 277) but the listener itself uses a different cert.

### Gap 2 — ACME-only mode does not produce an HTTPS listener

The HTTPS listener block (lines 293–324) is gated on `tls_config.file` being present. In `TlsMode::Acme`, `tls_config.file` is `None`, so no HTTPS listener is added. ACME initializes and populates `CertManager`, but no port ever accepts TLS connections.

### Gap 3 — Mixed mode precedence is implicit

In `TlsMode::Mixed`, file certs are loaded first, then ACME runs. Both write into the same `CertStore` via `insert()`. If both sources cover the same domain, the last writer wins — which is ACME, because it runs after `FileWatcher::load_all()`. This is not documented, not tested, and not intentional.

---

## 2. Decision

**Replace the static `add_tls` path with a dynamic resolver path backed by `CertManager` for all TLS modes.**

The target state:

1. All HTTPS listeners are added via Pingora's `add_tls_with_settings` using a `ServerConfig` that sets `CertManager` as the `cert_resolver`.
2. `CertManager` is the single source of truth for certificate selection at handshake time.
3. The HTTPS listener is added whenever `config.tls` is `Some(_)`, regardless of mode.
4. Certificate source precedence is explicit, deterministic, and tested (see §3).

This is the prerequisite for `bd-myo` (integrate `CertManager` as runtime resolver).

---

## 3. Certificate Source Precedence Policy

When multiple sources cover the same domain, the resolver applies this fixed priority order at **load time** (not at handshake time):

| Priority | Source | Condition |
|----------|--------|-----------|
| 1 (highest) | File-based cert | `mode = file` or `mode = mixed` with `file.certs` entry covering the domain |
| 2 | ACME-provisioned cert | `mode = acme` or `mode = mixed` with ACME cert covering the domain |
| 3 (fallback) | Default cert | First cert inserted into the store, promoted to `CertStore::default` |

**Rationale:** File certs are operator-controlled and explicitly placed. ACME certs are automated. When an operator provides a file cert for a domain, it should always win — they may be pinning a specific CA or using an EV cert. ACME should fill gaps, not override explicit choices.

### SNI matching behavior

Resolution order within `CertStore` (unchanged from current implementation):

1. **Exact match** — `api.example.com` → exact key lookup, case-insensitive.
2. **Wildcard match** — `api.example.com` → check for `*.example.com` (stored under base `example.com`). Single-label only: `a.b.example.com` does not match `*.example.com`.
3. **Default fallback** — if set, returned for any SNI that matches nothing above.
4. **No cert** — if no default is set and no match found, the TLS handshake fails with `no certificate found`. This is the correct behavior; the alternative (serving a wrong cert) is worse.

### No-SNI clients

Clients that do not send SNI (rare, but possible with old TLS stacks) receive the default cert if one is set, otherwise the handshake fails. This is acceptable; no-SNI clients cannot participate in virtual hosting regardless.

### Load order in mixed mode

```
1. FileWatcher::load_all()   → inserts file certs into CertStore (priority 1)
2. AcmeProvider::initialize() → inserts ACME certs for domains NOT already covered
```

ACME must check `CertStore::resolve(domain)` before inserting and skip domains already covered by a file cert. This is the behavioral contract; the implementation is tracked in `bd-myo`.

---

## 4. Listener Integration Model

### Current (broken) model

```
TlsMode::File   → add_tls(addr, first_cert_path, first_key_path)  [static, bypasses CertManager]
TlsMode::Acme   → no HTTPS listener added
TlsMode::Mixed  → add_tls(addr, first_file_cert_path, ...)        [static, ACME certs unreachable]
```

### Target model

```
Any TlsMode → build rustls ServerConfig with cert_resolver = Arc<CertManager>
            → add_tls_with_settings(https_addr, tls_settings)
```

Concretely, in `main.rs`:

```rust
// Pseudocode — implementation in bd-myo
if let Some(ref cm) = cert_manager {
    let tls_settings = TlsSettings::with_resolver(cm.clone());
    if let Err(e) = proxy_service.add_tls_with_settings(&https_addr, &tls_settings) {
        error!(error = %e, "Failed to configure HTTPS listener");
    } else {
        info!(address = %https_addr, "HTTPS proxy listening (dynamic resolver)");
    }
}
```

The HTTPS address calculation (port 443 from 80, port+363 otherwise) is preserved.

### ACME-only mode

With the target model, ACME-only mode works correctly:

1. `AcmeProvider::initialize()` provisions certs and loads them into `CertManager`.
2. The HTTPS listener is added with `CertManager` as resolver.
3. Incoming TLS handshakes resolve certs via SNI lookup in `CertStore`.

No special case needed. The listener is added whenever `cert_manager.is_some()`.

### Rotation

`CertManager::reload(store)` atomically swaps the `ArcSwap<CertStore>`. In-flight handshakes complete with the old store; new handshakes use the new store. No listener restart required. This works identically for file rotation (via `FileWatcher`) and ACME renewal.

---

## 5. Failure Modes and Behavior

| Scenario | Current behavior | Target behavior |
|----------|-----------------|-----------------|
| ACME-only, no file certs | No HTTPS listener; TLS silently broken | HTTPS listener added; serves ACME certs |
| SNI not in store, no default | Serves first file cert (wrong cert) | Handshake fails; client gets TLS alert |
| File cert load fails at startup | `error!` log, HTTPS disabled | Same — fail fast, log error, no listener |
| ACME provisioning fails at startup | HTTPS listener added but empty store | Startup fails with error; operator must fix DNS/credentials |
| ACME renewal fails (background) | Cert expires silently | `error!` log + metric increment; existing cert served until expiry |
| Mixed mode, domain in both sources | Last writer wins (ACME) | File cert wins; ACME skips covered domains |
| `CertManager` empty at handshake time | Serves wrong cert or panics | Returns `None` from `ResolvesServerCert`; rustls sends `handshake_failure` alert |

### Startup failure policy

ACME initialization failure (`AcmeProvider::initialize()` returning `Err`) is fatal at startup. Operators must have valid credentials and DNS access before deploying. This is consistent with the existing behavior for file cert load failures.

---

## 6. Migration Stages

Stages are independently mergeable. Each has a feature flag defaulting to the current (safe) behavior.

### Stage 0 — Baseline (this ADR)

Document the gaps. No code change. Establishes the contract that subsequent stages implement.

**Exit criteria:** This ADR merged. `bd-myo` created and unblocked.

### Stage 1 — Dynamic resolver path (`bd-myo`)

Replace `add_tls` with `add_tls_with_settings` using `CertManager` as resolver. Gate behind `WICKET_TLS_DYNAMIC_RESOLVER=false` (default).

**Exit criteria:**
- HTTPS listener added for all three modes.
- `CertManager` is the sole cert resolver for the HTTPS listener.
- Integration test: ACME-only config serves TLS traffic.
- Integration test: mixed mode, file cert wins for covered domain.
- Flag default flipped to `true` after 48h canary.

### Stage 2 — ACME skip-if-covered

Add domain coverage check in `AcmeProvider::initialize()`: skip ACME provisioning for domains already in `CertStore`. Enforces the precedence policy at load time.

**Exit criteria:**
- Unit test: mixed mode, file cert for `api.example.com` → ACME does not overwrite it.
- Unit test: mixed mode, ACME cert for `other.example.com` → ACME inserts it.

### Stage 3 — Default cert promotion

After all certs are loaded, promote the first cert inserted (lowest priority source) as `CertStore::default`. Ensures no-SNI clients get a cert rather than a hard failure.

**Exit criteria:**
- Unit test: no-SNI client receives default cert.
- Behavior documented in operator guide.

### Rollback

Each stage is behind a feature flag (env var). Flipping the flag reverts to the previous behavior without a code rollback. Flag changes take effect on next process start (env var) or rolling restart.

| Flag | Default | Controls |
|------|---------|----------|
| `WICKET_TLS_DYNAMIC_RESOLVER` | `false` → `true` after Stage 1 validation | Use `CertManager` resolver vs. static `add_tls` |
| `WICKET_TLS_ACME_SKIP_COVERED` | `false` → `true` after Stage 2 validation | ACME skips domains covered by file certs |
| `WICKET_TLS_DEFAULT_CERT` | `false` → `true` after Stage 3 validation | Promote first cert as default fallback |

Canary process per stage:
1. Deploy with flag `false` (no behavior change). Verify metrics baseline.
2. Enable flag on staging cluster. Run integration tests. Monitor for 24h.
3. Enable flag on production. Monitor TLS handshake error rate and cert resolution latency for 48h.
4. If TLS error rate increases by any amount, flip flag back immediately.

---

## 7. Test Plan / Acceptance Criteria

### Unit tests (wicket-tls)

- [ ] `CertStore`: exact match wins over wildcard for same domain.
- [ ] `CertStore`: wildcard does not match nested subdomains (`a.b.example.com` vs `*.example.com`).
- [ ] `CertStore`: default fallback returned when no match.
- [ ] `CertStore`: no-SNI (empty string) returns default if set, `None` otherwise.
- [ ] `CertManager`: `reload()` atomically replaces store; concurrent `resolve()` calls do not panic.
- [ ] Mixed mode load order: file cert inserted first, ACME cert for same domain does not overwrite.

### Integration tests (wicket / wicket-core)

- [ ] `TlsMode::Acme` config → HTTPS listener is added → TLS handshake succeeds with ACME cert.
- [ ] `TlsMode::File` config → HTTPS listener is added → TLS handshake succeeds with file cert.
- [ ] `TlsMode::Mixed` config, domain covered by file cert → file cert served.
- [ ] `TlsMode::Mixed` config, domain covered only by ACME → ACME cert served.
- [ ] SNI for unknown domain, no default → handshake fails with `handshake_failure` (not a panic or wrong cert).
- [ ] `FileWatcher` rotation → new cert served on next handshake without listener restart.
- [ ] ACME renewal → new cert served on next handshake without listener restart.

### Acceptance criteria (epic `bd-baf`)

The migration is complete when all of the following are true:

- [ ] `WICKET_TLS_DYNAMIC_RESOLVER=true` in production for ≥ 30 days with no TLS-related incidents.
- [ ] `add_tls` (static path) removed from `main.rs`; no dead code paths remain.
- [ ] ACME-only mode verified end-to-end in CI with a mock ACME server.
- [ ] Mixed mode precedence test passes in CI.
- [ ] TLS handshake error rate does not increase vs. baseline after migration.
- [ ] All feature flags removed from codebase after validation.
- [ ] `FEATURE_CONTRACT_MATRIX.yaml` TLS entries promoted from `Beta` to `GA` for unified modes.
