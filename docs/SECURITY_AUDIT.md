# Wicket Security Audit Report

**Date:** April 2026
**Scope:** wicket proxy, wicket-controller, wicket-stream, wicket-tls, wicket-sockmap
**Auditor:** Manual code review + automated analysis
**Status:** All HIGH and MEDIUM findings remediated; 7 LOW/informational items remain

---

## Executive Summary

This security audit covers the full Wicket codebase — a Rust-based Kubernetes Gateway API reverse proxy built on Cloudflare's Pingora framework. The audit identified **3 HIGH**, **6 MEDIUM**, and **5 LOW** severity findings in prior reviews, all of which (HIGH and MEDIUM) have been remediated. This updated audit confirms those fixes and adds **2 new findings** (both LOW severity) discovered during deeper review.

The codebase demonstrates strong security practices: Rust's memory safety eliminates entire vulnerability classes (buffer overflows, use-after-free), unsafe code is minimal and justified, input validation is thorough, and secrets handling follows defense-in-depth.

**Overall Security Grade: A (Excellent)**

---

## Remediation Status

| Severity | Found | Fixed | Remaining |
|----------|-------|-------|-----------|
| HIGH     | 3     | 3     | 0         |
| MEDIUM   | 6     | 6     | 0         |
| LOW      | 7     | 0     | 7         |

---

## HIGH Severity Findings

### H-1: TLS Private Keys Written to /tmp Directory — FIXED

**Location:** `crates/wicket-controller/src/reconcilers/secret.rs:398-451`

**Original Issue:** TLS private keys were written to `/tmp/wicket/tls/` which is world-accessible.

**Fix Applied:**
- Changed default storage to `/var/run/wicket/tls` (configurable via `Context.tls_cert_dir`)
- Directory permissions set to `0700` (owner only)
- File permissions set to `0600` (owner read/write only)
- Atomic file writes: write to temp file then `rename()` prevents partial reads
- Permissions set on temp file *before* writing data

**Verification:** Fix confirmed in `write_tls_file()` function (lines 398-451). Implementation is correct — permissions are set before the atomic rename, preventing a race window.

---

### H-2: Kubernetes Service Account with Wide Read Access — FIXED

**Location:** `crates/wicket-controller/src/reconcilers/context.rs`

**Original Issue:** Controller could watch all namespaces by default.

**Fix Applied:**
- `watch_all_namespaces` option restricts controller scope
- When disabled, controller only watches its own namespace
- Properly documented security implications

---

### H-3: Cloudflare API Token in Environment Variable — FIXED

**Location:** `crates/wicket-tls/src/acme/cloudflare.rs:36-88`

**Original Issue:** API token only readable from environment variable (visible in `/proc/<pid>/environ`).

**Fix Applied:**
- Added `from_token_file()` method for file-based tokens
- Added `from_env_or_file()` with precedence: `CF_API_TOKEN_FILE` > `CF_API_TOKEN`
- Token trimmed on read (handles trailing newlines from file reads)
- Token format validated via `HeaderValue::from_str()`

**Remaining Risk:** Environment variable fallback still exists for backwards compatibility. Deployments should prefer file-based tokens.

---

## MEDIUM Severity Findings

### M-1: Regex Denial of Service in Host Matching — FIXED

**Location:** `crates/wicket-core/src/routing.rs`

**Fix:** Replaced regex with O(n) string suffix matching. Only prefix wildcards (`*.example.com`) supported; complex patterns rejected at config parse time.

---

### M-2: No HTTP Request Authentication Layer — BY DESIGN

**Location:** `crates/wicket-core/src/routing.rs:83-104`

**Status:** Documented architectural decision. Authentication is delegated to backend services. This is the correct pattern for a reverse proxy.

---

### M-3: SNI Hostname Length Not Validated — FIXED

**Location:** `crates/wicket-stream/src/sni.rs:26-28`

**Fix:** `MAX_HOSTNAME_LEN = 253` (RFC 1035). Oversized hostnames rejected with warning log, falls back to default route.

---

### M-4: Path Sanitization May Be Insufficient — FIXED

**Location:** `crates/wicket-controller/src/reconcilers/secret.rs:343-396`

**Fix:** Allowlist-based `sanitize_filename_component()`:
- Only alphanumeric + hyphens allowed
- Consecutive hyphens collapsed, leading/trailing hyphens trimmed
- Max 63 characters (DNS label limit)
- Empty results default to `"unnamed"`

---

### M-5: Certificate Hot-Reload Race Condition — FIXED

**Location:** `crates/wicket-controller/src/reconcilers/secret.rs:426-448`

**Fix:** Atomic writes via temp file + POSIX `rename()`. Permissions set before data is written.

---

### M-6: ACME Account Credentials Stored on Disk — ALREADY SECURE

**Location:** `crates/wicket-tls/src/acme/storage.rs`

**Status:** Storage path is `/var/lib/wicket/acme`. Uses atomic writes and `0600` permissions.

---

## LOW Severity Findings

### L-1: Hardcoded EINPROGRESS Error Codes

**Location:** `crates/wicket-stream/src/proxy.rs:271-276`

```rust
let in_progress = if cfg!(target_os = "linux") { 115 } else { 36 };
```

**Risk:** Incorrect values on unsupported platforms could cause silent connection failures.

**Recommendation:** Use `libc::EINPROGRESS` constant instead.

---

### L-2: No Explicit Content-Length Validation

**Location:** HTTP layer (implicit in Pingora)

**Risk:** Large requests could consume excessive memory. Pingora has internal limits, but they are not documented or configurable in Wicket's config surface.

**Recommendation:** Expose `max_request_body_size` as a configurable option and document Pingora's defaults.

---

### L-3: API Tokens in Test Code

**Location:** `crates/wicket-config/src/lib.rs` (test functions), `crates/wicket-tls/src/acme/cloudflare.rs:272`

**Risk:** Minimal — test code only, but patterns could be copied into production configs.

---

### L-4: Missing Rate Limiting

**Location:** Proxy layer

**Risk:** No built-in DoS protection. Upstream flooding is possible.

**Recommendation:** Add configurable per-route/per-client rate limiting, or document use of external rate limiters.

---

### L-5: Verbose BPF Logging Option

**Location:** `crates/wicket-sockmap/src/sockmap_linux.rs:116`

**Risk:** Kernel debug output could leak internal state.

**Recommendation:** Ensure `verbose` mode is disabled in production deployments. Consider gating behind a `debug` feature flag.

---

### L-6: X-Forwarded-For Header Spoofing (NEW)

**Location:** `crates/wicket-core/src/proxy.rs:493-515`

**Description:** The proxy appends the connecting client's IP to the existing `X-Forwarded-For` header. However, when Wicket is the edge proxy (not behind a trusted load balancer), a malicious client can inject an arbitrary `X-Forwarded-For` value:

```
GET / HTTP/1.1
X-Forwarded-For: 10.0.0.1
```

The proxy will produce `X-Forwarded-For: 10.0.0.1, <actual-client-ip>`, and backend services that trust the *first* IP in the chain will see a spoofed address.

**Risk:** IP-based access controls in backend services can be bypassed if they trust X-Forwarded-For without considering Wicket's position in the proxy chain.

**Recommendation:**
1. Add a `trusted_proxies` configuration option
2. When Wicket is the edge proxy, strip or replace any incoming `X-Forwarded-For` header instead of appending
3. Document the trust model for `X-Forwarded-For` in the configuration reference

---

### L-7: Client-Supplied Request ID Accepted Without Validation (NEW)

**Location:** `crates/wicket-core/src/proxy.rs:357-363`

**Description:** The proxy accepts an incoming `x-request-id` header and uses it verbatim:

```rust
if let Some(incoming_id) = session.req_header()
    .headers.get(HEADER_REQUEST_ID)
    .and_then(|v| v.to_str().ok())
{
    ctx.request_id = incoming_id.to_string();
}
```

A malicious client can inject an arbitrarily long or malformed request ID that will appear in all log lines, enabling:
- **Log injection:** Newlines or control characters in the ID could corrupt structured log output
- **Log flooding:** An extremely long request ID wastes log storage
- **Correlation confusion:** Duplicate IDs across requests break distributed tracing

**Risk:** Low — the `.to_str().ok()` call rejects non-ASCII bytes, and structured logging (tracing) escapes special characters. However, there is no length limit.

**Recommendation:**
1. Enforce a maximum length (e.g., 128 bytes) on client-supplied request IDs
2. Validate the format (e.g., alphanumeric + hyphens/underscores only)
3. Optionally, always generate a new ID and propagate the client's as a separate header (e.g., `x-original-request-id`)

---

## Positive Security Findings

The audit identified several strong security practices:

1. **Memory Safety:** Rust eliminates buffer overflows, use-after-free, and data races at compile time. All `panic!` calls are confined to test code only.

2. **Minimal Unsafe Code:** Only 7 `unsafe` blocks in the entire codebase, all in low-level system call wrappers (`setsockopt`, `getsockname`, `getpeername`) and eBPF operations. Each is necessary and well-scoped.

3. **No Command Injection:** No shell execution or command construction from user input anywhere.

4. **Comprehensive Config Validation:** `wicket-config/src/lib.rs:468-641` validates all configuration thoroughly — upstream references, route rules, TLS settings.

5. **Secure TLS:** Uses `rustls` (memory-safe, no OpenSSL CVEs) with hot-reload via `arc-swap` for zero-downtime certificate rotation.

6. **Cross-Namespace Protection:** ReferenceGrant validation in the Kubernetes controller prevents unauthorized cross-namespace secret access.

7. **Non-Root Containers:** Both Dockerfiles create and switch to a non-root user (UID 65532) before running.

8. **Release Hardening:** `Cargo.toml` enables LTO, single codegen unit, and binary stripping for release builds.

9. **Atomic File Operations:** All sensitive file writes use temp file + rename pattern.

10. **No Sensitive Data in Logs:** Tokens, keys, and credentials are never logged in production code.

11. **No `todo!()` or `FIXME`/`HACK` comments:** Codebase has no incomplete security-relevant implementations.

---

## Dependency Security

| Dependency | Version | Risk | Notes |
|-----------|---------|------|-------|
| `rustls` | latest | Low | Memory-safe TLS, actively maintained |
| `pingora` | 0.6 | Low | Cloudflare's production proxy framework |
| `kube` | 0.98 | Low | Official Kubernetes client |
| `reqwest` | latest | Low | HTTP client for ACME/Cloudflare API |
| `libbpf-rs` | latest | Low | Safe eBPF wrapper, Linux-only |
| `instant-acme` | 0.7 | Low | ACME protocol implementation |

**Recommendation:** Add `cargo audit` to CI pipeline for continuous vulnerability scanning of dependencies.

---

## Recommendations Summary

| Priority | Item | Effort | Impact |
|----------|------|--------|--------|
| 1 | Add `trusted_proxies` config for XFF handling (L-6) | Medium | High |
| 2 | Validate/limit client-supplied request IDs (L-7) | Low | Medium |
| 3 | Add `cargo audit` to CI | Low | High |
| 4 | Expose `max_request_body_size` config (L-2) | Low | Medium |
| 5 | Use `libc::EINPROGRESS` constant (L-1) | Low | Low |
| 6 | Add per-route rate limiting (L-4) | High | High |
| 7 | Gate BPF verbose mode behind feature flag (L-5) | Low | Low |

---

## Conclusion

Wicket is a well-engineered, security-conscious codebase. All critical and medium-severity issues from the prior audit have been properly remediated. The two new LOW-severity findings (XFF spoofing, unvalidated request IDs) are common reverse proxy concerns with straightforward mitigations. The Rust language choice eliminates most memory safety vulnerabilities by design, and the use of battle-tested frameworks (Pingora, rustls) provides a strong security foundation.

For production deployment in high-security environments, prioritize implementing `trusted_proxies` for X-Forwarded-For handling and adding `cargo audit` to CI.
