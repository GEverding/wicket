# Wicket Security Audit Report

**Date:** January 2026
**Scope:** wicket proxy, wicket-controller, wicket-stream, wicket-tls, volt-sockmap
**Auditor:** Automated penetration testing analysis

---

## Executive Summary

This security audit identified **3 HIGH**, **6 MEDIUM**, and **5 LOW** severity findings across the wicket codebase. The most critical issues relate to secrets management and storage. Overall, the codebase demonstrates good security practices with proper input validation, safe Rust patterns, and minimal unsafe code.

---

## Severity Classification

| Severity | Count | Description |
|----------|-------|-------------|
| HIGH     | 3     | Immediate remediation recommended |
| MEDIUM   | 6     | Should be addressed in next release |
| LOW      | 5     | Best practice improvements |

---

## HIGH Severity Findings

### H-1: TLS Private Keys Written to /tmp Directory

**Location:** `crates/wicket-controller/src/reconcilers/secret.rs:54`

**Description:** TLS private keys extracted from Kubernetes Secrets are written to `/tmp/wicket/tls/` with 0600 permissions. While permissions are correctly set, the `/tmp` directory is:
- Accessible to all processes on the system
- Often mounted without encryption at rest
- Visible in container filesystem snapshots
- May persist across container restarts

**Code:**
```rust
const TLS_CERT_DIR: &str = "/tmp/wicket/tls";
```

**Risk:** An attacker with local filesystem access or container escape could read private keys.

**Recommendation:**
1. Use in-memory certificate storage (e.g., via rustls `CertifiedKey`)
2. If files are required, use a dedicated secure directory with tmpfs mount
3. Consider using Kubernetes CSI secrets driver for direct injection

---

### H-2: Kubernetes Service Account with Wide Read Access

**Location:** `crates/wicket-controller/src/main.rs:98`

**Description:** The controller uses `Client::try_default()` which inherits the pod's service account. The code lists resources across all namespaces:

```rust
let gw_api: Api<Gateway> = Api::all(client.clone());
let route_api: Api<HTTPRoute> = Api::all(ctx.client.clone());
```

**Risk:** If the controller is compromised, an attacker can read all Secrets, Gateway configurations, and routing rules across the entire cluster.

**Recommendation:**
1. Implement namespace-scoped watches where possible
2. Use minimal RBAC permissions (least privilege)
3. Consider namespace isolation per tenant

---

### H-3: Cloudflare API Token in Environment Variable

**Location:** `crates/wicket-tls/src/acme/cloudflare.rs:236`

**Description:** The Cloudflare API token is read from the `CF_API_TOKEN` environment variable:

```rust
let token = std::env::var("CF_API_TOKEN").expect("CF_API_TOKEN required");
```

**Risk:**
- Environment variables are visible in `/proc/<pid>/environ`
- May be logged by orchestration systems
- Exposed in container inspection commands

**Recommendation:**
1. Use Kubernetes Secrets mounted as files
2. Integrate with secret management systems (Vault, AWS Secrets Manager)
3. Add support for token rotation

---

## MEDIUM Severity Findings

### M-1: Regex Denial of Service in Host Matching

**Location:** `crates/wicket-core/src/routing.rs:194-203`

**Description:** Wildcard host patterns are compiled to regex at runtime:

```rust
let regex_pattern = format!("^{}$", pattern.replace('.', r"\.").replace('*', "[^.]+"));
let regex = Regex::new(&regex_pattern)?;
```

**Risk:** Complex wildcard patterns could cause CPU exhaustion during matching.

**Recommendation:**
1. Use simple string matching for wildcards instead of regex
2. Add pattern complexity limits
3. Pre-compile and cache regex patterns

---

### M-2: No HTTP Request Authentication Layer

**Location:** `crates/wicket-core/src/routing.rs:83-104`

**Description:** All HTTP requests matching route criteria are proxied to upstreams without authentication. The proxy relies entirely on backend services for auth.

**Risk:** Misconfigured routes could expose internal services.

**Recommendation:**
1. Document the authentication security model clearly
2. Consider adding optional JWT/OIDC validation
3. Add IP allowlist support for sensitive routes

---

### M-3: SNI Hostname Length Not Validated

**Location:** `crates/wicket-stream/src/sni.rs:115-124`

**Description:** The SNI hostname is extracted and used without length validation:

```rust
let name_len = read_u16(&mut cursor)? as usize;
// ... no max length check
let hostname = std::str::from_utf8(&buf[name_start..name_end]).ok()?;
```

RFC 6066 allows hostnames up to 65535 bytes, which could cause memory issues.

**Recommendation:**
1. Add maximum hostname length check (e.g., 253 characters per DNS spec)
2. Reject excessively long hostnames early

---

### M-4: Path Sanitization May Be Insufficient

**Location:** `crates/wicket-controller/src/reconcilers/secret.rs:315-316`

**Description:** Filenames are sanitized by replacing certain characters:

```rust
let safe_ns = namespace.replace(['/', '\\', '.'], "-");
let safe_name = name.replace(['/', '\\', '.'], "-");
```

**Risk:** Other special characters (null bytes, control characters) are not filtered.

**Recommendation:**
1. Use allowlist-based sanitization (only alphanumeric and dash)
2. Add explicit length limits
3. Validate against path traversal patterns

---

### M-5: Certificate Hot-Reload Race Condition

**Location:** `crates/wicket-tls/src/file_watcher.rs:89-161`

**Description:** Certificate files are watched and reloaded with a 500ms debounce. During updates, there's a window where partial files could be read.

**Risk:** TLS handshake failures during certificate rotation.

**Recommendation:**
1. Use atomic file replacement (write to temp, then rename)
2. Verify certificate chain validity before loading
3. Add retry logic on certificate load failure

---

### M-6: ACME Account Credentials Stored on Disk

**Location:** `crates/wicket-tls/src/acme/storage.rs:82-85`

**Description:** ACME account private keys are stored in `/tmp/wicket/acme/` with 0600 permissions.

**Risk:** Similar to H-1, local access could expose account keys.

**Recommendation:**
1. Use encrypted storage or secret management
2. Consider hardware security modules for key storage

---

## LOW Severity Findings

### L-1: Hardcoded EINPROGRESS Error Codes

**Location:** `crates/wicket-stream/src/proxy.rs:271-276`

**Description:** Platform-specific error codes are hardcoded:

```rust
// EINPROGRESS varies by platform
let in_progress = if cfg!(target_os = "linux") { 115 } else { 36 };
```

**Risk:** Incorrect values on unsupported platforms could cause connection failures.

**Recommendation:** Use `std::io::ErrorKind::WouldBlock` or libc constants.

---

### L-2: No Content-Length Validation

**Location:** HTTP layer (implicit in Pingora)

**Description:** No explicit request body size limits visible in wicket code.

**Risk:** Large requests could consume excessive memory.

**Recommendation:** Document Pingora's default limits and expose configuration options.

---

### L-3: API Token Appears in Test Code

**Location:** `crates/wicket-config/src/lib.rs` (various test functions)

**Description:** Hardcoded test tokens like `api_token = "test-token"` appear in tests.

**Risk:** Minimal - test code only, but patterns could be copied.

**Recommendation:** Use environment variables or mock providers in tests.

---

### L-4: Missing Rate Limiting on Proxy

**Location:** Proxy layer

**Description:** No built-in rate limiting for HTTP requests at the proxy layer.

**Risk:** DoS through request flooding.

**Recommendation:**
1. Add configurable rate limiting per route/client
2. Document use of external rate limiters (e.g., Cloudflare)

---

### L-5: Verbose BPF Logging Option

**Location:** `volt/crates/volt-sockmap/src/types.rs:18`

**Description:** The `verbose` option for BPF logging could expose sensitive data in kernel logs.

**Risk:** Information disclosure through kernel logs.

**Recommendation:** Ensure verbose mode is disabled in production.

---

## Positive Security Findings

The audit identified several good security practices:

1. **Safe Rust Usage:** Minimal unsafe code, limited to necessary system calls
   - `crates/wicket-stream/src/pool.rs:63` - Socket option setting (necessary)
   - `volt/crates/volt-sockmap/src/types.rs:336` - Byte slice conversion (necessary)

2. **No Command Injection:** No shell execution or command construction from user input

3. **Input Validation:** Comprehensive config validation in `wicket-config/src/lib.rs:427-636`

4. **TLS Implementation:** Uses well-audited rustls library

5. **Cross-Namespace Protection:** ReferenceGrant validation for Kubernetes secrets

6. **Logging Hygiene:** No sensitive data (passwords, tokens) logged in production code

7. **File Permissions:** Correct 0600 permissions set on sensitive files

8. **Graceful Degradation:** eBPF sockmap falls back to user-space copy on failure

---

## Dependency Analysis

Key security-relevant dependencies:
- `rustls` - Memory-safe TLS implementation
- `pingora` - Cloudflare's production proxy framework
- `kube` - Kubernetes client with RBAC integration
- `libbpf-rs` - Safe Rust wrapper for BPF

**Recommendation:** Run `cargo audit` in CI pipeline to detect vulnerable dependencies.

---

## Remediation Priority

| Priority | Finding | Effort |
|----------|---------|--------|
| 1        | H-1: TLS keys in /tmp | Medium |
| 2        | H-3: API token in env | Low |
| 3        | H-2: Wide K8s access | Medium |
| 4        | M-1: Regex DoS | Low |
| 5        | M-3: SNI length check | Low |
| 6        | M-4: Path sanitization | Low |

---

## Conclusion

The wicket codebase demonstrates security-conscious development with proper use of Rust's safety features. The primary areas for improvement are:

1. **Secrets management:** Move from filesystem storage to in-memory or encrypted solutions
2. **Input validation:** Add length limits and stricter sanitization
3. **Rate limiting:** Add configurable DoS protection

These findings should be addressed according to the priority matrix above before production deployment in high-security environments.
