# eBPF Socket Map Integration Plan: Volt → Wicket

This document outlines the plan to integrate the `volt` eBPF socket map implementation into the `wicket` reverse proxy to enable kernel-level zero-copy TCP proxying.

## Executive Summary

**Goal**: Integrate Volt's eBPF sockmap capabilities into Wicket to enable high-performance, zero-copy TCP proxying at the kernel level.

**Key Benefit**: After TLS termination in user-space (Pingora), data transfer between client and backend can happen entirely in kernel space via BPF socket redirection, eliminating user-space copies and context switches.

**Estimated Complexity**: Medium-High (requires build system changes, new crate dependencies, and integration with Pingora's connection lifecycle)

---

## 1. Architecture Overview

### Current Wicket Data Flow (L7/HTTP)
```
Client → TCP Accept → TLS Termination (Pingora)
       → HTTP Parsing → Route Match → Upstream Selection
       → Connect Backend → User-space Proxy (copy data)
       → Response → Client
```

### Proposed Data Flow with eBPF Sockmap
```
Client → TCP Accept → TLS Termination (Pingora)
       → HTTP/1.1 or passthrough detection
       → Connect Backend
       → Register socket pair in BPF sockmap
       → Kernel handles bidirectional data transfer (zero-copy)
       → Unregister on connection close
```

### Integration Points

```
┌─────────────────────────────────────────────────────────────────┐
│                        Wicket Proxy                             │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────────────┐ │
│  │ wicket-core │───→│ wicket-tls  │───→│ wicket-stream       │ │
│  │  (L7 HTTP)  │    │ (TLS term)  │    │ (L4 TCP passthrough)│ │
│  └──────┬──────┘    └──────┬──────┘    └──────────┬──────────┘ │
│         │                  │                      │             │
│         └──────────────────┴──────────────────────┘             │
│                            │                                    │
│                    ┌───────▼───────┐                           │
│                    │ wicket-ebpf   │  ← NEW CRATE              │
│                    │ (volt-sockmap │                           │
│                    │  integration) │                           │
│                    └───────┬───────┘                           │
│                            │                                    │
└────────────────────────────┼────────────────────────────────────┘
                             │
                    ┌────────▼────────┐
                    │   Linux Kernel  │
                    │  ┌────────────┐ │
                    │  │ sock_hash  │ │
                    │  │   map      │ │
                    │  └────────────┘ │
                    │  ┌────────────┐ │
                    │  │  SK_MSG    │ │
                    │  │  program   │ │
                    │  └────────────┘ │
                    └─────────────────┘
```

---

## 2. Component Integration Plan

### Phase 1: Foundation (New Crate Setup)

#### 1.1 Create `wicket-ebpf` Crate

Create a new crate that wraps volt-sockmap and provides Wicket-specific abstractions.

**Location**: `crates/wicket-ebpf/`

**Structure**:
```
crates/wicket-ebpf/
├── Cargo.toml
├── src/
│   ├── lib.rs           # Public API
│   ├── manager.rs       # SocketMapManager (lifecycle)
│   ├── connection.rs    # Connection pair tracking
│   ├── metrics.rs       # Prometheus metrics bridge
│   ├── config.rs        # eBPF configuration
│   └── error.rs         # Error types
└── build.rs             # BPF object embedding (optional)
```

**Cargo.toml**:
```toml
[package]
name = "wicket-ebpf"
version = "0.1.0"
edition = "2021"

[dependencies]
volt-sockmap = { path = "../../volt/crates/volt-sockmap" }
volt-core = { path = "../../volt/crates/volt-core" }
tokio = { version = "1", features = ["sync"] }
tracing = "0.1"
thiserror = "2"
prometheus = "0.13"

[target.'cfg(target_os = "linux")'.dependencies]
libbpf-rs = "0.24"

[features]
default = []
ebpf = []  # Feature flag for eBPF support
```

#### 1.2 SocketMapManager API

```rust
// crates/wicket-ebpf/src/manager.rs

use std::os::fd::RawFd;
use std::sync::Arc;
use tokio::sync::RwLock;

pub struct SocketMapManager {
    inner: Arc<RwLock<SocketMapInner>>,
    metrics: SocketMapMetrics,
}

struct SocketMapInner {
    #[cfg(target_os = "linux")]
    sockmap: Option<volt_sockmap::SocketMap>,
    active_pairs: u64,
    enabled: bool,
}

impl SocketMapManager {
    /// Create a new manager (lazy initialization)
    pub fn new(config: SocketMapConfig) -> Result<Self, Error>;

    /// Initialize and attach BPF programs (Linux only)
    pub async fn attach(&self) -> Result<(), Error>;

    /// Check if eBPF acceleration is available and enabled
    pub fn is_available(&self) -> bool;

    /// Register a socket pair for kernel-level proxying
    /// Returns Ok(true) if registered, Ok(false) if eBPF unavailable
    pub async fn register_pair(
        &self,
        client_fd: RawFd,
        backend_fd: RawFd,
    ) -> Result<bool, Error>;

    /// Unregister a socket pair
    pub async fn unregister_pair(
        &self,
        client_fd: RawFd,
        backend_fd: RawFd,
    ) -> Result<(), Error>;

    /// Get current statistics
    pub async fn stats(&self) -> SocketMapStats;

    /// Graceful shutdown
    pub async fn shutdown(&self);
}
```

#### 1.3 Configuration Extension

Add eBPF configuration to `wicket-config`:

```toml
# wicket.toml
[ebpf]
enabled = true
sockmap_path = "/opt/wicket/bpf/sockmap.bpf.o"  # Optional, can embed
max_connections = 500000
verbose = false

# Per-route override
[[routes]]
name = "api"
upstream = "backend"
ebpf_accelerated = true  # Enable kernel proxying for this route
```

```rust
// crates/wicket-config/src/types.rs

#[derive(Debug, Clone, Deserialize)]
pub struct EbpfConfig {
    #[serde(default)]
    pub enabled: bool,
    pub sockmap_path: Option<PathBuf>,
    #[serde(default = "default_max_connections")]
    pub max_connections: u32,
    #[serde(default)]
    pub verbose: bool,
}

fn default_max_connections() -> u32 {
    500_000
}
```

### Phase 2: Pingora Integration

#### 2.1 Integration Strategy

Wicket uses Pingora's `ProxyHttp` trait. The integration point is after upstream connection establishment but before data proxying begins.

**Key Insight**: For HTTP/1.1 connections with `Connection: keep-alive`, we can register the socket pair after the initial request/response and let the kernel handle subsequent exchanges.

**Challenge**: HTTP/2 multiplexing makes per-stream eBPF acceleration complex. Initial implementation should focus on:
1. L4 TCP passthrough (wicket-stream)
2. HTTP/1.1 with keep-alive
3. WebSocket upgrades

#### 2.2 wicket-stream Integration (L4 - Highest Priority)

The L4 stream proxy (`wicket-stream`) is the best initial integration target because it does bidirectional TCP copying after SNI extraction.

**Current flow** (`crates/wicket-stream/src/proxy.rs`):
```rust
// After SNI extraction and backend connection
tokio::select! {
    r = io::copy(&mut client_read, &mut backend_write) => { ... }
    r = io::copy(&mut backend_read, &mut client_write) => { ... }
}
```

**Proposed flow**:
```rust
// After SNI extraction and backend connection
if let Some(sockmap) = &self.sockmap_manager {
    if sockmap.register_pair(client_fd, backend_fd).await? {
        // Kernel handles data transfer
        // Just wait for connection close
        wait_for_close(&client, &backend).await;
        sockmap.unregister_pair(client_fd, backend_fd).await?;
        return Ok(());
    }
}
// Fallback to user-space proxying
tokio::select! { ... }
```

**Modified StreamProxy struct**:
```rust
// crates/wicket-stream/src/proxy.rs

pub struct StreamProxy {
    router: SniRouter,
    source_pool: Option<SourcePool>,
    proxy_protocol: Option<ProxyProtocolConfig>,
    sockmap_manager: Option<Arc<SocketMapManager>>,  // NEW
}

impl StreamProxy {
    pub fn with_sockmap(mut self, manager: Arc<SocketMapManager>) -> Self {
        self.sockmap_manager = Some(manager);
        self
    }
}
```

#### 2.3 wicket-core Integration (L7 HTTP)

For HTTP connections, integration is more nuanced:

```rust
// crates/wicket-core/src/proxy.rs

pub struct WicketProxy {
    // ... existing fields
    sockmap_manager: Option<Arc<SocketMapManager>>,
}

impl ProxyHttp for WicketProxy {
    // After upstream connection established
    async fn connected_to_upstream(
        &self,
        session: &mut Session,
        _reused: bool,
        _peer: &HttpPeer,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        // Only for HTTP/1.1 connections that could benefit
        if self.should_accelerate(ctx) {
            if let (Some(client_fd), Some(backend_fd)) =
                (session.client_fd(), session.upstream_fd())
            {
                ctx.ebpf_registered = self.sockmap_manager
                    .as_ref()
                    .map(|m| m.register_pair(client_fd, backend_fd))
                    .transpose()?
                    .unwrap_or(false);
            }
        }
        Ok(())
    }

    // On connection close
    async fn logging(&self, session: &Session, _e: Option<&Error>, ctx: &mut Self::CTX) {
        if ctx.ebpf_registered {
            if let (Some(client_fd), Some(backend_fd)) =
                (session.client_fd(), session.upstream_fd())
            {
                let _ = self.sockmap_manager
                    .as_ref()
                    .map(|m| m.unregister_pair(client_fd, backend_fd));
            }
        }
    }
}
```

### Phase 3: Build System Integration

#### 3.1 Workspace Structure

**Option A: Git Submodule** (Recommended for development)
```bash
git submodule add git@github.com:GEverding/volt.git volt
```

**Option B: Path Dependencies** (Current approach)
```toml
# Cargo.toml (workspace)
[workspace.dependencies]
volt-sockmap = { path = "volt/crates/volt-sockmap" }
volt-core = { path = "volt/crates/volt-core" }
```

**Option C: Publish to crates.io** (For production)
```toml
volt-sockmap = "0.1"
```

#### 3.2 BPF Object Management

**Approach 1: External BPF Object**
- Ship pre-compiled `sockmap.bpf.o` in deployment
- Configure path via `wicket.toml`
- Pros: Flexible, can update BPF without rebuilding Rust
- Cons: Additional deployment artifact

**Approach 2: Embedded BPF Object**
```rust
// crates/wicket-ebpf/build.rs
fn main() {
    #[cfg(target_os = "linux")]
    {
        println!("cargo:rerun-if-changed=../../volt/bpf/nlb/sockmap.bpf.c");
        // Compile and embed
    }
}

// crates/wicket-ebpf/src/lib.rs
const SOCKMAP_BPF: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/sockmap.bpf.o"));
```

#### 3.3 Cross-Platform Compilation

Wicket should compile on non-Linux platforms (macOS for development):

```rust
// crates/wicket-ebpf/src/lib.rs

#[cfg(target_os = "linux")]
mod linux_impl;

#[cfg(not(target_os = "linux"))]
mod stub_impl;

#[cfg(target_os = "linux")]
pub use linux_impl::*;

#[cfg(not(target_os = "linux"))]
pub use stub_impl::*;
```

```rust
// crates/wicket-ebpf/src/stub_impl.rs

/// Stub implementation for non-Linux platforms
pub struct SocketMapManager;

impl SocketMapManager {
    pub fn new(_config: SocketMapConfig) -> Result<Self, Error> {
        Ok(Self)
    }

    pub fn is_available(&self) -> bool {
        false
    }

    pub async fn register_pair(&self, _: RawFd, _: RawFd) -> Result<bool, Error> {
        Ok(false)  // eBPF not available
    }

    // ... other stubs
}
```

### Phase 4: Metrics & Observability

#### 4.1 Prometheus Metrics

```rust
// crates/wicket-ebpf/src/metrics.rs

use prometheus::{IntCounter, IntGauge, Histogram};

pub struct SocketMapMetrics {
    pub pairs_registered: IntCounter,
    pub pairs_active: IntGauge,
    pub msgs_redirected: IntCounter,
    pub bytes_forwarded: IntCounter,
    pub registration_errors: IntCounter,
    pub registration_latency: Histogram,
}

impl SocketMapMetrics {
    pub fn new() -> Self {
        Self {
            pairs_registered: register_int_counter!(
                "wicket_ebpf_pairs_registered_total",
                "Total socket pairs registered for eBPF acceleration"
            ).unwrap(),
            pairs_active: register_int_gauge!(
                "wicket_ebpf_pairs_active",
                "Currently active eBPF-accelerated socket pairs"
            ).unwrap(),
            msgs_redirected: register_int_counter!(
                "wicket_ebpf_msgs_redirected_total",
                "Total messages redirected via eBPF sockmap"
            ).unwrap(),
            bytes_forwarded: register_int_counter!(
                "wicket_ebpf_bytes_forwarded_total",
                "Total bytes forwarded via eBPF sockmap"
            ).unwrap(),
            // ...
        }
    }
}
```

#### 4.2 Tracing Integration

```rust
use tracing::{info, warn, instrument};

impl SocketMapManager {
    #[instrument(skip(self), fields(client_fd, backend_fd))]
    pub async fn register_pair(&self, client_fd: RawFd, backend_fd: RawFd) -> Result<bool, Error> {
        info!("Registering socket pair for eBPF acceleration");
        // ...
    }
}
```

### Phase 5: Testing Strategy

#### 5.1 Unit Tests

```rust
// crates/wicket-ebpf/src/manager.rs

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_defaults() {
        let config = SocketMapConfig::default();
        assert_eq!(config.max_connections, 500_000);
    }

    #[test]
    #[cfg(not(target_os = "linux"))]
    fn test_stub_returns_false() {
        let manager = SocketMapManager::new(Default::default()).unwrap();
        assert!(!manager.is_available());
    }
}
```

#### 5.2 Integration Tests (Linux VM)

```rust
// tests/ebpf_integration.rs

#[tokio::test]
#[cfg(target_os = "linux")]
async fn test_sockmap_registration() {
    let manager = SocketMapManager::new(SocketMapConfig::default()).unwrap();
    manager.attach().await.unwrap();

    // Create test sockets
    let (client, server) = create_socket_pair();
    let backend = TcpStream::connect("127.0.0.1:8080").await.unwrap();

    // Register pair
    assert!(manager.register_pair(client.as_raw_fd(), backend.as_raw_fd()).await.unwrap());

    // Verify stats
    let stats = manager.stats().await;
    assert_eq!(stats.active_pairs, 1);

    // Cleanup
    manager.unregister_pair(client.as_raw_fd(), backend.as_raw_fd()).await.unwrap();
}
```

#### 5.3 Performance Benchmarks

```rust
// benches/sockmap_bench.rs

use criterion::{criterion_group, criterion_main, Criterion, Throughput};

fn benchmark_sockmap_vs_userspace(c: &mut Criterion) {
    let mut group = c.benchmark_group("proxy_throughput");
    group.throughput(Throughput::Bytes(1024 * 1024)); // 1MB

    group.bench_function("userspace_copy", |b| {
        b.iter(|| userspace_proxy_1mb())
    });

    #[cfg(target_os = "linux")]
    group.bench_function("ebpf_sockmap", |b| {
        b.iter(|| ebpf_proxy_1mb())
    });

    group.finish();
}
```

---

## 3. Implementation Phases

### Phase 1: Foundation (Week 1-2)
- [ ] Add volt as git submodule
- [ ] Create `wicket-ebpf` crate with stub implementation
- [ ] Add eBPF configuration to `wicket-config`
- [ ] Implement `SocketMapManager` with Linux/stub branches
- [ ] Add basic metrics scaffolding
- [ ] Verify cross-platform compilation

### Phase 2: L4 Stream Integration (Week 3-4)
- [ ] Integrate `SocketMapManager` into `wicket-stream`
- [ ] Modify `StreamProxy` to attempt eBPF registration
- [ ] Implement fallback to user-space proxying
- [ ] Add integration tests in Linux VM
- [ ] Benchmark L4 performance improvement

### Phase 3: L7 HTTP Integration (Week 5-6)
- [ ] Research Pingora socket FD access patterns
- [ ] Implement HTTP/1.1 keep-alive acceleration
- [ ] Handle WebSocket upgrade scenarios
- [ ] Add route-level eBPF enable/disable configuration
- [ ] Document HTTP/2 limitations

### Phase 4: Production Hardening (Week 7-8)
- [ ] Error handling and graceful degradation
- [ ] Comprehensive metrics and alerting
- [ ] Kernel version compatibility testing (5.10+)
- [ ] Memory limit and resource management
- [ ] Documentation and operational runbooks

---

## 4. File Changes Summary

### New Files
```
crates/wicket-ebpf/
├── Cargo.toml
├── build.rs
└── src/
    ├── lib.rs
    ├── manager.rs
    ├── connection.rs
    ├── metrics.rs
    ├── config.rs
    ├── error.rs
    ├── linux_impl.rs
    └── stub_impl.rs

docs/
└── EBPF_OPERATIONS.md  # Operational guide
```

### Modified Files
```
Cargo.toml                           # Add wicket-ebpf to workspace
crates/wicket-config/src/types.rs    # Add EbpfConfig
crates/wicket-stream/src/proxy.rs    # Add sockmap integration
crates/wicket-stream/Cargo.toml      # Add wicket-ebpf dependency
crates/wicket-core/src/proxy.rs      # Add sockmap integration (Phase 3)
crates/wicket-core/Cargo.toml        # Add wicket-ebpf dependency
crates/wicket/src/main.rs            # Initialize SocketMapManager
```

### External Dependencies
```
volt/  (git submodule)
├── crates/volt-sockmap/
├── crates/volt-core/
└── bpf/nlb/sockmap.bpf.o
```

---

## 5. Risk Assessment & Mitigations

| Risk | Impact | Likelihood | Mitigation |
|------|--------|------------|------------|
| Kernel version incompatibility | High | Medium | Feature detection, graceful fallback |
| BPF verifier rejections | Medium | Low | Use proven volt BPF code unchanged |
| Pingora FD access limitations | High | Medium | Research Pingora internals, contribute upstream if needed |
| Performance regression | High | Low | Comprehensive benchmarking, feature flags |
| Memory leaks in BPF maps | Medium | Low | Proper cleanup on connection close, monitoring |
| Cross-platform build issues | Low | Medium | CI for Linux + macOS, stub implementations |

---

## 6. Success Criteria

### Performance Targets
- **L4 Throughput**: 2x improvement for sustained TCP connections
- **L4 Latency**: 30% reduction in p99 latency
- **CPU Usage**: 40% reduction under high load
- **Memory**: No increase in steady-state memory usage

### Functional Requirements
- [ ] eBPF acceleration works for L4 TCP passthrough
- [ ] Graceful fallback when eBPF unavailable
- [ ] Route-level configuration for eBPF enable/disable
- [ ] Prometheus metrics for eBPF operations
- [ ] No regression in existing functionality

### Operational Requirements
- [ ] Works on kernel 5.10+ (Ubuntu 20.04+, RHEL 8+)
- [ ] Clear error messages for eBPF failures
- [ ] Documentation for deployment and troubleshooting
- [ ] Runbooks for common operational scenarios

---

## 7. Open Questions

1. **Pingora socket access**: Does Pingora expose raw FDs for client and upstream connections? Need to investigate `Session` internals.

2. **HTTP/2 strategy**: Should we attempt per-stream acceleration or only support HTTP/1.1 initially?

3. **TLS passthrough**: For SNI-based routing with TLS passthrough, can we register sockets immediately after SNI extraction?

4. **Kubernetes deployment**: How to handle BPF object distribution in containerized environments? ConfigMap, init container, or embedded?

5. **Graceful reload**: How to handle configuration reloads when eBPF programs are attached?

---

## 8. References

- [Volt Repository](https://github.com/GEverding/volt) - eBPF socket map implementation
- [Linux Kernel sockmap docs](https://docs.kernel.org/bpf/map_sockmap.html)
- [Aya SockMap docs](https://docs.rs/aya/latest/aya/maps/sock/struct.SockMap.html)
- [Pingora GitHub](https://github.com/cloudflare/pingora)
- [eBPF for socket redirect blog](https://medium.com/all-things-ebpf/optimizing-local-socket-communication-sockmap-and-ebpf-0edf1a1cea3c)
