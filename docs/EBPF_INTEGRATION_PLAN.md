# eBPF Socket Map Integration Plan: Volt → Wicket

Integrate Volt's `volt-sockmap` into Wicket for kernel-level zero-copy TCP proxying.

## Goals

1. **K8s Gateway acceleration** - Sockmap in Pingora (wicket-core) for L7 traffic
2. **L4 stream acceleration** - Sockmap in wicket-stream (may eventually replace user-space proxying)
3. **Feature flag `ebpf`** - Conditional compilation for ARM Docker builds

---

## Feature Flag

```toml
# wicket-stream/Cargo.toml and wicket-core/Cargo.toml
[features]
default = []
ebpf = ["volt-sockmap"]

[target.'cfg(target_os = "linux")'.dependencies]
volt-sockmap = { workspace = true, optional = true }
```

**Build variants:**
```bash
# ARM Docker / macOS / Windows - no eBPF deps
cargo build --release

# Linux x86 with eBPF
cargo build --release --features ebpf
```

---

## Integration Points

### 1. wicket-core (Pingora / K8s Gateway)

Pingora exposes socket FDs via:
- **Client FD**: `session.as_downstream().stream().as_raw_fd()`
- **Upstream FD**: Passed directly to `connected_to_upstream` callback

```rust
use std::os::unix::io::AsRawFd;

// Add to WicketCtx
pub struct WicketCtx {
    // ... existing fields ...
    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    pub ebpf_registered: bool,
    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    pub client_fd: Option<std::os::unix::io::RawFd>,
    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    pub upstream_fd: Option<std::os::unix::io::RawFd>,
}

#[async_trait]
impl ProxyHttp for WicketProxy {
    // Pingora provides upstream_fd directly in this callback
    async fn connected_to_upstream(
        &self,
        session: &mut Session,
        _reused: bool,
        _peer: &HttpPeer,
        #[cfg(unix)] upstream_fd: std::os::unix::io::RawFd,
        #[cfg(windows)] _upstream_fd: std::os::windows::io::RawSocket,
        _digest: Option<&Digest>,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        #[cfg(all(target_os = "linux", feature = "ebpf"))]
        if let Some(ref sockmap) = self.sockmap {
            // Get client FD from downstream session
            if let Some(stream) = session.as_downstream().stream() {
                let client_fd = stream.as_raw_fd();
                if let Ok(mut sm) = sockmap.lock() {
                    if sm.register_pair(client_fd, upstream_fd).is_ok() {
                        ctx.ebpf_registered = true;
                        ctx.client_fd = Some(client_fd);
                        ctx.upstream_fd = Some(upstream_fd);
                    }
                }
            }
        }
        Ok(())
    }

    async fn logging(&self, _session: &mut Session, _error: Option<&Error>, ctx: &mut Self::CTX) {
        #[cfg(all(target_os = "linux", feature = "ebpf"))]
        if ctx.ebpf_registered {
            if let (Some(client_fd), Some(upstream_fd)) = (ctx.client_fd, ctx.upstream_fd) {
                if let Some(ref sockmap) = self.sockmap {
                    let _ = sockmap.lock().map(|mut sm| sm.unregister_pair(client_fd, upstream_fd));
                }
            }
        }
        // ... existing logging code ...
    }
}
```

**Note**: `stream()` returns `None` for HTTP/2 (multiplexed). Sockmap works for HTTP/1.1 and WebSocket.

### 2. wicket-stream (L4 TCP)

Replace `tokio::io::copy` with sockmap when available.

```rust
#[cfg(all(target_os = "linux", feature = "ebpf"))]
if sockmap.register_pair(client_fd, backend_fd).is_ok() {
    // Kernel handles bidirectional copy
    wait_for_close(&client, &backend).await;
    sockmap.unregister_pair(client_fd, backend_fd);
    return Ok(());
}

// Fallback to user-space
tokio::io::copy_bidirectional(&mut client, &mut backend).await?;
```

---

## Setup

```bash
# Add volt submodule
git submodule add https://github.com/GEverding/volt.git volt

# Build BPF objects (Linux only)
cd volt && make bpf && cd ..
```

**Workspace Cargo.toml:**
```toml
[workspace.dependencies]
volt-sockmap = { path = "volt/crates/volt-sockmap" }
```

---

## Notes

- **HTTP/2**: `session.as_downstream().stream()` returns `None` for H2 (multiplexed). Sockmap only benefits HTTP/1.1 and WebSocket.
- **Kernel**: Requires Linux 5.10+ with BPF sockmap support
