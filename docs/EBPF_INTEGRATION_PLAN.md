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

After Pingora establishes upstream connection, register the socket pair for kernel-level data transfer.

```rust
// Pseudocode - actual integration depends on Pingora's FD access
#[cfg(all(target_os = "linux", feature = "ebpf"))]
impl ProxyHttp for WicketProxy {
    async fn connected_to_upstream(&self, session: &mut Session, ctx: &mut Ctx) {
        if let (Some(client_fd), Some(upstream_fd)) = get_fds(session) {
            ctx.ebpf_registered = self.sockmap.register_pair(client_fd, upstream_fd).is_ok();
        }
    }

    async fn logging(&self, session: &Session, ctx: &mut Ctx) {
        if ctx.ebpf_registered {
            self.sockmap.unregister_pair(...);
        }
    }
}
```

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

## Open Questions

1. **Pingora FD access** - Does `Session` expose raw FDs for client/upstream sockets?
2. **HTTP/2** - Multiplexed streams may not benefit; focus on HTTP/1.1 and WebSocket initially
3. **Connection lifecycle** - When exactly to register/unregister in Pingora's request flow
