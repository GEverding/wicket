# eBPF Socket Map Integration Plan: Volt → Wicket

Integrate Volt's `volt-sockmap` crate into Wicket's L4 stream proxy for kernel-level zero-copy TCP proxying.

## Scope

**In Scope:**
- `volt-sockmap` integration into `wicket-stream`
- Feature flag `ebpf` (Linux-only, disabled by default)
- L4 TCP passthrough acceleration

**Out of Scope:**
- L7/HTTP integration (Pingora)
- Firewall, SynProxy, SNI capture from Volt
- Metrics (use volt-sockmap's built-in stats)
- New crates (use volt-sockmap directly)

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                  wicket-stream                      │
│                                                     │
│   Accept → SNI Extract → Route → Connect Backend    │
│                              │                      │
│              ┌───────────────┴───────────────┐      │
│              │                               │      │
│         [ebpf feature]              [no ebpf]       │
│              │                               │      │
│              ▼                               ▼      │
│    Register socket pair            tokio::select!  │
│    in volt-sockmap                 io::copy bidir  │
│              │                                      │
│              ▼                                      │
│    Kernel handles data                              │
│    (zero-copy redirect)                             │
│              │                                      │
│              ▼                                      │
│    Wait for close →                                 │
│    Unregister pair                                  │
└─────────────────────────────────────────────────────┘
```

---

## Implementation

### 1. Add Volt as Git Submodule

```bash
git submodule add https://github.com/GEverding/volt.git volt
```

### 2. Update Workspace Cargo.toml

```toml
[workspace]
members = [
    "crates/*",
]

[workspace.dependencies]
# ... existing deps ...
volt-sockmap = { path = "volt/crates/volt-sockmap" }
```

### 3. Update wicket-stream/Cargo.toml

```toml
[features]
default = []
ebpf = ["volt-sockmap"]

[target.'cfg(target_os = "linux")'.dependencies]
volt-sockmap = { workspace = true, optional = true }
```

### 4. Modify wicket-stream/src/proxy.rs

```rust
#[cfg(all(target_os = "linux", feature = "ebpf"))]
use volt_sockmap::{SocketMap, SocketMapConfig};

pub struct StreamProxy {
    router: SniRouter,
    source_pool: Option<SourcePool>,
    proxy_protocol: Option<ProxyProtocolConfig>,
    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    sockmap: Option<std::sync::Arc<std::sync::Mutex<SocketMap>>>,
}

impl StreamProxy {
    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    pub fn with_sockmap(mut self, sockmap: SocketMap) -> Self {
        self.sockmap = Some(std::sync::Arc::new(std::sync::Mutex::new(sockmap)));
        self
    }

    async fn proxy_connection(
        &self,
        mut client: TcpStream,
        mut backend: TcpStream,
    ) -> Result<(), Error> {
        #[cfg(all(target_os = "linux", feature = "ebpf"))]
        if let Some(sockmap) = &self.sockmap {
            use std::os::fd::AsRawFd;
            let client_fd = client.as_raw_fd();
            let backend_fd = backend.as_raw_fd();

            // Try to register for kernel-level proxying
            let registered = {
                let mut sm = sockmap.lock().unwrap();
                sm.register_pair(client_fd, backend_fd).is_ok()
            };

            if registered {
                // Kernel handles data transfer - just wait for close
                tokio::select! {
                    _ = wait_readable(&client) => {}
                    _ = wait_readable(&backend) => {}
                }

                // Unregister on close
                let _ = sockmap.lock().unwrap()
                    .unregister_pair(client_fd, backend_fd);
                return Ok(());
            }
            // Fall through to user-space proxying if registration failed
        }

        // User-space proxying (default path)
        let (mut client_read, mut client_write) = client.split();
        let (mut backend_read, mut backend_write) = backend.split();

        tokio::select! {
            r = tokio::io::copy(&mut client_read, &mut backend_write) => r?,
            r = tokio::io::copy(&mut backend_read, &mut client_write) => r?,
        };

        Ok(())
    }
}

#[cfg(all(target_os = "linux", feature = "ebpf"))]
async fn wait_readable(stream: &TcpStream) -> std::io::Result<()> {
    stream.readable().await
}
```

### 5. Update wicket/src/main.rs (Optional - for initialization)

```rust
#[cfg(all(target_os = "linux", feature = "ebpf"))]
fn init_sockmap() -> Option<volt_sockmap::SocketMap> {
    use volt_sockmap::{SocketMap, SocketMapConfig};

    let config = SocketMapConfig::default();
    match SocketMap::load(config) {
        Ok(mut sm) => {
            if let Err(e) = sm.attach() {
                tracing::warn!("Failed to attach sockmap: {}", e);
                return None;
            }
            tracing::info!("eBPF sockmap initialized");
            Some(sm)
        }
        Err(e) => {
            tracing::warn!("Failed to load sockmap: {}", e);
            None
        }
    }
}
```

---

## Build Instructions

### Linux (with eBPF)
```bash
# First time: initialize submodule and build BPF objects
git submodule update --init
cd volt && make bpf && cd ..

# Build with eBPF support
cargo build --release --features ebpf
```

### macOS/Windows (no eBPF)
```bash
# Standard build - ebpf feature not available
cargo build --release
```

---

## Configuration

Add to `wicket.toml`:

```toml
[stream]
# ... existing config ...
ebpf_enabled = true  # Only effective on Linux with ebpf feature
```

Or via environment variable:
```bash
WICKET_EBPF_ENABLED=true ./wicket
```

---

## Testing

### Verify eBPF is active
```bash
# Check BPF programs loaded
sudo bpftool prog list | grep sockmap

# Check sock_hash map
sudo bpftool map list | grep sock_hash
```

### Basic functionality test
```bash
# Start wicket with eBPF
cargo run --features ebpf -- --config wicket.toml

# In another terminal, test connection
curl -k https://localhost:8443/
```

---

## Limitations

1. **Linux only** - Feature flag compiles to no-op on other platforms
2. **Kernel 5.10+** - Requires modern kernel with sockmap support
3. **L4 only** - Does not accelerate L7/HTTP traffic through Pingora
4. **No TLS inspection** - Works with TLS passthrough, not termination

---

## Files Changed

```
wicket/
├── .gitmodules                      # NEW: volt submodule
├── volt/                            # NEW: submodule
├── Cargo.toml                       # ADD: volt-sockmap workspace dep
├── crates/
│   ├── wicket-stream/
│   │   ├── Cargo.toml               # ADD: ebpf feature, volt-sockmap dep
│   │   └── src/proxy.rs             # ADD: sockmap integration
│   └── wicket/
│       └── src/main.rs              # ADD: sockmap initialization
└── docs/
    └── EBPF_INTEGRATION_PLAN.md     # This file
```
