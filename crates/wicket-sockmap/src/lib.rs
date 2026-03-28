//! eBPF sockmap for kernel-level socket redirection.
//!
//! On Linux, this crate loads an SK_MSG BPF program that redirects data
//! directly between paired sockets in the kernel, bypassing userspace.
//! This provides significant throughput and latency improvements for
//! L4 passthrough traffic (TLS/TCP proxying).
//!
//! On non-Linux platforms, all operations are no-ops — the proxy falls
//! back to userspace `tokio::io::copy_bidirectional`.

mod error;

#[cfg(target_os = "linux")]
mod sockmap_linux;

#[cfg(not(target_os = "linux"))]
mod sockmap_noop;

pub use error::SockMapError;

#[cfg(target_os = "linux")]
pub use sockmap_linux::{SocketMap, SocketMapConfig};

#[cfg(not(target_os = "linux"))]
pub use sockmap_noop::{SocketMap, SocketMapConfig};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let e = SockMapError::Load("test".to_string());
        assert_eq!(e.to_string(), "BPF load failed: test");
    }

    #[test]
    fn test_config_construction() {
        let _ = SocketMapConfig {
            bpf_object_path: None,
            max_connections: 500_000,
            verbose: false,
        };
    }

    // On non-Linux, verify the no-op impl works
    #[cfg(not(target_os = "linux"))]
    #[test]
    fn test_noop_operations() {
        let config = SocketMapConfig {
            bpf_object_path: None,
            max_connections: 100,
            verbose: false,
        };
        let mut sm = SocketMap::load(config).unwrap();
        sm.attach().unwrap();
        sm.register_pair(0, 1).unwrap();
        sm.unregister_pair(0, 1).unwrap();
    }
}
