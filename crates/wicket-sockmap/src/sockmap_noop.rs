//! No-op sockmap implementation for non-Linux platforms.
//!
//! All operations succeed silently — the proxy falls back to userspace copying.

use crate::SockMapError;

/// Configuration for the eBPF sockmap (no-op on this platform).
pub struct SocketMapConfig {
    /// Path to a pre-compiled BPF object. `None` uses the embedded object.
    pub bpf_object_path: Option<String>,
    /// Maximum number of concurrent connection pairs in the sockhash map.
    pub max_connections: u32,
    /// Enable verbose BPF verifier output.
    pub verbose: bool,
}

/// eBPF sockmap for kernel-level socket redirection (no-op on this platform).
pub struct SocketMap;

impl SocketMap {
    /// Load the BPF program (no-op).
    pub fn load(_config: SocketMapConfig) -> Result<Self, SockMapError> {
        Ok(Self)
    }

    /// Attach the SK_MSG program to the sockhash map (no-op).
    pub fn attach(&mut self) -> Result<(), SockMapError> {
        Ok(())
    }

    /// Register a socket pair for kernel-level redirection (no-op).
    pub fn register_pair(
        &mut self,
        _client_fd: std::os::unix::io::RawFd,
        _backend_fd: std::os::unix::io::RawFd,
    ) -> Result<(), SockMapError> {
        Ok(())
    }

    /// Unregister a socket pair (no-op).
    pub fn unregister_pair(
        &mut self,
        _client_fd: std::os::unix::io::RawFd,
        _backend_fd: std::os::unix::io::RawFd,
    ) -> Result<(), SockMapError> {
        Ok(())
    }
}
