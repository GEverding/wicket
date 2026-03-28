/// Errors from eBPF sockmap operations.
#[derive(Debug, thiserror::Error)]
pub enum SockMapError {
    #[error("BPF load failed: {0}")]
    Load(String),

    #[error("BPF attach failed: {0}")]
    Attach(String),

    #[error("sockmap register_pair failed: {0}")]
    Register(String),

    #[error("sockmap unregister_pair failed: {0}")]
    Unregister(String),
}
