//! L4 TCP stream proxying for Wicket.
//!
//! This crate provides TCP stream proxying capabilities similar to nginx's stream block,
//! including SNI-based routing, source IP pooling, and proxy protocol support.

mod listener;
mod pool;
mod protocol;
mod proxy;
mod router;
mod sni;

pub use listener::{create_listener, into_tokio_listener, ListenerConfig};
pub use pool::SourceIpPool;
pub use protocol::{ProxyProtocolEncoder, ProxyProtocolVersion};
pub use proxy::{StreamProxy, Upstream};
pub use router::SniRouter;
pub use sni::SniExtractor;

/// Errors that can occur during stream proxying.
#[derive(Debug, thiserror::Error)]
pub enum StreamError {
    #[error("SNI extraction failed: {0}")]
    SniError(String),
    #[error("Routing error: {0}")]
    RoutingError(String),
    #[error("Connection failed: {0}")]
    ConnectionError(String),
    #[error("Config error: {0}")]
    ConfigError(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, StreamError>;
