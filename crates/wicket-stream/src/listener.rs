//! TCP listener configuration with SO_REUSEPORT and backlog tuning.
//!
//! Provides utilities for creating high-performance TCP listeners with kernel-level
//! load balancing across multiple workers via SO_REUSEPORT.

use socket2::{Domain, Protocol, Socket, Type};
use std::net::SocketAddr;

/// Configuration for stream proxy listener.
#[derive(Debug, Clone)]
pub struct ListenerConfig {
    /// Address to bind to
    pub addr: SocketAddr,
    /// TCP listen backlog (pending connections queue size)
    pub backlog: u32,
    /// Enable SO_REUSEPORT for kernel load balancing across workers
    pub reuseport: bool,
}

impl Default for ListenerConfig {
    fn default() -> Self {
        Self {
            addr: "0.0.0.0:443".parse().unwrap(),
            backlog: 8000,
            reuseport: true,
        }
    }
}

/// Create a configured TCP listener socket.
///
/// Sets SO_REUSEADDR, SO_REUSEPORT (if enabled), and the listen backlog.
/// Returns a non-blocking std::net::TcpListener ready for async runtime.
pub fn create_listener(config: &ListenerConfig) -> std::io::Result<std::net::TcpListener> {
    let domain = if config.addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };

    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;

    // Allow address reuse
    socket.set_reuse_address(true)?;

    // SO_REUSEPORT for kernel load balancing across workers
    if config.reuseport {
        socket.set_reuse_port(true)?;
    }

    // Bind before setting backlog
    socket.bind(&config.addr.into())?;

    // Listen with configured backlog
    socket.listen(config.backlog as i32)?;

    // Set non-blocking for async runtime
    socket.set_nonblocking(true)?;

    Ok(socket.into())
}

/// Convert std TcpListener to tokio TcpListener.
pub fn into_tokio_listener(
    listener: std::net::TcpListener,
) -> std::io::Result<tokio::net::TcpListener> {
    tokio::net::TcpListener::from_std(listener)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = ListenerConfig::default();
        assert_eq!(config.backlog, 8000);
        assert!(config.reuseport);
    }

    #[test]
    fn test_create_listener() {
        let config = ListenerConfig {
            addr: "127.0.0.1:0".parse().unwrap(), // port 0 = random
            backlog: 128,
            reuseport: false,
        };

        let listener = create_listener(&config).unwrap();
        let local_addr = listener.local_addr().unwrap();
        assert_ne!(local_addr.port(), 0); // Got a real port
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_reuseport_multiple_listeners() {
        // On Linux, SO_REUSEPORT allows multiple sockets on same port
        let config = ListenerConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            backlog: 128,
            reuseport: true,
        };

        let listener1 = create_listener(&config).unwrap();
        let port = listener1.local_addr().unwrap().port();

        let config2 = ListenerConfig {
            addr: format!("127.0.0.1:{}", port).parse().unwrap(),
            backlog: 128,
            reuseport: true,
        };

        // Second listener on same port should work with reuseport
        let listener2 = create_listener(&config2).unwrap();
        assert_eq!(listener2.local_addr().unwrap().port(), port);
    }

    #[tokio::test]
    async fn test_tokio_conversion() {
        let config = ListenerConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            backlog: 128,
            reuseport: false,
        };

        let std_listener = create_listener(&config).unwrap();
        let tokio_listener = into_tokio_listener(std_listener).unwrap();

        // Should be able to accept connections
        assert!(tokio_listener.local_addr().is_ok());
    }
}
