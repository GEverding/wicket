//! Common test utilities for wicket-stream integration tests.
//!
//! Provides helpers for:
//! - MockBackend: TCP server that logs connections
//! - ClientHelloBuilder: Generate TLS ClientHello packets
//! - ProxyProtocolParser: Parse PROXY protocol headers
//! - TestProxy: Helper to spawn StreamProxy for tests

pub mod client_hello;
pub mod mock_backend;
pub mod proxy_protocol;

pub use client_hello::ClientHelloBuilder;
pub use mock_backend::MockBackend;
pub use proxy_protocol::{ParsedProxyProtocol, ProxyProtocolVersion};

/// Get a free port by binding to 127.0.0.1:0 and reading the assigned port.
pub async fn free_port() -> u16 {
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind to free port");
    let addr = listener.local_addr().expect("Failed to get local addr");
    addr.port()
}

/// Create a minimal valid StreamConfig for testing.
pub fn test_stream_config(
    listen_port: u16,
    backends: &[(&str, std::net::SocketAddr)],
) -> wicket_config::StreamConfig {
    use std::collections::HashMap;

    let mut upstreams = Vec::new();
    let mut sni_routes = HashMap::new();

    for (sni, addr) in backends {
        let upstream_name = format!("backend_{}", addr.port());
        upstreams.push(wicket_config::StreamUpstreamConfig {
            name: upstream_name.clone(),
            servers: vec![addr.to_string()],
        });
        sni_routes.insert(sni.to_string(), upstream_name);
    }

    wicket_config::StreamConfig {
        listen: format!("127.0.0.1:{}", listen_port),
        backlog: 8000,
        reuseport: false,
        proxy_protocol: wicket_config::ProxyProtocolConfig::None,
        source_ips: Vec::new(),
        default_upstream: None,
        sni_routes,
        upstreams,
        health_cooldown_secs: 30,
        connect_timeout_ms: 5000,
        max_connections: 10000,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_free_port() {
        let port1 = free_port().await;
        let port2 = free_port().await;

        assert!(port1 > 0);
        assert!(port2 > 0);
        // Ports should be different (very likely)
        assert_ne!(port1, port2);
    }

    #[test]
    fn test_stream_config_creation() {
        use std::net::SocketAddr;

        let backends = vec![
            (
                "api.example.com",
                "127.0.0.1:3001".parse::<SocketAddr>().unwrap(),
            ),
            (
                "web.example.com",
                "127.0.0.1:3002".parse::<SocketAddr>().unwrap(),
            ),
        ];

        let config = test_stream_config(8443, &backends);

        assert_eq!(config.listen, "127.0.0.1:8443");
        assert_eq!(config.upstreams.len(), 2);
        assert_eq!(config.sni_routes.len(), 2);
        assert!(config.sni_routes.contains_key("api.example.com"));
        assert!(config.sni_routes.contains_key("web.example.com"));
    }
}
