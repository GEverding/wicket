//! Integration tests for wicket-stream.
//!
//! This file serves as a smoke test for the common test utilities and end-to-end
//! integration tests for SNI-based routing.

mod common;

use common::{ClientHelloBuilder, MockBackend, ParsedProxyProtocol, ProxyProtocolVersion};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

#[tokio::test]
async fn test_mock_backend_basic() {
    let backend = MockBackend::start().await.expect("Failed to start backend");
    let addr = backend.addr;

    // Connect and send data
    let handle = tokio::spawn(async move {
        let mut stream = TcpStream::connect(addr).await.expect("Failed to connect");
        stream
            .write_all(b"test data")
            .await
            .expect("Failed to write");
        stream.flush().await.expect("Failed to flush");
    });

    let log = backend
        .accept_one()
        .await
        .expect("Failed to accept connection");

    assert_eq!(log.received_bytes, b"test data");
    assert_eq!(log.client_addr.ip().to_string(), "127.0.0.1");

    handle.await.expect("Task panicked");
}

#[test]
fn test_client_hello_builder_basic() {
    let hello = ClientHelloBuilder::new().build();

    // Check TLS record header
    assert_eq!(hello[0], 0x16); // Handshake
    assert_eq!(hello[1], 0x03); // TLS version
    assert_eq!(hello[2], 0x01);

    // Check record length
    let record_len = u16::from_be_bytes([hello[3], hello[4]]) as usize;
    assert!(record_len > 0);
    assert_eq!(hello.len(), 5 + record_len);

    // Check handshake type
    assert_eq!(hello[5], 0x01); // ClientHello
}

#[test]
fn test_client_hello_with_sni() {
    let sni = "example.com";
    let hello = ClientHelloBuilder::new().with_sni(sni).build();

    // Verify SNI is in the packet
    let hello_str = String::from_utf8_lossy(&hello);
    assert!(hello_str.contains(sni));
}

#[test]
fn test_proxy_protocol_v1_parsing() {
    let data = b"PROXY TCP4 192.168.1.1 192.168.1.2 12345 80\r\n";
    let (parsed, consumed) = ParsedProxyProtocol::parse(data).expect("Failed to parse");

    assert_eq!(parsed.version, ProxyProtocolVersion::V1);
    assert_eq!(parsed.src_addr.ip().to_string(), "192.168.1.1");
    assert_eq!(parsed.src_addr.port(), 12345);
    assert_eq!(parsed.dst_addr.ip().to_string(), "192.168.1.2");
    assert_eq!(parsed.dst_addr.port(), 80);
    assert_eq!(consumed, data.len());
}

#[test]
fn test_proxy_protocol_v2_parsing() {
    let mut data = Vec::new();
    data.extend_from_slice(b"\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A");
    data.push(0x21); // v2, PROXY command
    data.push(0x11); // IPv4, TCP
    data.extend_from_slice(&[0x00, 0x0C]); // length = 12
    data.extend_from_slice(&[192, 168, 1, 1]); // src IP
    data.extend_from_slice(&[192, 168, 1, 2]); // dst IP
    data.extend_from_slice(&[0x30, 0x39]); // src port = 12345
    data.extend_from_slice(&[0x00, 0x50]); // dst port = 80

    let (parsed, consumed) = ParsedProxyProtocol::parse(&data).expect("Failed to parse");

    assert_eq!(parsed.version, ProxyProtocolVersion::V2);
    assert_eq!(parsed.src_addr.ip().to_string(), "192.168.1.1");
    assert_eq!(parsed.src_addr.port(), 12345);
    assert_eq!(parsed.dst_addr.ip().to_string(), "192.168.1.2");
    assert_eq!(parsed.dst_addr.port(), 80);
    assert_eq!(consumed, data.len());
}

#[tokio::test]
async fn test_free_port() {
    let port1 = common::free_port().await;
    let port2 = common::free_port().await;

    assert!(port1 > 0);
    assert!(port2 > 0);
    // Ports should be different (very likely)
    assert_ne!(port1, port2);
}

#[test]
fn test_stream_config_creation() {
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

    let config = common::test_stream_config(8443, &backends);

    assert_eq!(config.listen, "127.0.0.1:8443");
    assert_eq!(config.upstreams.len(), 2);
    assert_eq!(config.sni_routes.len(), 2);
    assert!(config.sni_routes.contains_key("api.example.com"));
    assert!(config.sni_routes.contains_key("web.example.com"));
}

// ============================================================================
// SNI Routing End-to-End Integration Tests
// ============================================================================

/// Helper to start a proxy with given config and return the listener task handle.
async fn start_proxy(
    config: &wicket_config::StreamConfig,
) -> Result<
    (Arc<wicket_stream::StreamProxy>, tokio::task::JoinHandle<()>),
    Box<dyn std::error::Error>,
> {
    let proxy = Arc::new(wicket_stream::StreamProxy::from_config(config)?);
    let listen_addr: SocketAddr = config.listen.parse()?;

    // Use create_listener to properly configure the socket
    let listener_config = wicket_stream::ListenerConfig {
        addr: listen_addr,
        backlog: config.backlog,
        reuseport: config.reuseport,
    };
    let listener = wicket_stream::create_listener(&listener_config)?;
    let listener = wicket_stream::into_tokio_listener(listener)?;

    let proxy_clone = Arc::clone(&proxy);
    let handle = tokio::spawn(async move {
        if let Err(e) = proxy_clone.run(listener).await {
            eprintln!("Proxy error: {}", e);
        }
    });

    // Give proxy time to start listening
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    Ok((proxy, handle))
}

#[tokio::test]
async fn test_sni_routing_exact_match() {
    // Start two mock backends
    let api_backend = Arc::new(
        MockBackend::start()
            .await
            .expect("Failed to start api backend"),
    );
    let www_backend = Arc::new(
        MockBackend::start()
            .await
            .expect("Failed to start www backend"),
    );

    // Start accepting connections in background
    let api_handle = api_backend.clone().accept_background();
    let www_handle = www_backend.clone().accept_background();

    // Create config with SNI routes
    let proxy_port = common::free_port().await;
    let backends = vec![
        ("api.example.com", api_backend.addr),
        ("www.example.com", www_backend.addr),
    ];
    let config = common::test_stream_config(proxy_port, &backends);

    // Start proxy
    let (_proxy, proxy_handle) = start_proxy(&config).await.expect("Failed to start proxy");

    // Connect to proxy with SNI="api.example.com"
    let proxy_addr = format!("127.0.0.1:{}", proxy_port);
    let mut client = TcpStream::connect(&proxy_addr)
        .await
        .expect("Failed to connect to proxy");

    let hello = ClientHelloBuilder::new()
        .with_sni("api.example.com")
        .build();
    client
        .write_all(&hello)
        .await
        .expect("Failed to write ClientHello");
    client.flush().await.expect("Failed to flush");

    // Give time for connection to be routed
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    // Verify api backend received connection, www backend did not
    let api_count = api_backend.connection_count().await;
    let www_count = www_backend.connection_count().await;

    assert_eq!(
        api_count, 1,
        "api.example.com backend should receive exactly 1 connection"
    );
    assert_eq!(
        www_count, 0,
        "www.example.com backend should receive 0 connections"
    );

    // Cleanup
    proxy_handle.abort();
    api_handle.abort();
    www_handle.abort();
}

#[tokio::test]
async fn test_sni_routing_wildcard_match() {
    // Start two mock backends
    let wildcard_backend = Arc::new(
        MockBackend::start()
            .await
            .expect("Failed to start wildcard backend"),
    );
    let exact_backend = Arc::new(
        MockBackend::start()
            .await
            .expect("Failed to start exact backend"),
    );

    // Start accepting connections in background
    let wildcard_handle = wildcard_backend.clone().accept_background();
    let exact_handle = exact_backend.clone().accept_background();

    // Create config with wildcard and exact routes
    let proxy_port = common::free_port().await;
    let mut config = wicket_config::StreamConfig {
        listen: format!("127.0.0.1:{}", proxy_port),
        backlog: 128,
        reuseport: false,
        proxy_protocol: wicket_config::ProxyProtocolConfig::None,
        source_ips: Vec::new(),
        default_upstream: None,
        sni_routes: std::collections::HashMap::new(),
        upstreams: vec![
            wicket_config::StreamUpstreamConfig {
                name: "wildcard".into(),
                servers: vec![wildcard_backend.addr.to_string()],
            },
            wicket_config::StreamUpstreamConfig {
                name: "exact".into(),
                servers: vec![exact_backend.addr.to_string()],
            },
        ],
    };
    config
        .sni_routes
        .insert("*.example.com".into(), "wildcard".into());
    config
        .sni_routes
        .insert("api.example.com".into(), "exact".into());

    // Start proxy
    let (_proxy, proxy_handle) = start_proxy(&config).await.expect("Failed to start proxy");

    let proxy_addr = format!("127.0.0.1:{}", proxy_port);

    // Test 1: Exact match should route to exact backend
    let mut client1 = TcpStream::connect(&proxy_addr)
        .await
        .expect("Failed to connect to proxy");
    let hello1 = ClientHelloBuilder::new()
        .with_sni("api.example.com")
        .build();
    client1
        .write_all(&hello1)
        .await
        .expect("Failed to write ClientHello");
    client1.flush().await.expect("Failed to flush");

    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    let exact_count = exact_backend.connection_count().await;
    assert_eq!(
        exact_count, 1,
        "Exact match should route to exact backend (api.example.com)"
    );

    // Test 2: Wildcard match should route to wildcard backend
    let mut client2 = TcpStream::connect(&proxy_addr)
        .await
        .expect("Failed to connect to proxy");
    let hello2 = ClientHelloBuilder::new()
        .with_sni("www.example.com")
        .build();
    client2
        .write_all(&hello2)
        .await
        .expect("Failed to write ClientHello");
    client2.flush().await.expect("Failed to flush");

    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    let wildcard_count = wildcard_backend.connection_count().await;
    assert_eq!(
        wildcard_count, 1,
        "Wildcard match should route to wildcard backend (www.example.com)"
    );

    // Test 3: Root domain should not match wildcard
    let mut client3 = TcpStream::connect(&proxy_addr)
        .await
        .expect("Failed to connect to proxy");
    let hello3 = ClientHelloBuilder::new().with_sni("example.com").build();
    client3
        .write_all(&hello3)
        .await
        .expect("Failed to write ClientHello");
    client3.flush().await.expect("Failed to flush");

    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    // Root domain should not match, so no new connections
    let exact_count_after = exact_backend.connection_count().await;
    let wildcard_count_after = wildcard_backend.connection_count().await;
    assert_eq!(
        exact_count_after, 1,
        "Root domain should not match exact pattern"
    );
    assert_eq!(
        wildcard_count_after, 1,
        "Root domain should not match wildcard pattern"
    );

    // Cleanup
    proxy_handle.abort();
    wildcard_handle.abort();
    exact_handle.abort();
}

#[tokio::test]
async fn test_sni_routing_default_upstream() {
    // Start two mock backends
    let default_backend = Arc::new(
        MockBackend::start()
            .await
            .expect("Failed to start default backend"),
    );
    let specific_backend = Arc::new(
        MockBackend::start()
            .await
            .expect("Failed to start specific backend"),
    );

    // Start accepting connections in background
    let default_handle = default_backend.clone().accept_background();
    let specific_handle = specific_backend.clone().accept_background();

    // Create config with default upstream
    let proxy_port = common::free_port().await;
    let mut config = wicket_config::StreamConfig {
        listen: format!("127.0.0.1:{}", proxy_port),
        backlog: 128,
        reuseport: false,
        proxy_protocol: wicket_config::ProxyProtocolConfig::None,
        source_ips: Vec::new(),
        default_upstream: Some("default".into()),
        sni_routes: std::collections::HashMap::new(),
        upstreams: vec![
            wicket_config::StreamUpstreamConfig {
                name: "default".into(),
                servers: vec![default_backend.addr.to_string()],
            },
            wicket_config::StreamUpstreamConfig {
                name: "specific".into(),
                servers: vec![specific_backend.addr.to_string()],
            },
        ],
    };
    config
        .sni_routes
        .insert("api.example.com".into(), "specific".into());

    // Start proxy
    let (_proxy, proxy_handle) = start_proxy(&config).await.expect("Failed to start proxy");

    let proxy_addr = format!("127.0.0.1:{}", proxy_port);

    // Test 1: Matched SNI should route to specific backend
    let mut client1 = TcpStream::connect(&proxy_addr)
        .await
        .expect("Failed to connect to proxy");
    let hello1 = ClientHelloBuilder::new()
        .with_sni("api.example.com")
        .build();
    client1
        .write_all(&hello1)
        .await
        .expect("Failed to write ClientHello");
    client1.flush().await.expect("Failed to flush");

    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    let specific_count = specific_backend.connection_count().await;
    assert_eq!(
        specific_count, 1,
        "Matched SNI should route to specific backend"
    );

    // Test 2: Unmatched SNI should route to default backend
    let mut client2 = TcpStream::connect(&proxy_addr)
        .await
        .expect("Failed to connect to proxy");
    let hello2 = ClientHelloBuilder::new()
        .with_sni("unknown.example.com")
        .build();
    client2
        .write_all(&hello2)
        .await
        .expect("Failed to write ClientHello");
    client2.flush().await.expect("Failed to flush");

    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    let default_count = default_backend.connection_count().await;
    assert_eq!(
        default_count, 1,
        "Unmatched SNI should route to default backend"
    );

    // Test 3: No SNI (None) should route to default backend
    let mut client3 = TcpStream::connect(&proxy_addr)
        .await
        .expect("Failed to connect to proxy");
    let hello3 = ClientHelloBuilder::new().build(); // No SNI
    client3
        .write_all(&hello3)
        .await
        .expect("Failed to write ClientHello");
    client3.flush().await.expect("Failed to flush");

    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    let default_count_after = default_backend.connection_count().await;
    assert_eq!(
        default_count_after, 2,
        "No SNI should route to default backend"
    );

    // Cleanup
    proxy_handle.abort();
    default_handle.abort();
    specific_handle.abort();
}

#[tokio::test]
async fn test_sni_routing_no_match_no_default() {
    // Start one mock backend
    let backend = Arc::new(MockBackend::start().await.expect("Failed to start backend"));

    // Start accepting connections in background
    let backend_handle = backend.clone().accept_background();

    // Create config WITHOUT default upstream
    let proxy_port = common::free_port().await;
    let mut config = wicket_config::StreamConfig {
        listen: format!("127.0.0.1:{}", proxy_port),
        backlog: 128,
        reuseport: false,
        proxy_protocol: wicket_config::ProxyProtocolConfig::None,
        source_ips: Vec::new(),
        default_upstream: None, // No default!
        sni_routes: std::collections::HashMap::new(),
        upstreams: vec![wicket_config::StreamUpstreamConfig {
            name: "api".into(),
            servers: vec![backend.addr.to_string()],
        }],
    };
    config
        .sni_routes
        .insert("api.example.com".into(), "api".into());

    // Start proxy
    let (_proxy, proxy_handle) = start_proxy(&config).await.expect("Failed to start proxy");

    let proxy_addr = format!("127.0.0.1:{}", proxy_port);

    // Try to connect with unmatched SNI
    let mut client = TcpStream::connect(&proxy_addr)
        .await
        .expect("Failed to connect to proxy");
    let hello = ClientHelloBuilder::new()
        .with_sni("unknown.example.com")
        .build();
    client
        .write_all(&hello)
        .await
        .expect("Failed to write ClientHello");
    client.flush().await.expect("Failed to flush");

    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    // Backend should not receive any connections (no match, no default)
    let count = backend.connection_count().await;
    assert_eq!(
        count, 0,
        "Unmatched SNI with no default should not route to any backend"
    );

    // Cleanup
    proxy_handle.abort();
    backend_handle.abort();
}

#[tokio::test]
async fn test_sni_routing_non_tls_traffic() {
    // Start two mock backends
    let default_backend = Arc::new(
        MockBackend::start()
            .await
            .expect("Failed to start default backend"),
    );
    let specific_backend = Arc::new(
        MockBackend::start()
            .await
            .expect("Failed to start specific backend"),
    );

    // Start accepting connections in background
    let default_handle = default_backend.clone().accept_background();
    let specific_handle = specific_backend.clone().accept_background();

    // Create config with default upstream
    let proxy_port = common::free_port().await;
    let mut config = wicket_config::StreamConfig {
        listen: format!("127.0.0.1:{}", proxy_port),
        backlog: 128,
        reuseport: false,
        proxy_protocol: wicket_config::ProxyProtocolConfig::None,
        source_ips: Vec::new(),
        default_upstream: Some("default".into()),
        sni_routes: std::collections::HashMap::new(),
        upstreams: vec![
            wicket_config::StreamUpstreamConfig {
                name: "default".into(),
                servers: vec![default_backend.addr.to_string()],
            },
            wicket_config::StreamUpstreamConfig {
                name: "specific".into(),
                servers: vec![specific_backend.addr.to_string()],
            },
        ],
    };
    config
        .sni_routes
        .insert("api.example.com".into(), "specific".into());

    // Start proxy
    let (_proxy, proxy_handle) = start_proxy(&config).await.expect("Failed to start proxy");

    let proxy_addr = format!("127.0.0.1:{}", proxy_port);

    // Send non-TLS traffic (plain HTTP)
    let mut client = TcpStream::connect(&proxy_addr)
        .await
        .expect("Failed to connect to proxy");
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        .await
        .expect("Failed to write HTTP request");
    client.flush().await.expect("Failed to flush");

    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    // Non-TLS traffic should route to default backend (SNI can't be extracted)
    let default_count = default_backend.connection_count().await;
    let specific_count = specific_backend.connection_count().await;

    assert_eq!(
        default_count, 1,
        "Non-TLS traffic should route to default backend"
    );
    assert_eq!(
        specific_count, 0,
        "Non-TLS traffic should not route to specific backend"
    );

    // Cleanup
    proxy_handle.abort();
    default_handle.abort();
    specific_handle.abort();
}

#[tokio::test]
async fn test_proxy_basic_routing() {
    // Start a mock backend
    let backend = Arc::new(MockBackend::start().await.expect("Failed to start backend"));
    let backend_handle = backend.clone().accept_background();

    // Create config with default upstream (no SNI routes)
    let proxy_port = common::free_port().await;
    let config = wicket_config::StreamConfig {
        listen: format!("127.0.0.1:{}", proxy_port),
        backlog: 128,
        reuseport: false,
        proxy_protocol: wicket_config::ProxyProtocolConfig::None,
        source_ips: Vec::new(),
        default_upstream: Some("backend".into()),
        sni_routes: std::collections::HashMap::new(),
        upstreams: vec![wicket_config::StreamUpstreamConfig {
            name: "backend".into(),
            servers: vec![backend.addr.to_string()],
        }],
    };

    // Start proxy
    let (_proxy, proxy_handle) = start_proxy(&config).await.expect("Failed to start proxy");

    let proxy_addr = format!("127.0.0.1:{}", proxy_port);

    // Connect and send data
    let mut client = TcpStream::connect(&proxy_addr)
        .await
        .expect("Failed to connect to proxy");
    client
        .write_all(b"test data")
        .await
        .expect("Failed to write");
    client.flush().await.expect("Failed to flush");

    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    // Verify backend received connection
    let count = backend.connection_count().await;
    assert_eq!(count, 1, "Backend should receive 1 connection");

    // Cleanup
    proxy_handle.abort();
    backend_handle.abort();
}
