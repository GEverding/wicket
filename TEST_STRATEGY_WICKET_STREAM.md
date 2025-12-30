# Wicket-Stream Test Strategy

## Executive Summary

The `wicket-stream` crate implements an L4 TCP stream proxy with SNI-based routing, source IP cycling, and proxy protocol support. Currently has **68 unit tests** covering individual components. This document outlines a comprehensive test strategy to add **integration tests, stress tests, and property-based tests** to ensure production readiness.

**Current State:**
- ✅ 68 unit tests (all passing)
- ✅ SNI extraction: 19 tests (TLS parsing, edge cases, malformed packets)
- ✅ Proxy protocol: 20 tests (v1/v2 encoding, IPv4/IPv6, edge cases)
- ✅ SNI routing: 18 tests (exact/wildcard matching, priority, defaults)
- ✅ Source IP pool: 11 tests (round-robin, thread safety, distribution)
- ✅ Listener config: 3 tests (SO_REUSEPORT, backlog, tokio conversion)
- ❌ Integration tests: 0 (no end-to-end tests)
- ❌ Stress tests: 0 (no high-load tests)
- ❌ Property-based tests: 0 (no fuzzing)

---

## Part 1: Unit Test Gaps

### 1.1 Upstream Round-Robin Selection

**Current Coverage:** None

**Missing Tests:**
- `test_upstream_next_server_round_robin` - Verify servers are selected in order
- `test_upstream_next_server_wraps_around` - Verify wraparound after last server
- `test_upstream_single_server` - Single server always returns same address
- `test_upstream_many_servers` - Large upstream with 100+ servers
- `test_upstream_concurrent_selection` - Thread-safe round-robin under concurrent access
- `test_upstream_counter_overflow` - Counter wraps at usize::MAX

**Setup:** Create `Upstream` instances with various server counts

**Assertions:**
```rust
let upstream = Upstream::new("api".into(), vec![addr1, addr2, addr3]);
assert_eq!(upstream.next_server(), addr1);
assert_eq!(upstream.next_server(), addr2);
assert_eq!(upstream.next_server(), addr3);
assert_eq!(upstream.next_server(), addr1); // wraps
```

**Priority:** MUST-HAVE (core load balancing logic)

---

### 1.2 StreamProxy Configuration Building

**Current Coverage:** None

**Missing Tests:**
- `test_stream_proxy_from_config_valid` - Build proxy from valid config
- `test_stream_proxy_from_config_invalid_server_address` - Bad server IP
- `test_stream_proxy_from_config_invalid_listen_address` - Bad listen IP
- `test_stream_proxy_from_config_missing_upstream` - Route references undefined upstream
- `test_stream_proxy_from_config_with_source_ips` - Source IP pool initialized
- `test_stream_proxy_from_config_without_source_ips` - No source IP pool
- `test_stream_proxy_from_config_proxy_protocol_v1` - V1 protocol set
- `test_stream_proxy_from_config_proxy_protocol_v2` - V2 protocol set
- `test_stream_proxy_from_config_no_proxy_protocol` - None protocol set

**Setup:** Use `wicket_config::StreamConfig` with various configurations

**Assertions:**
```rust
let config = StreamConfig { /* ... */ };
let proxy = StreamProxy::from_config(&config).unwrap();
assert!(proxy.source_ip_pool.is_some());
assert_eq!(proxy.proxy_protocol, Some(ProxyProtocolVersion::V2));
```

**Priority:** MUST-HAVE (config validation)

---

### 1.3 SNI Router Edge Cases

**Current Coverage:** 18 tests (good coverage)

**Missing Tests:**
- `test_router_case_insensitive_matching` - SNI should be case-insensitive (RFC 6066)
- `test_router_empty_hostname` - Empty string SNI with default
- `test_router_very_long_hostname` - 253-char hostname
- `test_router_special_chars_in_hostname` - Hyphens, numbers, underscores
- `test_router_ipv4_literal_as_sni` - "192.168.1.1" as SNI (should not match)
- `test_router_ipv6_literal_as_sni` - "[::1]" as SNI (should not match)

**Setup:** Create routers with various hostname patterns

**Assertions:**
```rust
let mut routes = HashMap::new();
routes.insert("api.example.com".into(), "backend".into());
let router = SniRouter::new(&routes, None);

// Case sensitivity test (document current behavior)
assert_eq!(router.match_sni(Some("api.example.com")), Some("backend"));
assert_eq!(router.match_sni(Some("API.EXAMPLE.COM")), None); // or Some if normalized
```

**Priority:** NICE-TO-HAVE (clarifies RFC compliance)

---

### 1.4 SNI Extraction Edge Cases

**Current Coverage:** 19 tests (excellent coverage)

**Missing Tests:**
- `test_extract_sni_multiple_sni_extensions` - ClientHello with multiple SNI entries (take first)
- `test_extract_sni_other_name_types` - SNI with non-hostname name types (skip gracefully)
- `test_extract_sni_zero_length_hostname` - SNI with 0-byte hostname
- `test_extract_sni_max_record_length` - 16KB TLS record (max size)
- `test_extract_sni_fragmented_record` - Record split across multiple packets (truncated)
- `test_extract_sni_with_session_ticket_extension` - ClientHello with session ticket
- `test_extract_sni_with_supported_groups_extension` - ClientHello with other extensions

**Setup:** Manually construct TLS ClientHello packets with various configurations

**Assertions:**
```rust
let sni = extract_sni(&malformed_packet);
assert_eq!(sni, None); // or Some(expected) for valid cases
```

**Priority:** NICE-TO-HAVE (robustness against malformed packets)

---

### 1.5 Proxy Protocol Encoding Edge Cases

**Current Coverage:** 20 tests (excellent coverage)

**Missing Tests:**
- `test_v1_encoding_with_ipv4_mapped_ipv6` - IPv4-mapped IPv6 address (::ffff:192.0.2.1)
- `test_v2_encoding_with_ipv4_mapped_ipv6` - Same for v2
- `test_v1_encoding_with_link_local_ipv6` - fe80:: addresses
- `test_v2_encoding_with_link_local_ipv6` - Same for v2
- `test_v1_encoding_with_multicast_address` - 224.0.0.0/4 (should still encode)
- `test_v2_encoding_with_multicast_address` - Same for v2

**Setup:** Create SocketAddr with special IP types

**Assertions:**
```rust
let client = "[::ffff:192.0.2.1]:1234".parse().unwrap();
let proxy = "10.0.0.1:443".parse().unwrap();
let encoded = ProxyProtocolEncoder::encode(ProxyProtocolVersion::V1, client, proxy);
// Verify encoding handles IPv4-mapped IPv6
```

**Priority:** NICE-TO-HAVE (handles edge case IPs)

---

## Part 2: Integration Tests

Integration tests verify end-to-end behavior with real TCP connections. These should live in `tests/` directory.

### 2.1 SNI-Based Routing (End-to-End)

**Test Name:** `test_sni_routing_exact_match`

**Description:** Send TLS ClientHello with SNI, verify correct backend receives it

**Setup:**
1. Start mock TLS server on port 5001 (logs received data)
2. Start mock TLS server on port 5002 (logs received data)
3. Create StreamProxy with SNI routes:
   - `api.example.com` → backend 5001
   - `www.example.com` → backend 5002
4. Start proxy on port 4443

**Test Flow:**
1. Connect to proxy:4443
2. Send TLS ClientHello with SNI=`api.example.com`
3. Verify backend 5001 receives the ClientHello
4. Verify backend 5002 does NOT receive it

**Assertions:**
```rust
assert_eq!(backend1.received_connections(), 1);
assert_eq!(backend2.received_connections(), 0);
assert_eq!(backend1.last_sni(), Some("api.example.com"));
```

**Priority:** MUST-HAVE (core feature)

---

**Test Name:** `test_sni_routing_wildcard_match`

**Description:** Wildcard SNI patterns route correctly

**Setup:**
1. Start backends on 5001, 5002
2. Create routes:
   - `*.api.example.com` → backend 5001
   - `*.example.com` → backend 5002
3. Start proxy

**Test Flow:**
1. Connect with SNI=`v1.api.example.com` → should hit backend 5001
2. Connect with SNI=`www.example.com` → should hit backend 5002
3. Connect with SNI=`other.org` → should fail (no default)

**Assertions:**
```rust
assert_eq!(backend1.received_connections(), 1);
assert_eq!(backend2.received_connections(), 1);
```

**Priority:** MUST-HAVE

---

**Test Name:** `test_sni_routing_default_upstream`

**Description:** Unmatched SNI falls back to default upstream

**Setup:**
1. Start backends on 5001, 5002
2. Create routes:
   - `api.example.com` → backend 5001
   - default → backend 5002
3. Start proxy

**Test Flow:**
1. Connect with SNI=`api.example.com` → backend 5001
2. Connect with SNI=`unknown.com` → backend 5002 (default)
3. Connect with no SNI → backend 5002 (default)

**Assertions:**
```rust
assert_eq!(backend1.received_connections(), 1);
assert_eq!(backend2.received_connections(), 2);
```

**Priority:** MUST-HAVE

---

**Test Name:** `test_sni_routing_no_match_no_default`

**Description:** Unmatched SNI with no default closes connection

**Setup:**
1. Start backend on 5001
2. Create routes:
   - `api.example.com` → backend 5001
   - no default
3. Start proxy

**Test Flow:**
1. Connect with SNI=`unknown.com`
2. Expect connection to be rejected/closed

**Assertions:**
```rust
assert!(client.write_all(&tls_hello).is_err() || 
        client.read(&mut buf).is_err());
assert_eq!(backend.received_connections(), 0);
```

**Priority:** MUST-HAVE

---

### 2.2 Proxy Protocol Verification

**Test Name:** `test_proxy_protocol_v1_sent_to_backend`

**Description:** Backend receives correct PROXY protocol v1 header

**Setup:**
1. Start backend that logs received bytes
2. Create proxy with `proxy_protocol = v1`
3. Start proxy

**Test Flow:**
1. Connect to proxy from `192.168.1.100:12345`
2. Send TLS ClientHello
3. Verify backend receives:
   ```
   PROXY TCP4 192.168.1.100 <proxy_ip> 12345 <proxy_port>\r\n
   <TLS ClientHello bytes>
   ```

**Assertions:**
```rust
let received = backend.received_data();
assert!(received.starts_with(b"PROXY TCP4 192.168.1.100"));
assert!(received.contains(&tls_hello_bytes));
```

**Priority:** MUST-HAVE (proxy protocol is critical for backend IP visibility)

---

**Test Name:** `test_proxy_protocol_v2_sent_to_backend`

**Description:** Backend receives correct PROXY protocol v2 header

**Setup:**
1. Start backend that logs received bytes
2. Create proxy with `proxy_protocol = v2`
3. Start proxy

**Test Flow:**
1. Connect to proxy from `192.168.1.100:12345`
2. Send TLS ClientHello
3. Verify backend receives:
   - 12-byte v2 signature
   - Version/command byte (0x21)
   - Family/protocol byte (0x11 for IPv4)
   - Length (0x000C for IPv4)
   - Source IP (192.168.1.100)
   - Dest IP (proxy IP)
   - Source port (12345)
   - Dest port (proxy port)
   - TLS ClientHello bytes

**Assertions:**
```rust
let received = backend.received_data();
assert_eq!(&received[0..12], &PROXY_V2_SIGNATURE);
assert_eq!(received[12], 0x21);
assert_eq!(received[13], 0x11);
```

**Priority:** MUST-HAVE

---

**Test Name:** `test_proxy_protocol_ipv6`

**Description:** Proxy protocol works with IPv6 clients

**Setup:**
1. Start backend
2. Create proxy with `proxy_protocol = v2`
3. Start proxy listening on IPv6

**Test Flow:**
1. Connect from IPv6 client `[2001:db8::1]:12345`
2. Verify backend receives v2 header with:
   - Family byte 0x21 (IPv6)
   - Length 0x0024 (36 bytes)
   - IPv6 addresses

**Assertions:**
```rust
assert_eq!(received[13], 0x21); // IPv6
assert_eq!(&received[14..16], &[0x00, 0x24]); // Length
```

**Priority:** MUST-HAVE

---

### 2.3 Source IP Cycling

**Test Name:** `test_source_ip_cycling_round_robin`

**Description:** Outbound connections cycle through source IPs

**Setup:**
1. Create 3 source IPs: `127.0.0.2`, `127.0.0.3`, `127.0.0.4`
2. Start backend that logs source IP of each connection
3. Create proxy with source_ips configured
4. Start proxy

**Test Flow:**
1. Make 9 connections through proxy
2. Verify backend sees connections from:
   - Connection 1: 127.0.0.2
   - Connection 2: 127.0.0.3
   - Connection 3: 127.0.0.4
   - Connection 4: 127.0.0.2 (wraps)
   - ... (pattern repeats)

**Assertions:**
```rust
let sources = backend.connection_sources();
assert_eq!(sources[0], "127.0.0.2");
assert_eq!(sources[1], "127.0.0.3");
assert_eq!(sources[2], "127.0.0.4");
assert_eq!(sources[3], "127.0.0.2");
```

**Priority:** MUST-HAVE (core feature for port multiplication)

---

**Test Name:** `test_source_ip_cycling_with_proxy_protocol`

**Description:** Source IP cycling works with proxy protocol enabled

**Setup:**
1. Create 2 source IPs
2. Start backend with proxy protocol v2 enabled
3. Create proxy with both source_ips and proxy_protocol = v2

**Test Flow:**
1. Make 4 connections
2. Verify:
   - Connections use different source IPs (127.0.0.2, 127.0.0.3, 127.0.0.2, 127.0.0.3)
   - Proxy protocol header contains correct source IP for each connection

**Assertions:**
```rust
// Connection 1: source IP 127.0.0.2
assert_eq!(backend.connection_source(0), "127.0.0.2");
assert_eq!(backend.proxy_protocol_source_ip(0), "127.0.0.2");

// Connection 2: source IP 127.0.0.3
assert_eq!(backend.connection_source(1), "127.0.0.3");
assert_eq!(backend.proxy_protocol_source_ip(1), "127.0.0.3");
```

**Priority:** MUST-HAVE

---

### 2.4 Connection Handling

**Test Name:** `test_bidirectional_data_flow`

**Description:** Data flows correctly in both directions

**Setup:**
1. Start echo backend (echoes received data back)
2. Start proxy

**Test Flow:**
1. Connect to proxy
2. Send TLS ClientHello
3. Send application data: "Hello, backend!"
4. Receive echo response

**Assertions:**
```rust
client.write_all(&tls_hello)?;
client.write_all(b"Hello, backend!")?;
let mut buf = [0u8; 1024];
let n = client.read(&mut buf)?;
assert_eq!(&buf[..n], b"Hello, backend!");
```

**Priority:** MUST-HAVE (core proxy functionality)

---

**Test Name:** `test_connection_close_client_side`

**Description:** Client closing connection closes backend connection

**Setup:**
1. Start backend that tracks connection state
2. Start proxy

**Test Flow:**
1. Connect to proxy
2. Send TLS ClientHello
3. Close client connection
4. Verify backend connection is also closed

**Assertions:**
```rust
drop(client); // Close client
tokio::time::sleep(Duration::from_millis(100)).await;
assert!(backend.is_connection_closed());
```

**Priority:** MUST-HAVE

---

**Test Name:** `test_connection_close_backend_side`

**Description:** Backend closing connection closes client connection

**Setup:**
1. Start backend that closes connection after receiving data
2. Start proxy

**Test Flow:**
1. Connect to proxy
2. Send TLS ClientHello
3. Backend closes connection
4. Verify client connection is also closed

**Assertions:**
```rust
let mut buf = [0u8; 1024];
let result = client.read(&mut buf);
assert!(result.is_err() || result.unwrap() == 0); // EOF
```

**Priority:** MUST-HAVE

---

**Test Name:** `test_connection_timeout`

**Description:** Idle connections eventually timeout

**Setup:**
1. Start backend
2. Start proxy with connection timeout (e.g., 5 seconds)

**Test Flow:**
1. Connect to proxy
2. Send TLS ClientHello
3. Wait 6 seconds without sending data
4. Verify connection is closed

**Assertions:**
```rust
tokio::time::sleep(Duration::from_secs(6)).await;
let result = client.write_all(b"test");
assert!(result.is_err());
```

**Priority:** NICE-TO-HAVE (resource management)

---

### 2.5 Error Scenarios

**Test Name:** `test_backend_unreachable`

**Description:** Connection fails gracefully when backend is down

**Setup:**
1. Create proxy with route to non-existent backend (127.0.0.1:9999)
2. Start proxy

**Test Flow:**
1. Connect to proxy
2. Send TLS ClientHello
3. Expect connection to be rejected

**Assertions:**
```rust
let result = client.write_all(&tls_hello);
assert!(result.is_err() || client.read(&mut buf).is_err());
```

**Priority:** MUST-HAVE

---

**Test Name:** `test_invalid_tls_data`

**Description:** Non-TLS data is handled gracefully

**Setup:**
1. Start backend
2. Start proxy with SNI routing

**Test Flow:**
1. Connect to proxy
2. Send HTTP request instead of TLS ClientHello
3. Expect connection to be rejected or routed to default

**Assertions:**
```rust
client.write_all(b"GET / HTTP/1.1\r\n")?;
// Either rejected or routed to default upstream
```

**Priority:** MUST-HAVE

---

**Test Name:** `test_truncated_tls_clienthello`

**Description:** Truncated ClientHello is handled gracefully

**Setup:**
1. Start backend
2. Start proxy

**Test Flow:**
1. Connect to proxy
2. Send partial TLS ClientHello (first 10 bytes only)
3. Expect connection to timeout or be rejected

**Assertions:**
```rust
client.write_all(&tls_hello[..10])?;
tokio::time::sleep(Duration::from_secs(1)).await;
// Connection should be closed or timeout
```

**Priority:** NICE-TO-HAVE

---

## Part 3: Stress/Load Tests

Stress tests verify behavior under high load and resource constraints.

### 3.1 High Connection Count

**Test Name:** `test_1000_concurrent_connections`

**Description:** Proxy handles 1000 concurrent connections

**Setup:**
1. Start backend
2. Start proxy
3. Create connection pool

**Test Flow:**
1. Open 1000 concurrent connections
2. Each sends TLS ClientHello
3. Each sends/receives data
4. All close gracefully

**Assertions:**
```rust
let mut handles = vec![];
for i in 0..1000 {
    let handle = tokio::spawn(async move {
        let mut client = TcpStream::connect(proxy_addr).await?;
        client.write_all(&tls_hello).await?;
        client.write_all(b"test").await?;
        let mut buf = [0u8; 1024];
        client.read(&mut buf).await?;
        Ok::<_, Box<dyn std::error::Error>>(())
    });
    handles.push(handle);
}

let results: Vec<_> = futures::future::join_all(handles).await;
assert!(results.iter().all(|r| r.is_ok()));
```

**Priority:** MUST-HAVE (production readiness)

---

**Test Name:** `test_10000_concurrent_connections`

**Description:** Proxy handles 10k concurrent connections (stress test)

**Setup:** Same as above, but with 10k connections

**Test Flow:** Same as above

**Assertions:** All connections succeed

**Priority:** NICE-TO-HAVE (extreme load)

---

### 3.2 Connection Churn

**Test Name:** `test_rapid_connect_disconnect`

**Description:** Proxy handles rapid connection open/close cycles

**Setup:**
1. Start backend
2. Start proxy

**Test Flow:**
1. Open connection
2. Send TLS ClientHello
3. Close immediately
4. Repeat 1000 times

**Assertions:**
```rust
for _ in 0..1000 {
    let mut client = TcpStream::connect(proxy_addr).await?;
    client.write_all(&tls_hello).await?;
    drop(client); // Close immediately
}
// No panics, no resource leaks
```

**Priority:** MUST-HAVE

---

**Test Name:** `test_connection_churn_with_source_ip_cycling`

**Description:** Source IP cycling works under connection churn

**Setup:**
1. Start backend that tracks source IPs
2. Start proxy with 3 source IPs
3. Create 1000 rapid connections

**Test Flow:**
1. Open/close 1000 connections rapidly
2. Verify source IPs cycle correctly
3. Verify no source IP is exhausted

**Assertions:**
```rust
let sources = backend.all_source_ips();
assert_eq!(sources.len(), 3); // Only 3 unique IPs
// Each IP used roughly 333 times
```

**Priority:** MUST-HAVE

---

### 3.3 Resource Leak Detection

**Test Name:** `test_no_fd_leak_after_1000_connections`

**Description:** File descriptors are properly closed

**Setup:**
1. Record initial FD count
2. Start backend and proxy
3. Make 1000 connections

**Test Flow:**
1. Open 1000 connections
2. Close all
3. Wait for cleanup
4. Record final FD count

**Assertions:**
```rust
let initial_fds = count_open_fds();
// ... make 1000 connections and close ...
tokio::time::sleep(Duration::from_secs(1)).await;
let final_fds = count_open_fds();
assert!(final_fds <= initial_fds + 10); // Allow small margin
```

**Priority:** MUST-HAVE

---

**Test Name:** `test_no_memory_leak_after_1000_connections`

**Description:** Memory is properly freed after connections close

**Setup:**
1. Record initial memory usage
2. Start backend and proxy

**Test Flow:**
1. Open 1000 connections
2. Close all
3. Force garbage collection
4. Record final memory usage

**Assertions:**
```rust
let initial_mem = get_memory_usage();
// ... make 1000 connections and close ...
tokio::time::sleep(Duration::from_secs(1)).await;
let final_mem = get_memory_usage();
assert!(final_mem < initial_mem * 1.5); // Allow 50% margin
```

**Priority:** NICE-TO-HAVE (memory safety)

---

## Part 4: Property-Based Tests

Property-based tests use fuzzing to find edge cases.

### 4.1 SNI Parser Fuzzing

**Test Name:** `test_sni_extraction_never_panics`

**Description:** SNI extractor never panics on arbitrary input

**Setup:**
1. Use `proptest` crate
2. Generate arbitrary byte sequences

**Test Flow:**
```rust
proptest!(|(data in any::<Vec<u8>>())| {
    let result = extract_sni(&data);
    // Should never panic, always return Option
    assert!(matches!(result, Some(_) | None));
});
```

**Assertions:**
- Never panics
- Always returns `Option<String>`
- Valid SNI returns `Some(hostname)`
- Invalid/non-TLS returns `None`

**Priority:** MUST-HAVE (robustness)

---

**Test Name:** `test_sni_extraction_valid_utf8_only`

**Description:** Extracted SNI is always valid UTF-8

**Setup:**
1. Generate valid TLS ClientHello packets with various SNI values
2. Use `proptest` to generate valid UTF-8 hostnames

**Test Flow:**
```rust
proptest!(|(hostname in "([a-z0-9-]*\\.)*[a-z0-9-]+")| {
    let packet = construct_tls_clienthello(&hostname);
    let sni = extract_sni(&packet);
    if let Some(extracted) = sni {
        assert_eq!(extracted, hostname);
        assert!(extracted.is_ascii()); // or valid UTF-8
    }
});
```

**Assertions:**
- Extracted SNI is valid UTF-8
- Extracted SNI matches input hostname

**Priority:** MUST-HAVE

---

### 4.2 Proxy Protocol Encoder Fuzzing

**Test Name:** `test_proxy_protocol_encoding_never_panics`

**Description:** Proxy protocol encoder never panics on arbitrary addresses

**Setup:**
1. Use `proptest` to generate arbitrary SocketAddr values

**Test Flow:**
```rust
proptest!(|(client in any::<SocketAddr>(), proxy in any::<SocketAddr>())| {
    let v1 = ProxyProtocolEncoder::encode(ProxyProtocolVersion::V1, client, proxy);
    let v2 = ProxyProtocolEncoder::encode(ProxyProtocolVersion::V2, client, proxy);
    
    // Should never panic
    assert!(!v1.is_empty());
    assert!(!v2.is_empty());
});
```

**Assertions:**
- Never panics
- Always produces non-empty output
- V1 output is valid UTF-8
- V2 output has correct signature

**Priority:** MUST-HAVE

---

**Test Name:** `test_proxy_protocol_v1_format_correctness`

**Description:** V1 encoding always produces valid format

**Setup:**
1. Generate arbitrary SocketAddr values
2. Encode with V1
3. Parse output

**Test Flow:**
```rust
proptest!(|(client in any::<SocketAddr>(), proxy in any::<SocketAddr>())| {
    let encoded = ProxyProtocolEncoder::encode(ProxyProtocolVersion::V1, client, proxy);
    let s = String::from_utf8(encoded).unwrap();
    
    // Must start with "PROXY "
    assert!(s.starts_with("PROXY "));
    // Must end with CRLF
    assert!(s.ends_with("\r\n"));
    // Must contain TCP4 or TCP6
    assert!(s.contains("TCP4") || s.contains("TCP6"));
});
```

**Assertions:**
- Starts with "PROXY "
- Ends with "\r\n"
- Contains "TCP4" or "TCP6"
- Contains valid IP addresses
- Contains valid port numbers

**Priority:** MUST-HAVE

---

### 4.3 Router Fuzzing

**Test Name:** `test_sni_router_never_panics`

**Description:** SNI router never panics on arbitrary hostnames

**Setup:**
1. Generate arbitrary hostname strings
2. Create router with random routes

**Test Flow:**
```rust
proptest!(|(hostname in ".*", routes in any::<HashMap<String, String>>())| {
    let router = SniRouter::new(&routes, None);
    let result = router.match_sni(Some(&hostname));
    // Should never panic
    assert!(matches!(result, Some(_) | None));
});
```

**Assertions:**
- Never panics
- Always returns `Option<&str>`

**Priority:** MUST-HAVE

---

## Part 5: Testing Infrastructure

### 5.1 Mock TLS Server

**Purpose:** Accept TLS connections and log received data

**Features:**
- Logs SNI from ClientHello
- Logs all received bytes
- Tracks connection count
- Tracks source IP of each connection
- Supports echo mode (echoes data back)
- Supports proxy protocol parsing

**Implementation Location:** `tests/common/mock_server.rs`

```rust
pub struct MockTlsServer {
    listener: TcpListener,
    received_data: Arc<Mutex<Vec<Vec<u8>>>>,
    connection_count: Arc<AtomicUsize>,
    source_ips: Arc<Mutex<Vec<String>>>,
}

impl MockTlsServer {
    pub async fn new(addr: &str) -> Self { ... }
    pub async fn accept_one(&self) -> Vec<u8> { ... }
    pub fn received_connections(&self) -> usize { ... }
    pub fn last_sni(&self) -> Option<String> { ... }
    pub fn connection_sources(&self) -> Vec<String> { ... }
}
```

---

### 5.2 TLS ClientHello Generator

**Purpose:** Generate valid TLS ClientHello packets with arbitrary SNI

**Features:**
- Generate TLS 1.2 ClientHello
- Generate TLS 1.3 ClientHello
- Set arbitrary SNI hostname
- Set arbitrary cipher suites
- Generate truncated packets for error testing

**Implementation Location:** `tests/common/tls_helper.rs`

```rust
pub fn generate_tls_clienthello(sni: &str) -> Vec<u8> { ... }
pub fn generate_tls_clienthello_tls13(sni: &str) -> Vec<u8> { ... }
pub fn generate_truncated_clienthello(sni: &str, truncate_at: usize) -> Vec<u8> { ... }
pub fn generate_clienthello_without_sni() -> Vec<u8> { ... }
```

---

### 5.3 Proxy Protocol Parser

**Purpose:** Parse and verify proxy protocol headers in received data

**Features:**
- Parse V1 headers
- Parse V2 headers
- Extract source/dest IPs and ports
- Verify format correctness

**Implementation Location:** `tests/common/proxy_protocol_parser.rs`

```rust
pub struct ProxyProtocolHeader {
    pub version: u8,
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
}

pub fn parse_proxy_protocol_v1(data: &[u8]) -> Option<ProxyProtocolHeader> { ... }
pub fn parse_proxy_protocol_v2(data: &[u8]) -> Option<ProxyProtocolHeader> { ... }
```

---

### 5.4 Connection Tracker

**Purpose:** Track connection state and metrics

**Features:**
- Count connections
- Track source IPs
- Track received/sent bytes
- Detect connection closure
- Measure latency

**Implementation Location:** `tests/common/connection_tracker.rs`

```rust
pub struct ConnectionTracker {
    connections: Arc<Mutex<Vec<ConnectionInfo>>>,
}

pub struct ConnectionInfo {
    pub source_ip: String,
    pub received_bytes: usize,
    pub sent_bytes: usize,
    pub is_closed: bool,
    pub duration: Duration,
}
```

---

## Part 6: Test Organization

```
crates/wicket-stream/
├── src/
│   ├── lib.rs
│   ├── proxy.rs
│   ├── router.rs
│   ├── sni.rs
│   ├── protocol.rs
│   ├── pool.rs
│   └── listener.rs
├── tests/
│   ├── common/
│   │   ├── mod.rs
│   │   ├── mock_server.rs
│   │   ├── tls_helper.rs
│   │   ├── proxy_protocol_parser.rs
│   │   └── connection_tracker.rs
│   ├── integration_sni_routing.rs
│   ├── integration_proxy_protocol.rs
│   ├── integration_source_ip.rs
│   ├── integration_connection_handling.rs
│   ├── integration_error_scenarios.rs
│   ├── stress_high_load.rs
│   ├── stress_connection_churn.rs
│   ├── stress_resource_leaks.rs
│   └── property_based.rs
└── Cargo.toml
```

---

## Part 7: Implementation Roadmap

### Phase 1: Unit Test Gaps (1-2 days)
- [ ] Upstream round-robin tests
- [ ] StreamProxy config building tests
- [ ] SNI router edge cases
- [ ] SNI extraction edge cases
- [ ] Proxy protocol edge cases

**Beads Task:** `wicket-44a` - Unit test coverage gaps

---

### Phase 2: Testing Infrastructure (2-3 days)
- [ ] Mock TLS server
- [ ] TLS ClientHello generator
- [ ] Proxy protocol parser
- [ ] Connection tracker

**Beads Task:** `wicket-44b` - Testing infrastructure

---

### Phase 3: Integration Tests (3-4 days)
- [ ] SNI routing tests (exact, wildcard, default)
- [ ] Proxy protocol tests (v1, v2, IPv4, IPv6)
- [ ] Source IP cycling tests
- [ ] Connection handling tests
- [ ] Error scenario tests

**Beads Task:** `wicket-44c` - Integration tests

---

### Phase 4: Stress Tests (2-3 days)
- [ ] High connection count tests (1k, 10k)
- [ ] Connection churn tests
- [ ] Resource leak detection

**Beads Task:** `wicket-44d` - Stress tests

---

### Phase 5: Property-Based Tests (1-2 days)
- [ ] SNI parser fuzzing
- [ ] Proxy protocol encoder fuzzing
- [ ] Router fuzzing

**Beads Task:** `wicket-44e` - Property-based tests

---

## Part 8: Success Criteria

### Coverage Goals
- **Unit tests:** 95%+ line coverage
- **Integration tests:** All major code paths covered
- **Stress tests:** Verified under 10k concurrent connections
- **Property-based tests:** No panics on arbitrary input

### Performance Goals
- **1k connections:** < 100ms latency, < 50MB memory
- **10k connections:** < 500ms latency, < 500MB memory
- **Connection churn:** 1000 open/close cycles/sec

### Reliability Goals
- **Zero panics** on malformed input
- **Zero resource leaks** after 10k connections
- **Graceful degradation** under overload

---

## Part 9: Dependencies

Add to `Cargo.toml`:

```toml
[dev-dependencies]
proptest = "1.0"
tokio-test = "0.4"
futures = "0.3"
```

---

## Part 10: Notes

### Known Limitations
1. **SNI case sensitivity:** Current implementation is case-sensitive. RFC 6066 specifies case-insensitive matching. Consider normalizing to lowercase.
2. **Wildcard matching:** Current implementation matches any suffix. `*.example.com` matches `.example.com` (edge case).
3. **IPv4-mapped IPv6:** Not explicitly tested. May need special handling.
4. **Connection timeout:** Not implemented. Consider adding idle timeout.

### Future Enhancements
1. **Metrics:** Add Prometheus metrics for connections, bytes, errors
2. **Graceful shutdown:** Implement connection draining
3. **Health checks:** Periodic backend health checks
4. **Circuit breaker:** Fail fast for unhealthy backends
5. **Rate limiting:** Per-upstream rate limits
6. **Connection pooling:** Reuse backend connections

---

## Summary

This test strategy provides comprehensive coverage across:
- **Unit tests:** 15+ new tests for gaps in current coverage
- **Integration tests:** 15+ end-to-end tests for core features
- **Stress tests:** 5+ tests for high load and resource management
- **Property-based tests:** 5+ fuzzing tests for robustness

**Total new tests:** ~40 tests
**Estimated implementation time:** 10-15 days
**Expected coverage:** 95%+ line coverage, all major code paths tested

