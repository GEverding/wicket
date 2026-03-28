//! PROXY protocol encoder (v1 and v2).
//!
//! Implements HAProxy PROXY protocol v1 (text) and v2 (binary) encoding.
//! See: https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt

use std::net::SocketAddr;

/// PROXY protocol version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyProtocolVersion {
    /// PROXY protocol v1 (text-based).
    V1,
    /// PROXY protocol v2 (binary).
    V2,
}

/// PROXY protocol v2 signature (12 bytes).
const PROXY_V2_SIGNATURE: [u8; 12] = [
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
];

/// Encodes PROXY protocol headers.
pub struct ProxyProtocolEncoder;

impl ProxyProtocolEncoder {
    /// Encode proxy protocol header.
    ///
    /// # Arguments
    /// * `version` - PROXY protocol version (v1 or v2)
    /// * `client_addr` - Original client address
    /// * `proxy_addr` - Proxy/destination address
    ///
    /// # Returns
    /// Encoded header bytes ready to send before proxied data.
    pub fn encode(
        version: ProxyProtocolVersion,
        client_addr: SocketAddr,
        proxy_addr: SocketAddr,
    ) -> Vec<u8> {
        match version {
            ProxyProtocolVersion::V1 => Self::encode_v1(client_addr, proxy_addr),
            ProxyProtocolVersion::V2 => Self::encode_v2(client_addr, proxy_addr),
        }
    }

    /// Encode v1 (text format).
    ///
    /// Format: `PROXY TCP4 <src_ip> <dst_ip> <src_port> <dst_port>\r\n`
    fn encode_v1(client_addr: SocketAddr, proxy_addr: SocketAddr) -> Vec<u8> {
        let protocol = if client_addr.is_ipv4() {
            "TCP4"
        } else {
            "TCP6"
        };
        let header = format!(
            "PROXY {} {} {} {} {}\r\n",
            protocol,
            client_addr.ip(),
            proxy_addr.ip(),
            client_addr.port(),
            proxy_addr.port()
        );
        header.into_bytes()
    }

    /// Encode v2 (binary format).
    ///
    /// Binary format with signature, version/command, family/protocol, length, and addresses.
    fn encode_v2(client_addr: SocketAddr, proxy_addr: SocketAddr) -> Vec<u8> {
        let mut buf = Vec::new();

        // Signature (12 bytes)
        buf.extend_from_slice(&PROXY_V2_SIGNATURE);

        // Version and command (1 byte): 0x21 = version 2, PROXY command
        buf.push(0x21);

        // Family and protocol (1 byte)
        let family = if client_addr.is_ipv4() {
            0x11 // AF_INET (IPv4) + STREAM
        } else {
            0x21 // AF_INET6 (IPv6) + STREAM
        };
        buf.push(family);

        // Length and addresses
        if client_addr.is_ipv4() {
            // Length: 12 bytes (4+4+2+2) in big-endian
            buf.extend_from_slice(&[0x00, 0x0C]);

            // Source address (4 bytes)
            if let SocketAddr::V4(addr) = client_addr {
                buf.extend_from_slice(&addr.ip().octets());
            }

            // Destination address (4 bytes)
            if let SocketAddr::V4(addr) = proxy_addr {
                buf.extend_from_slice(&addr.ip().octets());
            }

            // Source port (2 bytes, big-endian)
            buf.extend_from_slice(&client_addr.port().to_be_bytes());

            // Destination port (2 bytes, big-endian)
            buf.extend_from_slice(&proxy_addr.port().to_be_bytes());
        } else {
            // Length: 36 bytes (16+16+2+2) in big-endian
            buf.extend_from_slice(&[0x00, 0x24]);

            // Source address (16 bytes)
            if let SocketAddr::V6(addr) = client_addr {
                buf.extend_from_slice(&addr.ip().octets());
            }

            // Destination address (16 bytes)
            if let SocketAddr::V6(addr) = proxy_addr {
                buf.extend_from_slice(&addr.ip().octets());
            }

            // Source port (2 bytes, big-endian)
            buf.extend_from_slice(&client_addr.port().to_be_bytes());

            // Destination port (2 bytes, big-endian)
            buf.extend_from_slice(&proxy_addr.port().to_be_bytes());
        }

        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_v1_ipv4() {
        let client = "192.168.1.100:12345".parse().unwrap();
        let proxy = "10.0.0.1:443".parse().unwrap();
        let encoded = ProxyProtocolEncoder::encode(ProxyProtocolVersion::V1, client, proxy);
        let expected = b"PROXY TCP4 192.168.1.100 10.0.0.1 12345 443\r\n";
        assert_eq!(encoded, expected);
    }

    #[test]
    fn test_v1_ipv4_exact_haproxy_spec() {
        // Test exact format per HAProxy spec
        let client = "255.255.255.255:65535".parse().unwrap();
        let proxy = "0.0.0.0:1".parse().unwrap();
        let encoded = ProxyProtocolEncoder::encode(ProxyProtocolVersion::V1, client, proxy);
        let s = String::from_utf8(encoded.clone()).unwrap();

        // Must start with "PROXY "
        assert!(s.starts_with("PROXY "));
        // Must end with CRLF
        assert!(s.ends_with("\r\n"));
        // Must contain TCP4
        assert!(s.contains("TCP4"));
        // Verify exact format
        assert_eq!(encoded, b"PROXY TCP4 255.255.255.255 0.0.0.0 65535 1\r\n");
    }

    #[test]
    fn test_v1_ipv6() {
        let client = "[2001:db8::1]:12345".parse().unwrap();
        let proxy = "[2001:db8::2]:443".parse().unwrap();
        let encoded = ProxyProtocolEncoder::encode(ProxyProtocolVersion::V1, client, proxy);
        assert!(encoded.starts_with(b"PROXY TCP6 "));
        assert!(encoded.ends_with(b"\r\n"));
        let s = String::from_utf8(encoded).unwrap();
        assert!(s.contains("2001:db8::1"));
        assert!(s.contains("2001:db8::2"));
        assert!(s.contains("12345"));
        assert!(s.contains("443"));
    }

    #[test]
    fn test_v1_ipv6_full_address() {
        let client = "[2001:0db8:0000:0000:0000:0000:0000:0001]:8080"
            .parse()
            .unwrap();
        let proxy = "[fe80::1]:443".parse().unwrap();
        let encoded = ProxyProtocolEncoder::encode(ProxyProtocolVersion::V1, client, proxy);
        let s = String::from_utf8(encoded).unwrap();

        assert!(s.starts_with("PROXY TCP6 "));
        assert!(s.ends_with("\r\n"));
        assert!(s.contains("8080"));
        assert!(s.contains("443"));
    }

    #[test]
    fn test_v1_port_edge_cases() {
        // Port 0
        let client = "192.168.1.1:0".parse().unwrap();
        let proxy = "10.0.0.1:443".parse().unwrap();
        let encoded = ProxyProtocolEncoder::encode(ProxyProtocolVersion::V1, client, proxy);
        assert_eq!(encoded, b"PROXY TCP4 192.168.1.1 10.0.0.1 0 443\r\n");

        // Port 65535
        let client = "192.168.1.1:65535".parse().unwrap();
        let proxy = "10.0.0.1:65535".parse().unwrap();
        let encoded = ProxyProtocolEncoder::encode(ProxyProtocolVersion::V1, client, proxy);
        assert_eq!(encoded, b"PROXY TCP4 192.168.1.1 10.0.0.1 65535 65535\r\n");
    }

    #[test]
    fn test_v1_mixed_ipv4_ipv6() {
        // Client IPv4, proxy IPv4 (normal case)
        let client = "192.168.1.1:1234".parse().unwrap();
        let proxy = "10.0.0.1:443".parse().unwrap();
        let encoded = ProxyProtocolEncoder::encode(ProxyProtocolVersion::V1, client, proxy);
        let s = String::from_utf8(encoded).unwrap();
        assert!(s.contains("TCP4"));

        // Client IPv6, proxy IPv6
        let client = "[::1]:1234".parse().unwrap();
        let proxy = "[::1]:443".parse().unwrap();
        let encoded = ProxyProtocolEncoder::encode(ProxyProtocolVersion::V1, client, proxy);
        let s = String::from_utf8(encoded).unwrap();
        assert!(s.contains("TCP6"));
    }

    #[test]
    fn test_v2_ipv4() {
        let client = "192.168.1.100:12345".parse().unwrap();
        let proxy = "10.0.0.1:443".parse().unwrap();
        let encoded = ProxyProtocolEncoder::encode(ProxyProtocolVersion::V2, client, proxy);

        // Check signature
        assert_eq!(&encoded[0..12], &PROXY_V2_SIGNATURE);
        // Check version/command (0x21 = version 2, PROXY command)
        assert_eq!(encoded[12], 0x21);
        // Check family (0x11 = AF_INET, STREAM)
        assert_eq!(encoded[13], 0x11);
        // Check length (12 bytes for IPv4: 4+4+2+2)
        assert_eq!(&encoded[14..16], &[0x00, 0x0C]);

        // Check source IP (192.168.1.100)
        assert_eq!(&encoded[16..20], &[192, 168, 1, 100]);
        // Check dest IP (10.0.0.1)
        assert_eq!(&encoded[20..24], &[10, 0, 0, 1]);
        // Check source port (12345 = 0x3039)
        assert_eq!(&encoded[24..26], &[0x30, 0x39]);
        // Check dest port (443 = 0x01BB)
        assert_eq!(&encoded[26..28], &[0x01, 0xBB]);

        // Total length should be 28 bytes
        assert_eq!(encoded.len(), 28);
    }

    #[test]
    fn test_v2_ipv4_binary_format() {
        // Verify exact binary format per HAProxy spec
        let client = "127.0.0.1:80".parse().unwrap();
        let proxy = "127.0.0.1:8080".parse().unwrap();
        let encoded = ProxyProtocolEncoder::encode(ProxyProtocolVersion::V2, client, proxy);

        // Signature must be exact
        assert_eq!(
            &encoded[0..12],
            &[0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A]
        );

        // Version (2) and command (PROXY = 1) = 0x21
        assert_eq!(encoded[12], 0x21);

        // Family (INET = 1) and protocol (STREAM = 1) = 0x11
        assert_eq!(encoded[13], 0x11);

        // Source IP: 127.0.0.1
        assert_eq!(&encoded[16..20], &[127, 0, 0, 1]);
        // Dest IP: 127.0.0.1
        assert_eq!(&encoded[20..24], &[127, 0, 0, 1]);
        // Source port: 80 = 0x0050
        assert_eq!(&encoded[24..26], &[0x00, 0x50]);
        // Dest port: 8080 = 0x1F90
        assert_eq!(&encoded[26..28], &[0x1F, 0x90]);
    }

    #[test]
    fn test_v2_ipv6() {
        let client = "[2001:db8::1]:12345".parse().unwrap();
        let proxy = "[2001:db8::2]:443".parse().unwrap();
        let encoded = ProxyProtocolEncoder::encode(ProxyProtocolVersion::V2, client, proxy);

        // Check signature
        assert_eq!(&encoded[0..12], &PROXY_V2_SIGNATURE);
        // Check version/command
        assert_eq!(encoded[12], 0x21);
        // Check family (0x21 = AF_INET6, STREAM)
        assert_eq!(encoded[13], 0x21);
        // Check length (36 bytes for IPv6: 16+16+2+2)
        assert_eq!(&encoded[14..16], &[0x00, 0x24]);

        // Total length should be 52 bytes (12 + 1 + 1 + 2 + 36)
        assert_eq!(encoded.len(), 52);

        // Check source port (12345 = 0x3039)
        assert_eq!(&encoded[48..50], &[0x30, 0x39]);
        // Check dest port (443 = 0x01BB)
        assert_eq!(&encoded[50..52], &[0x01, 0xBB]);
    }

    #[test]
    fn test_v2_ipv6_addresses() {
        let client = "[2001:db8::1]:12345".parse().unwrap();
        let proxy = "[2001:db8::2]:443".parse().unwrap();
        let encoded = ProxyProtocolEncoder::encode(ProxyProtocolVersion::V2, client, proxy);

        // Source address: 2001:0db8:0000:0000:0000:0000:0000:0001
        let expected_src = [
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ];
        assert_eq!(&encoded[16..32], &expected_src);

        // Dest address: 2001:0db8:0000:0000:0000:0000:0000:0002
        let expected_dst = [
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x02,
        ];
        assert_eq!(&encoded[32..48], &expected_dst);
    }

    #[test]
    fn test_v2_ipv6_loopback() {
        let client = "[::1]:1234".parse().unwrap();
        let proxy = "[::1]:5678".parse().unwrap();
        let encoded = ProxyProtocolEncoder::encode(ProxyProtocolVersion::V2, client, proxy);

        // Loopback address: ::1
        let expected_loopback = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ];
        assert_eq!(&encoded[16..32], &expected_loopback);
        assert_eq!(&encoded[32..48], &expected_loopback);
    }

    #[test]
    fn test_v2_port_edge_cases() {
        // Port 0
        let client = "192.168.1.1:0".parse().unwrap();
        let proxy = "10.0.0.1:0".parse().unwrap();
        let encoded = ProxyProtocolEncoder::encode(ProxyProtocolVersion::V2, client, proxy);
        assert_eq!(&encoded[24..26], &[0x00, 0x00]); // Source port 0
        assert_eq!(&encoded[26..28], &[0x00, 0x00]); // Dest port 0

        // Port 65535
        let client = "192.168.1.1:65535".parse().unwrap();
        let proxy = "10.0.0.1:65535".parse().unwrap();
        let encoded = ProxyProtocolEncoder::encode(ProxyProtocolVersion::V2, client, proxy);
        assert_eq!(&encoded[24..26], &[0xFF, 0xFF]); // Source port 65535
        assert_eq!(&encoded[26..28], &[0xFF, 0xFF]); // Dest port 65535
    }

    #[test]
    fn test_v2_signature_exact() {
        // Verify signature matches HAProxy spec exactly
        let client = "1.2.3.4:1234".parse().unwrap();
        let proxy = "5.6.7.8:5678".parse().unwrap();
        let encoded = ProxyProtocolEncoder::encode(ProxyProtocolVersion::V2, client, proxy);

        // Signature: \r\n\r\n\0\r\nQUIT\n
        assert_eq!(encoded[0], 0x0D); // \r
        assert_eq!(encoded[1], 0x0A); // \n
        assert_eq!(encoded[2], 0x0D); // \r
        assert_eq!(encoded[3], 0x0A); // \n
        assert_eq!(encoded[4], 0x00); // \0
        assert_eq!(encoded[5], 0x0D); // \r
        assert_eq!(encoded[6], 0x0A); // \n
        assert_eq!(encoded[7], 0x51); // Q
        assert_eq!(encoded[8], 0x55); // U
        assert_eq!(encoded[9], 0x49); // I
        assert_eq!(encoded[10], 0x54); // T
        assert_eq!(encoded[11], 0x0A); // \n
    }

    // ========================================================================
    // BUG: Mixed IPv4/IPv6 address families produce malformed headers.
    //
    // In encode_v2(), the address family is determined by client_addr only.
    // If proxy_addr has a different family, `if let SocketAddr::V4(addr) = proxy_addr`
    // silently doesn't match, and the destination address bytes are never written.
    // This produces a truncated, malformed PROXY protocol v2 header.
    //
    // In encode_v1(), the protocol is "TCP4" based on the client, but the proxy
    // address is printed as IPv6, which violates the v1 spec format.
    // ========================================================================

    #[test]
    fn test_v2_mixed_ipv4_client_ipv6_proxy_correct_length() {
        // BUG: When client is IPv4 and proxy is IPv6, the destination address
        // bytes are silently omitted, producing a malformed header.
        let client: SocketAddr = "192.168.1.1:1234".parse().unwrap();
        let proxy: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
        let encoded = ProxyProtocolEncoder::encode(ProxyProtocolVersion::V2, client, proxy);

        // With an IPv4 client, the encoder uses IPv4 framing (length = 12).
        // But proxy is IPv6, so `if let SocketAddr::V4(addr) = proxy_addr` doesn't match,
        // and the destination IP (4 bytes) is never written.
        //
        // Expected: header should be 28 bytes (12 sig + 1 ver + 1 fam + 2 len + 12 addrs)
        // or the encoder should detect the mismatch and handle it.
        //
        // The total buffer should contain: sig(12) + ver(1) + fam(1) + len(2) + src_ip(4) + dst_ip(4) + src_port(2) + dst_port(2) = 28
        assert_eq!(
            encoded.len(),
            28,
            "IPv4 PROXY v2 header must be exactly 28 bytes, \
             but mixed address families cause missing destination address"
        );
    }

    #[test]
    fn test_v2_mixed_ipv6_client_ipv4_proxy_correct_length() {
        // BUG: When client is IPv6 and proxy is IPv4, the destination address
        // bytes are silently omitted, producing a malformed header.
        let client: SocketAddr = "[2001:db8::1]:1234".parse().unwrap();
        let proxy: SocketAddr = "192.168.1.1:443".parse().unwrap();
        let encoded = ProxyProtocolEncoder::encode(ProxyProtocolVersion::V2, client, proxy);

        // Expected: 52 bytes for IPv6 framing
        assert_eq!(
            encoded.len(),
            52,
            "IPv6 PROXY v2 header must be exactly 52 bytes, \
             but mixed address families cause missing destination address"
        );
    }

    #[test]
    fn test_v1_mixed_address_families_consistent_protocol() {
        // BUG: v1 uses client_addr to determine "TCP4" vs "TCP6" but then
        // prints proxy_addr.ip() which may be a different family.
        // "PROXY TCP4 192.168.1.1 2001:db8::1 ..." is invalid per the spec.
        let client: SocketAddr = "192.168.1.1:1234".parse().unwrap();
        let proxy: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
        let encoded = ProxyProtocolEncoder::encode(ProxyProtocolVersion::V1, client, proxy);
        let header = String::from_utf8(encoded).unwrap();

        // The header says TCP4 but includes an IPv6 destination address.
        // This is malformed. Either both addresses should be IPv4, both IPv6,
        // or the encoder should detect and handle the mismatch.
        assert!(
            !header.contains("TCP4") || !header.contains("2001:db8::1"),
            "PROXY v1 header must not mix TCP4 protocol with IPv6 address: {}",
            header
        );
    }

    #[test]
    fn test_version_enum() {
        // Test enum values
        assert_eq!(ProxyProtocolVersion::V1, ProxyProtocolVersion::V1);
        assert_eq!(ProxyProtocolVersion::V2, ProxyProtocolVersion::V2);
        assert_ne!(ProxyProtocolVersion::V1, ProxyProtocolVersion::V2);
    }

    #[test]
    fn test_v1_v2_different_output() {
        let client = "192.168.1.1:1234".parse().unwrap();
        let proxy = "10.0.0.1:5678".parse().unwrap();

        let v1 = ProxyProtocolEncoder::encode(ProxyProtocolVersion::V1, client, proxy);
        let v2 = ProxyProtocolEncoder::encode(ProxyProtocolVersion::V2, client, proxy);

        // V1 is text, V2 is binary
        assert_ne!(v1, v2);
        assert!(v1.starts_with(b"PROXY "));
        assert!(v2.starts_with(&PROXY_V2_SIGNATURE));
    }

    #[test]
    fn test_v2_length_field_correctness() {
        // IPv4: length should be 12 (4+4+2+2)
        let client = "1.2.3.4:1234".parse().unwrap();
        let proxy = "5.6.7.8:5678".parse().unwrap();
        let encoded = ProxyProtocolEncoder::encode(ProxyProtocolVersion::V2, client, proxy);
        let length = u16::from_be_bytes([encoded[14], encoded[15]]);
        assert_eq!(length, 12);

        // IPv6: length should be 36 (16+16+2+2)
        let client = "[::1]:1234".parse().unwrap();
        let proxy = "[::1]:5678".parse().unwrap();
        let encoded = ProxyProtocolEncoder::encode(ProxyProtocolVersion::V2, client, proxy);
        let length = u16::from_be_bytes([encoded[14], encoded[15]]);
        assert_eq!(length, 36);
    }
}
