//! PROXY protocol parser for testing.
//!
//! Parses and verifies PROXY protocol v1 and v2 headers from received data.

use std::io::{Cursor, Read};
use std::net::{IpAddr, SocketAddr};

/// Parsed PROXY protocol header.
#[derive(Debug, Clone, PartialEq)]
pub struct ParsedProxyProtocol {
    pub version: ProxyProtocolVersion,
    pub src_addr: SocketAddr,
    pub dst_addr: SocketAddr,
}

/// PROXY protocol version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyProtocolVersion {
    V1,
    V2,
}

impl ParsedProxyProtocol {
    /// Try to parse proxy protocol from buffer.
    ///
    /// Returns `(parsed, bytes_consumed)` if successful, or `None` if not proxy protocol.
    pub fn parse(buf: &[u8]) -> Option<(Self, usize)> {
        // Try v2 first (binary format)
        if let Some(result) = Self::parse_v2(buf) {
            return Some(result);
        }

        // Try v1 (text format)
        Self::parse_v1(buf)
    }

    /// Parse PROXY protocol v1 (text format).
    ///
    /// Format: `PROXY TCP4|TCP6|UNKNOWN src_ip src_port dst_ip dst_port\r\n`
    fn parse_v1(buf: &[u8]) -> Option<(Self, usize)> {
        if buf.len() < 6 {
            return None;
        }

        // Check for "PROXY " prefix
        if &buf[0..6] != b"PROXY " {
            return None;
        }

        // Find the end of line
        let line_end = buf.iter().position(|&b| b == b'\n')?;
        if line_end < 1 || buf[line_end - 1] != b'\r' {
            return None;
        }

        let line = std::str::from_utf8(&buf[6..line_end - 1]).ok()?;
        let parts: Vec<&str> = line.split_whitespace().collect();

        if parts.len() != 5 {
            return None;
        }

        let protocol = parts[0];
        if protocol == "UNKNOWN" {
            // UNKNOWN format: just consume the line
            return Some((
                ParsedProxyProtocol {
                    version: ProxyProtocolVersion::V1,
                    src_addr: "127.0.0.1:0".parse().unwrap(),
                    dst_addr: "127.0.0.1:0".parse().unwrap(),
                },
                line_end + 1,
            ));
        }

        let src_ip: IpAddr = parts[1].parse().ok()?;
        let dst_ip: IpAddr = parts[2].parse().ok()?;
        let src_port: u16 = parts[3].parse().ok()?;
        let dst_port: u16 = parts[4].parse().ok()?;

        Some((
            ParsedProxyProtocol {
                version: ProxyProtocolVersion::V1,
                src_addr: SocketAddr::new(src_ip, src_port),
                dst_addr: SocketAddr::new(dst_ip, dst_port),
            },
            line_end + 1,
        ))
    }

    /// Parse PROXY protocol v2 (binary format).
    ///
    /// Format:
    /// - Signature: 12 bytes (0x0D 0x0A 0x0D 0x0A 0x00 0x0D 0x0A 0x51 0x55 0x49 0x54 0x0A)
    /// - Version/Command: 1 byte (0x2x for v2)
    /// - Address family/protocol: 1 byte
    /// - Length: 2 bytes (big-endian)
    /// - Addresses (variable)
    fn parse_v2(buf: &[u8]) -> Option<(Self, usize)> {
        if buf.len() < 16 {
            return None;
        }

        // Check signature
        const SIGNATURE: &[u8] = b"\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A";
        if &buf[0..12] != SIGNATURE {
            return None;
        }

        let mut cursor = Cursor::new(&buf[12..]);

        // Read version/command byte
        let ver_cmd = read_u8(&mut cursor)?;
        let version = (ver_cmd >> 4) & 0x0F;
        if version != 2 {
            return None;
        }

        // Read address family/protocol
        let af_proto = read_u8(&mut cursor)?;
        let af = (af_proto >> 4) & 0x0F;
        let _proto = af_proto & 0x0F;

        // Read length
        let len = read_u16(&mut cursor)? as usize;

        let header_size = 16;
        if buf.len() < header_size + len {
            return None;
        }

        // Parse addresses based on family
        let (src_addr, dst_addr) = match af {
            1 => {
                // IPv4 TCP
                if len < 12 {
                    return None;
                }
                let src_ip = read_ipv4(&mut cursor)?;
                let dst_ip = read_ipv4(&mut cursor)?;
                let src_port = read_u16(&mut cursor)?;
                let dst_port = read_u16(&mut cursor)?;
                (
                    SocketAddr::new(src_ip, src_port),
                    SocketAddr::new(dst_ip, dst_port),
                )
            }
            2 => {
                // IPv6 TCP
                if len < 36 {
                    return None;
                }
                let src_ip = read_ipv6(&mut cursor)?;
                let dst_ip = read_ipv6(&mut cursor)?;
                let src_port = read_u16(&mut cursor)?;
                let dst_port = read_u16(&mut cursor)?;
                (
                    SocketAddr::new(src_ip, src_port),
                    SocketAddr::new(dst_ip, dst_port),
                )
            }
            _ => return None, // Unsupported family
        };

        Some((
            ParsedProxyProtocol {
                version: ProxyProtocolVersion::V2,
                src_addr,
                dst_addr,
            },
            header_size + len,
        ))
    }
}

fn read_u8(cursor: &mut Cursor<&[u8]>) -> Option<u8> {
    let mut buf = [0u8; 1];
    cursor.read_exact(&mut buf).ok()?;
    Some(buf[0])
}

fn read_u16(cursor: &mut Cursor<&[u8]>) -> Option<u16> {
    let mut buf = [0u8; 2];
    cursor.read_exact(&mut buf).ok()?;
    Some(u16::from_be_bytes(buf))
}

fn read_ipv4(cursor: &mut Cursor<&[u8]>) -> Option<IpAddr> {
    let mut buf = [0u8; 4];
    cursor.read_exact(&mut buf).ok()?;
    Some(IpAddr::from(buf))
}

fn read_ipv6(cursor: &mut Cursor<&[u8]>) -> Option<IpAddr> {
    let mut buf = [0u8; 16];
    cursor.read_exact(&mut buf).ok()?;
    Some(IpAddr::from(buf))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_v1_ipv4() {
        let data = b"PROXY TCP4 192.168.1.1 192.168.1.2 12345 80\r\n";
        let (parsed, consumed) = ParsedProxyProtocol::parse(data).unwrap();

        assert_eq!(parsed.version, ProxyProtocolVersion::V1);
        assert_eq!(parsed.src_addr.ip().to_string(), "192.168.1.1");
        assert_eq!(parsed.src_addr.port(), 12345);
        assert_eq!(parsed.dst_addr.ip().to_string(), "192.168.1.2");
        assert_eq!(parsed.dst_addr.port(), 80);
        assert_eq!(consumed, data.len());
    }

    #[test]
    fn test_parse_v1_ipv6() {
        let data = b"PROXY TCP6 2001:db8::1 2001:db8::2 12345 443\r\n";
        let (parsed, consumed) = ParsedProxyProtocol::parse(data).unwrap();

        assert_eq!(parsed.version, ProxyProtocolVersion::V1);
        assert_eq!(parsed.src_addr.port(), 12345);
        assert_eq!(parsed.dst_addr.port(), 443);
        assert_eq!(consumed, data.len());
    }

    #[test]
    fn test_parse_v1_unknown() {
        // UNKNOWN format still requires 5 parts per spec
        let data = b"PROXY UNKNOWN 0.0.0.0 0.0.0.0 0 0\r\n";
        let (parsed, consumed) = ParsedProxyProtocol::parse(data).unwrap();

        assert_eq!(parsed.version, ProxyProtocolVersion::V1);
        assert_eq!(consumed, data.len());
    }

    #[test]
    fn test_parse_v1_invalid_no_crlf() {
        let data = b"PROXY TCP4 192.168.1.1 192.168.1.2 12345 80\n";
        assert!(ParsedProxyProtocol::parse(data).is_none());
    }

    #[test]
    fn test_parse_v2_ipv4() {
        let mut data = Vec::new();
        data.extend_from_slice(b"\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A");
        data.push(0x21); // v2, PROXY command
        data.push(0x11); // IPv4, TCP
        data.extend_from_slice(&[0x00, 0x0C]); // length = 12
        data.extend_from_slice(&[192, 168, 1, 1]); // src IP
        data.extend_from_slice(&[192, 168, 1, 2]); // dst IP
        data.extend_from_slice(&[0x30, 0x39]); // src port = 12345
        data.extend_from_slice(&[0x00, 0x50]); // dst port = 80

        let (parsed, consumed) = ParsedProxyProtocol::parse(&data).unwrap();

        assert_eq!(parsed.version, ProxyProtocolVersion::V2);
        assert_eq!(parsed.src_addr.ip().to_string(), "192.168.1.1");
        assert_eq!(parsed.src_addr.port(), 12345);
        assert_eq!(parsed.dst_addr.ip().to_string(), "192.168.1.2");
        assert_eq!(parsed.dst_addr.port(), 80);
        assert_eq!(consumed, data.len());
    }

    #[test]
    fn test_parse_v2_ipv6() {
        let mut data = Vec::new();
        data.extend_from_slice(b"\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A");
        data.push(0x21); // v2, PROXY command
        data.push(0x21); // IPv6, TCP
        data.extend_from_slice(&[0x00, 0x24]); // length = 36
                                               // src IPv6: 2001:db8::1
        data.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        // dst IPv6: 2001:db8::2
        data.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        data.extend_from_slice(&[0x30, 0x39]); // src port = 12345
        data.extend_from_slice(&[0x01, 0xBB]); // dst port = 443

        let (parsed, consumed) = ParsedProxyProtocol::parse(&data).unwrap();

        assert_eq!(parsed.version, ProxyProtocolVersion::V2);
        assert_eq!(parsed.src_addr.port(), 12345);
        assert_eq!(parsed.dst_addr.port(), 443);
        assert_eq!(consumed, data.len());
    }

    #[test]
    fn test_parse_invalid_signature() {
        let data = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x21\x11\x00\x0C";
        assert!(ParsedProxyProtocol::parse(data).is_none());
    }

    #[test]
    fn test_parse_truncated_v2() {
        let data = b"\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A\x21\x11";
        assert!(ParsedProxyProtocol::parse(data).is_none());
    }
}
