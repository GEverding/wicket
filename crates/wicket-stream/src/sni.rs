//! SNI (Server Name Indication) extraction from TLS ClientHello.
//!
//! Parses TLS ClientHello messages to extract the Server Name Indication (SNI)
//! extension without terminating the TLS handshake.

use crate::Result;
use std::io::Cursor;
use tokio::io::{AsyncRead, AsyncReadExt};

/// Minimum bytes needed for TLS record header.
#[allow(dead_code)] // Used in tests and future proxy implementation
pub const MIN_TLS_HEADER: usize = 5;

/// TLS content type for handshake messages.
const TLS_HANDSHAKE: u8 = 22;

/// Handshake type for ClientHello.
const HANDSHAKE_CLIENT_HELLO: u8 = 1;

/// Extension type for server_name (SNI).
const EXT_SERVER_NAME: u16 = 0x0000;

/// Server name type for hostname.
const NAME_TYPE_HOSTNAME: u8 = 0;

/// Maximum allowed hostname length per DNS specifications (RFC 1035).
/// A fully qualified domain name can be at most 253 ASCII characters.
const MAX_HOSTNAME_LEN: usize = 253;

/// Check if buffer looks like a TLS handshake.
///
/// Returns true if the buffer starts with a TLS handshake record header.
#[allow(dead_code)] // Used in tests and future proxy implementation
pub fn is_tls_handshake(buf: &[u8]) -> bool {
    if buf.len() < MIN_TLS_HEADER {
        return false;
    }
    buf[0] == TLS_HANDSHAKE
}

/// Extract SNI from a buffer containing TLS ClientHello.
///
/// Returns `None` if:
/// - Not TLS traffic
/// - Not a ClientHello message
/// - No SNI extension present
/// - Parse error (malformed packet)
pub fn extract_sni(buf: &[u8]) -> Option<String> {
    let mut cursor = Cursor::new(buf);

    // Parse TLS record header
    let content_type = read_u8(&mut cursor)?;
    if content_type != TLS_HANDSHAKE {
        return None;
    }

    // Skip TLS version (2 bytes)
    skip(&mut cursor, 2)?;

    // Read record length
    let record_len = read_u16(&mut cursor)? as usize;
    if cursor.position() as usize + record_len > buf.len() {
        return None; // Truncated
    }

    // Parse handshake header
    let handshake_type = read_u8(&mut cursor)?;
    if handshake_type != HANDSHAKE_CLIENT_HELLO {
        return None;
    }

    // Read handshake length (3 bytes)
    let handshake_len = read_u24(&mut cursor)? as usize;
    let handshake_start = cursor.position() as usize;
    if handshake_start + handshake_len > buf.len() {
        return None; // Truncated
    }

    // Skip ClientHello version (2 bytes)
    skip(&mut cursor, 2)?;

    // Skip random (32 bytes)
    skip(&mut cursor, 32)?;

    // Skip session ID
    let session_id_len = read_u8(&mut cursor)? as usize;
    skip(&mut cursor, session_id_len)?;

    // Skip cipher suites
    let cipher_suites_len = read_u16(&mut cursor)? as usize;
    skip(&mut cursor, cipher_suites_len)?;

    // Skip compression methods
    let compression_len = read_u8(&mut cursor)? as usize;
    skip(&mut cursor, compression_len)?;

    // Check if we have extensions
    if cursor.position() as usize >= handshake_start + handshake_len {
        return None; // No extensions
    }

    // Read extensions length
    let extensions_len = read_u16(&mut cursor)? as usize;
    let extensions_end = cursor.position() as usize + extensions_len;

    // Parse extensions
    while (cursor.position() as usize) < extensions_end {
        let ext_type = read_u16(&mut cursor)?;
        let ext_len = read_u16(&mut cursor)? as usize;
        let ext_start = cursor.position() as usize;

        if ext_type == EXT_SERVER_NAME {
            // Parse server name list
            let list_len = read_u16(&mut cursor)? as usize;
            let list_end = cursor.position() as usize + list_len;

            while (cursor.position() as usize) < list_end {
                let name_type = read_u8(&mut cursor)?;
                let name_len = read_u16(&mut cursor)? as usize;

                if name_type == NAME_TYPE_HOSTNAME {
                    // Validate hostname length (M-3 security fix)
                    if name_len > MAX_HOSTNAME_LEN {
                        tracing::warn!(
                            name_len = name_len,
                            max = MAX_HOSTNAME_LEN,
                            "SNI hostname exceeds maximum DNS length, rejecting"
                        );
                        return None;
                    }

                    let name_start = cursor.position() as usize;
                    let name_end = name_start + name_len;
                    if name_end > buf.len() {
                        return None; // Truncated
                    }
                    let hostname = std::str::from_utf8(&buf[name_start..name_end]).ok()?;
                    return Some(hostname.to_string());
                } else {
                    // Skip unknown name type
                    skip(&mut cursor, name_len)?;
                }
            }
            return None; // SNI extension found but no hostname
        } else {
            // Skip this extension
            cursor.set_position((ext_start + ext_len) as u64);
        }
    }

    None // No SNI extension found
}

/// Peek SNI from a stream without consuming bytes.
///
/// Reads enough bytes to parse the ClientHello, then returns the SNI if found.
/// The buffer is reused and will contain the peeked data.
#[allow(dead_code)] // Will be used by proxy implementation
pub async fn peek_sni<R: AsyncRead + Unpin>(
    reader: &mut R,
    buf: &mut Vec<u8>,
) -> Result<Option<String>> {
    // Read TLS record header first
    buf.resize(MIN_TLS_HEADER, 0);
    reader.read_exact(&mut buf[..MIN_TLS_HEADER]).await?;

    if !is_tls_handshake(buf) {
        return Ok(None);
    }

    // Read record length
    let record_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;

    // Read the full record
    let total_len = MIN_TLS_HEADER + record_len;
    buf.resize(total_len, 0);
    reader
        .read_exact(&mut buf[MIN_TLS_HEADER..total_len])
        .await?;

    Ok(extract_sni(buf))
}

// Helper functions for parsing

fn read_u8(cursor: &mut Cursor<&[u8]>) -> Option<u8> {
    let pos = cursor.position() as usize;
    let buf = cursor.get_ref();
    if pos >= buf.len() {
        return None;
    }
    let val = buf[pos];
    cursor.set_position((pos + 1) as u64);
    Some(val)
}

fn read_u16(cursor: &mut Cursor<&[u8]>) -> Option<u16> {
    let pos = cursor.position() as usize;
    let buf = cursor.get_ref();
    if pos + 2 > buf.len() {
        return None;
    }
    let val = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
    cursor.set_position((pos + 2) as u64);
    Some(val)
}

fn read_u24(cursor: &mut Cursor<&[u8]>) -> Option<u32> {
    let pos = cursor.position() as usize;
    let buf = cursor.get_ref();
    if pos + 3 > buf.len() {
        return None;
    }
    let val = u32::from_be_bytes([0, buf[pos], buf[pos + 1], buf[pos + 2]]);
    cursor.set_position((pos + 3) as u64);
    Some(val)
}

fn skip(cursor: &mut Cursor<&[u8]>, n: usize) -> Option<()> {
    let pos = cursor.position() as usize;
    let buf = cursor.get_ref();
    if pos + n > buf.len() {
        return None;
    }
    cursor.set_position((pos + n) as u64);
    Some(())
}

/// Extracts SNI from TLS ClientHello messages.
#[derive(Debug)]
pub struct SniExtractor;

impl SniExtractor {
    /// Create a new SNI extractor.
    pub fn new() -> Self {
        Self
    }

    /// Extract SNI from TLS ClientHello bytes.
    pub fn extract(&self, data: &[u8]) -> Result<Option<String>> {
        Ok(extract_sni(data))
    }
}

impl Default for SniExtractor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Minimal TLS 1.2 ClientHello with SNI for "www.example.com"
    const TLS12_CLIENT_HELLO: &[u8] = &[
        0x16, 0x03, 0x01, 0x00, 0x4d, 0x01, 0x00, 0x00, 0x49, 0x03, 0x03, 0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12,
        0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x00, 0x00,
        0x04, 0x00, 0x2f, 0x00, 0x3c, 0x01, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x00, 0x14, 0x00, 0x12,
        0x00, 0x00, 0x0f, 0x77, 0x77, 0x77, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e,
        0x63, 0x6f, 0x6d, 0x00, 0x15, 0x00, 0x00,
    ];

    // TLS 1.3 ClientHello with SNI for "api.example.org"
    // Manually constructed to be valid
    const TLS13_CLIENT_HELLO: &[u8] = &[
        0x16, 0x03, 0x01, 0x00, 0x4e, // TLS Record: Handshake, TLS 1.0 (legacy), Length 78
        0x01, 0x00, 0x00, 0x4a, // Handshake: ClientHello, Length 74
        0x03, 0x03, // Version: TLS 1.2 (legacy)
        // Random (32 bytes)
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f, 0x00, // Session ID length: 0
        0x00, 0x02, // Cipher suites length: 2
        0x13, 0x01, // TLS_AES_128_GCM_SHA256
        0x01, // Compression methods length: 1
        0x00, // Compression method: null
        0x00, 0x1d, // Extensions length: 29 bytes
        // SNI extension
        0x00, 0x00, // Extension type: server_name (0)
        0x00, 0x14, // Extension length: 20
        0x00, 0x12, // Server name list length: 18
        0x00, // Name type: hostname
        0x00, 0x0f, // Hostname length: 15
        b'a', b'p', b'i', b'.', b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'o', b'r', b'g',
        // supported_versions extension (TLS 1.3)
        0x00, 0x2b, // Extension type: supported_versions (43)
        0x00, 0x03, // Extension length: 3
        0x02, // Supported versions length: 2
        0x03, 0x04, // TLS 1.3
    ];

    // Non-TLS data (HTTP request)
    const NON_TLS: &[u8] = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";

    // Random binary data
    const RANDOM_BYTES: &[u8] = &[
        0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1,
        0xf0,
    ];

    // TLS handshake but not ClientHello (ServerHello)
    const TLS_SERVER_HELLO: &[u8] = &[
        0x16, 0x03, 0x03, 0x00, 0x30, // TLS Record: Handshake, TLS 1.2, Length 48
        0x02, 0x00, 0x00, 0x2c, // Handshake: ServerHello (type 2), Length 44
        0x03, 0x03, // Version: TLS 1.2
        // Random and rest...
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];

    // TLS ClientHello without SNI extension
    const TLS_NO_SNI: &[u8] = &[
        0x16, 0x03, 0x01, 0x00, 0x40, // TLS Record: Handshake, TLS 1.0, Length 64
        0x01, 0x00, 0x00, 0x3c, // Handshake: ClientHello, Length 60
        0x03, 0x03, // Version: TLS 1.2
        // Random (32 bytes)
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f, 0x00, // Session ID length: 0
        0x00, 0x02, // Cipher suites length: 2
        0x00, 0x3c, 0x01, // Compression methods length: 1
        0x00, // Compression method: null
              // No extensions
    ];

    #[test]
    fn test_is_tls_handshake() {
        assert!(is_tls_handshake(TLS12_CLIENT_HELLO));
        assert!(is_tls_handshake(TLS13_CLIENT_HELLO));
        assert!(!is_tls_handshake(NON_TLS));
        assert!(!is_tls_handshake(RANDOM_BYTES));
        assert!(!is_tls_handshake(&[]));
        assert!(!is_tls_handshake(&[0x16, 0x03])); // Too short
    }

    #[test]
    fn test_extract_sni_tls12() {
        let sni = extract_sni(TLS12_CLIENT_HELLO);
        assert_eq!(sni, Some("www.example.com".to_string()));
    }

    #[test]
    fn test_extract_sni_tls13() {
        let sni = extract_sni(TLS13_CLIENT_HELLO);
        assert_eq!(sni, Some("api.example.org".to_string()));
    }

    #[test]
    fn test_extract_sni_non_tls_http() {
        let sni = extract_sni(NON_TLS);
        assert_eq!(sni, None);
    }

    #[test]
    fn test_extract_sni_random_bytes() {
        let sni = extract_sni(RANDOM_BYTES);
        assert_eq!(sni, None);
    }

    #[test]
    fn test_extract_sni_server_hello() {
        let sni = extract_sni(TLS_SERVER_HELLO);
        assert_eq!(sni, None);
    }

    #[test]
    fn test_extract_sni_no_extension() {
        let sni = extract_sni(TLS_NO_SNI);
        assert_eq!(sni, None);
    }

    #[test]
    fn test_extract_sni_truncated_header() {
        // Truncate in the middle of TLS record header
        let truncated = &TLS12_CLIENT_HELLO[..3];
        let sni = extract_sni(truncated);
        assert_eq!(sni, None);
    }

    #[test]
    fn test_extract_sni_truncated_handshake() {
        // Truncate in the middle of handshake
        let truncated = &TLS12_CLIENT_HELLO[..50];
        let sni = extract_sni(truncated);
        assert_eq!(sni, None);
    }

    #[test]
    fn test_extract_sni_truncated_sni_extension() {
        // Truncate in the middle of SNI extension
        let truncated = &TLS12_CLIENT_HELLO[..TLS12_CLIENT_HELLO.len() - 5];
        let sni = extract_sni(truncated);
        assert_eq!(sni, None);
    }

    #[test]
    fn test_extract_sni_empty() {
        let sni = extract_sni(&[]);
        assert_eq!(sni, None);
    }

    #[test]
    fn test_extract_sni_malformed_record_length() {
        // TLS record with invalid length (claims more bytes than available)
        let mut malformed = TLS12_CLIENT_HELLO.to_vec();
        malformed[3] = 0xff; // Set record length to 0xff??
        malformed[4] = 0xff;
        let sni = extract_sni(&malformed);
        assert_eq!(sni, None);
    }

    #[test]
    fn test_extract_sni_malformed_handshake_length() {
        // ClientHello with invalid handshake length
        let mut malformed = TLS12_CLIENT_HELLO.to_vec();
        malformed[7] = 0xff; // Set handshake length byte 2 to 0xff
        let sni = extract_sni(&malformed);
        assert_eq!(sni, None);
    }

    #[test]
    fn test_extract_sni_very_long_hostname() {
        // Test with maximum valid DNS label length (253 chars)
        // Build a ClientHello with a very long SNI
        let long_hostname = "a".repeat(253);
        let mut client_hello = vec![
            0x16, 0x03, 0x01, // TLS Record header (length filled later)
        ];

        // Calculate lengths
        let hostname_len = long_hostname.len();
        let sni_list_len = 1 + 2 + hostname_len; // name_type(1) + name_len(2) + hostname
        let sni_ext_len = 2 + sni_list_len; // list_len(2) + list
        let extensions_len = 2 + 2 + sni_ext_len; // ext_type(2) + ext_len(2) + ext_data
        let handshake_len = 2 + 32 + 1 + 2 + 1 + 2 + extensions_len; // version + random + session_id + ciphers + compression + extensions
        let record_len = 1 + 3 + handshake_len; // handshake_type + handshake_len(3) + handshake_data

        // Record length
        client_hello.extend_from_slice(&(record_len as u16).to_be_bytes());

        // Handshake header
        client_hello.push(0x01); // ClientHello
        client_hello.extend_from_slice(&[
            ((handshake_len >> 16) & 0xff) as u8,
            ((handshake_len >> 8) & 0xff) as u8,
            (handshake_len & 0xff) as u8,
        ]);

        // ClientHello body
        client_hello.extend_from_slice(&[0x03, 0x03]); // TLS 1.2
        client_hello.extend_from_slice(&[0u8; 32]); // Random
        client_hello.push(0x00); // Session ID length
        client_hello.extend_from_slice(&[0x00, 0x02, 0x00, 0x3c]); // Cipher suites
        client_hello.extend_from_slice(&[0x01, 0x00]); // Compression

        // Extensions
        client_hello.extend_from_slice(&(extensions_len as u16).to_be_bytes());

        // SNI extension
        client_hello.extend_from_slice(&[0x00, 0x00]); // Extension type: server_name
        client_hello.extend_from_slice(&(sni_ext_len as u16).to_be_bytes());
        client_hello.extend_from_slice(&(sni_list_len as u16).to_be_bytes());
        client_hello.push(0x00); // Name type: hostname
        client_hello.extend_from_slice(&(hostname_len as u16).to_be_bytes());
        client_hello.extend_from_slice(long_hostname.as_bytes());

        let sni = extract_sni(&client_hello);
        assert_eq!(sni, Some(long_hostname));
    }

    #[test]
    fn test_extract_sni_punycode() {
        // Test with internationalized domain name (punycode)
        // "münchen.de" encoded as "xn--mnchen-3ya.de"
        let punycode_hostname = "xn--mnchen-3ya.de";
        let mut client_hello = vec![
            0x16, 0x03, 0x01, // TLS Record header
        ];

        let hostname_len = punycode_hostname.len();
        let sni_list_len = 1 + 2 + hostname_len;
        let sni_ext_len = 2 + sni_list_len;
        let extensions_len = 2 + 2 + sni_ext_len;
        let handshake_len = 2 + 32 + 1 + 2 + 1 + 2 + extensions_len;
        let record_len = 1 + 3 + handshake_len;

        client_hello.extend_from_slice(&(record_len as u16).to_be_bytes());
        client_hello.push(0x01); // ClientHello
        client_hello.extend_from_slice(&[
            ((handshake_len >> 16) & 0xff) as u8,
            ((handshake_len >> 8) & 0xff) as u8,
            (handshake_len & 0xff) as u8,
        ]);
        client_hello.extend_from_slice(&[0x03, 0x03]); // TLS 1.2
        client_hello.extend_from_slice(&[0u8; 32]); // Random
        client_hello.push(0x00); // Session ID length
        client_hello.extend_from_slice(&[0x00, 0x02, 0x00, 0x3c]); // Cipher suites
        client_hello.extend_from_slice(&[0x01, 0x00]); // Compression
        client_hello.extend_from_slice(&(extensions_len as u16).to_be_bytes());
        client_hello.extend_from_slice(&[0x00, 0x00]); // SNI extension
        client_hello.extend_from_slice(&(sni_ext_len as u16).to_be_bytes());
        client_hello.extend_from_slice(&(sni_list_len as u16).to_be_bytes());
        client_hello.push(0x00); // Name type
        client_hello.extend_from_slice(&(hostname_len as u16).to_be_bytes());
        client_hello.extend_from_slice(punycode_hostname.as_bytes());

        let sni = extract_sni(&client_hello);
        assert_eq!(sni, Some(punycode_hostname.to_string()));
    }

    #[test]
    fn test_extract_sni_invalid_utf8() {
        // Test with invalid UTF-8 in hostname field
        let mut client_hello = TLS12_CLIENT_HELLO.to_vec();
        // Replace valid hostname with invalid UTF-8
        let hostname_start = client_hello.len() - 18; // Position of hostname
        client_hello[hostname_start] = 0xff; // Invalid UTF-8
        client_hello[hostname_start + 1] = 0xfe;

        let sni = extract_sni(&client_hello);
        assert_eq!(sni, None); // Should fail gracefully
    }

    // ========================================================================
    // BUG: TLS_NO_SNI constant is truncated — tests wrong codepath.
    //
    // The constant declares record_length = 0x40 (64 bytes) but only provides
    // 45 bytes of record body. extract_sni() returns None because the
    // truncation check at line 62 fires, NOT because there's no SNI extension.
    // This test proves the issue by constructing a valid ClientHello with no
    // SNI extension and the correct lengths.
    // ========================================================================

    #[test]
    fn test_extract_sni_valid_no_extension_not_truncated() {
        // A properly-formed TLS ClientHello with NO extensions at all.
        // The record length and handshake length must be consistent with the
        // actual buffer size so we actually test the "no extensions" path,
        // not the truncation check.
        let mut client_hello = Vec::new();

        // TLS Record header
        client_hello.push(0x16); // content_type = Handshake
        client_hello.extend_from_slice(&[0x03, 0x01]); // TLS 1.0

        // We'll fill in record length later
        let record_len_pos = client_hello.len();
        client_hello.extend_from_slice(&[0x00, 0x00]); // placeholder

        // Handshake header
        let handshake_start = client_hello.len();
        client_hello.push(0x01); // ClientHello

        // We'll fill in handshake length later
        let hs_len_pos = client_hello.len();
        client_hello.extend_from_slice(&[0x00, 0x00, 0x00]); // placeholder

        let hs_body_start = client_hello.len();

        // ClientHello body
        client_hello.extend_from_slice(&[0x03, 0x03]); // Version TLS 1.2
        client_hello.extend_from_slice(&[0u8; 32]); // Random
        client_hello.push(0x00); // Session ID length = 0
        client_hello.extend_from_slice(&[0x00, 0x02]); // Cipher suites length = 2
        client_hello.extend_from_slice(&[0x00, 0x3c]); // One cipher suite
        client_hello.push(0x01); // Compression methods length = 1
        client_hello.push(0x00); // Null compression
        // No extensions follow — this is where the handshake body ends.

        let hs_body_len = client_hello.len() - hs_body_start;
        let record_body_len = client_hello.len() - handshake_start;

        // Fill in handshake length (3 bytes, big-endian)
        client_hello[hs_len_pos] = ((hs_body_len >> 16) & 0xff) as u8;
        client_hello[hs_len_pos + 1] = ((hs_body_len >> 8) & 0xff) as u8;
        client_hello[hs_len_pos + 2] = (hs_body_len & 0xff) as u8;

        // Fill in record length (2 bytes, big-endian)
        client_hello[record_len_pos] = ((record_body_len >> 8) & 0xff) as u8;
        client_hello[record_len_pos + 1] = (record_body_len & 0xff) as u8;

        let sni = extract_sni(&client_hello);
        assert_eq!(
            sni, None,
            "Valid ClientHello with no extensions should return None (not truncation error)"
        );

        // Verify our constant is self-consistent: record length must match actual buffer
        let declared_record_len =
            u16::from_be_bytes([client_hello[3], client_hello[4]]) as usize;
        let actual_record_body = client_hello.len() - 5; // subtract 5-byte header
        assert_eq!(
            declared_record_len, actual_record_body,
            "Record length field must match actual buffer size"
        );
    }

    /// Verify that the existing TLS_NO_SNI constant has inconsistent lengths.
    /// This test documents the bug: the constant is truncated, so the existing
    /// test_extract_sni_no_extension passes for the wrong reason.
    #[test]
    fn test_tls_no_sni_constant_is_truncated() {
        // The constant declares record length = 0x40 = 64
        let declared_record_len = u16::from_be_bytes([TLS_NO_SNI[3], TLS_NO_SNI[4]]) as usize;
        let actual_record_body = TLS_NO_SNI.len() - 5;

        // This should fail if the constant were correct - it proves the constant is broken
        assert_eq!(
            declared_record_len, actual_record_body,
            "TLS_NO_SNI constant has record_length={} but only {} bytes of record body. \
             The extract_sni test passes due to truncation detection, not because it \
             correctly identifies a ClientHello without SNI extension.",
            declared_record_len, actual_record_body
        );
    }

    #[test]
    fn test_sni_extractor() {
        let extractor = SniExtractor::new();
        let result = extractor.extract(TLS12_CLIENT_HELLO).unwrap();
        assert_eq!(result, Some("www.example.com".to_string()));
    }

    #[test]
    fn test_sni_extractor_default() {
        let extractor = SniExtractor;
        let result = extractor.extract(TLS12_CLIENT_HELLO).unwrap();
        assert_eq!(result, Some("www.example.com".to_string()));
    }

    #[tokio::test]
    async fn test_peek_sni_async() {
        let data = TLS12_CLIENT_HELLO.to_vec();
        let mut cursor = std::io::Cursor::new(data.clone());
        let mut buf = Vec::new();

        let sni = peek_sni(&mut cursor, &mut buf).await.unwrap();
        assert_eq!(sni, Some("www.example.com".to_string()));
        assert_eq!(buf.len(), TLS12_CLIENT_HELLO.len());
    }

    #[tokio::test]
    async fn test_peek_sni_async_non_tls() {
        let data = NON_TLS.to_vec();
        let mut cursor = std::io::Cursor::new(data);
        let mut buf = Vec::new();

        let sni = peek_sni(&mut cursor, &mut buf).await.unwrap();
        assert_eq!(sni, None);
    }
}
