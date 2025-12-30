//! TLS ClientHello builder for testing.
//!
//! Generates valid TLS 1.2 ClientHello packets with optional SNI extension.

use rand::Rng;

/// Builder for TLS ClientHello messages.
#[derive(Debug, Clone)]
pub struct ClientHelloBuilder {
    sni: Option<String>,
}

impl ClientHelloBuilder {
    /// Create a new ClientHello builder.
    pub fn new() -> Self {
        Self { sni: None }
    }

    /// Set the SNI (Server Name Indication) hostname.
    pub fn with_sni(mut self, sni: &str) -> Self {
        self.sni = Some(sni.to_string());
        self
    }

    /// Build a valid TLS 1.2 ClientHello packet.
    ///
    /// Returns the complete TLS record including:
    /// - TLS record header (5 bytes)
    /// - Handshake header (4 bytes)
    /// - ClientHello message
    pub fn build(&self) -> Vec<u8> {
        let mut rng = rand::thread_rng();

        // Build ClientHello message
        let mut client_hello = Vec::new();

        // ClientHello version (TLS 1.2 = 0x0303)
        client_hello.extend_from_slice(&[0x03, 0x03]);

        // Random (32 bytes)
        let mut random = [0u8; 32];
        rng.fill(&mut random);
        client_hello.extend_from_slice(&random);

        // Session ID length (0 = no session)
        client_hello.push(0x00);

        // Cipher suites
        // TLS_RSA_WITH_AES_128_GCM_SHA256 = 0x009C
        let cipher_suites = vec![0x00, 0x9C, 0x00, 0x2F]; // Also include TLS_RSA_WITH_AES_128_CBC_SHA
        client_hello.push((cipher_suites.len() >> 8) as u8);
        client_hello.push(cipher_suites.len() as u8);
        client_hello.extend_from_slice(&cipher_suites);

        // Compression methods (null compression)
        client_hello.push(0x01); // length
        client_hello.push(0x00); // null compression

        // Extensions
        let mut extensions = Vec::new();

        // SNI extension (if provided)
        if let Some(ref sni) = self.sni {
            extensions.extend_from_slice(&self.build_sni_extension(sni));
        }

        // Add extensions to ClientHello
        if !extensions.is_empty() {
            client_hello.push((extensions.len() >> 8) as u8);
            client_hello.push(extensions.len() as u8);
            client_hello.extend_from_slice(&extensions);
        }

        // Build handshake message
        let mut handshake = Vec::new();
        handshake.push(0x01); // Handshake type: ClientHello
        let len = client_hello.len() as u32;
        handshake.push(((len >> 16) & 0xFF) as u8);
        handshake.push(((len >> 8) & 0xFF) as u8);
        handshake.push((len & 0xFF) as u8);
        handshake.extend_from_slice(&client_hello);

        // Build TLS record
        let mut record = Vec::new();
        record.push(0x16); // Content type: Handshake
        record.extend_from_slice(&[0x03, 0x01]); // Version: TLS 1.0 (for compatibility)
        let record_len = handshake.len() as u16;
        record.push((record_len >> 8) as u8);
        record.push((record_len & 0xFF) as u8);
        record.extend_from_slice(&handshake);

        record
    }

    /// Build SNI extension.
    fn build_sni_extension(&self, sni: &str) -> Vec<u8> {
        let mut ext = Vec::new();

        // Extension type: server_name (0x0000)
        ext.extend_from_slice(&[0x00, 0x00]);

        // Build SNI list
        let mut sni_list = Vec::new();
        sni_list.push(0x00); // Name type: host_name
        let sni_len = sni.len() as u16;
        sni_list.push((sni_len >> 8) as u8);
        sni_list.push((sni_len & 0xFF) as u8);
        sni_list.extend_from_slice(sni.as_bytes());

        // SNI list length
        let list_len = sni_list.len() as u16;
        let mut sni_names = Vec::new();
        sni_names.push((list_len >> 8) as u8);
        sni_names.push((list_len & 0xFF) as u8);
        sni_names.extend_from_slice(&sni_list);

        // Extension length
        let ext_len = sni_names.len() as u16;
        ext.push((ext_len >> 8) as u8);
        ext.push((ext_len & 0xFF) as u8);
        ext.extend_from_slice(&sni_names);

        ext
    }
}

impl Default for ClientHelloBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_hello_without_sni() {
        let hello = ClientHelloBuilder::new().build();

        // Check TLS record header
        assert_eq!(hello[0], 0x16); // Handshake
        assert_eq!(hello[1], 0x03); // TLS version
        assert_eq!(hello[2], 0x01);

        // Check record length is reasonable
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

        // Check TLS record header
        assert_eq!(hello[0], 0x16); // Handshake
        assert_eq!(hello[1], 0x03); // TLS version
        assert_eq!(hello[2], 0x01);

        // Check record length is reasonable
        let record_len = u16::from_be_bytes([hello[3], hello[4]]) as usize;
        assert!(record_len > 0);
        assert_eq!(hello.len(), 5 + record_len);

        // Check handshake type
        assert_eq!(hello[5], 0x01); // ClientHello

        // Verify SNI is in the packet
        let hello_str = String::from_utf8_lossy(&hello);
        assert!(hello_str.contains(sni));
    }

    #[test]
    fn test_client_hello_with_long_sni() {
        let sni = "very.long.subdomain.example.com";
        let hello = ClientHelloBuilder::new().with_sni(sni).build();

        // Should still be valid
        assert_eq!(hello[0], 0x16);
        let record_len = u16::from_be_bytes([hello[3], hello[4]]) as usize;
        assert_eq!(hello.len(), 5 + record_len);
    }

    #[test]
    fn test_client_hello_deterministic_structure() {
        // Build two ClientHellos without SNI - structure should be same (random differs)
        let hello1 = ClientHelloBuilder::new().build();
        let hello2 = ClientHelloBuilder::new().build();

        // Same length
        assert_eq!(hello1.len(), hello2.len());

        // Same record header
        assert_eq!(&hello1[0..5], &hello2[0..5]);

        // Same handshake type
        assert_eq!(hello1[5], hello2[5]);

        // Random should differ
        assert_ne!(&hello1[11..43], &hello2[11..43]);
    }

    #[test]
    fn test_client_hello_sni_consistency() {
        let sni = "test.example.com";
        let hello1 = ClientHelloBuilder::new().with_sni(sni).build();
        let hello2 = ClientHelloBuilder::new().with_sni(sni).build();

        // Both should contain the SNI
        assert!(String::from_utf8_lossy(&hello1).contains(sni));
        assert!(String::from_utf8_lossy(&hello2).contains(sni));
    }
}
