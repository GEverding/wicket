//! SNI-based certificate storage and resolution.

use std::collections::HashMap;
use std::sync::Arc;

use rustls::server::ClientHello;
use rustls::server::ResolvesServerCert;
use rustls::sign::CertifiedKey;

/// Certificate store with SNI-based resolution.
///
/// Supports exact domain matches and wildcard certificates.
/// Resolution order:
/// 1. Exact match (e.g., "api.example.com")
/// 2. Wildcard match (e.g., "*.example.com" matches "api.example.com")
/// 3. Default certificate (if set)
#[derive(Debug, Clone, Default)]
pub struct CertStore {
    /// Exact domain -> cert mapping
    exact: HashMap<String, Arc<CertifiedKey>>,
    /// Wildcard base domain -> cert mapping
    /// Key is the base domain (e.g., "example.com" for "*.example.com")
    wildcard: HashMap<String, Arc<CertifiedKey>>,
    /// Default fallback certificate
    default: Option<Arc<CertifiedKey>>,
}

impl CertStore {
    /// Create a new empty certificate store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a certificate for the given domains.
    ///
    /// Domains starting with "*." are treated as wildcards.
    /// The same cert is registered for all provided domains.
    pub fn insert(&mut self, domains: &[String], cert: Arc<CertifiedKey>) {
        for domain in domains {
            let domain_lower = domain.to_lowercase();

            if let Some(base) = domain_lower.strip_prefix("*.") {
                // Wildcard cert: *.example.com -> store under "example.com"
                self.wildcard.insert(base.to_string(), cert.clone());
            } else {
                // Exact match
                self.exact.insert(domain_lower, cert.clone());
            }
        }
    }

    /// Set the default fallback certificate.
    pub fn set_default(&mut self, cert: Arc<CertifiedKey>) {
        self.default = Some(cert);
    }

    /// Resolve a certificate for the given SNI hostname.
    ///
    /// Returns None if no matching certificate is found.
    pub fn resolve(&self, sni: &str) -> Option<Arc<CertifiedKey>> {
        let sni_lower = sni.to_lowercase();

        // 1. Try exact match
        if let Some(cert) = self.exact.get(&sni_lower) {
            return Some(cert.clone());
        }

        // 2. Try wildcard match
        // "api.example.com" -> check for "*.example.com" (stored as "example.com")
        if let Some(parent) = sni_lower.split_once('.').map(|(_, rest)| rest) {
            if let Some(cert) = self.wildcard.get(parent) {
                return Some(cert.clone());
            }
        }

        // 3. Return default if set
        self.default.clone()
    }

    /// Check if the store is empty.
    pub fn is_empty(&self) -> bool {
        self.exact.is_empty() && self.wildcard.is_empty() && self.default.is_none()
    }

    /// Get the number of certificates (exact + wildcard entries).
    pub fn len(&self) -> usize {
        self.exact.len() + self.wildcard.len()
    }
}

impl ResolvesServerCert for CertStore {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let sni = client_hello.server_name()?;
        CertStore::resolve(self, sni)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Helper to create a dummy CertifiedKey for testing
    fn dummy_cert() -> Arc<CertifiedKey> {
        use crate::pem::load_certified_key;
        use rcgen::{generate_simple_self_signed, CertifiedKey as RcgenKey};
        use std::io::Write;
        use tempfile::NamedTempFile;

        let subject_alt_names = vec!["test.example.com".to_string()];
        let RcgenKey { cert, key_pair } = generate_simple_self_signed(subject_alt_names).unwrap();

        let mut cert_file = NamedTempFile::new().unwrap();
        cert_file.write_all(cert.pem().as_bytes()).unwrap();

        let mut key_file = NamedTempFile::new().unwrap();
        key_file
            .write_all(key_pair.serialize_pem().as_bytes())
            .unwrap();

        load_certified_key(cert_file.path(), key_file.path()).unwrap()
    }

    #[test]
    fn test_exact_match() {
        let mut store = CertStore::new();
        let cert = dummy_cert();

        store.insert(&["api.example.com".to_string()], cert.clone());

        assert!(store.resolve("api.example.com").is_some());
        assert!(store.resolve("other.example.com").is_none());
    }

    #[test]
    fn test_wildcard_match() {
        let mut store = CertStore::new();
        let cert = dummy_cert();

        store.insert(&["*.example.com".to_string()], cert.clone());

        // Wildcard should match subdomains
        assert!(store.resolve("api.example.com").is_some());
        assert!(store.resolve("www.example.com").is_some());

        // But not the base domain itself
        assert!(store.resolve("example.com").is_none());

        // Or nested subdomains
        assert!(store.resolve("a.b.example.com").is_none());
    }

    #[test]
    fn test_exact_takes_priority() {
        let mut store = CertStore::new();
        let cert1 = dummy_cert();
        let cert2 = dummy_cert();

        store.insert(&["*.example.com".to_string()], cert1);
        store.insert(&["api.example.com".to_string()], cert2);

        // Exact match should be found
        assert!(store.resolve("api.example.com").is_some());
        // Wildcard should still work for others
        assert!(store.resolve("www.example.com").is_some());
    }

    #[test]
    fn test_default_fallback() {
        let mut store = CertStore::new();
        let cert = dummy_cert();

        store.set_default(cert);

        // Any domain should resolve to default
        assert!(store.resolve("anything.com").is_some());
    }

    #[test]
    fn test_case_insensitive() {
        let mut store = CertStore::new();
        let cert = dummy_cert();

        store.insert(&["API.Example.COM".to_string()], cert);

        assert!(store.resolve("api.example.com").is_some());
        assert!(store.resolve("API.EXAMPLE.COM").is_some());
    }

    #[test]
    fn test_no_match() {
        let store = CertStore::new();
        assert!(store.resolve("example.com").is_none());
    }
}
