//! Hot-reloadable certificate manager.
//!
//! The CertManager wraps a CertStore in ArcSwap for lock-free atomic updates.
//! This allows certificates to be reloaded without any request downtime.

use std::sync::Arc;

use arc_swap::ArcSwap;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;

use crate::metrics;
use crate::metrics::CertResolutionOutcome;
use crate::CertStore;

/// Hot-reloadable certificate manager.
///
/// Uses ArcSwap for lock-free atomic updates, allowing certificate
/// reloads without blocking TLS handshakes in progress.
///
/// # Example
///
/// ```ignore
/// let manager = CertManager::new();
///
/// // Load certificates
/// let mut store = CertStore::new();
/// store.insert(&["example.com".to_string()], cert);
/// manager.reload(store);
///
/// // Use with rustls ServerConfig
/// let config = ServerConfig::builder()
///     .with_no_client_auth()
///     .with_cert_resolver(Arc::new(manager));
/// ```
#[derive(Debug)]
pub struct CertManager {
    store: ArcSwap<CertStore>,
}

impl CertManager {
    /// Create a new certificate manager with an empty store.
    pub fn new() -> Self {
        Self {
            store: ArcSwap::from_pointee(CertStore::new()),
        }
    }

    /// Create a new certificate manager with an initial store.
    pub fn with_store(store: CertStore) -> Self {
        Self {
            store: ArcSwap::from_pointee(store),
        }
    }

    /// Atomically replace the certificate store.
    ///
    /// This is lock-free and will not block any in-progress TLS handshakes.
    /// Existing connections continue using the old certificates until they
    /// complete their handshake.
    pub fn reload(&self, store: CertStore) {
        self.store.store(Arc::new(store));
        tracing::info!("certificate store reloaded");
    }

    /// Get a reference to the current certificate store.
    pub fn store(&self) -> arc_swap::Guard<Arc<CertStore>> {
        self.store.load()
    }

    /// Resolve a certificate for the given SNI hostname.
    pub fn resolve(&self, sni: &str) -> Option<Arc<CertifiedKey>> {
        self.store.load().resolve(sni)
    }

    /// Check if the certificate store is empty.
    pub fn is_empty(&self) -> bool {
        self.store.load().is_empty()
    }
}

impl Default for CertManager {
    fn default() -> Self {
        Self::new()
    }
}

impl ResolvesServerCert for CertManager {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let Some(sni) = client_hello.server_name() else {
            metrics::inc_cert_resolution(CertResolutionOutcome::NoSni);
            return None;
        };

        let (cert, outcome) = self.store.load().resolve_with_outcome(sni);
        metrics::inc_cert_resolution(outcome);
        cert
    }
}

// CertManager needs to be Send + Sync for use across threads
// ArcSwap<T> is Send + Sync when T is Send + Sync
// CertStore is Send + Sync (contains HashMap with Arc values)

#[cfg(test)]
mod tests {
    use super::*;

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
    fn test_new_is_empty() {
        let manager = CertManager::new();
        assert!(manager.is_empty());
    }

    #[test]
    fn test_with_store() {
        let mut store = CertStore::new();
        store.insert(&["example.com".to_string()], dummy_cert());

        let manager = CertManager::with_store(store);
        assert!(!manager.is_empty());
        assert!(manager.resolve("example.com").is_some());
    }

    #[test]
    fn test_reload() {
        let manager = CertManager::new();
        assert!(manager.resolve("example.com").is_none());

        // Reload with new store
        let mut store = CertStore::new();
        store.insert(&["example.com".to_string()], dummy_cert());
        manager.reload(store);

        assert!(manager.resolve("example.com").is_some());
    }

    #[test]
    fn test_reload_replaces() {
        let manager = CertManager::new();

        // Add first cert
        let mut store1 = CertStore::new();
        store1.insert(&["first.com".to_string()], dummy_cert());
        manager.reload(store1);

        assert!(manager.resolve("first.com").is_some());
        assert!(manager.resolve("second.com").is_none());

        // Replace with second cert (first should be gone)
        let mut store2 = CertStore::new();
        store2.insert(&["second.com".to_string()], dummy_cert());
        manager.reload(store2);

        assert!(manager.resolve("first.com").is_none());
        assert!(manager.resolve("second.com").is_some());
    }

    #[test]
    fn test_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<CertManager>();
    }
}
