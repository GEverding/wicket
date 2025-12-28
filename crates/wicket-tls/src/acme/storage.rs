//! ACME account and certificate storage.
//!
//! Storage layout:
//! ```text
//! {base_path}/
//!   account.json       # ACME account credentials
//!   certs/
//!     {domain}/
//!       cert.pem       # Certificate chain
//!       key.pem        # Private key  
//!       meta.json      # Expiry, domains, etc.
//! ```

use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("certificate not found for domain: {0}")]
    CertNotFound(String),
}

/// Stored certificate with metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredCert {
    /// PEM-encoded certificate chain
    pub cert_pem: String,
    /// PEM-encoded private key
    pub key_pem: String,
    /// Certificate expiry time
    pub expiry: DateTime<Utc>,
    /// Domains covered by this cert
    pub domains: Vec<String>,
}

/// Certificate metadata (stored separately as JSON).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CertMeta {
    expiry: DateTime<Utc>,
    domains: Vec<String>,
    created_at: DateTime<Utc>,
}

/// ACME storage manager.
pub struct AcmeStorage {
    base_path: PathBuf,
}

impl AcmeStorage {
    /// Create a new storage manager.
    ///
    /// Creates the base directory if it doesn't exist.
    pub fn new(base_path: PathBuf) -> Result<Self, StorageError> {
        fs::create_dir_all(&base_path)?;
        fs::create_dir_all(base_path.join("certs"))?;
        Ok(Self { base_path })
    }

    /// Load ACME account credentials.
    pub fn load_account(&self) -> Result<Option<String>, StorageError> {
        let path = self.base_path.join("account.json");
        if !path.exists() {
            return Ok(None);
        }

        let creds = fs::read_to_string(&path)?;
        Ok(Some(creds))
    }

    /// Save ACME account credentials.
    pub fn save_account(&self, credentials_json: &str) -> Result<(), StorageError> {
        let path = self.base_path.join("account.json");
        self.atomic_write(&path, credentials_json.as_bytes(), 0o600)?;
        Ok(())
    }

    /// Load a stored certificate.
    pub fn load_cert(&self, primary_domain: &str) -> Result<Option<StoredCert>, StorageError> {
        let cert_dir = self.cert_path(primary_domain);

        let cert_path = cert_dir.join("cert.pem");
        let key_path = cert_dir.join("key.pem");
        let meta_path = cert_dir.join("meta.json");

        if !cert_path.exists() || !key_path.exists() || !meta_path.exists() {
            return Ok(None);
        }

        let cert_pem = fs::read_to_string(&cert_path)?;
        let key_pem = fs::read_to_string(&key_path)?;

        let meta_file = File::open(&meta_path)?;
        let meta: CertMeta = serde_json::from_reader(BufReader::new(meta_file))?;

        Ok(Some(StoredCert {
            cert_pem,
            key_pem,
            expiry: meta.expiry,
            domains: meta.domains,
        }))
    }

    /// Save a certificate.
    pub fn save_cert(&self, primary_domain: &str, cert: &StoredCert) -> Result<(), StorageError> {
        let cert_dir = self.cert_path(primary_domain);
        fs::create_dir_all(&cert_dir)?;

        // Write cert (readable)
        let cert_path = cert_dir.join("cert.pem");
        self.atomic_write(&cert_path, cert.cert_pem.as_bytes(), 0o644)?;

        // Write key (private)
        let key_path = cert_dir.join("key.pem");
        self.atomic_write(&key_path, cert.key_pem.as_bytes(), 0o600)?;

        // Write metadata
        let meta = CertMeta {
            expiry: cert.expiry,
            domains: cert.domains.clone(),
            created_at: Utc::now(),
        };
        let meta_path = cert_dir.join("meta.json");
        let meta_json = serde_json::to_string_pretty(&meta)?;
        self.atomic_write(&meta_path, meta_json.as_bytes(), 0o644)?;

        Ok(())
    }

    /// Check if a certificate needs renewal.
    ///
    /// Returns true if cert doesn't exist or expires within `days_before` days.
    pub fn needs_renewal(
        &self,
        primary_domain: &str,
        days_before: u32,
    ) -> Result<bool, StorageError> {
        match self.load_cert(primary_domain)? {
            None => Ok(true), // No cert, definitely needs one
            Some(cert) => {
                let renewal_threshold = Utc::now() + chrono::Duration::days(days_before as i64);
                Ok(cert.expiry < renewal_threshold)
            }
        }
    }

    /// Get the path for a domain's certificates.
    fn cert_path(&self, domain: &str) -> PathBuf {
        // Sanitize domain name for filesystem
        let safe_domain = domain.replace(['/', '\\', '\0'], "_");
        self.base_path.join("certs").join(safe_domain)
    }

    /// Atomic write: write to temp file, then rename.
    fn atomic_write(&self, path: &Path, data: &[u8], mode: u32) -> Result<(), StorageError> {
        let parent = path.parent().unwrap_or(Path::new("."));
        let temp_path = parent.join(format!(
            ".{}.tmp",
            path.file_name().unwrap().to_string_lossy()
        ));

        {
            let file = File::create(&temp_path)?;
            // Set permissions before writing sensitive data
            file.set_permissions(fs::Permissions::from_mode(mode))?;
            let mut writer = BufWriter::new(file);
            writer.write_all(data)?;
            writer.flush()?;
        }

        fs::rename(&temp_path, path)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_save_and_load_account() {
        let temp = TempDir::new().unwrap();
        let storage = AcmeStorage::new(temp.path().to_path_buf()).unwrap();

        let creds = r#"{"key": "value"}"#;
        storage.save_account(creds).unwrap();

        let loaded = storage.load_account().unwrap();
        assert_eq!(loaded, Some(creds.to_string()));
    }

    #[test]
    fn test_load_missing_account() {
        let temp = TempDir::new().unwrap();
        let storage = AcmeStorage::new(temp.path().to_path_buf()).unwrap();

        let loaded = storage.load_account().unwrap();
        assert!(loaded.is_none());
    }

    #[test]
    fn test_save_and_load_cert() {
        let temp = TempDir::new().unwrap();
        let storage = AcmeStorage::new(temp.path().to_path_buf()).unwrap();

        let cert = StoredCert {
            cert_pem: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----".to_string(),
            key_pem: "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----".to_string(),
            expiry: Utc::now() + chrono::Duration::days(90),
            domains: vec!["example.com".to_string()],
        };

        storage.save_cert("example.com", &cert).unwrap();

        let loaded = storage.load_cert("example.com").unwrap().unwrap();
        assert_eq!(loaded.cert_pem, cert.cert_pem);
        assert_eq!(loaded.key_pem, cert.key_pem);
        assert_eq!(loaded.domains, cert.domains);
    }

    #[test]
    fn test_needs_renewal_no_cert() {
        let temp = TempDir::new().unwrap();
        let storage = AcmeStorage::new(temp.path().to_path_buf()).unwrap();

        assert!(storage.needs_renewal("missing.com", 30).unwrap());
    }

    #[test]
    fn test_needs_renewal_fresh_cert() {
        let temp = TempDir::new().unwrap();
        let storage = AcmeStorage::new(temp.path().to_path_buf()).unwrap();

        let cert = StoredCert {
            cert_pem: "cert".to_string(),
            key_pem: "key".to_string(),
            expiry: Utc::now() + chrono::Duration::days(60),
            domains: vec!["fresh.com".to_string()],
        };
        storage.save_cert("fresh.com", &cert).unwrap();

        // 30 days threshold, 60 days until expiry -> no renewal needed
        assert!(!storage.needs_renewal("fresh.com", 30).unwrap());
    }

    #[test]
    fn test_needs_renewal_expiring_cert() {
        let temp = TempDir::new().unwrap();
        let storage = AcmeStorage::new(temp.path().to_path_buf()).unwrap();

        let cert = StoredCert {
            cert_pem: "cert".to_string(),
            key_pem: "key".to_string(),
            expiry: Utc::now() + chrono::Duration::days(15),
            domains: vec!["expiring.com".to_string()],
        };
        storage.save_cert("expiring.com", &cert).unwrap();

        // 30 days threshold, 15 days until expiry -> renewal needed
        assert!(storage.needs_renewal("expiring.com", 30).unwrap());
    }

    #[test]
    fn test_key_file_permissions() {
        let temp = TempDir::new().unwrap();
        let storage = AcmeStorage::new(temp.path().to_path_buf()).unwrap();

        let cert = StoredCert {
            cert_pem: "cert".to_string(),
            key_pem: "key".to_string(),
            expiry: Utc::now() + chrono::Duration::days(90),
            domains: vec!["test.com".to_string()],
        };
        storage.save_cert("test.com", &cert).unwrap();

        let key_path = temp.path().join("certs/test.com/key.pem");
        let perms = fs::metadata(&key_path).unwrap().permissions();
        assert_eq!(perms.mode() & 0o777, 0o600);
    }
}
