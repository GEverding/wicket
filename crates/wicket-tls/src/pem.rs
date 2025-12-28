//! PEM file loading utilities.

use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::sign::CertifiedKey;
use rustls_pemfile::{certs, private_key};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PemError {
    #[error("failed to read file {path}: {source}")]
    ReadFile {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("no certificates found in {0}")]
    NoCertificates(String),

    #[error("no private key found in {0}")]
    NoPrivateKey(String),

    #[error("failed to parse private key: {0}")]
    ParseKey(String),

    #[error("unsupported key type")]
    UnsupportedKeyType,
}

/// Load certificate chain from a PEM file.
pub fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, PemError> {
    let file = File::open(path).map_err(|e| PemError::ReadFile {
        path: path.display().to_string(),
        source: e,
    })?;
    let mut reader = BufReader::new(file);

    let certs: Vec<_> = certs(&mut reader).filter_map(|r| r.ok()).collect();

    if certs.is_empty() {
        return Err(PemError::NoCertificates(path.display().to_string()));
    }

    Ok(certs)
}

/// Load private key from a PEM file.
/// Supports RSA, ECDSA, and Ed25519 keys.
pub fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>, PemError> {
    let file = File::open(path).map_err(|e| PemError::ReadFile {
        path: path.display().to_string(),
        source: e,
    })?;
    let mut reader = BufReader::new(file);

    private_key(&mut reader)
        .map_err(|e| PemError::ParseKey(e.to_string()))?
        .ok_or_else(|| PemError::NoPrivateKey(path.display().to_string()))
}

/// Load a certified key (cert chain + private key) from PEM files.
pub fn load_certified_key(
    cert_path: &Path,
    key_path: &Path,
) -> Result<Arc<CertifiedKey>, PemError> {
    let certs = load_certs(cert_path)?;
    let key = load_private_key(key_path)?;

    let signing_key = rustls::crypto::aws_lc_rs::sign::any_supported_type(&key)
        .map_err(|_| PemError::UnsupportedKeyType)?;

    Ok(Arc::new(CertifiedKey::new(certs, signing_key)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn generate_test_cert_and_key() -> (String, String) {
        use base64::Engine;
        use rcgen::generate_simple_self_signed;

        let subject_alt_names = vec!["localhost".to_string(), "127.0.0.1".to_string()];
        let cert = generate_simple_self_signed(subject_alt_names).unwrap();

        // Serialize to DER and convert to PEM manually
        let cert_der = cert.cert.der();
        let cert_b64 = base64::engine::general_purpose::STANDARD.encode(cert_der);
        let mut cert_pem = String::from("-----BEGIN CERTIFICATE-----\n");
        for chunk in cert_b64.as_bytes().chunks(64) {
            cert_pem.push_str(&String::from_utf8_lossy(chunk));
            cert_pem.push('\n');
        }
        cert_pem.push_str("-----END CERTIFICATE-----\n");

        let key_pem = cert.key_pair.serialize_pem();

        (cert_pem, key_pem)
    }

    #[test]
    fn test_load_missing_cert_file() {
        let result = load_certs(Path::new("/nonexistent/cert.pem"));
        assert!(matches!(result, Err(PemError::ReadFile { .. })));
    }

    #[test]
    fn test_load_missing_key_file() {
        let result = load_private_key(Path::new("/nonexistent/key.pem"));
        assert!(matches!(result, Err(PemError::ReadFile { .. })));
    }

    #[test]
    fn test_load_empty_cert_file() {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(b"").unwrap();
        file.flush().unwrap();

        let result = load_certs(file.path());
        assert!(matches!(result, Err(PemError::NoCertificates(_))));
    }

    #[test]
    fn test_load_empty_key_file() {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(b"").unwrap();
        file.flush().unwrap();

        let result = load_private_key(file.path());
        assert!(matches!(result, Err(PemError::NoPrivateKey(_))));
    }

    #[test]
    fn test_load_valid_cert() {
        let (cert_pem, _) = generate_test_cert_and_key();
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(cert_pem.as_bytes()).unwrap();
        file.flush().unwrap();

        let result = load_certs(file.path());
        assert!(result.is_ok());
        let certs = result.unwrap();
        assert!(!certs.is_empty());
    }

    #[test]
    fn test_load_valid_key() {
        let (_, key_pem) = generate_test_cert_and_key();
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(key_pem.as_bytes()).unwrap();
        file.flush().unwrap();

        let result = load_private_key(file.path());
        assert!(result.is_ok());
    }

    #[test]
    fn test_load_certified_key() {
        let (cert_pem, key_pem) = generate_test_cert_and_key();

        let mut cert_file = NamedTempFile::new().unwrap();
        cert_file.write_all(cert_pem.as_bytes()).unwrap();
        cert_file.flush().unwrap();

        let mut key_file = NamedTempFile::new().unwrap();
        key_file.write_all(key_pem.as_bytes()).unwrap();
        key_file.flush().unwrap();

        let result = load_certified_key(cert_file.path(), key_file.path());
        assert!(result.is_ok());
    }
}
