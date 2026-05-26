//! File-based certificate watcher for Kubernetes cert-manager integration.
//!
//! Watches certificate files and automatically reloads them when changed.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use notify::{Config, Event, RecommendedWatcher, RecursiveMode, Watcher};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{debug, error, info, warn};

use crate::config::FileConfig;
use crate::metrics;
use crate::metrics::CertReloadStatus;
use crate::pem::{extract_cert_expiry, load_certified_key};
use crate::{CertManager, CertStore};

/// File-based certificate watcher.
///
/// Watches certificate files and reloads them into the CertManager
/// when changes are detected.
pub struct FileWatcher {
    config: FileConfig,
    manager: Arc<CertManager>,
}

impl FileWatcher {
    /// Create a new file watcher.
    pub fn new(config: FileConfig, manager: Arc<CertManager>) -> Self {
        Self { config, manager }
    }

    /// Load all certificates from config into the manager.
    ///
    /// Call this on startup before starting the watcher.
    pub fn load_all(&self) -> Result<(), FileWatcherError> {
        let store = self.build_store()?;
        self.manager.reload(store);
        Ok(())
    }

    /// Build a CertStore from all configured certificates.
    fn build_store(&self) -> Result<CertStore, FileWatcherError> {
        let mut store = CertStore::new();

        for cert_config in &self.config.certs {
            match load_certified_key(&cert_config.cert, &cert_config.key) {
                Ok(key) => {
                    info!(
                        name = %cert_config.name,
                        domains = ?cert_config.domains,
                        "loaded certificate"
                    );

                    // Extract and emit certificate expiry metric
                    if let Ok(cert_der) = key.end_entity_cert() {
                        if let Some(expiry_timestamp) = extract_cert_expiry(cert_der) {
                            // Emit metric for each domain
                            for domain in &cert_config.domains {
                                metrics::set_cert_expiry(domain, expiry_timestamp);
                            }
                            debug!(
                                name = %cert_config.name,
                                expiry_timestamp = expiry_timestamp,
                                "emitted certificate expiry metric"
                            );
                        } else {
                            warn!(
                                name = %cert_config.name,
                                "failed to extract certificate expiry timestamp"
                            );
                        }
                    }

                    store.insert(&cert_config.domains, key);
                }
                Err(e) => {
                    error!(
                        name = %cert_config.name,
                        cert = %cert_config.cert.display(),
                        key = %cert_config.key.display(),
                        error = %e,
                        "failed to load certificate"
                    );
                    // Continue loading other certs
                }
            }
        }

        if store.is_empty() {
            return Err(FileWatcherError::NoCertificatesLoaded);
        }

        Ok(store)
    }

    /// Start the file watcher in a background task.
    ///
    /// Returns a handle to the spawned task.
    pub fn start(self) -> JoinHandle<()> {
        tokio::spawn(async move {
            if let Err(e) = self.watch_loop().await {
                error!(error = %e, "file watcher stopped with error");
            }
        })
    }

    async fn watch_loop(&self) -> Result<(), FileWatcherError> {
        let (tx, mut rx) = mpsc::channel::<notify::Result<Event>>(100);

        // Create watcher
        let mut watcher = RecommendedWatcher::new(
            move |res| {
                let _ = tx.blocking_send(res);
            },
            Config::default(),
        )
        .map_err(FileWatcherError::Notify)?;

        // Collect unique directories to watch
        let mut dirs: HashMap<PathBuf, ()> = HashMap::new();
        for cert_config in &self.config.certs {
            if let Some(parent) = cert_config.cert.parent() {
                dirs.insert(parent.to_path_buf(), ());
            }
            if let Some(parent) = cert_config.key.parent() {
                dirs.insert(parent.to_path_buf(), ());
            }
        }

        // Watch all directories
        for dir in dirs.keys() {
            debug!(dir = %dir.display(), "watching directory");
            watcher
                .watch(dir, RecursiveMode::NonRecursive)
                .map_err(FileWatcherError::Notify)?;
        }

        info!(
            certs = self.config.certs.len(),
            dirs = dirs.len(),
            "file watcher started"
        );

        // Debounce timer
        let debounce_duration = Duration::from_millis(500);
        let mut debounce_deadline: Option<tokio::time::Instant> = None;

        loop {
            tokio::select! {
                Some(event) = rx.recv() => {
                    match event {
                        Ok(event) => {
                            if self.is_relevant_event(&event) {
                                debug!(paths = ?event.paths, "file change detected");
                                // Set/reset debounce timer
                                debounce_deadline = Some(
                                    tokio::time::Instant::now() + debounce_duration
                                );
                            }
                        }
                        Err(e) => {
                            warn!(error = %e, "file watcher error");
                        }
                    }
                }
                _ = async {
                    if let Some(deadline) = debounce_deadline {
                        tokio::time::sleep_until(deadline).await;
                    } else {
                        // No deadline, sleep forever
                        std::future::pending::<()>().await;
                    }
                } => {
                    debounce_deadline = None;
                    self.reload_certs();
                }
            }
        }
    }

    /// Check if a file event is relevant to our certificates.
    fn is_relevant_event(&self, event: &Event) -> bool {
        // Check if any event path matches our cert/key files
        for path in &event.paths {
            for cert_config in &self.config.certs {
                if path == &cert_config.cert || path == &cert_config.key {
                    return true;
                }
            }
        }
        false
    }

    /// Reload all certificates.
    fn reload_certs(&self) {
        info!("reloading certificates");

        match self.build_store() {
            Ok(store) => {
                self.manager.reload(store);
                metrics::inc_cert_reload(CertReloadStatus::Success);
                info!("certificates reloaded successfully");
            }
            Err(e) => {
                metrics::inc_cert_reload(CertReloadStatus::Failure);
                error!(error = %e, "failed to reload certificates, keeping old");
            }
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum FileWatcherError {
    #[error("notify error: {0}")]
    Notify(#[from] notify::Error),

    #[error("no certificates loaded")]
    NoCertificatesLoaded,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::FileCertConfig;
    use rcgen::{generate_simple_self_signed, CertifiedKey as RcgenKey};
    use tempfile::TempDir;

    fn create_test_cert(dir: &std::path::Path, name: &str) -> (PathBuf, PathBuf) {
        let subject_alt_names = vec![format!("{}.example.com", name)];
        let RcgenKey { cert, key_pair } = generate_simple_self_signed(subject_alt_names).unwrap();

        let cert_path = dir.join(format!("{}.crt", name));
        let key_path = dir.join(format!("{}.key", name));

        std::fs::write(&cert_path, cert.pem()).unwrap();
        std::fs::write(&key_path, key_pair.serialize_pem()).unwrap();

        (cert_path, key_path)
    }

    #[test]
    fn test_load_all() {
        let temp = TempDir::new().unwrap();
        let (cert_path, key_path) = create_test_cert(temp.path(), "test");

        let config = FileConfig {
            watch: true,
            poll_interval_secs: 30,
            certs: vec![FileCertConfig {
                name: "test".to_string(),
                cert: cert_path,
                key: key_path,
                domains: vec!["test.example.com".to_string()],
            }],
        };

        let manager = Arc::new(CertManager::new());
        let watcher = FileWatcher::new(config, manager.clone());

        watcher.load_all().unwrap();

        assert!(manager.resolve("test.example.com").is_some());
    }

    #[test]
    fn test_missing_cert_continues() {
        let temp = TempDir::new().unwrap();
        let (cert_path, key_path) = create_test_cert(temp.path(), "valid");

        let config = FileConfig {
            watch: true,
            poll_interval_secs: 30,
            certs: vec![
                FileCertConfig {
                    name: "missing".to_string(),
                    cert: PathBuf::from("/nonexistent/cert.pem"),
                    key: PathBuf::from("/nonexistent/key.pem"),
                    domains: vec!["missing.example.com".to_string()],
                },
                FileCertConfig {
                    name: "valid".to_string(),
                    cert: cert_path,
                    key: key_path,
                    domains: vec!["valid.example.com".to_string()],
                },
            ],
        };

        let manager = Arc::new(CertManager::new());
        let watcher = FileWatcher::new(config, manager.clone());

        watcher.load_all().unwrap();

        // Missing cert should fail, but valid cert should load
        assert!(manager.resolve("missing.example.com").is_none());
        assert!(manager.resolve("valid.example.com").is_some());
    }

    #[tokio::test]
    async fn test_reload_on_file_change() {
        let temp = TempDir::new().unwrap();
        let (cert_path, key_path) = create_test_cert(temp.path(), "v1");

        let config = FileConfig {
            watch: true,
            poll_interval_secs: 30,
            certs: vec![FileCertConfig {
                name: "test".to_string(),
                cert: cert_path.clone(),
                key: key_path.clone(),
                domains: vec!["test.example.com".to_string()],
            }],
        };

        let manager = Arc::new(CertManager::new());
        let watcher = FileWatcher::new(config, manager.clone());

        watcher.load_all().unwrap();
        assert!(manager.resolve("test.example.com").is_some());

        // Start the watcher
        let _handle = watcher.start();

        // Overwrite cert file with new cert (same domain in config, different cert content)
        let (new_cert_path, new_key_path) = create_test_cert(temp.path(), "v2");
        std::fs::copy(&new_cert_path, &cert_path).unwrap();
        std::fs::copy(&new_key_path, &key_path).unwrap();

        // Wait for debounce (500ms) + margin
        tokio::time::sleep(Duration::from_millis(700)).await;

        // Verify cert still resolves after reload
        assert!(manager.resolve("test.example.com").is_some());
    }

    #[tokio::test]
    async fn test_debounce_multiple_changes() {
        let temp = TempDir::new().unwrap();
        let (cert_path, key_path) = create_test_cert(temp.path(), "test");

        let config = FileConfig {
            watch: true,
            poll_interval_secs: 30,
            certs: vec![FileCertConfig {
                name: "test".to_string(),
                cert: cert_path.clone(),
                key: key_path.clone(),
                domains: vec!["test.example.com".to_string()],
            }],
        };

        let manager = Arc::new(CertManager::new());
        let watcher = FileWatcher::new(config, manager.clone());

        watcher.load_all().unwrap();
        assert!(manager.resolve("test.example.com").is_some());

        // Start the watcher
        let _handle = watcher.start();

        // Make multiple rapid changes (10ms apart)
        for i in 0..5 {
            let (new_cert_path, new_key_path) =
                create_test_cert(temp.path(), &format!("rapid{}", i));
            std::fs::copy(&new_cert_path, &cert_path).unwrap();
            std::fs::copy(&new_key_path, &key_path).unwrap();
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        // Wait for debounce (500ms) + margin
        tokio::time::sleep(Duration::from_millis(700)).await;

        // Verify cert still resolves (watcher didn't crash)
        assert!(manager.resolve("test.example.com").is_some());
    }

    #[tokio::test]
    async fn test_wildcard_after_reload() {
        let temp = TempDir::new().unwrap();

        // Create cert with wildcard domain
        let subject_alt_names = vec!["*.example.com".to_string()];
        let RcgenKey { cert, key_pair } = generate_simple_self_signed(subject_alt_names).unwrap();

        let cert_path = temp.path().join("wildcard.crt");
        let key_path = temp.path().join("wildcard.key");

        std::fs::write(&cert_path, cert.pem()).unwrap();
        std::fs::write(&key_path, key_pair.serialize_pem()).unwrap();

        let config = FileConfig {
            watch: true,
            poll_interval_secs: 30,
            certs: vec![FileCertConfig {
                name: "wildcard".to_string(),
                cert: cert_path.clone(),
                key: key_path.clone(),
                domains: vec!["*.example.com".to_string()],
            }],
        };

        let manager = Arc::new(CertManager::new());
        let watcher = FileWatcher::new(config, manager.clone());

        watcher.load_all().unwrap();

        // Verify wildcard resolves for subdomain
        assert!(manager.resolve("api.example.com").is_some());

        // Start the watcher
        let _handle = watcher.start();

        // Modify cert file
        let (new_cert_path, new_key_path) = create_test_cert(temp.path(), "modified");
        std::fs::copy(&new_cert_path, &cert_path).unwrap();
        std::fs::copy(&new_key_path, &key_path).unwrap();

        // Wait for reload
        tokio::time::sleep(Duration::from_millis(700)).await;

        // Verify wildcard still resolves after reload
        assert!(manager.resolve("api.example.com").is_some());
    }
}
