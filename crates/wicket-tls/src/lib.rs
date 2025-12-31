//! # wicket-tls
//!
//! Automatic TLS certificate management for Wicket.
//!
//! ## Features
//!
//! - **ACME DNS-01**: Automatic certificates from Let's Encrypt via Cloudflare DNS
//! - **File Watcher**: Hot-reload certificates from disk (Kubernetes cert-manager)
//! - **Multi-cert SNI**: Different certificates for different domains
//! - **Hot Reload**: Zero-downtime certificate updates via [`arc_swap::ArcSwap`]
//!
//! ## Usage
//!
//! ### File Watcher Mode
//!
//! Load certificates from disk and watch for changes:
//!
//! ```ignore
//! use wicket_tls::{CertManager, FileWatcher};
//! use std::sync::Arc;
//!
//! let manager = Arc::new(CertManager::new());
//! let watcher = FileWatcher::new(file_config, manager.clone())?;
//! watcher.load_all()?;
//! watcher.start(); // Background task
//! ```
//!
//! ### ACME Mode
//!
//! Automatically obtain and renew certificates from Let's Encrypt:
//!
//! ```ignore
//! use wicket_tls::{CertManager, AcmeProvider};
//! use std::sync::Arc;
//!
//! let manager = Arc::new(CertManager::new());
//! let provider = Arc::new(AcmeProvider::new(acme_config, manager.clone())?);
//! provider.initialize().await?;
//! provider.clone().start_renewal_loop(); // Background task
//! ```
//!
//! ## Certificate Resolution
//!
//! The [`CertManager`] implements [`rustls::server::ResolvesServerCert`] for
//! integration with rustls/Pingora. Certificates are matched via SNI:
//!
//! 1. **Exact match** - `api.example.com` matches cert with that exact domain
//! 2. **Wildcard match** - `*.example.com` matches `api.example.com`, `www.example.com`
//! 3. **Default fallback** - If configured, used when no match found
//!
//! Wildcards only match one level (RFC 6125):
//! - `*.example.com` matches `foo.example.com`
//! - `*.example.com` does NOT match `foo.bar.example.com`
//!
//! ## Configuration
//!
//! See [`TlsConfig`] for the configuration structure. Supports three modes:
//!
//! - `"file"` - Load from disk with optional hot reload
//! - `"acme"` - Automatic ACME provisioning
//! - `"mixed"` - Both file and ACME sources
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────┐
//! │ CertManager                                     │
//! │                                                 │
//! │  ┌─────────────────────────────────────────┐   │
//! │  │ CertStore (ArcSwap)                     │   │
//! │  │                                         │   │
//! │  │  exact: HashMap<domain, CertifiedKey>  │   │
//! │  │  wildcard: HashMap<base, CertifiedKey> │   │
//! │  └─────────────────────────────────────────┘   │
//! │         ▲                    ▲                  │
//! │         │                    │                  │
//! │  ┌──────┴──────┐     ┌──────┴──────┐          │
//! │  │ FileWatcher │     │ AcmeProvider│          │
//! │  └─────────────┘     └─────────────┘          │
//! └─────────────────────────────────────────────────┘
//! ```
//!
//! The [`CertStore`] uses [`arc_swap::ArcSwap`] for lock-free updates,
//! enabling zero-downtime certificate reloads.

mod cert_manager;
mod cert_store;
mod config;
mod file_watcher;
pub mod metrics;
pub mod pem;

pub mod acme;

pub use acme::{AcmeError, AcmeProvider};
pub use cert_manager::CertManager;
pub use cert_store::CertStore;
pub use config::{AcmeConfig, AutoTlsDomain, FileCertConfig, TlsConfig, TlsMode};
pub use file_watcher::{FileWatcher, FileWatcherError};
pub use pem::{load_certified_key, load_certs, load_private_key, PemError};
