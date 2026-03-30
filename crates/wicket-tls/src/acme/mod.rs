//! ACME certificate provider for automatic TLS certificate management.
//!
//! Uses instant-acme to obtain certificates from Let's Encrypt via DNS-01 challenges.

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use instant_acme::{
    Account, AuthorizationStatus, ChallengeType, Identifier, LetsEncrypt, NewAccount, NewOrder,
    OrderStatus,
};
use tokio::task::JoinHandle;
use tracing::{debug, error, info, warn};

use crate::config::{AcmeCertConfig, AcmeConfig, AutoTlsDomain};
use crate::metrics::{tls_metrics, AcmeRenewalStatus};
use crate::pem::load_certified_key;
use crate::{CertManager, CertStore};

pub mod cloudflare;
pub mod storage;

pub use cloudflare::{CloudflareClient, CloudflareError};
pub use storage::{AcmeStorage, StorageError, StoredCert};

/// ACME certificate provider.
///
/// Manages automatic certificate acquisition and renewal via Let's Encrypt.
pub struct AcmeProvider {
    config: AcmeConfig,
    storage: AcmeStorage,
    manager: Arc<CertManager>,
    /// Additional domains from routes with `tls = "auto"`, with optional provider overrides
    auto_tls_domains: Vec<AutoTlsDomain>,
}

/// Builder for AcmeProvider.
pub struct AcmeProviderBuilder {
    config: AcmeConfig,
    manager: Arc<CertManager>,
    auto_tls_domains: Vec<AutoTlsDomain>,
}

impl AcmeProviderBuilder {
    /// Set auto-TLS domains from routes.
    pub fn auto_tls_domains(mut self, domains: Vec<AutoTlsDomain>) -> Self {
        self.auto_tls_domains = domains;
        self
    }

    /// Build the AcmeProvider.
    pub fn build(self) -> Result<AcmeProvider, AcmeError> {
        let storage = AcmeStorage::new(self.config.storage.clone())?;

        Ok(AcmeProvider {
            config: self.config,
            storage,
            manager: self.manager,
            auto_tls_domains: self.auto_tls_domains,
        })
    }
}

impl AcmeProvider {
    /// Create a builder for AcmeProvider.
    pub fn builder(config: AcmeConfig, manager: Arc<CertManager>) -> AcmeProviderBuilder {
        AcmeProviderBuilder {
            config,
            manager,
            auto_tls_domains: Vec::new(),
        }
    }

    /// Create a new ACME provider (convenience method).
    pub fn new(config: AcmeConfig, manager: Arc<CertManager>) -> Result<Self, AcmeError> {
        Self::builder(config, manager).build()
    }

    /// Get all cert configs including auto-TLS domains.
    fn all_certs(&self) -> Vec<AcmeCertConfig> {
        self.config.all_certs_with_providers(&self.auto_tls_domains)
    }

    /// Initialize certificates - load existing or obtain new ones.
    ///
    /// Call this on startup before starting the renewal loop.
    pub async fn initialize(&self) -> Result<(), AcmeError> {
        info!("initializing ACME certificates");

        let mut store = CertStore::new();
        let all_certs = self.all_certs();

        if all_certs.is_empty() {
            info!("no ACME certificates configured");
            return Ok(());
        }

        for cert_config in &all_certs {
            let primary_domain = cert_config
                .domains
                .first()
                .ok_or_else(|| AcmeError::Config("cert config has no domains".into()))?;

            // Check if we have a valid cert
            if !self
                .storage
                .needs_renewal(primary_domain, self.config.renew_before_days)?
            {
                // Load existing cert
                if let Some(stored) = self.storage.load_cert(primary_domain)? {
                    info!(
                        domain = %primary_domain,
                        expiry = %stored.expiry,
                        "loaded existing certificate"
                    );

                    let key = self.load_stored_cert(&stored)?;
                    store.insert(&cert_config.domains, key);
                    continue;
                }
            }

            // Need to obtain new cert
            info!(domain = %primary_domain, "obtaining new certificate");

            match self.obtain_cert(cert_config).await {
                Ok(stored) => {
                    let key = self.load_stored_cert(&stored)?;
                    store.insert(&cert_config.domains, key);
                }
                Err(e) => {
                    error!(domain = %primary_domain, error = %e, "failed to obtain certificate");
                    // Try to use existing cert if available
                    if let Ok(Some(stored)) = self.storage.load_cert(primary_domain) {
                        warn!(domain = %primary_domain, "using expired certificate as fallback");
                        let key = self.load_stored_cert(&stored)?;
                        store.insert(&cert_config.domains, key);
                    }
                }
            }
        }

        if store.is_empty() {
            return Err(AcmeError::NoCertificates);
        }

        self.manager.reload(store);
        info!("ACME initialization complete");

        Ok(())
    }

    /// Start the background renewal loop.
    ///
    /// Checks certificates daily and renews those expiring soon.
    pub fn start_renewal_loop(self: Arc<Self>) -> JoinHandle<()> {
        tokio::spawn(async move {
            let check_interval = Duration::from_secs(24 * 60 * 60); // Daily

            loop {
                tokio::time::sleep(check_interval).await;

                info!("checking certificates for renewal");

                if let Err(e) = self.check_and_renew().await {
                    error!(error = %e, "renewal check failed");
                }
            }
        })
    }

    /// Check all certificates and renew those expiring soon.
    async fn check_and_renew(&self) -> Result<(), AcmeError> {
        let mut store = CertStore::new();
        let mut any_renewed = false;
        let all_certs = self.all_certs();

        for cert_config in &all_certs {
            let primary_domain = cert_config
                .domains
                .first()
                .ok_or_else(|| AcmeError::Config("cert config has no domains".into()))?;

            if self
                .storage
                .needs_renewal(primary_domain, self.config.renew_before_days)?
            {
                info!(domain = %primary_domain, "certificate needs renewal");

                match self.obtain_cert(cert_config).await {
                    Ok(stored) => {
                        let key = self.load_stored_cert(&stored)?;
                        store.insert(&cert_config.domains, key);
                        tls_metrics::wicket_acme_renewal_total(AcmeRenewalStatus::Success).inc();
                        any_renewed = true;
                    }
                    Err(e) => {
                        tls_metrics::wicket_acme_renewal_total(AcmeRenewalStatus::Failure).inc();
                        error!(domain = %primary_domain, error = %e, "renewal failed");
                        // Keep using existing cert
                        if let Ok(Some(stored)) = self.storage.load_cert(primary_domain) {
                            let key = self.load_stored_cert(&stored)?;
                            store.insert(&cert_config.domains, key);
                        }
                    }
                }
            } else {
                // Load existing cert
                if let Some(stored) = self.storage.load_cert(primary_domain)? {
                    tls_metrics::wicket_acme_renewal_total(AcmeRenewalStatus::Skipped).inc();
                    let key = self.load_stored_cert(&stored)?;
                    store.insert(&cert_config.domains, key);
                }
            }
        }

        if any_renewed && !store.is_empty() {
            self.manager.reload(store);
        }

        Ok(())
    }

    /// Obtain a certificate for the given domains.
    async fn obtain_cert(&self, cert_config: &AcmeCertConfig) -> Result<StoredCert, AcmeError> {
        let primary_domain = cert_config
            .domains
            .first()
            .ok_or_else(|| AcmeError::Config("no domains specified".into()))?;

        // Get or create ACME account
        let account = self.get_or_create_account().await?;

        // Create DNS client for challenges using resolved token (supports file-based secrets)
        let api_token = cert_config
            .dns
            .resolve_api_token()
            .map_err(AcmeError::Config)?;
        let dns_client = CloudflareClient::new(api_token)?;

        // Get zone ID
        let zone_id = match &cert_config.dns.zone_id {
            Some(id) => id.clone(),
            None => dns_client.get_zone_id(primary_domain).await?,
        };

        // Create order
        let identifiers: Vec<_> = cert_config
            .domains
            .iter()
            .map(|d| Identifier::Dns(d.clone()))
            .collect();

        let mut order = account
            .new_order(&NewOrder {
                identifiers: &identifiers,
            })
            .await?;

        debug!(domains = ?cert_config.domains, "created ACME order");

        // Process authorizations
        let mut record_ids: Vec<(String, String)> = Vec::new();

        // Handle challenges
        let result = async {
            let authorizations = order.authorizations().await?;

            for authz in authorizations {
                if matches!(authz.status, AuthorizationStatus::Valid) {
                    continue;
                }

                let challenge = authz
                    .challenges
                    .iter()
                    .find(|c| matches!(c.r#type, ChallengeType::Dns01))
                    .ok_or_else(|| AcmeError::NoChallenge)?;

                let domain_str = match &authz.identifier {
                    Identifier::Dns(d) => d.clone(),
                };
                let txt_name = format!("_acme-challenge.{}", domain_str);
                let txt_value = order.key_authorization(challenge).dns_value();

                debug!(domain = %domain_str, "setting DNS challenge");

                // Create DNS record
                let record_id = dns_client
                    .create_txt_record(&zone_id, &txt_name, &txt_value)
                    .await?;
                record_ids.push((txt_name.clone(), record_id));

                // Wait for DNS propagation
                tokio::time::sleep(Duration::from_secs(10)).await;

                // Validate challenge
                order.set_challenge_ready(&challenge.url).await?;
            }

            Ok::<_, AcmeError>(())
        }
        .await;

        if let Err(e) = result {
            cleanup_dns_records(&dns_client, &zone_id, &record_ids).await;
            return Err(e);
        }

        // Wait for order to be ready
        loop {
            order.refresh().await?;
            if matches!(order.state().status, OrderStatus::Ready) {
                break;
            }
            if matches!(order.state().status, OrderStatus::Invalid) {
                cleanup_dns_records(&dns_client, &zone_id, &record_ids).await;
                return Err(AcmeError::OrderFailed(format!(
                    "{:?}",
                    order.state().status
                )));
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }

        // Generate CSR
        let (private_key_pem, csr_der) = generate_csr(&cert_config.domains)?;

        // Finalize order
        order.finalize(&csr_der).await?;

        // Poll for certificate
        let cert_pem = loop {
            if let Some(cert) = order.certificate().await? {
                break cert;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        };

        // Cleanup DNS records
        cleanup_dns_records(&dns_client, &zone_id, &record_ids).await;

        // Parse expiry from the actual certificate
        let expiry = parse_certificate_expiry(&cert_pem).unwrap_or_else(|| {
            warn!("Failed to parse certificate expiry, using 90 days from now");
            Utc::now() + chrono::Duration::days(90)
        });

        let stored = StoredCert {
            cert_pem,
            key_pem: private_key_pem,
            expiry,
            domains: cert_config.domains.clone(),
        };

        // Save to storage
        self.storage.save_cert(primary_domain, &stored)?;

        info!(domain = %primary_domain, expiry = %expiry, "certificate obtained successfully");

        Ok(stored)
    }

    /// Get or create ACME account.
    async fn get_or_create_account(&self) -> Result<Account, AcmeError> {
        let server_url = if self.config.staging {
            LetsEncrypt::Staging.url()
        } else {
            LetsEncrypt::Production.url()
        };

        // Try to load existing account
        if let Some(creds_json) = self.storage.load_account()? {
            let creds = serde_json::from_str(&creds_json)?;
            let account = Account::from_credentials(creds).await?;
            debug!("loaded existing ACME account");
            return Ok(account);
        }

        // Create new account
        let contact = if self.config.email.is_empty() {
            vec![]
        } else {
            vec![format!("mailto:{}", self.config.email)]
        };

        let (account, creds) = Account::create(
            &NewAccount {
                contact: &contact.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            server_url,
            None,
        )
        .await?;

        // Save account credentials
        let creds_json = serde_json::to_string(&creds)?;
        self.storage.save_account(&creds_json)?;

        info!("created new ACME account");

        Ok(account)
    }

    /// Load a stored certificate into a CertifiedKey.
    fn load_stored_cert(
        &self,
        stored: &StoredCert,
    ) -> Result<Arc<rustls::sign::CertifiedKey>, AcmeError> {
        use std::io::Write;
        use tempfile::NamedTempFile;

        // Write to temp files for loading
        let mut cert_file = NamedTempFile::new()?;
        cert_file.write_all(stored.cert_pem.as_bytes())?;

        let mut key_file = NamedTempFile::new()?;
        key_file.write_all(stored.key_pem.as_bytes())?;

        let key = load_certified_key(cert_file.path(), key_file.path())?;
        Ok(key)
    }
}

/// Clean up DNS challenge records, logging any failures.
async fn cleanup_dns_records(
    dns_client: &CloudflareClient,
    zone_id: &str,
    record_ids: &[(String, String)],
) {
    for (name, record_id) in record_ids {
        if let Err(e) = dns_client.delete_txt_record(zone_id, record_id).await {
            warn!(name = %name, error = %e, "failed to cleanup DNS record");
        }
    }
}

/// Generate a CSR and private key for the given domains.
fn generate_csr(domains: &[String]) -> Result<(String, Vec<u8>), AcmeError> {
    use rcgen::{generate_simple_self_signed, CertificateParams};

    // Generate a simple self-signed cert to get a key pair
    let rcgen::CertifiedKey { cert: _, key_pair } = generate_simple_self_signed(domains.to_vec())?;

    let key_pem = key_pair.serialize_pem();

    // Generate CSR from certificate params
    let params = CertificateParams::new(domains)?;
    let csr = params.serialize_request(&key_pair)?;
    let csr_pem = csr.pem()?;

    // Convert PEM to DER for the CSR
    let csr_der = pem_to_der(&csr_pem)?;

    Ok((key_pem, csr_der))
}

/// Parse a PEM-encoded X.509 certificate to extract its expiry datetime.
fn parse_certificate_expiry(cert_pem: &str) -> Option<chrono::DateTime<Utc>> {
    use x509_parser::prelude::*;

    // Parse PEM
    let (_, pem) = parse_x509_pem(cert_pem.as_bytes()).ok()?;

    // Parse the X.509 certificate
    let (_, cert) = X509Certificate::from_der(&pem.contents).ok()?;

    // Get the expiry timestamp
    let expiry = cert.validity().not_after;
    chrono::DateTime::from_timestamp(expiry.timestamp(), 0)
}

/// Convert PEM to DER format.
fn pem_to_der(pem: &str) -> Result<Vec<u8>, AcmeError> {
    use base64::prelude::{Engine, BASE64_STANDARD};

    let lines: Vec<&str> = pem.lines().collect();
    let mut der = Vec::new();

    let mut in_block = false;
    for line in lines {
        if line.contains("-----BEGIN") {
            in_block = true;
            continue;
        }
        if line.contains("-----END") {
            break;
        }
        if in_block {
            der.extend(BASE64_STANDARD.decode(line)?);
        }
    }

    Ok(der)
}

#[derive(Debug, thiserror::Error)]
pub enum AcmeError {
    #[error("storage error: {0}")]
    Storage(#[from] StorageError),

    #[error("cloudflare error: {0}")]
    Cloudflare(#[from] CloudflareError),

    #[error("ACME error: {0}")]
    Acme(#[from] instant_acme::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("PEM error: {0}")]
    Pem(#[from] crate::pem::PemError),

    #[error("CSR generation error: {0}")]
    Rcgen(#[from] rcgen::Error),

    #[error("base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),

    #[error("configuration error: {0}")]
    Config(String),

    #[error("no DNS-01 challenge available")]
    NoChallenge,

    #[error("order failed: {0}")]
    OrderFailed(String),

    #[error("no certificates loaded")]
    NoCertificates,
}
