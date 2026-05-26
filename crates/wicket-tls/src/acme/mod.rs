//! ACME certificate provider for automatic TLS certificate management.
//!
//! Uses instant-acme to obtain certificates from Let's Encrypt via DNS-01 challenges.

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, LetsEncrypt,
    NewAccount, NewOrder, Order, OrderStatus, RetryPolicy,
};
use rand::Rng;
use tokio::task::JoinHandle;
use tracing::{debug, error, info, warn};

use crate::config::{AcmeCertConfig, AcmeConfig, AutoTlsDomain};
use crate::metrics;
use crate::metrics::AcmeRenewalStatus;
use crate::pem::load_certified_key;
use crate::{CertManager, CertStore};

pub mod cloudflare;
pub mod storage;

pub use cloudflare::{CloudflareClient, CloudflareError};
pub use storage::{AcmeStorage, StorageError, StoredCert};

const DNS_PROPAGATION_WAIT: Duration = Duration::from_secs(30);

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
        let storage = AcmeStorage::new(self.config.storage.clone(), self.config.staging)?;

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

        info!(
            certificate_groups = all_certs.len(),
            "initializing configured ACME certificate groups"
        );

        for cert_config in &all_certs {
            let primary_domain = cert_config
                .domains
                .first()
                .ok_or_else(|| AcmeError::Config("cert config has no domains".into()))?;

            // Check if we have a valid cert
            info!(domain = %primary_domain, "checking stored ACME certificate");
            let needs_renewal = self
                .storage
                .needs_renewal(primary_domain, self.config.renew_before_days)?;
            if !needs_renewal {
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
                    info!(domain = %primary_domain, expiry = %stored.expiry, "obtained ACME certificate");
                    emit_acme_cert_metrics(&stored);
                    metrics::set_acme_last_success(primary_domain, Utc::now().timestamp());
                    let key = self.load_stored_cert(&stored)?;
                    store.insert(&cert_config.domains, key);
                }
                Err(e) => {
                    error!(domain = %primary_domain, error = %e, "failed to obtain certificate");
                    // Try to use existing cert if available
                    if let Ok(Some(stored)) = self.storage.load_cert(primary_domain) {
                        warn!(domain = %primary_domain, expiry = %stored.expiry, "using stored certificate as fallback");
                        emit_acme_cert_metrics(&stored);
                        let key = self.load_stored_cert(&stored)?;
                        store.insert(&cert_config.domains, key);
                    } else {
                        return Err(e);
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
                info!("checking certificates for renewal");

                if let Err(e) = self.check_and_renew().await {
                    error!(error = %e, "renewal check failed");
                }

                let jitter = rand::thread_rng().gen_range(0..3600);
                tokio::time::sleep(check_interval + Duration::from_secs(jitter)).await;
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
                metrics::set_acme_last_attempt(primary_domain, Utc::now().timestamp());
                info!(domain = %primary_domain, "certificate needs renewal");

                match self.obtain_cert(cert_config).await {
                    Ok(stored) => {
                        emit_acme_cert_metrics(&stored);
                        metrics::set_acme_last_success(primary_domain, Utc::now().timestamp());
                        let key = self.load_stored_cert(&stored)?;
                        store.insert(&cert_config.domains, key);
                        metrics::inc_acme_renewal(AcmeRenewalStatus::Success);
                        any_renewed = true;
                    }
                    Err(e) => {
                        metrics::inc_acme_renewal(AcmeRenewalStatus::Failure);
                        metrics::inc_acme_renewal_failure(primary_domain, acme_failure_reason(&e));
                        error!(domain = %primary_domain, error = %e, "renewal failed");
                        // Keep using existing cert
                        if let Ok(Some(stored)) = self.storage.load_cert(primary_domain) {
                            emit_acme_cert_metrics(&stored);
                            let key = self.load_stored_cert(&stored)?;
                            store.insert(&cert_config.domains, key);
                        }
                    }
                }
            } else {
                // Load existing cert
                if let Some(stored) = self.storage.load_cert(primary_domain)? {
                    emit_acme_cert_metrics(&stored);
                    metrics::inc_acme_renewal(AcmeRenewalStatus::Skipped);
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
        info!(domain = %primary_domain, "preparing ACME account");
        let account = self.get_or_create_account().await?;
        info!(domain = %primary_domain, "ACME account ready");

        // Create DNS client for challenges using resolved token (supports file-based secrets)
        let api_token = cert_config
            .dns
            .resolve_api_token()
            .map_err(AcmeError::Config)?;
        let dns_client = CloudflareClient::new(api_token)?;

        // Get zone ID
        info!(domain = %primary_domain, "resolving Cloudflare zone for ACME DNS-01");
        let zone_id = match &cert_config.dns.zone_id {
            Some(id) => id.clone(),
            None => dns_client.get_zone_id(primary_domain).await?,
        };
        info!(domain = %primary_domain, zone_id = %zone_id, "Cloudflare zone resolved for ACME DNS-01");

        // Create order
        let identifiers: Vec<_> = cert_config
            .domains
            .iter()
            .map(|d| Identifier::Dns(d.clone()))
            .collect();

        info!(domains = ?cert_config.domains, "creating ACME order");
        let mut order = account.new_order(&NewOrder::new(&identifiers)).await?;

        info!(domains = ?cert_config.domains, "created ACME order");

        let mut record_ids: Vec<(String, String)> = Vec::new();

        let result = async {
            create_dns_challenge_records(&mut order, &dns_client, &zone_id, &mut record_ids)
                .await?;

            if !record_ids.is_empty() {
                info!(
                    records = record_ids.len(),
                    wait_secs = DNS_PROPAGATION_WAIT.as_secs(),
                    "waiting for DNS challenge propagation"
                );
                tokio::time::sleep(DNS_PROPAGATION_WAIT).await;
            }

            notify_dns_challenges_ready(&mut order).await?;

            Ok::<_, AcmeError>(())
        }
        .await;

        if let Err(e) = result {
            cleanup_dns_records(&dns_client, &zone_id, &record_ids).await;
            return Err(e);
        }

        // Wait for order to be ready
        let retry_policy = RetryPolicy::new()
            .initial_delay(Duration::from_secs(1))
            .timeout(Duration::from_secs(120));
        info!(domains = ?cert_config.domains, "waiting for ACME order to become ready");
        let status = order.poll_ready(&retry_policy).await?;
        if matches!(status, OrderStatus::Invalid) {
            let details = summarize_authorizations(&mut order)
                .await
                .unwrap_or_else(|e| format!("failed to fetch authorization details: {e}"));
            cleanup_dns_records(&dns_client, &zone_id, &record_ids).await;
            return Err(AcmeError::OrderFailed(format!("{status:?}: {details}")));
        }
        info!(domains = ?cert_config.domains, "ACME order is ready; finalizing CSR");

        // Generate CSR
        let (private_key_pem, csr_der) = generate_csr(&cert_config.domains)?;

        // Finalize order
        order.finalize_csr(&csr_der).await?;

        // Poll for certificate
        info!(domains = ?cert_config.domains, "waiting for ACME certificate issuance");
        let cert_pem = order.poll_certificate(&retry_policy).await?;

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
            let creds: AccountCredentials = serde_json::from_str(&creds_json)?;
            let account = Account::builder()?.from_credentials(creds).await?;
            debug!("loaded existing ACME account");
            return Ok(account);
        }

        // Create new account
        let contact = if self.config.email.is_empty() {
            vec![]
        } else {
            vec![format!("mailto:{}", self.config.email)]
        };

        let contact_refs = contact.iter().map(String::as_str).collect::<Vec<_>>();
        let (account, creds) = Account::builder()?
            .create(
                &NewAccount {
                    contact: &contact_refs,
                    terms_of_service_agreed: true,
                    only_return_existing: false,
                },
                server_url.to_string(),
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

async fn create_dns_challenge_records(
    order: &mut Order,
    dns_client: &CloudflareClient,
    zone_id: &str,
    record_ids: &mut Vec<(String, String)>,
) -> Result<(), AcmeError> {
    let mut authorizations = order.authorizations();

    while let Some(authz) = authorizations.next().await {
        let mut authz = authz?;
        if matches!(authz.status, AuthorizationStatus::Valid) {
            continue;
        }

        let domain_str = dns_identifier(&authz.identifier())?;
        let txt_name = format!("_acme-challenge.{domain_str}");
        let challenge = authz
            .challenge(ChallengeType::Dns01)
            .ok_or_else(|| AcmeError::NoChallenge)?;
        let txt_value = challenge.key_authorization().dns_value();

        // Delete any stale challenge records from previous failed attempts.
        match dns_client.list_txt_records(zone_id, &txt_name).await {
            Ok(stale_ids) => {
                for id in stale_ids {
                    debug!(record_id = %id, "deleting stale ACME challenge record");
                    if let Err(e) = dns_client.delete_txt_record(zone_id, &id).await {
                        warn!(record_id = %id, error = %e, "failed to delete stale ACME challenge record");
                    }
                }
            }
            Err(e) => {
                warn!(txt_name = %txt_name, error = %e, "failed to list existing ACME challenge records");
            }
        }

        info!(domain = %domain_str, txt_name = %txt_name, "creating ACME DNS-01 challenge record");

        let record_id = dns_client
            .create_txt_record(zone_id, &txt_name, &txt_value)
            .await?;
        record_ids.push((txt_name, record_id));
    }

    Ok(())
}

async fn notify_dns_challenges_ready(order: &mut Order) -> Result<(), AcmeError> {
    let mut authorizations = order.authorizations();

    while let Some(authz) = authorizations.next().await {
        let mut authz = authz?;
        if matches!(authz.status, AuthorizationStatus::Valid) {
            continue;
        }

        let domain_str = dns_identifier(&authz.identifier())?;
        let mut challenge = authz
            .challenge(ChallengeType::Dns01)
            .ok_or_else(|| AcmeError::NoChallenge)?;

        info!(domain = %domain_str, "notifying ACME server that DNS challenge is ready");
        challenge.set_ready().await?;
    }

    Ok(())
}

fn dns_identifier(
    identifier: &instant_acme::AuthorizedIdentifier<'_>,
) -> Result<String, AcmeError> {
    match identifier.identifier {
        Identifier::Dns(d) => Ok(d.clone()),
        unsupported => Err(AcmeError::Config(format!(
            "unsupported ACME identifier: {unsupported:?}"
        ))),
    }
}

async fn summarize_authorizations(order: &mut Order) -> Result<String, AcmeError> {
    let mut authorizations = order.authorizations();
    let mut summaries = Vec::new();

    while let Some(authz) = authorizations.next().await {
        let mut authz = authz?;
        let state = authz.refresh().await?;
        let identifier = state.identifier().to_string();
        let challenges = state
            .challenges
            .iter()
            .map(|challenge| {
                let error = challenge
                    .error
                    .as_ref()
                    .map_or_else(String::new, |error| format!(", error={error}"));
                format!("{:?}:{:?}{error}", challenge.r#type, challenge.status)
            })
            .collect::<Vec<_>>()
            .join("|");

        summaries.push(format!(
            "{identifier}: authz={:?}, challenges=[{challenges}]",
            state.status
        ));
    }

    Ok(summaries.join("; "))
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

fn emit_acme_cert_metrics(stored: &StoredCert) {
    let expiry = stored.expiry.timestamp();
    for domain in &stored.domains {
        metrics::set_cert_expiry(domain, expiry);
    }
}

fn acme_failure_reason(error: &AcmeError) -> &'static str {
    match error {
        AcmeError::Storage(_) => "storage",
        AcmeError::Cloudflare(_) => "dns",
        AcmeError::Acme(_) => "acme_api",
        AcmeError::Json(_) => "json",
        AcmeError::Io(_) => "io",
        AcmeError::Pem(_) => "pem",
        AcmeError::Rcgen(_) => "csr",
        AcmeError::Base64(_) => "base64",
        AcmeError::Config(_) => "config",
        AcmeError::NoChallenge => "no_challenge",
        AcmeError::OrderFailed(_) => "order_failed",
        AcmeError::NoCertificates => "no_certificates",
    }
}

/// Generate a CSR and private key for the given domains.
fn generate_csr(domains: &[String]) -> Result<(String, Vec<u8>), AcmeError> {
    use rcgen::{generate_simple_self_signed, CertificateParams, DistinguishedName};

    // Generate a simple self-signed cert to get a key pair
    let rcgen::CertifiedKey { cert: _, key_pair } = generate_simple_self_signed(domains.to_vec())?;

    let key_pem = key_pair.serialize_pem();

    // Generate CSR from certificate params
    let mut params = CertificateParams::new(domains)?;
    params.distinguished_name = DistinguishedName::new();
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
