//! TLS Secret reconciler.
//!
//! Watches Kubernetes Secrets referenced by Gateways for TLS termination.
//! Validates cross-namespace references using ReferenceGrant.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use k8s_openapi::api::core::v1::Secret;
use kube::{
    api::Api,
    runtime::{
        controller::{Action, Controller},
        watcher::Config,
    },
    Client, ResourceExt,
};

use crate::crds::{Gateway, GatewayClass, ReferenceGrant};
use crate::metrics::{
    ReconcileMetrics, TLS_CERTIFICATES, TLS_CERTIFICATE_EXPIRY_TIMESTAMP,
    TLS_SECRET_EXTRACTIONS_TOTAL, TLS_SECRET_EXTRACTION_DURATION_SECONDS,
};
use wicket_tls::load_certified_key;

use super::config_generator::GatewayState;
use super::context::Context;
use super::store::{ResourceClass, SharedStore};

/// Error type for Secret reconciliation.
#[derive(Debug, thiserror::Error)]
pub enum SecretError {
    #[error("Kubernetes API error: {0}")]
    KubeError(#[from] kube::Error),

    #[error("Secret missing tls.crt or tls.key")]
    MissingTlsData,

    #[error("Failed to decode base64: {0}")]
    Base64Decode(String),

    #[error("Failed to write certificate file: {0}")]
    WriteFile(String),

    #[error("Invalid TLS certificate material: {0}")]
    InvalidTlsMaterial(String),

    #[error("Cross-namespace reference not permitted")]
    ReferenceNotPermitted,

    #[error("Configuration error: {0}")]
    ConfigError(String),
}

// TLS certificate directory is now configurable via Context.tls_cert_dir
// Default is /var/run/wicket/tls (see context.rs)

/// Reconcile a Secret resource.
///
/// This is triggered when a TLS Secret changes. We check if any Gateway
/// references this secret and regenerate configuration if so.
pub async fn reconcile_secret(
    secret: Arc<Secret>,
    ctx: Arc<Context>,
) -> Result<Action, SecretError> {
    let metrics = ReconcileMetrics::new("Secret");
    let namespace = secret.namespace().unwrap_or_default();
    let name = secret.name_any();

    // Handle deletion: remove from store, clean up on-disk files, trigger config update.
    if secret.metadata.deletion_timestamp.is_some() {
        let secret_key = GatewayState::key(&namespace, &name);
        ctx.store.remove_tls_secret(&secret_key).await;

        // Best-effort: delete on-disk cert/key files.
        let safe_ns = sanitize_filename_component(&namespace);
        let safe_name = sanitize_filename_component(&name);
        let dir = PathBuf::from(&ctx.tls_cert_dir);
        for ext in &["crt", "key"] {
            let path = dir.join(format!("{}-{}.{}", safe_ns, safe_name, ext));
            if let Err(e) = tokio::fs::remove_file(&path).await {
                if e.kind() != std::io::ErrorKind::NotFound {
                    tracing::warn!(
                        path = %path.display(),
                        error = %e,
                        "Failed to delete TLS file on secret deletion"
                    );
                }
            }
        }

        tracing::info!(namespace = %namespace, name = %name, "Secret deleted, removed from store");
        return Ok(Action::await_change());
    }

    // Only process TLS secrets
    let secret_type = secret.type_.as_deref().unwrap_or("");
    if secret_type != "kubernetes.io/tls" && secret_type != "Opaque" {
        return Ok(Action::await_change());
    }

    // Check if this secret has TLS data
    let data = match &secret.data {
        Some(d) if d.contains_key("tls.crt") && d.contains_key("tls.key") => d,
        _ => return Ok(Action::await_change()), // Not a TLS secret
    };

    tracing::debug!(namespace = %namespace, name = %name, "Checking if Secret is referenced by Gateway");

    // Find all Gateways that reference this secret
    let referencing_gateways = find_referencing_gateways(&ctx.client, &namespace, &name).await?;

    if referencing_gateways.is_empty() {
        tracing::trace!(
            namespace = %namespace,
            name = %name,
            "Secret not referenced by any Gateway, skipping"
        );
        return Ok(Action::await_change());
    }

    tracing::info!(
        namespace = %namespace,
        name = %name,
        gateways = ?referencing_gateways,
        "Secret referenced by Gateways, processing"
    );

    // Validate cross-namespace references using ReferenceGrant
    for (gw_ns, gw_name) in &referencing_gateways {
        if gw_ns != &namespace {
            // Cross-namespace reference - need ReferenceGrant
            let permitted = validate_reference_grant(
                &ctx.client,
                &namespace, // Secret namespace (where ReferenceGrant must exist)
                gw_ns,      // Gateway namespace
                &name,      // Secret name
            )
            .await?;

            if !permitted {
                tracing::warn!(
                    secret_ns = %namespace,
                    secret_name = %name,
                    gateway_ns = %gw_ns,
                    gateway_name = %gw_name,
                    "Cross-namespace reference not permitted by ReferenceGrant"
                );
                // Don't fail - just skip this secret for this gateway
                continue;
            }

            tracing::debug!(
                secret_ns = %namespace,
                secret_name = %name,
                gateway_ns = %gw_ns,
                "Cross-namespace reference permitted by ReferenceGrant"
            );
        }
    }

    // Extract and write certificate files
    let extraction_start = std::time::Instant::now();
    let cert_data = data.get("tls.crt").ok_or(SecretError::MissingTlsData)?;
    let key_data = data.get("tls.key").ok_or(SecretError::MissingTlsData)?;

    let cert_path =
        write_tls_file(&ctx.tls_cert_dir, &namespace, &name, "crt", &cert_data.0).await?;
    let key_path = write_tls_file(&ctx.tls_cert_dir, &namespace, &name, "key", &key_data.0).await?;

    let secret_key = GatewayState::key(&namespace, &name);
    if let Err(error) =
        upsert_valid_tls_secret(&ctx.store, secret_key.clone(), &cert_path, &key_path).await
    {
        tracing::warn!(
            namespace = %namespace,
            name = %name,
            error = %error,
            "Invalid TLS Secret material"
        );
        delete_tls_files_if_present(&cert_path, &key_path).await;
        ctx.store.remove_tls_secret(&secret_key).await;
        return Err(error);
    }

    // Record extraction metrics
    let extraction_duration = extraction_start.elapsed().as_secs_f64();
    TLS_SECRET_EXTRACTIONS_TOTAL
        .with_label_values(&[&namespace, "success"])
        .inc();
    TLS_SECRET_EXTRACTION_DURATION_SECONDS
        .with_label_values(&[&namespace])
        .observe(extraction_duration);

    // Update TLS certificate count metric
    TLS_CERTIFICATES
        .with_label_values(&[&namespace, "kubernetes"])
        .inc();

    // Parse X.509 certificate to extract expiry timestamp
    if let Some(expiry) = parse_certificate_expiry(&cert_data.0) {
        TLS_CERTIFICATE_EXPIRY_TIMESTAMP
            .with_label_values(&[&namespace, &name])
            .set(expiry as f64);
        tracing::debug!(
            namespace = %namespace,
            name = %name,
            expiry_timestamp = expiry,
            "Certificate expiry timestamp extracted"
        );
    }

    tracing::info!(
        namespace = %namespace,
        name = %name,
        cert_path = %cert_path.display(),
        key_path = %key_path.display(),
        extraction_time_ms = extraction_duration * 1000.0,
        "TLS certificate extracted"
    );

    // Upsert the TLS secret into the shared store so the cache path reflects
    // this event.  We do this before triggering config update so that if the
    // store is already ready the snapshot will include the new cert paths.
    let secret_key = GatewayState::key(&namespace, &name);
    ctx.store
        .upsert_tls_secret(
            secret_key,
            cert_path.to_string_lossy().to_string(),
            key_path.to_string_lossy().to_string(),
        )
        .await;

    metrics.record_success();
    Ok(Action::requeue(Duration::from_secs(300))) // Recheck every 5 minutes
}

/// Handle errors during Secret reconciliation.
pub fn error_policy_secret(secret: Arc<Secret>, error: &SecretError, _ctx: Arc<Context>) -> Action {
    let namespace = secret.namespace().unwrap_or_default();
    let name = secret.name_any();

    tracing::error!(
        namespace = %namespace,
        name = %name,
        error = %error,
        "Secret reconciliation failed"
    );

    // Track extraction failures for TLS-related errors
    if matches!(
        error,
        SecretError::MissingTlsData
            | SecretError::WriteFile(_)
            | SecretError::Base64Decode(_)
            | SecretError::InvalidTlsMaterial(_)
    ) {
        TLS_SECRET_EXTRACTIONS_TOTAL
            .with_label_values(&[&namespace, "failure"])
            .inc();
    }

    crate::metrics::RECONCILE_ERRORS_TOTAL
        .with_label_values(&["Secret", "reconcile_error"])
        .inc();

    Action::requeue(Duration::from_secs(5))
}

/// Find all Gateways that reference a given Secret.
async fn find_referencing_gateways(
    client: &Client,
    secret_ns: &str,
    secret_name: &str,
) -> Result<Vec<(String, String)>, SecretError> {
    let mut referencing = Vec::new();

    let gw_api: Api<Gateway> = Api::all(client.clone());
    let gateways = gw_api.list(&Default::default()).await?;

    for gateway in gateways.items {
        let gw_ns = gateway.namespace().unwrap_or_default();
        let gw_name = gateway.name_any();

        // Check if this gateway is managed by Wicket
        let gc_api: Api<GatewayClass> = Api::all(client.clone());
        let is_wicket = gc_api
            .get(&gateway.spec.gateway_class_name)
            .await
            .map(|gc| gc.is_wicket_managed())
            .unwrap_or(false);

        if !is_wicket {
            continue;
        }

        // Check each listener for TLS certificate references
        for listener in &gateway.spec.listeners {
            if let Some(tls) = &listener.tls {
                for cert_ref in &tls.certificate_refs {
                    let ref_ns = cert_ref.namespace.as_deref().unwrap_or(&gw_ns);
                    let ref_name = &cert_ref.name;

                    if ref_ns == secret_ns && ref_name == secret_name {
                        referencing.push((gw_ns.clone(), gw_name.clone()));
                        break; // Found a match, no need to check more refs
                    }
                }
            }
        }
    }

    Ok(referencing)
}

/// Validate that a ReferenceGrant permits cross-namespace Secret access.
async fn validate_reference_grant(
    client: &Client,
    secret_ns: &str,   // Namespace where the secret (and ReferenceGrant) lives
    gateway_ns: &str,  // Namespace of the Gateway making the reference
    secret_name: &str, // Name of the secret being referenced
) -> Result<bool, SecretError> {
    use crate::metrics::{CROSS_NAMESPACE_BLOCKED_TOTAL, REFERENCE_GRANT_VALIDATIONS_TOTAL};

    // ReferenceGrant must exist in the target namespace (secret's namespace)
    let grant_api: Api<ReferenceGrant> = Api::namespaced(client.clone(), secret_ns);
    let grants = grant_api.list(&Default::default()).await?;

    for grant in grants.items {
        if grant.allows_tls_secret_reference(gateway_ns, Some(secret_name)) {
            REFERENCE_GRANT_VALIDATIONS_TOTAL
                .with_label_values(&[gateway_ns, secret_ns, "allowed"])
                .inc();
            return Ok(true);
        }
        // Also check if there's a wildcard grant (no specific name)
        if grant.allows_tls_secret_reference(gateway_ns, None) {
            REFERENCE_GRANT_VALIDATIONS_TOTAL
                .with_label_values(&[gateway_ns, secret_ns, "allowed"])
                .inc();
            return Ok(true);
        }
    }

    // No ReferenceGrant allows this access
    REFERENCE_GRANT_VALIDATIONS_TOTAL
        .with_label_values(&[gateway_ns, secret_ns, "denied"])
        .inc();
    CROSS_NAMESPACE_BLOCKED_TOTAL
        .with_label_values(&[gateway_ns, secret_ns, "Secret"])
        .inc();

    Ok(false)
}

/// Sanitize a string for use in a filename using allowlist approach.
/// Only allows alphanumeric characters and hyphens. All other characters
/// are replaced with hyphens. Consecutive hyphens are collapsed.
/// Maximum length is enforced to prevent filesystem issues.
fn sanitize_filename_component(s: &str) -> String {
    const MAX_COMPONENT_LEN: usize = 63; // DNS label max length

    let sanitized: String = s
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect();

    // Collapse consecutive hyphens and trim hyphens from edges
    let mut result = String::with_capacity(sanitized.len());
    let mut prev_hyphen = true; // Start true to trim leading hyphens
    for c in sanitized.chars() {
        if c == '-' {
            if !prev_hyphen {
                result.push(c);
                prev_hyphen = true;
            }
        } else {
            result.push(c);
            prev_hyphen = false;
        }
    }

    // Trim trailing hyphen
    if result.ends_with('-') {
        result.pop();
    }

    // Enforce max length
    if result.len() > MAX_COMPONENT_LEN {
        result.truncate(MAX_COMPONENT_LEN);
        // Don't end with hyphen after truncation
        while result.ends_with('-') {
            result.pop();
        }
    }

    // Ensure we have something valid
    if result.is_empty() {
        result = "unnamed".to_string();
    }

    result
}

/// Write TLS certificate or key to a file using atomic replacement.
async fn write_tls_file(
    tls_cert_dir: &str,
    namespace: &str,
    name: &str,
    extension: &str,
    data: &[u8],
) -> Result<PathBuf, SecretError> {
    // Ensure directory exists with secure permissions.
    // If the directory cannot be created (read-only filesystem, permissions),
    // skip the disk write silently — this indicates managed-runtime mode
    // where TLS certs flow via mounted Secrets, not controller-written files.
    let dir = PathBuf::from(tls_cert_dir);
    if let Err(e) = tokio::fs::create_dir_all(&dir).await {
        // Read-only filesystem or permission denied → skip disk write.
        // This is expected in managed-runtime mode where the controller
        // container has no writable volume for TLS certs.
        if e.kind() == std::io::ErrorKind::PermissionDenied || e.raw_os_error() == Some(30)
        // EROFS (Read-only file system)
        {
            tracing::debug!(
                path = %dir.display(),
                error = %e,
                "TLS cert directory not writable, skipping disk write"
            );
            let safe_ns = sanitize_filename_component(namespace);
            let safe_name = sanitize_filename_component(name);
            return Ok(dir.join(format!("{}-{}.{}", safe_ns, safe_name, extension)));
        }
        return Err(SecretError::WriteFile(format!("Failed to create dir: {e}")));
    }

    // Set directory permissions to 0700 (owner only)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let dir_perms = std::fs::Permissions::from_mode(0o700);
        let _ = tokio::fs::set_permissions(&dir, dir_perms).await;
    }

    // Sanitize names using allowlist approach (M-4 fix)
    let safe_ns = sanitize_filename_component(namespace);
    let safe_name = sanitize_filename_component(name);
    let filename = format!("{}-{}.{}", safe_ns, safe_name, extension);
    let path = dir.join(&filename);

    // Atomic write: write to temp file then rename (M-5 fix)
    let temp_filename = format!(".{}.tmp.{}", filename, std::process::id());
    let temp_path = dir.join(&temp_filename);

    // Write to temp file with restrictive permissions
    tokio::fs::write(&temp_path, data)
        .await
        .map_err(|e| SecretError::WriteFile(format!("Failed to write temp file: {}", e)))?;

    // Set file permissions to 0600 (owner read/write only)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        tokio::fs::set_permissions(&temp_path, perms)
            .await
            .map_err(|e| SecretError::WriteFile(format!("Failed to set permissions: {}", e)))?;
    }

    // Atomic rename
    tokio::fs::rename(&temp_path, &path)
        .await
        .map_err(|e| SecretError::WriteFile(format!("Failed to rename temp file: {}", e)))?;

    Ok(path)
}

/// Parse a PEM-encoded X.509 certificate to extract its expiry timestamp.
///
/// Returns the expiry as a Unix timestamp (seconds since epoch), or None if parsing fails.
fn parse_certificate_expiry(cert_data: &[u8]) -> Option<i64> {
    use x509_parser::prelude::*;

    // Try to parse as PEM first
    let cert_bytes = if let Ok((_, pem)) = parse_x509_pem(cert_data) {
        pem.contents
    } else {
        // Already DER format
        cert_data.to_vec()
    };

    // Parse the X.509 certificate
    match X509Certificate::from_der(&cert_bytes) {
        Ok((_, cert)) => {
            let expiry = cert.validity().not_after;
            Some(expiry.timestamp())
        }
        Err(e) => {
            tracing::warn!(error = %e, "Failed to parse X.509 certificate for expiry");
            None
        }
    }
}

fn validate_written_tls_material(cert_path: &Path, key_path: &Path) -> Result<(), SecretError> {
    load_certified_key(cert_path, key_path)
        .map(|_| ())
        .map_err(|error| SecretError::InvalidTlsMaterial(error.to_string()))
}

async fn upsert_valid_tls_secret(
    store: &SharedStore,
    secret_key: String,
    cert_path: &Path,
    key_path: &Path,
) -> Result<(), SecretError> {
    validate_written_tls_material(cert_path, key_path)?;
    store
        .upsert_tls_secret(
            secret_key,
            cert_path.to_string_lossy().to_string(),
            key_path.to_string_lossy().to_string(),
        )
        .await;
    Ok(())
}

async fn delete_tls_files_if_present(cert_path: &Path, key_path: &Path) {
    for path in [cert_path, key_path] {
        if let Err(error) = tokio::fs::remove_file(path).await {
            if error.kind() != std::io::ErrorKind::NotFound {
                tracing::warn!(path = %path.display(), error = %error, "Failed to delete TLS file");
            }
        }
    }
}

/// Create the Secret controller for watching TLS secret changes.
pub async fn run_secret_controller(ctx: Arc<Context>) -> Result<(), kube::Error> {
    use crate::metrics::{WATCH_CONNECTIONS_ACTIVE, WATCH_ERRORS_TOTAL, WATCH_EVENTS_TOTAL};

    let api: Api<Secret> = if ctx.watch_all_namespaces {
        Api::all(ctx.client.clone())
    } else {
        Api::namespaced(ctx.client.clone(), &ctx.controller_namespace)
    };

    // Only watch TLS-type secrets
    let config = Config::default();

    WATCH_CONNECTIONS_ACTIVE
        .with_label_values(&["Secret"])
        .set(1);

    let mut attempt: u32 = 0;
    loop {
        attempt += 1;
        match tokio::time::timeout(Duration::from_secs(30), api.list(&Default::default())).await {
            Ok(Ok(list)) => {
                let mut initial_list_error: Option<SecretError> = None;
                for secret in list.items {
                    let secret_type = secret.type_.as_deref().unwrap_or("");
                    let Some(data) = &secret.data else {
                        continue;
                    };
                    if (secret_type != "kubernetes.io/tls" && secret_type != "Opaque")
                        || !data.contains_key("tls.crt")
                        || !data.contains_key("tls.key")
                    {
                        continue;
                    }

                    let namespace = secret.metadata.namespace.clone().unwrap_or_default();
                    let name = secret.metadata.name.clone().unwrap_or_default();
                    let cert_path = match write_tls_file(
                        &ctx.tls_cert_dir,
                        &namespace,
                        &name,
                        "crt",
                        &data["tls.crt"].0,
                    )
                    .await
                    {
                        Ok(path) => path,
                        Err(e) => {
                            initial_list_error = Some(e);
                            break;
                        }
                    };
                    let key_path = match write_tls_file(
                        &ctx.tls_cert_dir,
                        &namespace,
                        &name,
                        "key",
                        &data["tls.key"].0,
                    )
                    .await
                    {
                        Ok(path) => path,
                        Err(e) => {
                            initial_list_error = Some(e);
                            break;
                        }
                    };
                    let secret_key = GatewayState::key(&namespace, &name);
                    if let Err(error) =
                        upsert_valid_tls_secret(&ctx.store, secret_key, &cert_path, &key_path).await
                    {
                        tracing::warn!(
                            namespace = %namespace,
                            name = %name,
                            error = %error,
                            "Skipping invalid TLS Secret from initial list"
                        );
                        delete_tls_files_if_present(&cert_path, &key_path).await;
                        continue;
                    }
                }
                if let Some(e) = initial_list_error {
                    let backoff = std::cmp::min(attempt * 2, 30);
                    tracing::warn!(
                        error = %e,
                        attempt,
                        backoff_secs = backoff,
                        "Initial Secret list processing failed; will retry"
                    );
                    tokio::time::sleep(Duration::from_secs(backoff as u64)).await;
                    continue;
                }
                ctx.store.mark_listed(ResourceClass::Secrets).await;
                tracing::debug!(attempt, "Secret initial list complete; store flag set");
                break;
            }
            Ok(Err(e)) => {
                let backoff = std::cmp::min(attempt * 2, 30);
                tracing::warn!(
                    error = %e,
                    attempt,
                    backoff_secs = backoff,
                    "Initial Secret list failed; will retry"
                );
                tokio::time::sleep(Duration::from_secs(backoff as u64)).await;
            }
            Err(_) => {
                tracing::warn!(
                    attempt,
                    "Initial Secret list timed out after 30s; will retry"
                );
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }
    }

    Controller::new(api, config)
        .run(reconcile_secret, error_policy_secret, ctx)
        .for_each(|result| async move {
            match result {
                Ok((obj, _)) => {
                    WATCH_EVENTS_TOTAL
                        .with_label_values(&["Secret", "reconcile_success"])
                        .inc();
                    tracing::trace!(
                        namespace = obj.namespace.as_deref().unwrap_or(""),
                        name = %obj.name,
                        "Secret reconciled"
                    );
                }
                Err(e) => {
                    WATCH_EVENTS_TOTAL
                        .with_label_values(&["Secret", "reconcile_error"])
                        .inc();
                    WATCH_ERRORS_TOTAL
                        .with_label_values(&["Secret", "controller_error"])
                        .inc();
                    tracing::error!(error = %e, "Secret controller error");
                }
            }
        })
        .await;

    WATCH_CONNECTIONS_ACTIVE
        .with_label_values(&["Secret"])
        .set(0);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reconcilers::store::SharedStore;
    use std::path::PathBuf;

    const VALID_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----\nMIIDCTCCAfGgAwIBAgIUS504oJN00coQI7WdYXtCv4rdSEYwDQYJKoZIhvcNAQEL\nBQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MDUxMDAwNDMxNloXDTI2MDUx\nMTAwNDMxNlowFDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEF\nAAOCAQ8AMIIBCgKCAQEAt0pgc70rBq5gFqsvwMev8oM54NNWw3zBpDDPzzsD59yZ\nne8abMrGnCBsW9ywv14gCvJeZ+hwj5Oi54fvj7X5hBI2QjLnPAGQ+HX2Z/RpqG5U\neEXQSObIVWo/R6z1yd8IO9Zxv2kd3Pr/i2XdE3bzAARNa97ebxSZhW4ByiL+GISt\nvwEvjaUzkbnZSwkhzi1CRKXABEBgaX2N67OQegwo+ccgjys3Z/I9tVmF0NrZxwqF\nMLm9sB5jd8zoCfdJWv1eeHn+uOYDXFi1oETX64aWJbWvbQPH+7kbKPYgqLzD1gOc\nWHghQOahaAcbK593GFm7Lz9dqIzC4AxO4QWpg7vvrwIDAQABo1MwUTAdBgNVHQ4E\nFgQUllHGGwkfNrbyaSbNxgExi2NpiUEwHwYDVR0jBBgwFoAUllHGGwkfNrbyaSbN\nxgExi2NpiUEwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAZ3aD\n4xzoIQ+opkhAMsBYXlSJ32bdEQjE91EHEDIv/ts+0Gh4azMfMOnd9tH+Vk5ZPoA2\nTWSB292ukbY4TflNrk3jrxrYRJcWSe3XRVeMYSsJQSAWceqlNWXcWwtX2X95BD6k\nCVv0Xj/iiCHWa2W8L0mvaU/neT6ajSioKVPnK+g18yr9JZ/J2V58Vb9Yf22XSx+f\nWy13F/QUcSnrqPUmoL6gdMKuzGZq47DKHLz1akQfg1FtPLE5IsdEWnP4bp9reKB5\nHMjREOUymg6W6Uu609T6mMHgRmQcStXt/oGOjXsiJsT3Ow9boY2IPkPB5lCnzLIX\nWU6ggfhLx97rw9+tmw==\n-----END CERTIFICATE-----\n";
    const VALID_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQC3SmBzvSsGrmAW\nqy/Ax6/ygzng01bDfMGkMM/POwPn3Jmd7xpsysacIGxb3LC/XiAK8l5n6HCPk6Ln\nh++PtfmEEjZCMuc8AZD4dfZn9GmoblR4RdBI5shVaj9HrPXJ3wg71nG/aR3c+v+L\nZd0TdvMABE1r3t5vFJmFbgHKIv4YhK2/AS+NpTORudlLCSHOLUJEpcAEQGBpfY3r\ns5B6DCj5xyCPKzdn8j21WYXQ2tnHCoUwub2wHmN3zOgJ90la/V54ef645gNcWLWg\nRNfrhpYlta9tA8f7uRso9iCovMPWA5xYeCFA5qFoBxsrn3cYWbsvP12ojMLgDE7h\nBamDu++vAgMBAAECggEAQtkPgGa3sIIcbWgVzHuHwiz2CPdLJ5Tyks1ynSPq8r9U\nD3PK8W6rLPnuSzqcA89yZEus/ryZgOPZgBPl3UYDMJXr0Az8pLf1hYiQS62qc1F5\n4TulEVGKMwzC84MzSWLcf+ZgKe1OhO/OD6shDB5P1eu7yOHJwj2DGFTctjo47fun\n2HZZGo7OpcwkhPgZbSfFniqc4LjLBQ2D8RmZe4EDXoCzbablT4W9r6Y+L7STo+hX\nVS8+VG/3HqtAaaSoZrE/4og4fi7wkyeyKXFQUAj1fI77NZQeB3Hl4cot4a3x0j5S\nOwyB95uLUFkHJKWQ2f/YtGvOFQ4NEkn4mHodYERmkQKBgQDZp9pS/TL2oNQMutX1\nTYNTsUdIBsmfju+8aBJcxJNfOpQU3JiI3YtR13tEl11syEmdhfNnkxqPV0W8pd8W\nNlcP/6j3LoEPiJPM9x1s9G00yKatUk3mVlOfqBhkoP2UjazzV1673DbRKPfl4yuH\n/cww4onve5OB235pzpANsTPziwKBgQDXlKz137m/y1Etm+kTNm2J1ZQH7HAYH6xV\nGHdh4VuVCRQ4zlSze/75hKw3sV++WJ0u5XYp3IOF08X2tSkqIchx8nbQw2azafKQ\nWh3o3LzpbwEWUc/eewFj5qg6lfuYwa+SpdE37+fiHMhPjGRdz6MKB22qUOqUUdRR\nIp/fnXlo7QKBgQCAskZescZTnA8mI8dlT1rqvrUWOqU3Sk4oyiSpY7Z8JWfv2ev7\naXv6fX4utY2RR/B3Sv/8azfWL9VVUYLSYHkkRZhD5+R6Kdiy5h8pEHIONuKPM05K\ndxrlGYCq56JpF0h/blben7xt+lpyPNu9gm0dLqY+y4QR0ZYyu+fjoLbGNwKBgQCm\n9MK6rKiLS+ezndJ1Cartm1XIiSkK1cS+JnOWf1RQ6LYbhFf+pOID1ecWPq06miAp\nSJYpt1i4lRj0hrq5oW4+KRwxc5MfEcdEWjZduE4prsk1wuhskfCysNjKfotac24I\n8ZhFbOu1prrPOJgmOv82bihVRdNWSMVYjKsqICf9xQKBgQCgVouUfA1wwpwDmQKZ\nJMXEk9Rt1f2Ds87XK+OPxfzrwgcVIBitV9Ie0VyxFVsfgOY6ezFVkyZ4sCHOBmQH\nlyefYgwRhkpsr9SKUlrqi00TrSRjsA6kbZejBwb79qW6Tg35F4qkQRFfYQcLdyQM\nsOOSw9wbokU4ou6OxbsP9C5yYQ==\n-----END PRIVATE KEY-----\n";

    async fn write_test_tls_files(cert_pem: &str, key_pem: &str) -> (PathBuf, PathBuf) {
        let unique = format!(
            "wicket-secret-tests-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time should move forward")
                .as_nanos()
        );
        let dir = std::env::temp_dir().join(unique);
        tokio::fs::create_dir_all(&dir)
            .await
            .expect("create temp dir");

        let cert_path = dir.join("tls.crt");
        let key_path = dir.join("tls.key");
        tokio::fs::write(&cert_path, cert_pem)
            .await
            .expect("write cert");
        tokio::fs::write(&key_path, key_pem)
            .await
            .expect("write key");

        (cert_path, key_path)
    }

    /// Confirms the store upsert path works in isolation.
    #[tokio::test]
    async fn test_tls_secret_upsert_into_store() {
        let store = SharedStore::new();
        store.mark_ready().await;

        let key = GatewayState::key("default", "my-cert");
        store
            .upsert_tls_secret(
                key.clone(),
                "/var/run/wicket/tls/default-my-cert.crt".to_string(),
                "/var/run/wicket/tls/default-my-cert.key".to_string(),
            )
            .await;

        let snap = store.snapshot().await.expect("store should be ready");
        let (cert, key_path) = snap
            .tls_secrets
            .get(&key)
            .expect("secret should be present");
        assert!(cert.ends_with(".crt"));
        assert!(key_path.ends_with(".key"));
    }

    #[tokio::test]
    async fn test_validate_written_tls_material_rejects_invalid_material() {
        let (cert_path, key_path) = write_test_tls_files("not a cert", "not a key").await;

        let result = validate_written_tls_material(&cert_path, &key_path);
        assert!(matches!(result, Err(SecretError::InvalidTlsMaterial(_))));
    }

    #[tokio::test]
    async fn test_validate_written_tls_material_accepts_valid_material() {
        let (cert_path, key_path) = write_test_tls_files(VALID_CERT_PEM, VALID_KEY_PEM).await;

        validate_written_tls_material(&cert_path, &key_path)
            .expect("valid tls material should pass");
    }

    #[tokio::test]
    async fn test_invalid_tls_material_does_not_upsert_store_secret() {
        let store = SharedStore::new();
        store.mark_ready().await;

        let (cert_path, key_path) = write_test_tls_files("not a cert", "not a key").await;
        let secret_key = GatewayState::key("default", "broken-cert");

        let result =
            upsert_valid_tls_secret(&store, secret_key.clone(), &cert_path, &key_path).await;
        assert!(matches!(result, Err(SecretError::InvalidTlsMaterial(_))));

        let snap = store.snapshot().await.expect("store should be ready");
        assert!(!snap.tls_secrets.contains_key(&secret_key));
    }

    #[tokio::test]
    async fn test_valid_tls_material_upserts_store_secret() {
        let store = SharedStore::new();
        store.mark_ready().await;

        let (cert_path, key_path) = write_test_tls_files(VALID_CERT_PEM, VALID_KEY_PEM).await;
        let secret_key = GatewayState::key("default", "good-cert");

        upsert_valid_tls_secret(&store, secret_key.clone(), &cert_path, &key_path)
            .await
            .expect("valid tls material should upsert");

        let snap = store.snapshot().await.expect("store should be ready");
        let (cert, key) = snap
            .tls_secrets
            .get(&secret_key)
            .expect("secret should exist");
        assert_eq!(cert, cert_path.to_string_lossy().as_ref());
        assert_eq!(key, key_path.to_string_lossy().as_ref());
    }

    /// Verify that sanitize_filename_component handles edge cases safely.
    #[test]
    fn test_sanitize_filename_component_basic() {
        assert_eq!(sanitize_filename_component("my-namespace"), "my-namespace");
        assert_eq!(sanitize_filename_component("my.secret"), "my-secret");
        // All-hyphen input collapses to empty → falls back to "unnamed"
        assert_eq!(sanitize_filename_component("---"), "unnamed");
        assert_eq!(sanitize_filename_component(""), "unnamed");
        assert_eq!(sanitize_filename_component("a/b"), "a-b");
    }
}
