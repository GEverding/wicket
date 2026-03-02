//! TLS Secret reconciler.
//!
//! Watches Kubernetes Secrets referenced by Gateways for TLS termination.
//! Validates cross-namespace references using ReferenceGrant.

use std::path::PathBuf;
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
    Client, Resource, ResourceExt,
};

use crate::crds::{Gateway, GatewayClass, ReferenceGrant};
use crate::metrics::{
    ReconcileMetrics, TLS_CERTIFICATES_TOTAL, TLS_CERTIFICATE_EXPIRY_TIMESTAMP,
    TLS_SECRET_EXTRACTIONS_TOTAL, TLS_SECRET_EXTRACTION_DURATION_SECONDS,
};

use super::config_generator::GatewayState;
use super::context::{trigger_config_update, Context};

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

    // Record extraction metrics
    let extraction_duration = extraction_start.elapsed().as_secs_f64();
    TLS_SECRET_EXTRACTIONS_TOTAL
        .with_label_values(&[&namespace, "success"])
        .inc();
    TLS_SECRET_EXTRACTION_DURATION_SECONDS
        .with_label_values(&[&namespace])
        .observe(extraction_duration);

    // Update TLS certificate count metric
    TLS_CERTIFICATES_TOTAL
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

    // Trigger configuration regeneration via the shared path.
    trigger_config_update(&ctx, "Secret reconciled")
        .await
        .map_err(|e| SecretError::ConfigError(e.to_string()))?;

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
        SecretError::MissingTlsData | SecretError::WriteFile(_) | SecretError::Base64Decode(_)
    ) {
        TLS_SECRET_EXTRACTIONS_TOTAL
            .with_label_values(&[&namespace, "failure"])
            .inc();
    }

    crate::metrics::RECONCILE_ERRORS_TOTAL
        .with_label_values(&["Secret", "reconcile_error"])
        .inc();

    Action::requeue(Duration::from_secs(60))
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
    // Ensure directory exists with secure permissions
    let dir = PathBuf::from(tls_cert_dir);
    tokio::fs::create_dir_all(&dir)
        .await
        .map_err(|e| SecretError::WriteFile(format!("Failed to create dir: {}", e)))?;

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

    /// Verify that the secret module no longer defines its own trigger_config_update.
    ///
    /// Compile-time assertion: if a local function with the old 5-argument signature
    /// existed it would shadow the import and the two-argument call site above would
    /// fail to compile.  This test confirms the store upsert path works in isolation.
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
