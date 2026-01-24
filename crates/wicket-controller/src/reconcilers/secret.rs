//! TLS Secret reconciler.
//!
//! Watches Kubernetes Secrets referenced by Gateways for TLS termination.
//! Validates cross-namespace references using ReferenceGrant.

use std::collections::HashSet;
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
use super::context::Context;

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

/// Directory where extracted TLS certificates are written.
const TLS_CERT_DIR: &str = "/tmp/wicket/tls";

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

    let cert_path = write_tls_file(&namespace, &name, "crt", &cert_data.0).await?;
    let key_path = write_tls_file(&namespace, &name, "key", &key_data.0).await?;

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

    // TODO: Parse X.509 certificate to extract expiry timestamp
    // This would require adding x509-parser crate
    // TLS_CERTIFICATE_EXPIRY_TIMESTAMP.with_label_values(&[&namespace, &name]).set(expiry_timestamp);

    tracing::info!(
        namespace = %namespace,
        name = %name,
        cert_path = %cert_path.display(),
        key_path = %key_path.display(),
        extraction_time_ms = extraction_duration * 1000.0,
        "TLS certificate extracted"
    );

    // Trigger configuration regeneration
    trigger_config_update(&ctx, &namespace, &name, cert_path, key_path).await?;

    metrics.record_success();
    Ok(Action::requeue(Duration::from_secs(300))) // Recheck every 5 minutes
}

/// Handle errors during Secret reconciliation.
pub fn error_policy_secret(
    secret: Arc<Secret>,
    error: &SecretError,
    _ctx: Arc<Context>,
) -> Action {
    let namespace = secret.namespace().unwrap_or_default();
    let name = secret.name_any();

    tracing::error!(
        namespace = %namespace,
        name = %name,
        error = %error,
        "Secret reconciliation failed"
    );

    // Track extraction failures for TLS-related errors
    if matches!(error, SecretError::MissingTlsData | SecretError::WriteFile(_) | SecretError::Base64Decode(_)) {
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
    use crate::metrics::{REFERENCE_GRANT_VALIDATIONS_TOTAL, CROSS_NAMESPACE_BLOCKED_TOTAL};

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

/// Write TLS certificate or key to a file.
async fn write_tls_file(
    namespace: &str,
    name: &str,
    extension: &str,
    data: &[u8],
) -> Result<PathBuf, SecretError> {
    // Ensure directory exists
    let dir = PathBuf::from(TLS_CERT_DIR);
    tokio::fs::create_dir_all(&dir)
        .await
        .map_err(|e| SecretError::WriteFile(format!("Failed to create dir: {}", e)))?;

    // Sanitize names for filesystem
    let safe_ns = namespace.replace(['/', '\\', '.'], "-");
    let safe_name = name.replace(['/', '\\', '.'], "-");
    let filename = format!("{}-{}.{}", safe_ns, safe_name, extension);
    let path = dir.join(&filename);

    // Write file with restrictive permissions
    tokio::fs::write(&path, data)
        .await
        .map_err(|e| SecretError::WriteFile(format!("Failed to write {}: {}", path.display(), e)))?;

    // Set file permissions to 0600 (owner read/write only)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        tokio::fs::set_permissions(&path, perms)
            .await
            .map_err(|e| SecretError::WriteFile(format!("Failed to set permissions: {}", e)))?;
    }

    Ok(path)
}

/// Trigger a full configuration update with the new TLS secret.
async fn trigger_config_update(
    ctx: &Context,
    secret_ns: &str,
    secret_name: &str,
    cert_path: PathBuf,
    key_path: PathBuf,
) -> Result<(), SecretError> {
    use super::service::load_all_service_endpoints;
    use crate::crds::{HTTPRoute, TCPRoute, TLSRoute};

    let mut state = GatewayState::default();

    // Add this TLS secret to state
    let secret_key = GatewayState::key(secret_ns, secret_name);
    state.tls_secrets.insert(
        secret_key,
        (
            cert_path.to_string_lossy().to_string(),
            key_path.to_string_lossy().to_string(),
        ),
    );

    // Load all other TLS secrets that have been extracted
    load_existing_tls_secrets(&mut state).await;

    // Load all Gateways (only Wicket-managed ones)
    let gw_api: Api<Gateway> = Api::all(ctx.client.clone());
    if let Ok(gateways) = gw_api.list(&Default::default()).await {
        for gateway in gateways.items {
            let gc_api: Api<GatewayClass> = Api::all(ctx.client.clone());
            let is_wicket = gc_api
                .get(&gateway.spec.gateway_class_name)
                .await
                .map(|gc| gc.is_wicket_managed())
                .unwrap_or(false);

            if is_wicket {
                let gw_key = GatewayState::key(
                    gateway.namespace().as_deref().unwrap_or("default"),
                    &gateway.name_any(),
                );
                state.gateways.insert(gw_key, gateway);
            }
        }
    }

    // Load all HTTPRoutes
    let route_api: Api<HTTPRoute> = Api::all(ctx.client.clone());
    if let Ok(routes) = route_api.list(&Default::default()).await {
        for route in routes.items {
            let route_key = GatewayState::key(
                route.namespace().as_deref().unwrap_or("default"),
                &route.name_any(),
            );
            state.http_routes.insert(route_key, route);
        }
    }

    // Load all TCPRoutes
    let tcp_route_api: Api<TCPRoute> = Api::all(ctx.client.clone());
    if let Ok(routes) = tcp_route_api.list(&Default::default()).await {
        for route in routes.items {
            let route_key = GatewayState::key(
                route.namespace().as_deref().unwrap_or("default"),
                &route.name_any(),
            );
            state.tcp_routes.insert(route_key, route);
        }
    }

    // Load all TLSRoutes
    let tls_route_api: Api<TLSRoute> = Api::all(ctx.client.clone());
    if let Ok(routes) = tls_route_api.list(&Default::default()).await {
        for route in routes.items {
            let route_key = GatewayState::key(
                route.namespace().as_deref().unwrap_or("default"),
                &route.name_any(),
            );
            state.tls_routes.insert(route_key, route);
        }
    }

    // Load service endpoints
    load_all_service_endpoints(&ctx.client, &mut state).await;

    // Generate and update config
    let config = state.generate_config();
    ctx.update_config(config)
        .await
        .map_err(|e| SecretError::ConfigError(e.to_string()))?;

    Ok(())
}

/// Load existing TLS secrets from the certificate directory.
async fn load_existing_tls_secrets(state: &mut GatewayState) {
    let dir = PathBuf::from(TLS_CERT_DIR);

    let mut entries = match tokio::fs::read_dir(&dir).await {
        Ok(e) => e,
        Err(_) => return, // Directory doesn't exist yet
    };

    let mut cert_files: HashSet<String> = HashSet::new();

    while let Ok(Some(entry)) = entries.next_entry().await {
        let filename = entry.file_name().to_string_lossy().to_string();
        if filename.ends_with(".crt") {
            // Extract the base name (without .crt extension)
            let base = filename.trim_end_matches(".crt").to_string();
            cert_files.insert(base);
        }
    }

    // For each .crt file, check if matching .key exists
    for base in cert_files {
        let cert_path = dir.join(format!("{}.crt", base));
        let key_path = dir.join(format!("{}.key", base));

        if cert_path.exists() && key_path.exists() {
            // Parse namespace-name from filename
            // Filename format: {namespace}-{name}.{ext}
            // Note: We use the filename as the key since we sanitized it
            state.tls_secrets.insert(
                base.clone(),
                (
                    cert_path.to_string_lossy().to_string(),
                    key_path.to_string_lossy().to_string(),
                ),
            );
        }
    }
}

/// Create the Secret controller for watching TLS secret changes.
pub async fn run_secret_controller(ctx: Arc<Context>) -> Result<(), kube::Error> {
    use crate::metrics::{WATCH_CONNECTIONS_ACTIVE, WATCH_EVENTS_TOTAL, WATCH_ERRORS_TOTAL};

    let api: Api<Secret> = if ctx.watch_all_namespaces {
        Api::all(ctx.client.clone())
    } else {
        Api::namespaced(ctx.client.clone(), &ctx.controller_namespace)
    };

    // Only watch TLS-type secrets
    let config = Config::default();

    WATCH_CONNECTIONS_ACTIVE.with_label_values(&["Secret"]).set(1);

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

    WATCH_CONNECTIONS_ACTIVE.with_label_values(&["Secret"]).set(0);

    Ok(())
}
