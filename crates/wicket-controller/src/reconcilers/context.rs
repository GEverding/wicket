//! Shared context for reconcilers.

use std::collections::BTreeMap;
use std::sync::Arc;

use k8s_openapi::api::core::v1::ConfigMap;
use kube::api::{Api, Patch, PatchParams};
use kube::{Client, ResourceExt};
use tokio::sync::RwLock;

use super::config_generator::{GatewayState, WicketConfig};
use super::store::SharedStore;
use crate::crds::{Gateway, GatewayClass, HTTPRoute, TCPRoute, TLSRoute};

/// Shared context passed to all reconcilers.
#[derive(Clone)]
pub struct Context {
    /// Kubernetes client.
    pub client: Client,

    /// Current generated Wicket configuration.
    pub config: Arc<RwLock<WicketConfig>>,

    /// Shared resource cache/index.  Reconcilers read from this store
    /// instead of issuing repeated full-list API calls.
    pub store: Arc<SharedStore>,

    /// Controller name for status updates.
    pub controller_name: String,

    /// Namespace the controller is deployed in (for leader election).
    pub controller_namespace: String,

    /// Whether to watch all namespaces or just the controller namespace.
    pub watch_all_namespaces: bool,

    /// Name of the ConfigMap to update with proxy configuration.
    pub config_configmap_name: String,

    /// Namespace of the ConfigMap to update.
    pub config_configmap_namespace: String,

    /// Directory for storing TLS certificates extracted from Kubernetes secrets.
    /// Defaults to /var/run/wicket/tls for security (not world-readable /tmp).
    pub tls_cert_dir: String,
}

/// Default directory for TLS certificates (more secure than /tmp).
pub const DEFAULT_TLS_CERT_DIR: &str = "/var/run/wicket/tls";

impl Context {
    pub fn new(
        client: Client,
        controller_namespace: String,
        watch_all_namespaces: bool,
        config_configmap_name: String,
        config_configmap_namespace: String,
    ) -> Self {
        Self::with_tls_dir(
            client,
            controller_namespace,
            watch_all_namespaces,
            config_configmap_name,
            config_configmap_namespace,
            DEFAULT_TLS_CERT_DIR.to_string(),
        )
    }

    pub fn with_tls_dir(
        client: Client,
        controller_namespace: String,
        watch_all_namespaces: bool,
        config_configmap_name: String,
        config_configmap_namespace: String,
        tls_cert_dir: String,
    ) -> Self {
        Self {
            client,
            config: Arc::new(RwLock::new(WicketConfig::default())),
            store: Arc::new(SharedStore::new()),
            controller_name: "wicket.io/gateway-controller".to_string(),
            controller_namespace,
            watch_all_namespaces,
            config_configmap_name,
            config_configmap_namespace,
            tls_cert_dir,
        }
    }

    /// Update the Wicket configuration by patching the ConfigMap.
    pub async fn update_config(&self, config: WicketConfig) -> Result<(), ConfigUpdateError> {
        // Update in memory
        {
            let mut current = self.config.write().await;
            *current = config.clone();
        }

        // Serialize to TOML
        let toml_content: String = toml::to_string_pretty(&config)
            .map_err(|e: toml::ser::Error| ConfigUpdateError::Serialization(e.to_string()))?;

        // Update the ConfigMap
        let api: Api<ConfigMap> =
            Api::namespaced(self.client.clone(), &self.config_configmap_namespace);

        let mut data = BTreeMap::new();
        data.insert("wicket.toml".to_string(), toml_content);

        let patch = serde_json::json!({
            "data": data
        });

        api.patch(
            &self.config_configmap_name,
            &PatchParams::apply("wicket-controller"),
            &Patch::Merge(&patch),
        )
        .await
        .map_err(|e| ConfigUpdateError::KubeApi(e.to_string()))?;

        // Update metrics
        crate::metrics::CONFIG_UPDATES_TOTAL
            .with_label_values(&["success"])
            .inc();
        crate::metrics::CONFIG_LAST_UPDATE_TIMESTAMP.set(chrono::Utc::now().timestamp());
        crate::metrics::CONFIG_GENERATION.inc();

        tracing::info!(
            configmap = %self.config_configmap_name,
            namespace = %self.config_configmap_namespace,
            "Configuration updated in ConfigMap"
        );
        Ok(())
    }

    /// Get the current configuration.
    pub async fn get_config(&self) -> WicketConfig {
        self.config.read().await.clone()
    }
}

/// Errors that can occur during configuration updates.
#[derive(Debug, thiserror::Error)]
pub enum ConfigUpdateError {
    #[error("Failed to serialize configuration: {0}")]
    Serialization(String),

    #[error("Kubernetes API error: {0}")]
    KubeApi(String),
}

/// Trigger a full configuration update by loading all resources and regenerating config.
///
/// ## Cache-first strategy
///
/// When the shared store is ready, we use its snapshot directly — no API
/// list calls needed.  When the store is not yet ready (startup warm-up),
/// we fall back to the existing full-list API path.
///
/// ## Store readiness safety
///
/// The store is only marked ready (via `ingest_gateway_state`) when **all**
/// core list calls succeed.  If any list fails, we still generate config
/// from whatever partial data we have (existing behavior), but we do NOT
/// promote the store to ready — so future calls continue to fall back to
/// the API-list path until a fully-successful list completes.
pub async fn trigger_config_update(ctx: &Context, reason: &str) -> Result<(), ConfigUpdateError> {
    use super::service::load_all_service_endpoints;

    tracing::debug!(reason = %reason, "Triggering configuration update");

    // ── Cache-first path ──────────────────────────────────────────────────────
    if let Some(state) = ctx.store.snapshot().await {
        tracing::debug!(reason = %reason, "Using shared store snapshot for config generation");
        let config = state.generate_config();
        ctx.update_config(config).await?;
        tracing::debug!(reason = %reason, "Configuration update completed (cache path)");
        return Ok(());
    }

    // ── Fallback: full API-list path ──────────────────────────────────────────
    tracing::info!(
        reason = %reason,
        "Shared store not ready; falling back to full API-list for config generation"
    );

    let mut state = GatewayState::default();
    let mut all_lists_ok = true;

    // Load all Gateways (only Wicket-managed ones)
    let gw_api: Api<Gateway> = Api::all(ctx.client.clone());
    match gw_api.list(&Default::default()).await {
        Ok(gateways) => {
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
        Err(e) => {
            tracing::warn!(error = %e, "Failed to list Gateways; store will not be marked ready");
            all_lists_ok = false;
        }
    }

    // Load all HTTPRoutes
    let route_api: Api<HTTPRoute> = Api::all(ctx.client.clone());
    match route_api.list(&Default::default()).await {
        Ok(routes) => {
            for route in routes.items {
                let route_key = GatewayState::key(
                    route.namespace().as_deref().unwrap_or("default"),
                    &route.name_any(),
                );
                state.http_routes.insert(route_key, route);
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "Failed to list HTTPRoutes; store will not be marked ready");
            all_lists_ok = false;
        }
    }

    // Load all TCPRoutes
    let tcp_route_api: Api<TCPRoute> = Api::all(ctx.client.clone());
    match tcp_route_api.list(&Default::default()).await {
        Ok(routes) => {
            for route in routes.items {
                let route_key = GatewayState::key(
                    route.namespace().as_deref().unwrap_or("default"),
                    &route.name_any(),
                );
                state.tcp_routes.insert(route_key, route);
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "Failed to list TCPRoutes; store will not be marked ready");
            all_lists_ok = false;
        }
    }

    // Load all TLSRoutes
    let tls_route_api: Api<TLSRoute> = Api::all(ctx.client.clone());
    match tls_route_api.list(&Default::default()).await {
        Ok(routes) => {
            for route in routes.items {
                let route_key = GatewayState::key(
                    route.namespace().as_deref().unwrap_or("default"),
                    &route.name_any(),
                );
                state.tls_routes.insert(route_key, route);
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "Failed to list TLSRoutes; store will not be marked ready");
            all_lists_ok = false;
        }
    }

    // Load service endpoints
    load_all_service_endpoints(&ctx.client, &mut state).await;

    // Only populate the shared store when ALL core lists succeeded.
    // A partial snapshot would lock in missing resources and prevent
    // future fallback retries.
    if all_lists_ok {
        ctx.store.ingest_gateway_state(state.clone()).await;
    } else {
        tracing::warn!(
            reason = %reason,
            "Skipping store ingestion due to partial list failures;              store remains not-ready for future fallback retries"
        );
    }

    // Generate and update config from whatever we got (preserves existing behavior).
    let config = state.generate_config();
    ctx.update_config(config).await?;

    tracing::debug!(reason = %reason, "Configuration update completed (API-list fallback path)");
    Ok(())
}
