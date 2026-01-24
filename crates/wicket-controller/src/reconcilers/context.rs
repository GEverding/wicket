//! Shared context for reconcilers.

use std::collections::BTreeMap;
use std::sync::Arc;

use k8s_openapi::api::core::v1::ConfigMap;
use kube::api::{Api, Patch, PatchParams};
use kube::Client;
use tokio::sync::RwLock;

use super::config_generator::WicketConfig;

/// Shared context passed to all reconcilers.
#[derive(Clone)]
pub struct Context {
    /// Kubernetes client.
    pub client: Client,

    /// Current generated Wicket configuration.
    pub config: Arc<RwLock<WicketConfig>>,

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
}

impl Context {
    pub fn new(
        client: Client,
        controller_namespace: String,
        watch_all_namespaces: bool,
        config_configmap_name: String,
        config_configmap_namespace: String,
    ) -> Self {
        Self {
            client,
            config: Arc::new(RwLock::new(WicketConfig::default())),
            controller_name: "wicket.io/gateway-controller".to_string(),
            controller_namespace,
            watch_all_namespaces,
            config_configmap_name,
            config_configmap_namespace,
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
