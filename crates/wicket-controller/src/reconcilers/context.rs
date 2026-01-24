//! Shared context for reconcilers.

use std::sync::Arc;
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

    /// Config output path for the proxy to read.
    pub config_output_path: String,
}

impl Context {
    pub fn new(
        client: Client,
        controller_namespace: String,
        watch_all_namespaces: bool,
        config_output_path: String,
    ) -> Self {
        Self {
            client,
            config: Arc::new(RwLock::new(WicketConfig::default())),
            controller_name: "wicket.io/gateway-controller".to_string(),
            controller_namespace,
            watch_all_namespaces,
            config_output_path,
        }
    }

    /// Update the Wicket configuration and write it to disk.
    pub async fn update_config(&self, config: WicketConfig) -> Result<(), ConfigUpdateError> {
        // Update in memory
        {
            let mut current = self.config.write().await;
            *current = config.clone();
        }

        // Write to disk
        let toml_content: String = toml::to_string_pretty(&config)
            .map_err(|e: toml::ser::Error| ConfigUpdateError::Serialization(e.to_string()))?;

        tokio::fs::write(&self.config_output_path, &toml_content)
            .await
            .map_err(|e: std::io::Error| ConfigUpdateError::WriteFile(e.to_string()))?;

        // Update metrics
        crate::metrics::CONFIG_UPDATES_TOTAL
            .with_label_values(&["success"])
            .inc();
        crate::metrics::CONFIG_LAST_UPDATE_TIMESTAMP
            .set(chrono::Utc::now().timestamp());
        crate::metrics::CONFIG_GENERATION.inc();

        tracing::info!(path = %self.config_output_path, "Configuration updated");
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

    #[error("Failed to write configuration file: {0}")]
    WriteFile(String),
}
