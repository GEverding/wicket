//! Shared context for reconcilers.

use std::sync::Arc;

use kube::Client;
use tokio::sync::RwLock;

use super::config_generator::WicketConfig;
use super::store::SharedStore;
use crate::crds::WICKET_CONTROLLER_NAME;

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

    /// Directory for storing TLS certificates extracted from Kubernetes secrets.
    /// Defaults to /var/run/wicket/tls for security (not world-readable /tmp).
    pub tls_cert_dir: String,

    /// Controller-level configuration injected into the managed-runtime planner.
    ///
    /// Defaults to `ControllerConfig::default()` (suitable for development /
    /// single-node clusters).  In production this should be populated from
    /// flags, environment variables, or a controller ConfigMap before the
    /// controller starts.
    pub controller_config: super::runtime_plan::ControllerConfig,
}

/// Default directory for TLS certificates (more secure than /tmp).
pub const DEFAULT_TLS_CERT_DIR: &str = "/var/run/wicket/tls";

impl Context {
    pub fn new(client: Client, controller_namespace: String, watch_all_namespaces: bool) -> Self {
        Self::with_tls_dir(
            client,
            controller_namespace,
            watch_all_namespaces,
            DEFAULT_TLS_CERT_DIR.to_string(),
        )
    }

    pub fn with_tls_dir(
        client: Client,
        controller_namespace: String,
        watch_all_namespaces: bool,
        tls_cert_dir: String,
    ) -> Self {
        Self {
            client,
            config: Arc::new(RwLock::new(WicketConfig::default())),
            store: Arc::new(SharedStore::new()),
            controller_name: WICKET_CONTROLLER_NAME.to_string(),
            controller_namespace,
            watch_all_namespaces,
            tls_cert_dir,
            controller_config: super::runtime_plan::ControllerConfig::default(),
        }
    }

    /// Explicit constructor for callsites that supply a fully-built
    /// `ControllerConfig`.  Prefer this over `new` / `with_tls_dir` in
    /// production paths so the effective managed-runtime defaults are always
    /// injected explicitly rather than silently defaulted.
    pub fn with_controller_config(
        client: Client,
        controller_namespace: String,
        watch_all_namespaces: bool,
        tls_cert_dir: String,
        controller_config: super::runtime_plan::ControllerConfig,
    ) -> Self {
        Self {
            client,
            config: Arc::new(RwLock::new(WicketConfig::default())),
            store: Arc::new(SharedStore::new()),
            controller_name: WICKET_CONTROLLER_NAME.to_string(),
            controller_namespace,
            watch_all_namespaces,
            tls_cert_dir,
            controller_config,
        }
    }

    /// Get the current configuration.
    pub async fn get_config(&self) -> WicketConfig {
        self.config.read().await.clone()
    }
}
