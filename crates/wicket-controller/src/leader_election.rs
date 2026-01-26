//! Simple leader election using Kubernetes Lease resources.
//!
//! This implementation uses the coordination.k8s.io Lease API for leader election.
//! Only one replica can hold the lease at a time.

use std::time::Duration;

use chrono::Utc;
use k8s_openapi::api::coordination::v1::Lease;
use kube::{
    api::{Api, Patch, PatchParams},
    Client,
};

/// Parameters for leader election.
pub struct LeaderElectionConfig {
    /// Name of the lease resource
    pub lease_name: String,
    /// Namespace for the lease
    pub namespace: String,
    /// Identity of this holder (usually pod name)
    pub holder_identity: String,
    /// How long the lease is valid
    pub lease_duration: Duration,
    /// How long to wait before retrying on error
    pub retry_period: Duration,
    /// How often to renew the lease
    pub renew_deadline: Duration,
}

impl Default for LeaderElectionConfig {
    fn default() -> Self {
        Self {
            lease_name: "wicket-controller-leader".to_string(),
            namespace: "wicket-system".to_string(),
            holder_identity: String::new(),
            lease_duration: Duration::from_secs(15),
            retry_period: Duration::from_secs(2),
            renew_deadline: Duration::from_secs(10),
        }
    }
}

/// Result of a leader election attempt.
#[derive(Debug, Clone)]
pub struct LeaseState {
    /// Whether this instance is the leader
    pub is_leader: bool,
    /// Current holder identity
    pub holder: Option<String>,
    /// When the lease expires
    pub expire_time: Option<chrono::DateTime<Utc>>,
}

/// Leader election coordinator.
pub struct LeaderElection {
    client: Client,
    config: LeaderElectionConfig,
    api: Api<Lease>,
}

impl LeaderElection {
    /// Create a new leader election coordinator.
    pub fn new(client: Client, config: LeaderElectionConfig) -> Self {
        let api = Api::namespaced(client.clone(), &config.namespace);
        Self {
            client,
            config,
            api,
        }
    }

    /// Try to acquire or renew the lease.
    ///
    /// Returns the current lease state.
    pub async fn try_acquire_or_renew(&self) -> Result<LeaseState, kube::Error> {
        let now = Utc::now();

        // Try to get the existing lease
        let lease = match self.api.get_opt(&self.config.lease_name).await? {
            Some(lease) => lease,
            None => {
                // Lease doesn't exist, try to create it
                return self.create_lease().await;
            }
        };

        // Check if we already hold the lease
        let current_holder = lease.spec.as_ref().and_then(|s| s.holder_identity.as_ref());
        let is_current_holder = current_holder == Some(&self.config.holder_identity);

        // Check if the lease has expired
        let renew_time = lease.spec.as_ref().and_then(|s| s.renew_time.as_ref());
        let duration_secs = lease
            .spec
            .as_ref()
            .and_then(|s| s.lease_duration_seconds)
            .unwrap_or(15);
        let expire_time = renew_time.map(|t| t.0 + chrono::Duration::seconds(duration_secs.into()));
        let is_expired = expire_time.map(|t| now > t).unwrap_or(true);

        if is_current_holder || is_expired {
            // We can acquire/renew the lease
            self.update_lease(&lease).await
        } else {
            // Someone else holds a valid lease
            Ok(LeaseState {
                is_leader: false,
                holder: current_holder.cloned(),
                expire_time,
            })
        }
    }

    /// Create a new lease.
    async fn create_lease(&self) -> Result<LeaseState, kube::Error> {
        use k8s_openapi::api::coordination::v1::LeaseSpec;
        use k8s_openapi::apimachinery::pkg::apis::meta::v1::MicroTime;
        use kube::api::PostParams;

        let now = Utc::now();
        let expire_time = now + chrono::Duration::from_std(self.config.lease_duration).unwrap();

        let lease = Lease {
            metadata: kube::core::ObjectMeta {
                name: Some(self.config.lease_name.clone()),
                namespace: Some(self.config.namespace.clone()),
                ..Default::default()
            },
            spec: Some(LeaseSpec {
                holder_identity: Some(self.config.holder_identity.clone()),
                lease_duration_seconds: Some(self.config.lease_duration.as_secs() as i32),
                acquire_time: Some(MicroTime(now)),
                renew_time: Some(MicroTime(now)),
                lease_transitions: Some(0),
                ..Default::default()
            }),
        };

        match self.api.create(&PostParams::default(), &lease).await {
            Ok(_) => {
                tracing::info!(
                    lease = %self.config.lease_name,
                    holder = %self.config.holder_identity,
                    "Created leader lease"
                );
                Ok(LeaseState {
                    is_leader: true,
                    holder: Some(self.config.holder_identity.clone()),
                    expire_time: Some(expire_time),
                })
            }
            Err(kube::Error::Api(e)) if e.code == 409 => {
                // Conflict - someone else created it first, retry get
                tracing::debug!("Lease creation conflict, another leader exists");
                Ok(LeaseState {
                    is_leader: false,
                    holder: None,
                    expire_time: None,
                })
            }
            Err(e) => Err(e),
        }
    }

    /// Update an existing lease.
    async fn update_lease(&self, lease: &Lease) -> Result<LeaseState, kube::Error> {
        use k8s_openapi::api::coordination::v1::LeaseSpec;
        use k8s_openapi::apimachinery::pkg::apis::meta::v1::MicroTime;

        let now = Utc::now();
        let expire_time = now + chrono::Duration::from_std(self.config.lease_duration).unwrap();

        let current_transitions = lease
            .spec
            .as_ref()
            .and_then(|s| s.lease_transitions)
            .unwrap_or(0);
        let current_holder = lease.spec.as_ref().and_then(|s| s.holder_identity.as_ref());
        let is_new_leader = current_holder != Some(&self.config.holder_identity);

        let patch = serde_json::json!({
            "spec": {
                "holderIdentity": self.config.holder_identity,
                "leaseDurationSeconds": self.config.lease_duration.as_secs() as i32,
                "renewTime": MicroTime(now),
                "leaseTransitions": if is_new_leader { current_transitions + 1 } else { current_transitions },
            }
        });

        match self
            .api
            .patch(
                &self.config.lease_name,
                &PatchParams::default(),
                &Patch::Merge(&patch),
            )
            .await
        {
            Ok(_) => {
                if is_new_leader {
                    tracing::info!(
                        lease = %self.config.lease_name,
                        holder = %self.config.holder_identity,
                        "Acquired leader lease"
                    );
                }
                Ok(LeaseState {
                    is_leader: true,
                    holder: Some(self.config.holder_identity.clone()),
                    expire_time: Some(expire_time),
                })
            }
            Err(kube::Error::Api(e)) if e.code == 409 => {
                // Conflict - someone else updated it, we lost the lease
                tracing::debug!("Lease update conflict, lost leadership");
                Ok(LeaseState {
                    is_leader: false,
                    holder: None,
                    expire_time: None,
                })
            }
            Err(e) => Err(e),
        }
    }
}
