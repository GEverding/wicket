//! Pingora-based proxy service for Wicket.
//!
//! This module implements the core proxy functionality using Pingora's HttpProxy trait.

use crate::config::{Config, LoadBalanceStrategy, UpstreamConfig};
use crate::routing::{RouteMatch2, Router};
use anyhow::Result;
use arc_swap::ArcSwap;
use async_trait::async_trait;
use pingora_core::prelude::*;
use pingora_core::upstreams::peer::{HttpPeer, Peer};
use pingora_core::Result as PingoraResult;
use pingora_load_balancing::selection::consistent::KetamaHashing;
use pingora_load_balancing::selection::RoundRobin;
use pingora_load_balancing::{health_check::TcpHealthCheck, LoadBalancer};
use pingora_proxy::{ProxyHttp, Session};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error, info, warn};

/// Context carried through the request lifecycle.
pub struct WicketCtx {
    /// The matched route information
    pub route_match: Option<RouteMatch2>,

    /// Start time for request duration tracking
    pub start_time: std::time::Instant,

    /// Request ID for tracing
    pub request_id: String,
}

/// The main Wicket proxy service.
pub struct WicketProxy {
    /// Router for matching requests to upstreams
    router: ArcSwap<Router>,

    /// Map of upstream name to load balancer
    upstreams: ArcSwap<HashMap<String, Arc<UpstreamCluster>>>,
}

/// Wrapper around a load balancer for an upstream.
pub struct UpstreamCluster {
    /// The load balancer instance (using round-robin)
    lb_round_robin: Option<Arc<LoadBalancer<RoundRobin>>>,

    /// The load balancer instance (using consistent hashing)
    lb_ketama: Option<Arc<LoadBalancer<KetamaHashing>>>,

    /// Strategy being used
    strategy: LoadBalanceStrategy,
}

impl WicketProxy {
    /// Create a new WicketProxy from configuration.
    pub fn new(config: &Config) -> Result<Self> {
        let router = Router::build(&config.routes);
        let upstreams = Self::build_upstreams(&config.upstreams)?;

        Ok(WicketProxy {
            router: ArcSwap::new(Arc::new(router)),
            upstreams: ArcSwap::new(Arc::new(upstreams)),
        })
    }

    /// Build upstream load balancers from configuration.
    fn build_upstreams(
        configs: &HashMap<String, UpstreamConfig>,
    ) -> Result<HashMap<String, Arc<UpstreamCluster>>> {
        let mut upstreams = HashMap::new();

        for (name, config) in configs {
            let cluster = UpstreamCluster::new(config)?;
            info!(
                upstream = %name,
                backends = config.backends.len(),
                strategy = ?config.strategy,
                "Configured upstream"
            );
            upstreams.insert(name.clone(), Arc::new(cluster));
        }

        Ok(upstreams)
    }

    /// Reload configuration at runtime.
    #[allow(dead_code)]
    pub fn reload(&self, config: &Config) -> Result<()> {
        let router = Router::build(&config.routes);
        let upstreams = Self::build_upstreams(&config.upstreams)?;

        self.router.store(Arc::new(router));
        self.upstreams.store(Arc::new(upstreams));

        info!("Configuration reloaded");
        Ok(())
    }

    /// Get an upstream peer for the given upstream name.
    fn get_peer(&self, upstream_name: &str, key: &[u8]) -> Option<HttpPeer> {
        let upstreams = self.upstreams.load();
        let cluster = upstreams.get(upstream_name)?;
        cluster.select_peer(key)
    }
}

impl UpstreamCluster {
    /// Create a new upstream cluster from configuration.
    fn new(config: &UpstreamConfig) -> Result<Self> {
        // Parse backend addresses
        let backends: Vec<_> = config
            .backends
            .iter()
            .map(|b| {
                // Parse address, handling potential scheme prefix
                let addr = b
                    .strip_prefix("http://")
                    .or_else(|| b.strip_prefix("https://"))
                    .unwrap_or(b);
                addr.to_string()
            })
            .collect();

        let backend_refs: Vec<&str> = backends.iter().map(|s| s.as_str()).collect();

        match config.strategy {
            LoadBalanceStrategy::RoundRobin => {
                let mut lb = LoadBalancer::try_from_iter(backend_refs)?;

                // Configure health check if specified
                if let Some(ref hc_config) = config.health_check {
                    let hc = TcpHealthCheck::new();
                    lb.set_health_check(hc);
                    lb.health_check_frequency =
                        Some(Duration::from_secs(hc_config.interval));
                }

                Ok(UpstreamCluster {
                    lb_round_robin: Some(Arc::new(lb)),
                    lb_ketama: None,
                    strategy: LoadBalanceStrategy::RoundRobin,
                })
            }
            LoadBalanceStrategy::ConsistentHash => {
                let lb =
                    LoadBalancer::<KetamaHashing>::try_from_iter(backend_refs)?;

                Ok(UpstreamCluster {
                    lb_round_robin: None,
                    lb_ketama: Some(Arc::new(lb)),
                    strategy: LoadBalanceStrategy::ConsistentHash,
                })
            }
        }
    }

    /// Select a peer from this upstream cluster.
    fn select_peer(&self, key: &[u8]) -> Option<HttpPeer> {
        match self.strategy {
            LoadBalanceStrategy::RoundRobin => {
                let lb = self.lb_round_robin.as_ref()?;
                let backend = lb.select(key, 256)?;
                Some(HttpPeer::new(backend.addr, false, String::new()))
            }
            LoadBalanceStrategy::ConsistentHash => {
                let lb = self.lb_ketama.as_ref()?;
                let backend = lb.select(key, 256)?;
                Some(HttpPeer::new(backend.addr, false, String::new()))
            }
        }
    }
}

#[async_trait]
impl ProxyHttp for WicketProxy {
    type CTX = WicketCtx;

    fn new_ctx(&self) -> Self::CTX {
        WicketCtx {
            route_match: None,
            start_time: std::time::Instant::now(),
            request_id: generate_request_id(),
        }
    }

    async fn request_filter(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> PingoraResult<bool>
    where
        Self::CTX: Send + Sync,
    {
        let req_header = session.req_header();

        // Extract request properties
        let host = req_header
            .headers
            .get("host")
            .and_then(|v| v.to_str().ok());

        let path = req_header.uri.path();
        let method = req_header.method.as_str();

        // Build headers map for matching
        let headers: HashMap<String, String> = req_header
            .headers
            .iter()
            .filter_map(|(k, v)| {
                v.to_str()
                    .ok()
                    .map(|v| (k.as_str().to_lowercase(), v.to_string()))
            })
            .collect();

        // Match route
        let router = self.router.load();
        let route_match = router.match_request(host, path, method, &headers);

        if let Some(ref rm) = route_match {
            debug!(
                request_id = %ctx.request_id,
                route = ?rm.route_name,
                upstream = %rm.upstream,
                method = %method,
                path = %path,
                host = ?host,
                "Request matched route"
            );
        } else {
            warn!(
                request_id = %ctx.request_id,
                method = %method,
                path = %path,
                host = ?host,
                "No matching route found"
            );
        }

        ctx.route_match = route_match;

        // Return false to continue processing (true would mean we handled it ourselves)
        Ok(false)
    }

    async fn upstream_peer(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> PingoraResult<Box<HttpPeer>> {
        let route_match = ctx.route_match.as_ref().ok_or_else(|| {
            Error::new(ErrorType::HTTPStatus(404))
        })?;

        // Use request URI as hash key for consistent hashing
        let key = session.req_header().uri.path().as_bytes();

        let peer = self
            .get_peer(&route_match.upstream, key)
            .ok_or_else(|| {
                error!(
                    upstream = %route_match.upstream,
                    "No healthy backends available"
                );
                Error::new(ErrorType::HTTPStatus(503))
            })?;

        debug!(
            request_id = %ctx.request_id,
            peer = ?peer.address(),
            "Selected upstream peer"
        );

        Ok(Box::new(peer))
    }

    async fn logging(
        &self,
        session: &mut Session,
        _e: Option<&Error>,
        ctx: &mut Self::CTX,
    ) where
        Self::CTX: Send + Sync,
    {
        let duration = ctx.start_time.elapsed();
        let req_header = session.req_header();

        let status = session
            .response_written()
            .map(|r| r.status.as_u16())
            .unwrap_or(0);

        let method = req_header.method.as_str();
        let path = req_header.uri.path();
        let host = req_header
            .headers
            .get("host")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("-");

        let route_name = ctx
            .route_match
            .as_ref()
            .and_then(|r| r.route_name.as_deref())
            .unwrap_or("-");

        let upstream = ctx
            .route_match
            .as_ref()
            .map(|r| r.upstream.as_str())
            .unwrap_or("-");

        info!(
            request_id = %ctx.request_id,
            method = %method,
            path = %path,
            host = %host,
            status = status,
            duration_ms = duration.as_millis() as u64,
            route = %route_name,
            upstream = %upstream,
            "Request completed"
        );
    }
}

/// Generate a unique request ID.
fn generate_request_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();

    format!("{:x}", timestamp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    #[test]
    fn test_request_id_generation() {
        let id1 = generate_request_id();
        let id2 = generate_request_id();
        assert!(!id1.is_empty());
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_upstream_cluster_creation() {
        let config = UpstreamConfig {
            backends: vec!["127.0.0.1:3000".to_string()],
            strategy: LoadBalanceStrategy::RoundRobin,
            health_check: None,
        };

        let cluster = UpstreamCluster::new(&config).unwrap();
        assert!(cluster.lb_round_robin.is_some());
        assert!(cluster.lb_ketama.is_none());
    }
}
