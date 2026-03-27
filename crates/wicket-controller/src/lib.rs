//! Wicket Kubernetes Gateway API Controller
//!
//! This crate implements a Kubernetes controller for the Gateway API,
//! allowing Wicket to be configured via Gateway, HTTPRoute, TCPRoute,
//! TLSRoute, and ReferenceGrant custom resources.
//!
//! ## Architecture
//!
//! The controller watches Gateway API resources and Kubernetes Services/Endpoints
//! to dynamically generate Wicket configuration:
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                    Wicket Controller                            │
//! ├─────────────────────────────────────────────────────────────────┤
//! │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐ │
//! │  │ GatewayClass│  │   Gateway   │  │  HTTPRoute / TCPRoute   │ │
//! │  │ Reconciler  │  │ Reconciler  │  │  TLSRoute Reconcilers   │ │
//! │  └──────┬──────┘  └──────┬──────┘  └───────────┬─────────────┘ │
//! │         │                │                     │               │
//! │         └────────────────┴─────────────────────┘               │
//! │                          │                                     │
//! │                          ▼                                     │
//! │  ┌─────────────────────────────────────────────────────────┐   │
//! │  │              Configuration Generator                     │   │
//! │  │  - Collects all Gateway API resources                   │   │
//! │  │  - Resolves Service endpoints                           │   │
//! │  │  - Generates Wicket TOML config                         │   │
//! │  └─────────────────────────────────────────────────────────┘   │
//! │                          │                                     │
//! │                          ▼                                     │
//! │  ┌─────────────────────────────────────────────────────────┐   │
//! │  │              Endpoints Watcher                          │   │
//! │  │  - Watches K8s Endpoints for backend changes            │   │
//! │  │  - Triggers config updates on scale events              │   │
//! │  └─────────────────────────────────────────────────────────┘   │
//! │                          │                                     │
//! │                          ▼                                     │
//! │  ┌─────────────────────────────────────────────────────────┐   │
//! │  │                  wicket.toml                             │   │
//! │  │  (Hot-reloaded by Wicket proxy)                         │   │
//! │  └─────────────────────────────────────────────────────────┘   │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Gateway API Resources
//!
//! - **GatewayClass**: Defines the controller that manages a class of Gateways
//! - **Gateway**: Defines listeners (ports, protocols, TLS) that accept traffic
//! - **HTTPRoute**: Defines HTTP routing rules (host, path, headers → backend)
//! - **TCPRoute**: Defines TCP routing rules (port → backend)
//! - **TLSRoute**: Defines SNI-based TLS routing (passthrough)
//! - **ReferenceGrant**: Allows cross-namespace references (e.g., TLS secrets)
//!
//! ## Metrics
//!
//! The controller exposes Prometheus metrics on port 8081:
//!
//! - `wicket_gateway_classes` - Number of GatewayClass resources
//! - `wicket_gateways{namespace, gateway_class}` - Number of Gateways
//! - `wicket_httproutes{namespace}` - Number of HTTPRoutes
//! - `wicket_reconcile_total{resource_type, result}` - Reconciliation counts
//! - `wicket_reconcile_duration_seconds{resource_type}` - Reconciliation latency
//! - `wicket_backend_endpoints_healthy{namespace, service}` - Healthy endpoints
//! - `wicket_config_updates_total{result}` - Configuration update counts

pub mod crds;
pub mod leader_election;
pub mod metrics;
pub mod reconcilers;

pub use crds::*;
pub use leader_election::*;
pub use metrics::*;
pub use reconcilers::*;
