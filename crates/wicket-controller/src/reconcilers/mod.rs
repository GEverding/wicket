//! Reconcilers for Gateway API resources.
//!
//! Each reconciler is responsible for watching and reconciling a specific resource type.
//!
//! ## Planner/applier contracts
//!
//! See [`contracts`] for the boundary types that separate pure planning from
//! side-effect application.  All reconcilers are expected to follow those
//! contracts.
//!
//! ## Config regeneration
//!
//! Managed-runtime Gateways own their proxy ConfigMaps through
//! [`runtime_plan`] and [`runtime_applier`]. The legacy central proxy ConfigMap
//! path has been removed.

mod config_generator;
mod context;
mod gateway;
mod gateway_class;
mod httproute;
mod referencegrant;
mod secret;
mod service;
pub mod store;
mod tcproute;
mod tlsroute;

pub mod attachment_planner;
pub mod contracts;
pub mod runtime_applier;
pub mod runtime_plan;
pub mod status_helpers;

pub use config_generator::*;
pub use context::*;
pub use gateway::*;
pub use gateway_class::*;
pub use httproute::*;
pub use referencegrant::*;
pub use secret::*;
pub use service::*;
pub use store::SharedStore;
pub use tcproute::*;
pub use tlsroute::*;
