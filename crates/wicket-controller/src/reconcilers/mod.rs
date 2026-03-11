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
//! ## Config regeneration split
//!
//! Config generation is split into a pure planner and a side-effecting applier:
//! - [`config_planner`]: `GlobalConfigPlanner` -- pure, sync, `GatewayState -> ConfigPlan`.
//! - [`config_applier`]: `apply_config_plan` -- async, patches ConfigMap + metrics.

mod config_applier;
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
pub mod config_planner;
pub mod contracts;
pub mod runtime_applier;
pub mod runtime_plan;

pub use config_applier::apply_config_plan;
pub use config_generator::*;
pub use context::{trigger_config_update, *};
pub use gateway::*;
pub use gateway_class::*;
pub use httproute::*;
pub use referencegrant::*;
pub use secret::*;
pub use service::*;
pub use store::SharedStore;
pub use tcproute::*;
pub use tlsroute::*;
