//! Gateway API Custom Resource Definitions for Wicket.
//!
//! This module defines the Kubernetes CRDs following the Gateway API specification.
//! Reference: https://gateway-api.sigs.k8s.io/

mod gateway_class;
mod gateway;
mod httproute;
mod tcproute;
mod tlsroute;
mod referencegrant;
mod common;

pub use gateway_class::*;
pub use gateway::*;
pub use httproute::*;
pub use tcproute::*;
pub use tlsroute::*;
pub use referencegrant::*;
pub use common::*;
