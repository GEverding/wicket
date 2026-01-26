//! Gateway API Custom Resource Definitions for Wicket.
//!
//! This module defines the Kubernetes CRDs following the Gateway API specification.
//! Reference: https://gateway-api.sigs.k8s.io/

mod common;
mod gateway;
mod gateway_class;
mod httproute;
mod referencegrant;
mod tcproute;
mod tlsroute;

pub use common::*;
pub use gateway::*;
pub use gateway_class::*;
pub use httproute::*;
pub use referencegrant::*;
pub use tcproute::*;
pub use tlsroute::*;
