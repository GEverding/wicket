//! Core proxy and routing logic for Wicket.
//!
//! This crate provides the Pingora-based proxy service and request routing.

pub mod proxy;
pub mod routing;

pub use proxy::{WicketCtx, WicketProxy};
pub use routing::{RouteMatch as MatchedRoute, Router};
pub use wicket_tls;
