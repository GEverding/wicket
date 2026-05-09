//! Pure config planner: snapshot/bootstrap state -> `ConfigPlan`.
//!
//! # Overview
//!
//! This module extracts the *planning* half of config regeneration from the
//! mixed planning+apply path that previously lived in `context.rs`.
//!
//! ```text
//!   GlobalConfigPlanInput { gateway_state: GatewayState }
//!         |
//!         v
//!   GlobalConfigPlanner::plan()   -- pure, sync, no I/O
//!         |
//!         v
//!   ConfigPlan { Update { toml_content, config_hash } | NoOp }
//! ```
//!
//! # Invariants
//!
//! - No I/O, no async, no side effects.
//! - Deterministic: same `GatewayState` always produces the same `ConfigPlan`.
//! - Never calls `unwrap()` on inputs.
//! - Returns `Err(PlanError)` for invalid inputs; never panics.
//!
//! # Relationship to `runtime_plan`
//!
//! `runtime_plan::config_toml_from_snapshot` generates config scoped to a
//! *single* Gateway from a `PlannerSnapshot`.  This module generates the
//! *global* config from a `GatewayState` (all Gateways), which is the path
//! used by `trigger_config_update` and the bootstrap/recovery fallback.
//!
//! Both paths converge on `ConfigPlan` from `contracts.rs` so the applier
//! boundary is shared.
//!
//! For the managed-runtime path, use `runtime_plan::config_plan_from_runtime_plan`
//! to convert a `GatewayRuntimePlan` into a `ConfigPlan` without recomputing
//! the TOML or hash.
//!
//! # Hash helper
//!
//! `sha256_hex` is re-exported from `runtime_plan` (the canonical location)
//! for backward compatibility with existing callers.

use crate::reconcilers::config_generator::{GatewayState, WicketConfig};
use crate::reconcilers::contracts::{ConfigPlan, PlanError, Planner};

// ─────────────────────────────────────────────────────────────────────────────
// Planner input
// ─────────────────────────────────────────────────────────────────────────────

/// All inputs required to plan the global Wicket config.
///
/// The planner does not read from the Kubernetes API or the store.  All inputs
/// arrive here.
#[derive(Debug, Clone)]
pub struct GlobalConfigPlanInput {
    /// Snapshot of all Gateway API resources needed for config generation.
    pub gateway_state: GatewayState,

    /// Optional current config hash (lowercase hex SHA-256 of the current
    /// `wicket.toml` in the ConfigMap).  When `Some`, the planner returns
    /// `ConfigPlan::NoOp` if the newly generated hash matches.  When `None`
    /// the planner always returns `ConfigPlan::Update`.
    pub current_config_hash: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Planner
// ─────────────────────────────────────────────────────────────────────────────

/// Pure planner for the global Wicket configuration.
///
/// Implements [`Planner`] with `Input = GlobalConfigPlanInput` and
/// `Plan = ConfigPlan`.
///
/// ## Invariants
///
/// - No I/O, no async, no side effects.
/// - Deterministic: same inputs always produce the same plan.
/// - Returns `Err(PlanError)` for invalid or incomplete inputs; never panics.
pub struct GlobalConfigPlanner;

impl Planner for GlobalConfigPlanner {
    type Input = GlobalConfigPlanInput;
    type Plan = ConfigPlan;

    fn plan(&self, input: &GlobalConfigPlanInput) -> Result<ConfigPlan, PlanError> {
        // Generate config deterministically so that HashMap iteration order
        // does not affect the output or the resulting hash.
        let config: WicketConfig = input.gateway_state.generate_config();

        // Serialize to TOML.  Surface any serialization failure as a planning
        // error rather than silently falling back to a minimal config.
        let toml_content =
            toml::to_string_pretty(&config).map_err(|e| PlanError::InvalidInput {
                reason: format!("TOML serialization failed: {}", e),
            })?;

        // Compute SHA-256 hash of the rendered TOML.
        let config_hash = sha256_hex(&toml_content);

        // If the caller supplied the current hash and it matches, no patch is
        // needed.  We still carry the content so the applier can sync the
        // in-memory WicketConfig without an extra Kubernetes read.
        if let Some(ref current) = input.current_config_hash {
            if current == &config_hash {
                return Ok(ConfigPlan::NoOp {
                    toml_content,
                    config_hash,
                });
            }
        }

        Ok(ConfigPlan::Update {
            toml_content,
            config_hash,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Hash helper (re-exported from runtime_plan for backward compatibility)
// ─────────────────────────────────────────────────────────────────────────────

/// Compute the lowercase hex SHA-256 of `data`.
///
/// Re-exported from `runtime_plan::sha256_hex` so that existing callers of
/// `config_planner::sha256_hex` continue to compile without change.
pub use crate::reconcilers::runtime_plan::sha256_hex;

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crds::{
        Condition, Gateway, HTTPRoute, HTTPRouteStatus, ParentReference, ProtocolType,
        RouteParentStatus, WICKET_CONTROLLER_NAME,
    };
    use crate::crds::{GatewaySpec, HTTPBackendRef, HTTPRouteRule, HTTPRouteSpec, Listener};
    use crate::reconcilers::config_generator::ServiceEndpoints;
    use kube::core::ObjectMeta;

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn empty_state() -> GatewayState {
        GatewayState::default()
    }

    fn state_with_gateway() -> GatewayState {
        let mut state = GatewayState::default();
        let gw = Gateway {
            metadata: ObjectMeta {
                name: Some("gw".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            },
            spec: GatewaySpec {
                gateway_class_name: "wicket".to_string(),
                listeners: vec![Listener {
                    name: "http".to_string(),
                    hostname: None,
                    port: 8080,
                    protocol: ProtocolType::HTTP,
                    tls: None,
                    allowed_routes: None,
                }],
                addresses: vec![],
                infrastructure: None,
            },
            status: None,
        };
        state
            .gateways
            .insert(GatewayState::key("default", "gw"), gw);
        state
    }

    fn state_with_gateway_and_route() -> GatewayState {
        let mut state = state_with_gateway();
        let route = HTTPRoute {
            metadata: ObjectMeta {
                name: Some("r".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            },
            spec: HTTPRouteSpec {
                parent_refs: vec![],
                hostnames: vec!["api.example.com".to_string()],
                rules: vec![HTTPRouteRule {
                    name: None,
                    matches: vec![],
                    filters: vec![],
                    backend_refs: vec![HTTPBackendRef {
                        backend_ref: crate::crds::BackendRef {
                            group: "".to_string(),
                            kind: "Service".to_string(),
                            name: "svc".to_string(),
                            namespace: None,
                            port: Some(80),
                            weight: 1,
                        },
                        filters: vec![],
                    }],
                    timeouts: None,
                }],
            },
            status: Some(HTTPRouteStatus {
                parents: vec![RouteParentStatus {
                    parent_ref: ParentReference {
                        group: "gateway.networking.k8s.io".to_string(),
                        kind: "Gateway".to_string(),
                        namespace: None,
                        name: "gw".to_string(),
                        section_name: None,
                        port: None,
                    },
                    controller_name: WICKET_CONTROLLER_NAME.to_string(),
                    conditions: vec![Condition::accepted()],
                }],
            }),
        };
        state
            .http_routes
            .insert(GatewayState::key("default", "r"), route);
        state.service_endpoints.insert(
            GatewayState::key("default", "svc"),
            ServiceEndpoints {
                namespace: "default".to_string(),
                name: "svc".to_string(),
                endpoints: vec!["10.0.0.1:80".to_string()],
            },
        );
        state
    }

    // ── sha256_hex ────────────────────────────────────────────────────────────

    #[test]
    fn sha256_hex_is_64_chars() {
        let h = sha256_hex("hello");
        assert_eq!(h.len(), 64);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn sha256_hex_is_deterministic() {
        assert_eq!(sha256_hex("test"), sha256_hex("test"));
    }

    #[test]
    fn sha256_hex_differs_for_different_inputs() {
        assert_ne!(sha256_hex("a"), sha256_hex("b"));
    }

    // ── GlobalConfigPlanner ───────────────────────────────────────────────────

    #[test]
    fn planner_returns_update_for_empty_state_no_current_hash() {
        let planner = GlobalConfigPlanner;
        let input = GlobalConfigPlanInput {
            gateway_state: empty_state(),
            current_config_hash: None,
        };
        let plan = planner.plan(&input).expect("plan should succeed");
        assert!(
            matches!(plan, ConfigPlan::Update { .. }),
            "expected Update when no current hash is provided"
        );
    }

    #[test]
    fn planner_returns_noop_when_hash_matches() {
        let planner = GlobalConfigPlanner;
        // First pass: get the hash.
        let input = GlobalConfigPlanInput {
            gateway_state: empty_state(),
            current_config_hash: None,
        };
        let plan = planner.plan(&input).expect("first plan should succeed");
        let (hash, toml) = match plan {
            ConfigPlan::Update {
                ref config_hash,
                ref toml_content,
            } => (config_hash.clone(), toml_content.clone()),
            ConfigPlan::NoOp { .. } => panic!("expected Update on first call"),
        };

        // Second pass: supply the same hash -> NoOp.
        let input2 = GlobalConfigPlanInput {
            gateway_state: empty_state(),
            current_config_hash: Some(hash.clone()),
        };
        let plan2 = planner.plan(&input2).expect("second plan should succeed");
        assert!(
            matches!(plan2, ConfigPlan::NoOp { .. }),
            "expected NoOp when hash matches current"
        );
        // NoOp must carry the same content so the applier can sync in-memory.
        match plan2 {
            ConfigPlan::NoOp {
                toml_content,
                config_hash,
            } => {
                assert_eq!(config_hash, hash, "NoOp hash must match supplied hash");
                assert_eq!(toml_content, toml, "NoOp toml must match generated toml");
            }
            _ => panic!("expected NoOp"),
        }
    }

    #[test]
    fn planner_returns_update_when_hash_differs() {
        let planner = GlobalConfigPlanner;
        let input = GlobalConfigPlanInput {
            gateway_state: state_with_gateway(),
            current_config_hash: Some("deadbeef".to_string()),
        };
        let plan = planner.plan(&input).expect("plan should succeed");
        assert!(
            matches!(plan, ConfigPlan::Update { .. }),
            "expected Update when hash differs"
        );
    }

    #[test]
    fn planner_update_carries_valid_toml() {
        let planner = GlobalConfigPlanner;
        let input = GlobalConfigPlanInput {
            gateway_state: state_with_gateway_and_route(),
            current_config_hash: None,
        };
        let plan = planner.plan(&input).expect("plan should succeed");
        match plan {
            ConfigPlan::Update { toml_content, .. } => {
                // Must be valid TOML.
                let parsed: Result<toml::Value, _> = toml::from_str(&toml_content);
                assert!(parsed.is_ok(), "generated TOML must be valid: {:?}", parsed);
            }
            ConfigPlan::NoOp { .. } => panic!("expected Update"),
        }
    }

    #[test]
    fn planner_update_hash_matches_toml_content() {
        let planner = GlobalConfigPlanner;
        let input = GlobalConfigPlanInput {
            gateway_state: state_with_gateway_and_route(),
            current_config_hash: None,
        };
        let plan = planner.plan(&input).expect("plan should succeed");
        match plan {
            ConfigPlan::Update {
                toml_content,
                config_hash,
            } => {
                assert_eq!(
                    config_hash,
                    sha256_hex(&toml_content),
                    "config_hash must be SHA-256 of toml_content"
                );
            }
            ConfigPlan::NoOp { .. } => panic!("expected Update"),
        }
    }

    #[test]
    fn planner_noop_carries_content() {
        let planner = GlobalConfigPlanner;
        let input = GlobalConfigPlanInput {
            gateway_state: empty_state(),
            current_config_hash: None,
        };
        let first = planner.plan(&input).expect("first plan should succeed");
        let hash = match &first {
            ConfigPlan::Update { config_hash, .. } => config_hash.clone(),
            ConfigPlan::NoOp { .. } => panic!("expected Update"),
        };

        let input2 = GlobalConfigPlanInput {
            gateway_state: empty_state(),
            current_config_hash: Some(hash.clone()),
        };
        let noop = planner.plan(&input2).expect("noop plan should succeed");
        match noop {
            ConfigPlan::NoOp {
                ref toml_content,
                ref config_hash,
            } => {
                assert_eq!(config_hash, &hash);
                assert_eq!(
                    sha256_hex(toml_content),
                    hash,
                    "NoOp toml_content must hash to config_hash"
                );
            }
            _ => panic!("expected NoOp"),
        }
    }

    #[test]
    fn planner_is_deterministic_for_same_state() {
        let planner = GlobalConfigPlanner;
        let state = state_with_gateway_and_route();
        let input = GlobalConfigPlanInput {
            gateway_state: state.clone(),
            current_config_hash: None,
        };
        let plan_a = planner.plan(&input).expect("plan a should succeed");
        let plan_b = planner.plan(&input).expect("plan b should succeed");
        assert_eq!(
            plan_a, plan_b,
            "planner must be deterministic for identical inputs"
        );
    }

    #[test]
    fn planner_produces_different_hash_for_different_states() {
        let planner = GlobalConfigPlanner;

        // Use states that produce observably different TOML:
        // - empty state: no routes, no upstreams
        // - state with gateway + route + endpoint: has upstreams and routes
        let input_empty = GlobalConfigPlanInput {
            gateway_state: empty_state(),
            current_config_hash: None,
        };
        let input_with_route = GlobalConfigPlanInput {
            gateway_state: state_with_gateway_and_route(),
            current_config_hash: None,
        };

        let hash_empty = match planner.plan(&input_empty).unwrap() {
            ConfigPlan::Update { config_hash, .. } => config_hash,
            ConfigPlan::NoOp { .. } => panic!("expected Update"),
        };
        let hash_with_route = match planner.plan(&input_with_route).unwrap() {
            ConfigPlan::Update { config_hash, .. } => config_hash,
            ConfigPlan::NoOp { .. } => panic!("expected Update"),
        };

        assert_ne!(
            hash_empty, hash_with_route,
            "different states must produce different hashes"
        );
    }
}
