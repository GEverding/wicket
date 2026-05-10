//! Pure attachment and reference-resolution planner for Gateway listeners.
//!
//! # Overview
//!
//! This module answers the question: *which routes attach to which Gateway
//! listeners, and why?*  It is a pure, synchronous planner -- no I/O, no async,
//! no side effects.  Given the same inputs it always produces the same output.
//!
//! The output ([`AttachmentPlan`]) is designed to be consumed by two downstream
//! consumers:
//!
//! 1. **Runtime planner** (`bd-rgw`) -- uses `listener_summaries` to populate
//!    `ListenerStatusIntent.attached_routes` in the `GatewayRuntimePlan`.
//! 2. **Status writer** -- uses `route_results` to write per-route
//!    `RouteParentStatus` conditions (`Accepted`, `ResolvedRefs`).
//!
//! # What is checked
//!
//! For each route that references this Gateway (via `spec.parentRefs`):
//!
//! - **parentRef attachment** -- does the parentRef point to a known listener
//!   (by `sectionName` and/or `port`) or to the Gateway as a whole?
//! - **Protocol compatibility** -- does the route kind match the listener
//!   protocol?  (HTTPRoute -> HTTP/HTTPS, TCPRoute -> TCP, TLSRoute -> TLS)
//! - **Hostname compatibility** -- for HTTP and TLS listeners, does at least
//!   one route hostname intersect with the listener hostname?
//! - **`AllowedRoutes` namespace filtering** -- `Same`, `All`, or `Selector`.
//!   For `Selector`, both `matchLabels` and `matchExpressions` are evaluated
//!   against the namespace labels supplied in the snapshot.  Supported
//!   `matchExpressions` operators: `In`, `NotIn`, `Exists`, `DoesNotExist`.
//!   An unrecognised operator is denied conservatively.  When namespace labels
//!   are absent the result is `NotAllowedByListenerNamespacePolicy` (safe
//!   denial).
//! - **`AllowedRoutes` kind filtering** -- if the listener specifies
//!   `allowedRoutes.kinds`, the route kind must appear in that list.
//! - **Cross-namespace `ReferenceGrant` checks** -- when a route's backend
//!   `BackendRef` references a `Service` (core group, `""`) in a different
//!   namespace, a `ReferenceGrant` in the target namespace must permit it.
//!   Both `group` and `kind` are checked so non-core refs are not
//!   misclassified.  Routes with unresolved cross-namespace backend refs are
//!   marked `RefNotPermitted` rather than `Attached`.
//!
//! # Determinism
//!
//! All output collections are sorted by a stable key (`namespace/name` or
//! listener name) before being returned.  This ensures the planner produces
//! identical output for identical store contents regardless of `HashMap`
//! iteration order.
//!
//! # Attached-routes counting
//!
//! `ListenerAttachmentSummary.attached_routes` counts **unique routes** (by
//! `namespace/name`) that are attached to a listener.  A route with duplicate
//! parentRefs targeting the same listener is counted only once.

use std::collections::{BTreeMap, HashMap, HashSet};

use crate::crds::{
    AllowedRoutes, FromNamespaces, Gateway, HTTPRoute, LabelSelector, ProtocolType, TCPRoute,
    TLSRoute,
};
use crate::reconcilers::contracts::{PlanError, RouteGroupKind};
use crate::reconcilers::store::PlannerSnapshot;

// ─────────────────────────────────────────────────────────────────────────────
// Gateway API group constant
// ─────────────────────────────────────────────────────────────────────────────

const GATEWAY_API_GROUP: &str = "gateway.networking.k8s.io";

// ─────────────────────────────────────────────────────────────────────────────
// Planner input
// ─────────────────────────────────────────────────────────────────────────────

/// All inputs required to plan route attachment for a single Gateway.
///
/// The planner does not read from the Kubernetes API.  All inputs arrive here.
#[derive(Debug, Clone)]
pub struct AttachmentPlanInput {
    /// Namespace of the Gateway being planned.
    pub gateway_namespace: String,
    /// Name of the Gateway being planned.
    pub gateway_name: String,
    /// `.metadata.generation` of the Gateway at plan time.
    /// Stored in each `RouteAttachmentResult` as `observed_generation`.
    pub gateway_generation: i64,
    /// Consistent snapshot of all store contents.
    pub snapshot: PlannerSnapshot,
}

// ─────────────────────────────────────────────────────────────────────────────
// Route kind tag
// ─────────────────────────────────────────────────────────────────────────────

/// The kind of a route that was evaluated.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum RouteKind {
    HTTPRoute,
    TCPRoute,
    TLSRoute,
}

impl RouteKind {
    /// Returns the Gateway API kind string.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::HTTPRoute => "HTTPRoute",
            Self::TCPRoute => "TCPRoute",
            Self::TLSRoute => "TLSRoute",
        }
    }

    /// Returns the `RouteGroupKind` for this route kind.
    pub fn to_route_group_kind(&self) -> RouteGroupKind {
        RouteGroupKind {
            group: GATEWAY_API_GROUP.to_string(),
            kind: self.as_str().to_string(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Attachment status
// ─────────────────────────────────────────────────────────────────────────────

/// The outcome of evaluating one (route, parentRef, listener) triple.
///
/// This maps directly to the Gateway API `Accepted` and `ResolvedRefs`
/// condition reasons that the status writer will emit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttachmentStatus {
    /// The route is attached to the listener.  All checks passed.
    Attached,

    /// The parentRef `sectionName` or `port` does not match any listener on
    /// this Gateway.
    NoMatchingParent,

    /// The route kind is not compatible with the listener protocol.
    ///
    /// E.g., an HTTPRoute referencing a TCP listener.
    NotAllowedByListenerProtocol,

    /// The route's namespace is not allowed by the listener's `AllowedRoutes`
    /// namespace policy.
    NotAllowedByListenerNamespacePolicy,

    /// The route kind is not in the listener's `AllowedRoutes.kinds` list.
    NotAllowedByListenerKindPolicy,

    /// No route hostname intersects with the listener hostname.
    ///
    /// Applies to HTTP/HTTPS and TLS listeners that carry a hostname.
    NoMatchingListenerHostname,

    /// A cross-namespace backend `BackendRef` is not covered by any
    /// `ReferenceGrant` in the target namespace.
    ///
    /// The route is otherwise accepted by the listener but cannot be fully
    /// resolved.  The status writer should emit `ResolvedRefs=False` with
    /// reason `RefNotPermitted`.
    RefNotPermitted {
        /// Namespace of the route that holds the unresolved ref.
        route_namespace: String,
        /// Namespace of the target backend.
        target_namespace: String,
        /// Name of the target backend.
        target_name: String,
    },

    /// A core `Service` backend ref points at a Service that does not exist.
    ///
    /// This keeps the route attached/accepted while allowing `ResolvedRefs` to
    /// report `False` for missing same-namespace Services.
    BackendNotFound {
        /// Namespace of the route that holds the unresolved ref.
        route_namespace: String,
        /// Namespace of the target backend.
        target_namespace: String,
        /// Name of the target backend.
        target_name: String,
    },
}

impl AttachmentStatus {
    /// Returns `true` if the route is considered attached to the listener.
    ///
    /// A route is attached when it passes all listener-level checks.
    /// `RefNotPermitted` is still counted as attached at the listener level
    /// (the route is accepted) but the status writer must also emit a
    /// `ResolvedRefs=False` condition.
    #[must_use]
    pub fn is_attached(&self) -> bool {
        matches!(
            self,
            Self::Attached | Self::RefNotPermitted { .. } | Self::BackendNotFound { .. }
        )
    }

    /// Returns the Gateway API reason string for the `Accepted` condition.
    #[must_use]
    pub fn accepted_reason(&self) -> &'static str {
        match self {
            Self::Attached | Self::RefNotPermitted { .. } | Self::BackendNotFound { .. } => {
                "Accepted"
            }
            Self::NoMatchingParent => "NoMatchingParent",
            Self::NotAllowedByListenerProtocol => "NotAllowedByListenerProtocol",
            Self::NotAllowedByListenerNamespacePolicy => "NotAllowedByListenerNamespacePolicy",
            Self::NotAllowedByListenerKindPolicy => "NotAllowedByListenerKindPolicy",
            Self::NoMatchingListenerHostname => "NoMatchingListenerHostname",
        }
    }

    /// Returns the Gateway API reason string for the `ResolvedRefs` condition,
    /// if applicable.
    ///
    /// Returns `None` when `ResolvedRefs` should be `True` (no ref issues).
    #[must_use]
    pub fn resolved_refs_reason(&self) -> Option<&'static str> {
        match self {
            Self::RefNotPermitted { .. } => Some("RefNotPermitted"),
            Self::BackendNotFound { .. } => Some("BackendNotFound"),
            _ => None,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Per-route result
// ─────────────────────────────────────────────────────────────────────────────

/// The attachment result for one route with respect to one parentRef.
///
/// A single route may have multiple parentRefs (referencing different Gateways
/// or different listeners on the same Gateway).  Each parentRef produces one
/// `RouteAttachmentResult`.
///
/// `parent_ref_section_name` and `parent_ref_port` carry the identity of the
/// parentRef that produced this result.  Downstream status writers use these
/// to emit the correct `RouteParentStatus` entry and to deduplicate results
/// when a route has multiple parentRefs targeting the same listener.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteAttachmentResult {
    /// Namespace of the route.
    pub route_namespace: String,
    /// Name of the route.
    pub route_name: String,
    /// Kind of the route.
    pub route_kind: RouteKind,
    /// The listener name this result applies to, if the parentRef specified a
    /// `sectionName`.  `None` means the parentRef targeted the Gateway as a
    /// whole (all listeners).
    pub listener_name: Option<String>,
    /// The `sectionName` from the parentRef that produced this result.
    /// Matches `listener_name` when present; `None` for Gateway-wide refs.
    pub parent_ref_section_name: Option<String>,
    /// The `port` from the parentRef that produced this result, if any.
    pub parent_ref_port: Option<u16>,
    /// The attachment outcome.
    pub status: AttachmentStatus,
    /// The Gateway `.metadata.generation` at plan time.
    /// The status writer sets `observedGeneration` to this value.
    pub observed_generation: i64,
}

// ─────────────────────────────────────────────────────────────────────────────
// Per-listener summary
// ─────────────────────────────────────────────────────────────────────────────

/// Aggregated attachment summary for one listener.
///
/// Consumed by the runtime planner to populate `ListenerStatusIntent` and by
/// the status writer to set `attachedRoutes` on the Gateway listener status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListenerAttachmentSummary {
    /// Listener name (matches `Gateway.spec.listeners[*].name`).
    pub listener_name: String,
    /// Number of **unique routes** (by `namespace/name`) that are attached to
    /// this listener.  A route with duplicate parentRefs targeting the same
    /// listener is counted only once.
    pub attached_routes: u32,
    /// Route group/kind pairs that this listener supports, derived from the
    /// listener protocol.
    pub supported_kinds: Vec<RouteGroupKind>,
    /// Whether the listener itself is accepted (protocol is supported).
    pub listener_accepted: bool,
    /// Reason for listener rejection, if `listener_accepted` is false.
    pub listener_rejection_reason: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Planner output
// ─────────────────────────────────────────────────────────────────────────────

/// The full attachment plan for one Gateway.
///
/// This is the output of [`AttachmentPlanner::plan`].  It is consumed by:
/// - The runtime planner (`bd-rgw`) to populate `ListenerStatusIntent` counts.
/// - The status writer to emit per-route `RouteParentStatus` conditions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachmentPlan {
    /// Gateway namespace.
    pub gateway_namespace: String,
    /// Gateway name.
    pub gateway_name: String,
    /// Gateway `.metadata.generation` at plan time.
    pub gateway_generation: i64,

    /// Per-route attachment results, sorted by `(route_namespace, route_name,
    /// route_kind, listener_name, parent_ref_port)` for deterministic output.
    pub route_results: Vec<RouteAttachmentResult>,

    /// Per-listener attachment summaries, sorted by `listener_name`.
    pub listener_summaries: Vec<ListenerAttachmentSummary>,
}

impl AttachmentPlan {
    /// Returns the `ListenerAttachmentSummary` for the given listener name.
    #[must_use]
    pub fn listener_summary(&self, listener_name: &str) -> Option<&ListenerAttachmentSummary> {
        self.listener_summaries
            .iter()
            .find(|s| s.listener_name == listener_name)
    }

    /// Returns all route results for the given listener name.
    ///
    /// Includes results where `listener_name` is `None` (parentRef targeted
    /// the Gateway as a whole) only when `include_gateway_wide` is `true`.
    #[must_use]
    pub fn results_for_listener(
        &self,
        listener_name: &str,
        include_gateway_wide: bool,
    ) -> Vec<&RouteAttachmentResult> {
        self.route_results
            .iter()
            .filter(|r| match &r.listener_name {
                Some(ln) => ln == listener_name,
                None => include_gateway_wide,
            })
            .collect()
    }

    /// Returns the attachment result for a specific route / parentRef combination.
    ///
    /// This is the targeted query used by the HTTPRoute status writer to look up
    /// the planner outcome for a single `(route_namespace, route_name,
    /// section_name, port)` tuple.
    ///
    /// `section_name` **must** be `Some` — callers that have a gateway-wide
    /// parentRef (no `sectionName`) should not call this method; the planner
    /// result for gateway-wide refs is ambiguous across multiple listeners and
    /// the status writer falls back to the existing flat `Accepted=True` path.
    ///
    /// When the planner produced multiple results for the same parentRef (which
    /// can happen if the same `sectionName` appears more than once in the
    /// Gateway spec — an invalid Gateway, but defensively handled), the first
    /// match is returned.
    #[must_use]
    pub fn result_for_route_parent_ref(
        &self,
        route_namespace: &str,
        route_name: &str,
        section_name: &str,
        port: Option<u16>,
    ) -> Option<&RouteAttachmentResult> {
        self.route_results.iter().find(|r| {
            r.route_namespace == route_namespace
                && r.route_name == route_name
                && r.parent_ref_section_name.as_deref() == Some(section_name)
                && r.parent_ref_port == port
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Planner
// ─────────────────────────────────────────────────────────────────────────────

/// Pure attachment and reference-resolution planner.
///
/// Implements the [`crate::reconcilers::contracts::Planner`] contract:
/// - No I/O, no async, no side effects.
/// - Deterministic: same inputs always produce the same plan.
/// - Returns `Err(PlanError)` for invalid or incomplete inputs; never panics.
pub struct AttachmentPlanner;

impl AttachmentPlanner {
    /// Compute the attachment plan for the given input.
    ///
    /// # Errors
    ///
    /// Returns `PlanError::MissingField` when the Gateway is not found in the
    /// snapshot.
    pub fn plan(&self, input: &AttachmentPlanInput) -> Result<AttachmentPlan, PlanError> {
        let snapshot = &input.snapshot;

        // ── 1. Resolve the Gateway ────────────────────────────────────────────
        let gateway = snapshot
            .gateway(&input.gateway_namespace, &input.gateway_name)
            .ok_or(PlanError::MissingField {
                field: "gateway (not found in snapshot)",
            })?;

        // ── 2. Build per-listener unique-route sets (for dedup counting) ──────
        // Key: listener_name -> HashSet<"namespace/name"> of attached routes.
        let mut listener_attached: HashMap<String, HashSet<String>> = HashMap::new();
        for l in &gateway.spec.listeners {
            listener_attached.insert(l.name.clone(), HashSet::new());
        }

        // ── 3. Evaluate all routes that reference this Gateway ─────────────────
        let mut route_results: Vec<RouteAttachmentResult> = Vec::new();

        // HTTPRoutes
        let http_routes =
            snapshot.http_routes_for_gateway(&input.gateway_namespace, &input.gateway_name);
        for route in http_routes {
            let route_ns = route
                .metadata
                .namespace
                .as_deref()
                .unwrap_or("default")
                .to_string();
            let route_name = route.metadata.name.as_deref().unwrap_or("").to_string();
            let route_key = format!("{route_ns}/{route_name}");

            for parent_ref in &route.spec.parent_refs {
                if !parent_ref_targets_gateway(
                    &route_ns,
                    parent_ref,
                    &input.gateway_namespace,
                    &input.gateway_name,
                ) {
                    continue;
                }

                let results = evaluate_http_route_attachment(
                    gateway,
                    &route_ns,
                    &route_name,
                    ParentRefKey {
                        section_name: parent_ref.section_name.as_deref(),
                        port: parent_ref.port,
                    },
                    snapshot,
                    route,
                    input.gateway_generation,
                );
                for r in &results {
                    if r.status.is_attached() {
                        if let Some(ln) = &r.listener_name {
                            if let Some(set) = listener_attached.get_mut(ln.as_str()) {
                                set.insert(route_key.clone());
                            }
                        } else {
                            // Gateway-wide parentRef: count against all compatible listeners.
                            for l in &gateway.spec.listeners {
                                if is_protocol_compatible_http(&l.protocol) {
                                    if let Some(set) = listener_attached.get_mut(&l.name) {
                                        set.insert(route_key.clone());
                                    }
                                }
                            }
                        }
                    }
                }
                route_results.extend(results);
            }
        }

        // TCPRoutes
        let tcp_routes =
            snapshot.tcp_routes_for_gateway(&input.gateway_namespace, &input.gateway_name);
        for route in tcp_routes {
            let route_ns = route
                .metadata
                .namespace
                .as_deref()
                .unwrap_or("default")
                .to_string();
            let route_name = route.metadata.name.as_deref().unwrap_or("").to_string();
            let route_key = format!("{route_ns}/{route_name}");

            for parent_ref in &route.spec.parent_refs {
                if !parent_ref_targets_gateway(
                    &route_ns,
                    parent_ref,
                    &input.gateway_namespace,
                    &input.gateway_name,
                ) {
                    continue;
                }

                let results = evaluate_tcp_route_attachment(
                    gateway,
                    &route_ns,
                    &route_name,
                    ParentRefKey {
                        section_name: parent_ref.section_name.as_deref(),
                        port: parent_ref.port,
                    },
                    snapshot,
                    route,
                    input.gateway_generation,
                );
                for r in &results {
                    if r.status.is_attached() {
                        if let Some(ln) = &r.listener_name {
                            if let Some(set) = listener_attached.get_mut(ln.as_str()) {
                                set.insert(route_key.clone());
                            }
                        } else {
                            for l in &gateway.spec.listeners {
                                if is_protocol_compatible_tcp(&l.protocol) {
                                    if let Some(set) = listener_attached.get_mut(&l.name) {
                                        set.insert(route_key.clone());
                                    }
                                }
                            }
                        }
                    }
                }
                route_results.extend(results);
            }
        }

        // TLSRoutes
        let tls_routes =
            snapshot.tls_routes_for_gateway(&input.gateway_namespace, &input.gateway_name);
        for route in tls_routes {
            let route_ns = route
                .metadata
                .namespace
                .as_deref()
                .unwrap_or("default")
                .to_string();
            let route_name = route.metadata.name.as_deref().unwrap_or("").to_string();
            let route_key = format!("{route_ns}/{route_name}");

            for parent_ref in &route.spec.parent_refs {
                if !parent_ref_targets_gateway(
                    &route_ns,
                    parent_ref,
                    &input.gateway_namespace,
                    &input.gateway_name,
                ) {
                    continue;
                }

                let results = evaluate_tls_route_attachment(
                    gateway,
                    &route_ns,
                    &route_name,
                    ParentRefKey {
                        section_name: parent_ref.section_name.as_deref(),
                        port: parent_ref.port,
                    },
                    snapshot,
                    route,
                    input.gateway_generation,
                );
                for r in &results {
                    if r.status.is_attached() {
                        if let Some(ln) = &r.listener_name {
                            if let Some(set) = listener_attached.get_mut(ln.as_str()) {
                                set.insert(route_key.clone());
                            }
                        } else {
                            for l in &gateway.spec.listeners {
                                if is_protocol_compatible_tls(&l.protocol) {
                                    if let Some(set) = listener_attached.get_mut(&l.name) {
                                        set.insert(route_key.clone());
                                    }
                                }
                            }
                        }
                    }
                }
                route_results.extend(results);
            }
        }

        // ── 4. Sort route_results for determinism ─────────────────────────────
        route_results.sort_by(|a, b| {
            (
                &a.route_namespace,
                &a.route_name,
                &a.route_kind,
                &a.listener_name,
                &a.parent_ref_port,
            )
                .cmp(&(
                    &b.route_namespace,
                    &b.route_name,
                    &b.route_kind,
                    &b.listener_name,
                    &b.parent_ref_port,
                ))
        });

        // ── 5. Build listener summaries ───────────────────────────────────────
        let mut listener_summaries: Vec<ListenerAttachmentSummary> = gateway
            .spec
            .listeners
            .iter()
            .map(|l| {
                let (accepted, rejection_reason, supported_kinds) =
                    listener_acceptance(&l.protocol);
                let count = listener_attached
                    .get(&l.name)
                    .map(|s| s.len() as u32)
                    .unwrap_or(0);
                ListenerAttachmentSummary {
                    listener_name: l.name.clone(),
                    attached_routes: count,
                    supported_kinds,
                    listener_accepted: accepted,
                    listener_rejection_reason: rejection_reason,
                }
            })
            .collect();

        // Sort by listener name for determinism.
        listener_summaries.sort_by(|a, b| a.listener_name.cmp(&b.listener_name));

        Ok(AttachmentPlan {
            gateway_namespace: input.gateway_namespace.clone(),
            gateway_name: input.gateway_name.clone(),
            gateway_generation: input.gateway_generation,
            route_results,
            listener_summaries,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal: parentRef targeting
// ─────────────────────────────────────────────────────────────────────────────

/// Returns `true` if `parent_ref` targets the given Gateway.
fn parent_ref_targets_gateway(
    route_namespace: &str,
    parent_ref: &crate::crds::ParentReference,
    gateway_namespace: &str,
    gateway_name: &str,
) -> bool {
    let group_ok = parent_ref.group.is_empty() || parent_ref.group == GATEWAY_API_GROUP;
    let kind_ok = parent_ref.kind == "Gateway";
    let ns_ok = parent_ref.namespace.as_deref().unwrap_or(route_namespace) == gateway_namespace;
    let name_ok = parent_ref.name == gateway_name;
    group_ok && kind_ok && ns_ok && name_ok
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal: listener acceptance
// ─────────────────────────────────────────────────────────────────────────────

/// Returns `(accepted, rejection_reason, supported_kinds)` for a listener
/// based solely on its protocol.
fn listener_acceptance(protocol: &ProtocolType) -> (bool, Option<String>, Vec<RouteGroupKind>) {
    match protocol {
        ProtocolType::HTTP | ProtocolType::HTTPS => (
            true,
            None,
            vec![RouteGroupKind {
                group: GATEWAY_API_GROUP.to_string(),
                kind: "HTTPRoute".to_string(),
            }],
        ),
        ProtocolType::TCP => (
            true,
            None,
            vec![RouteGroupKind {
                group: GATEWAY_API_GROUP.to_string(),
                kind: "TCPRoute".to_string(),
            }],
        ),
        ProtocolType::TLS => (
            true,
            None,
            vec![RouteGroupKind {
                group: GATEWAY_API_GROUP.to_string(),
                kind: "TLSRoute".to_string(),
            }],
        ),
        ProtocolType::UDP => (
            false,
            Some(
                "UnsupportedProtocol: UDP listeners are not supported by this controller"
                    .to_string(),
            ),
            vec![],
        ),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal: protocol compatibility predicates
// ─────────────────────────────────────────────────────────────────────────────

fn is_protocol_compatible_http(protocol: &ProtocolType) -> bool {
    matches!(protocol, ProtocolType::HTTP | ProtocolType::HTTPS)
}

fn is_protocol_compatible_tcp(protocol: &ProtocolType) -> bool {
    matches!(protocol, ProtocolType::TCP)
}

fn is_protocol_compatible_tls(protocol: &ProtocolType) -> bool {
    matches!(protocol, ProtocolType::TLS)
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal: hostname compatibility
// ─────────────────────────────────────────────────────────────────────────────

/// Returns `true` if the route hostnames are compatible with the listener
/// hostname per the Gateway API spec (GEP-1364).
///
/// Rules:
/// - If the listener has no hostname, all route hostnames are compatible.
/// - If the route has no hostnames, it is compatible with any listener hostname.
/// - Otherwise, at least one route hostname must intersect with the listener
///   hostname.  Intersection means:
///   - Exact match, OR
///   - The listener hostname is a wildcard (`*.example.com`) and the route
///     hostname is a subdomain of it, OR
///   - The route hostname is a wildcard and the listener hostname is a
///     subdomain of it.
///
/// TCPRoute has no hostname concept; always returns `true`.
fn hostnames_compatible(listener_hostname: Option<&str>, route_hostnames: &[String]) -> bool {
    let listener_host = match listener_hostname {
        None | Some("") => return true,
        Some(h) => h,
    };

    if route_hostnames.is_empty() {
        return true;
    }

    route_hostnames
        .iter()
        .any(|rh| hostname_intersects(listener_host, rh.as_str()))
}

/// Returns `true` if two hostnames intersect (either can match the other).
///
/// Wildcard matching requires a proper dot boundary: `*.example.com` matches
/// `api.example.com` (the label before the suffix is separated by a dot) but
/// NOT `fooexample.com` (no dot boundary before the shared suffix).
fn hostname_intersects(a: &str, b: &str) -> bool {
    if a == b {
        return true;
    }
    // a is wildcard, b must be a proper subdomain (one label + dot + suffix).
    if let Some(a_suffix) = a.strip_prefix("*.") {
        if !b.starts_with("*.") {
            // b must be of the form "<label>.<a_suffix>" -- require the dot.
            let expected_prefix = format!(".{a_suffix}");
            if let Some(label) = b.strip_suffix(expected_prefix.as_str()) {
                return !label.is_empty() && !label.contains('.');
            }
        }
    }
    // b is wildcard, a must be a proper subdomain (one label + dot + suffix).
    if let Some(b_suffix) = b.strip_prefix("*.") {
        if !a.starts_with("*.") {
            let expected_prefix = format!(".{b_suffix}");
            if let Some(label) = a.strip_suffix(expected_prefix.as_str()) {
                return !label.is_empty() && !label.contains('.');
            }
        }
    }
    false
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal: AllowedRoutes checks
// ─────────────────────────────────────────────────────────────────────────────

/// Returns `true` if the route's namespace is allowed by the listener's
/// `AllowedRoutes.namespaces` policy.
///
/// - `None` (no `allowedRoutes`) defaults to `Same` per the Gateway API spec.
/// - `All` allows any namespace.
/// - `Same` allows only the Gateway's own namespace.
/// - `Selector` evaluates `matchLabels` and `matchExpressions` against the
///   namespace labels in the snapshot.  When namespace labels are absent for
///   the route namespace the result is `false` (safe denial).
fn namespace_allowed(
    allowed_routes: Option<&AllowedRoutes>,
    gateway_namespace: &str,
    route_namespace: &str,
    namespace_labels: &HashMap<String, BTreeMap<String, String>>,
) -> bool {
    let ns_config = allowed_routes.and_then(|ar| ar.namespaces.as_ref());

    let from = ns_config
        .map(|ns| &ns.from)
        .unwrap_or(&FromNamespaces::Same);

    match from {
        FromNamespaces::All => true,
        FromNamespaces::Same => route_namespace == gateway_namespace,
        FromNamespaces::Selector => {
            let selector = ns_config.and_then(|ns| ns.selector.as_ref());
            match selector {
                None => false, // Selector specified but no selector expression -- deny.
                Some(sel) => {
                    let mut labels = namespace_labels
                        .get(route_namespace)
                        .cloned()
                        .unwrap_or_default();
                    labels.insert(
                        "kubernetes.io/metadata.name".to_string(),
                        route_namespace.to_string(),
                    );
                    label_selector_matches(sel, &labels)
                }
            }
        }
    }
}

/// Returns `true` if the given labels satisfy the `LabelSelector`.
///
/// Both `matchLabels` (key=value equality) and `matchExpressions` are
/// evaluated.  All terms must be satisfied (logical AND).
///
/// `matchExpressions` operators:
/// - `In`           -- label key exists and its value is in the set.
/// - `NotIn`        -- label key is absent OR its value is not in the set.
/// - `Exists`       -- label key is present (any value).
/// - `DoesNotExist` -- label key is absent.
///
/// An unrecognised operator is treated as a non-match (safe denial).
fn label_selector_matches(selector: &LabelSelector, labels: &BTreeMap<String, String>) -> bool {
    // matchLabels: all key=value pairs must be present.
    if let Some(required) = &selector.match_labels {
        if !required.is_empty()
            && !required
                .iter()
                .all(|(k, v)| labels.get(k).map(|lv| lv == v).unwrap_or(false))
        {
            return false;
        }
    }

    // matchExpressions: every requirement must be satisfied.
    for req in &selector.match_expressions {
        let matched = match req.operator.as_str() {
            "In" => labels
                .get(&req.key)
                .map(|v| req.values.iter().any(|rv| rv == v))
                .unwrap_or(false),
            "NotIn" => labels
                .get(&req.key)
                .map(|v| !req.values.iter().any(|rv| rv == v))
                .unwrap_or(true), // key absent => satisfied
            "Exists" => labels.contains_key(&req.key),
            "DoesNotExist" => !labels.contains_key(&req.key),
            // Unknown operator: deny conservatively.
            _ => false,
        };
        if !matched {
            return false;
        }
    }

    true
}

/// Returns `true` if the route kind is allowed by the listener's
/// `AllowedRoutes.kinds` list.
///
/// When `kinds` is empty (or `allowedRoutes` is absent), all route kinds
/// compatible with the listener protocol are allowed.
fn kind_allowed(allowed_routes: Option<&AllowedRoutes>, route_kind: &RouteKind) -> bool {
    let kinds = allowed_routes.map(|ar| ar.kinds.as_slice()).unwrap_or(&[]);

    if kinds.is_empty() {
        // No restriction; protocol compatibility is the only gate.
        return true;
    }

    kinds.iter().any(|k| {
        let group_ok = k.group.is_empty() || k.group == GATEWAY_API_GROUP;
        let kind_ok = k.kind == route_kind.as_str();
        group_ok && kind_ok
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal: cross-namespace backend ref check
// ─────────────────────────────────────────────────────────────────────────────

/// Returns the first unresolved core `Service` backend ref, if any.
///
/// Same-namespace missing Services yield `BackendNotFound`; cross-namespace
/// refs without a matching `ReferenceGrant` yield `RefNotPermitted`.
/// Non-core refs are skipped.
///
/// A backend ref is treated as a core `Service` ref when:
/// - `kind` is `"Service"` or empty (the Gateway API default), AND
/// - `group` is `""` (core group) or empty.
///
/// Non-core refs (e.g., custom resource backends) are skipped -- they are not
/// validated here.
///
/// `route_kind_str` is the Gateway API kind string for the route (e.g.
/// `"HTTPRoute"`) and is used to match the `from.kind` field of the grant.
fn first_unresolved_backend_ref_for_kind(
    route_namespace: &str,
    route_kind_str: &str,
    backend_refs: &[crate::crds::BackendRef],
    snapshot: &PlannerSnapshot,
) -> Option<AttachmentStatus> {
    for br in backend_refs {
        // Only check core-group Service refs.
        let kind_is_service = br.kind.is_empty() || br.kind == "Service";
        let group_is_core = br.group.is_empty();
        if !kind_is_service || !group_is_core {
            continue;
        }

        let target_ns = match br.namespace.as_deref() {
            Some(ns) => ns,
            None => route_namespace,
        };

        let target_key =
            crate::reconcilers::config_generator::GatewayState::key(target_ns, &br.name);

        if target_ns == route_namespace && !snapshot.service_endpoints.contains_key(&target_key) {
            return Some(AttachmentStatus::BackendNotFound {
                route_namespace: route_namespace.to_string(),
                target_namespace: target_ns.to_string(),
                target_name: br.name.clone(),
            });
        }

        if target_ns == route_namespace {
            continue;
        }

        let grants = snapshot.reference_grants_in_namespace(target_ns);
        let permitted = grants.iter().any(|g| {
            g.allows_service_reference(
                GATEWAY_API_GROUP,
                route_kind_str,
                route_namespace,
                Some(br.name.as_str()),
            )
        });

        if !permitted {
            return Some(AttachmentStatus::RefNotPermitted {
                route_namespace: route_namespace.to_string(),
                target_namespace: target_ns.to_string(),
                target_name: br.name.clone(),
            });
        }
    }
    None
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal: per-route-kind attachment evaluation
// ─────────────────────────────────────────────────────────────────────────────

/// The identity fields from a `parentRef` that are relevant to listener
/// matching.  Bundled to keep per-route-kind evaluate functions under the
/// clippy `too_many_arguments` limit.
struct ParentRefKey<'a> {
    section_name: Option<&'a str>,
    port: Option<u16>,
}

/// Evaluate attachment for one HTTPRoute parentRef against all matching
/// listeners on the Gateway.
///
/// Returns one `RouteAttachmentResult` per listener that was evaluated.
fn evaluate_http_route_attachment(
    gateway: &Gateway,
    route_namespace: &str,
    route_name: &str,
    parent_ref: ParentRefKey<'_>,
    snapshot: &PlannerSnapshot,
    route: &HTTPRoute,
    observed_generation: i64,
) -> Vec<RouteAttachmentResult> {
    // Collect all backend refs for cross-namespace grant checking.
    let all_backend_refs: Vec<crate::crds::BackendRef> = route
        .spec
        .rules
        .iter()
        .flat_map(|r| r.backend_refs.iter().map(|br| br.backend_ref.clone()))
        .collect();

    evaluate_route_attachment_inner(RouteEvalContext {
        gateway,
        route_namespace,
        route_name,
        route_kind: RouteKind::HTTPRoute,
        route_hostnames: &route.spec.hostnames,
        section_name: parent_ref.section_name,
        parent_ref_port: parent_ref.port,
        snapshot,
        backend_refs: &all_backend_refs,
        observed_generation,
        protocol_compat: is_protocol_compatible_http,
        check_hostname_compat: true,
    })
}

/// Evaluate attachment for one TCPRoute parentRef.
fn evaluate_tcp_route_attachment(
    gateway: &Gateway,
    route_namespace: &str,
    route_name: &str,
    parent_ref: ParentRefKey<'_>,
    snapshot: &PlannerSnapshot,
    route: &TCPRoute,
    observed_generation: i64,
) -> Vec<RouteAttachmentResult> {
    let all_backend_refs: Vec<crate::crds::BackendRef> = route
        .spec
        .rules
        .iter()
        .flat_map(|r| r.backend_refs.iter().cloned())
        .collect();

    evaluate_route_attachment_inner(RouteEvalContext {
        gateway,
        route_namespace,
        route_name,
        route_kind: RouteKind::TCPRoute,
        route_hostnames: &[],
        section_name: parent_ref.section_name,
        parent_ref_port: parent_ref.port,
        snapshot,
        backend_refs: &all_backend_refs,
        observed_generation,
        protocol_compat: is_protocol_compatible_tcp,
        check_hostname_compat: false,
    })
}

/// Evaluate attachment for one TLSRoute parentRef.
fn evaluate_tls_route_attachment(
    gateway: &Gateway,
    route_namespace: &str,
    route_name: &str,
    parent_ref: ParentRefKey<'_>,
    snapshot: &PlannerSnapshot,
    route: &TLSRoute,
    observed_generation: i64,
) -> Vec<RouteAttachmentResult> {
    let all_backend_refs: Vec<crate::crds::BackendRef> = route
        .spec
        .rules
        .iter()
        .flat_map(|r| r.backend_refs.iter().cloned())
        .collect();

    evaluate_route_attachment_inner(RouteEvalContext {
        gateway,
        route_namespace,
        route_name,
        route_kind: RouteKind::TLSRoute,
        route_hostnames: &route.spec.hostnames,
        section_name: parent_ref.section_name,
        parent_ref_port: parent_ref.port,
        snapshot,
        backend_refs: &all_backend_refs,
        observed_generation,
        protocol_compat: is_protocol_compatible_tls,
        check_hostname_compat: true,
    })
}

/// Context bundle for [`evaluate_route_attachment_inner`].
///
/// Bundles the per-route inputs that would otherwise push the function over
/// the clippy `too_many_arguments` limit.
struct RouteEvalContext<'a> {
    gateway: &'a Gateway,
    route_namespace: &'a str,
    route_name: &'a str,
    route_kind: RouteKind,
    /// Hostnames declared on the route spec (empty for TCPRoute).
    route_hostnames: &'a [String],
    section_name: Option<&'a str>,
    /// Port from the parentRef, if any.
    parent_ref_port: Option<u16>,
    snapshot: &'a PlannerSnapshot,
    backend_refs: &'a [crate::crds::BackendRef],
    observed_generation: i64,
    /// Returns `true` when the listener protocol is compatible with this route kind.
    protocol_compat: fn(&ProtocolType) -> bool,
    /// Whether to evaluate listener/route hostname compatibility.
    check_hostname_compat: bool,
}

/// Core attachment evaluation logic shared across all route kinds.
fn evaluate_route_attachment_inner(ctx: RouteEvalContext<'_>) -> Vec<RouteAttachmentResult> {
    let RouteEvalContext {
        gateway,
        route_namespace,
        route_name,
        route_kind,
        route_hostnames,
        section_name,
        parent_ref_port,
        snapshot,
        backend_refs,
        observed_generation,
        protocol_compat,
        check_hostname_compat,
    } = ctx;
    let gateway_namespace = gateway.metadata.namespace.as_deref().unwrap_or("default");

    // Determine which listeners to evaluate.
    //
    // When `section_name` is set, find the listener by name AND verify that
    // `parent_ref_port` (if set) matches the listener port.
    // When `section_name` is absent, evaluate all listeners (port filtering
    // still applies per-listener when `parent_ref_port` is set).
    let listeners_to_check: Vec<&crate::crds::Listener> = match section_name {
        Some(sn) => {
            match gateway.spec.listeners.iter().find(|l| l.name == sn) {
                Some(l) => {
                    // If parentRef.port is set it must match the listener port.
                    if let Some(ref_port) = parent_ref_port {
                        if l.port != ref_port {
                            return vec![RouteAttachmentResult {
                                route_namespace: route_namespace.to_string(),
                                route_name: route_name.to_string(),
                                route_kind,
                                listener_name: Some(sn.to_string()),
                                parent_ref_section_name: Some(sn.to_string()),
                                parent_ref_port,
                                status: AttachmentStatus::NoMatchingParent,
                                observed_generation,
                            }];
                        }
                    }
                    vec![l]
                }
                None => {
                    return vec![RouteAttachmentResult {
                        route_namespace: route_namespace.to_string(),
                        route_name: route_name.to_string(),
                        route_kind,
                        listener_name: Some(sn.to_string()),
                        parent_ref_section_name: Some(sn.to_string()),
                        parent_ref_port,
                        status: AttachmentStatus::NoMatchingParent,
                        observed_generation,
                    }];
                }
            }
        }
        None => {
            // Gateway-wide ref: filter by port when parentRef.port is set.
            gateway
                .spec
                .listeners
                .iter()
                .filter(|l| parent_ref_port.is_none_or(|p| l.port == p))
                .collect()
        }
    };

    // If a port-only parentRef matched no listeners, emit NoMatchingParent.
    if listeners_to_check.is_empty() {
        return vec![RouteAttachmentResult {
            route_namespace: route_namespace.to_string(),
            route_name: route_name.to_string(),
            route_kind,
            listener_name: None,
            parent_ref_section_name: None,
            parent_ref_port,
            status: AttachmentStatus::NoMatchingParent,
            observed_generation,
        }];
    }

    let mut results = Vec::new();

    for listener in listeners_to_check {
        // ── Protocol compatibility ────────────────────────────────────────────
        if !protocol_compat(&listener.protocol) {
            results.push(RouteAttachmentResult {
                route_namespace: route_namespace.to_string(),
                route_name: route_name.to_string(),
                route_kind: route_kind.clone(),
                listener_name: Some(listener.name.clone()),
                parent_ref_section_name: section_name.map(str::to_string),
                parent_ref_port,
                status: AttachmentStatus::NotAllowedByListenerProtocol,
                observed_generation,
            });
            continue;
        }

        // ── Namespace policy ──────────────────────────────────────────────────
        if !namespace_allowed(
            listener.allowed_routes.as_ref(),
            gateway_namespace,
            route_namespace,
            &snapshot.namespace_labels,
        ) {
            results.push(RouteAttachmentResult {
                route_namespace: route_namespace.to_string(),
                route_name: route_name.to_string(),
                route_kind: route_kind.clone(),
                listener_name: Some(listener.name.clone()),
                parent_ref_section_name: section_name.map(str::to_string),
                parent_ref_port,
                status: AttachmentStatus::NotAllowedByListenerNamespacePolicy,
                observed_generation,
            });
            continue;
        }

        // ── Kind policy ───────────────────────────────────────────────────────
        if !kind_allowed(listener.allowed_routes.as_ref(), &route_kind) {
            results.push(RouteAttachmentResult {
                route_namespace: route_namespace.to_string(),
                route_name: route_name.to_string(),
                route_kind: route_kind.clone(),
                listener_name: Some(listener.name.clone()),
                parent_ref_section_name: section_name.map(str::to_string),
                parent_ref_port,
                status: AttachmentStatus::NotAllowedByListenerKindPolicy,
                observed_generation,
            });
            continue;
        }

        // ── Hostname compatibility ─────────────────────────────────────────────
        if check_hostname_compat
            && !hostnames_compatible(listener.hostname.as_deref(), route_hostnames)
        {
            results.push(RouteAttachmentResult {
                route_namespace: route_namespace.to_string(),
                route_name: route_name.to_string(),
                route_kind: route_kind.clone(),
                listener_name: Some(listener.name.clone()),
                parent_ref_section_name: section_name.map(str::to_string),
                parent_ref_port,
                status: AttachmentStatus::NoMatchingListenerHostname,
                observed_generation,
            });
            continue;
        }

        // ── Cross-namespace backend ref check ─────────────────────────────────
        if let Some(status) = first_unresolved_backend_ref_for_kind(
            route_namespace,
            route_kind.as_str(),
            backend_refs,
            snapshot,
        ) {
            results.push(RouteAttachmentResult {
                route_namespace: route_namespace.to_string(),
                route_name: route_name.to_string(),
                route_kind: route_kind.clone(),
                listener_name: Some(listener.name.clone()),
                parent_ref_section_name: section_name.map(str::to_string),
                parent_ref_port,
                status,
                observed_generation,
            });
            continue;
        }

        // ── All checks passed ─────────────────────────────────────────────────
        results.push(RouteAttachmentResult {
            route_namespace: route_namespace.to_string(),
            route_name: route_name.to_string(),
            route_kind: route_kind.clone(),
            listener_name: Some(listener.name.clone()),
            parent_ref_section_name: section_name.map(str::to_string),
            parent_ref_port,
            status: AttachmentStatus::Attached,
            observed_generation,
        });
    }

    results
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crds::{
        AllowedRoutes, BackendRef, FromNamespaces, Gateway, GatewaySpec, HTTPBackendRef, HTTPRoute,
        HTTPRouteRule, HTTPRouteSpec, LabelSelector, Listener, ParentReference, ProtocolType,
        ReferenceGrant, ReferenceGrantFrom, ReferenceGrantSpec, ReferenceGrantTo, RouteNamespaces,
        TCPRoute, TCPRouteRule, TCPRouteSpec, TLSRoute, TLSRouteRule, TLSRouteSpec,
    };
    use crate::reconcilers::store::PlannerSnapshot;
    use kube::core::ObjectMeta;
    use std::collections::{BTreeMap, HashMap, HashSet};

    // ── Snapshot builder ──────────────────────────────────────────────────────

    #[derive(Default)]
    struct SnapshotBuilder {
        gateways: HashMap<String, Gateway>,
        http_routes: HashMap<String, HTTPRoute>,
        tcp_routes: HashMap<String, TCPRoute>,
        tls_routes: HashMap<String, TLSRoute>,
        service_endpoints: HashMap<String, crate::reconcilers::config_generator::ServiceEndpoints>,
        reference_grants: HashMap<String, ReferenceGrant>,
        namespace_labels: HashMap<String, BTreeMap<String, String>>,
    }

    impl SnapshotBuilder {
        fn with_gateway(mut self, gw: Gateway) -> Self {
            let key = format!(
                "{}/{}",
                gw.metadata.namespace.as_deref().unwrap_or("default"),
                gw.metadata.name.as_deref().unwrap_or("")
            );
            self.gateways.insert(key, gw);
            self
        }

        fn with_http_route(mut self, route: HTTPRoute) -> Self {
            let key = format!(
                "{}/{}",
                route.metadata.namespace.as_deref().unwrap_or("default"),
                route.metadata.name.as_deref().unwrap_or("")
            );
            self.http_routes.insert(key, route);
            self
        }

        fn with_tcp_route(mut self, route: TCPRoute) -> Self {
            let key = format!(
                "{}/{}",
                route.metadata.namespace.as_deref().unwrap_or("default"),
                route.metadata.name.as_deref().unwrap_or("")
            );
            self.tcp_routes.insert(key, route);
            self
        }

        fn with_tls_route(mut self, route: TLSRoute) -> Self {
            let key = format!(
                "{}/{}",
                route.metadata.namespace.as_deref().unwrap_or("default"),
                route.metadata.name.as_deref().unwrap_or("")
            );
            self.tls_routes.insert(key, route);
            self
        }

        fn with_service_endpoint(mut self, namespace: &str, name: &str) -> Self {
            let key = format!("{}/{}", namespace, name);
            self.service_endpoints.insert(
                key,
                crate::reconcilers::config_generator::ServiceEndpoints {
                    namespace: namespace.to_string(),
                    name: name.to_string(),
                    endpoints: vec!["127.0.0.1:80".to_string()],
                },
            );
            self
        }

        fn with_reference_grant(mut self, grant: ReferenceGrant) -> Self {
            let key = format!(
                "{}/{}",
                grant.metadata.namespace.as_deref().unwrap_or("default"),
                grant.metadata.name.as_deref().unwrap_or("")
            );
            self.reference_grants.insert(key, grant);
            self
        }

        fn with_namespace_labels(mut self, ns: &str, labels: BTreeMap<String, String>) -> Self {
            self.namespace_labels.insert(ns.to_string(), labels);
            self
        }

        fn build(self) -> PlannerSnapshot {
            PlannerSnapshot {
                gateways: self.gateways,
                gateway_classes: HashMap::new(),
                http_routes: self.http_routes,
                tcp_routes: self.tcp_routes,
                tls_routes: self.tls_routes,
                service_endpoints: self.service_endpoints,
                tls_secrets: HashMap::new(),
                reference_grants: self.reference_grants,
                service_ref_index: HashSet::new(),
                namespace_labels: self.namespace_labels,
            }
        }
    }

    // ── CRD helpers ───────────────────────────────────────────────────────────

    fn make_gateway(namespace: &str, name: &str, listeners: Vec<Listener>) -> Gateway {
        Gateway {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some(namespace.to_string()),
                uid: Some("uid-gw".to_string()),
                generation: Some(1),
                ..Default::default()
            },
            spec: GatewaySpec {
                gateway_class_name: "wicket".to_string(),
                listeners,
                addresses: vec![],
                infrastructure: None,
            },
            status: None,
        }
    }

    fn make_listener(name: &str, port: u16, protocol: ProtocolType) -> Listener {
        Listener {
            name: name.to_string(),
            hostname: None,
            port,
            protocol,
            tls: None,
            allowed_routes: None,
        }
    }

    fn make_listener_with_hostname(
        name: &str,
        port: u16,
        protocol: ProtocolType,
        hostname: &str,
    ) -> Listener {
        Listener {
            name: name.to_string(),
            hostname: Some(hostname.to_string()),
            port,
            protocol,
            tls: None,
            allowed_routes: None,
        }
    }

    fn make_listener_with_allowed(
        name: &str,
        port: u16,
        protocol: ProtocolType,
        allowed_routes: AllowedRoutes,
    ) -> Listener {
        Listener {
            name: name.to_string(),
            hostname: None,
            port,
            protocol,
            tls: None,
            allowed_routes: Some(allowed_routes),
        }
    }

    fn make_parent_ref(gw_ns: &str, gw_name: &str, section: Option<&str>) -> ParentReference {
        ParentReference {
            group: GATEWAY_API_GROUP.to_string(),
            kind: "Gateway".to_string(),
            namespace: Some(gw_ns.to_string()),
            name: gw_name.to_string(),
            section_name: section.map(str::to_string),
            port: None,
        }
    }

    fn make_parent_ref_with_port(
        gw_ns: &str,
        gw_name: &str,
        section: Option<&str>,
        port: u16,
    ) -> ParentReference {
        ParentReference {
            group: GATEWAY_API_GROUP.to_string(),
            kind: "Gateway".to_string(),
            namespace: Some(gw_ns.to_string()),
            name: gw_name.to_string(),
            section_name: section.map(str::to_string),
            port: Some(port),
        }
    }

    fn make_http_route(
        ns: &str,
        name: &str,
        parent_refs: Vec<ParentReference>,
        backend_refs: Vec<HTTPBackendRef>,
    ) -> HTTPRoute {
        make_http_route_with_hostnames(ns, name, parent_refs, backend_refs, vec![])
    }

    fn make_http_route_with_hostnames(
        ns: &str,
        name: &str,
        parent_refs: Vec<ParentReference>,
        backend_refs: Vec<HTTPBackendRef>,
        hostnames: Vec<String>,
    ) -> HTTPRoute {
        HTTPRoute {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some(ns.to_string()),
                ..Default::default()
            },
            spec: HTTPRouteSpec {
                parent_refs,
                hostnames,
                rules: vec![HTTPRouteRule {
                    name: None,
                    matches: vec![],
                    filters: vec![],
                    backend_refs,
                    timeouts: None,
                }],
            },
            status: None,
        }
    }

    fn make_tcp_route(
        ns: &str,
        name: &str,
        parent_refs: Vec<ParentReference>,
        backend_refs: Vec<BackendRef>,
    ) -> TCPRoute {
        TCPRoute {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some(ns.to_string()),
                ..Default::default()
            },
            spec: TCPRouteSpec {
                parent_refs,
                rules: vec![TCPRouteRule {
                    name: None,
                    backend_refs,
                }],
            },
            status: None,
        }
    }

    fn make_tls_route(
        ns: &str,
        name: &str,
        parent_refs: Vec<ParentReference>,
        backend_refs: Vec<BackendRef>,
    ) -> TLSRoute {
        make_tls_route_with_hostnames(ns, name, parent_refs, backend_refs, vec![])
    }

    fn make_tls_route_with_hostnames(
        ns: &str,
        name: &str,
        parent_refs: Vec<ParentReference>,
        backend_refs: Vec<BackendRef>,
        hostnames: Vec<String>,
    ) -> TLSRoute {
        TLSRoute {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some(ns.to_string()),
                ..Default::default()
            },
            spec: TLSRouteSpec {
                parent_refs,
                hostnames,
                rules: vec![TLSRouteRule {
                    name: None,
                    backend_refs,
                }],
            },
            status: None,
        }
    }

    fn make_backend_ref(ns: Option<&str>, name: &str) -> BackendRef {
        BackendRef {
            group: "".to_string(),
            kind: "Service".to_string(),
            name: name.to_string(),
            namespace: ns.map(str::to_string),
            port: Some(80),
            weight: 1,
        }
    }

    fn make_http_backend_ref(ns: Option<&str>, name: &str) -> HTTPBackendRef {
        HTTPBackendRef {
            backend_ref: make_backend_ref(ns, name),
            filters: vec![],
        }
    }

    fn make_reference_grant(
        grant_ns: &str,
        grant_name: &str,
        from_group: &str,
        from_kind: &str,
        from_ns: &str,
        to_kind: &str,
        to_name: Option<&str>,
    ) -> ReferenceGrant {
        ReferenceGrant {
            metadata: ObjectMeta {
                name: Some(grant_name.to_string()),
                namespace: Some(grant_ns.to_string()),
                ..Default::default()
            },
            spec: ReferenceGrantSpec {
                from: vec![ReferenceGrantFrom {
                    group: from_group.to_string(),
                    kind: from_kind.to_string(),
                    namespace: from_ns.to_string(),
                }],
                to: vec![ReferenceGrantTo {
                    group: "".to_string(),
                    kind: to_kind.to_string(),
                    name: to_name.map(str::to_string),
                }],
            },
        }
    }

    fn make_input(gw_ns: &str, gw_name: &str, snapshot: PlannerSnapshot) -> AttachmentPlanInput {
        AttachmentPlanInput {
            gateway_namespace: gw_ns.to_string(),
            gateway_name: gw_name.to_string(),
            gateway_generation: 1,
            snapshot,
        }
    }

    // ── Basic attachment ──────────────────────────────────────────────────────

    #[test]
    fn http_route_attaches_to_http_listener() {
        let gw = make_gateway(
            "prod",
            "my-gw",
            vec![make_listener("http", 80, ProtocolType::HTTP)],
        );
        let route = make_http_route(
            "prod",
            "my-route",
            vec![make_parent_ref("prod", "my-gw", Some("http"))],
            vec![make_http_backend_ref(None, "my-svc")],
        );
        let snapshot = SnapshotBuilder::default()
            .with_gateway(gw)
            .with_http_route(route)
            .with_service_endpoint("prod", "my-svc")
            .build();

        let plan = AttachmentPlanner
            .plan(&make_input("prod", "my-gw", snapshot))
            .unwrap();

        assert_eq!(plan.route_results.len(), 1);
        assert_eq!(plan.route_results[0].status, AttachmentStatus::Attached);
        assert_eq!(
            plan.listener_summaries[0].attached_routes, 1,
            "listener should count one attached route"
        );
    }

    #[test]
    fn gateway_with_one_attached_route_counts_one_listener_attachment() {
        let gw = make_gateway(
            "prod",
            "my-gw",
            vec![make_listener("http", 80, ProtocolType::HTTP)],
        );
        let route = make_http_route(
            "prod",
            "route-a",
            vec![make_parent_ref("prod", "my-gw", Some("http"))],
            vec![make_http_backend_ref(None, "svc-a")],
        );
        let snapshot = SnapshotBuilder::default()
            .with_gateway(gw)
            .with_http_route(route)
            .with_service_endpoint("prod", "svc-a")
            .build();

        let plan = AttachmentPlanner
            .plan(&make_input("prod", "my-gw", snapshot))
            .unwrap();

        assert_eq!(plan.listener_summary("http").unwrap().attached_routes, 1);
    }

    #[test]
    fn gateway_with_two_attached_routes_counts_two_listener_attachments() {
        let gw = make_gateway(
            "prod",
            "my-gw",
            vec![make_listener("http", 80, ProtocolType::HTTP)],
        );
        let route_a = make_http_route(
            "prod",
            "route-a",
            vec![make_parent_ref("prod", "my-gw", Some("http"))],
            vec![make_http_backend_ref(None, "svc-a")],
        );
        let route_b = make_http_route(
            "prod",
            "route-b",
            vec![make_parent_ref("prod", "my-gw", Some("http"))],
            vec![make_http_backend_ref(None, "svc-b")],
        );
        let snapshot = SnapshotBuilder::default()
            .with_gateway(gw)
            .with_http_route(route_a)
            .with_http_route(route_b)
            .build();

        let plan = AttachmentPlanner
            .plan(&make_input("prod", "my-gw", snapshot))
            .unwrap();

        assert_eq!(plan.listener_summary("http").unwrap().attached_routes, 2);
    }

    #[test]
    fn unresolved_route_still_counts_as_attached_route() {
        let allowed = AllowedRoutes {
            namespaces: Some(RouteNamespaces {
                from: FromNamespaces::All,
                selector: None,
            }),
            kinds: vec![],
        };
        let gw = make_gateway(
            "prod",
            "my-gw",
            vec![make_listener_with_allowed(
                "http",
                80,
                ProtocolType::HTTP,
                allowed,
            )],
        );
        let route = make_http_route(
            "app-ns",
            "route-a",
            vec![make_parent_ref("prod", "my-gw", Some("http"))],
            vec![make_http_backend_ref(Some("backend-ns"), "svc-a")],
        );
        let snapshot = SnapshotBuilder::default()
            .with_gateway(gw)
            .with_http_route(route)
            .build();

        let plan = AttachmentPlanner
            .plan(&make_input("prod", "my-gw", snapshot))
            .unwrap();

        assert!(matches!(
            plan.route_results[0].status,
            AttachmentStatus::RefNotPermitted { .. }
        ));
        assert_eq!(plan.listener_summary("http").unwrap().attached_routes, 1);
    }

    #[test]
    fn tcp_route_attaches_to_tcp_listener() {
        let gw = make_gateway(
            "prod",
            "my-gw",
            vec![make_listener("tcp", 5432, ProtocolType::TCP)],
        );
        let route = make_tcp_route(
            "prod",
            "my-tcp",
            vec![make_parent_ref("prod", "my-gw", Some("tcp"))],
            vec![make_backend_ref(None, "db-svc")],
        );
        let snapshot = SnapshotBuilder::default()
            .with_gateway(gw)
            .with_tcp_route(route)
            .with_service_endpoint("prod", "db-svc")
            .build();

        let plan = AttachmentPlanner
            .plan(&make_input("prod", "my-gw", snapshot))
            .unwrap();

        assert_eq!(plan.route_results[0].status, AttachmentStatus::Attached);
        assert_eq!(plan.listener_summaries[0].attached_routes, 1);
    }

    #[test]
    fn tls_route_attaches_to_tls_listener() {
        let gw = make_gateway(
            "prod",
            "my-gw",
            vec![make_listener("tls", 443, ProtocolType::TLS)],
        );
        let route = make_tls_route(
            "prod",
            "my-tls",
            vec![make_parent_ref("prod", "my-gw", Some("tls"))],
            vec![make_backend_ref(None, "tls-svc")],
        );
        let snapshot = SnapshotBuilder::default()
            .with_gateway(gw)
            .with_tls_route(route)
            .with_service_endpoint("prod", "tls-svc")
            .build();

        let plan = AttachmentPlanner
            .plan(&make_input("prod", "my-gw", snapshot))
            .unwrap();

        assert_eq!(plan.route_results[0].status, AttachmentStatus::Attached);
        assert_eq!(plan.listener_summaries[0].attached_routes, 1);
    }

    // ── Protocol mismatch ─────────────────────────────────────────────────────

    #[test]
    fn http_route_rejected_by_tcp_listener() {
        let gw = make_gateway(
            "prod",
            "my-gw",
            vec![make_listener("tcp", 5432, ProtocolType::TCP)],
        );
        let route = make_http_route(
            "prod",
            "my-route",
            vec![make_parent_ref("prod", "my-gw", Some("tcp"))],
            vec![],
        );
        let snapshot = SnapshotBuilder::default()
            .with_gateway(gw)
            .with_http_route(route)
            .build();

        let plan = AttachmentPlanner
            .plan(&make_input("prod", "my-gw", snapshot))
            .unwrap();

        assert_eq!(
            plan.route_results[0].status,
            AttachmentStatus::NotAllowedByListenerProtocol
        );
        assert_eq!(plan.listener_summaries[0].attached_routes, 0);
    }

    #[test]
    fn tcp_route_rejected_by_http_listener() {
        let gw = make_gateway(
            "prod",
            "my-gw",
            vec![make_listener("http", 80, ProtocolType::HTTP)],
        );
        let route = make_tcp_route(
            "prod",
            "my-tcp",
            vec![make_parent_ref("prod", "my-gw", Some("http"))],
            vec![],
        );
        let snapshot = SnapshotBuilder::default()
            .with_gateway(gw)
            .with_tcp_route(route)
            .with_service_endpoint("prod", "db-svc")
            .build();

        let plan = AttachmentPlanner
            .plan(&make_input("prod", "my-gw", snapshot))
            .unwrap();

        assert_eq!(
            plan.route_results[0].status,
            AttachmentStatus::NotAllowedByListenerProtocol
        );
    }

    // ── No matching parent ────────────────────────────────────────────────────

    #[test]
    fn route_with_unknown_section_name_gets_no_matching_parent() {
        let gw = make_gateway(
            "prod",
            "my-gw",
            vec![make_listener("http", 80, ProtocolType::HTTP)],
        );
        let route = make_http_route(
            "prod",
            "my-route",
            vec![make_parent_ref("prod", "my-gw", Some("nonexistent"))],
            vec![],
        );
        let snapshot = SnapshotBuilder::default()
            .with_gateway(gw)
            .with_http_route(route)
            .build();

        let plan = AttachmentPlanner
            .plan(&make_input("prod", "my-gw", snapshot))
            .unwrap();

        assert_eq!(
            plan.route_results[0].status,
            AttachmentStatus::NoMatchingParent
        );
        assert_eq!(plan.listener_summaries[0].attached_routes, 0);
    }

    // ── Namespace policy ──────────────────────────────────────────────────────

    #[test]
    fn route_from_different_ns_denied_when_same_policy() {
        // Default policy is Same; route in "other-ns" should be denied.
        let gw = make_gateway(
            "prod",
            "my-gw",
            vec![make_listener("http", 80, ProtocolType::HTTP)],
        );
        let route = make_http_route(
            "other-ns",
            "cross-route",
            vec![make_parent_ref("prod", "my-gw", Some("http"))],
            vec![],
        );
        let snapshot = SnapshotBuilder::default()
            .with_gateway(gw)
            .with_http_route(route)
            .build();

        let plan = AttachmentPlanner
            .plan(&make_input("prod", "my-gw", snapshot))
            .unwrap();

        assert_eq!(
            plan.route_results[0].status,
            AttachmentStatus::NotAllowedByListenerNamespacePolicy
        );
    }

    #[test]
    fn route_from_different_ns_allowed_when_all_policy() {
        let allowed = AllowedRoutes {
            namespaces: Some(RouteNamespaces {
                from: FromNamespaces::All,
                selector: None,
            }),
            kinds: vec![],
        };
        let gw = make_gateway(
            "prod",
            "my-gw",
            vec![make_listener_with_allowed(
                "http",
                80,
                ProtocolType::HTTP,
                allowed,
            )],
        );
        let route = make_http_route(
            "other-ns",
            "cross-route",
            vec![make_parent_ref("prod", "my-gw", Some("http"))],
            vec![],
        );
        let snapshot = SnapshotBuilder::default()
            .with_gateway(gw)
            .with_http_route(route)
            .build();

        let plan = AttachmentPlanner
            .plan(&make_input("prod", "my-gw", snapshot))
            .unwrap();

        assert_eq!(plan.route_results[0].status, AttachmentStatus::Attached);
    }

    #[test]
    fn route_denied_when_selector_policy_and_no_labels_in_snapshot() {
        // Selector policy but namespace labels absent from snapshot -> safe denial.
        let allowed = AllowedRoutes {
            namespaces: Some(RouteNamespaces {
                from: FromNamespaces::Selector,
                selector: Some(LabelSelector {
                    match_labels: Some({
                        let mut m = BTreeMap::new();
                        m.insert("env".to_string(), "prod".to_string());
                        m
                    }),
                    match_expressions: vec![],
                }),
            }),
            kinds: vec![],
        };
        let gw = make_gateway(
            "prod",
            "my-gw",
            vec![make_listener_with_allowed(
                "http",
                80,
                ProtocolType::HTTP,
                allowed,
            )],
        );
        let route = make_http_route(
            "prod",
            "my-route",
            vec![make_parent_ref("prod", "my-gw", Some("http"))],
            vec![],
        );
        // No namespace labels in snapshot.
        let snapshot = SnapshotBuilder::default()
            .with_gateway(gw)
            .with_http_route(route)
            .build();

        let plan = AttachmentPlanner
            .plan(&make_input("prod", "my-gw", snapshot))
            .unwrap();

        assert_eq!(
            plan.route_results[0].status,
            AttachmentStatus::NotAllowedByListenerNamespacePolicy
        );
    }

    #[test]
    fn route_allowed_when_selector_policy_matches_standard_namespace_label_without_cached_labels() {
        let allowed = AllowedRoutes {
            namespaces: Some(RouteNamespaces {
                from: FromNamespaces::Selector,
                selector: Some(LabelSelector {
                    match_labels: Some({
                        let mut m = BTreeMap::new();
                        m.insert(
                            "kubernetes.io/metadata.name".to_string(),
                            "app-ns".to_string(),
                        );
                        m
                    }),
                    match_expressions: vec![],
                }),
            }),
            kinds: vec![],
        };
        let gw = make_gateway(
            "prod",
            "my-gw",
            vec![make_listener_with_allowed(
                "http",
                80,
                ProtocolType::HTTP,
                allowed,
            )],
        );
        let route = make_http_route(
            "app-ns",
            "my-route",
            vec![make_parent_ref("prod", "my-gw", Some("http"))],
            vec![],
        );
        let snapshot = SnapshotBuilder::default()
            .with_gateway(gw)
            .with_http_route(route)
            .build();

        let plan = AttachmentPlanner
            .plan(&make_input("prod", "my-gw", snapshot))
            .unwrap();

        assert_eq!(plan.route_results[0].status, AttachmentStatus::Attached);
    }

    #[test]
    fn route_allowed_when_selector_policy_and_labels_match() {
        let mut ns_labels = BTreeMap::new();
        ns_labels.insert("env".to_string(), "prod".to_string());

        let allowed = AllowedRoutes {
            namespaces: Some(RouteNamespaces {
                from: FromNamespaces::Selector,
                selector: Some(LabelSelector {
                    match_labels: Some({
                        let mut m = BTreeMap::new();
                        m.insert("env".to_string(), "prod".to_string());
                        m
                    }),
                    match_expressions: vec![],
                }),
            }),
            kinds: vec![],
        };
        let gw = make_gateway(
            "prod",
            "my-gw",
            vec![make_listener_with_allowed(
                "http",
                80,
                ProtocolType::HTTP,
                allowed,
            )],
        );
        let route = make_http_route(
            "app-ns",
            "my-route",
            vec![make_parent_ref("prod", "my-gw", Some("http"))],
            vec![],
        );
        let snapshot = SnapshotBuilder::default()
            .with_gateway(gw)
            .with_http_route(route)
            .with_namespace_labels("app-ns", ns_labels)
            .build();

        let plan = AttachmentPlanner
            .plan(&make_input("prod", "my-gw", snapshot))
            .unwrap();

        assert_eq!(plan.route_results[0].status, AttachmentStatus::Attached);
    }

    #[test]
    fn route_denied_when_selector_policy_and_labels_do_not_match() {
        let mut ns_labels = BTreeMap::new();
        ns_labels.insert("env".to_string(), "staging".to_string());

        let allowed = AllowedRoutes {
            namespaces: Some(RouteNamespaces {
                from: FromNamespaces::Selector,
                selector: Some(LabelSelector {
                    match_labels: Some({
                        let mut m = BTreeMap::new();
                        m.insert("env".to_string(), "prod".to_string());
                        m
                    }),
                    match_expressions: vec![],
                }),
            }),
            kinds: vec![],
        };
        let gw = make_gateway(
            "prod",
            "my-gw",
            vec![make_listener_with_allowed(
                "http",
                80,
                ProtocolType::HTTP,
                allowed,
            )],
        );
        let route = make_http_route(
            "app-ns",
            "my-route",
            vec![make_parent_ref("prod", "my-gw", Some("http"))],
            vec![],
        );
        let snapshot = SnapshotBuilder::default()
            .with_gateway(gw)
            .with_http_route(route)
            .with_namespace_labels("app-ns", ns_labels)
            .build();

        let plan = AttachmentPlanner
            .plan(&make_input("prod", "my-gw", snapshot))
            .unwrap();

        assert_eq!(
            plan.route_results[0].status,
            AttachmentStatus::NotAllowedByListenerNamespacePolicy
        );
    }

    // ── Kind policy ───────────────────────────────────────────────────────────

    #[test]
    fn route_denied_by_kind_policy() {
        use crate::crds::RouteGroupKind as CrdRouteGroupKind;
        let allowed = AllowedRoutes {
            namespaces: None,
            kinds: vec![CrdRouteGroupKind {
                group: GATEWAY_API_GROUP.to_string(),
                kind: "TCPRoute".to_string(),
            }],
        };
        let gw = make_gateway(
            "prod",
            "my-gw",
            vec![make_listener_with_allowed(
                "http",
                80,
                ProtocolType::HTTP,
                allowed,
            )],
        );
        let route = make_http_route(
            "prod",
            "my-route",
            vec![make_parent_ref("prod", "my-gw", Some("http"))],
            vec![],
        );
        let snapshot = SnapshotBuilder::default()
            .with_gateway(gw)
            .with_http_route(route)
            .build();

        let plan = AttachmentPlanner
            .plan(&make_input("prod", "my-gw", snapshot))
            .unwrap();

        assert_eq!(
            plan.route_results[0].status,
            AttachmentStatus::NotAllowedByListenerKindPolicy
        );
    }

    #[test]
    fn route_allowed_when_kind_matches_policy() {
        use crate::crds::RouteGroupKind as CrdRouteGroupKind;
        let allowed = AllowedRoutes {
            namespaces: None,
            kinds: vec![CrdRouteGroupKind {
                group: GATEWAY_API_GROUP.to_string(),
                kind: "HTTPRoute".to_string(),
            }],
        };
        let gw = make_gateway(
            "prod",
            "my-gw",
            vec![make_listener_with_allowed(
                "http",
                80,
                ProtocolType::HTTP,
                allowed,
            )],
        );
        let route = make_http_route(
            "prod",
            "my-route",
            vec![make_parent_ref("prod", "my-gw", Some("http"))],
            vec![],
        );
        let snapshot = SnapshotBuilder::default()
            .with_gateway(gw)
            .with_http_route(route)
            .build();

        let plan = AttachmentPlanner
            .plan(&make_input("prod", "my-gw", snapshot))
            .unwrap();

        assert_eq!(plan.route_results[0].status, AttachmentStatus::Attached);
    }

    // ── Cross-namespace ReferenceGrant ────────────────────────────────────────

    #[test]
    fn cross_ns_backend_ref_denied_without_grant() {
        let allowed = AllowedRoutes {
            namespaces: Some(RouteNamespaces {
                from: FromNamespaces::All,
                selector: None,
            }),
            kinds: vec![],
        };
        let gw = make_gateway(
            "prod",
            "my-gw",
            vec![make_listener_with_allowed(
                "http",
                80,
                ProtocolType::HTTP,
                allowed,
            )],
        );
        // Route in "app-ns" references a backend in "backend-ns" -- no grant.
        let route = make_http_route(
            "app-ns",
            "my-route",
            vec![make_parent_ref("prod", "my-gw", Some("http"))],
            vec![make_http_backend_ref(Some("backend-ns"), "my-svc")],
        );
        let snapshot = SnapshotBuilder::default()
            .with_gateway(gw)
            .with_http_route(route)
            .build();

        let plan = AttachmentPlanner
            .plan(&make_input("prod", "my-gw", snapshot))
            .unwrap();

        assert!(
            matches!(
                &plan.route_results[0].status,
                AttachmentStatus::RefNotPermitted { target_namespace, .. }
                    if target_namespace == "backend-ns"
            ),
            "expected RefNotPermitted, got {:?}",
            plan.route_results[0].status
        );
        // RefNotPermitted is still counted as attached at the listener level.
        assert_eq!(plan.listener_summaries[0].attached_routes, 1);
    }

    #[test]
    fn cross_ns_backend_ref_allowed_with_grant() {
        let allowed = AllowedRoutes {
            namespaces: Some(RouteNamespaces {
                from: FromNamespaces::All,
                selector: None,
            }),
            kinds: vec![],
        };
        let gw = make_gateway(
            "prod",
            "my-gw",
            vec![make_listener_with_allowed(
                "http",
                80,
                ProtocolType::HTTP,
                allowed,
            )],
        );
        let route = make_http_route(
            "app-ns",
            "my-route",
            vec![make_parent_ref("prod", "my-gw", Some("http"))],
            vec![make_http_backend_ref(Some("backend-ns"), "my-svc")],
        );
        // Grant in "backend-ns" allows HTTPRoute from "app-ns" to reference any Service.
        let grant = make_reference_grant(
            "backend-ns",
            "allow-httproute",
            GATEWAY_API_GROUP,
            "HTTPRoute",
            "app-ns",
            "Service",
            None,
        );
        let snapshot = SnapshotBuilder::default()
            .with_gateway(gw)
            .with_http_route(route)
            .with_reference_grant(grant)
            .build();

        let plan = AttachmentPlanner
            .plan(&make_input("prod", "my-gw", snapshot))
            .unwrap();

        assert_eq!(plan.route_results[0].status, AttachmentStatus::Attached);
    }

    #[test]
    fn same_ns_backend_ref_missing_service_is_still_attached() {
        let gw = make_gateway(
            "prod",
            "my-gw",
            vec![make_listener_with_allowed(
                "http",
                80,
                ProtocolType::HTTP,
                AllowedRoutes {
                    namespaces: Some(RouteNamespaces {
                        from: FromNamespaces::All,
                        selector: None,
                    }),
                    kinds: vec![],
                },
            )],
        );
        let route = make_http_route(
            "app-ns",
            "my-route",
            vec![make_parent_ref("prod", "my-gw", Some("http"))],
            vec![make_http_backend_ref(None, "does-not-exist")],
        );
        let snapshot = SnapshotBuilder::default()
            .with_gateway(gw)
            .with_http_route(route)
            .build();

        let plan = AttachmentPlanner
            .plan(&make_input("prod", "my-gw", snapshot))
            .unwrap();

        assert!(matches!(
            &plan.route_results[0].status,
            AttachmentStatus::BackendNotFound { target_name, .. } if target_name == "does-not-exist"
        ));
        assert_eq!(plan.listener_summaries[0].attached_routes, 1);
    }

    #[test]
    fn cross_ns_backend_ref_denied_when_grant_targets_wrong_service() {
        let allowed = AllowedRoutes {
            namespaces: Some(RouteNamespaces {
                from: FromNamespaces::All,
                selector: None,
            }),
            kinds: vec![],
        };
        let gw = make_gateway(
            "prod",
            "my-gw",
            vec![make_listener_with_allowed(
                "http",
                80,
                ProtocolType::HTTP,
                allowed,
            )],
        );
        let route = make_http_route(
            "app-ns",
            "my-route",
            vec![make_parent_ref("prod", "my-gw", Some("http"))],
            vec![make_http_backend_ref(Some("backend-ns"), "my-svc")],
        );
        // Grant only allows "other-svc", not "my-svc".
        let grant = make_reference_grant(
            "backend-ns",
            "allow-other",
            GATEWAY_API_GROUP,
            "HTTPRoute",
            "app-ns",
            "Service",
            Some("other-svc"),
        );
        let snapshot = SnapshotBuilder::default()
            .with_gateway(gw)
            .with_http_route(route)
            .with_reference_grant(grant)
            .build();

        let plan = AttachmentPlanner
            .plan(&make_input("prod", "my-gw", snapshot))
            .unwrap();

        assert!(matches!(
            &plan.route_results[0].status,
            AttachmentStatus::RefNotPermitted { .. }
        ));
    }

    /// Non-core group backend refs (e.g. custom resource backends) must NOT be
    /// checked for cross-namespace grants -- they are not core Services.
    #[test]
    fn non_core_group_backend_ref_is_not_checked_for_grant() {
        let allowed = AllowedRoutes {
            namespaces: Some(RouteNamespaces {
                from: FromNamespaces::All,
                selector: None,
            }),
            kinds: vec![],
        };
        let gw = make_gateway(
            "prod",
            "my-gw",
            vec![make_listener_with_allowed(
                "http",
                80,
                ProtocolType::HTTP,
                allowed,
            )],
        );
        // Backend ref with non-core group -- should not trigger grant check.
        let custom_backend = HTTPBackendRef {
            backend_ref: BackendRef {
                group: "custom.example.com".to_string(),
                kind: "CustomBackend".to_string(),
                name: "my-backend".to_string(),
                namespace: Some("backend-ns".to_string()),
                port: Some(8080),
                weight: 1,
            },
            filters: vec![],
        };
        let route = make_http_route(
            "app-ns",
            "my-route",
            vec![make_parent_ref("prod", "my-gw", Some("http"))],
            vec![custom_backend],
        );
        // No grant -- but should still attach because non-core refs are skipped.
        let snapshot = SnapshotBuilder::default()
            .with_gateway(gw)
            .with_http_route(route)
            .build();

        let plan = AttachmentPlanner
            .plan(&make_input("prod", "my-gw", snapshot))
            .unwrap();

        assert_eq!(
            plan.route_results[0].status,
            AttachmentStatus::Attached,
            "non-core group backend ref should not trigger grant check"
        );
    }

    // ── Multiple listeners ────────────────────────────────────────────────────

    #[test]
    fn gateway_wide_parent_ref_attaches_to_all_compatible_listeners() {
        // Gateway with HTTP and TCP listeners; HTTPRoute with no sectionName.
        let gw = make_gateway(
            "prod",
            "my-gw",
            vec![
                make_listener("http", 80, ProtocolType::HTTP),
                make_listener("https", 443, ProtocolType::HTTPS),
                make_listener("tcp", 5432, ProtocolType::TCP),
            ],
        );
        let route = make_http_route(
            "prod",
            "my-route",
            // No sectionName -> targets all listeners.
            vec![make_parent_ref("prod", "my-gw", None)],
            vec![],
        );
        let snapshot = SnapshotBuilder::default()
            .with_gateway(gw)
            .with_http_route(route)
            .build();

        let plan = AttachmentPlanner
            .plan(&make_input("prod", "my-gw", snapshot))
            .unwrap();

        // Should produce results for all 3 listeners.
        assert_eq!(plan.route_results.len(), 3);

        // HTTP and HTTPS listeners should be Attached; TCP should be protocol mismatch.
        let http_result = plan
            .route_results
            .iter()
            .find(|r| r.listener_name.as_deref() == Some("http"))
            .unwrap();
        assert_eq!(http_result.status, AttachmentStatus::Attached);

        let https_result = plan
            .route_results
            .iter()
            .find(|r| r.listener_name.as_deref() == Some("https"))
            .unwrap();
        assert_eq!(https_result.status, AttachmentStatus::Attached);

        let tcp_result = plan
            .route_results
            .iter()
            .find(|r| r.listener_name.as_deref() == Some("tcp"))
            .unwrap();
        assert_eq!(
            tcp_result.status,
            AttachmentStatus::NotAllowedByListenerProtocol
        );

        // HTTP and HTTPS listeners each count 1 attached route.
        let http_summary = plan.listener_summary("http").unwrap();
        assert_eq!(http_summary.attached_routes, 1);
        let https_summary = plan.listener_summary("https").unwrap();
        assert_eq!(https_summary.attached_routes, 1);
        let tcp_summary = plan.listener_summary("tcp").unwrap();
        assert_eq!(tcp_summary.attached_routes, 0);
    }

    #[test]
    fn multiple_routes_counted_per_listener() {
        let gw = make_gateway(
            "prod",
            "my-gw",
            vec![make_listener("http", 80, ProtocolType::HTTP)],
        );
        let route_a = make_http_route(
            "prod",
            "route-a",
            vec![make_parent_ref("prod", "my-gw", Some("http"))],
            vec![],
        );
        let route_b = make_http_route(
            "prod",
            "route-b",
            vec![make_parent_ref("prod", "my-gw", Some("http"))],
            vec![],
        );
        let snapshot = SnapshotBuilder::default()
            .with_gateway(gw)
            .with_http_route(route_a)
            .with_http_route(route_b)
            .build();

        let plan = AttachmentPlanner
            .plan(&make_input("prod", "my-gw", snapshot))
            .unwrap();

        assert_eq!(plan.listener_summaries[0].attached_routes, 2);
    }

    // ── Duplicate parentRefs (HIGH: dedup counting) ───────────────────────────

    /// A route with two identical parentRefs targeting the same listener must
    /// be counted only once in `attached_routes`.
    #[test]
    fn duplicate_parent_refs_counted_once() {
        let gw = make_gateway(
            "prod",
            "my-gw",
            vec![make_listener("http", 80, ProtocolType::HTTP)],
        );
        // Two identical parentRefs on the same route.
        let route = make_http_route(
            "prod",
            "my-route",
            vec![
                make_parent_ref("prod", "my-gw", Some("http")),
                make_parent_ref("prod", "my-gw", Some("http")),
            ],
            vec![],
        );
        let snapshot = SnapshotBuilder::default()
            .with_gateway(gw)
            .with_http_route(route)
            .build();

        let plan = AttachmentPlanner
            .plan(&make_input("prod", "my-gw", snapshot))
            .unwrap();

        // Two results (one per parentRef) but only one unique route attached.
        assert_eq!(plan.route_results.len(), 2);
        assert_eq!(
            plan.listener_summaries[0].attached_routes, 1,
            "duplicate parentRefs must not inflate attached_routes"
        );
    }

    // ── parentRef.port (HIGH) ─────────────────────────────────────────────────

    #[test]
    fn parent_ref_port_matches_listener_port() {
        let gw = make_gateway(
            "prod",
            "my-gw",
            vec![make_listener("http", 80, ProtocolType::HTTP)],
        );
        let route = make_http_route(
            "prod",
            "my-route",
            vec![make_parent_ref_with_port("prod", "my-gw", Some("http"), 80)],
            vec![],
        );
        let snapshot = SnapshotBuilder::default()
            .with_gateway(gw)
            .with_http_route(route)
            .build();

        let plan = AttachmentPlanner
            .plan(&make_input("prod", "my-gw", snapshot))
            .unwrap();

        assert_eq!(plan.route_results[0].status, AttachmentStatus::Attached);
        assert_eq!(plan.route_results[0].parent_ref_port, Some(80));
    }

    #[test]
    fn parent_ref_port_mismatch_gives_no_matching_parent() {
        let gw = make_gateway(
            "prod",
            "my-gw",
            vec![make_listener("http", 80, ProtocolType::HTTP)],
        );
        // parentRef.port = 8080 but listener is on 80.
        let route = make_http_route(
            "prod",
            "my-route",
            vec![make_parent_ref_with_port(
                "prod",
                "my-gw",
                Some("http"),
                8080,
            )],
            vec![],
        );
        let snapshot = SnapshotBuilder::default()
            .with_gateway(gw)
            .with_http_route(route)
            .build();

        let plan = AttachmentPlanner
            .plan(&make_input("prod", "my-gw", snapshot))
            .unwrap();

        assert_eq!(
            plan.route_results[0].status,
            AttachmentStatus::NoMatchingParent,
            "port mismatch must yield NoMatchingParent"
        );
        assert_eq!(plan.listener_summaries[0].attached_routes, 0);
    }

    #[test]
    fn gateway_wide_parent_ref_with_port_filters_listeners() {
        // Two listeners on different ports; parentRef has no sectionName but
        // specifies port=443.  Only the HTTPS listener should be evaluated.
        let gw = make_gateway(
            "prod",
            "my-gw",
            vec![
                make_listener("http", 80, ProtocolType::HTTP),
                make_listener("https", 443, ProtocolType::HTTPS),
            ],
        );
        let route = make_http_route(
            "prod",
            "my-route",
            vec![make_parent_ref_with_port("prod", "my-gw", None, 443)],
            vec![],
        );
        let snapshot = SnapshotBuilder::default()
            .with_gateway(gw)
            .with_http_route(route)
            .build();

        let plan = AttachmentPlanner
            .plan(&make_input("prod", "my-gw", snapshot))
            .unwrap();

        // Only one result (the https listener).
        assert_eq!(plan.route_results.len(), 1);
        assert_eq!(
            plan.route_results[0].listener_name.as_deref(),
            Some("https")
        );
        assert_eq!(plan.route_results[0].status, AttachmentStatus::Attached);
        assert_eq!(plan.listener_summary("http").unwrap().attached_routes, 0);
        assert_eq!(plan.listener_summary("https").unwrap().attached_routes, 1);
    }

    // ── Hostname compatibility (HIGH) ─────────────────────────────────────────

    #[test]
    fn http_route_with_matching_hostname_attaches() {
        let gw = make_gateway(
            "prod",
            "my-gw",
            vec![make_listener_with_hostname(
                "http",
                80,
                ProtocolType::HTTP,
                "example.com",
            )],
        );
        let route = make_http_route_with_hostnames(
            "prod",
            "my-route",
            vec![make_parent_ref("prod", "my-gw", Some("http"))],
            vec![],
            vec!["example.com".to_string()],
        );
        let snapshot = SnapshotBuilder::default()
            .with_gateway(gw)
            .with_http_route(route)
            .build();

        let plan = AttachmentPlanner
            .plan(&make_input("prod", "my-gw", snapshot))
            .unwrap();

        assert_eq!(plan.route_results[0].status, AttachmentStatus::Attached);
    }

    #[test]
    fn http_route_with_non_matching_hostname_rejected() {
        let gw = make_gateway(
            "prod",
            "my-gw",
            vec![make_listener_with_hostname(
                "http",
                80,
                ProtocolType::HTTP,
                "example.com",
            )],
        );
        let route = make_http_route_with_hostnames(
            "prod",
            "my-route",
            vec![make_parent_ref("prod", "my-gw", Some("http"))],
            vec![],
            vec!["other.com".to_string()],
        );
        let snapshot = SnapshotBuilder::default()
            .with_gateway(gw)
            .with_http_route(route)
            .build();

        let plan = AttachmentPlanner
            .plan(&make_input("prod", "my-gw", snapshot))
            .unwrap();

        assert_eq!(
            plan.route_results[0].status,
            AttachmentStatus::NoMatchingListenerHostname
        );
        assert_eq!(plan.listener_summaries[0].attached_routes, 0);
    }

    #[test]
    fn http_route_with_no_hostnames_attaches_to_any_listener_hostname() {
        let gw = make_gateway(
            "prod",
            "my-gw",
            vec![make_listener_with_hostname(
                "http",
                80,
                ProtocolType::HTTP,
                "example.com",
            )],
        );
        // Route has no hostnames -> compatible with any listener hostname.
        let route = make_http_route(
            "prod",
            "my-route",
            vec![make_parent_ref("prod", "my-gw", Some("http"))],
            vec![],
        );
        let snapshot = SnapshotBuilder::default()
            .with_gateway(gw)
            .with_http_route(route)
            .build();

        let plan = AttachmentPlanner
            .plan(&make_input("prod", "my-gw", snapshot))
            .unwrap();

        assert_eq!(plan.route_results[0].status, AttachmentStatus::Attached);
    }

    #[test]
    fn wildcard_listener_hostname_matches_subdomain_route_hostname() {
        let gw = make_gateway(
            "prod",
            "my-gw",
            vec![make_listener_with_hostname(
                "http",
                80,
                ProtocolType::HTTP,
                "*.example.com",
            )],
        );
        let route = make_http_route_with_hostnames(
            "prod",
            "my-route",
            vec![make_parent_ref("prod", "my-gw", Some("http"))],
            vec![],
            vec!["api.example.com".to_string()],
        );
        let snapshot = SnapshotBuilder::default()
            .with_gateway(gw)
            .with_http_route(route)
            .build();

        let plan = AttachmentPlanner
            .plan(&make_input("prod", "my-gw", snapshot))
            .unwrap();

        assert_eq!(plan.route_results[0].status, AttachmentStatus::Attached);
    }

    #[test]
    fn tls_route_with_non_matching_sni_rejected() {
        let gw = make_gateway(
            "prod",
            "my-gw",
            vec![make_listener_with_hostname(
                "tls",
                443,
                ProtocolType::TLS,
                "db.example.com",
            )],
        );
        let route = make_tls_route_with_hostnames(
            "prod",
            "my-tls",
            vec![make_parent_ref("prod", "my-gw", Some("tls"))],
            vec![],
            vec!["other.example.com".to_string()],
        );
        let snapshot = SnapshotBuilder::default()
            .with_gateway(gw)
            .with_tls_route(route)
            .build();

        let plan = AttachmentPlanner
            .plan(&make_input("prod", "my-gw", snapshot))
            .unwrap();

        assert_eq!(
            plan.route_results[0].status,
            AttachmentStatus::NoMatchingListenerHostname
        );
    }

    #[test]
    fn tcp_route_hostname_check_skipped() {
        // TCPRoute has no hostname concept; listener hostname must not block it.
        let gw = make_gateway(
            "prod",
            "my-gw",
            vec![make_listener_with_hostname(
                "tcp",
                5432,
                ProtocolType::TCP,
                "db.example.com",
            )],
        );
        let route = make_tcp_route(
            "prod",
            "my-tcp",
            vec![make_parent_ref("prod", "my-gw", Some("tcp"))],
            vec![make_backend_ref(None, "db-svc")],
        );
        let snapshot = SnapshotBuilder::default()
            .with_gateway(gw)
            .with_tcp_route(route)
            .with_service_endpoint("prod", "db-svc")
            .build();

        let plan = AttachmentPlanner
            .plan(&make_input("prod", "my-gw", snapshot))
            .unwrap();

        assert_eq!(plan.route_results[0].status, AttachmentStatus::Attached);
    }

    // ── parentRef identity in result (MED) ────────────────────────────────────

    #[test]
    fn route_result_carries_parent_ref_identity() {
        let gw = make_gateway(
            "prod",
            "my-gw",
            vec![make_listener("http", 80, ProtocolType::HTTP)],
        );
        let route = make_http_route(
            "prod",
            "my-route",
            vec![make_parent_ref_with_port("prod", "my-gw", Some("http"), 80)],
            vec![],
        );
        let snapshot = SnapshotBuilder::default()
            .with_gateway(gw)
            .with_http_route(route)
            .build();

        let plan = AttachmentPlanner
            .plan(&make_input("prod", "my-gw", snapshot))
            .unwrap();

        let r = &plan.route_results[0];
        assert_eq!(r.parent_ref_section_name.as_deref(), Some("http"));
        assert_eq!(r.parent_ref_port, Some(80));
    }

    // ── UDP listener ──────────────────────────────────────────────────────────

    #[test]
    fn udp_listener_is_not_accepted() {
        let gw = make_gateway(
            "prod",
            "my-gw",
            vec![make_listener("udp", 53, ProtocolType::UDP)],
        );
        let snapshot = SnapshotBuilder::default().with_gateway(gw).build();

        let plan = AttachmentPlanner
            .plan(&make_input("prod", "my-gw", snapshot))
            .unwrap();

        assert!(!plan.listener_summaries[0].listener_accepted);
        assert!(plan.listener_summaries[0]
            .listener_rejection_reason
            .is_some());
    }

    // ── Determinism ───────────────────────────────────────────────────────────

    #[test]
    fn plan_is_deterministic_for_same_inputs() {
        let gw = make_gateway(
            "prod",
            "my-gw",
            vec![
                make_listener("http", 80, ProtocolType::HTTP),
                make_listener("tcp", 5432, ProtocolType::TCP),
            ],
        );
        let route_a = make_http_route(
            "prod",
            "route-a",
            vec![make_parent_ref("prod", "my-gw", Some("http"))],
            vec![],
        );
        let route_b = make_http_route(
            "prod",
            "route-b",
            vec![make_parent_ref("prod", "my-gw", Some("http"))],
            vec![],
        );
        let snapshot = SnapshotBuilder::default()
            .with_gateway(gw)
            .with_http_route(route_a)
            .with_http_route(route_b)
            .build();

        let plan_a = AttachmentPlanner
            .plan(&make_input("prod", "my-gw", snapshot.clone()))
            .unwrap();
        let plan_b = AttachmentPlanner
            .plan(&make_input("prod", "my-gw", snapshot))
            .unwrap();

        assert_eq!(plan_a, plan_b, "planner must be deterministic");
    }

    // ── AttachmentStatus helpers ──────────────────────────────────────────────

    #[test]
    fn attached_is_attached() {
        assert!(AttachmentStatus::Attached.is_attached());
    }

    #[test]
    fn ref_not_permitted_is_attached_at_listener_level() {
        let s = AttachmentStatus::RefNotPermitted {
            route_namespace: "ns".to_string(),
            target_namespace: "other".to_string(),
            target_name: "svc".to_string(),
        };
        assert!(s.is_attached());
        assert_eq!(s.accepted_reason(), "Accepted");
        assert_eq!(s.resolved_refs_reason(), Some("RefNotPermitted"));
    }

    #[test]
    fn backend_not_found_is_attached_at_listener_level() {
        let s = AttachmentStatus::BackendNotFound {
            route_namespace: "ns".to_string(),
            target_namespace: "ns".to_string(),
            target_name: "svc".to_string(),
        };
        assert!(s.is_attached());
        assert_eq!(s.accepted_reason(), "Accepted");
        assert_eq!(s.resolved_refs_reason(), Some("BackendNotFound"));
    }

    #[test]
    fn no_matching_parent_is_not_attached() {
        assert!(!AttachmentStatus::NoMatchingParent.is_attached());
        assert_eq!(
            AttachmentStatus::NoMatchingParent.accepted_reason(),
            "NoMatchingParent"
        );
        assert_eq!(
            AttachmentStatus::NoMatchingParent.resolved_refs_reason(),
            None
        );
    }

    #[test]
    fn protocol_mismatch_is_not_attached() {
        assert!(!AttachmentStatus::NotAllowedByListenerProtocol.is_attached());
    }

    #[test]
    fn no_matching_listener_hostname_is_not_attached() {
        assert!(!AttachmentStatus::NoMatchingListenerHostname.is_attached());
        assert_eq!(
            AttachmentStatus::NoMatchingListenerHostname.accepted_reason(),
            "NoMatchingListenerHostname"
        );
    }

    // ── Missing gateway ───────────────────────────────────────────────────────

    #[test]
    fn plan_errors_when_gateway_not_in_snapshot() {
        let snapshot = SnapshotBuilder::default().build();
        let err = AttachmentPlanner
            .plan(&make_input("prod", "missing-gw", snapshot))
            .unwrap_err();
        assert!(matches!(err, PlanError::MissingField { .. }));
    }

    // ── Listener summaries sorted ─────────────────────────────────────────────

    #[test]
    fn listener_summaries_are_sorted_by_name() {
        let gw = make_gateway(
            "prod",
            "my-gw",
            vec![
                make_listener("zzz", 9000, ProtocolType::HTTP),
                make_listener("aaa", 8000, ProtocolType::HTTP),
                make_listener("mmm", 8500, ProtocolType::HTTP),
            ],
        );
        let snapshot = SnapshotBuilder::default().with_gateway(gw).build();

        let plan = AttachmentPlanner
            .plan(&make_input("prod", "my-gw", snapshot))
            .unwrap();

        let names: Vec<&str> = plan
            .listener_summaries
            .iter()
            .map(|s| s.listener_name.as_str())
            .collect();
        assert_eq!(names, vec!["aaa", "mmm", "zzz"]);
    }

    // ── Supported kinds ───────────────────────────────────────────────────────

    #[test]
    fn http_listener_supports_httproute_kind() {
        let gw = make_gateway(
            "prod",
            "my-gw",
            vec![make_listener("http", 80, ProtocolType::HTTP)],
        );
        let snapshot = SnapshotBuilder::default().with_gateway(gw).build();

        let plan = AttachmentPlanner
            .plan(&make_input("prod", "my-gw", snapshot))
            .unwrap();

        assert_eq!(plan.listener_summaries[0].supported_kinds.len(), 1);
        assert_eq!(
            plan.listener_summaries[0].supported_kinds[0].kind,
            "HTTPRoute"
        );
    }

    #[test]
    fn tcp_listener_supports_tcproute_kind() {
        let gw = make_gateway(
            "prod",
            "my-gw",
            vec![make_listener("tcp", 5432, ProtocolType::TCP)],
        );
        let snapshot = SnapshotBuilder::default().with_gateway(gw).build();

        let plan = AttachmentPlanner
            .plan(&make_input("prod", "my-gw", snapshot))
            .unwrap();

        assert_eq!(
            plan.listener_summaries[0].supported_kinds[0].kind,
            "TCPRoute"
        );
    }

    // ── results_for_listener helper ───────────────────────────────────────────

    #[test]
    fn results_for_listener_filters_correctly() {
        let gw = make_gateway(
            "prod",
            "my-gw",
            vec![
                make_listener("http", 80, ProtocolType::HTTP),
                make_listener("https", 443, ProtocolType::HTTPS),
            ],
        );
        let route = make_http_route(
            "prod",
            "my-route",
            vec![make_parent_ref("prod", "my-gw", Some("http"))],
            vec![],
        );
        let snapshot = SnapshotBuilder::default()
            .with_gateway(gw)
            .with_http_route(route)
            .build();

        let plan = AttachmentPlanner
            .plan(&make_input("prod", "my-gw", snapshot))
            .unwrap();

        let http_results = plan.results_for_listener("http", false);
        assert_eq!(http_results.len(), 1);

        let https_results = plan.results_for_listener("https", false);
        assert_eq!(https_results.len(), 0);
    }

    // ── hostname_intersects unit tests ────────────────────────────────────────

    #[test]
    fn hostname_intersects_exact() {
        assert!(hostname_intersects("example.com", "example.com"));
        assert!(!hostname_intersects("example.com", "other.com"));
    }

    #[test]
    fn hostname_intersects_wildcard_listener() {
        assert!(hostname_intersects("*.example.com", "api.example.com"));
        assert!(hostname_intersects("*.example.com", "www.example.com"));
        assert!(!hostname_intersects("*.example.com", "example.com"));
        assert!(!hostname_intersects(
            "*.example.com",
            "deep.api.example.com"
        ));
    }

    #[test]
    fn hostname_intersects_wildcard_route() {
        assert!(hostname_intersects("api.example.com", "*.example.com"));
        assert!(!hostname_intersects("example.com", "*.example.com"));
    }

    // ── Wildcard hostname dot-boundary fix (HIGH) ─────────────────────────────

    /// `*.example.com` must NOT match `fooexample.com` -- no dot boundary.
    #[test]
    fn wildcard_does_not_match_without_dot_boundary() {
        assert!(
            !hostname_intersects("*.example.com", "fooexample.com"),
            "*.example.com must not match fooexample.com (no dot boundary)"
        );
        assert!(
            !hostname_intersects("fooexample.com", "*.example.com"),
            "fooexample.com must not match *.example.com (no dot boundary)"
        );
    }

    /// `*.example.com` must NOT match `notexample.com` (suffix shares chars but no dot).
    #[test]
    fn wildcard_does_not_match_partial_suffix() {
        assert!(!hostname_intersects("*.example.com", "notexample.com"));
        assert!(!hostname_intersects("*.example.com", "xample.com"));
    }

    /// Proper subdomain still matches after the fix.
    #[test]
    fn wildcard_matches_proper_subdomain_after_fix() {
        assert!(hostname_intersects("*.example.com", "sub.example.com"));
        assert!(hostname_intersects("sub.example.com", "*.example.com"));
    }

    // ── matchExpressions evaluation (Issue 3) ─────────────────────────────────

    #[test]
    fn match_expressions_in_operator_allows_when_value_in_set() {
        use crate::crds::LabelSelectorRequirement;
        let mut labels = BTreeMap::new();
        labels.insert("env".to_string(), "prod".to_string());

        let sel = LabelSelector {
            match_labels: None,
            match_expressions: vec![LabelSelectorRequirement {
                key: "env".to_string(),
                operator: "In".to_string(),
                values: vec!["prod".to_string(), "staging".to_string()],
            }],
        };
        assert!(label_selector_matches(&sel, &labels));
    }

    #[test]
    fn match_expressions_in_operator_denies_when_value_not_in_set() {
        use crate::crds::LabelSelectorRequirement;
        let mut labels = BTreeMap::new();
        labels.insert("env".to_string(), "dev".to_string());

        let sel = LabelSelector {
            match_labels: None,
            match_expressions: vec![LabelSelectorRequirement {
                key: "env".to_string(),
                operator: "In".to_string(),
                values: vec!["prod".to_string(), "staging".to_string()],
            }],
        };
        assert!(!label_selector_matches(&sel, &labels));
    }

    #[test]
    fn match_expressions_in_operator_denies_when_key_absent() {
        use crate::crds::LabelSelectorRequirement;
        let labels = BTreeMap::new();

        let sel = LabelSelector {
            match_labels: None,
            match_expressions: vec![LabelSelectorRequirement {
                key: "env".to_string(),
                operator: "In".to_string(),
                values: vec!["prod".to_string()],
            }],
        };
        assert!(!label_selector_matches(&sel, &labels));
    }

    #[test]
    fn match_expressions_not_in_operator_allows_when_key_absent() {
        use crate::crds::LabelSelectorRequirement;
        let labels = BTreeMap::new();

        let sel = LabelSelector {
            match_labels: None,
            match_expressions: vec![LabelSelectorRequirement {
                key: "env".to_string(),
                operator: "NotIn".to_string(),
                values: vec!["prod".to_string()],
            }],
        };
        assert!(label_selector_matches(&sel, &labels));
    }

    #[test]
    fn match_expressions_not_in_operator_allows_when_value_not_in_set() {
        use crate::crds::LabelSelectorRequirement;
        let mut labels = BTreeMap::new();
        labels.insert("env".to_string(), "dev".to_string());

        let sel = LabelSelector {
            match_labels: None,
            match_expressions: vec![LabelSelectorRequirement {
                key: "env".to_string(),
                operator: "NotIn".to_string(),
                values: vec!["prod".to_string(), "staging".to_string()],
            }],
        };
        assert!(label_selector_matches(&sel, &labels));
    }

    #[test]
    fn match_expressions_not_in_operator_denies_when_value_in_set() {
        use crate::crds::LabelSelectorRequirement;
        let mut labels = BTreeMap::new();
        labels.insert("env".to_string(), "prod".to_string());

        let sel = LabelSelector {
            match_labels: None,
            match_expressions: vec![LabelSelectorRequirement {
                key: "env".to_string(),
                operator: "NotIn".to_string(),
                values: vec!["prod".to_string()],
            }],
        };
        assert!(!label_selector_matches(&sel, &labels));
    }

    #[test]
    fn match_expressions_exists_operator_allows_when_key_present() {
        use crate::crds::LabelSelectorRequirement;
        let mut labels = BTreeMap::new();
        labels.insert("team".to_string(), "backend".to_string());

        let sel = LabelSelector {
            match_labels: None,
            match_expressions: vec![LabelSelectorRequirement {
                key: "team".to_string(),
                operator: "Exists".to_string(),
                values: vec![],
            }],
        };
        assert!(label_selector_matches(&sel, &labels));
    }

    #[test]
    fn match_expressions_exists_operator_denies_when_key_absent() {
        use crate::crds::LabelSelectorRequirement;
        let labels = BTreeMap::new();

        let sel = LabelSelector {
            match_labels: None,
            match_expressions: vec![LabelSelectorRequirement {
                key: "team".to_string(),
                operator: "Exists".to_string(),
                values: vec![],
            }],
        };
        assert!(!label_selector_matches(&sel, &labels));
    }

    #[test]
    fn match_expressions_does_not_exist_operator_allows_when_key_absent() {
        use crate::crds::LabelSelectorRequirement;
        let labels = BTreeMap::new();

        let sel = LabelSelector {
            match_labels: None,
            match_expressions: vec![LabelSelectorRequirement {
                key: "deprecated".to_string(),
                operator: "DoesNotExist".to_string(),
                values: vec![],
            }],
        };
        assert!(label_selector_matches(&sel, &labels));
    }

    #[test]
    fn match_expressions_does_not_exist_operator_denies_when_key_present() {
        use crate::crds::LabelSelectorRequirement;
        let mut labels = BTreeMap::new();
        labels.insert("deprecated".to_string(), "true".to_string());

        let sel = LabelSelector {
            match_labels: None,
            match_expressions: vec![LabelSelectorRequirement {
                key: "deprecated".to_string(),
                operator: "DoesNotExist".to_string(),
                values: vec![],
            }],
        };
        assert!(!label_selector_matches(&sel, &labels));
    }

    #[test]
    fn match_expressions_unknown_operator_denies_conservatively() {
        use crate::crds::LabelSelectorRequirement;
        let mut labels = BTreeMap::new();
        labels.insert("env".to_string(), "prod".to_string());

        let sel = LabelSelector {
            match_labels: None,
            match_expressions: vec![LabelSelectorRequirement {
                key: "env".to_string(),
                operator: "GreaterThan".to_string(), // not a real operator
                values: vec!["prod".to_string()],
            }],
        };
        assert!(!label_selector_matches(&sel, &labels));
    }

    /// Both matchLabels and matchExpressions must be satisfied simultaneously.
    #[test]
    fn match_labels_and_expressions_both_must_pass() {
        use crate::crds::LabelSelectorRequirement;
        let mut labels = BTreeMap::new();
        labels.insert("env".to_string(), "prod".to_string());
        labels.insert("team".to_string(), "backend".to_string());

        // matchLabels: env=prod (passes), matchExpressions: team Exists (passes)
        let sel_pass = LabelSelector {
            match_labels: Some({
                let mut m = BTreeMap::new();
                m.insert("env".to_string(), "prod".to_string());
                m
            }),
            match_expressions: vec![LabelSelectorRequirement {
                key: "team".to_string(),
                operator: "Exists".to_string(),
                values: vec![],
            }],
        };
        assert!(label_selector_matches(&sel_pass, &labels));

        // matchLabels: env=staging (fails) -- overall must fail
        let sel_fail = LabelSelector {
            match_labels: Some({
                let mut m = BTreeMap::new();
                m.insert("env".to_string(), "staging".to_string());
                m
            }),
            match_expressions: vec![LabelSelectorRequirement {
                key: "team".to_string(),
                operator: "Exists".to_string(),
                values: vec![],
            }],
        };
        assert!(!label_selector_matches(&sel_fail, &labels));
    }

    /// End-to-end: route allowed when matchExpressions (In) matches namespace labels.
    #[test]
    fn route_allowed_when_selector_match_expressions_in_matches() {
        use crate::crds::LabelSelectorRequirement;
        let mut ns_labels = BTreeMap::new();
        ns_labels.insert("env".to_string(), "prod".to_string());

        let allowed = AllowedRoutes {
            namespaces: Some(RouteNamespaces {
                from: FromNamespaces::Selector,
                selector: Some(LabelSelector {
                    match_labels: None,
                    match_expressions: vec![LabelSelectorRequirement {
                        key: "env".to_string(),
                        operator: "In".to_string(),
                        values: vec!["prod".to_string(), "staging".to_string()],
                    }],
                }),
            }),
            kinds: vec![],
        };
        let gw = make_gateway(
            "prod",
            "my-gw",
            vec![make_listener_with_allowed(
                "http",
                80,
                ProtocolType::HTTP,
                allowed,
            )],
        );
        let route = make_http_route(
            "app-ns",
            "my-route",
            vec![make_parent_ref("prod", "my-gw", Some("http"))],
            vec![],
        );
        let snapshot = SnapshotBuilder::default()
            .with_gateway(gw)
            .with_http_route(route)
            .with_namespace_labels("app-ns", ns_labels)
            .build();

        let plan = AttachmentPlanner
            .plan(&make_input("prod", "my-gw", snapshot))
            .unwrap();

        assert_eq!(plan.route_results[0].status, AttachmentStatus::Attached);
    }

    /// End-to-end: route denied when matchExpressions (In) does not match.
    #[test]
    fn route_denied_when_selector_match_expressions_in_does_not_match() {
        use crate::crds::LabelSelectorRequirement;
        let mut ns_labels = BTreeMap::new();
        ns_labels.insert("env".to_string(), "dev".to_string());

        let allowed = AllowedRoutes {
            namespaces: Some(RouteNamespaces {
                from: FromNamespaces::Selector,
                selector: Some(LabelSelector {
                    match_labels: None,
                    match_expressions: vec![LabelSelectorRequirement {
                        key: "env".to_string(),
                        operator: "In".to_string(),
                        values: vec!["prod".to_string(), "staging".to_string()],
                    }],
                }),
            }),
            kinds: vec![],
        };
        let gw = make_gateway(
            "prod",
            "my-gw",
            vec![make_listener_with_allowed(
                "http",
                80,
                ProtocolType::HTTP,
                allowed,
            )],
        );
        let route = make_http_route(
            "app-ns",
            "my-route",
            vec![make_parent_ref("prod", "my-gw", Some("http"))],
            vec![],
        );
        let snapshot = SnapshotBuilder::default()
            .with_gateway(gw)
            .with_http_route(route)
            .with_namespace_labels("app-ns", ns_labels)
            .build();

        let plan = AttachmentPlanner
            .plan(&make_input("prod", "my-gw", snapshot))
            .unwrap();

        assert_eq!(
            plan.route_results[0].status,
            AttachmentStatus::NotAllowedByListenerNamespacePolicy
        );
    }

    /// End-to-end: route allowed when matchExpressions (DoesNotExist) matches.
    #[test]
    fn route_allowed_when_selector_does_not_exist_matches() {
        use crate::crds::LabelSelectorRequirement;
        // Namespace has no "deprecated" label -- DoesNotExist should pass.
        let mut ns_labels = BTreeMap::new();
        ns_labels.insert("env".to_string(), "prod".to_string());

        let allowed = AllowedRoutes {
            namespaces: Some(RouteNamespaces {
                from: FromNamespaces::Selector,
                selector: Some(LabelSelector {
                    match_labels: None,
                    match_expressions: vec![LabelSelectorRequirement {
                        key: "deprecated".to_string(),
                        operator: "DoesNotExist".to_string(),
                        values: vec![],
                    }],
                }),
            }),
            kinds: vec![],
        };
        let gw = make_gateway(
            "prod",
            "my-gw",
            vec![make_listener_with_allowed(
                "http",
                80,
                ProtocolType::HTTP,
                allowed,
            )],
        );
        let route = make_http_route(
            "app-ns",
            "my-route",
            vec![make_parent_ref("prod", "my-gw", Some("http"))],
            vec![],
        );
        let snapshot = SnapshotBuilder::default()
            .with_gateway(gw)
            .with_http_route(route)
            .with_namespace_labels("app-ns", ns_labels)
            .build();

        let plan = AttachmentPlanner
            .plan(&make_input("prod", "my-gw", snapshot))
            .unwrap();

        assert_eq!(plan.route_results[0].status, AttachmentStatus::Attached);
    }

    // ── result_for_route_parent_ref helper ────────────────────────────────────

    /// `result_for_route_parent_ref` finds the correct result by
    /// `(route_ns, route_name, section_name, port)`.
    #[test]
    fn result_for_route_parent_ref_finds_matching_result() {
        let gw = make_gateway(
            "prod",
            "my-gw",
            vec![make_listener("http", 80, ProtocolType::HTTP)],
        );
        let route = make_http_route(
            "prod",
            "my-route",
            vec![make_parent_ref("prod", "my-gw", Some("http"))],
            vec![],
        );
        let snapshot = SnapshotBuilder::default()
            .with_gateway(gw)
            .with_http_route(route)
            .build();

        let plan = AttachmentPlanner
            .plan(&make_input("prod", "my-gw", snapshot))
            .unwrap();

        let result = plan.result_for_route_parent_ref("prod", "my-route", "http", None);
        assert!(result.is_some(), "should find result for matching triple");
        assert_eq!(result.unwrap().status, AttachmentStatus::Attached);
    }

    /// `result_for_route_parent_ref` finds a `NoMatchingParent` result when
    /// the route's parentRef specifies an unknown `sectionName`.
    ///
    /// The planner emits a `NoMatchingParent` result whose
    /// `parent_ref_section_name` is set to the unknown name, so the lookup
    /// still finds it.  A `None` return only happens when the route itself
    /// is absent from the plan (different route name / namespace).
    #[test]
    fn result_for_route_parent_ref_returns_none_for_unknown_section() {
        let gw = make_gateway(
            "prod",
            "my-gw",
            vec![make_listener("http", 80, ProtocolType::HTTP)],
        );
        // Route's parentRef uses "nonexistent" as sectionName.
        let route = make_http_route(
            "prod",
            "my-route",
            vec![make_parent_ref("prod", "my-gw", Some("nonexistent"))],
            vec![],
        );
        let snapshot = SnapshotBuilder::default()
            .with_gateway(gw)
            .with_http_route(route)
            .build();

        let plan = AttachmentPlanner
            .plan(&make_input("prod", "my-gw", snapshot))
            .unwrap();

        // The planner emits a NoMatchingParent result with
        // parent_ref_section_name = Some("nonexistent"), so the lookup finds it.
        let result = plan.result_for_route_parent_ref("prod", "my-route", "nonexistent", None);
        assert!(result.is_some(), "should find NoMatchingParent result");
        assert_eq!(result.unwrap().status, AttachmentStatus::NoMatchingParent);

        // A lookup for a section name that was never in any parentRef returns None.
        let not_found =
            plan.result_for_route_parent_ref("prod", "my-route", "completely-different", None);
        assert!(
            not_found.is_none(),
            "should return None for section name not in any parentRef"
        );
    }

    /// `result_for_route_parent_ref` returns `None` when the route name
    /// does not match.
    #[test]
    fn result_for_route_parent_ref_returns_none_for_wrong_route_name() {
        let gw = make_gateway(
            "prod",
            "my-gw",
            vec![make_listener("http", 80, ProtocolType::HTTP)],
        );
        let route = make_http_route(
            "prod",
            "my-route",
            vec![make_parent_ref("prod", "my-gw", Some("http"))],
            vec![],
        );
        let snapshot = SnapshotBuilder::default()
            .with_gateway(gw)
            .with_http_route(route)
            .build();

        let plan = AttachmentPlanner
            .plan(&make_input("prod", "my-gw", snapshot))
            .unwrap();

        let result = plan.result_for_route_parent_ref("prod", "other-route", "http", None);
        assert!(result.is_none(), "should return None for wrong route name");
    }

    /// `result_for_route_parent_ref` distinguishes by port when set.
    #[test]
    fn result_for_route_parent_ref_distinguishes_by_port() {
        let gw = make_gateway(
            "prod",
            "my-gw",
            vec![make_listener("http", 80, ProtocolType::HTTP)],
        );
        let route = make_http_route(
            "prod",
            "my-route",
            vec![make_parent_ref_with_port("prod", "my-gw", Some("http"), 80)],
            vec![],
        );
        let snapshot = SnapshotBuilder::default()
            .with_gateway(gw)
            .with_http_route(route)
            .build();

        let plan = AttachmentPlanner
            .plan(&make_input("prod", "my-gw", snapshot))
            .unwrap();

        // Correct port → finds result.
        let found = plan.result_for_route_parent_ref("prod", "my-route", "http", Some(80));
        assert!(found.is_some());
        assert_eq!(found.unwrap().status, AttachmentStatus::Attached);

        // Wrong port → no match.
        let not_found = plan.result_for_route_parent_ref("prod", "my-route", "http", Some(9999));
        assert!(not_found.is_none());
    }
}
