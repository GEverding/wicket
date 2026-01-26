//! HTTPRoute CRD definition.
//!
//! HTTPRoute provides a way to route HTTP requests.

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::common::{
    BackendRef, Condition, Duration, Hostname, ParentReference, RouteParentStatus,
};

/// HTTPRouteSpec defines the desired state of HTTPRoute.
#[derive(CustomResource, Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[kube(
    group = "gateway.networking.k8s.io",
    version = "v1",
    kind = "HTTPRoute",
    plural = "httproutes",
    shortname = "httproute",
    namespaced,
    status = "HTTPRouteStatus",
    printcolumn = r#"{"name":"Hostnames","type":"string","jsonPath":".spec.hostnames"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct HTTPRouteSpec {
    /// ParentRefs references the resources that can attach to this HTTPRoute.
    #[serde(default)]
    pub parent_refs: Vec<ParentReference>,

    /// Hostnames defines a set of hostnames to match against the Host header.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hostnames: Vec<Hostname>,

    /// Rules are a list of HTTP matchers, filters, and actions.
    #[serde(default)]
    pub rules: Vec<HTTPRouteRule>,
}

/// HTTPRouteRule defines semantics for matching an HTTP request based on conditions.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct HTTPRouteRule {
    /// Name is an optional name for the rule.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Matches define conditions used for matching the rule against incoming HTTP requests.
    #[serde(default)]
    pub matches: Vec<HTTPRouteMatch>,

    /// Filters define the filters that are applied to requests that match this rule.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub filters: Vec<HTTPRouteFilter>,

    /// BackendRefs defines the backend(s) where matching requests should be sent.
    #[serde(default)]
    pub backend_refs: Vec<HTTPBackendRef>,

    /// Timeouts for this rule.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeouts: Option<HTTPRouteTimeouts>,
}

/// HTTPRouteMatch defines the predicate used to match requests to a given action.
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct HTTPRouteMatch {
    /// Path specifies a HTTP request path matcher.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<HTTPPathMatch>,

    /// Headers specifies HTTP request header matchers.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub headers: Vec<HTTPHeaderMatch>,

    /// QueryParams specifies HTTP query parameter matchers.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub query_params: Vec<HTTPQueryParamMatch>,

    /// Method specifies HTTP method matcher.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<HTTPMethod>,
}

/// HTTPPathMatch describes how to select an HTTP route by path.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct HTTPPathMatch {
    /// Type specifies how to match against the path Value.
    #[serde(rename = "type", default)]
    pub type_: PathMatchType,

    /// Value of the HTTP path to match against.
    #[serde(default = "default_path")]
    pub value: String,
}

fn default_path() -> String {
    "/".to_string()
}

/// PathMatchType specifies the semantics of path matching.
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
pub enum PathMatchType {
    /// Matches the URL path exactly.
    Exact,
    /// Matches based on a URL path prefix split by `/`.
    #[default]
    PathPrefix,
    /// Matches if the URL path matches the given regular expression.
    RegularExpression,
}

/// HTTPHeaderMatch describes how to select an HTTP route by header.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct HTTPHeaderMatch {
    /// Type specifies how to match against the value of the header.
    #[serde(rename = "type", default)]
    pub type_: HeaderMatchType,

    /// Name is the name of the HTTP Header to be matched.
    pub name: String,

    /// Value is the value of HTTP Header to be matched.
    pub value: String,
}

/// HeaderMatchType specifies the semantics of header matching.
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
pub enum HeaderMatchType {
    #[default]
    Exact,
    RegularExpression,
}

/// HTTPQueryParamMatch describes how to select an HTTP route by query param.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct HTTPQueryParamMatch {
    /// Type specifies how to match against the value of the query parameter.
    #[serde(rename = "type", default)]
    pub type_: QueryParamMatchType,

    /// Name is the name of the HTTP query param to be matched.
    pub name: String,

    /// Value is the value of HTTP query param to be matched.
    pub value: String,
}

/// QueryParamMatchType specifies the semantics of query param matching.
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
pub enum QueryParamMatchType {
    #[default]
    Exact,
    RegularExpression,
}

/// HTTPMethod describes HTTP method matching.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
pub enum HTTPMethod {
    GET,
    HEAD,
    POST,
    PUT,
    DELETE,
    CONNECT,
    OPTIONS,
    TRACE,
    PATCH,
}

/// HTTPRouteFilter defines processing steps that must be completed during request/response lifecycle.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct HTTPRouteFilter {
    /// Type identifies the type of filter to apply.
    #[serde(rename = "type")]
    pub type_: HTTPRouteFilterType,

    /// RequestHeaderModifier defines a schema for a filter that modifies request headers.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_header_modifier: Option<HTTPHeaderFilter>,

    /// ResponseHeaderModifier defines a schema for a filter that modifies response headers.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_header_modifier: Option<HTTPHeaderFilter>,

    /// RequestMirror defines a schema for a filter that mirrors requests.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_mirror: Option<HTTPRequestMirrorFilter>,

    /// RequestRedirect defines a schema for a filter that responds with a redirect.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_redirect: Option<HTTPRequestRedirectFilter>,

    /// URLRewrite defines a schema for a filter that modifies the URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url_rewrite: Option<HTTPURLRewriteFilter>,

    /// ExtensionRef is an extension filter.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extension_ref: Option<LocalObjectReference>,
}

/// HTTPRouteFilterType identifies a type of HTTPRoute filter.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
pub enum HTTPRouteFilterType {
    RequestHeaderModifier,
    ResponseHeaderModifier,
    RequestMirror,
    RequestRedirect,
    URLRewrite,
    ExtensionRef,
}

/// HTTPHeaderFilter defines a filter that modifies HTTP headers.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct HTTPHeaderFilter {
    /// Set overwrites the request with the given header.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub set: Vec<HTTPHeader>,

    /// Add adds the given header(s) to the request before forwarding.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub add: Vec<HTTPHeader>,

    /// Remove the given header(s) from the request before forwarding.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub remove: Vec<String>,
}

/// HTTPHeader represents an HTTP Header name and value.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
pub struct HTTPHeader {
    /// Name is the name of the HTTP Header.
    pub name: String,

    /// Value is the value of the HTTP Header.
    pub value: String,
}

/// HTTPRequestMirrorFilter defines configuration for the RequestMirror filter.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct HTTPRequestMirrorFilter {
    /// BackendRef references a resource where mirrored requests are sent.
    pub backend_ref: BackendRef,

    /// Percent of requests to mirror.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub percent: Option<i32>,
}

/// HTTPRequestRedirectFilter defines configuration for the RequestRedirect filter.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct HTTPRequestRedirectFilter {
    /// Scheme is the scheme to be used in the value of the Location header.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scheme: Option<String>,

    /// Hostname is the hostname to be used in the value of the Location header.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<Hostname>,

    /// Path defines the path for the redirect.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<HTTPPathModifier>,

    /// Port is the port to be used in the value of the Location header.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,

    /// StatusCode is the HTTP status code to be used in response.
    #[serde(default = "default_redirect_status")]
    pub status_code: i32,
}

fn default_redirect_status() -> i32 {
    302
}

/// HTTPPathModifier defines configuration for path modifiers.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct HTTPPathModifier {
    /// Type defines the type of path modifier.
    #[serde(rename = "type")]
    pub type_: HTTPPathModifierType,

    /// ReplaceFullPath specifies the value to replace the full path.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replace_full_path: Option<String>,

    /// ReplacePrefixMatch specifies the value to replace the prefix match.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replace_prefix_match: Option<String>,
}

/// HTTPPathModifierType defines the type of path modifier.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
pub enum HTTPPathModifierType {
    ReplaceFullPath,
    ReplacePrefixMatch,
}

/// HTTPURLRewriteFilter defines configuration for the URLRewrite filter.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct HTTPURLRewriteFilter {
    /// Hostname is the value to be used to replace the Host header value during forwarding.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<Hostname>,

    /// Path defines a path rewrite.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<HTTPPathModifier>,
}

/// LocalObjectReference identifies an API object within the namespace of the referrer.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LocalObjectReference {
    /// Group is the group of the referent.
    pub group: String,

    /// Kind is the kind of the referent.
    pub kind: String,

    /// Name is the name of the referent.
    pub name: String,
}

/// HTTPBackendRef defines how a HTTPRoute forwards a HTTP request.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct HTTPBackendRef {
    /// BackendRef is a reference to a backend.
    #[serde(flatten)]
    pub backend_ref: BackendRef,

    /// Filters are request/response filters to be applied when routing to the backend.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub filters: Vec<HTTPRouteFilter>,
}

/// HTTPRouteTimeouts defines timeouts for an HTTP route.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct HTTPRouteTimeouts {
    /// Request specifies the maximum duration for a request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request: Option<Duration>,

    /// BackendRequest specifies the maximum duration for a backend request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backend_request: Option<Duration>,
}

/// HTTPRouteStatus defines the observed state of HTTPRoute.
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct HTTPRouteStatus {
    /// Parents is a list of parent resources (usually Gateways) that are associated with the route.
    #[serde(default)]
    pub parents: Vec<RouteParentStatus>,
}

impl HTTPRoute {
    /// Get all backend service references from this route.
    pub fn backend_refs(&self) -> Vec<&BackendRef> {
        self.spec
            .rules
            .iter()
            .flat_map(|rule| rule.backend_refs.iter())
            .map(|br| &br.backend_ref)
            .collect()
    }

    /// Get hostnames for this route.
    pub fn hostnames(&self) -> &[Hostname] {
        &self.spec.hostnames
    }

    /// Check if this route matches a given hostname.
    pub fn matches_hostname(&self, hostname: &str) -> bool {
        if self.spec.hostnames.is_empty() {
            return true; // No hostnames means match all
        }
        self.spec.hostnames.iter().any(|h| {
            if h.starts_with("*.") {
                hostname.ends_with(&h[1..])
            } else {
                h == hostname
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hostname_matching() {
        let route = HTTPRoute::new(
            "test",
            HTTPRouteSpec {
                parent_refs: vec![],
                hostnames: vec!["example.com".to_string(), "*.test.com".to_string()],
                rules: vec![],
            },
        );

        assert!(route.matches_hostname("example.com"));
        assert!(route.matches_hostname("api.test.com"));
        assert!(route.matches_hostname("www.test.com"));
        assert!(!route.matches_hostname("other.com"));
    }

    #[test]
    fn test_empty_hostnames_matches_all() {
        let route = HTTPRoute::new(
            "test",
            HTTPRouteSpec {
                parent_refs: vec![],
                hostnames: vec![],
                rules: vec![],
            },
        );

        assert!(route.matches_hostname("anything.com"));
    }
}
