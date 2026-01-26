//! Request routing and matching for Wicket proxy.
//!
//! This module provides fast route matching based on host, path, method, and headers.

use anyhow::Result;
use std::collections::HashMap;
use tracing::debug;
use wicket_config::RouteConfig;

/// A compiled router that matches requests to upstream names.
#[derive(Debug, Clone)]
pub struct Router {
    routes: Vec<CompiledRoute>,
}

/// A route with pre-compiled matchers for fast matching.
#[derive(Debug, Clone)]
struct CompiledRoute {
    /// Original route name for debugging
    name: Option<String>,

    /// Target upstream name
    upstream: String,

    /// Compiled host matcher
    host_matcher: Option<HostMatcher>,

    /// Path matching strategy
    path_matcher: Option<PathMatcher>,

    /// Allowed methods (empty = all methods)
    methods: Vec<String>,

    /// Required headers
    headers: HashMap<String, String>,
}

/// Host matching with wildcard support.
///
/// Uses simple string matching instead of regex to prevent ReDoS attacks.
#[derive(Debug, Clone)]
enum HostMatcher {
    /// Exact host match (case-insensitive)
    Exact(String),
    /// Wildcard prefix match: *.example.com matches foo.example.com but not foo.bar.example.com
    WildcardPrefix {
        /// The suffix after the wildcard (e.g., ".example.com" for "*.example.com")
        suffix: String,
    },
}

/// Path matching strategies.
#[derive(Debug, Clone)]
enum PathMatcher {
    Exact(String),
    Prefix(String),
}

/// Information about a matched route.
#[derive(Debug, Clone)]
pub struct RouteMatch {
    /// Name of the matched route
    pub route_name: Option<String>,

    /// Target upstream name
    pub upstream: String,
}

impl Router {
    /// Build a router from route configurations.
    pub fn build(routes: &[RouteConfig]) -> Result<Self> {
        let mut compiled = Vec::new();
        for route in routes {
            compiled.push(CompiledRoute::compile(route)?);
        }

        debug!("Built router with {} routes", compiled.len());
        Ok(Router { routes: compiled })
    }

    /// Check if any route requires header matching.
    pub fn has_header_matchers(&self) -> bool {
        self.routes.iter().any(|r| !r.headers.is_empty())
    }

    /// Find a matching route for the given request properties.
    ///
    /// Returns the first matching route, or None if no routes match.
    pub fn match_request(
        &self,
        host: Option<&str>,
        path: &str,
        method: &str,
        headers: &HashMap<String, String>,
    ) -> Option<RouteMatch> {
        for route in &self.routes {
            if route.matches(host, path, method, headers) {
                debug!(
                    route_name = ?route.name,
                    upstream = %route.upstream,
                    "Matched route"
                );
                return Some(RouteMatch {
                    route_name: route.name.clone(),
                    upstream: route.upstream.clone(),
                });
            }
        }
        None
    }
}

impl CompiledRoute {
    /// Compile a route configuration into an optimized matcher.
    fn compile(config: &RouteConfig) -> Result<Self> {
        let host_matcher = if let Some(ref h) = config.match_rules.host {
            Some(HostMatcher::compile(h)?)
        } else {
            None
        };

        let path_matcher = if let Some(ref exact) = config.match_rules.path {
            Some(PathMatcher::Exact(exact.clone()))
        } else {
            config
                .match_rules
                .path_prefix
                .as_ref()
                .map(|p| PathMatcher::Prefix(p.clone()))
        };

        let methods: Vec<String> = config
            .match_rules
            .methods
            .iter()
            .map(|m| m.to_uppercase())
            .collect();

        Ok(CompiledRoute {
            name: config.name.clone(),
            upstream: config.upstream.clone(),
            host_matcher,
            path_matcher,
            methods,
            headers: config.match_rules.headers.clone(),
        })
    }

    /// Check if this route matches the given request properties.
    fn matches(
        &self,
        host: Option<&str>,
        path: &str,
        method: &str,
        headers: &HashMap<String, String>,
    ) -> bool {
        // Check host
        if let Some(ref matcher) = self.host_matcher {
            match host {
                Some(h) => {
                    if !matcher.matches(h) {
                        return false;
                    }
                }
                None => return false,
            }
        }

        // Check path
        if let Some(ref matcher) = self.path_matcher {
            if !matcher.matches(path) {
                return false;
            }
        }

        // Check method
        if !self.methods.is_empty() && !self.methods.contains(&method.to_uppercase()) {
            return false;
        }

        // Check headers
        for (key, value) in &self.headers {
            match headers.get(key) {
                Some(v) if v == value => {}
                _ => return false,
            }
        }

        true
    }
}

impl HostMatcher {
    /// Compile a host pattern into a matcher.
    ///
    /// Supports wildcards like "*.example.com".
    ///
    /// Uses simple string matching instead of regex to prevent ReDoS attacks.
    /// Only `*` at the beginning (e.g., `*.example.com`) is supported.
    fn compile(pattern: &str) -> Result<Self> {
        if let Some(suffix) = pattern.strip_prefix("*.") {
            // Wildcard prefix pattern: *.example.com
            // Store the suffix with the leading dot for matching
            Ok(HostMatcher::WildcardPrefix {
                suffix: format!(".{}", suffix.to_lowercase()),
            })
        } else if pattern.contains('*') {
            // Reject other wildcard patterns (e.g., foo.*.com) to prevent complexity
            // and potential matching issues
            anyhow::bail!(
                "Invalid host pattern '{}': only prefix wildcards (*.example.com) are supported",
                pattern
            );
        } else {
            Ok(HostMatcher::Exact(pattern.to_lowercase()))
        }
    }

    fn matches(&self, host: &str) -> bool {
        let host_lower = host.to_lowercase();
        // Strip port if present
        let host_without_port = host_lower.split(':').next().unwrap_or(&host_lower);

        match self {
            HostMatcher::Exact(expected) => host_without_port == expected,
            HostMatcher::WildcardPrefix { suffix } => {
                // Must end with the suffix (e.g., ".example.com")
                if !host_without_port.ends_with(suffix) {
                    return false;
                }

                // Get the prefix part (before the suffix)
                let prefix_len = host_without_port.len() - suffix.len();
                if prefix_len == 0 {
                    // Host is exactly the suffix without the leading dot, no wildcard match
                    return false;
                }

                let prefix = &host_without_port[..prefix_len];

                // Wildcard should match exactly one label (no dots in prefix)
                // This matches RFC 6125 behavior for wildcard certificates
                !prefix.contains('.')
            }
        }
    }
}

impl PathMatcher {
    fn matches(&self, path: &str) -> bool {
        match self {
            PathMatcher::Exact(expected) => path == expected,
            PathMatcher::Prefix(prefix) => {
                path.starts_with(prefix)
                    || (prefix.ends_with('/') && path == &prefix[..prefix.len() - 1])
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wicket_config::RouteMatch as ConfigRouteMatch;

    fn make_route(
        name: Option<&str>,
        upstream: &str,
        host: Option<&str>,
        path_prefix: Option<&str>,
        path: Option<&str>,
        methods: Vec<&str>,
    ) -> RouteConfig {
        RouteConfig {
            name: name.map(String::from),
            upstream: upstream.to_string(),
            match_rules: ConfigRouteMatch {
                host: host.map(String::from),
                path_prefix: path_prefix.map(String::from),
                path: path.map(String::from),
                methods: methods.into_iter().map(String::from).collect(),
                headers: HashMap::new(),
            },
            tls: None,
            filters: None,
            timeout: None,
        }
    }

    #[test]
    fn test_exact_host_match() {
        let routes = vec![make_route(
            Some("test"),
            "backend",
            Some("example.com"),
            Some("/"),
            None,
            vec![],
        )];

        let router = Router::build(&routes).unwrap();
        let headers = HashMap::new();

        assert!(router
            .match_request(Some("example.com"), "/foo", "GET", &headers)
            .is_some());
        assert!(router
            .match_request(Some("Example.COM"), "/foo", "GET", &headers)
            .is_some());
        assert!(router
            .match_request(Some("other.com"), "/foo", "GET", &headers)
            .is_none());
    }

    #[test]
    fn test_wildcard_host_match() {
        let routes = vec![make_route(
            Some("test"),
            "backend",
            Some("*.example.com"),
            Some("/"),
            None,
            vec![],
        )];

        let router = Router::build(&routes).unwrap();
        let headers = HashMap::new();

        assert!(router
            .match_request(Some("api.example.com"), "/foo", "GET", &headers)
            .is_some());
        assert!(router
            .match_request(Some("www.example.com"), "/foo", "GET", &headers)
            .is_some());
        assert!(router
            .match_request(Some("example.com"), "/foo", "GET", &headers)
            .is_none());
        assert!(router
            .match_request(Some("sub.api.example.com"), "/foo", "GET", &headers)
            .is_none());
    }

    #[test]
    fn test_path_prefix_match() {
        let routes = vec![make_route(
            Some("api"),
            "api-backend",
            None,
            Some("/api"),
            None,
            vec![],
        )];

        let router = Router::build(&routes).unwrap();
        let headers = HashMap::new();

        assert!(router
            .match_request(None, "/api", "GET", &headers)
            .is_some());
        assert!(router
            .match_request(None, "/api/users", "GET", &headers)
            .is_some());
        assert!(router
            .match_request(None, "/api/", "GET", &headers)
            .is_some());
        assert!(router
            .match_request(None, "/other", "GET", &headers)
            .is_none());
    }

    #[test]
    fn test_exact_path_match() {
        let routes = vec![make_route(
            Some("health"),
            "backend",
            None,
            None,
            Some("/health"),
            vec![],
        )];

        let router = Router::build(&routes).unwrap();
        let headers = HashMap::new();

        assert!(router
            .match_request(None, "/health", "GET", &headers)
            .is_some());
        assert!(router
            .match_request(None, "/health/", "GET", &headers)
            .is_none());
        assert!(router
            .match_request(None, "/health/check", "GET", &headers)
            .is_none());
    }

    #[test]
    fn test_method_match() {
        let routes = vec![make_route(
            Some("post-only"),
            "backend",
            None,
            Some("/"),
            None,
            vec!["POST", "PUT"],
        )];

        let router = Router::build(&routes).unwrap();
        let headers = HashMap::new();

        assert!(router
            .match_request(None, "/foo", "POST", &headers)
            .is_some());
        assert!(router
            .match_request(None, "/foo", "PUT", &headers)
            .is_some());
        assert!(router
            .match_request(None, "/foo", "post", &headers)
            .is_some()); // Case insensitive
        assert!(router
            .match_request(None, "/foo", "GET", &headers)
            .is_none());
    }

    #[test]
    fn test_route_priority() {
        let routes = vec![
            make_route(Some("specific"), "api", None, Some("/api/v2"), None, vec![]),
            make_route(Some("general"), "legacy", None, Some("/api"), None, vec![]),
        ];

        let router = Router::build(&routes).unwrap();
        let headers = HashMap::new();

        // More specific route should match first
        let matched = router
            .match_request(None, "/api/v2/users", "GET", &headers)
            .unwrap();
        assert_eq!(matched.upstream, "api");

        // Fallback to general route
        let matched = router
            .match_request(None, "/api/v1/users", "GET", &headers)
            .unwrap();
        assert_eq!(matched.upstream, "legacy");
    }

    #[test]
    fn test_host_with_port() {
        let routes = vec![make_route(
            Some("test"),
            "backend",
            Some("example.com"),
            Some("/"),
            None,
            vec![],
        )];

        let router = Router::build(&routes).unwrap();
        let headers = HashMap::new();

        assert!(router
            .match_request(Some("example.com:8080"), "/foo", "GET", &headers)
            .is_some());
    }
}
