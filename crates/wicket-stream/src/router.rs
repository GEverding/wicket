//! SNI-based routing for TCP stream proxy.
//!
//! Routes incoming TLS connections to upstream backends based on the SNI hostname.

use std::collections::HashMap;

/// Compiled SNI pattern for fast matching.
#[derive(Debug, Clone, PartialEq, Eq)]
enum CompiledPattern {
    /// Exact hostname match (e.g., "api.example.com")
    Exact(String),
    /// Wildcard pattern (e.g., "*.example.com" -> suffix = ".example.com")
    Wildcard { suffix: String },
}

impl CompiledPattern {
    /// Parse a pattern string into a compiled pattern.
    fn parse(pattern: &str) -> Self {
        let pattern_lower = pattern.to_ascii_lowercase();
        if let Some(suffix) = pattern_lower.strip_prefix("*.") {
            CompiledPattern::Wildcard {
                suffix: format!(".{}", suffix),
            }
        } else {
            CompiledPattern::Exact(pattern_lower)
        }
    }

    /// Check if this pattern matches the given hostname.
    fn matches(&self, hostname: &str) -> bool {
        match self {
            CompiledPattern::Exact(exact) => hostname == exact,
            CompiledPattern::Wildcard { suffix } => {
                if let Some(prefix) = hostname.strip_suffix(suffix.as_str()) {
                    !prefix.is_empty() && !prefix.contains('.')
                } else {
                    false
                }
            }
        }
    }

    /// Return priority for sorting (exact matches first).
    fn priority(&self) -> u8 {
        match self {
            CompiledPattern::Exact(_) => 0,
            CompiledPattern::Wildcard { .. } => 1,
        }
    }
}

/// SNI-based router for stream proxy.
///
/// Routes TLS connections to upstream backends based on the Server Name Indication (SNI)
/// hostname. Supports exact matches and wildcard patterns.
#[derive(Debug)]
pub struct SniRouter {
    routes: Vec<(CompiledPattern, String)>,
    default_upstream: Option<String>,
}

impl SniRouter {
    /// Build a new SNI router from configuration.
    ///
    /// # Arguments
    ///
    /// * `sni_routes` - Map of SNI patterns to upstream names
    /// * `default_upstream` - Optional default upstream for unmatched SNI
    ///
    /// # Pattern Syntax
    ///
    /// * `"api.example.com"` - Exact match only
    /// * `"*.example.com"` - Wildcard match (matches `api.example.com`, `www.example.com`, etc.)
    ///
    /// Exact matches take priority over wildcards.
    pub fn new(sni_routes: &HashMap<String, String>, default_upstream: Option<String>) -> Self {
        let mut routes: Vec<(CompiledPattern, String)> = sni_routes
            .iter()
            .map(|(pattern, upstream)| (CompiledPattern::parse(pattern), upstream.clone()))
            .collect();

        // Sort: exact matches first, then wildcards (longest suffix first)
        routes.sort_by(|(a, _), (b, _)| {
            a.priority().cmp(&b.priority()).then_with(|| {
                // Among wildcards, longer suffixes (more specific) come first
                match (a, b) {
                    (
                        CompiledPattern::Wildcard { suffix: sa },
                        CompiledPattern::Wildcard { suffix: sb },
                    ) => sb.len().cmp(&sa.len()),
                    _ => std::cmp::Ordering::Equal,
                }
            })
        });

        Self {
            routes,
            default_upstream,
        }
    }

    /// Match an SNI hostname to an upstream name.
    ///
    /// Returns the upstream name if a match is found, or the default upstream if configured.
    /// Returns `None` if no match and no default is configured.
    ///
    /// # Arguments
    ///
    /// * `sni` - The SNI hostname, or `None` for non-TLS or missing SNI extension
    pub fn match_sni(&self, sni: Option<&str>) -> Option<&str> {
        if let Some(hostname) = sni {
            let hostname_lower = hostname.to_ascii_lowercase();
            for (pattern, upstream) in &self.routes {
                if pattern.matches(&hostname_lower) {
                    return Some(upstream);
                }
            }
        }

        self.default_upstream.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exact_match() {
        let mut routes = HashMap::new();
        routes.insert("api.example.com".into(), "api-backend".into());
        routes.insert("www.example.com".into(), "www-backend".into());

        let router = SniRouter::new(&routes, Some("default-backend".into()));

        assert_eq!(
            router.match_sni(Some("api.example.com")),
            Some("api-backend")
        );
        assert_eq!(
            router.match_sni(Some("www.example.com")),
            Some("www-backend")
        );
        assert_eq!(
            router.match_sni(Some("other.example.com")),
            Some("default-backend")
        );
    }

    #[test]
    fn test_wildcard_match() {
        let mut routes = HashMap::new();
        routes.insert("*.example.com".into(), "wildcard-backend".into());
        routes.insert("api.example.com".into(), "api-backend".into()); // exact takes priority

        let router = SniRouter::new(&routes, None);

        assert_eq!(
            router.match_sni(Some("api.example.com")),
            Some("api-backend")
        ); // exact
        assert_eq!(
            router.match_sni(Some("www.example.com")),
            Some("wildcard-backend")
        ); // wildcard
           // Multi-level subdomains should NOT match per RFC 6125
        assert_eq!(router.match_sni(Some("sub.api.example.com")), None);
        assert_eq!(router.match_sni(Some("example.com")), None); // no match
    }

    #[test]
    fn test_no_sni() {
        let routes = HashMap::new();
        let router = SniRouter::new(&routes, Some("default-backend".into()));

        assert_eq!(router.match_sni(None), Some("default-backend"));
    }

    #[test]
    fn test_multiple_overlapping_wildcards() {
        let mut routes = HashMap::new();
        routes.insert("*.example.com".into(), "wildcard-example".into());
        routes.insert("*.api.example.com".into(), "wildcard-api".into());
        routes.insert("*.internal.example.com".into(), "wildcard-internal".into());

        let router = SniRouter::new(&routes, None);

        // First matching wildcard wins (both *.example.com and *.api.example.com match)
        let result = router.match_sni(Some("v1.api.example.com"));
        assert!(result.is_some());

        // Only *.example.com matches
        assert_eq!(
            router.match_sni(Some("www.example.com")),
            Some("wildcard-example")
        );

        // Only *.internal.example.com matches
        let result = router.match_sni(Some("db.internal.example.com"));
        assert!(result.is_some());
    }

    #[test]
    fn test_exact_priority_over_wildcard() {
        let mut routes = HashMap::new();
        routes.insert("*.example.com".into(), "wildcard".into());
        routes.insert("*.api.example.com".into(), "wildcard-api".into());
        routes.insert("api.example.com".into(), "exact-api".into());
        routes.insert("www.example.com".into(), "exact-www".into());

        let router = SniRouter::new(&routes, None);

        // Exact matches should always win
        assert_eq!(router.match_sni(Some("api.example.com")), Some("exact-api"));
        assert_eq!(router.match_sni(Some("www.example.com")), Some("exact-www"));

        // Wildcards for non-exact
        let result = router.match_sni(Some("other.example.com"));
        assert!(result.is_some());
    }

    #[test]
    fn test_longer_wildcard_priority() {
        // More specific wildcards should match before less specific ones
        let mut routes = HashMap::new();
        routes.insert("*.example.com".into(), "short-wildcard".into());
        routes.insert("*.prod.example.com".into(), "long-wildcard".into());

        let router = SniRouter::new(&routes, None);

        // Both patterns match, but order depends on HashMap iteration
        // We just verify that one of them matches
        let result = router.match_sni(Some("api.prod.example.com"));
        assert!(result.is_some());
    }

    #[test]
    fn test_case_sensitivity() {
        // DNS is case-insensitive, but our implementation does exact string matching
        // This test documents current behavior
        let mut routes = HashMap::new();
        routes.insert("api.example.com".into(), "backend".into());

        let router = SniRouter::new(&routes, None);

        // Exact case matches
        assert_eq!(router.match_sni(Some("api.example.com")), Some("backend"));

        // Case-insensitive matching per RFC 1035
        assert_eq!(router.match_sni(Some("API.EXAMPLE.COM")), Some("backend"));
        assert_eq!(router.match_sni(Some("Api.Example.Com")), Some("backend"));
    }

    #[test]
    fn test_empty_sni_with_default() {
        let routes = HashMap::new();
        let router = SniRouter::new(&routes, Some("default-backend".into()));

        assert_eq!(router.match_sni(None), Some("default-backend"));
        assert_eq!(router.match_sni(Some("")), Some("default-backend"));
    }

    #[test]
    fn test_empty_sni_no_default() {
        let routes = HashMap::new();
        let router = SniRouter::new(&routes, None);

        assert_eq!(router.match_sni(None), None);
    }

    #[test]
    fn test_no_match_no_default() {
        let mut routes = HashMap::new();
        routes.insert("api.example.com".into(), "backend".into());

        let router = SniRouter::new(&routes, None);

        assert_eq!(router.match_sni(Some("other.com")), None);
        assert_eq!(router.match_sni(Some("example.org")), None);
    }

    #[test]
    fn test_no_match_with_default() {
        let mut routes = HashMap::new();
        routes.insert("api.example.com".into(), "backend".into());

        let router = SniRouter::new(&routes, Some("default".into()));

        assert_eq!(router.match_sni(Some("other.com")), Some("default"));
        assert_eq!(router.match_sni(Some("example.org")), Some("default"));
    }

    #[test]
    fn test_pattern_parsing() {
        assert_eq!(
            CompiledPattern::parse("api.example.com"),
            CompiledPattern::Exact("api.example.com".into())
        );
        assert_eq!(
            CompiledPattern::parse("*.example.com"),
            CompiledPattern::Wildcard {
                suffix: ".example.com".into()
            }
        );
        assert_eq!(
            CompiledPattern::parse("*.api.example.com"),
            CompiledPattern::Wildcard {
                suffix: ".api.example.com".into()
            }
        );
    }

    #[test]
    fn test_pattern_matching() {
        let exact = CompiledPattern::Exact("api.example.com".into());
        assert!(exact.matches("api.example.com"));
        assert!(!exact.matches("www.example.com"));
        assert!(!exact.matches("api.example.org"));

        let wildcard = CompiledPattern::Wildcard {
            suffix: ".example.com".into(),
        };
        assert!(wildcard.matches("api.example.com"));
        assert!(wildcard.matches("www.example.com"));
        assert!(!wildcard.matches("sub.api.example.com")); // RFC 6125: no multi-level
        assert!(!wildcard.matches("example.com")); // Doesn't match root
        assert!(!wildcard.matches("example.org"));
        assert!(!wildcard.matches("notexample.com"));
    }

    #[test]
    fn test_pattern_priority() {
        let exact = CompiledPattern::Exact("api.example.com".into());
        let wildcard = CompiledPattern::Wildcard {
            suffix: ".example.com".into(),
        };

        // Exact has priority 0, wildcard has priority 1
        assert_eq!(exact.priority(), 0);
        assert_eq!(wildcard.priority(), 1);
        assert!(exact.priority() < wildcard.priority());
    }

    #[test]
    fn test_priority_ordering() {
        let mut routes = HashMap::new();
        routes.insert("*.example.com".into(), "wildcard".into());
        routes.insert("api.example.com".into(), "exact".into());
        routes.insert("*.api.example.com".into(), "nested-wildcard".into());

        let router = SniRouter::new(&routes, None);

        // Exact should match first
        assert_eq!(router.match_sni(Some("api.example.com")), Some("exact"));

        // Wildcards should match for non-exact hostnames
        let www_match = router.match_sni(Some("www.example.com"));
        assert!(www_match.is_some());
    }

    #[test]
    fn test_wildcard_edge_cases() {
        let mut routes = HashMap::new();
        routes.insert("*.example.com".into(), "backend".into());

        let router = SniRouter::new(&routes, None);

        // Should match (single-level subdomain)
        assert_eq!(router.match_sni(Some("a.example.com")), Some("backend"));

        // Should not match (multi-level subdomain per RFC 6125)
        assert_eq!(
            router.match_sni(Some("very.long.subdomain.example.com")),
            None
        );

        // Should not match
        assert_eq!(router.match_sni(Some("example.com")), None);
        assert_eq!(router.match_sni(Some("examplexcom")), None);
        // ".example.com" has empty prefix, so no match
        assert_eq!(router.match_sni(Some(".example.com")), None);
    }

    // ========================================================================
    // BUG: Wildcard matches multi-level subdomains (RFC 6125 violation).
    //
    // `*.example.com` matches `a.b.example.com` because the wildcard only
    // checks `ends_with(".example.com")`. Per RFC 6125 Section 6.4.3, a
    // wildcard should match exactly one DNS label. The HTTP router
    // (wicket-core/src/routing.rs) correctly prevents this with a
    // `!prefix.contains('.')` check, but the stream SniRouter does not.
    // ========================================================================

    #[test]
    fn test_wildcard_must_not_match_multi_level_subdomains() {
        let mut routes = HashMap::new();
        routes.insert("*.example.com".into(), "backend".into());

        let router = SniRouter::new(&routes, None);

        // Single-level subdomain should match
        assert_eq!(
            router.match_sni(Some("api.example.com")),
            Some("backend"),
            "single-level subdomain should match wildcard"
        );

        // Multi-level subdomain should NOT match per RFC 6125
        assert_eq!(
            router.match_sni(Some("sub.api.example.com")),
            None,
            "multi-level subdomain must NOT match *.example.com per RFC 6125"
        );

        assert_eq!(
            router.match_sni(Some("a.b.c.example.com")),
            None,
            "deeply nested subdomain must NOT match *.example.com"
        );
    }

    // ========================================================================
    // BUG: SNI matching is case-sensitive (RFC 1035 violation).
    //
    // DNS names are case-insensitive per RFC 1035 Section 2.3.3. The HTTP
    // router normalizes to lowercase, but SniRouter does exact string
    // comparison. A client sending "API.EXAMPLE.COM" won't match a route
    // for "api.example.com".
    // ========================================================================

    #[test]
    fn test_sni_matching_must_be_case_insensitive() {
        let mut routes = HashMap::new();
        routes.insert("api.example.com".into(), "backend".into());
        routes.insert("*.example.org".into(), "wildcard-backend".into());

        let router = SniRouter::new(&routes, None);

        // Exact match with different case
        assert_eq!(
            router.match_sni(Some("API.EXAMPLE.COM")),
            Some("backend"),
            "DNS matching must be case-insensitive per RFC 1035"
        );
        assert_eq!(
            router.match_sni(Some("Api.Example.Com")),
            Some("backend"),
            "DNS matching must be case-insensitive per RFC 1035"
        );

        // Wildcard match with different case
        assert_eq!(
            router.match_sni(Some("WWW.EXAMPLE.ORG")),
            Some("wildcard-backend"),
            "Wildcard DNS matching must be case-insensitive per RFC 1035"
        );
    }

    // ========================================================================
    // BUG: More specific wildcards don't take priority over less specific ones.
    //
    // When both *.prod.example.com and *.example.com exist, a request for
    // api.prod.example.com should match *.prod.example.com (more specific).
    // Currently the match order among wildcards depends on HashMap iteration
    // order, which is nondeterministic.
    // ========================================================================

    #[test]
    fn test_more_specific_wildcard_must_win() {
        let mut routes = HashMap::new();
        routes.insert("*.example.com".into(), "short-wildcard".into());
        routes.insert("*.prod.example.com".into(), "long-wildcard".into());

        let router = SniRouter::new(&routes, None);

        // api.prod.example.com matches both wildcards.
        // The more specific one (*.prod.example.com) must win.
        assert_eq!(
            router.match_sni(Some("api.prod.example.com")),
            Some("long-wildcard"),
            "more specific wildcard (*.prod.example.com) must take priority \
             over less specific wildcard (*.example.com)"
        );
    }

    #[test]
    fn test_empty_routes() {
        let routes = HashMap::new();
        let router = SniRouter::new(&routes, None);

        assert_eq!(router.match_sni(Some("anything.com")), None);
        assert_eq!(router.match_sni(None), None);
    }

    #[test]
    fn test_many_routes() {
        let mut routes = HashMap::new();
        for i in 0..100 {
            routes.insert(format!("api{}.example.com", i), format!("backend-{}", i));
        }

        let router = SniRouter::new(&routes, None);

        assert_eq!(
            router.match_sni(Some("api0.example.com")),
            Some("backend-0")
        );
        assert_eq!(
            router.match_sni(Some("api50.example.com")),
            Some("backend-50")
        );
        assert_eq!(
            router.match_sni(Some("api99.example.com")),
            Some("backend-99")
        );
        assert_eq!(router.match_sni(Some("api100.example.com")), None);
    }
}
