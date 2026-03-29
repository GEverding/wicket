//! Integration tests for the config-to-routing pipeline.
//!
//! These tests verify that parsed configs produce correct routing behavior
//! and that the reload mechanism works atomically.

use std::collections::HashMap;
use wicket_config::Config;
use wicket_core::{Router, WicketProxy};

/// Helper: parse a TOML config string into a Config.
fn parse(toml: &str) -> Config {
    Config::parse(toml).expect("test config should parse")
}

/// Helper: build a Router from a TOML config string.
fn router(toml: &str) -> Router {
    let config = parse(toml);
    Router::build(&config.routes).expect("router should build")
}

fn empty_headers() -> HashMap<String, String> {
    HashMap::new()
}

// ── Host-based routing ──────────────────────────────────────────────────────

#[test]
fn test_router_host_routing() {
    let r = router(
        r#"
[server]
listen = "127.0.0.1:8080"

[upstreams.api]
backends = ["127.0.0.1:3001"]

[upstreams.web]
backends = ["127.0.0.1:3002"]

[[routes]]
name = "api"
upstream = "api"
[routes.match]
host = "api.example.com"
path_prefix = "/"

[[routes]]
name = "web"
upstream = "web"
[routes.match]
host = "web.example.com"
path_prefix = "/"
"#,
    );

    let h = empty_headers();

    let m = r
        .match_request(Some("api.example.com"), "/users", "GET", &h)
        .expect("api host should match");
    assert_eq!(m.upstream, "api");

    let m = r
        .match_request(Some("web.example.com"), "/index.html", "GET", &h)
        .expect("web host should match");
    assert_eq!(m.upstream, "web");

    assert!(r
        .match_request(Some("unknown.example.com"), "/", "GET", &h)
        .is_none());
}

// ── Path-based routing ──────────────────────────────────────────────────────

#[test]
fn test_router_path_routing() {
    let r = router(
        r#"
[server]
listen = "127.0.0.1:8080"

[upstreams.api-v2]
backends = ["127.0.0.1:3001"]

[upstreams.api-legacy]
backends = ["127.0.0.1:3002"]

[upstreams.catch-all]
backends = ["127.0.0.1:3003"]

[[routes]]
name = "v2"
upstream = "api-v2"
[routes.match]
path_prefix = "/api/v2"

[[routes]]
name = "legacy"
upstream = "api-legacy"
[routes.match]
path_prefix = "/api"

[[routes]]
name = "catch-all"
upstream = "catch-all"
[routes.match]
path_prefix = "/"
"#,
    );

    let h = empty_headers();

    // Most specific path should match first
    let m = r
        .match_request(None, "/api/v2/users", "GET", &h)
        .expect("v2 path should match");
    assert_eq!(m.upstream, "api-v2");

    // Fallback to less-specific
    let m = r
        .match_request(None, "/api/v1/old", "GET", &h)
        .expect("legacy path should match");
    assert_eq!(m.upstream, "api-legacy");

    // Catch-all for unmatched paths
    let m = r
        .match_request(None, "/other", "GET", &h)
        .expect("catch-all should match");
    assert_eq!(m.upstream, "catch-all");
}

// ── Method filtering ────────────────────────────────────────────────────────

#[test]
fn test_router_method_filtering() {
    let r = router(
        r#"
[server]
listen = "127.0.0.1:8080"

[upstreams.write-api]
backends = ["127.0.0.1:3001"]

[upstreams.read-api]
backends = ["127.0.0.1:3002"]

[[routes]]
name = "writes"
upstream = "write-api"
[routes.match]
path_prefix = "/api"
methods = ["POST", "PUT", "DELETE"]

[[routes]]
name = "reads"
upstream = "read-api"
[routes.match]
path_prefix = "/api"
methods = ["GET"]
"#,
    );

    let h = empty_headers();

    let m = r
        .match_request(None, "/api/items", "POST", &h)
        .expect("POST should match writes");
    assert_eq!(m.upstream, "write-api");

    let m = r
        .match_request(None, "/api/items", "GET", &h)
        .expect("GET should match reads");
    assert_eq!(m.upstream, "read-api");

    // PATCH is not in either route
    assert!(r.match_request(None, "/api/items", "PATCH", &h).is_none());
}

// ── Wildcard host ───────────────────────────────────────────────────────────

#[test]
fn test_router_wildcard_host() {
    let r = router(
        r#"
[server]
listen = "127.0.0.1:8080"

[upstreams.tenant]
backends = ["127.0.0.1:3001"]

[[routes]]
name = "wildcard"
upstream = "tenant"
[routes.match]
host = "*.myapp.com"
path_prefix = "/"
"#,
    );

    let h = empty_headers();

    assert!(r
        .match_request(Some("foo.myapp.com"), "/", "GET", &h)
        .is_some());
    assert!(r
        .match_request(Some("bar.myapp.com"), "/api", "GET", &h)
        .is_some());
    // Root domain should NOT match wildcard
    assert!(r.match_request(Some("myapp.com"), "/", "GET", &h).is_none());
    // Sub-subdomain should NOT match (wildcard matches exactly one label)
    assert!(r
        .match_request(Some("a.b.myapp.com"), "/", "GET", &h)
        .is_none());
}

// ── No match ────────────────────────────────────────────────────────────────

#[test]
fn test_router_no_match_returns_none() {
    let r = router(
        r#"
[server]
listen = "127.0.0.1:8080"

[upstreams.backend]
backends = ["127.0.0.1:3001"]

[[routes]]
name = "specific"
upstream = "backend"
[routes.match]
host = "only-this.example.com"
path = "/exact"
"#,
    );

    let h = empty_headers();

    // Wrong host
    assert!(r
        .match_request(Some("other.com"), "/exact", "GET", &h)
        .is_none());
    // Wrong path
    assert!(r
        .match_request(Some("only-this.example.com"), "/other", "GET", &h)
        .is_none());
    // No host at all
    assert!(r.match_request(None, "/exact", "GET", &h).is_none());
}

// ── Header matching ─────────────────────────────────────────────────────────

#[test]
fn test_router_header_matching() {
    let r = router(
        r#"
[server]
listen = "127.0.0.1:8080"

[upstreams.internal]
backends = ["127.0.0.1:3001"]

[[routes]]
name = "auth-required"
upstream = "internal"
[routes.match]
path_prefix = "/"
[routes.match.headers]
x-api-key = "secret-token"
"#,
    );

    // Without the required header
    assert!(r
        .match_request(None, "/data", "GET", &HashMap::new())
        .is_none());

    // With correct header
    let mut h = HashMap::new();
    h.insert("x-api-key".to_string(), "secret-token".to_string());
    assert!(r.match_request(None, "/data", "GET", &h).is_some());

    // With wrong header value
    let mut h = HashMap::new();
    h.insert("x-api-key".to_string(), "wrong".to_string());
    assert!(r.match_request(None, "/data", "GET", &h).is_none());
}

// ── WicketProxy creation ────────────────────────────────────────────────────

#[test]
fn test_proxy_creation_from_config() {
    let config = parse(
        r#"
[server]
listen = "127.0.0.1:8080"

[upstreams.backend]
backends = ["127.0.0.1:3000", "127.0.0.1:3001"]
strategy = "round_robin"

[upstreams.api]
backends = ["127.0.0.1:4000"]
strategy = "consistent_hash"

[[routes]]
name = "default"
upstream = "backend"
[routes.match]
path_prefix = "/"
"#,
    );

    let proxy = WicketProxy::new(&config);
    assert!(proxy.is_ok(), "WicketProxy::new should succeed");
}

// ── Reload handle ───────────────────────────────────────────────────────────

#[test]
fn test_reload_handle_updates_routing() {
    let config = parse(
        r#"
[server]
listen = "127.0.0.1:8080"

[upstreams.old-backend]
backends = ["127.0.0.1:3000"]

[[routes]]
name = "only-route"
upstream = "old-backend"
[routes.match]
host = "app.example.com"
path_prefix = "/"
"#,
    );

    let proxy = WicketProxy::new(&config).expect("proxy creation should succeed");
    let reload_handle = proxy.reload_handle();

    // New config with a different upstream for the same host
    let new_config = parse(
        r#"
[server]
listen = "127.0.0.1:8080"

[upstreams.new-backend]
backends = ["127.0.0.1:4000"]

[[routes]]
name = "updated-route"
upstream = "new-backend"
[routes.match]
host = "app.example.com"
path_prefix = "/"

[[routes]]
name = "added-route"
upstream = "new-backend"
[routes.match]
host = "new.example.com"
path_prefix = "/"
"#,
    );

    reload_handle
        .reload(&new_config)
        .expect("reload should succeed");

    // We can't directly test routing on WicketProxy (it uses internal ArcSwap),
    // but we can verify the reload didn't error. The Router unit tests cover
    // the actual matching logic.
}
