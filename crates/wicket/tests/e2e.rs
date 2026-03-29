//! End-to-end tests for the Wicket HTTP proxy.
//!
//! These tests start a real Pingora server with WicketProxy, send HTTP
//! requests through it via reqwest, and verify they reach mock backends
//! and return correct responses.

mod helpers;

use helpers::{free_port, HttpMockBackend, TestProxy};
use wicket_config::Config;

/// Helper: build a Config from TOML with backend port placeholders replaced.
fn config_with_ports(toml_template: &str, replacements: &[(&str, u16)]) -> Config {
    let mut toml = toml_template.to_string();
    for (placeholder, port) in replacements {
        toml = toml.replace(placeholder, &port.to_string());
    }
    Config::parse(&toml).expect("test config should parse")
}

// ── Basic proxying ──────────────────────────────────────────────────────────

#[tokio::test]
async fn test_proxy_basic_request() {
    let backend = HttpMockBackend::start("hello from backend").await;
    let proxy_port = free_port();

    let config = config_with_ports(
        r#"
[server]
listen = "127.0.0.1:{{PROXY_PORT}}"

[upstreams.backend]
backends = ["127.0.0.1:{{BACKEND_PORT}}"]

[[routes]]
name = "default"
upstream = "backend"
[routes.match]
path_prefix = "/"
"#,
        &[
            ("{{PROXY_PORT}}", proxy_port),
            ("{{BACKEND_PORT}}", backend.addr.port()),
        ],
    );

    let proxy = TestProxy::start(&config);

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://127.0.0.1:{}/hello", proxy_port))
        .send()
        .await
        .expect("request should succeed");

    assert_eq!(resp.status(), 200);
    let body = resp.text().await.expect("read body");
    assert_eq!(body, "hello from backend");

    // Backend should have received exactly one request
    assert_eq!(backend.request_count().await, 1);
    let req = backend.last_request().await.expect("should have a request");
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/hello");

    drop(proxy);
}

// ── Host-based routing ──────────────────────────────────────────────────────

#[tokio::test]
async fn test_proxy_host_routing() {
    let api_backend = HttpMockBackend::start("api response").await;
    let web_backend = HttpMockBackend::start("web response").await;
    let proxy_port = free_port();

    let config = config_with_ports(
        r#"
[server]
listen = "127.0.0.1:{{PROXY_PORT}}"

[upstreams.api]
backends = ["127.0.0.1:{{API_PORT}}"]

[upstreams.web]
backends = ["127.0.0.1:{{WEB_PORT}}"]

[[routes]]
name = "api"
upstream = "api"
[routes.match]
host = "api.test.local"
path_prefix = "/"

[[routes]]
name = "web"
upstream = "web"
[routes.match]
host = "web.test.local"
path_prefix = "/"
"#,
        &[
            ("{{PROXY_PORT}}", proxy_port),
            ("{{API_PORT}}", api_backend.addr.port()),
            ("{{WEB_PORT}}", web_backend.addr.port()),
        ],
    );

    let proxy = TestProxy::start(&config);
    let client = reqwest::Client::new();
    let base = format!("http://127.0.0.1:{}", proxy_port);

    // Request with Host: api.test.local should reach api backend
    let resp = client
        .get(format!("{}/data", base))
        .header("Host", "api.test.local")
        .send()
        .await
        .expect("api request");
    assert_eq!(resp.text().await.unwrap(), "api response");
    assert_eq!(api_backend.request_count().await, 1);
    assert_eq!(web_backend.request_count().await, 0);

    // Request with Host: web.test.local should reach web backend
    let resp = client
        .get(format!("{}/page", base))
        .header("Host", "web.test.local")
        .send()
        .await
        .expect("web request");
    assert_eq!(resp.text().await.unwrap(), "web response");
    assert_eq!(web_backend.request_count().await, 1);

    drop(proxy);
}

// ── Path-based routing ──────────────────────────────────────────────────────

#[tokio::test]
async fn test_proxy_path_routing() {
    let api_backend = HttpMockBackend::start("api").await;
    let static_backend = HttpMockBackend::start("static").await;
    let proxy_port = free_port();

    let config = config_with_ports(
        r#"
[server]
listen = "127.0.0.1:{{PROXY_PORT}}"

[upstreams.api]
backends = ["127.0.0.1:{{API_PORT}}"]

[upstreams.static-files]
backends = ["127.0.0.1:{{STATIC_PORT}}"]

[[routes]]
name = "api"
upstream = "api"
[routes.match]
path_prefix = "/api"

[[routes]]
name = "static"
upstream = "static-files"
[routes.match]
path_prefix = "/static"
"#,
        &[
            ("{{PROXY_PORT}}", proxy_port),
            ("{{API_PORT}}", api_backend.addr.port()),
            ("{{STATIC_PORT}}", static_backend.addr.port()),
        ],
    );

    let proxy = TestProxy::start(&config);
    let client = reqwest::Client::new();
    let base = format!("http://127.0.0.1:{}", proxy_port);

    let resp = client
        .get(format!("{}/api/users", base))
        .send()
        .await
        .expect("api request");
    assert_eq!(resp.text().await.unwrap(), "api");

    let resp = client
        .get(format!("{}/static/style.css", base))
        .send()
        .await
        .expect("static request");
    assert_eq!(resp.text().await.unwrap(), "static");

    assert_eq!(api_backend.request_count().await, 1);
    assert_eq!(static_backend.request_count().await, 1);

    drop(proxy);
}

// ── Header injection: X-Request-Id ──────────────────────────────────────────

#[tokio::test]
async fn test_proxy_x_request_id_injection() {
    let backend = HttpMockBackend::start("ok").await;
    let proxy_port = free_port();

    let config = config_with_ports(
        r#"
[server]
listen = "127.0.0.1:{{PROXY_PORT}}"

[upstreams.backend]
backends = ["127.0.0.1:{{BACKEND_PORT}}"]

[[routes]]
upstream = "backend"
[routes.match]
path_prefix = "/"
"#,
        &[
            ("{{PROXY_PORT}}", proxy_port),
            ("{{BACKEND_PORT}}", backend.addr.port()),
        ],
    );

    let proxy = TestProxy::start(&config);
    let client = reqwest::Client::new();

    client
        .get(format!("http://127.0.0.1:{}/test", proxy_port))
        .send()
        .await
        .expect("request");

    let req = backend.last_request().await.expect("should have request");

    // The proxy should inject an x-request-id header
    let has_request_id = req
        .headers
        .iter()
        .any(|(k, _)| k == "x-request-id");
    assert!(
        has_request_id,
        "backend should receive x-request-id header, got headers: {:?}",
        req.headers
    );

    drop(proxy);
}

// ── Header injection: X-Forwarded-For ───────────────────────────────────────

#[tokio::test]
async fn test_proxy_x_forwarded_for_injection() {
    let backend = HttpMockBackend::start("ok").await;
    let proxy_port = free_port();

    let config = config_with_ports(
        r#"
[server]
listen = "127.0.0.1:{{PROXY_PORT}}"

[upstreams.backend]
backends = ["127.0.0.1:{{BACKEND_PORT}}"]

[[routes]]
upstream = "backend"
[routes.match]
path_prefix = "/"
"#,
        &[
            ("{{PROXY_PORT}}", proxy_port),
            ("{{BACKEND_PORT}}", backend.addr.port()),
        ],
    );

    let proxy = TestProxy::start(&config);
    let client = reqwest::Client::new();

    client
        .get(format!("http://127.0.0.1:{}/test", proxy_port))
        .send()
        .await
        .expect("request");

    let req = backend.last_request().await.expect("should have request");

    let xff = req
        .headers
        .iter()
        .find(|(k, _)| k == "x-forwarded-for")
        .map(|(_, v)| v.as_str());
    assert!(
        xff.is_some(),
        "backend should receive x-forwarded-for header, got headers: {:?}",
        req.headers
    );
    // Client connects from 127.0.0.1
    assert!(
        xff.unwrap().contains("127.0.0.1"),
        "x-forwarded-for should contain 127.0.0.1, got: {}",
        xff.unwrap()
    );

    drop(proxy);
}

// ── Route not found ─────────────────────────────────────────────────────────

#[tokio::test]
async fn test_proxy_route_not_found() {
    let backend = HttpMockBackend::start("ok").await;
    let proxy_port = free_port();

    let config = config_with_ports(
        r#"
[server]
listen = "127.0.0.1:{{PROXY_PORT}}"

[upstreams.backend]
backends = ["127.0.0.1:{{BACKEND_PORT}}"]

[[routes]]
name = "specific"
upstream = "backend"
[routes.match]
host = "known.example.com"
path_prefix = "/"
"#,
        &[
            ("{{PROXY_PORT}}", proxy_port),
            ("{{BACKEND_PORT}}", backend.addr.port()),
        ],
    );

    let proxy = TestProxy::start(&config);
    let client = reqwest::Client::new();

    // Request with an unmatched host should get an error status
    let resp = client
        .get(format!("http://127.0.0.1:{}/test", proxy_port))
        .header("Host", "unknown.example.com")
        .send()
        .await
        .expect("request should complete");

    // Pingora returns 404 when no route matches (from upstream_peer)
    assert!(
        resp.status().is_client_error() || resp.status().is_server_error(),
        "unmatched route should return error status, got: {}",
        resp.status()
    );

    // Backend should NOT have received the request
    assert_eq!(backend.request_count().await, 0);

    drop(proxy);
}

// ── Round-robin distribution ────────────────────────────────────────────────

#[tokio::test]
async fn test_proxy_round_robin_distribution() {
    let backend1 = HttpMockBackend::start("b1").await;
    let backend2 = HttpMockBackend::start("b2").await;
    let proxy_port = free_port();

    let config = config_with_ports(
        r#"
[server]
listen = "127.0.0.1:{{PROXY_PORT}}"

[upstreams.pool]
backends = ["127.0.0.1:{{B1_PORT}}", "127.0.0.1:{{B2_PORT}}"]
strategy = "round_robin"

[[routes]]
upstream = "pool"
[routes.match]
path_prefix = "/"
"#,
        &[
            ("{{PROXY_PORT}}", proxy_port),
            ("{{B1_PORT}}", backend1.addr.port()),
            ("{{B2_PORT}}", backend2.addr.port()),
        ],
    );

    let proxy = TestProxy::start(&config);
    let client = reqwest::Client::new();
    let url = format!("http://127.0.0.1:{}/test", proxy_port);

    // Send several requests; both backends should get at least one
    for _ in 0..6 {
        client.get(&url).send().await.expect("request");
    }

    let c1 = backend1.request_count().await;
    let c2 = backend2.request_count().await;

    assert!(
        c1 > 0 && c2 > 0,
        "both backends should receive requests with round-robin, got b1={} b2={}",
        c1,
        c2
    );
    assert_eq!(c1 + c2, 6, "total requests should be 6");

    drop(proxy);
}

// ── Config reload adds route ────────────────────────────────────────────────

#[tokio::test]
async fn test_proxy_reload_adds_route() {
    let backend = HttpMockBackend::start("original").await;
    let new_backend = HttpMockBackend::start("added").await;
    let proxy_port = free_port();

    let config = config_with_ports(
        r#"
[server]
listen = "127.0.0.1:{{PROXY_PORT}}"

[upstreams.original]
backends = ["127.0.0.1:{{BACKEND_PORT}}"]

[[routes]]
name = "original"
upstream = "original"
[routes.match]
host = "app.test.local"
path_prefix = "/"
"#,
        &[
            ("{{PROXY_PORT}}", proxy_port),
            ("{{BACKEND_PORT}}", backend.addr.port()),
        ],
    );

    let proxy = TestProxy::start(&config);
    let client = reqwest::Client::new();
    let base = format!("http://127.0.0.1:{}", proxy_port);

    // Verify original route works
    let resp = client
        .get(format!("{}/test", base))
        .header("Host", "app.test.local")
        .send()
        .await
        .expect("original request");
    assert_eq!(resp.text().await.unwrap(), "original");

    // New route should not work yet
    let resp = client
        .get(format!("{}/test", base))
        .header("Host", "new.test.local")
        .send()
        .await
        .expect("request to unmatched host");
    assert!(resp.status().is_client_error() || resp.status().is_server_error());

    // Reload with new route added
    let new_config = config_with_ports(
        r#"
[server]
listen = "127.0.0.1:{{PROXY_PORT}}"

[upstreams.original]
backends = ["127.0.0.1:{{BACKEND_PORT}}"]

[upstreams.added]
backends = ["127.0.0.1:{{NEW_BACKEND_PORT}}"]

[[routes]]
name = "original"
upstream = "original"
[routes.match]
host = "app.test.local"
path_prefix = "/"

[[routes]]
name = "added"
upstream = "added"
[routes.match]
host = "new.test.local"
path_prefix = "/"
"#,
        &[
            ("{{PROXY_PORT}}", proxy_port),
            ("{{BACKEND_PORT}}", backend.addr.port()),
            ("{{NEW_BACKEND_PORT}}", new_backend.addr.port()),
        ],
    );

    proxy
        .reload_handle
        .reload(&new_config)
        .expect("reload should succeed");

    // New route should now work
    let resp = client
        .get(format!("{}/test", base))
        .header("Host", "new.test.local")
        .send()
        .await
        .expect("new route request");
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "added");

    // Original route should still work
    let resp = client
        .get(format!("{}/test", base))
        .header("Host", "app.test.local")
        .send()
        .await
        .expect("original still works");
    assert_eq!(resp.text().await.unwrap(), "original");

    drop(proxy);
}
