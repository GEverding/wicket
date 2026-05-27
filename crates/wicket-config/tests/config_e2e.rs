//! End-to-end tests for wicket-config: TOML parsing pipeline.
//!
//! These tests exercise the full Config::load() and Config::parse() paths,
//! verifying that real TOML configs produce correct Config structs.

use std::io::Write;
use tempfile::NamedTempFile;
use wicket_config::Config;

/// Helper: write TOML to a temp file and load it via Config::load().
fn load_toml(toml: &str) -> Result<Config, anyhow::Error> {
    let mut f = NamedTempFile::new().unwrap();
    f.write_all(toml.as_bytes()).unwrap();
    Config::load(f.path())
}

#[test]
fn test_load_minimal_config() {
    let config = load_toml(
        r#"
[server]
listen = "127.0.0.1:8080"

[upstreams.backend]
backends = ["127.0.0.1:3000"]

[[routes]]
name = "default"
upstream = "backend"
[routes.match]
path_prefix = "/"
"#,
    )
    .expect("minimal config should parse");

    assert_eq!(config.server.listen.port(), 8080);
    assert!(config.upstreams.contains_key("backend"));
    assert_eq!(config.upstreams["backend"].backends, vec!["127.0.0.1:3000"]);
    assert_eq!(config.routes.len(), 1);
    assert_eq!(config.routes[0].name.as_deref(), Some("default"));
    assert_eq!(config.routes[0].upstream, "backend");
    assert_eq!(
        config.routes[0].match_rules.path_prefix.as_deref(),
        Some("/")
    );
    assert!(config.tls.is_none());
    assert!(config.streams.is_empty());
}

#[test]
fn test_load_multi_upstream_multi_route() {
    let config = load_toml(
        r#"
[server]
listen = "0.0.0.0:80"
workers = 4
json_logs = true
log_level = "debug"

[upstreams.api]
backends = ["10.0.0.1:3000", "10.0.0.2:3000"]
strategy = "round_robin"

[upstreams.static-files]
backends = ["10.0.0.5:8080"]
strategy = "consistent_hash"

[upstreams.admin]
backends = ["10.0.0.10:9000"]

[[routes]]
name = "api-v2"
upstream = "api"
[routes.match]
host = "api.example.com"
path_prefix = "/v2"
methods = ["GET", "POST"]

[[routes]]
name = "static"
upstream = "static-files"
[routes.match]
path_prefix = "/static"

[[routes]]
name = "admin"
upstream = "admin"
[routes.match]
host = "admin.example.com"
path_prefix = "/"
"#,
    )
    .expect("multi config should parse");

    assert_eq!(config.server.listen.port(), 80);
    assert_eq!(config.server.workers, Some(4));
    assert!(config.server.json_logs);
    assert_eq!(config.server.log_level, "debug");
    assert_eq!(config.upstreams.len(), 3);
    assert_eq!(config.upstreams["api"].backends.len(), 2);
    assert_eq!(
        config.upstreams["static-files"].strategy,
        wicket_config::LoadBalanceStrategy::ConsistentHash
    );
    assert_eq!(config.routes.len(), 3);
    assert_eq!(config.routes[0].match_rules.methods, vec!["GET", "POST"]);
    assert_eq!(
        config.routes[0].match_rules.host.as_deref(),
        Some("api.example.com")
    );
}

#[test]
fn test_load_stream_config() {
    let config = load_toml(
        r#"
[server]
listen = "127.0.0.1:8080"

[upstreams.backend]
backends = ["127.0.0.1:3000"]

[[routes]]
upstream = "backend"
[routes.match]
path_prefix = "/"

[[streams]]
name = "tls-passthrough"
listen = "0.0.0.0:8443"
backlog = 4096
proxy_protocol = "v2"
default_upstream = "echo"

[streams.sni_routes]
"api.example.com" = "api-back"
"*.internal.com" = "internal-back"

[[streams.upstreams]]
name = "echo"
servers = ["127.0.0.1:3001"]

[[streams.upstreams]]
name = "api-back"
servers = ["127.0.0.1:5443"]

[[streams.upstreams]]
name = "internal-back"
servers = ["127.0.0.1:6443"]
"#,
    )
    .expect("stream config should parse");

    assert_eq!(config.streams.len(), 1);
    let stream = &config.streams[0];
    assert_eq!(stream.name, "tls-passthrough");
    assert_eq!(stream.listen, "0.0.0.0:8443");
    assert_eq!(stream.backlog, 4096);
    assert_eq!(
        stream.proxy_protocol,
        wicket_config::ProxyProtocolConfig::V2
    );
    assert_eq!(stream.default_upstream.as_deref(), Some("echo"));
    assert_eq!(stream.sni_routes.len(), 2);
    assert_eq!(stream.upstreams.len(), 3);
    assert!(stream.sni_routes.contains_key("api.example.com"));
    assert!(stream.sni_routes.contains_key("*.internal.com"));
}

#[test]
fn test_parse_invalid_toml_errors() {
    let result = Config::parse("this is not { valid toml !!!");
    assert!(result.is_err(), "invalid TOML should return error");
}

#[test]
fn test_parse_missing_server_section_errors() {
    let result = Config::parse(
        r#"
[upstreams.backend]
backends = ["127.0.0.1:3000"]
"#,
    );
    assert!(result.is_err(), "missing [server] should return error");
}

#[test]
fn test_validation_route_references_missing_upstream() {
    let result = Config::parse(
        r#"
[server]
listen = "127.0.0.1:8080"

[upstreams.real-backend]
backends = ["127.0.0.1:3000"]

[[routes]]
name = "bad-route"
upstream = "nonexistent"
[routes.match]
path_prefix = "/"
"#,
    );
    assert!(result.is_err(), "referencing missing upstream should error");
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("nonexistent"),
        "error should mention the missing upstream name: {}",
        err_msg
    );
}

#[test]
fn test_load_from_file_matches_parse() {
    let toml = r#"
[server]
listen = "127.0.0.1:9090"

[upstreams.web]
backends = ["127.0.0.1:4000"]

[[routes]]
name = "web"
upstream = "web"
[routes.match]
path_prefix = "/"
"#;

    let from_parse = Config::parse(toml).expect("parse should succeed");
    let from_load = load_toml(toml).expect("load should succeed");

    assert_eq!(from_parse.server.listen, from_load.server.listen);
    assert_eq!(from_parse.routes.len(), from_load.routes.len());
    assert_eq!(from_parse.upstreams.len(), from_load.upstreams.len());
}

#[test]
fn test_config_defaults() {
    let config = Config::parse(
        r#"
[server]
listen = "127.0.0.1:8080"

[upstreams.backend]
backends = ["127.0.0.1:3000"]

[[routes]]
upstream = "backend"
[routes.match]
path_prefix = "/"
"#,
    )
    .expect("config with defaults should parse");

    // Check defaults are applied
    assert_eq!(config.server.log_level, "info");
    assert_eq!(config.server.shutdown_timeout, 30);
    assert!(config.server.workers.is_none());
    assert_eq!(
        config.upstreams["backend"].strategy,
        wicket_config::LoadBalanceStrategy::RoundRobin
    );
}

#[test]
fn test_load_nonexistent_file_errors() {
    let result = Config::load("/tmp/definitely-does-not-exist-wicket-test.toml");
    assert!(result.is_err(), "loading nonexistent file should error");
}
