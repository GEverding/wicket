# Wicket

A Kubernetes Gateway API implementation and general-purpose reverse proxy built on [Cloudflare's Pingora](https://github.com/cloudflare/pingora) framework.

## Features

- **Fast**: Built on Pingora, the framework powering Cloudflare's edge
- **Config-driven**: Simple TOML configuration for routes and upstreams
- **Observable**: Production-grade telemetry via [Cloudflare Foundations](https://github.com/cloudflare/foundations)
- **Gateway API native**: Kubernetes Gateway API support (coming soon)
- **Single binary**: No runtime dependencies

## Quick Start

```bash
# Build
cargo build --release

# Run with default config
./target/release/wicket

# Run with custom config
./target/release/wicket -c /path/to/wicket.toml

# Validate configuration
./target/release/wicket --validate
```

## Configuration

Wicket uses TOML for configuration. Here's a minimal example:

```toml
[server]
listen = "127.0.0.1:8080"
json_logs = false
log_level = "info"

[upstreams.backend]
backends = ["127.0.0.1:3000"]
strategy = "round_robin"

[[routes]]
name = "default"
upstream = "backend"
[routes.match]
path_prefix = "/"
```

### Server Configuration

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `listen` | string | required | Address and port to listen on |
| `workers` | number | CPU count | Number of worker threads |
| `json_logs` | bool | true | Enable structured JSON logging |
| `log_level` | string | "info" | Log level (trace, debug, info, warn, error) |
| `shutdown_timeout` | number | 30 | Graceful shutdown timeout in seconds |

### Upstream Configuration

```toml
[upstreams.api]
backends = ["127.0.0.1:3000", "127.0.0.1:3001"]
strategy = "round_robin"  # or "consistent_hash"

[upstreams.api.health_check]
path = "/health"
interval = 10
unhealthy_threshold = 3
```

### Route Configuration

Routes are evaluated in order; the first match wins.

```toml
[[routes]]
name = "api-v1"
upstream = "api"

[routes.match]
host = "api.example.com"      # Exact host or wildcard (*.example.com)
path_prefix = "/v1"           # Path prefix match
path = "/health"              # Exact path match (mutually exclusive with path_prefix)
methods = ["GET", "POST"]     # HTTP methods to match
headers = { "x-api-key" = "secret" }  # Required headers
```

## CLI Options

```
Usage: wicket [OPTIONS]

Options:
  -c, --config <CONFIG>        Path to the configuration file [default: wicket.toml]
      --validate               Validate configuration and exit
  -l, --log-level <LOG_LEVEL>  Override log level
      --json-logs              Force JSON log output
      --dump-config            Print the parsed configuration and exit
  -h, --help                   Print help
  -V, --version                Print version
```

## Project Structure

```
crates/
├── wicket/           # Main binary with CLI and telemetry
│   └── src/
│       └── main.rs   # Entry point with foundations integration
├── wicket-config/    # Configuration parsing crate
│   └── src/
│       └── lib.rs    # TOML config types and validation
└── wicket-core/      # Core proxy logic crate
    └── src/
        ├── lib.rs
        ├── proxy.rs  # Pingora ProxyHttp implementation
        └── routing.rs # Request routing and matching
```

## Workspace Crates

| Crate | Description |
|-------|-------------|
| `wicket` | Main binary with CLI, telemetry, and server bootstrap |
| `wicket-config` | Configuration parsing and validation |
| `wicket-core` | Pingora proxy service and request routing |

## Dependencies

- **[Pingora](https://github.com/cloudflare/pingora)** - High-performance proxy framework
- **[Foundations](https://github.com/cloudflare/foundations)** - Production telemetry, logging, and settings

## Roadmap

### Phase 1 (Current)
- [x] TOML configuration parsing
- [x] Path and host-based routing
- [x] Round-robin and consistent-hash load balancing
- [x] Structured JSON logging
- [x] Request tracing with IDs
- [x] Workspace structure with modular crates
- [x] Foundations integration for telemetry

### Phase 2
- [ ] TLS termination
- [ ] Health checks with circuit breaking
- [ ] Request/response header transforms
- [ ] Rate limiting

### Phase 3
- [ ] Kubernetes Gateway API controller (kube-rs)
- [ ] Hot configuration reload (SIGHUP)
- [ ] Prometheus metrics endpoint
- [ ] OpenTelemetry integration

## License

Apache-2.0
