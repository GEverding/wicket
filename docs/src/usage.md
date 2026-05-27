# Usage Guide

> **Warning**
> Wicket is pre-production, alpha, experimental software. APIs and behaviors may change without notice.

## Prerequisites

- **Rust 1.85+** (for building from source)
- **Docker** (optional, for containerized deployment)
- **Kubernetes 1.28+** (optional, for Gateway API mode)

## Building from Source

```bash
# Build all crates (release mode recommended)
cargo build --release

# Build only the proxy binary
cargo build --release -p wicket

# Build the Kubernetes Gateway API controller
cargo build --release -p wicket-controller

# Build with eBPF sockmap acceleration (Linux only, requires clang + libelf-dev)
cargo build --release --features ebpf
```

The binaries are located at:
- `target/release/wicket` - Main proxy
- `target/release/wicket-controller` - Kubernetes Gateway API controller

## Running Wicket

### Basic Usage

```bash
# Run with the default config file (wicket.toml in current directory)
./target/release/wicket

# Run with a specific config file
./target/release/wicket -c /path/to/wicket.toml

# Validate configuration without starting the server
./target/release/wicket --validate

# Print the parsed configuration and exit
./target/release/wicket --dump-config
```

### CLI Options

```
Usage: wicket [OPTIONS]

Options:
  -c, --config <CONFIG>            Path to the configuration file [default: wicket.toml]
      --validate                   Validate configuration and exit
  -l, --log-level <LOG_LEVEL>      Override log level (trace, debug, info, warn, error)
      --json-logs                  Force JSON log output
      --dump-config                Print the parsed configuration and exit
      --metrics-addr <METRICS_ADDR> Prometheus metrics server address [default: 0.0.0.0:9090]
  -h, --help                       Print help
  -V, --version                    Print version
```

### Running Modes

#### Standalone Reverse Proxy (L7)

The default mode. Wicket acts as an HTTP reverse proxy, routing requests based on host, path, method, and headers.

```bash
./target/release/wicket -c wicket.toml
```

Wicket listens for HTTP on `server.listen` (default `127.0.0.1:8080`) and forwards requests to configured upstreams. When `[tls]` is configured, HTTPS is a separate listener. Use `server.https_listen = "0.0.0.0:443"` for HTTPS on port 443; `server.listen = "0.0.0.0:443"` means HTTP on port 443.

#### L4 TCP/TLS Stream Proxy

When one or more `[[streams]]` entries are present in the config, Wicket also starts TCP stream listeners that route connections based on SNI (Server Name Indication) without terminating TLS.

```toml
[[streams]]
name = "public-http"
listen = "PUBLIC_TCP_IP:80"
default_upstream = "http-passthrough"

[[streams.upstreams]]
name = "http-passthrough"
servers = ["10.0.0.10:80"]

[[streams]]
name = "public-tls"
listen = "PUBLIC_TCP_IP:443"

[streams.sni_routes]
"api.example.com" = "api-backend"

[[streams.upstreams]]
name = "api-backend"
servers = ["10.0.0.1:443"]
```

`name` and `listen` must be unique across `[[streams]]`.

#### Kubernetes Gateway API Controller

The `wicket-controller` binary watches Kubernetes Gateway API resources (GatewayClass, Gateway, HTTPRoute, TCPRoute, TLSRoute) and generates Wicket proxy configuration automatically.

```bash
./target/release/wicket-controller \
  --namespace wicket-system \
  --metrics-addr 0.0.0.0:8081
```

See the [Deployment Guide](DEPLOYMENT.md) for Kubernetes setup.

## Configuration Validation

Wicket validates the full configuration at startup and rejects invalid configs with clear error messages:

```bash
# Validate only
./target/release/wicket --validate
# Output: Configuration at wicket.toml is valid

# See the parsed config
./target/release/wicket --dump-config
```

Unsupported features (unsupported filter types, timeouts, path regex) are rejected at validation time rather than silently ignored. See the [Feature Contract Matrix](FEATURE_CONTRACT_MATRIX.md) for details.

## Hot Reload

Wicket watches the config file for changes and automatically reloads routes and upstreams without restarting. The reload is atomic -- if the new config is invalid, the running config is preserved.

For stream proxying: listener set changes require restart (add/remove a `[[streams]]` entry, or change `name`/`listen`). Unchanged listeners can hot-reload routes/upstreams/timeouts.

The config file is polled every 2 seconds. Active connections continue with the previous configuration; new connections use the updated config.

## Logging

Wicket uses structured logging via [Cloudflare Foundations](https://github.com/cloudflare/foundations).

```bash
# Text logs (development)
./target/release/wicket -l debug

# JSON logs (production)
./target/release/wicket --json-logs -l info
```

Each request logs: request ID, method, path, host, status code, duration, route name, and upstream name. Stream logs include listener `name` and `listen`.

## Metrics

Prometheus metrics are exposed at the address specified by `--metrics-addr` (default `0.0.0.0:9090`).

```bash
# Scrape metrics
curl http://localhost:9090/metrics
```

Key metrics follow the RED pattern (Rate, Errors, Duration). Stream metrics are currently aggregate across listeners:

| Metric | Type | Description |
|--------|------|-------------|
| `wicket_http_requests_total` | Counter | Total HTTP requests by method, route, status |
| `wicket_http_errors_total` | Counter | HTTP error responses (4xx/5xx) |
| `wicket_http_request_duration_seconds` | Histogram | Request latency by method and route |
| `wicket_upstream_errors_total` | Counter | Upstream connection errors |
| `wicket_upstream_duration_seconds` | Histogram | Upstream response time |
| `wicket_client_connections_active` | Gauge | Active client connections |
| `wicket_upstream_health` | Gauge | Backend health status (1=healthy, 0=unhealthy) |
| `wicket_tls_certificate_expiry_timestamp_seconds` | Gauge | Certificate expiry Unix timestamp |

Stream proxy metrics are prefixed with `wicket_stream_*`.

## Health Checks

HTTP upstream health checks are configured per-upstream:

```toml
[upstreams.api.health_check]
path = "/health"
interval = 10           # seconds between checks
unhealthy_threshold = 3 # failures before marking unhealthy
```

The stream (L4) proxy uses passive health tracking -- backends are marked unhealthy based on connection failures and recover automatically after a cooldown period (default 30 seconds).

## Testing

```bash
# Run all tests
cargo test --workspace

# Run tests for a specific crate
cargo test -p wicket-core
cargo test -p wicket-stream

# Run tests with output
cargo test --workspace -- --nocapture

# Run a specific test
cargo test -p wicket-core routing
```

## Quick Start Example

1. Start a backend server (e.g., a simple HTTP server on port 3000)

2. Create a minimal `wicket.toml`:

```toml
[server]
listen = "127.0.0.1:8080"
json_logs = false
log_level = "info"

[upstreams.backend]
backends = ["127.0.0.1:3000"]

[[routes]]
name = "default"
upstream = "backend"
[routes.match]
path_prefix = "/"
```

3. Run Wicket:

```bash
cargo run --release -- -c wicket.toml
```

4. Send a request:

```bash
curl http://127.0.0.1:8080/
```

The request is proxied to `127.0.0.1:3000` and the response is returned to the client.
