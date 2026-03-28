# Wicket

A Kubernetes Gateway API implementation and general-purpose reverse proxy built on [Cloudflare's Pingora](https://github.com/cloudflare/pingora) framework.

## Features

- **Fast**: Built on Pingora, the framework powering Cloudflare's edge
- **L7 + L4**: HTTP reverse proxy and TCP/TLS stream proxying with SNI routing
- **Config-driven**: Simple TOML configuration for routes and upstreams
- **Gateway API (beta)**: Kubernetes Gateway API reconciliation via `wicket-controller`; see [`docs/FEATURE_CONTRACT_MATRIX.md`](docs/FEATURE_CONTRACT_MATRIX.md) for per-capability status
- **Automatic TLS**: ACME DNS-01 and file-watch certificate management with zero-downtime rotation
- **eBPF acceleration**: Optional kernel-level socket redirection via sockmap for L4 passthrough traffic (Linux)
- **Observable**: RED-method metrics (Rate, Errors, Duration) via [Cloudflare Foundations](https://github.com/cloudflare/foundations), with optional Prometheus alerting rules and Grafana dashboards
- **Single binary**: No runtime dependencies
- **Explicit contracts**: Unsupported capabilities are validation-rejected, not silently ignored; see [`docs/FEATURE_CONTRACT_MATRIX.md`](docs/FEATURE_CONTRACT_MATRIX.md) for the authoritative feature support status

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
├── wicket/              # Main binary with CLI and telemetry
├── wicket-config/       # Configuration parsing and validation
├── wicket-core/         # L7 HTTP proxy logic (Pingora ProxyHttp)
├── wicket-stream/       # L4 TCP/TLS stream proxying
├── wicket-controller/   # Kubernetes Gateway API controller
├── wicket-tls/          # Automatic TLS certificate management (ACME, file-watch)
└── wicket-sockmap/      # eBPF sockmap kernel-level socket redirection (Linux)

deploy/
└── helm/wicket/         # Helm chart with optional monitoring templates
```

## Workspace Crates

| Crate | Description |
|-------|-------------|
| `wicket` | Main binary with CLI, telemetry, and server bootstrap |
| `wicket-config` | Configuration parsing and validation |
| `wicket-core` | Pingora HTTP proxy service and request routing |
| `wicket-stream` | L4 TCP stream proxying with SNI routing and proxy protocol |
| `wicket-controller` | Kubernetes Gateway API reconciler (GatewayClass, Gateway, HTTPRoute, TCPRoute, TLSRoute) |
| `wicket-tls` | ACME DNS-01 (Let's Encrypt), file-watch hot-reload, multi-cert SNI, zero-downtime rotation |
| `wicket-sockmap` | eBPF SK_MSG socket redirection for zero-copy L4 passthrough (Linux only, no-op stub elsewhere) |

## Dependencies

- **[Pingora](https://github.com/cloudflare/pingora)** - High-performance proxy framework
- **[Foundations](https://github.com/cloudflare/foundations)** - Production telemetry, logging, and settings
- **[libbpf-rs](https://github.com/libbpf/libbpf-rs)** - eBPF skeleton loading (optional, Linux only)

## Monitoring

The Helm chart includes optional Prometheus alerting rules, a ServiceMonitor, and Grafana dashboard ConfigMaps. Enable them in `values.yaml`:

```yaml
monitoring:
  prometheusRules:
    enabled: true
  grafanaDashboards:
    enabled: true
  proxyServiceMonitor:
    enabled: true
```

Dashboards cover proxy traffic (request rate, error rate, latency percentiles, upstream health) and controller operations (reconciliation rate, config sync lag, resource counts). Alert thresholds are configurable under `monitoring.prometheusRules.proxy` and `monitoring.prometheusRules.controller`.

## eBPF Sockmap Acceleration

On Linux, wicket can use eBPF SK_MSG programs to redirect data between paired sockets directly in the kernel, bypassing userspace copies for L4 passthrough traffic (TCP/TLS proxying). Enable with the `ebpf` feature flag:

```bash
cargo build --release --features ebpf
```

Requires `libelf-dev` and `clang` at build time. On non-Linux platforms the feature compiles to a no-op stub.

## Feature Status

The authoritative feature contract is documented in [`docs/FEATURE_CONTRACT_MATRIX.md`](docs/FEATURE_CONTRACT_MATRIX.md) and its YAML companion `docs/FEATURE_CONTRACT_MATRIX.yaml`. Each capability is marked **GA**, **Beta**, or **Unsupported**.

- **Unsupported** capabilities are rejected at validation time and never silently ignored.
- **Beta** capabilities are partially implemented; behavior may still evolve.

Current focus areas: data-plane parity, TLS unification, and controller hardening.

## License

Apache-2.0
