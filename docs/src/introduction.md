# Wicket

> **Warning**
> This project is **pre-production, alpha, experimental software**. APIs, configuration formats, and behaviors may change without notice between releases.

Wicket is a Kubernetes Gateway API implementation and general-purpose reverse proxy built on [Cloudflare's Pingora](https://github.com/cloudflare/pingora) framework.

## Features

- **Fast**: Built on Pingora, the framework powering Cloudflare's edge
- **L7 + L4**: HTTP reverse proxy and TCP/TLS stream proxying with SNI routing
- **Config-driven**: Simple TOML configuration for routes and upstreams
- **Gateway API (beta)**: Kubernetes Gateway API reconciliation via `wicket-controller`
- **Automatic TLS**: ACME DNS-01 and file-watch certificate management with zero-downtime rotation
- **eBPF acceleration**: Optional kernel-level socket redirection via sockmap for L4 passthrough traffic (Linux)
- **Observable**: RED-method metrics (Rate, Errors, Duration) with Prometheus alerting rules and Grafana dashboards
- **Single binary**: No runtime dependencies
- **Explicit contracts**: Unsupported capabilities are validation-rejected, not silently ignored

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

# Generate JSON Schema for configuration
./target/release/wicket --dump-schema
```

## Dependencies

- **[Pingora](https://github.com/cloudflare/pingora)** - High-performance proxy framework
- **[Foundations](https://github.com/cloudflare/foundations)** - Production telemetry, logging, and settings
- **[libbpf-rs](https://github.com/libbpf/libbpf-rs)** - eBPF skeleton loading (optional, Linux only)

## License

Apache-2.0
