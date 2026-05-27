# Deployment Guide

> **Warning**
> Wicket is pre-production, alpha, experimental software. Do not use in production without understanding the risks.

## Table of Contents

- [Docker](#docker)
- [Kubernetes with Helm](#kubernetes-with-helm)
- [Kubernetes Manual Deployment](#kubernetes-manual-deployment)
- [Local Development with k3d](#local-development-with-k3d)
- [Production Considerations](#production-considerations)
- [Monitoring](#monitoring)

---

## Docker

### Building Images

Two Docker images are available: the proxy and the Gateway API controller.

```bash
# Build the proxy image
docker build -t wicket:latest .

# Build the controller image
docker build -t wicket-controller:latest -f Dockerfile.controller .
```

Both images use multi-stage builds with Rust 1.85 and produce minimal Debian slim runtime images. They run as non-root user (UID 65532).

### Running with Docker

```bash
# Run the proxy with a local config file
docker run -d \
  --name wicket \
  -p 8080:8080 \
  -p 9090:9090 \
  -v $(pwd)/wicket.toml:/etc/wicket/wicket.toml:ro \
  wicket:latest \
  -c /etc/wicket/wicket.toml

# Validate config
docker run --rm \
  -v $(pwd)/wicket.toml:/etc/wicket/wicket.toml:ro \
  wicket:latest \
  --validate -c /etc/wicket/wicket.toml
```

### Docker Compose Example

```yaml
version: "3.8"
services:
  wicket:
    build: .
    ports:
      - "8080:8080"   # HTTP proxy
      - "8443:8443"   # HTTPS proxy (if TLS configured)
      - "9090:9090"   # Prometheus metrics
    volumes:
      - ./wicket.toml:/etc/wicket/wicket.toml:ro
      - ./certs:/etc/wicket/tls:ro   # Optional: TLS certificates
    command: ["-c", "/etc/wicket/wicket.toml"]
    restart: unless-stopped
```

---

## Kubernetes with Helm

The recommended way to deploy Wicket on Kubernetes is via the Helm chart at `deploy/helm/wicket/`.

### Prerequisites

- Kubernetes 1.28+
- Helm 3.x
- Gateway API CRDs (installed automatically by the chart if `crds.install: true`)

### Installation

```bash
# Install from local chart
helm install wicket deploy/helm/wicket/ \
  --namespace wicket-system \
  --create-namespace

# Install with custom values
helm install wicket deploy/helm/wicket/ \
  --namespace wicket-system \
  --create-namespace \
  -f my-values.yaml
```

### Chart Configuration

Key values in `values.yaml`:

```yaml
# Controller deployment
controller:
  image:
    repository: ghcr.io/geverding/wicket-controller
    tag: ""  # Defaults to Chart appVersion
  replicas: 1
  resources:
    limits:
      memory: 1024Mi
    requests:
      cpu: 100m
      memory: 256Mi

# Controller config
config:
  controllerName: gateway.wicket.dev/gatewayclass-controller
  logging:
    level: info

# Install Gateway API CRDs
crds:
  install: true

# RBAC
rbac:
  create: true

# Monitoring (see Monitoring section below)
monitoring:
  prometheusRules:
    enabled: false
  grafanaDashboards:
    enabled: false
  proxyServiceMonitor:
    enabled: false
```

### Upgrading

```bash
helm upgrade wicket deploy/helm/wicket/ \
  --namespace wicket-system \
  -f my-values.yaml
```

### Uninstalling

```bash
helm uninstall wicket --namespace wicket-system
```

---

## Kubernetes Manual Deployment

For testing or environments without Helm, use the raw manifests in `deploy/k8s/`.

```bash
# Create namespace
kubectl apply -f deploy/k8s/namespace.yaml

# Deploy test backends
kubectl apply -f deploy/k8s/echo.yaml
kubectl apply -f deploy/k8s/httpbin.yaml

# Deploy Wicket proxy with config
kubectl apply -f deploy/k8s/wicket-config.yaml
kubectl apply -f deploy/k8s/wicket.yaml
```

---

## Local Development with k3d

Use [k3d](https://k3d.io/) for local Kubernetes development and testing.

### Setup

```bash
# Create a k3d cluster using the provided config
k3d cluster create -c deploy/k3d/cluster.yaml

# Build and import the proxy image
docker build -t wicket:latest .
k3d image import wicket:latest -c wicket-poc

# Build and import the controller image (if needed)
docker build -t wicket-controller:latest -f Dockerfile.controller .
k3d image import wicket-controller:latest -c wicket-poc

# Deploy Gateway API CRDs
kubectl apply -f deploy/crds/

# Deploy test workloads
kubectl apply -f deploy/k8s/namespace.yaml
kubectl apply -f deploy/k8s/echo.yaml
kubectl apply -f deploy/k8s/httpbin.yaml
kubectl apply -f deploy/k8s/wicket.yaml

# Run integration tests
./deploy/test.sh
```

### Teardown

```bash
k3d cluster delete wicket-poc
```

---

## Production Considerations

### Resource Sizing

| Component | CPU | Memory | Notes |
|-----------|-----|--------|-------|
| Proxy (low traffic) | 100m | 128Mi | < 1k req/s |
| Proxy (medium traffic) | 500m | 256Mi | 1k-10k req/s |
| Proxy (high traffic) | 2+ cores | 512Mi+ | 10k+ req/s, tune `workers` |
| Controller | 100m | 256Mi | Scales with number of K8s resources |

### Worker Threads

By default, Wicket uses one worker thread per CPU core. Override with:

```toml
[server]
workers = 4
```

For L4 stream proxying with high connection counts, consider enabling `SO_REUSEPORT`:

```toml
[[streams]]
name = "public-tls"
reuseport = true
```

### Graceful Shutdown

Wicket supports graceful shutdown. On `SIGTERM` or `SIGINT`:

1. Stops accepting new connections
2. Waits for active connections to complete (up to `shutdown_timeout` seconds)
3. Terminates remaining connections

Configure the timeout:

```toml
[server]
shutdown_timeout = 30  # seconds

[[streams]]
name = "public-tls"
drain_timeout_secs = 30  # L4 proxy drain timeout
```

In Kubernetes, ensure `terminationGracePeriodSeconds` >= `shutdown_timeout`.

### High Connection Counts (L4 Proxy)

For 400k+ concurrent connections, see the [performance tuning guide](./performance-tuning.md) for a concrete 64-core EPYC/64GB host profile. The short version:

1. **Source IP pooling**: Configure multiple source IPs to multiply available ephemeral ports
   ```toml
   [[streams]]
   name = "public-tls"
   source_ips = ["10.0.0.10", "10.0.0.11", "10.0.0.12", "10.0.0.13"]
   ```

2. **Connection limits**: Set appropriate limits to prevent resource exhaustion
   ```toml
   [[streams]]
   name = "public-tls"
   max_connections = 500000
   ```

3. **TCP backlog**: Increase for burst handling
   ```toml
   [[streams]]
   name = "public-tls"
   backlog = 16000
   ```

4. **System tuning**: Increase `ulimit -n` (file descriptors), tune `net.core.somaxconn`, and increase ephemeral port range.

Use `source_ips` for remote TCP backends when a single Wicket source address would run out of outbound ephemeral ports. Use Unix socket backends for local services on the same host when possible; `unix:/run/app/backend.sock` avoids outbound TCP ephemeral port limits entirely.

```toml
[[streams.upstreams]]
name = "local-app"
servers = ["unix:/run/local-app/backend.sock"]
```

For Unix socket backends, make the socket path absolute, ensure the Wicket process user can read and write the socket, and coordinate socket ownership with systemd `RuntimeDirectory`, `User`, `Group`, or service-specific `UMask` settings. Keep `LimitNOFILE` high enough for client TCP sockets plus backend Unix sockets; Unix sockets remove ephemeral port pressure, not file descriptor usage.

`source_ips` and eBPF sockmap acceleration are TCP-only and are skipped for Unix backends. PROXY protocol remains supported for Unix backends and carries the TCP client and Wicket listener addresses.

### eBPF Sockmap Acceleration

On Linux, enable eBPF sockmap for kernel-level socket redirection on L4 passthrough traffic:

```bash
cargo build --release --features ebpf
```

Requires `libelf-dev` and `clang` at build time. Falls back to userspace proxying if eBPF loading fails.

### Security

- Both Docker images run as non-root user (UID 65532)
- Use read-only filesystem mounts for config and certificates
- The controller uses RBAC with least-privilege access
- See [Security Audit](SECURITY_AUDIT.md) for the full threat model

---

## Monitoring

### Prometheus Metrics

The proxy exposes metrics at `--metrics-addr` (default `0.0.0.0:9090`). The controller exposes metrics on port 8081.

Enable the Helm chart monitoring stack:

```yaml
monitoring:
  prometheusRules:
    enabled: true
    proxy:
      errorRateThreshold: 0.01        # Alert at 1% error rate
      latencyP99Threshold: 1.0        # Alert at 1s p99 latency
      certExpiryWarningSeconds: 604800 # Alert 7 days before cert expiry
    controller:
      reconcileErrorRateThreshold: 0.05
      configSyncLagThreshold: 300

  grafanaDashboards:
    enabled: true
    datasource: "Prometheus"

  proxyServiceMonitor:
    enabled: true
    interval: 30s
```

### Grafana Dashboards

The Helm chart includes two Grafana dashboards (deployed as ConfigMaps):

- **Proxy Dashboard**: Request rate, error rate, latency percentiles (p50/p95/p99), upstream health, active connections, bytes in/out
- **Controller Dashboard**: Reconciliation rate, error rate, config sync lag, resource counts, leader election status

### Alert Rules

Pre-configured PrometheusRule alerts cover:

- High HTTP error rate
- High p99 latency
- TLS certificate approaching expiry
- Upstream backends unhealthy
- Controller reconciliation errors
- Config sync lag

Alert thresholds are configurable in `values.yaml` under `monitoring.prometheusRules`.

---

## CI/CD

The repository includes GitHub Actions workflows:

- **`ci.yml`**: Runs on push to main and PRs. Checks formatting (`cargo fmt`), linting (`cargo clippy`), and tests (`cargo test`).
- **`build.yml`**: Builds multi-architecture Docker images and pushes to the container registry.
