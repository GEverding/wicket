# Wicket Helm Chart

> **Warning**
> This chart deploys pre-production, alpha, experimental software.

Deploy the Wicket Gateway API controller and proxy on Kubernetes.

## Prerequisites

- Kubernetes 1.25+
- Helm 3.x
- Gateway API CRDs (installed automatically if `crds.install: true`)

## Quick Start

```bash
helm install wicket ./deploy/helm/wicket \
  --namespace wicket-system \
  --create-namespace
```

## Architecture

This chart deploys two components:

| Component | Description | Default |
|-----------|-------------|---------|
| **Controller** | Watches Gateway API resources (GatewayClass, Gateway, HTTPRoute, TCPRoute, TLSRoute) and generates proxy configuration | Enabled |
| **Proxy** | High-performance reverse proxy (Pingora-based) that serves traffic based on generated config | Enabled |

Both components can be independently enabled/disabled via `controller.enabled` and `proxy.enabled`.

## Installation

```bash
# Install with defaults
helm install wicket ./deploy/helm/wicket \
  --namespace wicket-system \
  --create-namespace

# Install with custom values
helm install wicket ./deploy/helm/wicket \
  --namespace wicket-system \
  --create-namespace \
  -f my-values.yaml

# Dry-run to preview resources
helm template wicket ./deploy/helm/wicket \
  --namespace wicket-system
```

## Configuration

### Global

| Parameter | Description | Default |
|-----------|-------------|---------|
| `global.imagePullSecrets` | Image pull secrets for all deployments | `[]` |
| `namespace.name` | Override namespace (defaults to release namespace) | `""` |
| `nameOverride` | Override chart name | `""` |
| `fullnameOverride` | Override fully qualified app name | `""` |

### Controller

| Parameter | Description | Default |
|-----------|-------------|---------|
| `controller.enabled` | Enable controller deployment | `true` |
| `controller.image.repository` | Controller image repository | `ghcr.io/geverding/wicket-controller` |
| `controller.image.tag` | Image tag (defaults to chart appVersion) | `""` |
| `controller.image.pullPolicy` | Image pull policy | `IfNotPresent` |
| `controller.replicaCount` | Number of replicas (leader-elected) | `1` |
| `controller.resources` | CPU/memory requests and limits | See values.yaml |
| `controller.securityContext` | Pod security context | Non-root (65532) |
| `controller.containerSecurityContext` | Container security context | Read-only root FS |
| `controller.args.logLevel` | Log level | `info` |
| `controller.args.jsonLogs` | JSON log output | `true` |
| `controller.args.watchAllNamespaces` | Watch all namespaces | `true` |
| `controller.args.leaderElection` | Enable leader election | `true` |
| `controller.metrics.enabled` | Enable metrics endpoint | `true` |
| `controller.metrics.port` | Metrics port | `8081` |
| `controller.metrics.serviceMonitor.enabled` | Create ServiceMonitor | `false` |
| `controller.serviceAccount.create` | Create ServiceAccount | `true` |
| `controller.serviceAccount.name` | ServiceAccount name | Auto-generated |
| `controller.serviceAccount.annotations` | ServiceAccount annotations | `{}` |
| `controller.podDisruptionBudget.enabled` | Enable PDB | `false` |
| `controller.podDisruptionBudget.minAvailable` | Min available pods | `1` |
| `controller.nodeSelector` | Node selector | `{}` |
| `controller.affinity` | Affinity rules | `{}` |
| `controller.tolerations` | Tolerations | `[]` |

### Proxy

| Parameter | Description | Default |
|-----------|-------------|---------|
| `proxy.enabled` | Enable proxy deployment | `true` |
| `proxy.image.repository` | Proxy image repository | `ghcr.io/geverding/wicket` |
| `proxy.image.tag` | Image tag (defaults to chart appVersion) | `""` |
| `proxy.image.pullPolicy` | Image pull policy | `IfNotPresent` |
| `proxy.replicaCount` | Number of replicas (ignored if HPA enabled) | `1` |
| `proxy.config.listen` | Listen address inside container | `0.0.0.0:8080` |
| `proxy.config.workers` | Worker threads (null = CPU count) | `null` |
| `proxy.config.jsonLogs` | JSON log output | `true` |
| `proxy.config.logLevel` | Log level | `info` |
| `proxy.config.shutdownTimeout` | Graceful shutdown timeout (seconds) | `30` |
| `proxy.resources` | CPU/memory requests and limits | See values.yaml |
| `proxy.securityContext` | Pod security context | Non-root (65532) |
| `proxy.containerSecurityContext` | Container security context | Read-only root FS |
| `proxy.service.type` | Service type | `ClusterIP` |
| `proxy.service.annotations` | Service annotations | `{}` |
| `proxy.service.ports` | Service port definitions | HTTP 80 -> 8080 |
| `proxy.autoscaling.enabled` | Enable HPA | `false` |
| `proxy.autoscaling.minReplicas` | HPA min replicas | `1` |
| `proxy.autoscaling.maxReplicas` | HPA max replicas | `10` |
| `proxy.autoscaling.targetCPUUtilizationPercentage` | HPA CPU target | `80` |
| `proxy.serviceAccount.create` | Create ServiceAccount | `true` |
| `proxy.serviceAccount.name` | ServiceAccount name | Auto-generated |
| `proxy.podDisruptionBudget.enabled` | Enable PDB | `false` |
| `proxy.terminationGracePeriodSeconds` | Termination grace period | `60` |
| `proxy.preStopSleepSeconds` | Pre-stop sleep (LB deregistration) | `5` |
| `proxy.nodeSelector` | Node selector | `{}` |
| `proxy.affinity` | Affinity rules | `{}` |
| `proxy.tolerations` | Tolerations | `[]` |
| `proxy.topologySpreadConstraints` | Topology spread constraints | `[]` |
| `proxy.priorityClassName` | Priority class name | `""` |

### Gateway API

| Parameter | Description | Default |
|-----------|-------------|---------|
| `gatewayClass.create` | Create GatewayClass resource | `true` |
| `gatewayClass.name` | GatewayClass name | `wicket` |
| `gatewayClass.description` | GatewayClass description | `Wicket Gateway Controller` |
| `crds.install` | Install Gateway API CRDs | `true` |
| `rbac.create` | Create RBAC resources | `true` |

### Monitoring

| Parameter | Description | Default |
|-----------|-------------|---------|
| `monitoring.prometheusRules.enabled` | Enable PrometheusRule resources | `false` |
| `monitoring.prometheusRules.labels` | Additional labels for PrometheusRules | `{}` |
| `monitoring.prometheusRules.proxy.errorRateThreshold` | HTTP error rate alert threshold | `0.01` |
| `monitoring.prometheusRules.proxy.latencyP99Threshold` | p99 latency alert threshold (seconds) | `1.0` |
| `monitoring.prometheusRules.proxy.certExpiryWarningSeconds` | Cert expiry warning threshold | `604800` |
| `monitoring.prometheusRules.controller.reconcileErrorRateThreshold` | Reconcile error rate threshold | `0.05` |
| `monitoring.prometheusRules.controller.configSyncLagThreshold` | Config sync lag threshold (seconds) | `300` |
| `monitoring.grafanaDashboards.enabled` | Deploy Grafana dashboard ConfigMaps | `false` |
| `monitoring.grafanaDashboards.folder` | Grafana sidecar folder | `Wicket` |
| `monitoring.grafanaDashboards.datasource` | Prometheus datasource name | `Prometheus` |
| `monitoring.proxyServiceMonitor.enabled` | Create proxy ServiceMonitor | `false` |
| `monitoring.proxyServiceMonitor.interval` | Scrape interval | `30s` |
| `monitoring.proxyServiceMonitor.scrapeTimeout` | Scrape timeout | `10s` |

## Monitoring Setup

Enable the full monitoring stack:

```yaml
monitoring:
  prometheusRules:
    enabled: true
  grafanaDashboards:
    enabled: true
  proxyServiceMonitor:
    enabled: true

controller:
  metrics:
    serviceMonitor:
      enabled: true
```

This creates:
- **PrometheusRules** with alerts for error rates, latency, cert expiry, and controller health
- **Grafana dashboards** for proxy traffic and controller operations
- **ServiceMonitors** for both proxy and controller metrics scraping

## Upgrading

```bash
helm upgrade wicket ./deploy/helm/wicket \
  --namespace wicket-system \
  -f my-values.yaml
```

## Uninstalling

```bash
helm uninstall wicket --namespace wicket-system
```

Note: CRDs are not removed on uninstall. Remove manually if needed:

```bash
kubectl delete -f deploy/crds/
```
