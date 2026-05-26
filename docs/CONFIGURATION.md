# Configuration Reference

> **Warning**
> Wicket is pre-production, alpha, experimental software. Configuration formats may change without notice.

Wicket uses TOML for configuration. The default config file is `wicket.toml` in the current directory, overridden with `-c /path/to/config.toml`.

## Table of Contents

- [Server](#server)
- [Upstreams](#upstreams)
- [Routes](#routes)
- [Route Matching](#route-matching)
- [Route URL Rewrite](#route-url-rewrite)
- [Per-Route TLS](#per-route-tls)
- [TLS](#tls)
- [Stream (L4) Proxy](#stream-l4-proxy)
- [Minimal Example](#minimal-example)
- [Full Example](#full-example)

---

## Server

The `[server]` section configures the proxy listener and runtime behavior.

```toml
[server]
listen = "0.0.0.0:8080"
workers = 4
json_logs = true
log_level = "info"
shutdown_timeout = 30
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `listen` | string | **required** | Address and port to listen on (e.g., `"0.0.0.0:8080"`) |
| `workers` | integer | CPU count | Number of worker threads |
| `json_logs` | boolean | `true` | Enable structured JSON logging |
| `log_level` | string | `"info"` | Log level: `trace`, `debug`, `info`, `warn`, `error` |
| `shutdown_timeout` | integer | `30` | Graceful shutdown timeout in seconds |

### HTTPS Listener

When TLS is configured, Wicket automatically adds an HTTPS listener. The HTTPS port is derived from the HTTP port:
- Port 80 maps to 443
- Other ports: port + 363 (e.g., 8080 maps to 8443)

---

## Upstreams

Upstreams define backend server pools. Each upstream has a name and one or more backends.

```toml
[upstreams.api]
backends = ["10.0.0.1:3000", "10.0.0.2:3000", "10.0.0.3:3000"]
strategy = "round_robin"

[upstreams.api.health_check]
path = "/health"
interval = 10
unhealthy_threshold = 3
```

### Upstream Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `backends` | list of strings | **required** | Backend server addresses (`"host:port"`) |
| `strategy` | string | `"round_robin"` | Load balancing strategy: `round_robin` or `consistent_hash` |
| `health_check` | table | none | Optional health check configuration |

### Health Check Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `path` | string | `"/health"` | HTTP path to check |
| `interval` | integer | `10` | Seconds between checks |
| `unhealthy_threshold` | integer | `3` | Consecutive failures before marking unhealthy |

### Load Balancing Strategies

- **`round_robin`** (default): Distributes requests evenly across healthy backends in rotation.
- **`consistent_hash`**: Routes requests to the same backend based on the request path (Ketama hashing). Useful for caching layers where cache locality matters.

---

## Routes

Routes define how incoming requests are matched and forwarded to upstreams. Routes are evaluated in order; the first match wins.

```toml
[[routes]]
name = "api-v1"
upstream = "api"

[routes.match]
host = "api.example.com"
path_prefix = "/v1"
methods = ["GET", "POST"]
```

### Route Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `name` | string | none | Optional route name (used in logs and metrics) |
| `upstream` | string | **required** | Name of the upstream to proxy to (must exist in `[upstreams]`) |
| `match` | table | **required** | Match conditions (see below) |
| `tls` | string/table | none | Per-route TLS config (see [Per-Route TLS](#per-route-tls)) |
| `filters` | table | none | Route filters; currently supports `url_rewrite.path` |

> **Note**: `timeout` and filter types other than `filters.url_rewrite.path` are defined in the schema but not yet supported. Using unsupported filter types will cause a validation error.

---

## Route Matching

Each route must have at least one match condition. All specified conditions must match for the route to be selected (logical AND).

```toml
[routes.match]
host = "api.example.com"
path_prefix = "/v1"
methods = ["GET", "POST"]
headers = { "x-api-version" = "2" }
```

### Match Fields

| Field | Type | Description |
|-------|------|-------------|
| `host` | string | Exact host or wildcard (e.g., `"*.example.com"`) |
| `path_prefix` | string | Path prefix match (e.g., `"/api"` matches `/api/users`) |
| `path` | string | Exact path match (mutually exclusive with `path_prefix`) |
| `methods` | list of strings | HTTP methods to match (empty = all methods) |
| `headers` | map of strings | Required header key-value pairs (exact match) |

### Host Matching

- **Exact match**: `"api.example.com"` matches only `api.example.com`
- **Wildcard**: `"*.example.com"` matches `foo.example.com` but not `foo.bar.example.com`
- Case-insensitive

### Path Matching

- **Prefix**: `path_prefix = "/api"` matches `/api`, `/api/users`, `/api/users/123`
- **Exact**: `path = "/health"` matches only `/health`
- `path` and `path_prefix` are mutually exclusive

### Route Order

Routes are evaluated top-to-bottom. Place more specific routes before general catch-all routes:

```toml
# Specific route first
[[routes]]
name = "api"
upstream = "api-backend"
[routes.match]
host = "api.example.com"
path_prefix = "/v1"

# Catch-all route last
[[routes]]
name = "default"
upstream = "web-backend"
[routes.match]
path_prefix = "/"
```

---

## Route URL Rewrite

Routes can rewrite the upstream request path before proxying. This is useful for mapping a public route to a backend path prefix, such as a bucket or application base path.

```toml
[[routes]]
name = "updates"
upstream = "s3cache"

[routes.match]
host = "updates.example.com"
path_prefix = "/"

[routes.filters.url_rewrite]
path = { replace_prefix_match = "/b/updater-prod" }
```

With that route:

| Incoming path | Upstream path |
|---------------|---------------|
| `/latest.yml` | `/b/updater-prod/latest.yml` |
| `/packages/mac/app.zip?channel=stable` | `/b/updater-prod/packages/mac/app.zip?channel=stable` |

`replace_prefix_match` replaces the portion matched by `path_prefix` with the configured path. Query strings are preserved. Request headers, including range requests, are not modified by the rewrite.

The replacement path must start with `/`. URL rewrite hostname changes are not supported yet.

---

## Per-Route TLS

Each route can specify its own TLS behavior. This enables multi-app setups where different routes use different certificates or ACME providers.

### Formats

```toml
# Auto-provision via ACME (uses default_dns provider)
tls = "auto"

# Auto-provision via a named DNS provider (for multi-account setups)
tls = { auto = "provider-name" }

# Use a specific file-based certificate by name
tls = { cert = "cert-name" }

# Disable TLS for this route
tls = "off"
```

### Multi-App Auto TLS Example

```toml
[[routes]]
name = "app1"
upstream = "app1-backend"
tls = "auto"
[routes.match]
host = "app1.example.com"
path_prefix = "/"

[[routes]]
name = "app2"
upstream = "app2-backend"
tls = { auto = "other-account" }
[routes.match]
host = "app2.other.com"
path_prefix = "/"

[tls]
mode = "acme"

[tls.acme]
email = "admin@example.com"

[tls.acme.default_dns]
provider = "cloudflare"
api_token = "${CF_API_TOKEN}"

[tls.acme.dns_providers.other-account]
provider = "cloudflare"
api_token = "${CF_API_TOKEN_OTHER}"
```

---

## TLS

The `[tls]` section configures certificate management. Three modes are available:

### File Mode

Loads certificates from disk. Supports file watching for automatic reload (e.g., when cert-manager rotates certificates in Kubernetes).

```toml
[tls]
mode = "file"

[tls.file]
watch = true
poll_interval_secs = 30

[[tls.file.certs]]
name = "default"
cert = "/etc/wicket/tls/tls.crt"
key = "/etc/wicket/tls/tls.key"
domains = ["example.com", "*.example.com"]
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `watch` | boolean | `false` | Watch cert files for changes (inotify + poll fallback) |
| `poll_interval_secs` | integer | `30` | Poll interval for NFS/network filesystems |

### ACME Mode

Automatic certificate provisioning via Let's Encrypt with DNS-01 challenge validation.

```toml
[tls]
mode = "acme"

[tls.acme]
email = "admin@example.com"
staging = true
storage = "/var/lib/wicket/acme"
renew_before_days = 30

[[tls.acme.certs]]
domains = ["example.com", "*.example.com"]

[tls.acme.certs.dns]
provider = "cloudflare"
api_token = "${CF_API_TOKEN}"
zone_id = "optional-zone-id"
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `email` | string | **required** | ACME account email |
| `staging` | boolean | `false` | Use Let's Encrypt staging (no rate limits, untrusted certs) |
| `storage` | path | **required** | Directory for ACME account and certificate storage |
| `renew_before_days` | integer | `30` | Renew certificates this many days before expiry |
| `default_dns` | table | none | Default DNS provider for routes with `tls = "auto"` |
| `dns_providers` | map of tables | none | Named DNS providers for multi-account setups |

### Mixed Mode

Combines file-based and ACME certificates. File certs are loaded first, then ACME fills in remaining domains.

```toml
[tls]
mode = "mixed"

[tls.file]
watch = true
[[tls.file.certs]]
name = "fallback"
cert = "/etc/wicket/tls/fallback.crt"
key = "/etc/wicket/tls/fallback.key"
domains = ["example.com"]

[tls.acme]
email = "admin@example.com"
[[tls.acme.certs]]
domains = ["api.example.com"]
[tls.acme.certs.dns]
provider = "cloudflare"
api_token = "${CF_API_TOKEN}"
```

For detailed TLS configuration, see the [TLS Guide](../crates/wicket-tls/README.md).

---

## Stream (L4) Proxy

The `[stream]` section enables L4 TCP/TLS proxying with SNI-based routing. TLS connections are passed through to backends without termination.

```toml
[stream]
listen = "0.0.0.0:8443"
backlog = 8000
reuseport = true
proxy_protocol = "v2"
source_ips = ["10.0.0.10", "10.0.0.11"]
default_upstream = "fallback"
connect_timeout_ms = 5000
max_connections = 10000
drain_timeout_secs = 30
health_cooldown_secs = 30

[stream.sni_routes]
"api.example.com" = "api-backend"
"*.internal.com" = "internal-backend"

[[stream.upstreams]]
name = "api-backend"
servers = ["10.0.0.1:443", "10.0.0.2:443"]

[[stream.upstreams]]
name = "internal-backend"
servers = ["10.0.1.1:443"]

[[stream.upstreams]]
name = "fallback"
servers = ["10.0.2.1:443"]
```

### Stream Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `listen` | string | **required** | Address and port for the stream listener |
| `backlog` | integer | `8000` | TCP listen backlog (pending connections queue) |
| `reuseport` | boolean | `true` | Enable `SO_REUSEPORT` for kernel-level load balancing |
| `proxy_protocol` | string | `"none"` | PROXY protocol: `"none"`, `"v1"`, or `"v2"` |
| `source_ips` | list of IPs | `[]` | Source IPs for ephemeral port multiplication |
| `default_upstream` | string | none | Fallback upstream when no SNI route matches |
| `sni_routes` | map | `{}` | SNI hostname to upstream name mapping |
| `connect_timeout_ms` | integer | `5000` | Backend connect timeout in milliseconds |
| `max_connections` | integer | `10000` | Maximum concurrent connections (0 = unlimited) |
| `drain_timeout_secs` | integer | `30` | Graceful shutdown drain timeout in seconds |
| `health_cooldown_secs` | integer | `30` | Seconds before retrying an unhealthy backend |

### SNI Routing

SNI routes map TLS Server Name Indication hostnames to upstream backends:

- **Exact match**: `"api.example.com" = "api-backend"`
- **Wildcard**: `"*.example.com" = "catch-all"` (matches `foo.example.com`, not `foo.bar.example.com`)
- Exact matches take priority over wildcards

### Source IP Pooling

For high-connection-count workloads (400k+ concurrent), configure multiple source IPs to multiply available ephemeral ports:

```toml
source_ips = ["10.0.0.10", "10.0.0.11", "10.0.0.12"]
```

Each IP provides ~64k ephemeral ports. Three IPs give ~192k outbound connections per destination.

### PROXY Protocol

Send client connection information to backends using the PROXY protocol:

- `"v1"` - Text format (HAProxy v1, widely supported)
- `"v2"` - Binary format (more efficient, supports IPv6 cleanly)

---

## Minimal Example

```toml
[server]
listen = "127.0.0.1:8080"

[upstreams.backend]
backends = ["127.0.0.1:3000"]

[[routes]]
name = "default"
upstream = "backend"
[routes.match]
path_prefix = "/"
```

---

## Full Example

See [`wicket.toml`](../wicket.toml) in the repository root for a comprehensive annotated example covering all configuration sections.

## Validation

Wicket validates the entire config at load time:

- All route `upstream` references must exist in `[upstreams]`
- Each upstream must have at least one backend
- Each route must have at least one match rule
- TLS cert/provider references must exist
- Stream SNI routes must reference defined stream upstreams
- Unsupported filter types and `timeout` are rejected

Run `wicket --validate` to check a config file without starting the server.
