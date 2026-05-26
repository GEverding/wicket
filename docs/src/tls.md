# wicket-tls

Automatic TLS certificate management for Wicket.

## Features

- **ACME DNS-01** - Automatic certificates from Let's Encrypt via Cloudflare DNS
- **File Watcher** - Hot-reload certificates from disk (Kubernetes cert-manager)
- **Multi-cert SNI** - Different certificates for different domains
- **Hot Reload** - Zero-downtime certificate updates

## Quick Start

### File Watcher Mode (Kubernetes/cert-manager)

```toml
[tls]
mode = "file"

[tls.file]
watch = true

[[tls.file.certs]]
name = "default"
cert = "/etc/wicket/tls/tls.crt"
key = "/etc/wicket/tls/tls.key"
domains = ["example.com", "*.example.com"]
```

Certificates are loaded on startup and automatically reloaded when files change.

### ACME Mode (Let's Encrypt + Cloudflare)

```toml
[tls]
mode = "acme"

[tls.acme]
email = "admin@example.com"
staging = false  # Set true for testing
storage = "/var/lib/wicket/acme"
renew_before_days = 30

[[tls.acme.certs]]
domains = ["example.com", "*.example.com"]

[tls.acme.certs.dns]
provider = "cloudflare"
api_token = "${CF_API_TOKEN}"
# zone_id = "optional-explicit-zone-id"
```

Certificates are automatically obtained and renewed.

`staging = true` uses Let's Encrypt's staging environment and produces untrusted test certificates. Production certificates require `staging = false` or omitting the field.

Use a separate storage directory while testing staging certificates, or clear ACME storage before switching to production:

```bash
sudo systemctl stop wicket
sudo rm -rf /var/lib/wicket/acme/account.json
sudo rm -rf /var/lib/wicket/acme/certs/*
sudo systemctl start wicket
```

Stored certificates are loaded by domain before new issuance. An exact staging certificate, such as `cdn.example.com`, can shadow a later production wildcard certificate, such as `*.example.com`, because exact SNI matches take precedence over wildcard matches.

The `[tls.acme.certs.dns]` block belongs only to that explicit certificate entry. Routes that use `tls = "auto"` require `[tls.acme.default_dns]` or a named provider with `tls = { auto = "provider-name" }`.

```toml
[tls.acme.default_dns]
provider = "cloudflare"
api_token_file = "/run/secrets/cloudflare-token"
```

If you explicitly list the domains in `[[tls.acme.certs]]`, route `tls = "auto"` is usually unnecessary. Wicket selects the loaded certificate by SNI.

### Mixed Mode

Use both file-based and ACME certificates:

```toml
[tls]
mode = "mixed"

[tls.file]
watch = true

[[tls.file.certs]]
name = "internal"
cert = "/certs/internal.crt"
key = "/certs/internal.key"
domains = ["internal.example.com"]

[tls.acme]
email = "admin@example.com"

[[tls.acme.certs]]
domains = ["public.example.com", "*.public.example.com"]

[tls.acme.certs.dns]
provider = "cloudflare"
api_token = "${CF_API_TOKEN}"
```

## Configuration Reference

### TLS Section

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `mode` | string | required | `"acme"`, `"file"`, or `"mixed"` |
| `acme` | object | - | ACME configuration (required for acme/mixed) |
| `file` | object | - | File watcher configuration (required for file/mixed) |

### ACME Configuration

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `email` | string | required | Contact email for Let's Encrypt |
| `staging` | bool | `false` | Use Let's Encrypt staging; produces untrusted test certs |
| `storage` | path | `/var/lib/wicket/acme` | Where to store certs/account |
| `renew_before_days` | int | `30` | Days before expiry to renew |
| `certs` | array | required | Certificate configurations |
| `default_dns` | object | - | DNS provider for route-derived `tls = "auto"` certificates |
| `dns_providers` | map | - | Named DNS providers for `tls = { auto = "name" }` |

### ACME Certificate Configuration

| Field | Type | Description |
|-------|------|-------------|
| `domains` | array | Domains for this cert (first is primary) |
| `dns.provider` | string | DNS provider (`"cloudflare"`) |
| `dns.api_token` | string | API token (supports `${ENV_VAR}`) |
| `dns.zone_id` | string | Optional explicit zone ID |

### File Configuration

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `watch` | bool | `true` | Watch for file changes |
| `poll_interval_secs` | int | `30` | Poll interval (NFS fallback) |
| `certs` | array | required | Certificate configurations |

### File Certificate Configuration

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Unique identifier |
| `cert` | path | Path to certificate PEM |
| `key` | path | Path to private key PEM |
| `domains` | array | Domains for SNI matching |

## SNI Resolution

Certificates are matched to incoming connections via SNI (Server Name Indication):

1. **Exact match** - `api.example.com` matches cert with that exact domain
2. **Wildcard match** - `*.example.com` matches `api.example.com`, `www.example.com`
3. **Default fallback** - If configured, used when no match found

Wildcards only match one level (RFC 6125):
- `*.example.com` matches `foo.example.com`
- `*.example.com` does NOT match `foo.bar.example.com`

## Kubernetes Integration

### With cert-manager

1. Create a Certificate resource:

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: wicket-cert
spec:
  secretName: wicket-tls
  issuerRef:
    name: letsencrypt-prod
    kind: ClusterIssuer
  dnsNames:
    - example.com
    - "*.example.com"
```

2. Mount the secret in your Wicket deployment:

```yaml
volumeMounts:
  - name: tls
    mountPath: /etc/wicket/tls
    readOnly: true
volumes:
  - name: tls
    secret:
      secretName: wicket-tls
```

3. Configure Wicket:

```toml
[tls]
mode = "file"

[tls.file]
watch = true

[[tls.file.certs]]
name = "default"
cert = "/etc/wicket/tls/tls.crt"
key = "/etc/wicket/tls/tls.key"
domains = ["example.com", "*.example.com"]
```

Wicket will automatically reload when cert-manager rotates the certificate.

## Cloudflare Setup

### Create API Token

1. Go to Cloudflare Dashboard → My Profile → API Tokens
2. Create Token → Custom Token
3. Permissions:
   - Zone / DNS / Edit
   - Zone / Zone / Read
4. Zone Resources: Include → Specific zone → your domain
5. Copy the token

### Environment Variable

```bash
export CF_API_TOKEN="your-token-here"
```

Or in systemd:
```ini
[Service]
Environment="CF_API_TOKEN=your-token-here"
```

## Troubleshooting

### Certificate not loading

Check file permissions:
```bash
ls -la /etc/wicket/tls/
# Key should be readable by wicket process
```

Check PEM format:
```bash
openssl x509 -in /etc/wicket/tls/tls.crt -text -noout
openssl ec -in /etc/wicket/tls/tls.key -check  # or rsa
```

### ACME failures

Use staging first:
```toml
[tls.acme]
staging = true
```

Check logs for challenge errors. Common issues:
- Invalid API token
- Wrong zone ID
- DNS propagation delay

### Hot reload not working

- Ensure `watch = true` in config
- Check if filesystem supports inotify (NFS may need polling)
- Look for reload messages in logs

## Architecture

```
┌─────────────────────────────────────────────────┐
│ CertManager                                     │
│                                                 │
│  ┌─────────────────────────────────────────┐   │
│  │ CertStore (ArcSwap)                     │   │
│  │                                         │   │
│  │  exact: HashMap<domain, CertifiedKey>  │   │
│  │  wildcard: HashMap<base, CertifiedKey> │   │
│  └─────────────────────────────────────────┘   │
│         ▲                    ▲                  │
│         │                    │                  │
│  ┌──────┴──────┐     ┌──────┴──────┐          │
│  │ FileWatcher │     │ AcmeProvider│          │
│  └─────────────┘     └─────────────┘          │
└─────────────────────────────────────────────────┘
```

## License

Same as Wicket (see repository root).
