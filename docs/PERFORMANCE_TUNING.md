# Performance Tuning

This guide targets a single bare-metal host with:

- 64-core AMD EPYC 74xx-series CPU
- 64GB RAM
- Linux with systemd
- High-connection-count L4 stream proxying
- Local backends reachable over Unix domain sockets when possible

The numbers below are starting points, not universal limits. Validate with your workload.

## Target Profile

Use Unix socket stream backends for local services on the same host. This avoids outbound TCP ephemeral port exhaustion between Wicket and the backend.

```toml
[[streams]]
name = "public-tls"
listen = "0.0.0.0:443"
backlog = 65535
reuseport = true
proxy_protocol = "v2"
default_upstream = "local-app"
connect_timeout_ms = 1000
max_connections = 0
drain_timeout_secs = 30
health_cooldown_secs = 1

[[streams.upstreams]]
name = "local-app"
servers = ["unix:/run/local-app/backend.sock"]
```

For remote TCP backends, keep `source_ips` available to multiply outbound ephemeral ports:

```toml
[[streams]]
name = "public-tls"
source_ips = ["10.0.0.10", "10.0.0.11", "10.0.0.12", "10.0.0.13"]
```

Do not use `source_ips` for Unix socket backends. It is TCP-only and is skipped for Unix endpoints.

## Listener Queues

Wicket stream listener default backlog is `8000`. Pingora's HTTP listener backlog is `65535`. For high-rate stream accepts, set Wicket stream backlog explicitly:

```toml
[[streams]]
name = "public-tls"
backlog = 65535
```

Linux caps the effective accept queue with `net.core.somaxconn`, so raise the kernel cap too:

```conf
# /etc/sysctl.d/90-wicket-performance.conf
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 262144
net.ipv4.tcp_syncookies = 1
```

Check active queue pressure during load:

```bash
ss -ltn sport = :443
netstat -s | grep -i listen
```

## File Descriptors

Each proxied stream connection uses at least:

- 1 client TCP socket
- 1 backend socket, either TCP or Unix
- Extra descriptors for logs, metrics, and process internals

For 1M concurrent proxied connections, plan for at least 2M socket descriptors. Give the process headroom:

```ini
# /etc/systemd/system/wicket.service.d/performance.conf
[Service]
LimitNOFILE=4194304
TasksMax=infinity
```

Verify at runtime:

```bash
systemctl show wicket -p LimitNOFILE -p TasksMax
cat /proc/$(pidof wicket)/limits
```

## CPU Scheduling

Wicket's stream proxy still copies bytes in userspace for TCP client sockets to Unix backend sockets. Unix sockets remove port pressure, not CPU pressure.

If Wicket and the backend share the same 64-core host, do not assume the scheduler will automatically protect backend latency. Under high socket readiness, the proxy can stay runnable and consume its share aggressively.

Prefer systemd cgroup controls over only `nice`:

```ini
# /etc/systemd/system/wicket.service.d/performance.conf
[Service]
CPUWeight=60
Nice=5
```

Give the backend a higher CPU weight:

```ini
# /etc/systemd/system/local-app.service.d/performance.conf
[Service]
CPUWeight=100
Nice=0
```

If backend latency matters more than absolute proxy throughput, reserve CPU sets. Example split for a colocated backend:

```ini
# Wicket: first 16 CPUs
[Service]
AllowedCPUs=0-15
CPUWeight=60
Nice=5

# Backend: remaining 48 CPUs
[Service]
AllowedCPUs=16-63
CPUWeight=100
Nice=0
```

For proxy-only hosts, let Wicket use all CPUs and leave `Nice=0` unless another critical service is colocated.

## Memory

64GB is usually enough for very high connection counts if socket buffers are controlled and logging is not excessive. The dominant memory consumers are kernel socket buffers, per-connection task state, TLS state if the backend terminates TLS, and application memory in colocated backends.

Start with conservative TCP buffer defaults and tune after measuring:

```conf
# /etc/sysctl.d/90-wicket-performance.conf
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
```

For Unix socket local backends, outbound TCP buffer pressure between Wicket and backend disappears, but each connection still consumes file descriptors, task memory, and socket memory.

Watch these during load:

```bash
free -h
slabtop
cat /proc/net/sockstat
cat /proc/net/sockstat6
```

## Remote TCP Backends

For remote TCP upstreams, one Wicket source IP to one backend destination is limited by ephemeral ports. Expand the local port range and use `source_ips`:

```conf
# /etc/sysctl.d/90-wicket-performance.conf
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.tcp_tw_reuse = 1
```

Each additional source IP gives roughly another 64k outbound TCP connections per backend destination. This does not matter for Unix socket backends.

## Unix Socket Backends

Use absolute socket paths:

```toml
servers = ["unix:/run/local-app/backend.sock"]
```

Operational requirements:

- Wicket must have read/write permission on the socket.
- The backend should create the socket under a predictable runtime directory.
- Use systemd `RuntimeDirectory=`, `User=`, `Group=`, and `UMask=` to control ownership.
- Keep `LimitNOFILE` high for both Wicket and the backend.

Example backend service settings:

```ini
[Service]
RuntimeDirectory=local-app
RuntimeDirectoryMode=0750
User=local-app
Group=wicket
UMask=0007
LimitNOFILE=4194304
```

TCP-only Wicket features with Unix backends:

- `source_ips` is skipped.
- eBPF sockmap is skipped.
- PROXY protocol is allowed and carries the TCP client/listener addresses over the Unix socket before payload bytes.

## Logging

At high connection rates, logging can become a bottleneck. Keep default journald/stderr logging unless file logs are needed, and avoid debug/trace in load tests except for short captures.

Recommended production baseline:

```toml
[logging]
level = "info"
format = "text"

[logging.files]
enabled = true
directory = "/var/log/wicket"
error = "error.log"
access = "access.log"
acme = "acme.log"

[logging.access]
enabled = true
format = "combined"
```

For maximum throughput tests, disable access logging unless it is part of the benchmark objective.

## systemd Drop-In

Example Wicket drop-in for the 64-core/64GB colocated-backend profile:

```ini
# /etc/systemd/system/wicket.service.d/performance.conf
[Service]
LimitNOFILE=4194304
TasksMax=infinity
CPUWeight=60
Nice=5
AllowedCPUs=0-15
```

Apply changes:

```bash
systemctl daemon-reload
systemctl restart wicket
systemctl show wicket -p LimitNOFILE -p TasksMax -p CPUWeight -p Nice -p AllowedCPUs
```

If Wicket is on a dedicated proxy host, omit `AllowedCPUs` and `Nice`, or set `CPUWeight=100`.

## Validation Checklist

Before load testing:

```bash
cargo build --release -p wicket
sysctl net.core.somaxconn net.ipv4.tcp_max_syn_backlog net.ipv4.ip_local_port_range
systemctl show wicket -p LimitNOFILE -p TasksMax -p CPUWeight -p Nice -p AllowedCPUs
ss -ltn
```

During load testing:

```bash
pidstat -p $(pidof wicket) 1
pidstat -d -p $(pidof wicket) 1
cat /proc/net/sockstat
ss -s
ss -tan state established '( sport = :443 or dport = :443 )' | wc -l
```

Wicket metrics to watch:

- `wicket_stream_connections_active`
- `wicket_stream_connections_total`
- `wicket_stream_connection_errors_total`
- `wicket_stream_connect_duration_seconds`
- `wicket_stream_bytes_total`
- `wicket_stream_proxy_path_total`

## Starting Point Summary

For a 64-core EPYC 74xx host with 64GB RAM and local Unix socket backends:

- Wicket stream `backlog = 65535`
- Wicket stream `max_connections = 0` for unlimited, or set an explicit safety cap based on file descriptor budget
- Kernel `net.core.somaxconn = 65535`
- Kernel `net.ipv4.tcp_max_syn_backlog = 262144`
- systemd `LimitNOFILE = 4194304`
- Use Unix socket upstreams for local backends
- Use `CPUWeight`/`AllowedCPUs` if backend is colocated
- Keep access logging off during raw throughput benchmarks unless measuring logging too
