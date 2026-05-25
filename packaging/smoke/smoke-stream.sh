#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
  echo "usage: smoke-stream.sh <absolute-package-path> <install-command>" >&2
  exit 2
fi

PACKAGE="$1"
INSTALL_CMD="$2"

if [ "${PACKAGE#/}" = "$PACKAGE" ]; then
  echo "package path must be absolute: $PACKAGE" >&2
  exit 2
fi

if [ ! -f "$PACKAGE" ]; then
  echo "package not found in guest: $PACKAGE" >&2
  exit 2
fi

collect_wicket_diagnostics() {
  sudo systemctl status wicket --no-pager >/tmp/wicket-status.log || true
  sudo journalctl -u wicket -n 200 --no-pager >/tmp/wicket-journal.log || true
}

cleanup() {
  if [ -f /tmp/stream-backends.pid ]; then
    kill "$(cat /tmp/stream-backends.pid)" 2>/dev/null || true
  fi
}
trap cleanup EXIT

cat >/tmp/stream-backends.py <<'PY'
import socket
import threading


def serve(port, marker):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", port))
    sock.listen(128)
    while True:
        conn, _ = sock.accept()
        threading.Thread(target=handle, args=(conn, marker), daemon=True).start()


def handle(conn, marker):
    with conn:
        data = conn.recv(4096)
        if not data:
            return
        conn.sendall(marker.encode("ascii") + b":" + data[:32])


for port, marker in ((4000, "default"), (4001, "api")):
    threading.Thread(target=serve, args=(port, marker), daemon=True).start()

threading.Event().wait()
PY

nohup python3 /tmp/stream-backends.py >/tmp/stream-backends.log 2>&1 &
echo $! >/tmp/stream-backends.pid

python3 - <<'PY'
import socket
import time

deadline = time.time() + 30
while time.time() < deadline:
    try:
        for port in (4000, 4001):
            s = socket.create_connection(("127.0.0.1", port), timeout=1)
            s.close()
        raise SystemExit(0)
    except OSError:
        time.sleep(1)
raise SystemExit("stream backends failed to start")
PY

sudo sh -c "$INSTALL_CMD '$PACKAGE'"

sudo tee /etc/wicket/wicket.toml >/dev/null <<'EOF'
[server]
listen = "127.0.0.1:18080"
log_level = "info"
json_logs = false
shutdown_timeout = 10

[upstreams.backend]
backends = ["127.0.0.1:3000"]
strategy = "round_robin"

[[routes]]
name = "default"
upstream = "backend"

[routes.match]
path_prefix = "/"

[stream]
listen = "127.0.0.1:9443"
reuseport = false
default_upstream = "default"
connect_timeout_ms = 1000
drain_timeout_secs = 5

[stream.sni_routes]
"api.example.com" = "api"

[[stream.upstreams]]
name = "default"
servers = ["127.0.0.1:4000"]

[[stream.upstreams]]
name = "api"
servers = ["127.0.0.1:4001"]
EOF

sudo systemctl daemon-reload
sudo systemctl enable wicket
if ! sudo systemctl start wicket; then
  collect_wicket_diagnostics
  echo "wicket failed to start" >&2
  exit 1
fi

python3 - <<'PY'
import socket
import struct
import time


def wait_port(port):
    deadline = time.time() + 30
    while time.time() < deadline:
        try:
            s = socket.create_connection(("127.0.0.1", port), timeout=1)
            s.close()
            return
        except OSError:
            time.sleep(1)
    raise RuntimeError(f"port {port} did not open")


def tls_client_hello_sni(hostname):
    host = hostname.encode("ascii")
    server_name = b"\x00" + struct.pack("!H", len(host)) + host
    server_name_ext_data = struct.pack("!H", len(server_name)) + server_name
    server_name_ext = b"\x00\x00" + struct.pack("!H", len(server_name_ext_data)) + server_name_ext_data
    supported_versions = b"\x00\x2b\x00\x03\x02\x03\x04"
    extensions = server_name_ext + supported_versions
    body = b"\x03\x03" + (b"\x11" * 32)
    body += b"\x00"
    body += struct.pack("!H", 2) + b"\x13\x01"
    body += b"\x01\x00"
    body += struct.pack("!H", len(extensions)) + extensions
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


wait_port(9443)

with socket.create_connection(("127.0.0.1", 9443), timeout=5) as s:
    s.sendall(b"plain-stream-smoke")
    data = s.recv(128)
    if not data.startswith(b"default:plain-stream-smoke"):
        raise RuntimeError(f"plain stream routed incorrectly: {data!r}")

with socket.create_connection(("127.0.0.1", 9443), timeout=5) as s:
    s.sendall(tls_client_hello_sni("api.example.com"))
    data = s.recv(128)
    if not data.startswith(b"api:"):
        raise RuntimeError(f"SNI stream routed incorrectly: {data!r}")
PY

collect_wicket_diagnostics

exit 0
