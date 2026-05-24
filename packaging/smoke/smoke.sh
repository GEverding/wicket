#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
  echo "usage: smoke.sh <absolute-package-path> <install-command>" >&2
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

wait_for_backend() {
  i=0
  while [ "$i" -lt 30 ]; do
    if curl -fsS "http://127.0.0.1:3000/" | grep -q "wicket smoke"; then
      return 0
    fi
    i=$((i + 1))
    sleep 1
  done
  return 1
}

wait_for_proxy() {
  i=0
  while [ "$i" -lt 30 ]; do
    if systemctl is-active --quiet wicket && curl -fsS "http://127.0.0.1:8080/" | grep -q "wicket smoke"; then
      return 0
    fi
    i=$((i + 1))
    sleep 1
  done
  return 1
}

collect_wicket_diagnostics() {
  suffix="$1"
  sudo systemctl status wicket --no-pager >"/tmp/wicket-status${suffix}.log" || true
  sudo journalctl -u wicket -n 200 --no-pager >"/tmp/wicket-journal${suffix}.log" || true
}

cleanup() {
  if [ -f /tmp/backend.pid ]; then
    kill "$(cat /tmp/backend.pid)" 2>/dev/null || true
  fi
}
trap cleanup EXIT

sudo mkdir -p /srv/test
printf '<html><body><h1>wicket smoke</h1></body></html>\n' | sudo tee /srv/test/index.html >/dev/null
nohup python3 -m http.server 3000 --bind 127.0.0.1 --directory /srv/test >/tmp/backend.log 2>&1 &
echo $! >/tmp/backend.pid

if ! wait_for_backend; then
  echo "backend failed to become healthy" >&2
  exit 1
fi

sudo sh -c "$INSTALL_CMD '$PACKAGE'"

sudo tee /etc/wicket/wicket.toml >/dev/null <<'EOF'
[server]
listen = "127.0.0.1:8080"
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
EOF

sudo systemctl daemon-reload
sudo systemctl enable wicket
if ! sudo systemctl start wicket; then
  collect_wicket_diagnostics ""
  echo "wicket failed to start" >&2
  exit 1
fi

if ! wait_for_proxy; then
  collect_wicket_diagnostics ""
  echo "wicket failed to become healthy" >&2
  exit 1
fi

collect_wicket_diagnostics ""

if ! sudo systemctl reload wicket; then
  collect_wicket_diagnostics "-after"
  echo "wicket failed to reload" >&2
  exit 1
fi

if ! wait_for_proxy; then
  collect_wicket_diagnostics "-after"
  echo "wicket failed health check after reload" >&2
  exit 1
fi

collect_wicket_diagnostics "-after"

exit 0
