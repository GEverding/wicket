#!/usr/bin/env bash

set -euo pipefail

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

CLUSTER_NAME="wicket-smoke"
RELEASE_NAME="wicket"
SYSTEM_NAMESPACE="wicket-system"
TEST_NAMESPACE="wicket-test"
CONTROLLER_DEPLOYMENT="wicket-controller"
GATEWAY_NAME="smoke-gw"
ROUTE_NAME="smoke-route"
MANAGED_DEPLOYMENT="wicket-gw-smoke-gw-deploy"
MANAGED_SERVICE="wicket-gw-smoke-gw-svc"
MANAGED_CONFIGMAP="wicket-gw-smoke-gw-config"
RESPONSE_FILE="/tmp/wicket-smoke-response"
PORT_FORWARD_LOG="/tmp/wicket-smoke-portforward.log"
PORT_FORWARD_PID=""
NO_CLEANUP=false
SKIP_BUILD=false
RESULT="FAIL"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

log() {
  printf "%b[✓] %s%b\n" "${GREEN}" "$1" "${NC}"
}

info() {
  printf "%b[→] %s%b\n" "${BLUE}" "$1" "${NC}"
}

warn() {
  printf "%b[!] %s%b\n" "${YELLOW}" "$1" "${NC}"
}

dump_failure_diagnostics() {
  warn "Dumping failure diagnostics"

  kubectl -n "${SYSTEM_NAMESPACE}" logs "deploy/${CONTROLLER_DEPLOYMENT}" --tail=50 || true
  kubectl -n "${TEST_NAMESPACE}" get gateway "${GATEWAY_NAME}" -o yaml || true
  kubectl -n "${TEST_NAMESPACE}" get httproute "${ROUTE_NAME}" -o yaml || true
  kubectl -n "${TEST_NAMESPACE}" get sa,cm,svc,deploy -l app.kubernetes.io/managed-by=wicket-controller || true
  kubectl -n "${TEST_NAMESPACE}" get configmap "${MANAGED_CONFIGMAP}" -o yaml || true
}

fail() {
  printf "%b[✗] %s%b\n" "${RED}" "$1" "${NC}" >&2
  dump_failure_diagnostics
  exit 1
}

section() {
  printf "\n%b== %s ==%b\n" "${BLUE}" "$1" "${NC}"
}

wait_for() {
  local description="$1"
  local timeout_seconds="$2"
  local command="$3"
  local start
  local elapsed

  start="$(date +%s)"
  while true; do
    if eval "${command}"; then
      elapsed="$(( $(date +%s) - start ))"
      log "${description} (${elapsed}s)"
      return 0
    fi

    elapsed="$(( $(date +%s) - start ))"
    if (( elapsed >= timeout_seconds )); then
      warn "Timed out waiting for: ${description} (${elapsed}s)"
      return 1
    fi

    sleep 3
  done
}

cleanup() {
  local exit_code="$?"

  if [[ -n "${PORT_FORWARD_PID}" ]]; then
    if kill -0 "${PORT_FORWARD_PID}" >/dev/null 2>&1; then
      info "Stopping port-forward (pid ${PORT_FORWARD_PID})"
      kill "${PORT_FORWARD_PID}" >/dev/null 2>&1 || true
      wait "${PORT_FORWARD_PID}" 2>/dev/null || true
    fi
  fi

  if [[ "${NO_CLEANUP}" == true ]]; then
    warn "--no-cleanup set, leaving k3d cluster '${CLUSTER_NAME}' running"
  else
    info "Deleting k3d cluster '${CLUSTER_NAME}'"
    k3d cluster delete "${CLUSTER_NAME}" >/dev/null 2>&1 || true
  fi

  exit "${exit_code}"
}

trap cleanup EXIT

while [[ $# -gt 0 ]]; do
  case "$1" in
    --no-cleanup)
      NO_CLEANUP=true
      shift
      ;;
    --skip-build)
      SKIP_BUILD=true
      shift
      ;;
    *)
      printf "%b[✗] Unknown argument: %s%b\n" "${RED}" "$1" "${NC}" >&2
      exit 1
      ;;
  esac
done

section "Preflight"
for cmd in k3d kubectl helm docker cargo; do
  if ! command -v "${cmd}" >/dev/null 2>&1; then
    fail "Required command not found: ${cmd}"
  fi
done
log "Tooling check passed"

section "Build"
if [[ "${SKIP_BUILD}" == true ]]; then
  warn "Skipping cargo build (--skip-build)"
else
  info "Building wicket and wicket-controller"
  cargo build --release -p wicket -p wicket-controller --manifest-path "${ROOT_DIR}/Cargo.toml"
  log "Release binaries built"
fi

if [[ ! -x "${ROOT_DIR}/target/release/wicket" ]]; then
  fail "Missing executable binary: ${ROOT_DIR}/target/release/wicket"
fi
if [[ ! -x "${ROOT_DIR}/target/release/wicket-controller" ]]; then
  fail "Missing executable binary: ${ROOT_DIR}/target/release/wicket-controller"
fi

section "Package"
info "Building controller image wicket-controller:smoke"
docker build -t wicket-controller:smoke -f - "${ROOT_DIR}" <<'EOF'
FROM debian:trixie-slim
RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates \
  && rm -rf /var/lib/apt/lists/*
RUN groupadd -g 65532 wicket && useradd -u 65532 -g 65532 -M -s /usr/sbin/nologin wicket
COPY target/release/wicket-controller /usr/local/bin/wicket-controller
RUN chmod +x /usr/local/bin/wicket-controller
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/wicket-controller"]
EOF

info "Building proxy image wicket:smoke"
docker build -t wicket:smoke -f - "${ROOT_DIR}" <<'EOF'
FROM debian:trixie-slim
RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates libssl3 \
  && rm -rf /var/lib/apt/lists/*
RUN groupadd -g 65532 wicket && useradd -u 65532 -g 65532 -M -s /usr/sbin/nologin wicket
COPY target/release/wicket /usr/local/bin/wicket
RUN chmod +x /usr/local/bin/wicket
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/wicket"]
CMD ["-c", "/etc/wicket/wicket.toml"]
EOF
log "Docker images built"

section "Cluster"
if k3d cluster list | awk '{print $1}' | grep -Fxq "${CLUSTER_NAME}"; then
  warn "Deleting existing cluster '${CLUSTER_NAME}'"
  k3d cluster delete "${CLUSTER_NAME}"
fi

info "Creating k3d cluster '${CLUSTER_NAME}'"
k3d cluster create "${CLUSTER_NAME}" --servers 1 --agents 1 -p "8080:80@loadbalancer" --k3s-arg "--disable=traefik@server:0"
log "Cluster created"

section "Import"
info "Importing images into k3d"
k3d image import wicket-controller:smoke wicket:smoke -c "${CLUSTER_NAME}"
log "Images imported"

section "CRDs"
kubectl apply -f "${ROOT_DIR}/deploy/crds/"
log "Gateway API CRDs applied"

section "Helm Install"
helm upgrade --install "${RELEASE_NAME}" "${ROOT_DIR}/deploy/helm/wicket" \
  --skip-crds \
  -n "${SYSTEM_NAMESPACE}" \
  --create-namespace \
  --set controller.image.repository=wicket-controller \
  --set controller.image.tag=smoke \
  --set controller.image.pullPolicy=Never \
  --set controller.args.leaderElection=false \
  --set controller.args.logLevel=debug \
  --set controller.args.jsonLogs=false \
  --set proxy.enabled=false \
  --set crds.install=false

kubectl -n "${SYSTEM_NAMESPACE}" rollout status "deployment/${CONTROLLER_DEPLOYMENT}" --timeout=120s
log "Helm release installed"

section "Supplementary RBAC"
kubectl apply -f - <<EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: wicket-controller-managed-runtime
rules:
  - apiGroups: ["apps"]
    resources: ["deployments"]
    verbs: ["create", "update", "patch", "delete", "get", "list", "watch"]
  - apiGroups: [""]
    resources: ["services", "serviceaccounts"]
    verbs: ["create", "update", "patch", "delete", "get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: wicket-controller-managed-runtime
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: wicket-controller-managed-runtime
subjects:
  - kind: ServiceAccount
    name: wicket-controller
    namespace: wicket-system
EOF
log "Supplementary RBAC applied"

section "Configure Controller"
kubectl -n "${SYSTEM_NAMESPACE}" set env "deployment/${CONTROLLER_DEPLOYMENT}" WICKET_PROXY_IMAGE="wicket:smoke"
kubectl -n "${SYSTEM_NAMESPACE}" rollout status "deployment/${CONTROLLER_DEPLOYMENT}" --timeout=120s
log "Controller configured with local proxy image"

section "Backend"
kubectl create namespace "${TEST_NAMESPACE}" --dry-run=client -o yaml | kubectl apply -f -
kubectl -n "${TEST_NAMESPACE}" apply -f - <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: echo-svc
spec:
  replicas: 1
  selector:
    matchLabels:
      app: echo-svc
  template:
    metadata:
      labels:
        app: echo-svc
    spec:
      containers:
        - name: echo
          image: ealen/echo-server:latest
          ports:
            - containerPort: 80
---
apiVersion: v1
kind: Service
metadata:
  name: echo-svc
spec:
  selector:
    app: echo-svc
  ports:
    - port: 80
      targetPort: 80
EOF
kubectl -n "${TEST_NAMESPACE}" rollout status deployment/echo-svc --timeout=120s
log "Backend echo service ready"

section "Gateway Resources"
kubectl -n "${TEST_NAMESPACE}" apply -f - <<EOF
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: ${GATEWAY_NAME}
  annotations:
    wicket.io/managed-runtime: "true"
spec:
  gatewayClassName: wicket
  listeners:
    - name: http
      protocol: HTTP
      port: 80
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: ${ROUTE_NAME}
spec:
  parentRefs:
    - name: ${GATEWAY_NAME}
  rules:
    - backendRefs:
        - name: echo-svc
          port: 80
EOF
log "Gateway and HTTPRoute applied"

section "Wait"
wait_for "Gateway Accepted=True" 60 "[[ \"\$(kubectl -n '${TEST_NAMESPACE}' get gateway '${GATEWAY_NAME}' -o jsonpath='{.status.conditions[?(@.type==\"Accepted\")].status}')\" == \"True\" ]]" \
  || fail "Gateway did not become Accepted=True"

wait_for "Gateway Programmed=True" 120 "[[ \"\$(kubectl -n '${TEST_NAMESPACE}' get gateway '${GATEWAY_NAME}' -o jsonpath='{.status.conditions[?(@.type==\"Programmed\")].status}')\" == \"True\" ]]" \
  || fail "Gateway did not become Programmed=True"

wait_for "Managed deployment readyReplicas >= 1" 120 "ready=\$(kubectl -n '${TEST_NAMESPACE}' get deploy '${MANAGED_DEPLOYMENT}' -o jsonpath='{.status.readyReplicas}' 2>/dev/null || true); [[ \"\${ready:-0}\" =~ ^[0-9]+$ ]] && (( ready >= 1 ))" \
  || fail "Managed deployment '${MANAGED_DEPLOYMENT}' was not ready"

section "Diagnostics"
info "Managed resources"
kubectl -n "${TEST_NAMESPACE}" get sa,cm,svc,deploy -l app.kubernetes.io/managed-by=wicket-controller || true

info "Gateway status"
kubectl -n "${TEST_NAMESPACE}" get gateway "${GATEWAY_NAME}" -o yaml || true

info "Generated ConfigMap"
kubectl -n "${TEST_NAMESPACE}" get configmap "${MANAGED_CONFIGMAP}" -o yaml || true

info "HTTPRoute status"
kubectl -n "${TEST_NAMESPACE}" get httproute "${ROUTE_NAME}" -o yaml || true

section "Traffic Test"
rm -f "${RESPONSE_FILE}"
kubectl -n "${TEST_NAMESPACE}" port-forward "svc/${MANAGED_SERVICE}" 9090:80 >"${PORT_FORWARD_LOG}" 2>&1 &
PORT_FORWARD_PID="$!"

wait_for "Port-forward ready" 30 "curl -sS -m 1 -o /dev/null http://localhost:9090/ >/dev/null 2>&1 || curl -sS -m 1 -H 'Host: localhost' -o /dev/null http://localhost:9090/ >/dev/null 2>&1" \
  || fail "Port-forward did not become ready"

http_code="$(curl -sS -m 10 -o "${RESPONSE_FILE}" -w "%{http_code}" "http://localhost:9090/" || true)"

if [[ "${http_code}" == "000" || -z "${http_code}" ]]; then
  warn "First request failed/no response; retrying with Host header"
  http_code="$(curl -sS -m 10 -H "Host: localhost" -o "${RESPONSE_FILE}" -w "%{http_code}" "http://localhost:9090/" || true)"
fi

section "Results"
if [[ "${http_code}" == "200" ]]; then
  RESULT="PASS"
  log "PASS: Received HTTP 200"
  exit_code=0
elif [[ -n "${http_code}" && "${http_code}" != "000" ]]; then
  RESULT="PARTIAL"
  warn "PARTIAL: Received HTTP ${http_code}"
  exit_code=1
else
  RESULT="FAIL"
  warn "FAIL: No HTTP response"
  exit_code=1
fi

info "Response body (${RESPONSE_FILE}):"
if [[ -f "${RESPONSE_FILE}" ]]; then
  cat "${RESPONSE_FILE}"
else
  warn "No response body captured"
fi

info "Controller logs (last 50 lines)"
kubectl -n "${SYSTEM_NAMESPACE}" logs "deploy/${CONTROLLER_DEPLOYMENT}" --tail=50 || true

if [[ "${RESULT}" != "PASS" ]]; then
  dump_failure_diagnostics
fi

exit "${exit_code}"
