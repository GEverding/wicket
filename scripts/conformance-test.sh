#!/usr/bin/env bash

set -euo pipefail

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

CLUSTER_NAME="wicket-conformance"
RELEASE_NAME="wicket"
SYSTEM_NAMESPACE="wicket-system"
CONTROLLER_DEPLOYMENT="wicket-controller"

GO_VERSION="1.23.4"
GATEWAY_API_VERSION="v1.2.0"
GATEWAY_API_DIR="/tmp/gateway-api-${GATEWAY_API_VERSION}"

NO_CLEANUP=false
SKIP_BUILD=false
SKIP_CLUSTER=false
RUN_TEST=""
GENERATE_REPORT=false

CLUSTER_CREATED=false
TEST_EXIT_CODE=1
RESULT="FAIL"
GO_TEST_LOG="/tmp/wicket-conformance-go-test.log"
REPORT_TMP_PATH="/tmp/wicket-conformance-report.yaml"
BACKGROUND_PIDS=()

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPORT_OUTPUT_PATH="${ROOT_DIR}/conformance-report.yaml"

log() {
  printf "%b[✓] %s%b\n" "${GREEN}" "$1" "${NC}"
}

info() {
  printf "%b[→] %s%b\n" "${BLUE}" "$1" "${NC}"
}

warn() {
  printf "%b[!] %s%b\n" "${YELLOW}" "$1" "${NC}"
}

fail() {
  printf "%b[✗] %s%b\n" "${RED}" "$1" "${NC}" >&2
  exit 1
}

section() {
  printf "\n%b== %s ==%b\n" "${BLUE}" "$1" "${NC}"
}

cleanup() {
  local exit_code="$?"

  for pid in "${BACKGROUND_PIDS[@]:-}"; do
    if [[ -n "${pid}" ]] && kill -0 "${pid}" >/dev/null 2>&1; then
      info "Stopping background process (pid ${pid})"
      kill "${pid}" >/dev/null 2>&1 || true
      wait "${pid}" 2>/dev/null || true
    fi
  done

  if [[ "${NO_CLEANUP}" == true ]]; then
    warn "--no-cleanup set, leaving k3d cluster '${CLUSTER_NAME}' running"
  elif [[ "${CLUSTER_CREATED}" == true ]]; then
    info "Deleting k3d cluster '${CLUSTER_NAME}'"
    k3d cluster delete "${CLUSTER_NAME}" >/dev/null 2>&1 || true
  else
    info "No cluster created by this run; skipping cluster delete"
  fi

  exit "${exit_code}"
}

trap cleanup EXIT

ensure_go() {
  export GOROOT="${HOME}/.local/go"
  export GOPATH="${HOME}/go"
  export PATH="${GOROOT}/bin:${GOPATH}/bin:${PATH}"

  if ! command -v go >/dev/null 2>&1; then
    info "Go not found; installing go${GO_VERSION}"
    mkdir -p "${HOME}/.local"
    rm -rf "${GOROOT}"
    curl -sL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" | tar xz -C "${HOME}/.local"
    log "Installed go${GO_VERSION}"
  fi

  if ! command -v go >/dev/null 2>&1; then
    fail "Go installation failed"
  fi

  local go_version
  go_version="$(go version)"
  if [[ "${go_version}" != *"go${GO_VERSION}"* ]]; then
    warn "Expected go${GO_VERSION}, found: ${go_version}"
  else
    log "Using ${go_version}"
  fi
}

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
    --skip-cluster)
      SKIP_CLUSTER=true
      shift
      ;;
    --run-test)
      if [[ $# -lt 2 ]]; then
        fail "--run-test requires a test name"
      fi
      RUN_TEST="$2"
      shift 2
      ;;
    --report)
      GENERATE_REPORT=true
      shift
      ;;
    *)
      fail "Unknown argument: $1"
      ;;
  esac
done

section "Preflight"
for cmd in k3d kubectl helm docker cargo git curl; do
  if ! command -v "${cmd}" >/dev/null 2>&1; then
    fail "Required command not found: ${cmd}"
  fi
done
ensure_go
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
info "Building controller image wicket-controller:conformance"
docker build -t wicket-controller:conformance -f - "${ROOT_DIR}" <<'EOF'
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

info "Building proxy image wicket:conformance"
docker build -t wicket:conformance -f - "${ROOT_DIR}" <<'EOF'
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
if [[ "${SKIP_CLUSTER}" == true ]]; then
  info "Reusing existing k3d cluster '${CLUSTER_NAME}' (--skip-cluster)"
  if ! k3d cluster list | awk '{print $1}' | grep -Fxq "${CLUSTER_NAME}"; then
    fail "Cluster '${CLUSTER_NAME}' not found with --skip-cluster"
  fi
else
  if k3d cluster list | awk '{print $1}' | grep -Fxq "${CLUSTER_NAME}"; then
    warn "Deleting existing cluster '${CLUSTER_NAME}'"
    k3d cluster delete "${CLUSTER_NAME}"
  fi

  info "Creating k3d cluster '${CLUSTER_NAME}'"
  k3d cluster create "${CLUSTER_NAME}" \
    --servers 1 \
    --agents 2 \
    -p "8080:80@loadbalancer" \
    --k3s-arg "--disable=traefik@server:0"
  CLUSTER_CREATED=true
  log "Cluster created"
fi

section "Import"
info "Importing images into k3d"
k3d image import wicket-controller:conformance wicket:conformance -c "${CLUSTER_NAME}"
log "Images imported"

section "CRDs"
kubectl apply -f "${ROOT_DIR}/deploy/crds/"
log "Gateway API CRDs applied"

section "Helm Install"
helm upgrade --install wicket "${ROOT_DIR}/deploy/helm/wicket" \
  --namespace wicket-system --create-namespace \
  --set controller.image.repository=wicket-controller \
  --set controller.image.tag=conformance \
  --set controller.image.pullPolicy=Never \
  --set controller.args.leaderElection=false \
  --set controller.args.logLevel=info \
  --set controller.args.jsonLogs=false \
  --set proxy.enabled=false \
  --skip-crds \
  --wait --timeout 120s
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
kubectl -n "${SYSTEM_NAMESPACE}" set env "deployment/${CONTROLLER_DEPLOYMENT}" WICKET_PROXY_IMAGE="wicket:conformance"
kubectl -n "${SYSTEM_NAMESPACE}" rollout status "deployment/${CONTROLLER_DEPLOYMENT}" --timeout=120s
log "Controller configured with local proxy image"

section "Clone gateway-api"
if [[ ! -d "${GATEWAY_API_DIR}" ]]; then
  info "Cloning gateway-api ${GATEWAY_API_VERSION}"
  git clone --depth 1 --branch "${GATEWAY_API_VERSION}" \
    https://github.com/kubernetes-sigs/gateway-api.git "${GATEWAY_API_DIR}"
else
  info "Using existing checkout ${GATEWAY_API_DIR}"
fi
log "gateway-api source ready"

section "Run Conformance Tests"
rm -f "${GO_TEST_LOG}" "${REPORT_TMP_PATH}" "${REPORT_OUTPUT_PATH}"

go_test_cmd=(
  go test ./conformance -run TestConformance -v -count=1 -timeout 30m -args
  --gateway-class=wicket
  --supported-features=Gateway,HTTPRoute
  --cleanup-base-resources=true
  --debug
  --organization=geverding
  --project=wicket
  --url=https://github.com/GEverding/wicket
  --version=0.1.0
)

if [[ -n "${RUN_TEST}" ]]; then
  go_test_cmd+=("--run-test=${RUN_TEST}")
fi

if [[ "${GENERATE_REPORT}" == true ]]; then
  go_test_cmd+=("--report-output=${REPORT_TMP_PATH}")
fi

set +e
(
  cd "${GATEWAY_API_DIR}"
  "${go_test_cmd[@]}"
) 2>&1 | tee "${GO_TEST_LOG}"
TEST_EXIT_CODE=${PIPESTATUS[0]}
set -e

section "Results"
pass_count="$(grep -c '^--- PASS:' "${GO_TEST_LOG}" 2>/dev/null || true)"
fail_count="$(grep -c '^--- FAIL:' "${GO_TEST_LOG}" 2>/dev/null || true)"
skip_count="$(grep -c '^--- SKIP:' "${GO_TEST_LOG}" 2>/dev/null || true)"

if [[ "${GENERATE_REPORT}" == true ]]; then
  if [[ -f "${REPORT_TMP_PATH}" ]]; then
    cp "${REPORT_TMP_PATH}" "${REPORT_OUTPUT_PATH}"
    log "Conformance report written to ${REPORT_OUTPUT_PATH}"
  else
    warn "Report requested but not generated"
  fi
fi

info "go test exit code: ${TEST_EXIT_CODE}"
info "Counts: pass=${pass_count:-0} fail=${fail_count:-0} skip=${skip_count:-0}"

info "Controller logs (last 100 lines)"
kubectl -n "${SYSTEM_NAMESPACE}" logs "deploy/${CONTROLLER_DEPLOYMENT}" --tail=100 || true

if [[ "${TEST_EXIT_CODE}" -eq 0 ]]; then
  RESULT="PASS"
  printf "\n%b========================================%b\n" "${GREEN}" "${NC}"
  printf "%b   CONFORMANCE PASS (pass=%s fail=%s skip=%s)   %b\n" "${GREEN}" "${pass_count:-0}" "${fail_count:-0}" "${skip_count:-0}" "${NC}"
  printf "%b========================================%b\n\n" "${GREEN}" "${NC}"
else
  RESULT="FAIL"
  printf "\n%b========================================%b\n" "${RED}" "${NC}"
  printf "%b   CONFORMANCE FAIL (pass=%s fail=%s skip=%s)   %b\n" "${RED}" "${pass_count:-0}" "${fail_count:-0}" "${skip_count:-0}" "${NC}"
  printf "%b========================================%b\n\n" "${RED}" "${NC}"
fi

exit "${TEST_EXIT_CODE}"
