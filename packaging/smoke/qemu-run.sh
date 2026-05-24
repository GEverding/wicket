#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

DISTRO_FILE=""
PACKAGE_PATH=""
KEEP=0

usage() {
  cat <<'USAGE'
Usage:
  qemu-run.sh --distro <path-to-env-file> --package <path-to-deb-or-rpm> [--keep]
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --distro)
      DISTRO_FILE="${2:-}"
      shift 2
      ;;
    --package)
      PACKAGE_PATH="${2:-}"
      shift 2
      ;;
    --keep)
      KEEP=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage
      exit 2
      ;;
  esac
done

if [[ -z "$DISTRO_FILE" || -z "$PACKAGE_PATH" ]]; then
  echo "--distro and --package are required" >&2
  usage
  exit 2
fi

if [[ ! -f "$DISTRO_FILE" ]]; then
  echo "Distro env file not found: $DISTRO_FILE" >&2
  exit 2
fi

if [[ ! -f "$PACKAGE_PATH" ]]; then
  echo "Package not found: $PACKAGE_PATH" >&2
  exit 2
fi

# shellcheck disable=SC1090
source "$DISTRO_FILE"

for var in IMAGE_URL IMAGE_NAME SSH_PORT VM_NAME INSTALL_CMD; do
  if [[ -z "${!var:-}" ]]; then
    echo "Missing required distro variable: $var" >&2
    exit 2
  fi
done

LOG_PREFIX="[$VM_NAME]"
log() {
  echo "$LOG_PREFIX $*" >&2
}

shell_quote() {
  printf '%q' "$1"
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    log "Missing required command: $1"
    exit 2
  fi
}

for cmd in qemu-system-x86_64 qemu-img ssh scp ssh-keygen curl sha256sum; do
  require_cmd "$cmd"
done

if command -v genisoimage >/dev/null 2>&1; then
  ISO_TOOL="genisoimage"
elif command -v xorriso >/dev/null 2>&1; then
  ISO_TOOL="xorriso"
else
  log "Missing required command: need genisoimage or xorriso"
  exit 2
fi

CACHE_DIR="${WICKET_SMOKE_CACHE:-$HOME/.cache/wicket-smoke}"
RUNS_DIR="$CACHE_DIR/runs"
mkdir -p "$CACHE_DIR" "$RUNS_DIR"

TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
WORKDIR="$RUNS_DIR/${VM_NAME}-${TIMESTAMP}"
mkdir -p "$WORKDIR"

BASE_IMAGE="$CACHE_DIR/$IMAGE_NAME"
OVERLAY_IMAGE="$WORKDIR/overlay.qcow2"
SEED_ISO="$WORKDIR/seed.iso"
VM_PID_FILE="$WORKDIR/vm.pid"
SSH_KEY="$WORKDIR/id_ed25519"
CONSOLE_LOG="$WORKDIR/console.log"
USER_DATA="$WORKDIR/user-data"
META_DATA="$WORKDIR/meta-data"
PKG_BASENAME="$(basename "$PACKAGE_PATH")"

SSH_OPTS=(
  -i "$SSH_KEY"
  -o StrictHostKeyChecking=no
  -o UserKnownHostsFile=/dev/null
  -o IdentitiesOnly=yes
  -o LogLevel=ERROR
  -p "$SSH_PORT"
)

SCP_OPTS=(
  -i "$SSH_KEY"
  -o StrictHostKeyChecking=no
  -o UserKnownHostsFile=/dev/null
  -o IdentitiesOnly=yes
  -o LogLevel=ERROR
  -P "$SSH_PORT"
)

cleanup() {
  local rc=$?
  if [[ -f "$VM_PID_FILE" ]]; then
    local pid
    pid="$(cat "$VM_PID_FILE" || true)"
    if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
      if [[ "$KEEP" -eq 1 && "$rc" -eq 0 ]]; then
        log "Keeping VM running (pid=$pid)"
        log "Reconnect: ssh ${SSH_OPTS[*]} tester@127.0.0.1"
      else
        log "Stopping VM pid=$pid"
        kill "$pid" 2>/dev/null || true
      fi
    fi
  fi

  if [[ "$KEEP" -eq 0 && "$rc" -eq 0 ]]; then
    rm -rf "$WORKDIR"
  else
    log "Kept workdir: $WORKDIR"
  fi

  return "$rc"
}
trap cleanup EXIT

if [[ ! -f "$BASE_IMAGE" ]]; then
  log "Downloading base image: $IMAGE_URL"
  curl -fL --retry 3 -o "$BASE_IMAGE" "$IMAGE_URL"
else
  log "Using cached image: $BASE_IMAGE"
fi

log "Creating overlay image"
qemu-img create -f qcow2 -F qcow2 -b "$BASE_IMAGE" "$OVERLAY_IMAGE" >/dev/null

log "Generating ephemeral SSH keypair"
ssh-keygen -t ed25519 -N "" -f "$SSH_KEY" >/dev/null
SSH_PUBKEY="$(<"$SSH_KEY.pub")"

log "Rendering cloud-init templates"
sed "s|__SSH_PUBKEY__|$SSH_PUBKEY|g" "$SCRIPT_DIR/user-data.tmpl" > "$USER_DATA"
sed "s|__VM_NAME__|$VM_NAME|g" "$SCRIPT_DIR/meta-data.tmpl" > "$META_DATA"

log "Building seed ISO with $ISO_TOOL"
if [[ "$ISO_TOOL" == "genisoimage" ]]; then
  genisoimage -output "$SEED_ISO" -volid cidata -joliet -rock "$USER_DATA" "$META_DATA" >/dev/null 2>&1
else
  xorriso -as mkisofs -output "$SEED_ISO" -volid cidata -joliet -rock "$USER_DATA" "$META_DATA" >/dev/null 2>&1
fi

start_vm() {
  local cpu_args=("$@")
  qemu-system-x86_64 \
    -m 1024 -smp 2 \
    "${cpu_args[@]}" \
    -drive "file=$OVERLAY_IMAGE,if=virtio,format=qcow2" \
    -drive "file=$SEED_ISO,if=virtio,format=raw,readonly=on" \
    -netdev "user,id=net0,hostfwd=tcp:127.0.0.1:${SSH_PORT}-:22" \
    -device virtio-net-pci,netdev=net0 \
    -display none -monitor none -serial "file:$CONSOLE_LOG" \
    -pidfile "$VM_PID_FILE" -daemonize
}

log "Booting VM (try KVM first)"
if ! start_vm -enable-kvm -cpu host; then
  log "KVM unavailable, falling back to software CPU mode"
  start_vm -cpu max
fi

log "Waiting for SSH to come up"
SSH_READY=0
for _ in {1..60}; do
  if ssh "${SSH_OPTS[@]}" tester@127.0.0.1 true >/dev/null 2>&1; then
    SSH_READY=1
    break
  fi
  sleep 5
done

if [[ "$SSH_READY" -ne 1 ]]; then
  log "Timed out waiting for SSH"
  tail -n 200 "$CONSOLE_LOG" >&2 || true
  exit 1
fi

log "Waiting for cloud-init completion"
ssh "${SSH_OPTS[@]}" tester@127.0.0.1 cloud-init status --wait

log "Copying package and smoke script"
scp "${SCP_OPTS[@]}" "$PACKAGE_PATH" "$SCRIPT_DIR/smoke.sh" tester@127.0.0.1:/home/tester/

log "Running guest smoke test"
if ! ssh "${SSH_OPTS[@]}" tester@127.0.0.1 bash /home/tester/smoke.sh "$(shell_quote "/home/tester/$PKG_BASENAME")" "$(shell_quote "$INSTALL_CMD")"; then
  log "Smoke test failed; collecting diagnostics"
  tail -n 200 "$CONSOLE_LOG" >&2 || true
  scp "${SCP_OPTS[@]}" tester@127.0.0.1:/tmp/wicket-status.log "$WORKDIR/" >/dev/null 2>&1 || true
  scp "${SCP_OPTS[@]}" tester@127.0.0.1:/tmp/wicket-journal.log "$WORKDIR/" >/dev/null 2>&1 || true
  scp "${SCP_OPTS[@]}" tester@127.0.0.1:/tmp/wicket-status-after.log "$WORKDIR/" >/dev/null 2>&1 || true
  scp "${SCP_OPTS[@]}" tester@127.0.0.1:/tmp/wicket-journal-after.log "$WORKDIR/" >/dev/null 2>&1 || true
  for log_file in "$WORKDIR"/wicket-status.log "$WORKDIR"/wicket-journal.log "$WORKDIR"/wicket-status-after.log "$WORKDIR"/wicket-journal-after.log; do
    if [[ -f "$log_file" ]]; then
      log "Collected $(basename "$log_file")"
      tail -n 80 "$log_file" >&2 || true
    fi
  done
  exit 1
fi

log "Smoke test passed"
