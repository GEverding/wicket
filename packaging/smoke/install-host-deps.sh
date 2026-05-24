#!/usr/bin/env bash
set -euo pipefail

log() {
  printf '[wicket-smoke-deps] %s\n' "$*"
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1
}

if ! need_cmd apt-get; then
  log "This installer currently supports apt-based hosts only."
  log "Install these packages with your distro package manager: qemu-system-x86 qemu-utils genisoimage"
  exit 1
fi

log "Updating apt package index"
sudo apt-get update

log "Installing QEMU smoke dependencies"
sudo apt-get install -y qemu-system-x86 qemu-utils genisoimage

log "Installed tools:"
for cmd in qemu-system-x86_64 qemu-img genisoimage; do
  if need_cmd "$cmd"; then
    log "  $cmd: $(command -v "$cmd")"
  else
    log "  $cmd: missing"
  fi
done

if [ -e /dev/kvm ]; then
  log "KVM device found: /dev/kvm"
else
  log "KVM device not found; smoke tests can still run, but QEMU will use slow software emulation."
fi

log "Next: packaging/smoke/qemu-run.sh --distro packaging/smoke/distros/ubuntu.env --package /tmp/opencode/wicket-pkgs-local/wicket_0.1.0-1_amd64.deb"
