#!/bin/sh
set -eu

case "${1:-}" in
    0|erase|remove)
        if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet wicket.service; then
            systemctl stop wicket.service || true
        fi
        ;;
esac
