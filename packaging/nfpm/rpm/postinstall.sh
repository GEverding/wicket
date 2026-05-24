#!/bin/sh
set -eu

install -d -o root -g wicket -m 0750 /etc/wicket /etc/wicket/tls
install -d -o wicket -g wicket -m 0750 /var/lib/wicket /var/lib/wicket/acme

if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || printf '%s\n' "wicket: warning: systemd daemon-reload failed; continuing" >&2
    if systemctl is-active --quiet wicket.service; then
        systemctl reload wicket.service || printf '%s\n' "wicket: warning: reload failed; incumbent service left running" >&2
    fi
fi
