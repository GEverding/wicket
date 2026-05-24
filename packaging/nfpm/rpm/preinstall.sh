#!/bin/sh
set -eu

group_name=wicket
user_name=wicket

if ! getent group "$group_name" >/dev/null 2>&1; then
    groupadd --system "$group_name"
fi

if ! id -u "$user_name" >/dev/null 2>&1; then
    nologin_shell=$(command -v nologin 2>/dev/null || printf '%s' /usr/sbin/nologin)
    useradd \
        --system \
        --no-create-home \
        --home-dir /var/lib/wicket \
        --shell "$nologin_shell" \
        --gid "$group_name" \
        "$user_name"
fi
