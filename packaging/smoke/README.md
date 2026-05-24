# Wicket package smoke harness (QEMU + cloud-init)

Shared smoke harness for standalone package installs on Ubuntu 24 LTS (`.deb`), Ubuntu 26 LTS (`.deb`), and Oracle Linux 9 (`.rpm`).

## Prerequisites

- `qemu-system-x86_64`
- `qemu-img`
- `genisoimage` **or** `xorriso`
- `ssh`, `scp`, `ssh-keygen`
- `curl`
- `sha256sum`
- KVM is optional. Harness tries `-enable-kvm -cpu host` and falls back to `-cpu max`.

## Cache location

Cloud images are cached outside the repo at:

`$WICKET_SMOKE_CACHE` or default `~/.cache/wicket-smoke`

Per-run artifacts live under `.../runs/<vm>-<timestamp>/`.

## Run

Ubuntu 24 LTS:

```bash
packaging/smoke/qemu-run.sh \
  --distro packaging/smoke/distros/ubuntu.env \
  --package /tmp/opencode/wicket-pkgs-local/wicket_0.1.0-1_amd64.deb
```

Oracle Linux:

```bash
packaging/smoke/qemu-run.sh \
  --distro packaging/smoke/distros/oracle.env \
  --package /tmp/opencode/wicket-pkgs-local/wicket-0.1.0-1.x86_64.rpm
```

Ubuntu 26 LTS:

```bash
packaging/smoke/qemu-run.sh \
  --distro packaging/smoke/distros/ubuntu-26.env \
  --package /tmp/opencode/wicket-pkgs-local/wicket_0.1.0-1_amd64.deb
```

## Debugging (`--keep`)

Use `--keep` to skip teardown and keep run artifacts + VM alive after success:

```bash
packaging/smoke/qemu-run.sh --distro ... --package ... --keep
```

Script prints reconnect command in this shape:

```bash
ssh -i <workdir>/id_ed25519 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o IdentitiesOnly=yes -o LogLevel=ERROR -p <port> tester@127.0.0.1
```

## Exit codes

- `0`: full smoke succeeded (install + proxy + reload path)
- non-zero: setup or smoke failure (runner prints context and collects guest logs when available)

## Notes

- Oracle cloud image URLs can shift over time. Override via environment when needed:
  - `IMAGE_URL=...`
  - `IMAGE_NAME=...`
- Harness intentionally runs `systemctl reload wicket` even when package version is unchanged. This still exercises the helper-spawned `wicket --upgrade` child and SIGQUIT handoff path.
