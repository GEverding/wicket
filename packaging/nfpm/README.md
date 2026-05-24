# Wicket distro packages

Wicket ships standalone `.deb` and `.rpm` packages through `nFPM`.

## Supported Package Targets

The release package support matrix is:

- Ubuntu 24 LTS (`.deb`)
- Ubuntu 26 LTS (`.deb`)
- Oracle Linux 9 (`.rpm`)

## Compatibility Build

Build release packages with the compatibility wrapper, not directly on an arbitrary host:

```bash
packaging/nfpm/build-compatible.sh \
  --version 0.1.0 \
  --arch amd64 \
  --target /tmp/opencode/wicket-pkgs
```

The wrapper builds the `wicket` binary in a Debian Bookworm container, then packages that binary with `nFPM`. This keeps the glibc baseline low enough for Oracle Linux 9 while still supporting newer Ubuntu LTS releases.

The default container build installs:

- `build-essential`
- `clang`
- `cmake`
- `libclang-dev`
- `libssl-dev`
- `pkg-config`

Defaults can be overridden when needed:

```bash
WICKET_COMPAT_CONTAINER_IMAGE=rust:1.85-bookworm \
WICKET_COMPAT_RUST_TOOLCHAIN=nightly-2026-04-13 \
packaging/nfpm/build-compatible.sh --version 0.1.0 --arch amd64 --target /tmp/opencode/wicket-pkgs
```

## Host Build

`packaging/nfpm/build.sh` remains useful for local development, but host-built artifacts inherit the host glibc requirement. Do not use it for release artifacts unless the host is intentionally the supported compatibility baseline.

```bash
packaging/nfpm/build.sh --version 0.1.0 --arch amd64 --target /tmp/opencode/wicket-pkgs-local
```

## Smoke Tests

Run QEMU smoke tests for the supported package targets before release:

```bash
packaging/smoke/qemu-run.sh \
  --distro packaging/smoke/distros/ubuntu.env \
  --package /tmp/opencode/wicket-pkgs/wicket_0.1.0-1_amd64.deb

packaging/smoke/qemu-run.sh \
  --distro packaging/smoke/distros/oracle.env \
  --package /tmp/opencode/wicket-pkgs/wicket-0.1.0-1.x86_64.rpm
```
