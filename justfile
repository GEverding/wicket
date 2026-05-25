set dotenv-load := true

version := `awk '/^\[workspace\.package\]$/ { in_workspace_package = 1; next } /^\[/ { in_workspace_package = 0 } in_workspace_package && $1 == "version" { gsub(/"/, "", $3); print $3; exit }' Cargo.toml`
arch := "amd64"
pkg_dir := "/tmp/opencode/wicket-pkgs"

default:
    @just --list

# Build local development packages on the host. Do not use for releases.
package-local target=pkg_dir:
    packaging/nfpm/build.sh --arch {{arch}} --target {{target}}

# Build release-compatible normal packages from the older-glibc container baseline.
package target=pkg_dir:
    packaging/nfpm/build-compatible.sh --arch {{arch}} --target {{target}} --variant normal

# Build release-compatible eBPF packages from the older-glibc container baseline.
package-ebpf target=pkg_dir:
    packaging/nfpm/build-compatible.sh --arch {{arch}} --target {{target}} --variant ebpf

# Build all release-compatible package variants.
package-all target=pkg_dir:
    packaging/nfpm/build-compatible.sh --arch {{arch}} --target {{target}} --variant all

# Install host dependencies for QEMU/cloud-init package smoke tests.
smoke-deps:
    packaging/smoke/install-host-deps.sh

# Smoke normal DEB package on Ubuntu 24 LTS.
smoke-ubuntu target=pkg_dir:
    packaging/smoke/qemu-run.sh --distro packaging/smoke/distros/ubuntu.env --package {{target}}/wicket_{{version}}-1_{{arch}}.deb

# Smoke normal DEB package on Ubuntu 26 LTS.
smoke-ubuntu-26 target=pkg_dir:
    packaging/smoke/qemu-run.sh --distro packaging/smoke/distros/ubuntu-26.env --package {{target}}/wicket_{{version}}-1_{{arch}}.deb

# Smoke normal RPM package on Oracle Linux 9.
smoke-oracle target=pkg_dir:
    packaging/smoke/qemu-run.sh --distro packaging/smoke/distros/oracle.env --package {{target}}/wicket-{{version}}-1.x86_64.rpm

# Smoke plain TCP and SNI stream routing on Ubuntu 24 LTS.
smoke-stream-ubuntu target=pkg_dir:
    packaging/smoke/qemu-run.sh --distro packaging/smoke/distros/ubuntu.env --package {{target}}/wicket_{{version}}-1_{{arch}}.deb --smoke-script packaging/smoke/smoke-stream.sh

# Smoke plain TCP and SNI stream routing on Oracle Linux 9.
smoke-stream-oracle target=pkg_dir:
    packaging/smoke/qemu-run.sh --distro packaging/smoke/distros/oracle.env --package {{target}}/wicket-{{version}}-1.x86_64.rpm --smoke-script packaging/smoke/smoke-stream.sh

# Smoke all currently supported normal package targets.
smoke-all target=pkg_dir:
    just smoke-ubuntu {{target}}
    just smoke-ubuntu-26 {{target}}
    just smoke-oracle {{target}}

# Smoke normal package HTTP path plus stream path on representative DEB/RPM targets.
smoke-full target=pkg_dir:
    just smoke-all {{target}}
    just smoke-stream-ubuntu {{target}}
    just smoke-stream-oracle {{target}}

# Create a draft GitHub release with all package variants.
release-draft target=pkg_dir:
    packaging/release.sh --target {{target}} --draft

# Create a GitHub release with all package variants.
release target=pkg_dir:
    packaging/release.sh --target {{target}}
