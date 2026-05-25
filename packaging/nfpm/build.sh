#!/bin/sh
set -eu

usage() {
    printf '%s\n' "Usage: $0 --arch ARCH --target DIR [--version VERSION] [--formats deb,rpm] [--package-name NAME] [--features FEATURES] [--no-build]" >&2
    printf '%s\n' "" >&2
    printf '%s\n' "Builds target/release/wicket and packages .deb/.rpm artifacts with nFPM." >&2
    printf '%s\n' "Version defaults to [workspace.package].version in Cargo.toml." >&2
    printf '%s\n' "Set WICKET_RELEASE_BIN to package a prebuilt binary with --no-build." >&2
    exit 2
}

formats=deb,rpm
version=
arch=
target=
build=1
package_name=wicket
features=

while [ $# -gt 0 ]; do
    case "$1" in
        --version)
            version=${2:-}
            shift 2
            ;;
        --arch)
            arch=${2:-}
            shift 2
            ;;
        --target)
            target=${2:-}
            shift 2
            ;;
        --package-name)
            package_name=${2:-}
            shift 2
            ;;
        --features)
            features=${2:-}
            shift 2
            ;;
        --formats)
            formats=${2:-}
            shift 2
            ;;
        --no-build)
            build=0
            shift
            ;;
        -h|--help)
            usage
            ;;
        *)
            usage
            ;;
    esac
done

[ -n "$arch" ] || usage
[ -n "$target" ] || usage

command -v nfpm >/dev/null 2>&1 || {
    printf '%s\n' "nfpm not found in PATH" >&2
    exit 127
}

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/../.." && pwd)
config="$script_dir/wicket.nfpm.yaml"

workspace_version() {
    awk '
        /^\[workspace\.package\]$/ { in_workspace_package = 1; next }
        /^\[/ { in_workspace_package = 0 }
        in_workspace_package && $1 == "version" {
            gsub(/"/, "", $3)
            print $3
            exit
        }
    ' "$repo_root/Cargo.toml"
}

if [ -z "$version" ]; then
    version=$(workspace_version)
fi

[ -n "$version" ] || {
    printf '%s\n' "failed to read package version from Cargo.toml" >&2
    exit 2
}

version=${version#v}
release_bin=${WICKET_RELEASE_BIN:-$repo_root/target/release/wicket}

if [ "$build" -eq 1 ]; then
    command -v cargo >/dev/null 2>&1 || {
        printf '%s\n' "cargo not found in PATH" >&2
        exit 127
    }
    if [ -n "$features" ]; then
        cargo build --release -p wicket --locked --features "$features"
    else
        cargo build --release -p wicket --locked
    fi
fi

if [ ! -x "$release_bin" ]; then
    printf '%s\n' "release binary not found or not executable: $release_bin" >&2
    exit 2
fi

mkdir -p "$target"

old_ifs=$IFS
IFS=,
for format in $formats; do
    [ -n "$format" ] || continue
    description="Wicket standalone reverse proxy and graceful HTTP upgrade service."
    if [ "$package_name" = "wicket-ebpf" ]; then
        description="Wicket standalone reverse proxy with eBPF sockmap stream acceleration."
    fi
    WICKET_NFPM_VERSION=$version \
    WICKET_NFPM_NAME="$package_name" \
    WICKET_NFPM_DESCRIPTION="$description" \
    WICKET_NFPM_ARCH=$arch \
    WICKET_RELEASE_BIN="$release_bin" \
    WICKET_UPGRADE_HELPER="$repo_root/packaging/systemd/wicket-upgrade" \
    WICKET_SERVICE_UNIT="$repo_root/packaging/systemd/wicket.service" \
    WICKET_DEFAULT_CONFIG="$repo_root/wicket.toml" \
    WICKET_DEB_PREINSTALL="$script_dir/deb/preinstall.sh" \
    WICKET_DEB_POSTINSTALL="$script_dir/deb/postinstall.sh" \
    WICKET_DEB_PREREMOVE="$script_dir/deb/preremove.sh" \
    WICKET_DEB_POSTREMOVE="$script_dir/deb/postremove.sh" \
    WICKET_RPM_PREINSTALL="$script_dir/rpm/preinstall.sh" \
    WICKET_RPM_POSTINSTALL="$script_dir/rpm/postinstall.sh" \
    WICKET_RPM_PREREMOVE="$script_dir/rpm/preremove.sh" \
    WICKET_RPM_POSTREMOVE="$script_dir/rpm/postremove.sh" \
    nfpm package --config "$config" --packager "$format" --target "$target"
done
IFS=$old_ifs

printf '%s\n' "Artifacts written to: $target"
