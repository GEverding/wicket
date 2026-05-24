#!/bin/sh
set -eu

usage() {
    printf '%s\n' "Usage: $0 --version VERSION --arch ARCH --target DIR [--formats deb,rpm] [--no-build]" >&2
    printf '%s\n' "" >&2
    printf '%s\n' "Builds target/release/wicket and packages .deb/.rpm artifacts with nFPM." >&2
    printf '%s\n' "Set WICKET_RELEASE_BIN to package a prebuilt binary with --no-build." >&2
    exit 2
}

formats=deb,rpm
version=
arch=
target=
build=1

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

[ -n "$version" ] || usage
[ -n "$arch" ] || usage
[ -n "$target" ] || usage

command -v nfpm >/dev/null 2>&1 || {
    printf '%s\n' "nfpm not found in PATH" >&2
    exit 127
}

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/../.." && pwd)
config="$script_dir/wicket.nfpm.yaml"

version=${version#v}
release_bin=${WICKET_RELEASE_BIN:-$repo_root/target/release/wicket}

if [ "$build" -eq 1 ]; then
    command -v cargo >/dev/null 2>&1 || {
        printf '%s\n' "cargo not found in PATH" >&2
        exit 127
    }
    cargo build --release -p wicket --locked
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
    WICKET_NFPM_VERSION=$version \
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
