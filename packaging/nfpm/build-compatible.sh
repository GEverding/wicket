#!/bin/sh
set -eu

usage() {
    printf '%s\n' "Usage: $0 --arch ARCH --target DIR [--version VERSION] [--formats deb,rpm] [--variant normal|ebpf|all] [--container-image IMAGE] [--rust-toolchain TOOLCHAIN]" >&2
    printf '%s\n' "" >&2
    printf '%s\n' "Builds Wicket in an older-glibc Debian Bookworm container, then packages it with nFPM." >&2
    printf '%s\n' "Version defaults to [workspace.package].version in Cargo.toml." >&2
    printf '%s\n' "Default support baseline targets Ubuntu 24 LTS, Ubuntu 26 LTS, and Oracle Linux 9." >&2
    exit 2
}

formats=deb,rpm
version=
arch=
target=
container_image=${WICKET_COMPAT_CONTAINER_IMAGE:-rust:1.85-bookworm}
rust_toolchain=${WICKET_COMPAT_RUST_TOOLCHAIN:-nightly-2026-04-13}
variant=normal

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
        --variant)
            variant=${2:-}
            shift 2
            ;;
        --container-image)
            container_image=${2:-}
            shift 2
            ;;
        --rust-toolchain)
            rust_toolchain=${2:-}
            shift 2
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

case "$variant" in
    normal|ebpf|all)
        ;;
    *)
        printf '%s\n' "unknown variant: $variant" >&2
        usage
        ;;
esac

case "$arch" in
    amd64|x86_64)
        ;;
    *)
        printf '%s\n' "compatible container build currently supports amd64/x86_64 only: $arch" >&2
        exit 2
        ;;
esac

command -v docker >/dev/null 2>&1 || {
    printf '%s\n' "docker not found in PATH" >&2
    exit 127
}

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/../.." && pwd)
build_root=$(mktemp -d "${TMPDIR:-/tmp}/wicket-compatible-build.XXXXXX")

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

cleanup() {
    if [ "${WICKET_KEEP_COMPAT_BUILD:-0}" != "1" ]; then
        rm -rf "$build_root"
    else
        printf '%s\n' "Kept compatible build dir: $build_root" >&2
    fi
}
trap cleanup EXIT

build_variant() {
    variant_name=$1
    package_name=$2
    cargo_features=$3
    build_dir="$build_root/$variant_name"
    mkdir -p "$build_dir"

    printf '%s\n' "Building Wicket $variant_name compatibility binary in $container_image with $rust_toolchain" >&2

    docker run --rm \
        -e "RUST_TOOLCHAIN=$rust_toolchain" \
        -e "CARGO_FEATURES=$cargo_features" \
        -v "$repo_root:/src:ro" \
        -v "$build_dir:/out" \
        -v "wicket-cargo-registry:/usr/local/cargo/registry" \
        -v "wicket-cargo-git:/usr/local/cargo/git" \
        -v "wicket-rustup:/usr/local/rustup" \
        "$container_image" \
        sh -ceu '
            export PATH=/usr/local/cargo/bin:$PATH
            rustup toolchain install "$RUST_TOOLCHAIN" --profile minimal
            rustup component add --toolchain "$RUST_TOOLCHAIN" rustfmt
            apt-get update
            apt-get install -y --no-install-recommends \
                build-essential \
                clang \
                cmake \
                libclang-dev \
                libelf-dev \
                libssl-dev \
                llvm \
                pkg-config
            cp -a /src /work
            cd /work
            if [ -n "$CARGO_FEATURES" ]; then
                cargo +"$RUST_TOOLCHAIN" build --release -p wicket --locked --features "$CARGO_FEATURES"
            else
                cargo +"$RUST_TOOLCHAIN" build --release -p wicket --locked
            fi
            cp target/release/wicket /out/wicket
            /out/wicket --version
        '

    WICKET_RELEASE_BIN="$build_dir/wicket" \
        "$script_dir/build.sh" \
        --version "$version" \
        --arch "$arch" \
        --target "$target" \
        --formats "$formats" \
        --package-name "$package_name" \
        --no-build
}

case "$variant" in
    normal)
        build_variant normal wicket ""
        ;;
    ebpf)
        build_variant ebpf wicket-ebpf ebpf
        ;;
    all)
        build_variant normal wicket ""
        build_variant ebpf wicket-ebpf ebpf
        ;;
esac
