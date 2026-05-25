#!/bin/sh
set -eu

usage() {
    printf '%s\n' "Usage: $0 [--target DIR] [--arch ARCH] [--formats deb,rpm] [--tag TAG] [--draft]" >&2
    printf '%s\n' "" >&2
    printf '%s\n' "Builds all distro package variants from the Cargo version and creates a GitHub release with gh." >&2
    exit 2
}

arch=amd64
formats=deb,rpm
target=
tag=
draft=0

while [ $# -gt 0 ]; do
    case "$1" in
        --target)
            target=${2:-}
            shift 2
            ;;
        --arch)
            arch=${2:-}
            shift 2
            ;;
        --formats)
            formats=${2:-}
            shift 2
            ;;
        --tag)
            tag=${2:-}
            shift 2
            ;;
        --draft)
            draft=1
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

command -v cargo >/dev/null 2>&1 || {
    printf '%s\n' "cargo not found in PATH" >&2
    exit 127
}
command -v gh >/dev/null 2>&1 || {
    printf '%s\n' "gh not found in PATH" >&2
    exit 127
}
command -v git >/dev/null 2>&1 || {
    printf '%s\n' "git not found in PATH" >&2
    exit 127
}

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)

version=$(awk '
    /^\[workspace\.package\]$/ { in_workspace_package = 1; next }
    /^\[/ { in_workspace_package = 0 }
    in_workspace_package && $1 == "version" {
        gsub(/"/, "", $3)
        print $3
        exit
    }
' "$repo_root/Cargo.toml")

[ -n "$version" ] || {
    printf '%s\n' "failed to read package version from Cargo.toml" >&2
    exit 2
}

if [ -z "$tag" ]; then
    tag="v$version"
fi

if [ -z "$target" ]; then
    target="$repo_root/target/release-packages/$version"
fi

mkdir -p "$target"

"$repo_root/packaging/nfpm/build-compatible.sh" \
    --version "$version" \
    --arch "$arch" \
    --target "$target" \
    --formats "$formats" \
    --variant all

set -- "$target"/*
if [ ! -f "$1" ]; then
    printf '%s\n' "no release artifacts produced in $target" >&2
    exit 1
fi

commitish=$(git -C "$repo_root" rev-parse HEAD)

draft_arg=
if [ "$draft" -eq 1 ]; then
    draft_arg=--draft
fi

gh release create "$tag" "$target"/* \
    --target "$commitish" \
    --title "Wicket $tag" \
    --generate-notes \
    $draft_arg

printf '%s\n' "Created GitHub release $tag with artifacts from $target"
