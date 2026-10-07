#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Puts msb + libkrunfw for this host in <dest-dir>, for the VM tests (PUDDLE_VM_RUNTIME_DIR). Every
# downloaded file must match its SHA-256 pinned in ci/msb-runtime.sha256, and a source checkout its
# pinned commit.
# Usage: ci/fetch-msb.sh [<tag>] <dest-dir>     tag defaults to the SDK's fork tag (ci/msb-tag.sh)
#
#   fork tag v<release>-puddle.N (TijsVK/microsandbox):
#     Windows: the release's msb-windows-x86_64.exe and libkrunfw-windows-x86_64.dll, installed as
#              msb.exe + libkrunfw.dll.
#     Linux:   the fork releases no Linux msb, so msb is built from the tag's source (commit
#              pinned) with upstream's agentd embedded; libkrunfw from upstream's release v<release>
#              (the fork keeps upstream's firmware), installed as libkrunfw.so.5 and as a copy under
#              the versioned name msb looks for beside itself (libkrunfw.so.<version>, pinned in
#              ci/msb-runtime.sha256). Needs cargo and libcap-ng-dev; takes ~10 min cold. MSB_BUILD_DIR (default <dest-dir>/../msb-build) holds the checkout,
#              its target dir and the result msb-<commit>, which is reused when present (a CI
#              cache keeps only that file).
#   upstream tag v<release> (superradcompany/microsandbox): the release archive for this host.
# Works in Linux sh and in Git Bash on Windows. Network failures are retried (infrastructure) and each retry is printed; a checksum mismatch never is.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
case "$#" in
1) tag=$("$here/msb-tag.sh"); dest=$1 ;;
2) tag=$1; dest=$2 ;;
*) echo "usage: $0 [<tag>] <dest-dir>" >&2; exit 2 ;;
esac

case "$(uname -s)" in
Linux) os=linux ;;
MINGW* | MSYS* | CYGWIN*) os=windows ;;
*) echo "fetch-msb: unsupported host $(uname -s)" >&2; exit 2 ;;
esac
case "$(uname -m)" in
x86_64 | amd64) arch=x86_64 ;;
*) echo "fetch-msb: unsupported arch $(uname -m)" >&2; exit 2 ;;
esac

fork_repo=TijsVK/microsandbox
upstream_repo=superradcompany/microsandbox
case "$tag" in
v*-puddle.*) release=${tag%%-puddle.*} ;;
v*) release=$tag ;;
*) echo "fetch-msb: not a release tag: $tag" >&2; exit 2 ;;
esac

# pinned <tag> <name>: the third field of the matching line in ci/msb-runtime.sha256.
pinned() {
    want=$(awk -v t="$1" -v a="$2" '$1 == t && $2 == a { print $3 }' "$here/msb-runtime.sha256")
    [ -n "$want" ] || {
        echo "fetch-msb: nothing pinned for $1 $2 in ci/msb-runtime.sha256" >&2
        exit 1
    }
    echo "$want"
}

# fetch <repo> <tag> <asset> <out>: download one release asset and check its pinned SHA-256.
fetch() {
    want=$(pinned "$2" "$3")
    url="https://github.com/$1/releases/download/$2/$3"
    attempt=1
    until curl -fsSL --connect-timeout 20 --max-time 300 -o "$4" "$url"; do
        [ "$attempt" -lt 3 ] || { echo "fetch-msb: download failed 3 times: $url" >&2; exit 1; }
        echo "fetch-msb: download attempt $attempt failed, retrying (infrastructure retry)" >&2
        attempt=$((attempt + 1))
        sleep 5
    done
    # Hash from stdin: for a path with backslashes, Git Bash's sha256sum puts a backslash before the hash.
    got=$(sha256sum < "$4" | cut -d' ' -f1)
    if [ "$got" != "$want" ]; then
        echo "fetch-msb: checksum mismatch for $2 $3: got $got, pinned $want" >&2
        exit 1
    fi
    echo "fetch-msb: $1 $2 $3 verified ($got)" >&2
}

mkdir -p "$dest"
# Absolute: the source build below runs from other directories and gets paths under $dest.
dest=$(cd "$dest" && pwd)
case "$tag/$os" in
*-puddle.*/windows)
    fetch "$fork_repo" "$tag" "msb-windows-$arch.exe" "$dest/msb.exe"
    fetch "$fork_repo" "$tag" "libkrunfw-windows-$arch.dll" "$dest/libkrunfw.dll"
    ;;
*-puddle.*/linux)
    commit=$(pinned "$tag" source-commit)
    fetch "$upstream_repo" "$release" "libkrunfw-linux-$arch.so" "$dest/libkrunfw.so.5"
    build=${MSB_BUILD_DIR:-$dest/../msb-build}
    built=$build/msb-$commit
    if [ -x "$built" ]; then
        echo "fetch-msb: reusing $built (built from $commit earlier)" >&2
    else
        src=$build/microsandbox-$commit
        [ -d "$src" ] || git clone --quiet --depth 1 --branch "$tag" "https://github.com/$fork_repo" "$src"
        head=$(git -C "$src" rev-parse HEAD)
        if [ "$head" != "$commit" ]; then
            echo "fetch-msb: $fork_repo $tag in $src is $head, pinned $commit (the tag moved?)" >&2
            exit 1
        fi
        mkdir -p "$build/embed"
        fetch "$upstream_repo" "$release" "agentd-$arch" "$build/embed/agentd"
        toolchain=$(awk -F'"' '/^channel/ { print $2 }' "$here/../rust-toolchain.toml")
        # Upstream's Linux steps (release-linux.yml "Build msb"), with the fork's own lock.
        (
            cd "$src"
            MSB_EMBED_ARTIFACTS_DIR="$build/embed" CARGO_TARGET_DIR="$build/target" \
                cargo "+$toolchain" build --locked --release --no-default-features \
                --features embed-binaries,net,ssh -p microsandbox-cli
        )
        cp "$build/target/release/msb" "$built"
    fi
    cp "$built" "$dest/msb"
    # msb loads the firmware from beside itself under the exact name it was built to look for
    # (libkrunfw.so.<LIBKRUNFW_VERSION>); the release asset is only SONAME-named. The version is
    # pinned with the commit, and checked against the source when this run has the checkout.
    fw_version=$(pinned "$tag" libkrunfw-linux-version)
    if [ -f "${src:-/nonexistent}/crates/utils/lib/lib.rs" ] &&
        ! grep -q "LIBKRUNFW_VERSION: &str = \"$fw_version\"" "$src/crates/utils/lib/lib.rs"; then
        echo "fetch-msb: $tag's source does not look for libkrunfw $fw_version (fix libkrunfw-linux-version in ci/msb-runtime.sha256)" >&2
        exit 1
    fi
    versioned=libkrunfw.so.$fw_version
    cp "$dest/libkrunfw.so.5" "$dest/$versioned"
    ;;
*/*)
    archive="microsandbox-$os-$arch.tar.gz"
    fetch "$upstream_repo" "$tag" "$archive" "$dest/$archive"
    tar -xzf "$dest/$archive" -C "$dest"
    ;;
esac

case "$os" in windows) msb=$dest/msb.exe ;; *) msb=$dest/msb ;; esac
version=$("$msb" --version)
echo "fetch-msb: $version" >&2
if [ "$version" != "msb ${tag#v}" ]; then
    echo "fetch-msb: $msb reports '$version', expected 'msb ${tag#v}'" >&2
    exit 1
fi
echo "fetch-msb: $tag ready in $dest" >&2
ls -l "$dest" >&2
