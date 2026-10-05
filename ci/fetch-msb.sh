#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Downloads msb's runtime archive (msb + libkrunfw) for this host, checks it against the pinned
# SHA-256 in ci/msb-runtime.sha256 and unpacks it, for the VM tests (PUDDLE_VM_RUNTIME_DIR).
# Usage: ci/fetch-msb.sh <tag> <dest-dir>     e.g. ci/fetch-msb.sh v0.7.7 "$RUNNER_TEMP/msb"
# Works in Linux sh and in Git Bash on Windows. Network failures are retried (infrastructure,
# T-032) and each retry is printed; a checksum mismatch never is.
set -eu

[ "$#" -eq 2 ] || { echo "usage: $0 <tag> <dest-dir>" >&2; exit 2; }
tag=$1
dest=$2
repo=${MSB_RELEASE_REPO:-superradcompany/microsandbox}
here=$(cd "$(dirname "$0")" && pwd)

case "$(uname -s)" in
Linux) os=linux ;;
MINGW* | MSYS* | CYGWIN*) os=windows ;;
*) echo "fetch-msb: unsupported host $(uname -s)" >&2; exit 2 ;;
esac
case "$(uname -m)" in
x86_64 | amd64) arch=x86_64 ;;
*) echo "fetch-msb: unsupported arch $(uname -m)" >&2; exit 2 ;;
esac
archive="microsandbox-$os-$arch.tar.gz"

want=$(awk -v t="$tag" -v a="$archive" '$1 == t && $2 == a { print $3 }' "$here/msb-runtime.sha256")
[ -n "$want" ] || {
    echo "fetch-msb: no pinned checksum for $tag $archive in ci/msb-runtime.sha256" >&2
    exit 1
}

mkdir -p "$dest"
url="https://github.com/$repo/releases/download/$tag/$archive"
attempt=1
until curl -fsSL --connect-timeout 20 --max-time 300 -o "$dest/$archive" "$url"; do
    [ "$attempt" -lt 3 ] || { echo "fetch-msb: download failed 3 times: $url" >&2; exit 1; }
    echo "fetch-msb: download attempt $attempt failed, retrying (infrastructure retry)" >&2
    attempt=$((attempt + 1))
    sleep 5
done

# Hash from stdin: for a path with backslashes, Git Bash's sha256sum puts a backslash before the hash.
got=$(sha256sum < "$dest/$archive" | cut -d' ' -f1)
if [ "$got" != "$want" ]; then
    echo "fetch-msb: checksum mismatch for $archive: got $got, pinned $want" >&2
    exit 1
fi
tar -xzf "$dest/$archive" -C "$dest"
echo "fetch-msb: $tag $archive verified and unpacked in $dest" >&2
ls -l "$dest" >&2
