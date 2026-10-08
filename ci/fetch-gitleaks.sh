#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Puts the pinned gitleaks release for this host in <dest-dir> (gitleaks, or gitleaks.exe on
# Windows); the secrets gate (scripts/check-secrets.sh) needs it on PATH. The download must match
# the SHA-256 pinned in ci/gitleaks.sha256. Usage: ci/fetch-gitleaks.sh <dest-dir>
# Works in Linux sh, macOS sh and Git Bash on Windows. Network failures are retried
# (infrastructure) and each retry is printed; a checksum mismatch never is.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
[ "$#" -eq 1 ] || { echo "usage: $0 <dest-dir>" >&2; exit 2; }
dest=$1

case "$(uname -m)" in
x86_64 | amd64) arch=x64 ;;
arm64 | aarch64) arch=arm64 ;;
*) echo "fetch-gitleaks: unsupported arch $(uname -m)" >&2; exit 2 ;;
esac
case "$(uname -s)" in
Linux) os=linux ext=tar.gz exe=gitleaks ;;
Darwin) os=darwin ext=tar.gz exe=gitleaks ;;
MINGW* | MSYS* | CYGWIN*) os=windows ext=zip exe=gitleaks.exe ;;
*) echo "fetch-gitleaks: unsupported host $(uname -s)" >&2; exit 2 ;;
esac

# The pinned line for this host: `<version> <asset> <sha256>`.
line=$(awk -v s="_${os}_${arch}.${ext}" '!/^#/ && index($2, s) { print; exit }' "$here/gitleaks.sha256")
[ -n "$line" ] || { echo "fetch-gitleaks: nothing pinned for ${os}_${arch} in ci/gitleaks.sha256" >&2; exit 1; }
version=${line%% *}
rest=${line#* }
asset=${rest%% *}
want=${rest##* }

mkdir -p "$dest"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
url="https://github.com/gitleaks/gitleaks/releases/download/v$version/$asset"
attempt=1
until curl -fsSL --connect-timeout 20 --max-time 300 -o "$work/$asset" "$url"; do
    [ "$attempt" -lt 3 ] || { echo "fetch-gitleaks: download failed 3 times: $url" >&2; exit 1; }
    echo "fetch-gitleaks: download attempt $attempt failed, retrying (infrastructure retry)" >&2
    attempt=$((attempt + 1))
    sleep 5
done
# Hash from stdin: for a path with backslashes, Git Bash's sha256sum puts a backslash before the hash.
got=$(sha256sum < "$work/$asset" | cut -d' ' -f1)
if [ "$got" != "$want" ]; then
    echo "fetch-gitleaks: checksum mismatch for $asset: got $got, pinned $want" >&2
    exit 1
fi
if [ "$ext" = zip ]; then
    # Git for Windows may lack unzip; Windows PowerShell always has Expand-Archive.
    if command -v unzip >/dev/null 2>&1; then
        unzip -q -o "$work/$asset" "$exe" -d "$dest"
    else
        powershell.exe -NoProfile -Command "Expand-Archive -Force -LiteralPath '$(cygpath -w "$work/$asset")' -DestinationPath '$(cygpath -w "$work")\\x'"
        cp "$work/x/$exe" "$dest/$exe"
    fi
else
    tar -xzf "$work/$asset" -C "$dest" "$exe"
fi
chmod +x "$dest/$exe"
echo "fetch-gitleaks: $asset verified ($got), installed $dest/$exe" >&2
