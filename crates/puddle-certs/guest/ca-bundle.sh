#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
#
# puddle's guest CA bundle (T-110): the image's own CA bundle with puddle's extra CAs appended
# (the host's corporate and user-added roots, puddle's own CAs), every certificate once.
# SSL_CERT_FILE, REQUESTS_CA_BUNDLE and CURL_CA_BUNDLE point at the result, so tools that take
# a bundle path keep the distro roots: append, never replace (T-026 §2b).
#
# boot.sh runs this as a plan step at every boot, after update-ca-certificates (which has then
# already added the extra CAs to the system bundle; they are not added twice). The bundle file is
# rewritten only when its contents change. POSIX sh; needs awk to drop duplicates (without awk
# the bundle is still complete, only possibly with a certificate twice).
#
# PUDDLE_ROOT relocates every path, for the unit tests only (boot.sh passes it on empty).
set -eu

ROOT=${PUDDLE_ROOT:-}
EXTRA=$ROOT/etc/puddle/extra-cas.pem
OUT=$ROOT/etc/puddle/ca-bundle.pem

[ -f "$EXTRA" ] || {
    echo "ca-bundle: ${EXTRA#"$ROOT"} is missing" >&2
    exit 1
}
[ ! -d "$OUT" ] || {
    echo "ca-bundle: ${OUT#"$ROOT"} is a directory" >&2
    exit 1
}

# The image's bundle: Debian/Ubuntu/Alpine/Arch, Fedora/RHEL, openSUSE, then the generic ones.
distro=
for f in /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt \
    /etc/ssl/ca-bundle.pem /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem /etc/ssl/cert.pem; do
    if [ -f "$ROOT$f" ] && [ -r "$ROOT$f" ]; then
        distro=$ROOT$f
        break
    fi
done

tmp=$OUT.new.$$
trap 'rm -f "$tmp"' EXIT
if command -v awk >/dev/null 2>&1; then
    # Every PEM certificate once (compared without whitespace or CR), in input order; text
    # outside certificates (comments in some distro bundles) is left out.
    awk '
        { sub(/\r$/, "") }
        /^-----BEGIN CERTIFICATE-----/ { inside = 1; block = $0 "\n"; key = ""; next }
        inside {
            block = block $0 "\n"
            if ($0 ~ /^-----END CERTIFICATE-----/) {
                inside = 0
                if (!(key in seen)) { seen[key] = 1; printf "%s", block }
            } else {
                line = $0
                gsub(/[ \t]/, "", line)
                key = key line
            }
        }
    ' ${distro:+"$distro"} "$EXTRA" >"$tmp"
else
    cat ${distro:+"$distro"} "$EXTRA" >"$tmp"
fi
chmod 0644 "$tmp"

from=${distro:+ with ${distro#"$ROOT"}}
if [ -f "$OUT" ] && command -v cmp >/dev/null 2>&1 && cmp -s "$tmp" "$OUT"; then
    echo "bundle unchanged${from:- (no distro bundle)}"
    exit 0
fi
mv -f "$tmp" "$OUT"
echo "bundle updated, $(grep -c -- '-----BEGIN CERTIFICATE-----' "$OUT") certificates${from:- (no distro bundle)}"
