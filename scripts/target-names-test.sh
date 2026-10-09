#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Checks that no target of a workspace crate (an integration test, bin, example or bench) is named
# like a dependency from the registry or git. `cargo llvm-cov` clears the workspace's old build
# output before each run by file name (`deps/<target>-*`, `deps/lib<target>-*`), so a test target
# `http` also cleared the `http` crate's build, and every crate that depends on it (hyper, axum,
# reqwest, tonic, tauri, microsandbox, 29 to 47 crates) was compiled again on every coverage run.
# Names are compared with `-` and `_` treated as the same, because that is how the files are named.
# Not seen: a target whose name comes from a path cargo discovers outside the layouts below
# (`[[test]] path = ...` is found by its `name`), and a target of a crate outside `crates/`.
# usage: scripts/target-names-test.sh [root]   (default: the repository; `--self-test` checks the check)
set -eu

# Prints "<name>" for every workspace target and "-" for every dependency, one per line, normalised.
collisions() { # collisions <root>
    root=$1
    {
        # The workspace's own packages: not dependencies, and a target may share their name.
        for toml in "$root"/crates/*/Cargo.toml; do
            [ -f "$toml" ] || continue
            awk '/^\[package\]/ { p = 1; next } /^\[/ { p = 0 } p && $1 == "name" { gsub(/"/, "", $3); print "P " $3 }' "$toml"
            # Explicit targets.
            awk '/^\[\[(test|bin|example|bench)\]\]/ { t = 1; next } /^\[/ { t = 0 } t && $1 == "name" { gsub(/"/, "", $3); print "T " $3 }' "$toml"
            dir=$(dirname "$toml")
            for f in "$dir"/tests/*.rs "$dir"/src/bin/*.rs "$dir"/examples/*.rs "$dir"/benches/*.rs; do
                [ -f "$f" ] || continue
                b=$(basename "$f" .rs)
                [ "$b" = main ] || echo "T $b"
            done
            for d in "$dir"/tests/*/ "$dir"/src/bin/*/ "$dir"/examples/*/ "$dir"/benches/*/; do
                [ -f "${d}main.rs" ] && echo "T $(basename "$d")"
            done
        done
        awk '$1 == "name" { gsub(/"/, "", $3); print "L " $3 }' "$root/Cargo.lock"
    } | tr - _ | awk '
        $1 == "P" { own[$2] = 1 }
        $1 == "T" { targets[$2] = 1 }
        $1 == "L" { lock[$2] = 1 }
        END { for (t in targets) if ((t in lock) && !(t in own)) print t }' | sort
}

if [ "${1:-}" = --self-test ]; then
    tmp=$(mktemp -d "${TMPDIR:-/tmp}/target-names-test.XXXXXX")
    trap 'rm -rf "$tmp"' EXIT
    mkdir -p "$tmp/crates/a/tests/http" "$tmp/crates/a/src/bin" "$tmp/crates/b/tests"
    printf '[package]\nname = "a"\n[[test]]\nname = "tauri"\npath = "x.rs"\n' >"$tmp/crates/a/Cargo.toml"
    printf '[package]\nname = "b-b"\n' >"$tmp/crates/b/Cargo.toml"
    : >"$tmp/crates/a/tests/http/main.rs"
    : >"$tmp/crates/a/src/bin/serde-json.rs"
    : >"$tmp/crates/b/tests/fine.rs"
    printf 'name = "a"\nname = "b-b"\nname = "http"\nname = "tauri"\nname = "serde_json"\nname = "http-body"\n' >"$tmp/Cargo.lock"
    got=$(collisions "$tmp" | tr '\n' ' ')
    [ "$got" = "http serde_json tauri " ] || {
        echo "target-names-test: the self-test found '$got', expected 'http serde_json tauri '" >&2
        exit 1
    }
    # A target named like one of the workspace's own packages is no collision.
    printf 'name = "a"\nname = "b-b"\n' >"$tmp/Cargo.lock"
    mkdir -p "$tmp/crates/b/tests"
    : >"$tmp/crates/b/tests/a.rs"
    [ -z "$(collisions "$tmp")" ] || {
        echo "target-names-test: the self-test flagged a target that shares its own package's name" >&2
        exit 1
    }
    exit 0
fi

root=${1:-$(cd "$(dirname "$0")/.." && pwd)}
found=$(collisions "$root")
if [ -n "$found" ]; then
    echo "target-names-test: a workspace target is named like a dependency:" >&2
    echo "$found" | sed 's/^/  /' >&2
    echo "  cargo llvm-cov deletes build output by target name (deps/<name>-*), so the dependency is rebuilt on every coverage run." >&2
    echo "  Rename the target (a test file or directory under tests/)." >&2
    exit 1
fi
echo "target-names-test: no workspace target shares a dependency's name"
