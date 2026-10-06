#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Builds the guest agent (crates/puddle-agent) as a static x86_64 Linux binary: target
# x86_64-unknown-linux-musl, linked with the toolchain's own rust-lld, so it runs in any guest
# image (glibc or musl) and builds the same on a Linux or a Windows host (no C toolchain needed).
# Prints the binary's path on stdout; the VM tests take it from PUDDLE_AGENT_BIN.
# Usage: ci/build-agent.sh [cargo args...]      e.g. ci/build-agent.sh --locked
set -eu

target=x86_64-unknown-linux-musl
cd "$(dirname "$0")/.."
rustup target add "$target" >&2
CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=rust-lld \
    cargo build -p puddle-agent --release --target "$target" "$@" >&2
dir=${CARGO_TARGET_DIR:-target}
bin="$dir/$target/release/puddle-agent"
[ -f "$bin" ] || { echo "build-agent: $bin missing after the build" >&2; exit 1; }
echo "$bin"
