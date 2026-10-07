#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Builds the guest agent (crates/puddle-agent) as a static Linux binary, linked with the toolchain's
# own rust-lld so it runs in any guest image (glibc or musl) and builds the same on a Linux or a
# Windows host (no C toolchain needed). The guest architecture is the host's (msb runs guests of
# its own architecture): PUDDLE_GUEST_ARCH selects it, default x86_64, the only one built and
# tested today. The targets repeat puddle_runtime::GuestArch::agent_target (a unit test keeps the
# two equal).
# Prints the binary's path on stdout; the VM tests take it from PUDDLE_AGENT_BIN.
# Usage: [PUDDLE_GUEST_ARCH=x86_64|aarch64] ci/build-agent.sh [cargo args...]   e.g. ci/build-agent.sh --locked
set -eu

case "${PUDDLE_GUEST_ARCH:-x86_64}" in
x86_64) target=x86_64-unknown-linux-musl ;;
aarch64) target=aarch64-unknown-linux-musl ;;
*)
    echo "build-agent: unknown guest architecture '${PUDDLE_GUEST_ARCH}' (x86_64 or aarch64)" >&2
    exit 1
    ;;
esac
cd "$(dirname "$0")/.."
rustup target add "$target" >&2
linker_var="CARGO_TARGET_$(echo "$target" | tr 'a-z-' 'A-Z_')_LINKER"
env "$linker_var=rust-lld" cargo build -p puddle-agent --release --target "$target" "$@" >&2
dir=${CARGO_TARGET_DIR:-target}
bin="$dir/$target/release/puddle-agent"
[ -f "$bin" ] || { echo "build-agent: $bin missing after the build" >&2; exit 1; }
echo "$bin"
