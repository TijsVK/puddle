// SPDX-License-Identifier: GPL-3.0-or-later
//! Reads the msb runtime version this build of puddle runs from the workspace `Cargo.lock`: the
//! version of the `microsandbox` SDK package, which the root `Cargo.toml` takes from the fork tag
//! `v<version>` (the SDK and the bundled runtime move together, so the tag there is the only
//! place the version is written). Fails the build when the SDK doesn't come from that fork tag, or
//! when the SDK's crates resolve to more than one source (a half-done bump).

#![expect(
    clippy::exit,
    reason = "a build script stops the build with an exit code"
)]

use std::path::Path;

#[path = "build/built_for.rs"]
mod built_for;

use built_for::built_for;

fn main() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_default();
    let lock_path = Path::new(&manifest_dir).join("../../Cargo.lock");
    println!("cargo::rerun-if-changed={}", lock_path.display());
    let lock = std::fs::read_to_string(&lock_path).unwrap_or_else(|e| {
        fail(&format!(
            "cannot read the workspace lock file {}: {e}",
            lock_path.display()
        ))
    });
    match built_for(&lock) {
        Ok(version) => println!("cargo::rustc-env=PUDDLE_MSB_BUILT_FOR={version}"),
        Err(message) => fail(&message),
    }
}

fn fail(message: &str) -> ! {
    println!("cargo::error=puddle-runtime: {message}");
    std::process::exit(1)
}
