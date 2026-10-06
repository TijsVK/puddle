// SPDX-License-Identifier: GPL-3.0-or-later
//! Reads the msb runtime version this build of puddle runs from the workspace `Cargo.lock`: the
//! version of the `microsandbox` SDK package, which the root `Cargo.toml` takes from the fork tag
//! `v<version>` (D-19: the SDK and the bundled runtime move together, so the tag there is the only
//! place the version is written). Fails the build when the SDK doesn't come from that fork tag, or
//! when the SDK's crates resolve to more than one source (a half-done bump).

#![expect(
    clippy::exit,
    reason = "a build script stops the build with an exit code"
)]

use std::path::Path;

/// The fork every `microsandbox*` package must come from.
const FORK: &str = "git+https://github.com/TijsVK/microsandbox?tag=v";

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

/// The `microsandbox` package's version, checked against its fork tag and its sibling crates.
fn built_for(lock: &str) -> Result<String, String> {
    let mut sdk = None;
    let mut sources = Vec::new();
    for package in lock.split("[[package]]").skip(1) {
        let field = |key: &str| {
            package.lines().find_map(|line| {
                line.strip_prefix(key)
                    .and_then(|rest| rest.strip_prefix(" = \""))
                    .and_then(|rest| rest.strip_suffix('"'))
            })
        };
        let (Some(name), Some(version)) = (field("name"), field("version")) else {
            continue;
        };
        if !name.starts_with("microsandbox") {
            continue;
        }
        let source = field("source").unwrap_or("(path)");
        sources.push(format!("{name} {version} {source}"));
        if name == "microsandbox" {
            sdk = Some((version, source));
        }
    }
    let (version, source) = sdk.ok_or("no `microsandbox` package in Cargo.lock")?;
    let tag = source
        .strip_prefix(FORK)
        .and_then(|rest| rest.split_once('#'))
        .map(|(tag, _)| tag)
        .ok_or_else(|| format!("the msb SDK must come from {FORK}<version>, not {source}"))?;
    if tag != version {
        return Err(format!(
            "the msb SDK's fork tag v{tag} doesn't match its package version {version}"
        ));
    }
    let odd: Vec<_> = sources
        .iter()
        .filter(|line| !line.ends_with(source) || !line.contains(&format!(" {version} ")))
        .collect();
    if !odd.is_empty() {
        return Err(format!(
            "every microsandbox crate must come from {source}; these don't: {odd:?}"
        ));
    }
    Ok(version.to_owned())
}
