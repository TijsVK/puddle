// SPDX-License-Identifier: GPL-3.0-or-later
//! The build script's `BUILT_FOR` check (`build/built_for.rs`): the version comes from the msb
//! SDK's fork tag in `Cargo.lock`, and a lock that mixes sources or isn't on the fork fails.

#[path = "../build/built_for.rs"]
mod built_for;

use built_for::built_for;

const TAG: &str = "git+https://github.com/TijsVK/microsandbox?tag=v0.7.7-puddle.3#7e3e0b2b4611cd6f4cfa2c82b58cee650eff03a7";

fn package(name: &str, version: &str, source: Option<&str>) -> String {
    let source = source.map_or_else(String::new, |s| format!("source = \"{s}\"\n"));
    format!("[[package]]\nname = \"{name}\"\nversion = \"{version}\"\n{source}\n")
}

fn lock(packages: &[String]) -> String {
    format!("version = 4\n\n{}", packages.concat())
}

#[test]
fn the_version_is_the_sdk_package_version_on_its_fork_tag() {
    let lock = lock(&[
        package(
            "anyhow",
            "1.0.0",
            Some("registry+https://github.com/rust-lang/crates.io-index"),
        ),
        package("microsandbox", "0.7.7-puddle.3", Some(TAG)),
        package("microsandbox-image", "0.7.7-puddle.3", Some(TAG)),
        package("puddle-runtime", "0.1.0", None),
    ]);
    assert_eq!(built_for(&lock).as_deref(), Ok("0.7.7-puddle.3"));
}

#[test]
fn the_workspace_lock_names_the_built_for_version() {
    let lock = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../Cargo.lock"))
        .expect("workspace Cargo.lock");
    assert_eq!(built_for(&lock).as_deref(), Ok(puddle_runtime::BUILT_FOR));
}

#[test]
fn a_lock_without_the_sdk_fails() {
    let lock = lock(&[package("anyhow", "1.0.0", None)]);
    let err = built_for(&lock).unwrap_err();
    assert!(err.contains("no `microsandbox` package"), "{err}");
}

#[test]
fn an_sdk_from_crates_io_fails() {
    let lock = lock(&[package(
        "microsandbox",
        "0.7.7",
        Some("registry+https://github.com/rust-lang/crates.io-index"),
    )]);
    let err = built_for(&lock).unwrap_err();
    assert!(err.contains("must come from"), "{err}");
}

#[test]
fn an_sdk_from_a_fork_branch_fails() {
    let lock = lock(&[package(
        "microsandbox",
        "0.7.7-puddle.3",
        Some("git+https://github.com/TijsVK/microsandbox?branch=puddle#7e3e0b2b"),
    )]);
    let err = built_for(&lock).unwrap_err();
    assert!(err.contains("must come from"), "{err}");
}

#[test]
fn a_tag_that_disagrees_with_the_package_version_fails() {
    let lock = lock(&[package("microsandbox", "0.7.7-puddle.2", Some(TAG))]);
    let err = built_for(&lock).unwrap_err();
    assert!(err.contains("doesn't match"), "{err}");
}

#[test]
fn a_half_done_bump_fails_and_names_the_odd_crate() {
    let lock = lock(&[
        package("microsandbox", "0.7.7-puddle.3", Some(TAG)),
        package(
            "microsandbox-image",
            "0.7.7",
            Some("registry+https://github.com/rust-lang/crates.io-index"),
        ),
    ]);
    let err = built_for(&lock).unwrap_err();
    assert!(err.contains("microsandbox-image 0.7.7"), "{err}");
}

#[test]
fn packages_without_a_name_or_version_are_skipped() {
    let lock = format!(
        "[[package]]\nname = \"half\"\n\n{}",
        package("microsandbox", "0.7.7-puddle.3", Some(TAG))
    );
    assert_eq!(built_for(&lock).as_deref(), Ok("0.7.7-puddle.3"));
}
