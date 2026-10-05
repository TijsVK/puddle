// SPDX-License-Identifier: GPL-3.0-or-later
//! The dev override can't reach a shipped build: no crate enables it, and a release build with it
//! doesn't compile.
#![expect(
    clippy::unwrap_used,
    reason = "the root helper runs outside #[test] but only in tests"
)]

use std::path::Path;

const FEATURE: &str = "dev-override";

fn workspace_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .unwrap()
}

#[test]
fn no_crate_enables_the_dev_override() {
    let crates = workspace_root().join("crates");
    let own = Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
    let mut checked = 0;
    for entry in std::fs::read_dir(&crates).unwrap() {
        let manifest = entry.unwrap().path().join("Cargo.toml");
        if !manifest.is_file() {
            continue;
        }
        checked += 1;
        let text = std::fs::read_to_string(&manifest).unwrap();
        if manifest == own {
            let default = text.lines().find(|l| l.trim_start().starts_with("default"));
            assert!(
                default.is_none_or(|l| !l.contains(FEATURE)),
                "puddle-runtime's default features include {FEATURE}"
            );
        } else {
            assert!(
                !text.contains(FEATURE),
                "{} mentions {FEATURE}; only developers turn it on, by hand",
                manifest.display()
            );
        }
    }
    assert!(
        checked >= 2,
        "found only {checked} manifests under {}",
        crates.display()
    );
    let root = std::fs::read_to_string(workspace_root().join("Cargo.toml")).unwrap();
    assert!(!root.contains(FEATURE));
}

#[test]
fn a_release_build_with_the_dev_override_does_not_compile() {
    let target = Path::new(env!("CARGO_TARGET_TMPDIR")).join("dev-override-release");
    let out = std::process::Command::new(env!("CARGO"))
        .current_dir(workspace_root())
        .args([
            "check",
            "--offline",
            "--locked",
            "--release",
            "-p",
            "puddle-runtime",
            "--features",
            FEATURE,
            "--message-format",
            "short",
        ])
        .env("CARGO_TARGET_DIR", &target)
        // Coverage instrumentation flags from the outer run would only slow this build down.
        .env_remove("RUSTFLAGS")
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .env_remove("RUSTC_WRAPPER")
        .env_remove("RUSTC_WORKSPACE_WRAPPER")
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "release build with {FEATURE} compiled:\n{stderr}"
    );
    assert!(stderr.contains("development builds only"), "{stderr}");
}
