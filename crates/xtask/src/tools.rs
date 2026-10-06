// SPDX-License-Identifier: GPL-3.0-or-later
//! Running the external tools xtask drives: cargo (tree, cargo-about), gh and git.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::path::Path;
use std::process::Command;

use crate::error::{Result, XtaskError};
use crate::inventory::{Inventory, Package, shipped_packages};

/// Runs `command` and returns its stdout.
///
/// # Errors
///
/// [`XtaskError::Tool`] when it can't start or exits non-zero (with the end of its stderr).
pub fn run(command: &mut Command) -> Result<String> {
    let shown = format!(
        "{} {}",
        command.get_program().to_string_lossy(),
        command
            .get_args()
            .map(|a| a.to_string_lossy())
            .collect::<Vec<_>>()
            .join(" ")
    );
    let out = command.output().map_err(|e| XtaskError::Tool {
        command: shown.clone(),
        detail: format!("cannot start: {e}"),
    })?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        let tail: String = {
            let chars: Vec<char> = stderr.trim_end().chars().collect();
            chars
                .iter()
                .skip(chars.len().saturating_sub(2000))
                .collect()
        };
        return Err(XtaskError::Tool {
            command: shown,
            detail: format!("{}\n{tail}", out.status),
        });
    }
    String::from_utf8(out.stdout).map_err(|e| XtaskError::parse(format!("output of `{shown}`"), e))
}

/// Which features a cargo tree is resolved with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Features {
    /// `--all-features`.
    All,
    /// `--no-default-features --features <list>`.
    Only(Vec<String>),
}

impl Features {
    fn args(&self) -> Vec<String> {
        match self {
            Self::All => vec!["--all-features".into()],
            Self::Only(list) => vec![
                "--no-default-features".into(),
                "--features".into(),
                list.join(" "),
            ],
        }
    }
}

/// The cargo to run: `$CARGO` (set when xtask runs under `cargo run`) or `cargo`.
#[derive(Debug, Clone)]
pub struct Cargo {
    program: OsString,
    offline: bool,
}

impl Cargo {
    /// The cargo from the environment; `offline` adds `--offline` to every call.
    #[must_use]
    pub fn from_env(offline: bool) -> Self {
        Self {
            program: std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into()),
            offline,
        }
    }

    fn command(&self) -> Command {
        Command::new(&self.program)
    }

    fn common(&self, cmd: &mut Command, manifest: &Path, features: &Features) {
        cmd.arg("--manifest-path")
            .arg(manifest)
            .args(features.args())
            .arg("--locked");
        if self.offline {
            cmd.arg("--offline");
        }
    }

    /// The packages the tree at `manifest` ships on any of `targets` ([`shipped_packages`]):
    /// the whole workspace when `workspace`, else the manifest's package.
    ///
    /// # Errors
    ///
    /// [`XtaskError::Tool`] or [`XtaskError::Parse`].
    pub fn shipped(
        &self,
        manifest: &Path,
        features: &Features,
        targets: &[&str],
        workspace: bool,
    ) -> Result<BTreeSet<Package>> {
        let mut all = BTreeSet::new();
        for target in targets {
            let mut cmd = self.command();
            cmd.args([
                "tree", "--edges", "normal", "--prefix", "none", "--format", "{p}", "--target",
                target,
            ]);
            if workspace {
                cmd.arg("--workspace");
            }
            self.common(&mut cmd, manifest, features);
            all.extend(shipped_packages(&run(&mut cmd)?)?);
        }
        Ok(all)
    }

    /// cargo-about's JSON report for the tree at `manifest`, with the config at `config`.
    ///
    /// # Errors
    ///
    /// [`XtaskError::Tool`] (cargo-about missing: `cargo install cargo-about --locked --features cli`).
    pub fn about(&self, manifest: &Path, config: &Path, features: &Features) -> Result<String> {
        let mut cmd = self.command();
        cmd.args(["about", "generate", "--format", "json", "--config"])
            .arg(config);
        self.common(&mut cmd, manifest, features);
        run(&mut cmd)
    }

    /// The checked inventory of a tree: cargo-about's report plus the shipped packages.
    ///
    /// # Errors
    ///
    /// As [`Cargo::shipped`] and [`Cargo::about`].
    pub fn inventory(
        &self,
        tree: &str,
        manifest: &Path,
        config: &Path,
        features: &Features,
        targets: &[&str],
        workspace: bool,
    ) -> Result<Inventory> {
        let required = self.shipped(manifest, features, targets, workspace)?;
        Inventory::new(tree, &self.about(manifest, config, features)?, required)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn feature_args() {
        assert_eq!(Features::All.args(), ["--all-features"]);
        assert_eq!(
            Features::Only(vec!["a".into(), "b".into()]).args(),
            ["--no-default-features", "--features", "a b"]
        );
    }

    #[test]
    fn run_reports_failures_and_missing_programs() {
        let err = run(&mut Command::new("/nonexistent/xtask-tool"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("cannot start"), "{err}");
        let cargo = Cargo::from_env(true);
        let err =
            run(cargo
                .command()
                .args(["metadata", "--manifest-path", "/nonexistent/Cargo.toml"]))
            .unwrap_err()
            .to_string();
        assert!(err.contains("failed"), "{err}");
        let ok = run(cargo.command().arg("--version")).unwrap();
        assert!(ok.starts_with("cargo "), "{ok}");
    }

    #[test]
    fn shipped_reads_this_workspace() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../Cargo.toml");
        let shipped = Cargo::from_env(true)
            .shipped(&root, &Features::All, &["x86_64-unknown-linux-gnu"], true)
            .unwrap();
        assert!(shipped.iter().any(|p| p.name == "thiserror"));
        assert!(
            shipped.iter().all(|p| !p.name.starts_with("puddle")),
            "own crates are local"
        );
    }

    #[test]
    fn dev_only_features_do_not_ship() {
        // object's `write` feature is only turned on by puddle-runtime's dev-dependencies: its
        // extra deps don't ship. Checked on that one package: elsewhere in the workspace the msb
        // SDK (puddle-vm-tests) needs crc32fast on its own.
        let manifest = Path::new(env!("CARGO_MANIFEST_DIR")).join("../puddle-runtime/Cargo.toml");
        let shipped = Cargo::from_env(true)
            .shipped(
                &manifest,
                &Features::All,
                &["x86_64-unknown-linux-gnu"],
                false,
            )
            .unwrap();
        assert!(shipped.iter().any(|p| p.name == "object"));
        assert!(shipped.iter().all(|p| p.name != "crc32fast"));
    }
}
