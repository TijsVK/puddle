// SPDX-License-Identifier: GPL-3.0-or-later
//! Developer and release tasks, run as `cargo xtask <command>` (alias in `.cargo/config.toml`).
//!
//! - `runtime`: assembles the bundled msb runtime folder ([`assemble`]): the fork's `msb.exe` and
//!   upstream's `libkrunfw.dll`, both checksum verified, the embedded msb version checked against
//!   the tag, and `licenses/` with the licence texts, the NOTICE (fork commits, written offer) and
//!   the third-party notices of msb's and puddle's dependency trees.
//! - `notices`: puddle's own third-party notices; `--check` only verifies that every shipped
//!   dependency has a licence entry (a `scripts/check.sh` gate).
//!
//! Needs `cargo-about` (`cargo install cargo-about --locked --features cli`); `runtime` also needs
//! `gh` and `git` unless `--from` points at a folder with the parts ([`source::DirSource`]).
#![forbid(unsafe_code)]

pub mod assemble;
pub mod checksums;
pub mod error;
pub mod inventory;
pub mod notice;
pub mod source;
pub mod tools;

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use puddle_runtime::{BUILT_FOR, RuntimeVersion};

pub use error::{Result, XtaskError};
use inventory::{Inventory, shipped_packages};
use source::{DirSource, GitHubSource, ReleaseSource};
use tools::{Cargo, Features};

/// Command-line help.
pub const USAGE: &str = "\
usage: cargo xtask <command> [options]

commands:
  runtime   assemble the bundled runtime folder
            --out <dir>            output folder (default: <target>/runtime); must not have content
            --tag <tag>            fork tag (default: v<BUILT_FOR>, the version this puddle runs)
            --upstream-tag <tag>   upstream base tag (default: derived from a -puddle.N tag)
            --fork <owner/name>    fork repository (default: TijsVK/microsandbox)
            --upstream <owner/name> upstream repository (default: superradcompany/microsandbox)
            --from <dir>           take the parts from a folder instead of GitHub
            --offline              no network for cargo
  notices   puddle's third-party notices
            --check                only check that every dependency has a licence entry
            --out <file>           output file (default: <target>/THIRD-PARTY-puddle.txt)
            --offline              no network for cargo";

/// The default fork (D-53).
pub const DEFAULT_FORK: &str = "TijsVK/microsandbox";
/// Upstream msb.
pub const DEFAULT_UPSTREAM: &str = "superradcompany/microsandbox";
/// The targets puddle ships binaries for (host on Windows, guest agent on Linux musl) or develops on.
pub const PUDDLE_TARGETS: [&str; 3] = [
    "x86_64-pc-windows-msvc",
    "x86_64-unknown-linux-gnu",
    "x86_64-unknown-linux-musl",
];

/// The workspace root (two levels above this crate).
#[must_use]
pub fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..")
}

fn target_dir() -> PathBuf {
    std::env::var_os("CARGO_TARGET_DIR")
        .map_or_else(|| workspace_root().join("target"), PathBuf::from)
}

/// Parsed options: `--flag value` pairs and bare `--switch`es.
struct Options {
    values: Vec<(String, String)>,
    switches: Vec<String>,
}

impl Options {
    fn parse(args: Vec<String>, value_flags: &[&str], switch_flags: &[&str]) -> Result<Self> {
        let mut values = Vec::new();
        let mut switches = Vec::new();
        let mut it = args.into_iter();
        while let Some(arg) = it.next() {
            if value_flags.contains(&arg.as_str()) {
                let v = it
                    .next()
                    .ok_or_else(|| XtaskError::Usage(format!("{arg} needs a value")))?;
                values.push((arg, v));
            } else if switch_flags.contains(&arg.as_str()) {
                switches.push(arg);
            } else {
                return Err(XtaskError::Usage(format!("unknown argument {arg}")));
            }
        }
        Ok(Self { values, switches })
    }

    fn value(&self, flag: &str) -> Option<&str> {
        self.values
            .iter()
            .rev()
            .find(|(f, _)| f == flag)
            .map(|(_, v)| v.as_str())
    }

    fn has(&self, flag: &str) -> bool {
        self.switches.iter().any(|s| s == flag)
    }
}

/// Runs the command in `args` (without the program name) and returns the line to print.
///
/// # Errors
///
/// [`XtaskError::Usage`] for a bad command line, or the command's error.
pub fn run(args: impl IntoIterator<Item = OsString>) -> Result<String> {
    let mut args: Vec<String> = args
        .into_iter()
        .map(|a| {
            a.into_string()
                .map_err(|a| XtaskError::Usage(format!("argument is not UTF-8: {}", a.display())))
        })
        .collect::<Result<_>>()?;
    if args.is_empty() {
        return Err(XtaskError::Usage("no command".into()));
    }
    let command = args.remove(0);
    match command.as_str() {
        "runtime" => runtime(&Options::parse(
            args,
            &[
                "--out",
                "--tag",
                "--upstream-tag",
                "--fork",
                "--upstream",
                "--from",
            ],
            &["--offline"],
        )?),
        "notices" => notices(&Options::parse(
            args,
            &["--out"],
            &["--check", "--offline"],
        )?),
        "help" | "--help" | "-h" => Ok(USAGE.to_owned()),
        other => Err(XtaskError::Usage(format!("unknown command {other}"))),
    }
}

/// puddle's own inventory, computed with cargo-about.
fn puddle_inventory(cargo: &Cargo) -> Result<Inventory> {
    let root = workspace_root();
    cargo.inventory(
        "puddle",
        &root.join("Cargo.toml"),
        &root.join("about.toml"),
        &Features::All,
        &PUDDLE_TARGETS,
        true,
    )
}

fn notices(opts: &Options) -> Result<String> {
    let inventory = puddle_inventory(&Cargo::from_env(opts.has("--offline")))?;
    inventory.check()?;
    if opts.has("--check") {
        return Ok(format!(
            "notices ok: every shipped dependency has a licence entry ({} licence texts)",
            inventory.groups().len()
        ));
    }
    let out = opts.value("--out").map_or_else(
        || target_dir().join("THIRD-PARTY-puddle.txt"),
        PathBuf::from,
    );
    std::fs::write(
        &out,
        inventory.render("The Rust crates in puddle's own programs, with their licences."),
    )
    .map_err(|e| XtaskError::io(format!("writing {}", out.display()), e))?;
    Ok(format!("wrote {}", out.display()))
}

fn runtime(opts: &Options) -> Result<String> {
    let tag = opts
        .value("--tag")
        .map_or_else(|| format!("v{BUILT_FOR}"), ToOwned::to_owned);
    let expected = tag.strip_prefix('v').unwrap_or(&tag).to_owned();
    let upstream_tag = match opts.value("--upstream-tag") {
        Some(t) => t.to_owned(),
        None => expected
            .parse::<RuntimeVersion>()
            .map_err(|_| {
                XtaskError::Usage(format!("{tag} is not a -puddle.N tag; pass --upstream-tag"))
            })?
            .upstream_tag(),
    };
    let out = opts
        .value("--out")
        .map_or_else(|| target_dir().join("runtime"), PathBuf::from);
    let cargo = Cargo::from_env(opts.has("--offline"));

    let (source, puddle): (Box<dyn ReleaseSource>, Inventory) = if let Some(dir) =
        opts.value("--from")
    {
        let dir = PathBuf::from(dir);
        let puddle = fixture_puddle_inventory(&dir).unwrap_or_else(|| puddle_inventory(&cargo))?;
        (Box::new(DirSource::new(dir)), puddle)
    } else {
        let source = GitHubSource {
            fork: opts.value("--fork").unwrap_or(DEFAULT_FORK).to_owned(),
            upstream: opts
                .value("--upstream")
                .unwrap_or(DEFAULT_UPSTREAM)
                .to_owned(),
            tag,
            upstream_tag,
            work: target_dir().join("xtask-runtime-src"),
            about_config: workspace_root().join("crates/xtask/about/msb.toml"),
            cargo: cargo.clone(),
        };
        (Box::new(source), puddle_inventory(&cargo)?)
    };
    let manifest = assemble::assemble(source.as_ref(), &expected, &puddle, &out)?;
    Ok(format!(
        "runtime {} assembled in {} (msb.exe sha256 {})",
        manifest.version,
        out.display(),
        manifest.msb_sha256
    ))
}

/// A fixture folder may carry puddle's inventory too (`puddle-about.json`, `puddle-tree.txt`),
/// so tests and offline runs don't need cargo-about.
fn fixture_puddle_inventory(dir: &Path) -> Option<Result<Inventory>> {
    let about = std::fs::read_to_string(dir.join("puddle-about.json")).ok()?;
    let tree = std::fs::read_to_string(dir.join("puddle-tree.txt")).ok()?;
    Some(shipped_packages(&tree).and_then(|required| Inventory::new("puddle", &about, required)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<OsString> {
        list.iter().map(OsString::from).collect()
    }

    #[test]
    fn usage_errors() {
        for (input, needle) in [
            (vec![], "no command"),
            (vec!["frobnicate"], "unknown command frobnicate"),
            (vec!["runtime", "--out"], "--out needs a value"),
            (vec!["runtime", "--bogus"], "unknown argument --bogus"),
            (vec!["notices", "--tag", "x"], "unknown argument --tag"),
            (
                vec!["runtime", "--tag", "v0.7.7", "--from", "/nonexistent"],
                "pass --upstream-tag",
            ),
        ] {
            let err = run(args(&input)).unwrap_err();
            assert!(matches!(err, XtaskError::Usage(_)), "{input:?}: {err}");
            let msg = err.to_string();
            assert!(
                msg.contains(needle) && msg.contains("usage: cargo xtask"),
                "{msg}"
            );
        }
        assert!(run(args(&["help"])).unwrap().starts_with("usage:"));
    }

    #[test]
    fn last_value_wins_and_switches_are_seen() {
        let o = Options::parse(
            vec![
                "--out".into(),
                "a".into(),
                "--offline".into(),
                "--out".into(),
                "b".into(),
            ],
            &["--out"],
            &["--offline"],
        )
        .unwrap();
        assert_eq!(o.value("--out"), Some("b"));
        assert!(o.has("--offline"));
        assert!(!o.has("--check"));
        assert_eq!(o.value("--tag"), None);
    }

    #[test]
    fn workspace_root_has_the_workspace_manifest() {
        let text = std::fs::read_to_string(workspace_root().join("Cargo.toml")).unwrap();
        assert!(text.contains("[workspace]"));
        assert!(workspace_root().join("about.toml").is_file());
        assert!(
            workspace_root()
                .join("crates/xtask/about/msb.toml")
                .is_file()
        );
    }
}
