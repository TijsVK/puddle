// SPDX-License-Identifier: GPL-3.0-or-later
//! Where the runtime's parts come from: the fork's GitHub release (msb), upstream's release (the
//! firmware), the fork's source at the tag (commits, firmware source, licences of msb's tree), or a
//! fixture folder with the same parts for tests and offline runs.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde::{Deserialize, Serialize};

use crate::error::{Result, XtaskError};
use crate::inventory::{Inventory, shipped_packages};
use crate::tools::{Cargo, Features, git_command, run};

/// The fork's Windows msb asset (upstream's name, kept by the fork's release job).
pub const MSB_ASSET: &str = "msb-windows-x86_64.exe";
/// Upstream's Windows firmware asset (the fork uses upstream's firmware).
pub const LIBKRUNFW_ASSET: &str = "libkrunfw-windows-x86_64.dll";
/// Every release's checksum list.
pub const CHECKSUMS_ASSET: &str = "checksums.sha256";

/// The msb package and features `msb.exe` is built from (upstream's MSVC release steps).
const MSB_MANIFEST: &str = "crates/cli/Cargo.toml";
const MSB_FEATURES: [&str; 3] = ["embed-binaries", "net", "ssh"];
const MSB_TARGET: &str = "x86_64-pc-windows-msvc";
const LIBKRUNFW_SUBMODULE: &str = "vendor/libkrunfw";

/// Which release an asset comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// The fork's release at the fork tag.
    Fork,
    /// Upstream's release at the base tag.
    Upstream,
}

impl Origin {
    fn dir_name(self) -> &'static str {
        match self {
            Self::Fork => "fork",
            Self::Upstream => "upstream",
        }
    }
}

/// A commit the fork carries on top of upstream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Commit {
    /// Full SHA.
    pub sha: String,
    /// First line of the message.
    pub subject: String,
}

/// The firmware's source, for the written offer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Firmware {
    /// libkrunfw version (`FULL_VERSION` in its Makefile).
    pub libkrunfw_version: String,
    /// Linux kernel version inside it (`KERNEL_VERSION`, without `linux-`).
    pub kernel_version: String,
    /// The libkrunfw repository (`https://github.com/...`).
    pub repo_url: String,
    /// The libkrunfw commit msb's tag pins as a submodule.
    pub commit: String,
}

/// Facts about the fork tag for the NOTICE file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForkFacts {
    /// `owner/name` of the fork.
    pub fork_repo: String,
    /// `owner/name` of upstream.
    pub upstream_repo: String,
    /// The fork tag.
    pub tag: String,
    /// Upstream's tag the fork tag is based on.
    pub upstream_tag: String,
    /// The fork's commits on top of `upstream_tag`, oldest first (Apache-2.0 §4(b) change note).
    pub commits: Vec<Commit>,
    /// The firmware source.
    pub firmware: Firmware,
}

/// A provider of the runtime's parts.
pub trait ReleaseSource {
    /// Puts release asset `name` from `origin` into `dir` and returns its path.
    ///
    /// # Errors
    ///
    /// When the asset can't be fetched.
    fn fetch(&self, origin: Origin, name: &str, dir: &Path) -> Result<PathBuf>;

    /// The fork tag's facts.
    ///
    /// # Errors
    ///
    /// When they can't be gathered.
    fn facts(&self) -> Result<ForkFacts>;

    /// The licence inventory of `msb.exe`'s dependency tree at the fork tag.
    ///
    /// # Errors
    ///
    /// When it can't be built.
    fn msb_inventory(&self) -> Result<Inventory>;
}

/// A folder holding the parts: `fork/<asset>`, `upstream/<asset>`, `facts.json`,
/// `msb-about.json` (cargo-about report) and `msb-tree.txt` (`cargo tree` output, see
/// [`shipped_packages`]).
#[derive(Debug, Clone)]
pub struct DirSource {
    root: PathBuf,
}

impl DirSource {
    /// A source reading from `root`.
    #[must_use]
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    fn read(&self, name: &str) -> Result<String> {
        let path = self.root.join(name);
        std::fs::read_to_string(&path)
            .map_err(|e| XtaskError::io(format!("reading {}", path.display()), e))
    }
}

impl ReleaseSource for DirSource {
    fn fetch(&self, origin: Origin, name: &str, dir: &Path) -> Result<PathBuf> {
        let from = self.root.join(origin.dir_name()).join(name);
        let to = dir.join(name);
        std::fs::copy(&from, &to)
            .map_err(|e| XtaskError::io(format!("copying {}", from.display()), e))?;
        Ok(to)
    }

    fn facts(&self) -> Result<ForkFacts> {
        serde_json::from_str(&self.read("facts.json")?)
            .map_err(|e| XtaskError::parse("facts.json", e))
    }

    fn msb_inventory(&self) -> Result<Inventory> {
        let required = shipped_packages(&self.read("msb-tree.txt")?)?;
        Inventory::new("msb", &self.read("msb-about.json")?, required)
    }
}

/// The real thing: `gh` for releases and the compare API, `git` for the fork's source at the tag,
/// cargo-about on that source.
#[derive(Debug, Clone)]
pub struct GitHubSource {
    /// `owner/name` of the fork.
    pub fork: String,
    /// `owner/name` of upstream.
    pub upstream: String,
    /// The fork tag.
    pub tag: String,
    /// Upstream's base tag.
    pub upstream_tag: String,
    /// Where the fork's source is cloned (reused when present).
    pub work: PathBuf,
    /// The cargo-about config for msb's tree.
    pub about_config: PathBuf,
    /// The cargo to run.
    pub cargo: Cargo,
}

impl GitHubSource {
    fn repo(&self, origin: Origin) -> (&str, &str) {
        match origin {
            Origin::Fork => (&self.fork, &self.tag),
            Origin::Upstream => (&self.upstream, &self.upstream_tag),
        }
    }

    /// The fork's source at the tag, cloned once (shallow).
    fn checkout(&self) -> Result<PathBuf> {
        let src = self.work.join(format!("src-{}", self.tag));
        if !src.join("Cargo.toml").is_file() {
            std::fs::create_dir_all(&self.work)
                .map_err(|e| XtaskError::io(format!("creating {}", self.work.display()), e))?;
            run(git_command()
                .args(["clone", "--quiet", "--depth", "1", "--branch", &self.tag])
                .arg(format!("https://github.com/{}.git", self.fork))
                .arg(&src))?;
        }
        Ok(src)
    }

    fn firmware(src: &Path) -> Result<Firmware> {
        let tree =
            run(git_command()
                .arg("-C")
                .arg(src)
                .args(["ls-tree", "HEAD", LIBKRUNFW_SUBMODULE]))?;
        let commit = parse_submodule_commit(&tree)?;
        let modules = std::fs::read_to_string(src.join(".gitmodules"))
            .map_err(|e| XtaskError::io("reading .gitmodules", e))?;
        let repo_url = parse_submodule_url(&modules, LIBKRUNFW_SUBMODULE)?;
        let slug = github_slug(&repo_url)?;
        let makefile = run(Command::new("gh").args([
            "api",
            "-H",
            "Accept: application/vnd.github.raw",
            &format!("repos/{slug}/contents/Makefile?ref={commit}"),
        ]))?;
        let (libkrunfw_version, kernel_version) = parse_libkrunfw_makefile(&makefile)?;
        Ok(Firmware {
            libkrunfw_version,
            kernel_version,
            repo_url: format!("https://github.com/{slug}"),
            commit,
        })
    }
}

impl ReleaseSource for GitHubSource {
    fn fetch(&self, origin: Origin, name: &str, dir: &Path) -> Result<PathBuf> {
        let (repo, tag) = self.repo(origin);
        run(Command::new("gh")
            .args([
                "release",
                "download",
                tag,
                "--repo",
                repo,
                "--pattern",
                name,
                "--clobber",
                "--dir",
            ])
            .arg(dir))?;
        Ok(dir.join(name))
    }

    fn facts(&self) -> Result<ForkFacts> {
        let compare = run(Command::new("gh").args([
            "api",
            &compare_path(&self.fork, &self.upstream, &self.upstream_tag, &self.tag),
        ]))?;
        let commits = parse_compare(&compare)?;
        let src = self.checkout()?;
        Ok(ForkFacts {
            fork_repo: self.fork.clone(),
            upstream_repo: self.upstream.clone(),
            tag: self.tag.clone(),
            upstream_tag: self.upstream_tag.clone(),
            commits,
            firmware: Self::firmware(&src)?,
        })
    }

    fn msb_inventory(&self) -> Result<Inventory> {
        let manifest = self.checkout()?.join(MSB_MANIFEST);
        let features = Features::Only(MSB_FEATURES.iter().map(ToString::to_string).collect());
        self.cargo.inventory(
            "msb",
            &manifest,
            &self.about_config,
            &features,
            &[MSB_TARGET],
            false,
        )
    }
}

/// The commit of `git ls-tree HEAD <submodule>` output (`160000 commit <sha>\t<path>`).
fn parse_submodule_commit(ls_tree: &str) -> Result<String> {
    let mut fields = ls_tree.split_whitespace();
    match (fields.next(), fields.next(), fields.next()) {
        (Some("160000"), Some("commit"), Some(sha))
            if sha.len() == 40 && sha.bytes().all(|b| b.is_ascii_hexdigit()) =>
        {
            Ok(sha.to_owned())
        }
        _ => Err(XtaskError::parse(
            "git ls-tree",
            format!("{LIBKRUNFW_SUBMODULE} is not a submodule: {ls_tree:?}"),
        )),
    }
}

/// The `url` of the submodule at `path` in a `.gitmodules` file.
fn parse_submodule_url(gitmodules: &str, path: &str) -> Result<String> {
    let mut in_section = false;
    let mut url = None;
    for line in gitmodules.lines().map(str::trim) {
        if line.starts_with('[') {
            if in_section && url.is_some() {
                break;
            }
            in_section = false;
            url = None;
        } else if let Some((key, value)) = line.split_once('=') {
            match key.trim() {
                "path" if value.trim() == path => in_section = true,
                "url" => url = Some(value.trim().to_owned()),
                _ => {}
            }
        }
    }
    url.filter(|_| in_section)
        .ok_or_else(|| XtaskError::parse(".gitmodules", format!("no url for {path}")))
}

/// `owner/name` of a `https://github.com/owner/name(.git)` URL.
fn github_slug(url: &str) -> Result<String> {
    url.strip_prefix("https://github.com/")
        .map(|s| s.trim_end_matches('/').trim_end_matches(".git"))
        .filter(|s| s.split('/').count() == 2 && !s.contains(".."))
        .map(ToOwned::to_owned)
        .ok_or_else(|| {
            XtaskError::parse("submodule url", format!("not a GitHub repository: {url}"))
        })
}

/// `FULL_VERSION` and `KERNEL_VERSION` (without `linux-`) from libkrunfw's Makefile.
fn parse_libkrunfw_makefile(makefile: &str) -> Result<(String, String)> {
    let var = |name: &str| {
        makefile.lines().find_map(|l| {
            let (k, v) = l.split_once('=')?;
            (k.trim() == name).then(|| v.trim().to_owned())
        })
    };
    let missing = |what: &str| XtaskError::parse("libkrunfw Makefile", format!("no {what}"));
    let version = var("FULL_VERSION").ok_or_else(|| missing("FULL_VERSION"))?;
    let kernel = var("KERNEL_VERSION").ok_or_else(|| missing("KERNEL_VERSION"))?;
    let kernel = kernel.strip_prefix("linux-").unwrap_or(&kernel).to_owned();
    Ok((version, kernel))
}

/// The compare API path for the fork's commits on top of upstream's tag. The base names upstream's
/// owner: the fork has upstream's commits but not its tags (`compare/v0.7.7...` on the fork is a
/// 404).
fn compare_path(fork: &str, upstream: &str, upstream_tag: &str, tag: &str) -> String {
    let owner = upstream
        .split_once('/')
        .map_or(upstream, |(owner, _)| owner);
    format!("repos/{fork}/compare/{owner}:{upstream_tag}...{tag}")
}

/// The commits of a GitHub compare API response, oldest first.
fn parse_compare(json: &str) -> Result<Vec<Commit>> {
    #[derive(Deserialize)]
    struct Compare {
        commits: Vec<Entry>,
    }
    #[derive(Deserialize)]
    struct Entry {
        sha: String,
        commit: Message,
    }
    #[derive(Deserialize)]
    struct Message {
        message: String,
    }
    let compare: Compare =
        serde_json::from_str(json).map_err(|e| XtaskError::parse("GitHub compare response", e))?;
    Ok(compare
        .commits
        .into_iter()
        .map(|e| Commit {
            sha: e.sha,
            subject: e
                .commit
                .message
                .lines()
                .next()
                .unwrap_or_default()
                .to_owned(),
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_submodule_commit() {
        let sha = "21f169f7e94798c8916315f8ac6f5999d5b88566";
        assert_eq!(
            parse_submodule_commit(&format!("160000 commit {sha}\tvendor/libkrunfw\n")).unwrap(),
            sha
        );
        assert!(parse_submodule_commit("").is_err());
        assert!(parse_submodule_commit(&format!("100644 blob {sha}\tvendor/libkrunfw")).is_err());
        assert!(parse_submodule_commit("160000 commit abc\tvendor/libkrunfw").is_err());
    }

    #[test]
    fn parses_the_submodule_url() {
        let modules = "[submodule \"vendor/libkrunfw\"]\n\tpath = vendor/libkrunfw\n\turl = https://github.com/superradcompany/libkrunfw.git\n\tbranch = krunfw\n[submodule \"mcp\"]\n\tpath = mcp\n\turl = https://github.com/x/mcp.git\n";
        assert_eq!(
            parse_submodule_url(modules, "vendor/libkrunfw").unwrap(),
            "https://github.com/superradcompany/libkrunfw.git"
        );
        assert_eq!(
            parse_submodule_url(modules, "mcp").unwrap(),
            "https://github.com/x/mcp.git"
        );
        assert!(parse_submodule_url(modules, "other").is_err());
        // url before path in the section still counts
        let reordered = "[submodule \"a\"]\n url = https://github.com/o/a\n path = a\n";
        assert_eq!(
            parse_submodule_url(reordered, "a").unwrap(),
            "https://github.com/o/a"
        );
    }

    #[test]
    fn github_slugs() {
        assert_eq!(github_slug("https://github.com/o/r.git").unwrap(), "o/r");
        assert_eq!(github_slug("https://github.com/o/r/").unwrap(), "o/r");
        assert!(github_slug("git@github.com:o/r.git").is_err());
        assert!(github_slug("https://github.com/o/r/x").is_err());
        assert!(github_slug("https://github.com/../r").is_err());
    }

    #[test]
    fn parses_libkrunfw_makefile() {
        let mk = "KERNEL_VERSION = linux-6.12.109\nKERNEL_REMOTE = x\nABI_VERSION = 5\nFULL_VERSION = 5.6.1\n";
        assert_eq!(
            parse_libkrunfw_makefile(mk).unwrap(),
            ("5.6.1".into(), "6.12.109".into())
        );
        assert!(
            parse_libkrunfw_makefile("FULL_VERSION = 1")
                .unwrap_err()
                .to_string()
                .contains("KERNEL_VERSION")
        );
        assert!(parse_libkrunfw_makefile("KERNEL_VERSION = 1").is_err());
    }

    #[test]
    fn parses_compare_responses() {
        let json = r#"{"commits": [
            {"sha": "aaa", "commit": {"message": "fix(vsock): one\n\nbody"}},
            {"sha": "bbb", "commit": {"message": ""}}
        ]}"#;
        let commits = parse_compare(json).unwrap();
        assert_eq!(
            commits[0],
            Commit {
                sha: "aaa".into(),
                subject: "fix(vsock): one".into()
            }
        );
        assert_eq!(commits[1].subject, "");
        assert!(parse_compare("{}").is_err());
    }

    #[test]
    fn github_source_maps_origins_to_repos() {
        let s = GitHubSource {
            fork: "f/m".into(),
            upstream: "u/m".into(),
            tag: "v1.0.0-puddle.1".into(),
            upstream_tag: "v1.0.0".into(),
            work: PathBuf::from("/w"),
            about_config: PathBuf::from("/c"),
            cargo: Cargo::from_env(true),
        };
        assert_eq!(s.repo(Origin::Fork), ("f/m", "v1.0.0-puddle.1"));
        assert_eq!(s.repo(Origin::Upstream), ("u/m", "v1.0.0"));
    }

    #[test]
    fn the_compare_base_names_upstreams_owner() {
        assert_eq!(
            compare_path(
                "TijsVK/microsandbox",
                "superradcompany/microsandbox",
                "v0.7.7",
                "v0.7.7-puddle.3"
            ),
            "repos/TijsVK/microsandbox/compare/superradcompany:v0.7.7...v0.7.7-puddle.3"
        );
    }
}
