// SPDX-License-Identifier: GPL-3.0-or-later
//! The boot plan: everything one run of `boot.sh` applies, rendered as the shell fragment it
//! reads on stdin.
//!
//! The hook holds no provider logic. Providers (proxy config, corporate roots, the
//! per-sandbox CA) hand over [`GuestFile`]s and a [`GuestEnv`]; the plan adds puddle's own files
//! (the image `PATH` fix, the env file for login shells, the git settings and VS Code's Machine
//! settings) and the image's ENTRYPOINT, and checks that no two of them claim the same path.

use std::collections::BTreeSet;
use std::time::Duration;

use puddle_compute::{ExecRequest, ImageConfig};
use puddle_types::{ApplyKind, GuestEnv, GuestFile, GuestPath};

use crate::assets::{AGENT_GUEST, BOOT_SH_GUEST, MOUNT_DIR_GUEST, guest_path};
use crate::machine::machine_settings;
use crate::quote::{printf_format, sh_word};

/// The plan's first line; `boot.sh` refuses any other.
pub const PLAN_HEADER: &str = "# puddle-boot-plan 1";

/// Restores the image's `ENV PATH` in login shells, which Debian's `/etc/profile` resets.
pub const PATH_FILE_GUEST: &str = "/etc/profile.d/00-puddle-path.sh";

/// The provider environment, for login shells and the chained ENTRYPOINT.
pub const ENV_FILE_GUEST: &str = "/etc/profile.d/01-puddle-env.sh";

/// puddle's git settings, included from `/etc/gitconfig`.
pub const GIT_CONFIG_GUEST: &str = "/etc/puddle/gitconfig";

/// The directory of the per-rule author files [`GitAuthorRule`] writes, next to
/// [`GIT_CONFIG_GUEST`] (which includes them by relative path).
pub const GIT_AUTHOR_DIR_GUEST: &str = "/etc/puddle";

/// The most author rules a plan holds.
pub const MAX_GIT_AUTHOR_RULES: usize = 64;

/// The most remote globs one author rule holds.
pub const MAX_GIT_AUTHOR_GLOBS: usize = 32;

/// When a file below this directory changes, the hook runs `update-ca-certificates`; when none
/// did, it skips it (it costs 0.6–0.9 s per boot).
pub const CA_DIR_GUEST: &str = "/usr/local/share/ca-certificates";

/// The port `puddle-agent` listens on in the guest (the proxy address in `HTTP(S)_PROXY`).
pub const DEFAULT_AGENT_PORT: u16 = 3128;

/// Env names the hook keeps for itself.
const RESERVED_ENV_PREFIX: &str = "PUDDLE_";

const GENERATED: &str = "# Written by puddle at every boot; changes here are overwritten.\n";

/// Why a plan can't be built. Every variant names the offending item.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PlanError {
    /// Two files (from providers or puddle) claim the same guest path.
    #[error("two boot files claim {path}")]
    DuplicatePath {
        /// The path.
        path: String,
    },
    /// A file would land below puddle's read-only mounts.
    #[error("boot file {path} is below {MOUNT_DIR_GUEST}, which holds puddle's read-only mounts")]
    ReservedPath {
        /// The path.
        path: String,
    },
    /// A path contains a control character, which the hook's file list can't hold.
    #[error("boot file path {path:?} contains a control character")]
    UnsafePath {
        /// The path.
        path: String,
    },
    /// A provider env name is reserved for the hook.
    #[error("environment variable {name} is reserved for puddle's boot hook")]
    ReservedEnv {
        /// The name.
        name: String,
    },
    /// The git identity can't be written to a git config file.
    #[error("git {field} {reason}")]
    GitIdentity {
        /// `user.name` or `user.email`.
        field: &'static str,
        /// What is wrong.
        reason: &'static str,
    },
    /// An author rule can't be written to a git config file.
    #[error("git author rule {reason}")]
    GitAuthorRule {
        /// What is wrong.
        reason: &'static str,
    },
    /// A file asks for an [`ApplyKind`] this hook doesn't know.
    #[error("boot file {path} has an apply kind this boot hook can't apply")]
    UnknownApplyKind {
        /// The path.
        path: String,
    },
    /// A value from the image can't be passed on.
    #[error("the image's {what} contains a NUL or newline")]
    ImageValue {
        /// `ENV PATH` or `ENTRYPOINT/CMD`.
        what: &'static str,
    },
    /// A provider step names a script the plan doesn't write.
    #[error("boot step {path} is not a file of this plan")]
    StepNotInPlan {
        /// The step's path.
        path: String,
    },
}

/// The git identity puddle writes into the sandbox (a basic identities feature: the user
/// sets it in puddle, nothing is copied from the host's `.gitconfig`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitIdentity {
    name: String,
    email: String,
}

impl GitIdentity {
    /// Checks and wraps `user.name` and `user.email`.
    ///
    /// # Errors
    ///
    /// [`PlanError::GitIdentity`] when either is empty or contains a control character.
    pub fn new(name: &str, email: &str) -> Result<Self, PlanError> {
        for (field, value) in [("user.name", name), ("user.email", email)] {
            if value.trim().is_empty() {
                return Err(PlanError::GitIdentity {
                    field,
                    reason: "is empty",
                });
            }
            if value.chars().any(char::is_control) {
                return Err(PlanError::GitIdentity {
                    field,
                    reason: "contains a control character",
                });
            }
        }
        Ok(Self {
            name: name.to_owned(),
            email: email.to_owned(),
        })
    }

    /// `user.name`.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// `user.email`.
    #[must_use]
    pub fn email(&self) -> &str {
        &self.email
    }
}

/// An author for the repositories that have a remote matching one of `globs`: git's
/// `includeIf "hasconfig:remote.*.url:<glob>"`. The match is on any remote of the repository, is
/// case-sensitive, and `pushurl` is ignored.
///
/// Rules go into the plan in git's order of precedence: when a repository matches several, the
/// one written **last** wins, whatever the order of its remotes. The caller orders them, lowest
/// priority first. The author is a convenience for the user's commits, not a security control:
/// the guest can set any `user.email` in a repository.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitAuthorRule {
    globs: Vec<String>,
    author: GitIdentity,
}

impl GitAuthorRule {
    /// Checks and wraps a rule.
    ///
    /// # Errors
    ///
    /// [`PlanError::GitAuthorRule`] when there is no glob, too many, or one is empty, too long or
    /// holds a control character, a quote or a backslash (nothing a remote glob needs).
    pub fn new(globs: Vec<String>, author: GitIdentity) -> Result<Self, PlanError> {
        let bad = |reason| Err(PlanError::GitAuthorRule { reason });
        if globs.is_empty() {
            return bad("has no remote glob");
        }
        if globs.len() > MAX_GIT_AUTHOR_GLOBS {
            return bad("has too many remote globs");
        }
        for glob in &globs {
            if glob.is_empty() || glob.len() > 1024 {
                return bad("has an empty or over-long remote glob");
            }
            if glob
                .chars()
                .any(|c| c.is_control() || c == '"' || c == '\\')
            {
                return bad("has a remote glob with a control character, quote or backslash");
            }
        }
        Ok(Self { globs, author })
    }

    /// The remote globs.
    #[must_use]
    pub fn globs(&self) -> &[String] {
        &self.globs
    }

    /// The author.
    #[must_use]
    pub fn author(&self) -> &GitIdentity {
        &self.author
    }
}

/// Where the hook finds `puddle-agent` and the port it waits for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentConfig {
    /// The binary in the guest (a read-only mount).
    pub binary: GuestPath,
    /// The port on 127.0.0.1 the hook waits for before it reports ready.
    pub port: u16,
}

impl Default for AgentConfig {
    /// [`AGENT_GUEST`] on [`DEFAULT_AGENT_PORT`].
    fn default() -> Self {
        Self {
            binary: guest_path(AGENT_GUEST),
            port: DEFAULT_AGENT_PORT,
        }
    }
}

/// One boot's worth of work for `boot.sh`. Build it with [`BootPlan::builder`].
///
/// ```
/// use puddle_boot::{BootPlan, GitIdentity};
/// use puddle_compute::ImageConfig;
/// use puddle_types::{GuestEnv, GuestFile, GuestPath};
///
/// let image = ImageConfig {
///     entrypoint: vec!["dockerd-entrypoint.sh".into()],
///     env: vec![("PATH".into(), "/usr/local/bin:/usr/bin:/bin".into())],
///     ..ImageConfig::default()
/// };
/// let mut env = GuestEnv::new();
/// env.set("HTTPS_PROXY", "http://127.0.0.1:3128").unwrap();
/// let plan = BootPlan::builder(&image)
///     .env(&env)
///     .file(GuestFile::new(GuestPath::new("/etc/npmrc").unwrap(), b"proxy=x\n".to_vec()))
///     .git_identity(GitIdentity::new("Ada", "ada@example.org").unwrap())
///     .build()
///     .unwrap();
/// assert_eq!(plan.entrypoint(), Some(&["dockerd-entrypoint.sh".to_owned()][..]));
/// assert!(plan.files().iter().any(|f| f.path().as_str() == "/etc/npmrc"));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootPlan {
    files: Vec<GuestFile>,
    steps: Vec<GuestPath>,
    entry_env: Vec<GuestPath>,
    entrypoint: Vec<String>,
    entrypoint_cwd: Option<GuestPath>,
    agent: Option<AgentConfig>,
}

/// Builds a [`BootPlan`]; see there.
#[derive(Debug, Clone)]
#[must_use]
pub struct BootPlanBuilder {
    image: ImageConfig,
    env: GuestEnv,
    files: Vec<GuestFile>,
    steps: Vec<GuestPath>,
    git: Option<GitIdentity>,
    git_rules: Vec<GitAuthorRule>,
    agent: Option<AgentConfig>,
}

impl BootPlan {
    /// A builder for a sandbox of an image with `image`'s config (from
    /// [`puddle_compute::Runtime::pull_image`]). By default the plan starts the agent with
    /// [`AgentConfig::default`].
    pub fn builder(image: &ImageConfig) -> BootPlanBuilder {
        BootPlanBuilder {
            image: image.clone(),
            env: GuestEnv::new(),
            files: Vec::new(),
            steps: Vec::new(),
            git: None,
            git_rules: Vec::new(),
            agent: Some(AgentConfig::default()),
        }
    }

    /// Every file the hook writes, puddle's own first, then the providers' in the order given.
    #[must_use]
    pub fn files(&self) -> &[GuestFile] {
        &self.files
    }

    /// Provider steps: scripts of this plan the hook runs with `/bin/sh` at every boot, in this
    /// order, after the files and `update-ca-certificates`.
    #[must_use]
    pub fn steps(&self) -> &[GuestPath] {
        &self.steps
    }

    /// The command the hook chains after setup: the image's ENTRYPOINT + CMD, or `None` when the
    /// image declares no ENTRYPOINT (a CMD alone, such as `bash`, is the interactive default,
    /// not a service).
    #[must_use]
    pub fn entrypoint(&self) -> Option<&[String]> {
        (!self.entrypoint.is_empty()).then_some(self.entrypoint.as_slice())
    }

    /// The agent the hook starts and waits for, if any.
    #[must_use]
    pub fn agent(&self) -> Option<&AgentConfig> {
        self.agent.as_ref()
    }

    /// The binary that applies merged files (`puddle-agent merge-file`): the agent's,
    /// or [`AGENT_GUEST`] when the plan starts no agent. It must be mounted when
    /// [`BootPlan::has_merged_files`]; the hook also needs it to remove the keys of a merged file
    /// an earlier plan listed, and keeps that record for a later boot when it is missing.
    #[must_use]
    pub fn merge_tool(&self) -> GuestPath {
        self.agent
            .as_ref()
            .map_or_else(|| guest_path(AGENT_GUEST), |a| a.binary.clone())
    }

    /// Whether any file is applied with [`ApplyKind::Merge`].
    #[must_use]
    pub fn has_merged_files(&self) -> bool {
        self.files
            .iter()
            .any(|f| matches!(f.apply(), ApplyKind::Merge(_)))
    }

    /// The plan as `boot.sh` reads it on stdin.
    #[must_use]
    pub fn render(&self) -> Vec<u8> {
        let mut lines = vec![
            PLAN_HEADER.to_owned(),
            format!("puddle_merge_tool {}", sh_word(self.merge_tool().as_str())),
        ];
        for f in &self.files {
            let (call, body) = match f.apply() {
                ApplyKind::Merge(spec) => (
                    "puddle_merge",
                    // A spec of strings always serialises; an empty one would fail the boot
                    // loudly ("bad merge spec"), never write a wrong file.
                    serde_json::to_vec(spec).unwrap_or_default(),
                ),
                // `build` refuses kinds this hook doesn't know.
                _ => ("puddle_file", f.contents().to_vec()),
            };
            lines.push(format!(
                "{call} {} {:04o} {}",
                sh_word(f.path().as_str()),
                f.mode(),
                printf_format(&body)
            ));
        }
        lines.push(format!(
            "puddle_on_change {} update-ca-certificates",
            sh_word(CA_DIR_GUEST)
        ));
        for step in &self.steps {
            lines.push(format!("puddle_step {}", sh_word(step.as_str())));
        }
        lines.push(format!("puddle_git_include {}", sh_word(GIT_CONFIG_GUEST)));
        if let Some(agent) = &self.agent {
            lines.push(format!(
                "puddle_agent {} {}",
                sh_word(agent.binary.as_str()),
                agent.port
            ));
        }
        for p in &self.entry_env {
            lines.push(format!("puddle_entrypoint_env {}", sh_word(p.as_str())));
        }
        if let Some(cwd) = &self.entrypoint_cwd {
            lines.push(format!("puddle_entrypoint_cwd {}", sh_word(cwd.as_str())));
        }
        lines.push("puddle_plan_end\n".to_owned());
        lines.join("\n").into_bytes()
    }

    /// The exec that runs the hook: `/bin/sh /puddle/boot.sh [ENTRYPOINT CMD...]` as root, the
    /// plan on stdin, `PUDDLE_ROOT` forced empty (it is for the unit tests only).
    #[must_use]
    pub fn exec_request(&self, timeout: Duration) -> ExecRequest {
        let mut env = GuestEnv::new();
        // A fixed, valid name and value: can't fail.
        let _ = env.set("PUDDLE_ROOT", "");
        ExecRequest::new(
            "/bin/sh",
            std::iter::once(BOOT_SH_GUEST.to_owned()).chain(self.entrypoint.iter().cloned()),
        )
        .as_user("root")
        .with_env(&env)
        .with_stdin(self.render())
        .with_timeout(timeout)
    }
}

impl BootPlanBuilder {
    /// The provider environment (merged by the caller, who also puts it into the
    /// [`puddle_compute::SandboxSpec`] env). The hook writes it to [`ENV_FILE_GUEST`] for login
    /// shells and sources it before chaining the ENTRYPOINT.
    pub fn env(mut self, env: &GuestEnv) -> Self {
        self.env.extend(env);
        self
    }

    /// Adds one provider file.
    pub fn file(mut self, file: GuestFile) -> Self {
        self.files.push(file);
        self
    }

    /// Adds provider files, in order.
    pub fn files(mut self, files: impl IntoIterator<Item = GuestFile>) -> Self {
        self.files.extend(files);
        self
    }

    /// Runs `script`, one of the plan's provider files, with `/bin/sh` at every boot after the
    /// files and `update-ca-certificates` (a provider's own setup that needs the guest's state,
    /// such as merging the image's CA bundle). Steps run in the order added; a step added
    /// twice runs once. A failing step fails the boot with its output.
    pub fn step(mut self, script: GuestPath) -> Self {
        if !self.steps.contains(&script) {
            self.steps.push(script);
        }
        self
    }

    /// Sets `user.name` and `user.email` for the sandbox: the author of a repository no
    /// [`GitAuthorRule`] matches.
    pub fn git_identity(mut self, identity: GitIdentity) -> Self {
        self.git = Some(identity);
        self
    }

    /// Adds an author for the repositories whose remotes match the rule's globs. Rules are
    /// written in the order added, and git lets the last matching one win, so add the lowest
    /// priority first. At most [`MAX_GIT_AUTHOR_RULES`] fit in a plan.
    pub fn git_author_rule(mut self, rule: GitAuthorRule) -> Self {
        self.git_rules.push(rule);
        self
    }

    /// Starts this agent instead of the default one.
    pub fn agent(mut self, agent: AgentConfig) -> Self {
        self.agent = Some(agent);
        self
    }

    /// Starts no agent (e.g. a short-lived maintenance sandbox).
    pub fn no_agent(mut self) -> Self {
        self.agent = None;
        self
    }

    /// Checks everything and builds the plan.
    ///
    /// # Errors
    ///
    /// - [`PlanError::DuplicatePath`]: two files claim a path (also a provider file on one of
    ///   puddle's own paths);
    /// - [`PlanError::ReservedPath`], [`PlanError::UnsafePath`]: a file path is unusable;
    /// - [`PlanError::ReservedEnv`]: an env name starts with `PUDDLE_`;
    /// - [`PlanError::ImageValue`]: the image's `PATH` or ENTRYPOINT/CMD holds a NUL or newline;
    /// - [`PlanError::StepNotInPlan`]: a step names no file of the plan;
    /// - [`PlanError::GitAuthorRule`]: more than [`MAX_GIT_AUTHOR_RULES`] author rules.
    pub fn build(self) -> Result<BootPlan, PlanError> {
        if let Some((name, _)) = self
            .env
            .iter()
            .find(|(n, _)| n.starts_with(RESERVED_ENV_PREFIX))
        {
            return Err(PlanError::ReservedEnv {
                name: name.to_owned(),
            });
        }

        let mut files = Vec::new();
        let mut entry_env = vec![guest_path(ENV_FILE_GUEST)];
        files.push(env_file(&self.env));
        if let Some(path) = self.image.env_var("PATH") {
            if path.contains(['\0', '\n']) {
                return Err(PlanError::ImageValue { what: "ENV PATH" });
            }
            files.push(GuestFile::new(
                guest_path(PATH_FILE_GUEST),
                format!("{GENERATED}export PATH={}\n", sh_word(path)).into_bytes(),
            ));
            entry_env.push(guest_path(PATH_FILE_GUEST));
        }
        if self.git_rules.len() > MAX_GIT_AUTHOR_RULES {
            return Err(PlanError::GitAuthorRule {
                reason: "has more rules than a plan holds",
            });
        }
        files.push(git_config(self.git.as_ref(), &self.git_rules));
        files.extend(git_author_files(&self.git_rules));
        let port = self.agent.as_ref().map_or(DEFAULT_AGENT_PORT, |a| a.port);
        files.push(machine_settings(port));
        files.extend(self.files);

        let mounts = guest_path(MOUNT_DIR_GUEST);
        let mut seen = BTreeSet::new();
        for f in &files {
            let path = f.path();
            if path.as_str().chars().any(char::is_control) {
                return Err(PlanError::UnsafePath {
                    path: path.to_string(),
                });
            }
            if path.is_within(&mounts) {
                return Err(PlanError::ReservedPath {
                    path: path.to_string(),
                });
            }
            if !matches!(f.apply(), ApplyKind::Replace | ApplyKind::Merge(_)) {
                return Err(PlanError::UnknownApplyKind {
                    path: path.to_string(),
                });
            }
            if !seen.insert(path.as_str()) {
                return Err(PlanError::DuplicatePath {
                    path: path.to_string(),
                });
            }
        }

        if let Some(step) = self.steps.iter().find(|s| !seen.contains(s.as_str())) {
            return Err(PlanError::StepNotInPlan {
                path: step.to_string(),
            });
        }

        let entrypoint = if self.image.entrypoint.is_empty() {
            Vec::new()
        } else {
            let all: Vec<String> = self
                .image
                .entrypoint
                .iter()
                .chain(&self.image.cmd)
                .cloned()
                .collect();
            if all.iter().any(|a| a.contains('\0')) {
                return Err(PlanError::ImageValue {
                    what: "ENTRYPOINT/CMD",
                });
            }
            all
        };
        // An unusable WORKDIR (relative, `..`) from the image is ignored: the ENTRYPOINT then
        // starts in `/`, as the hook's own working directory.
        let entrypoint_cwd = self
            .image
            .working_dir
            .as_deref()
            .and_then(|d| GuestPath::new(d).ok())
            .filter(|_| !entrypoint.is_empty());

        Ok(BootPlan {
            files,
            steps: self.steps,
            entry_env,
            entrypoint,
            entrypoint_cwd,
            agent: self.agent,
        })
    }
}

fn env_file(env: &GuestEnv) -> GuestFile {
    let mut text = String::from(GENERATED);
    for (name, value) in env.iter() {
        text.extend(["export ", name, "=", &sh_word(value), "\n"]);
    }
    GuestFile::new(guest_path(ENV_FILE_GUEST), text.into_bytes())
}

/// A quoted git config value.
fn git_quote(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

/// A `[user]` section.
fn git_user(id: &GitIdentity) -> String {
    format!(
        "[user]\n\tname = {}\n\temail = {}\n",
        git_quote(&id.name),
        git_quote(&id.email)
    )
}

/// The file name of the author of rule number `n` (counted from 1), relative to
/// [`GIT_CONFIG_GUEST`]'s directory.
fn git_author_name(n: usize) -> String {
    format!("git-author-{n}.gitconfig")
}

/// puddle's git settings: `core.fsync=committed` always (ADR 0006: no lost commits on a VM
/// kill), the identity when set, then one `includeIf` per remote glob of each author rule, in
/// order (git lets the last match win), each pointing at that rule's author file. Never a
/// credential helper.
fn git_config(identity: Option<&GitIdentity>, rules: &[GitAuthorRule]) -> GuestFile {
    let mut text = String::from(GENERATED);
    text.push_str("[core]\n\tfsync = committed\n");
    if let Some(id) = identity {
        text.push_str(&git_user(id));
    }
    for (i, rule) in rules.iter().enumerate() {
        for glob in &rule.globs {
            text.extend([
                "[includeIf \"hasconfig:remote.*.url:",
                glob,
                "\"]\n\tpath = ",
                &git_author_name(i + 1),
                "\n",
            ]);
        }
    }
    GuestFile::new(guest_path(GIT_CONFIG_GUEST), text.into_bytes())
}

/// The author file of each rule: only a `[user]` section (an included file may not define
/// remotes, and needs nothing else).
fn git_author_files(rules: &[GitAuthorRule]) -> Vec<GuestFile> {
    rules
        .iter()
        .enumerate()
        .map(|(i, rule)| {
            GuestFile::new(
                guest_path(&format!(
                    "{GIT_AUTHOR_DIR_GUEST}/{}",
                    git_author_name(i + 1)
                )),
                format!("{GENERATED}{}", git_user(&rule.author)).into_bytes(),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::machine::MACHINE_SETTINGS_GUEST;

    fn image(entrypoint: &[&str], cmd: &[&str], path: Option<&str>) -> ImageConfig {
        ImageConfig {
            entrypoint: entrypoint.iter().map(|s| (*s).to_owned()).collect(),
            cmd: cmd.iter().map(|s| (*s).to_owned()).collect(),
            env: path
                .map(|p| vec![("PATH".to_owned(), p.to_owned())])
                .unwrap_or_default(),
            ..ImageConfig::default()
        }
    }

    fn file(path: &str, contents: &str) -> GuestFile {
        GuestFile::new(GuestPath::new(path).unwrap(), contents.as_bytes().to_vec())
    }

    fn text(plan: &BootPlan, path: &str) -> String {
        let f = plan
            .files()
            .iter()
            .find(|f| f.path().as_str() == path)
            .unwrap_or_else(|| panic!("no {path}"));
        String::from_utf8(f.contents().to_vec()).unwrap()
    }

    #[test]
    fn puddle_files_come_first_then_providers_in_order() {
        let plan = BootPlan::builder(&image(&[], &["bash"], Some("/x:/bin")))
            .file(file("/etc/b", "b"))
            .files([file("/etc/a", "a")])
            .build()
            .unwrap();
        let paths: Vec<_> = plan.files().iter().map(|f| f.path().as_str()).collect();
        assert_eq!(
            paths,
            [
                ENV_FILE_GUEST,
                PATH_FILE_GUEST,
                GIT_CONFIG_GUEST,
                MACHINE_SETTINGS_GUEST,
                "/etc/b",
                "/etc/a"
            ]
        );
    }

    #[test]
    fn entrypoint_is_chained_only_when_the_image_declares_one() {
        let debian = BootPlan::builder(&image(&[], &["bash"], None))
            .build()
            .unwrap();
        assert_eq!(debian.entrypoint(), None);
        let dind = BootPlan::builder(&image(&["dockerd-entrypoint.sh"], &["--tls=false"], None))
            .build()
            .unwrap();
        assert_eq!(
            dind.entrypoint().unwrap(),
            ["dockerd-entrypoint.sh", "--tls=false"]
        );
        let req = dind.exec_request(Duration::from_secs(9));
        assert_eq!(req.program, "/bin/sh");
        assert_eq!(
            req.args,
            [BOOT_SH_GUEST, "dockerd-entrypoint.sh", "--tls=false"]
        );
        assert_eq!(req.user.as_deref(), Some("root"));
        assert_eq!(req.env.get("PUDDLE_ROOT"), Some(""));
        assert_eq!(req.timeout, Duration::from_secs(9));
        assert_eq!(req.stdin, dind.render());
    }

    #[test]
    fn image_workdir_is_used_only_when_valid_and_chaining() {
        let mut img = image(&["run"], &[], None);
        img.working_dir = Some("/srv/app".into());
        let plan = BootPlan::builder(&img).build().unwrap();
        let rendered = String::from_utf8(plan.render()).unwrap();
        assert!(rendered.contains("puddle_entrypoint_cwd '/srv/app'\n"));
        img.working_dir = Some("relative".into());
        let rendered =
            String::from_utf8(BootPlan::builder(&img).build().unwrap().render()).unwrap();
        assert!(!rendered.contains("puddle_entrypoint_cwd"));
        let mut no_entry = image(&[], &["bash"], None);
        no_entry.working_dir = Some("/srv".into());
        let rendered =
            String::from_utf8(BootPlan::builder(&no_entry).build().unwrap().render()).unwrap();
        assert!(!rendered.contains("puddle_entrypoint_cwd"));
    }

    #[test]
    fn path_file_restores_the_image_path_quoted() {
        let plan = BootPlan::builder(&image(&[], &[], Some("/usr/local/cargo/bin:/it's")))
            .build()
            .unwrap();
        assert_eq!(
            text(&plan, PATH_FILE_GUEST),
            format!("{GENERATED}export PATH='/usr/local/cargo/bin:/it'\\''s'\n")
        );
        let none = BootPlan::builder(&image(&[], &[], None)).build().unwrap();
        assert!(
            none.files()
                .iter()
                .all(|f| f.path().as_str() != PATH_FILE_GUEST)
        );
    }

    #[test]
    fn env_file_exports_every_variable_quoted() {
        let mut env = GuestEnv::new();
        env.set("HTTPS_PROXY", "http://127.0.0.1:3128").unwrap();
        env.set("ODD", "a'b $c\nd").unwrap();
        let plan = BootPlan::builder(&ImageConfig::default())
            .env(&env)
            .build()
            .unwrap();
        assert_eq!(
            text(&plan, ENV_FILE_GUEST),
            format!(
                "{GENERATED}export HTTPS_PROXY='http://127.0.0.1:3128'\nexport ODD='a'\\''b $c\nd'\n"
            )
        );
    }

    #[test]
    fn git_config_has_fsync_identity_and_no_credential_helper() {
        let without_id = BootPlan::builder(&ImageConfig::default()).build().unwrap();
        assert_eq!(
            text(&without_id, GIT_CONFIG_GUEST),
            format!("{GENERATED}[core]\n\tfsync = committed\n")
        );
        let id = GitIdentity::new(r#"Ada "the" \Countess"#, "ada@example.org").unwrap();
        assert_eq!(id.name(), r#"Ada "the" \Countess"#);
        assert_eq!(id.email(), "ada@example.org");
        let plan = BootPlan::builder(&ImageConfig::default())
            .git_identity(id)
            .build()
            .unwrap();
        let git = text(&plan, GIT_CONFIG_GUEST);
        assert!(git.ends_with(
            "[user]\n\tname = \"Ada \\\"the\\\" \\\\Countess\"\n\temail = \"ada@example.org\"\n"
        ));
        for f in plan.files() {
            let body = String::from_utf8_lossy(f.contents()).to_lowercase();
            assert!(!body.contains("credential"), "{}", f.path());
        }
    }

    fn author(name: &str) -> GitIdentity {
        GitIdentity::new(name, &format!("{}@example.org", name.to_lowercase())).unwrap()
    }

    fn rule(globs: &[&str], name: &str) -> GitAuthorRule {
        GitAuthorRule::new(
            globs.iter().map(|g| (*g).to_owned()).collect(),
            author(name),
        )
        .unwrap()
    }

    #[test]
    fn author_rules_become_include_if_blocks_in_order_each_with_its_own_file() {
        let plan = BootPlan::builder(&ImageConfig::default())
            .git_identity(author("Ada"))
            .git_author_rule(rule(
                &["https://github.com/**", "https://*@github.com/**"],
                "Bob",
            ))
            .git_author_rule(rule(&["https://github.com/acme/**"], "Cy"))
            .build()
            .unwrap();
        assert_eq!(
            text(&plan, GIT_CONFIG_GUEST),
            format!(
                "{GENERATED}[core]\n\tfsync = committed\n\
                 [user]\n\tname = \"Ada\"\n\temail = \"ada@example.org\"\n\
                 [includeIf \"hasconfig:remote.*.url:https://github.com/**\"]\n\tpath = git-author-1.gitconfig\n\
                 [includeIf \"hasconfig:remote.*.url:https://*@github.com/**\"]\n\tpath = git-author-1.gitconfig\n\
                 [includeIf \"hasconfig:remote.*.url:https://github.com/acme/**\"]\n\tpath = git-author-2.gitconfig\n"
            )
        );
        assert_eq!(
            text(&plan, "/etc/puddle/git-author-1.gitconfig"),
            format!("{GENERATED}[user]\n\tname = \"Bob\"\n\temail = \"bob@example.org\"\n")
        );
        assert!(text(&plan, "/etc/puddle/git-author-2.gitconfig").contains("\"Cy\""));
        // No rule file without a rule, and still no credential helper anywhere.
        let none = BootPlan::builder(&ImageConfig::default()).build().unwrap();
        assert!(
            none.files()
                .iter()
                .all(|f| !f.path().as_str().contains("git-author"))
        );
        for f in plan.files() {
            let body = String::from_utf8_lossy(f.contents()).to_lowercase();
            assert!(!body.contains("credential"), "{}", f.path());
        }
    }

    #[test]
    fn author_rules_are_checked() {
        let a = author("Ada");
        let globs = |n: usize| (0..n).map(|i| format!("https://h{i}.example/**")).collect();
        for (bad, why) in [
            (GitAuthorRule::new(vec![], a.clone()), "no remote glob"),
            (
                GitAuthorRule::new(globs(MAX_GIT_AUTHOR_GLOBS + 1), a.clone()),
                "too many",
            ),
            (GitAuthorRule::new(vec![String::new()], a.clone()), "empty"),
            (
                GitAuthorRule::new(vec!["a".repeat(1025)], a.clone()),
                "over-long",
            ),
            (
                GitAuthorRule::new(vec!["a\nb".into()], a.clone()),
                "control",
            ),
            (GitAuthorRule::new(vec!["a\"b".into()], a.clone()), "quote"),
            (
                GitAuthorRule::new(vec!["a\\b".into()], a.clone()),
                "backslash",
            ),
        ] {
            let err = bad.unwrap_err();
            assert!(
                matches!(err, PlanError::GitAuthorRule { .. }),
                "{why}: {err}"
            );
            assert!(err.to_string().starts_with("git author rule "), "{err}");
        }
        let ok = GitAuthorRule::new(globs(MAX_GIT_AUTHOR_GLOBS), a).unwrap();
        assert_eq!(ok.globs().len(), MAX_GIT_AUTHOR_GLOBS);
        assert_eq!(ok.author(), &author("Ada"));
        let mut builder = BootPlan::builder(&ImageConfig::default());
        for _ in 0..=MAX_GIT_AUTHOR_RULES {
            builder = builder.git_author_rule(rule(&["https://x.example/**"], "Ada"));
        }
        assert!(matches!(
            builder.build().unwrap_err(),
            PlanError::GitAuthorRule { .. }
        ));
    }

    #[test]
    fn git_identity_rejects_empty_and_control_characters() {
        let cases = [
            ("", "a@b", "user.name is empty"),
            ("a", " ", "user.email is empty"),
            ("a\nb", "a@b", "user.name contains a control character"),
            ("a", "a@b\0", "user.email contains a control character"),
        ];
        for (name, email, want) in cases {
            let err = GitIdentity::new(name, email).unwrap_err();
            assert_eq!(err.to_string(), format!("git {want}"));
        }
    }

    #[test]
    fn plan_refuses_conflicting_or_unusable_files() {
        let build = |f: GuestFile| BootPlan::builder(&ImageConfig::default()).file(f).build();
        assert_eq!(
            build(file(ENV_FILE_GUEST, "x")).unwrap_err(),
            PlanError::DuplicatePath {
                path: ENV_FILE_GUEST.into()
            }
        );
        assert_eq!(
            build(file("/puddle/boot.sh", "x")).unwrap_err(),
            PlanError::ReservedPath {
                path: "/puddle/boot.sh".into()
            }
        );
        let err = build(file("/etc/a\nb", "x")).unwrap_err();
        assert!(matches!(err, PlanError::UnsafePath { .. }));
        assert!(err.to_string().contains("control character"));
        let two = BootPlan::builder(&ImageConfig::default())
            .file(file("/etc/x", "1"))
            .file(file("/etc/x", "2"))
            .build()
            .unwrap_err();
        assert_eq!(two.to_string(), "two boot files claim /etc/x");
    }

    #[test]
    fn plan_refuses_reserved_env_and_bad_image_values() {
        let mut env = GuestEnv::new();
        env.set("PUDDLE_ROOT", "/tmp").unwrap();
        let err = BootPlan::builder(&ImageConfig::default())
            .env(&env)
            .build()
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "environment variable PUDDLE_ROOT is reserved for puddle's boot hook"
        );
        let err = BootPlan::builder(&image(&[], &[], Some("/a\n/b")))
            .build()
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "the image's ENV PATH contains a NUL or newline"
        );
        let err = BootPlan::builder(&image(&["a\0"], &[], None))
            .build()
            .unwrap_err();
        assert_eq!(
            err,
            PlanError::ImageValue {
                what: "ENTRYPOINT/CMD"
            }
        );
    }

    #[test]
    fn render_has_header_files_steps_and_end_marker() {
        let plan = BootPlan::builder(&image(&["e"], &[], Some("/bin")))
            .file(file("/etc/it's", "50%\n").with_mode(0o600).unwrap())
            .agent(AgentConfig {
                binary: GuestPath::new("/opt/agent").unwrap(),
                port: 4000,
            })
            .build()
            .unwrap();
        let r = String::from_utf8(plan.render()).unwrap();
        let lines: Vec<&str> = r.lines().collect();
        assert_eq!(lines.first(), Some(&PLAN_HEADER));
        assert_eq!(lines.last(), Some(&"puddle_plan_end"));
        assert!(r.contains("puddle_file '/etc/it'\\''s' 0600 '50\\045\\012'\n"));
        assert!(r.contains(
            "puddle_on_change '/usr/local/share/ca-certificates' update-ca-certificates\n"
        ));
        assert!(r.contains("puddle_git_include '/etc/puddle/gitconfig'\n"));
        assert!(r.contains("puddle_agent '/opt/agent' 4000\n"));
        assert_eq!(lines.get(1), Some(&"puddle_merge_tool '/opt/agent'"));
        assert!(r.contains(&format!(
            "puddle_entrypoint_env '{ENV_FILE_GUEST}'\npuddle_entrypoint_env '{PATH_FILE_GUEST}'\n"
        )));
        assert_eq!(plan.agent().unwrap().port, 4000);
        // Every line is one call: content newlines are escaped.
        assert_eq!(lines.len(), 2 + plan.files().len() + 6);
        // The agent's port is the one VS Code is told to ignore.
        assert!(text(&plan, MACHINE_SETTINGS_GUEST).contains("\"4000\""));
    }

    #[test]
    fn steps_run_after_the_ca_trigger_once_each_and_must_be_plan_files() {
        let step = GuestPath::new("/usr/local/lib/puddle/step.sh").unwrap();
        let other = GuestPath::new("/usr/local/lib/puddle/other.sh").unwrap();
        let plan = BootPlan::builder(&ImageConfig::default())
            .file(file(step.as_str(), "true\n"))
            .file(file(other.as_str(), "true\n"))
            .step(other.clone())
            .step(step.clone())
            .step(other.clone())
            .build()
            .unwrap();
        assert_eq!(plan.steps(), [other.clone(), step.clone()]);
        let r = String::from_utf8(plan.render()).unwrap();
        let trigger = r.find("puddle_on_change").unwrap();
        let first = r
            .find("puddle_step '/usr/local/lib/puddle/other.sh'\n")
            .unwrap();
        let second = r
            .find("puddle_step '/usr/local/lib/puddle/step.sh'\n")
            .unwrap();
        assert!(trigger < first && first < second, "{r}");
        assert_eq!(r.matches("puddle_step ").count(), 2);

        let err = BootPlan::builder(&ImageConfig::default())
            .step(step.clone())
            .build()
            .unwrap_err();
        assert_eq!(
            err,
            PlanError::StepNotInPlan {
                path: step.to_string()
            }
        );
        assert!(err.to_string().contains("/usr/local/lib/puddle/step.sh"));
    }

    #[test]
    fn no_agent_leaves_the_agent_step_out() {
        let plan = BootPlan::builder(&ImageConfig::default())
            .no_agent()
            .build()
            .unwrap();
        assert!(plan.agent().is_none());
        let r = String::from_utf8(plan.render()).unwrap();
        assert!(!r.contains("puddle_agent "));
        // Merged files still have their tool: the agent binary's default mount.
        assert!(r.contains("puddle_merge_tool '/puddle/puddle-agent'\n"));
        assert!(text(&plan, MACHINE_SETTINGS_GUEST).contains("\"3128\""));
    }

    #[test]
    fn merged_files_render_their_spec_and_are_counted() {
        use puddle_types::{MergeEntry, MergeFormat, MergeSpec};
        let spec = MergeSpec::new(
            MergeFormat::Json,
            vec![MergeEntry::json(&["a"], &serde_json::json!("50%"))],
        )
        .unwrap();
        let merged = GuestFile::merged(GuestPath::new("/root/c.json").unwrap(), spec)
            .with_mode(0o600)
            .unwrap();
        // Every plan merges VS Code's Machine settings.
        let without = BootPlan::builder(&ImageConfig::default()).build().unwrap();
        assert!(without.has_merged_files());
        let plan = BootPlan::builder(&ImageConfig::default())
            .file(merged)
            .build()
            .unwrap();
        assert!(plan.has_merged_files());
        assert_eq!(plan.merge_tool().as_str(), AGENT_GUEST);
        let r = String::from_utf8(plan.render()).unwrap();
        assert!(
            r.contains(
                r#"puddle_merge '/root/c.json' 0600 '{"format":"json","entries":[{"key":["a"],"value":"\134"50\045\134""}]}'"#
            ),
            "{r}"
        );
    }
}
