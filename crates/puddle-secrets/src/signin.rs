// SPDX-License-Identifier: GPL-3.0-or-later
//! Signing in from puddle, on the user's click and never for a request.
//!
//! A source that cannot supply a secret answers [`SourceError::NotSignedIn`]. Here is how the user
//! fixes that: `gh auth login --web` for a GitHub CLI account, or Git Credential Manager allowed to
//! open its own window for a Git credential. The sign-in runs in the background for a limited
//! time; whoever started it asks the source again (`Fetch`) to learn whether it worked. A pasted
//! token has nothing to sign in to.
//!
//! `gh` is not run on a terminal, so it prints a one-time code and an address instead of opening a
//! browser; those two lines are what [`SignIns::begin`] hands back, after checking their shape.

use std::collections::HashMap;
use std::process::Stdio;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, BufReader};

use crate::error::{SourceError, Tool};
use crate::name::{AccountName, HostName, UrlPath};
use crate::run::{Prompts, ToolPaths, command, run_with, spawn_error};
use crate::sources::parse_fill;
use crate::spec::SourceSpec;

/// How long a sign-in may stay open before puddle ends it.
const SIGN_IN_WINDOW: Duration = Duration::from_mins(5);

/// How long `gh` gets to print its code and address.
const PROMPT_WAIT: Duration = Duration::from_secs(15);

/// How long a Git credential sign-in is watched for an early failure (no helper that can ask, a
/// helper that answered for something else) before it is taken to be waiting on the user.
const EARLY_WAIT: Duration = Duration::from_secs(2);

/// What a line of a tool's output may carry into an error message: no control characters, bounded.
fn clean_line(line: &str) -> String {
    line.chars()
        .filter(|c| !c.is_control())
        .take(200)
        .collect::<String>()
        .trim()
        .to_owned()
}

fn detail(text: &str) -> String {
    if text.is_empty() {
        String::new()
    } else {
        format!(": {text}")
    }
}

/// What the user needs to finish a sign-in that puddle started.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SignInStart {
    /// The one-time code to type at the address (`gh`).
    pub code: Option<String>,
    /// Where to type it (`https://github.com/login/device`).
    pub url: Option<String>,
}

/// Why a sign-in could not be started.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SignInError {
    /// A pasted token has nothing to sign in to; paste a new one.
    #[error("a pasted token has nothing to sign in to")]
    NothingToSignIn,
    /// The tool started but did not show a code and an address in time; the second field is the
    /// last line it printed, when it printed one.
    #[error("{} did not show a sign-in code{}", .0.name(), detail(.1))]
    NoPrompt(Tool, String),
    /// The tool ended at once without a sign-in (no credential helper that can ask, or one that
    /// answered for another host or path); the second field says what it was, when known.
    #[error("{} ended without signing in{}", .0.name(), detail(.1))]
    Ended(Tool, String),
    /// The tool could not be started.
    #[error(transparent)]
    Source(#[from] SourceError),
}

type Open = Arc<Mutex<HashMap<SourceSpec, SignInStart>>>;

/// The sign-ins that are open. One per source at a time: asking again while one is open returns
/// what the first one showed, so a reload of the page finds the same code.
pub struct SignIns {
    tools: ToolPaths,
    window: Duration,
    early_wait: Duration,
    open: Open,
    /// One `begin` at a time, so two clicks cannot start two tools.
    gate: tokio::sync::Mutex<()>,
}

impl SignIns {
    /// Sign-ins that run the tools at `tools`.
    #[must_use]
    pub fn new(tools: ToolPaths) -> Self {
        Self {
            tools,
            window: SIGN_IN_WINDOW,
            early_wait: EARLY_WAIT,
            open: Open::default(),
            gate: tokio::sync::Mutex::new(()),
        }
    }

    /// The same, ending a sign-in after `window` (the default is five minutes).
    #[must_use]
    pub fn with_window(mut self, window: Duration) -> Self {
        self.window = window;
        self
    }

    /// The same, watching a Git credential sign-in for an early failure for `wait` (the default is two seconds).
    #[must_use]
    pub fn with_early_wait(mut self, wait: Duration) -> Self {
        self.early_wait = wait;
        self
    }

    /// Starts signing in to `spec`, or returns what the open sign-in for it showed.
    ///
    /// # Errors
    /// [`SignInError`] when `spec` is a pasted token, a tool is missing or `gh` shows no code.
    pub async fn begin(&self, spec: &SourceSpec) -> Result<SignInStart, SignInError> {
        let _one_at_a_time = self.gate.lock().await;
        if let Some(open) = self
            .open
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(spec)
        {
            return Ok(open.clone());
        }
        match spec {
            SourceSpec::Gh { host, .. } => self.gh(spec, host).await,
            SourceSpec::GitCredential {
                host,
                path,
                username,
            } => {
                self.git_credential(spec, host, path, username.as_ref())
                    .await
            }
            SourceSpec::Stored { .. } => Err(SignInError::NothingToSignIn),
        }
    }

    /// Notes the sign-in as open, then runs `task`; the note goes when `task` ends.
    fn open_while(
        &self,
        spec: &SourceSpec,
        start: &SignInStart,
        task: impl Future<Output = ()> + Send + 'static,
    ) {
        let (open, key) = (Arc::clone(&self.open), spec.clone());
        open.lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(key.clone(), start.clone());
        tokio::spawn(async move {
            task.await;
            open.lock()
                .unwrap_or_else(PoisonError::into_inner)
                .remove(&key);
        });
    }

    /// `gh auth login --hostname H --web`: the user signs in at the address with the code.
    async fn gh(&self, spec: &SourceSpec, host: &HostName) -> Result<SignInStart, SignInError> {
        let program = self.tools.get(Tool::Gh)?;
        let mut cmd = command(program, Prompts::UserPresent);
        cmd.args(["auth", "login", "--hostname", host.as_str(), "--web"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        let mut child = cmd.spawn().map_err(|err| spawn_error(Tool::Gh, &err))?;
        let Some(stderr) = child.stderr.take() else {
            return Err(SignInError::NoPrompt(Tool::Gh, String::new()));
        };
        let mut lines = BufReader::new(stderr).lines();
        let mut last = String::new();
        let shown = tokio::time::timeout(PROMPT_WAIT, async {
            let (mut code, mut url) = (None, None);
            while let Ok(Some(line)) = lines.next_line().await {
                if let Some((_, rest)) = line.split_once("one-time code:") {
                    code = valid_code(rest);
                } else if let Some((_, rest)) = line.split_once("web browser:") {
                    url = valid_url(rest, host);
                }
                if code.is_some() && url.is_some() {
                    return Some(SignInStart { code, url });
                }
                let cleaned = clean_line(&line);
                if !cleaned.is_empty() {
                    last = cleaned;
                }
            }
            None
        })
        .await;
        let Ok(Some(start)) = shown else {
            // What the tool said last is the cause (a proxy, no route, a bad host), when it said anything.
            return Err(SignInError::NoPrompt(Tool::Gh, last));
        };
        // The tool keeps running until the user finishes at the address, or the window ends;
        // dropping the child then ends one that is still waiting.
        let window = self.window;
        self.open_while(spec, &start, async move {
            let finish = async {
                while let Ok(Some(_)) = lines.next_line().await {}
                let _ = child.wait().await;
            };
            let _ = tokio::time::timeout(window, finish).await;
        });
        Ok(start)
    }

    /// `git credential fill` with Git Credential Manager allowed to open its window; an answer
    /// for the right target is then handed to `git credential approve`, as Git does after a
    /// working sign-in, so the helper keeps it. A tool that ends at once without an answer (no
    /// helper that can ask) is reported; one still running after the early wait is taken to be
    /// waiting on the user.
    async fn git_credential(
        &self,
        spec: &SourceSpec,
        host: &HostName,
        path: &UrlPath,
        username: Option<&AccountName>,
    ) -> Result<SignInStart, SignInError> {
        let program = self.tools.get(Tool::Git)?.to_owned();
        let (host, path, username) = (host.clone(), path.clone(), username.cloned());
        let window = self.window;
        let mut input = format!("protocol=https\nhost={host}\npath={path}\n");
        if let Some(user) = &username {
            input.push_str("username=");
            input.push_str(user.as_str());
            input.push('\n');
        }
        input.push('\n');
        let start = SignInStart::default();
        let (tell, told) = tokio::sync::oneshot::channel::<Result<(), String>>();
        self.open_while(spec, &start, async move {
            let args = ["-c", "credential.useHttpPath=true", "credential", "fill"];
            let answer = run_with(
                Prompts::UserPresent,
                Tool::Git,
                &program,
                &args,
                Some(input.as_bytes()),
                window,
            )
            .await;
            let outcome = match &answer {
                Err(err) => Err(err.to_string()),
                Ok(answer) if !answer.success => Err(String::new()),
                Ok(answer) => {
                    let right_target = std::str::from_utf8(&answer.stdout).is_ok_and(|text| {
                        parse_fill(text, &host, &path, username.as_ref()).is_ok()
                    });
                    if right_target {
                        Ok(())
                    } else {
                        Err("the helper answered for another host or path".to_owned())
                    }
                }
            };
            let signed_in = outcome.is_ok();
            let _ = tell.send(outcome);
            if let (true, Ok(answer)) = (signed_in, &answer) {
                let _ = run_with(
                    Prompts::Never,
                    Tool::Git,
                    &program,
                    &["credential", "approve"],
                    Some(&answer.stdout),
                    Duration::from_secs(10),
                )
                .await;
            }
        });
        if let Ok(Ok(Err(why))) = tokio::time::timeout(self.early_wait, told).await {
            return Err(SignInError::Ended(Tool::Git, why));
        }
        Ok(start)
    }
}

/// The one-time code, when it is the shape `gh` prints (`ABCD-1234`).
fn valid_code(text: &str) -> Option<String> {
    let code = text.trim();
    let ok = (4..=16).contains(&code.len())
        && code.chars().all(|c| c.is_ascii_alphanumeric() || c == '-');
    ok.then(|| code.to_owned())
}

/// The sign-in address, when it is an `https` address on the host asked for.
fn valid_url(text: &str, host: &HostName) -> Option<String> {
    let url = text.trim();
    let rest = url.strip_prefix("https://")?;
    let authority = rest
        .split_once('/')
        .map_or(rest, |(authority, _)| authority);
    let plain = url.chars().all(|c| c.is_ascii_graphic());
    (plain && authority.eq_ignore_ascii_case(host.as_str())).then(|| url.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_code_and_address_must_have_the_shape_gh_prints() {
        assert_eq!(valid_code(" ABCD-1234 "), Some("ABCD-1234".into()));
        for bad in ["", "AB", "ABCD 1234", "ABCD-1234-ABCD-1234", "AB<script>"] {
            assert_eq!(valid_code(bad), None, "{bad:?}");
        }
        let host = HostName::new("github.com").unwrap();
        assert_eq!(
            valid_url(" https://github.com/login/device ", &host),
            Some("https://github.com/login/device".into())
        );
        assert_eq!(
            valid_url("https://github.com", &host),
            Some("https://github.com".into())
        );
        for bad in [
            "http://github.com/login/device",
            "https://evil.example/login/device",
            "https://github.com.evil.example/x",
            "https://github.com/a b",
            "javascript:alert(1)",
        ] {
            assert_eq!(valid_url(bad, &host), None, "{bad:?}");
        }
    }
}
