// SPDX-License-Identifier: GPL-3.0-or-later
//! The sources behind one interface: [`Fetch`].

use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::error::{Refusal, SourceError, Tool};
use crate::name::{AccountName, HostName, StoredId, UrlPath};
use crate::run::{TOOL_TIMEOUT, ToolPaths, run};
use crate::secret::Secret;
use crate::spec::SourceSpec;
use crate::store::SecretStore;

/// A credential read from a source. Cheap to clone: the secret is shared and wiped when the last
/// holder drops it.
///
/// The same value serves the proxy (which puts it in a header) and host-side API calls (which
/// send it to the Git host's own API); whoever uses it checks [`SourceSpec::scope`] first.
#[derive(Debug, Clone)]
pub struct Credential {
    /// The user name the source reported, when it has one (Git Credential Manager does).
    pub username: Option<String>,
    /// The token.
    pub secret: Arc<Secret>,
}

/// A credential and how long its source says it stays valid.
#[derive(Debug, Clone)]
pub struct Fetched {
    /// The credential.
    pub credential: Credential,
    /// How long from now the credential is good, when the source knows (an Entra token does).
    pub valid_for: Option<Duration>,
}

/// One interface over every source: give a [`SourceSpec`], get a credential or a typed reason. It
/// never asks the user anything; a source that needs a login answers
/// [`SourceError::NotSignedIn`].
pub trait Fetch: Send + Sync {
    /// Reads the secret `spec` names.
    fn fetch(&self, spec: &SourceSpec)
    -> impl Future<Output = Result<Fetched, SourceError>> + Send;
}

/// The real sources: `gh`, `git credential fill` and the OS store.
pub struct Sources {
    tools: ToolPaths,
    store: Arc<dyn SecretStore>,
    timeout: Duration,
}

impl Sources {
    /// Sources that run the tools at `tools` and read pasted tokens from `store`.
    #[must_use]
    pub fn new(tools: ToolPaths, store: Arc<dyn SecretStore>) -> Self {
        Self {
            tools,
            store,
            timeout: TOOL_TIMEOUT,
        }
    }

    /// The same sources with another time limit per tool call (the default is 10 seconds).
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Reads the token of one `gh` account. `gh auth token --user` answers from the keyring
    /// without a prompt, also for an account that is not the active one.
    async fn gh(&self, host: &HostName, account: &AccountName) -> Result<Fetched, SourceError> {
        let program = self.tools.get(Tool::Gh)?;
        let args = [
            "auth",
            "token",
            "--hostname",
            host.as_str(),
            "--user",
            account.as_str(),
        ];
        let out = run(Tool::Gh, program, &args, None, self.timeout).await?;
        if !out.success {
            return Err(SourceError::NotSignedIn);
        }
        let text = std::str::from_utf8(&out.stdout)
            .map_err(|_| SourceError::Refused(Refusal::Unreadable))?
            .trim();
        if text.is_empty() {
            return Err(SourceError::NotSignedIn);
        }
        let secret = token_secret(text, false)?;
        Ok(Fetched {
            credential: Credential {
                username: None,
                secret,
            },
            valid_for: None,
        })
    }

    /// Asks Git for the credential of one URL with its path, with every prompt off.
    async fn git_credential(
        &self,
        host: &HostName,
        path: &UrlPath,
        username: Option<&AccountName>,
    ) -> Result<Fetched, SourceError> {
        let program = self.tools.get(Tool::Git)?;
        // `useHttpPath` makes Git keep `path` in the request; without it Git drops the path and the
        // helper may answer from another organisation's entry.
        let args = ["-c", "credential.useHttpPath=true", "credential", "fill"];
        let mut input = format!("protocol=https\nhost={host}\npath={path}\n");
        if let Some(user) = username {
            input.push_str("username=");
            input.push_str(user.as_str());
            input.push('\n');
        }
        input.push('\n');
        let out = run(
            Tool::Git,
            program,
            &args,
            Some(input.as_bytes()),
            self.timeout,
        )
        .await?;
        if !out.success {
            return Err(SourceError::NotSignedIn);
        }
        let text = std::str::from_utf8(&out.stdout)
            .map_err(|_| SourceError::Refused(Refusal::Unreadable))?;
        parse_fill(text, host, path, username)
    }

    async fn stored(&self, id: &StoredId) -> Result<Fetched, SourceError> {
        let store = Arc::clone(&self.store);
        let id = id.clone();
        let found = tokio::task::spawn_blocking(move || store.get(&id))
            .await
            .map_err(|_| SourceError::StoreUnavailable)?
            .map_err(|_| SourceError::StoreUnavailable)?;
        let secret = found.ok_or(SourceError::NotSignedIn)?;
        Ok(Fetched {
            credential: Credential {
                username: None,
                secret: Arc::new(secret),
            },
            valid_for: None,
        })
    }
}

impl Fetch for Sources {
    async fn fetch(&self, spec: &SourceSpec) -> Result<Fetched, SourceError> {
        tracing::debug!(source = %spec.describe(), "reading a secret");
        match spec {
            SourceSpec::Gh { host, account } => self.gh(host, account).await,
            SourceSpec::GitCredential {
                host,
                path,
                username,
            } => self.git_credential(host, path, username.as_ref()).await,
            SourceSpec::Stored { id, .. } => self.stored(id).await,
        }
    }
}

/// Checks a token's characters and wraps it. `allow_space` is for helper passwords, which are not
/// always tokens; control characters never pass (they would end up in a header).
fn token_secret(text: &str, allow_space: bool) -> Result<Arc<Secret>, SourceError> {
    let bad = |c: char| c.is_control() || (!allow_space && c.is_whitespace());
    if text.len() > 8192 || text.chars().any(bad) {
        return Err(SourceError::Refused(Refusal::Malformed));
    }
    Ok(Arc::new(Secret::new(text.to_owned())))
}

/// Checks a token the user pasted before it is stored: trims surrounding whitespace and refuses
/// an empty value, inner whitespace or control characters.
///
/// # Errors
/// [`SourceError::Refused`] with [`Refusal::Malformed`].
pub fn pasted_token(text: &str) -> Result<Secret, SourceError> {
    let text = text.trim();
    if text.is_empty() {
        return Err(SourceError::Refused(Refusal::Malformed));
    }
    let arc = token_secret(text, false)?;
    Ok(Secret::new(arc.expose().to_owned()))
}

/// Reads `git credential fill` output. The answer is used only when it names the host and path
/// that were asked for (and the account, when one was): a helper that answered for another entry
/// is the failure this guards against.
fn parse_fill(
    text: &str,
    host: &HostName,
    path: &UrlPath,
    username: Option<&AccountName>,
) -> Result<Fetched, SourceError> {
    let (mut got_host, mut got_path, mut got_user) = (None, None, None);
    let (mut protocol, mut password, mut expiry) = (None, None, None);
    for line in text.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        match key {
            "protocol" => protocol = Some(value),
            "host" => got_host = Some(value),
            "path" => got_path = Some(value),
            "username" => got_user = Some(value),
            "password" => password = Some(value),
            "password_expiry_utc" => expiry = value.parse::<u64>().ok(),
            _ => {}
        }
    }
    let wrong = SourceError::Refused(Refusal::WrongTarget);
    if protocol.is_some_and(|p| p != "https") {
        return Err(wrong);
    }
    if !got_host.is_some_and(|h| h.eq_ignore_ascii_case(host.as_str())) {
        return Err(wrong);
    }
    if !got_path.is_some_and(|p| p.trim_matches('/').eq_ignore_ascii_case(path.as_str())) {
        return Err(wrong);
    }
    if let Some(asked) = username
        && !got_user.is_some_and(|u| u.eq_ignore_ascii_case(asked.as_str()))
    {
        return Err(wrong);
    }
    let password = password
        .filter(|p| !p.is_empty())
        .ok_or(SourceError::NotSignedIn)?;
    let valid_for = match expiry {
        None => None,
        Some(at) => {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            if at <= now {
                return Err(SourceError::NotSignedIn);
            }
            Some(Duration::from_secs(at - now))
        }
    };
    let secret = token_secret(password, true)?;
    Ok(Fetched {
        credential: Credential {
            username: got_user.map(str::to_owned),
            secret,
        },
        valid_for,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target() -> (HostName, UrlPath) {
        (
            HostName::new("dev.azure.com").unwrap(),
            UrlPath::new("org").unwrap(),
        )
    }

    #[test]
    fn fill_answer_must_match_the_request() {
        let (h, p) = target();
        let ok = "protocol=https\nhost=dev.azure.com\npath=org\nusername=me\npassword=CANARY-1\n";
        let got = parse_fill(ok, &h, &p, None).unwrap();
        assert_eq!(got.credential.secret.expose(), "CANARY-1");
        assert_eq!(got.credential.username.as_deref(), Some("me"));
        for bad in [
            "protocol=https\nhost=github.com\npath=org\npassword=x\n",
            "protocol=https\nhost=dev.azure.com\npath=other\npassword=x\n",
            "protocol=https\nhost=dev.azure.com\npassword=x\n",
            "protocol=http\nhost=dev.azure.com\npath=org\npassword=x\n",
            "password=x\n",
        ] {
            assert_eq!(
                parse_fill(bad, &h, &p, None).unwrap_err(),
                SourceError::Refused(Refusal::WrongTarget),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn fill_answer_checks_the_account_and_the_password() {
        let (h, p) = target();
        let me = AccountName::new("me").unwrap();
        let other = "host=dev.azure.com\npath=org\nusername=you\npassword=x\n";
        assert!(parse_fill(other, &h, &p, Some(&me)).is_err());
        let none = "host=dev.azure.com\npath=org/\nusername=me\npassword=\n";
        assert_eq!(
            parse_fill(none, &h, &p, Some(&me)).unwrap_err(),
            SourceError::NotSignedIn
        );
        let spaced = "host=DEV.azure.com\npath=org\npassword=a b\n";
        assert!(parse_fill(spaced, &h, &p, None).is_ok());
        let ctrl = "host=dev.azure.com\npath=org\npassword=a\u{7}b\n";
        assert_eq!(
            parse_fill(ctrl, &h, &p, None).unwrap_err(),
            SourceError::Refused(Refusal::Malformed)
        );
    }

    #[test]
    fn fill_answer_expiry() {
        let (h, p) = target();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let live = format!(
            "host=dev.azure.com\npath=org\npassword=x\npassword_expiry_utc={}\n",
            now + 3600
        );
        let got = parse_fill(&live, &h, &p, None).unwrap();
        assert!(got.valid_for.unwrap() > Duration::from_secs(3500));
        let dead = "host=dev.azure.com\npath=org\npassword=x\npassword_expiry_utc=5\n";
        assert_eq!(
            parse_fill(dead, &h, &p, None).unwrap_err(),
            SourceError::NotSignedIn
        );
    }

    #[test]
    fn pasted_tokens_are_trimmed_and_checked() {
        assert_eq!(pasted_token("  abc\n").unwrap().expose(), "abc");
        assert!(pasted_token("   ").is_err());
        assert!(pasted_token("a b").is_err());
        assert!(pasted_token("a\nb").is_err());
        assert!(pasted_token(&"a".repeat(9000)).is_err());
    }
}
