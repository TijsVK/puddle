// SPDX-License-Identifier: GPL-3.0-or-later
//! Environment variables and secrets, global or for one workspace
//! (`docs/arch/spec/credentials.md` §9).
//!
//! A plain variable's value is stored here and goes into the workspace's environment at its next
//! start. A secret's value is **not** stored here: this crate keeps only the id the operating
//! system's credential store files it under, the hosts it is for and, per workspace, the stand-in
//! the workspace holds instead of the value.

use std::collections::BTreeSet;
use std::fmt;

use puddle_secrets::StoredId;
use puddle_types::WorkspaceName;
use serde::{Deserialize, Serialize};

use crate::error::StoreError;
use crate::pattern::Pattern;

/// The longest variable name.
pub const MAX_NAME_LEN: usize = 64;
/// The longest value of a plain variable, in bytes.
pub const MAX_PLAIN_VALUE_BYTES: usize = 16 * 1024;
/// The longest value of a secret, in characters: a header value (servers refuse lines past about
/// 8 KiB) and, once the credential store holds it in pieces, no platform's own limit.
pub const MAX_SECRET_VALUE_CHARS: usize = 8 * 1024;
/// The most variables one scope holds.
pub const MAX_ENTRIES_PER_SCOPE: usize = 256;
/// The most bytes of names and plain values one scope holds, so the environment of a process
/// stays far below what a kernel accepts (2 MiB with the arguments) with the global scope and
/// puddle's own variables on top.
pub const MAX_SCOPE_BYTES: usize = 256 * 1024;
/// The most hosts one secret lists.
pub const MAX_SECRET_HOSTS: usize = 32;

/// Names puddle sets in every workspace for the proxy and the trust of its CA. A workspace whose
/// tools read these still routes through puddle, so the user's value would only break that; the
/// user's `JAVA_TOOL_OPTIONS`, `MAVEN_ARGS`, `GRADLE_USER_HOME` and `DOCKER_CONFIG` are not here
/// because puddle adds to them instead of replacing them. A test in `puddle-host` compares this
/// list with what the guest is actually given.
pub const PUDDLE_OWNED_NAMES: [&str; 18] = [
    "CARGO_NET_GIT_FETCH_WITH_CLI",
    "CURL_CA_BUNDLE",
    "ELECTRON_GET_USE_PROXY",
    "GLOBAL_AGENT_HTTPS_PROXY",
    "GLOBAL_AGENT_HTTP_PROXY",
    "GLOBAL_AGENT_NO_PROXY",
    "HTTPS_PROXY",
    "HTTP_PROXY",
    "NODE_EXTRA_CA_CERTS",
    "NODE_USE_ENV_PROXY",
    "NO_PROXY",
    "REQUESTS_CA_BUNDLE",
    "SSL_CERT_FILE",
    "YARN_HTTPS_PROXY",
    "YARN_HTTP_PROXY",
    "http_proxy",
    "https_proxy",
    "no_proxy",
];

/// Where an entry applies.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum EnvScope {
    /// Every workspace; a workspace's own entry of the same name wins.
    Global,
    /// One workspace.
    Workspace(WorkspaceName),
}

impl EnvScope {
    /// The workspace, or `None` for the global scope.
    #[must_use]
    pub fn workspace(&self) -> Option<&WorkspaceName> {
        match self {
            Self::Global => None,
            Self::Workspace(name) => Some(name),
        }
    }

    /// The column value: the workspace's name, or `None` for global.
    pub(crate) fn column(&self) -> Option<&str> {
        self.workspace().map(WorkspaceName::as_str)
    }
}

impl fmt::Display for EnvScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Global => f.write_str("the global environment"),
            Self::Workspace(name) => write!(f, "{name}'s environment"),
        }
    }
}

fn invalid(what: impl Into<String>) -> StoreError {
    StoreError::EnvInvalid(what.into())
}

/// The name of an environment variable: a shell identifier of at most 64 characters, not one
/// puddle sets itself.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct EnvName(String);

impl EnvName {
    /// Checks a name.
    ///
    /// # Errors
    /// [`StoreError::EnvInvalid`] for an empty, long or odd name, a name starting `PUDDLE_`, `PATH`,
    /// or a name puddle sets in every workspace ([`PUDDLE_OWNED_NAMES`]); the text says which.
    pub fn new(name: &str) -> Result<Self, StoreError> {
        if name.is_empty() {
            return Err(invalid("a variable needs a name"));
        }
        if name.len() > MAX_NAME_LEN {
            return Err(invalid(format!(
                "a variable name is at most {MAX_NAME_LEN} characters"
            )));
        }
        let mut chars = name.chars();
        let first_ok = chars
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_');
        if !first_ok || !chars.all(|c| c.is_ascii_alphanumeric() || c == '_') {
            return Err(invalid(format!(
                "{name:?} is not a variable name: letters, digits and _, not starting with a digit"
            )));
        }
        if name.starts_with("PUDDLE_") {
            return Err(invalid(format!(
                "{name} is reserved: names starting PUDDLE_ belong to puddle"
            )));
        }
        if name == "PATH" {
            return Err(invalid(
                "PATH comes from the workspace's image; puddle does not replace it".to_owned(),
            ));
        }
        if PUDDLE_OWNED_NAMES.contains(&name) {
            return Err(invalid(format!(
                "puddle sets {name} in every workspace so its tools use puddle's proxy and trust its certificate"
            )));
        }
        Ok(Self(name.to_owned()))
    }

    /// A name that is already stored, to find or remove it: only the shape is checked. A release
    /// that later owns a name an earlier one let through must not make that variable unlistable
    /// or unremovable; at start puddle's own value wins over a stored one of the same name.
    ///
    /// # Errors
    /// [`StoreError::EnvInvalid`] when it is not shaped like a variable name.
    pub fn existing(name: &str) -> Result<Self, StoreError> {
        let mut chars = name.chars();
        let shaped = !name.is_empty()
            && name.len() <= MAX_NAME_LEN
            && chars
                .next()
                .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
            && chars.all(|c| c.is_ascii_alphanumeric() || c == '_');
        if shaped {
            Ok(Self(name.to_owned()))
        } else {
            Err(invalid(format!("{name:?} is not a variable name")))
        }
    }

    /// The name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for EnvName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for EnvName {
    type Error = StoreError;
    fn try_from(value: String) -> Result<Self, StoreError> {
        Self::new(&value)
    }
}

impl From<EnvName> for String {
    fn from(name: EnvName) -> Self {
        name.0
    }
}

/// A host a secret may be sent to: an exact name, or `*.` and a name for every name below it.
/// Lower-case. The same rules as the proxy applies to a stand-in's hosts (a test in
/// `puddle-host` keeps them equal): names only, never an address or a port, and a pattern over a
/// domain anyone can register a name under (`*.github.io`, `*.co.uk`) is refused, because the
/// real value would go to whoever registers one.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct SecretHost(String);

impl SecretHost {
    /// Checks a host.
    ///
    /// # Errors
    /// [`StoreError::EnvInvalid`]; the text says why.
    pub fn new(text: &str) -> Result<Self, StoreError> {
        let text = text.trim();
        // A `.` prefix is rule syntax; a secret's host list has one spelling.
        if text.starts_with('.') || text.contains(['/', ':', '@', ' ']) {
            return Err(invalid(format!(
                "{text:?} is not a host name: give a name such as api.example.com, or *.example.com for every name below it; puddle decrypts port 443 only"
            )));
        }
        let lower = text.to_ascii_lowercase();
        let pattern = Pattern::parse(&lower).map_err(|err| match err {
            crate::pattern::PatternError::PublicSuffix(base) => invalid(format!(
                "*.{base} covers names anyone can register; list the exact hosts instead"
            )),
            other => invalid(format!("{text:?} is not a usable host: {other}")),
        })?;
        match pattern {
            Pattern::Exact(host) => match host {
                puddle_types::Host::Name(name) => Ok(Self(name.to_string())),
                puddle_types::Host::Ip(_) => Err(invalid(format!(
                    "{text:?} is an address; give a host name (certificates are for names)"
                ))),
            },
            Pattern::Suffix(suffix) => Ok(Self(format!("*.{}", suffix.base()))),
        }
    }

    /// Checks every host of a secret's list: at least one, at most 32, no repeats, sorted.
    ///
    /// # Errors
    /// [`StoreError::EnvInvalid`] for the first host that is refused, or for a list that is empty or
    /// too long.
    pub fn list<S: AsRef<str>>(hosts: &[S]) -> Result<Vec<Self>, StoreError> {
        checked_hosts(
            hosts
                .iter()
                .map(|h| Self::new(h.as_ref()))
                .collect::<Result<_, _>>()?,
        )
    }

    /// The host as stored: `name` or `*.name`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SecretHost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for SecretHost {
    type Error = StoreError;
    fn try_from(value: String) -> Result<Self, StoreError> {
        Self::new(&value)
    }
}

impl From<SecretHost> for String {
    fn from(host: SecretHost) -> Self {
        host.0
    }
}

/// Checks the value of a secret before it goes to the credential store: from 1 to
/// [`MAX_SECRET_VALUE_CHARS`] characters with no control character, because the proxy puts the
/// value into a request header, and anything a header cannot carry would only fail later in a
/// tool. The message never quotes the value.
///
/// # Errors
/// [`StoreError::EnvInvalid`]; the text says why.
pub fn check_secret_value(value: &str) -> Result<(), StoreError> {
    if value.is_empty() {
        return Err(invalid("a secret's value can't be empty"));
    }
    if value.chars().count() > MAX_SECRET_VALUE_CHARS {
        return Err(invalid(format!(
            "a secret's value is at most {MAX_SECRET_VALUE_CHARS} characters"
        )));
    }
    if value.chars().any(char::is_control) {
        return Err(invalid(
            "a secret's value can't contain a line break or another control character: it is sent in a request header",
        ));
    }
    Ok(())
}

/// The hosts of a secret: at least one, no repeats, sorted.
pub(crate) fn checked_hosts(hosts: Vec<SecretHost>) -> Result<Vec<SecretHost>, StoreError> {
    let unique: BTreeSet<SecretHost> = hosts.into_iter().collect();
    if unique.is_empty() {
        return Err(invalid(
            "a secret needs at least one host it may be sent to; without one it would be worth nothing anywhere",
        ));
    }
    if unique.len() > MAX_SECRET_HOSTS {
        return Err(invalid(format!(
            "a secret lists at most {MAX_SECRET_HOSTS} hosts"
        )));
    }
    Ok(unique.into_iter().collect())
}

/// What a secret keeps in the store: where its value is, and where it may go. Never the value.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct EnvSecret {
    /// The id the value is filed under in the operating system's credential store.
    pub id: StoredId,
    /// The hosts the real value may be sent to, sorted.
    pub hosts: Vec<SecretHost>,
}

/// A variable's value as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvValue {
    /// The workspace gets this value.
    Plain(String),
    /// The workspace gets a stand-in; the real value is added on the way out.
    Secret(EnvSecret),
}

/// What to store under a name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvDraft {
    /// A plain variable.
    Plain(String),
    /// A secret whose value is already in the credential store under `id`.
    Secret {
        /// Where the value is.
        id: StoredId,
        /// Where it may go.
        hosts: Vec<SecretHost>,
    },
}

impl EnvDraft {
    /// A plain variable with `value`.
    ///
    /// # Errors
    /// [`StoreError::EnvInvalid`] for a value with a NUL or longer than [`MAX_PLAIN_VALUE_BYTES`].
    pub fn plain(value: &str) -> Result<Self, StoreError> {
        if value.contains('\0') {
            return Err(invalid("a value can't contain a NUL character"));
        }
        if value.len() > MAX_PLAIN_VALUE_BYTES {
            return Err(invalid(format!(
                "a value is at most {MAX_PLAIN_VALUE_BYTES} bytes"
            )));
        }
        Ok(Self::Plain(value.to_owned()))
    }

    /// A secret under `id` for `hosts`.
    ///
    /// # Errors
    /// [`StoreError::EnvInvalid`] for no host, or too many.
    pub fn secret(id: StoredId, hosts: Vec<SecretHost>) -> Result<Self, StoreError> {
        Ok(Self::Secret {
            id,
            hosts: checked_hosts(hosts)?,
        })
    }
}

/// One variable as the store holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct EnvEntry {
    /// The row's number.
    pub id: i64,
    /// Where it applies.
    pub scope: EnvScope,
    /// Its name.
    pub name: EnvName,
    /// Its value, or where a secret's is.
    pub value: EnvValue,
    /// When it last changed, epoch ms.
    pub changed_at: u64,
}

/// What changing an entry did.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct EnvChange {
    /// The entry now.
    pub entry: EnvEntry,
    /// The entry it replaced, if the name was set. When this one was a secret under another id
    /// than `entry`'s, its value is no longer referenced: the caller removes it from the
    /// credential store.
    pub replaced: Option<EnvEntry>,
}

/// One entry in a workspace's view, with whether a workspace entry of the same name hides it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct EnvRow {
    /// The entry.
    pub entry: EnvEntry,
    /// A global entry that the workspace's own entry of the same name hides.
    pub overridden: bool,
}

/// A variable a workspace starts with, its secrets already given their stand-in.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct StartVar {
    /// The name.
    pub name: EnvName,
    /// What it is.
    pub value: StartValue,
}

/// What a workspace gets for a name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartValue {
    /// This text.
    Plain(String),
    /// The stand-in; the real value is under `id` in the credential store.
    Secret {
        /// Where the real value is.
        id: StoredId,
        /// The hosts it may be swapped in toward.
        hosts: Vec<SecretHost>,
        /// What the workspace holds instead.
        stand_in: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_shell_identifiers_that_puddle_does_not_own() {
        for ok in [
            "A",
            "_x",
            "NPM_TOKEN",
            "a1",
            "JAVA_TOOL_OPTIONS",
            "MAVEN_ARGS",
        ] {
            assert!(EnvName::new(ok).is_ok(), "{ok}");
        }
        for bad in ["", "1A", "A-B", "A B", "A=B", "ä", &"A".repeat(65)] {
            assert!(EnvName::new(bad).is_err(), "{bad:?}");
        }
        assert!(EnvName::new(&"A".repeat(64)).is_ok());
    }

    #[test]
    fn a_name_puddle_owns_is_refused_with_the_reason() {
        for name in PUDDLE_OWNED_NAMES {
            let err = EnvName::new(name).unwrap_err().to_string();
            assert!(err.contains("puddle sets"), "{name}: {err}");
        }
        assert!(
            EnvName::new("PUDDLE_ROOT")
                .unwrap_err()
                .to_string()
                .contains("PUDDLE_")
        );
        assert!(
            EnvName::new("PATH")
                .unwrap_err()
                .to_string()
                .contains("image")
        );
    }

    #[test]
    fn the_owned_names_are_sorted_and_unique() {
        let mut sorted = PUDDLE_OWNED_NAMES;
        sorted.sort_unstable();
        assert_eq!(sorted, PUDDLE_OWNED_NAMES);
        let all: BTreeSet<_> = PUDDLE_OWNED_NAMES.into_iter().collect();
        assert_eq!(all.len(), PUDDLE_OWNED_NAMES.len());
    }

    #[test]
    fn hosts_are_names_or_wildcards_in_lower_case() {
        for (given, stored) in [
            ("API.Example.com", "api.example.com"),
            ("*.example.com", "*.example.com"),
            (" github.com ", "github.com"),
            ("*.visualstudio.com", "*.visualstudio.com"),
        ] {
            assert_eq!(SecretHost::new(given).unwrap().as_str(), stored, "{given}");
        }
    }

    #[test]
    fn a_host_that_is_not_a_plain_name_is_refused_with_a_reason() {
        for bad in [
            "",
            "10.0.0.1",
            "[::1]",
            "api.example.com:8443",
            "https://example.com",
            "example.com/path",
            "user@example.com",
            ".example.com",
            "*.com",
            "*.co.uk",
            "*.github.io",
            "a b.example.com",
            "*",
        ] {
            assert!(SecretHost::new(bad).is_err(), "{bad:?}");
        }
        let shared = SecretHost::new("*.github.io").unwrap_err().to_string();
        assert!(shared.contains("anyone can register"), "{shared}");
        let address = SecretHost::new("10.0.0.1").unwrap_err().to_string();
        assert!(address.contains("host name"), "{address}");
    }

    #[test]
    fn a_secret_needs_hosts_and_they_are_sorted_without_repeats() {
        let id = StoredId::new("env-1").unwrap();
        assert!(EnvDraft::secret(id.clone(), Vec::new()).is_err());
        let hosts = ["b.example.com", "a.example.com", "b.example.com"]
            .map(|h| SecretHost::new(h).unwrap())
            .to_vec();
        let EnvDraft::Secret { hosts, .. } = EnvDraft::secret(id.clone(), hosts).unwrap() else {
            panic!("a secret")
        };
        assert_eq!(
            hosts.iter().map(SecretHost::as_str).collect::<Vec<_>>(),
            ["a.example.com", "b.example.com"]
        );
        let many = (0..=MAX_SECRET_HOSTS)
            .map(|i| SecretHost::new(&format!("h{i}.example.com")).unwrap())
            .collect();
        assert!(EnvDraft::secret(id, many).is_err());
    }

    #[test]
    fn a_plain_value_is_any_text_without_a_nul_up_to_the_limit() {
        assert!(EnvDraft::plain("").is_ok());
        assert!(EnvDraft::plain("a b\n'c' $d").is_ok());
        assert!(EnvDraft::plain("a\0b").is_err());
        assert!(EnvDraft::plain(&"x".repeat(MAX_PLAIN_VALUE_BYTES)).is_ok());
        assert!(EnvDraft::plain(&"x".repeat(MAX_PLAIN_VALUE_BYTES + 1)).is_err());
    }

    #[test]
    fn a_secret_value_is_header_text_of_a_sensible_length_and_the_message_never_quotes_it() {
        assert!(check_secret_value("ghp_abcDEF123").is_ok());
        assert!(check_secret_value("pass word with spaces and ünïcode").is_ok());
        assert!(check_secret_value(&"x".repeat(MAX_SECRET_VALUE_CHARS)).is_ok());
        for bad in [
            "".to_owned(),
            "x".repeat(MAX_SECRET_VALUE_CHARS + 1),
            "SECRET\nline2".to_owned(),
            "SECRET\tTAB".to_owned(),
            "SECRET\u{7f}DEL".to_owned(),
            "SECRET\u{85}NEL".to_owned(),
            "SECRET\0NUL".to_owned(),
        ] {
            let err = check_secret_value(&bad).unwrap_err().to_string();
            assert!(!err.contains("SECRET"), "{err}");
            assert!(!bad.is_empty() || err.contains("empty"), "{err}");
        }
    }

    #[test]
    fn scopes_read_aloud_and_name_their_workspace() {
        let ws = WorkspaceName::new("shop").unwrap();
        assert_eq!(EnvScope::Global.to_string(), "the global environment");
        assert_eq!(
            EnvScope::Workspace(ws.clone()).to_string(),
            "shop's environment"
        );
        assert_eq!(EnvScope::Workspace(ws.clone()).workspace(), Some(&ws));
        assert_eq!(EnvScope::Global.column(), None);
    }

    #[test]
    fn names_and_hosts_survive_json_only_when_valid() {
        let name: EnvName = serde_json::from_str("\"NPM_TOKEN\"").unwrap();
        assert_eq!(serde_json::to_string(&name).unwrap(), "\"NPM_TOKEN\"");
        assert!(serde_json::from_str::<EnvName>("\"PATH\"").is_err());
        let host: SecretHost = serde_json::from_str("\"*.example.com\"").unwrap();
        assert_eq!(serde_json::to_string(&host).unwrap(), "\"*.example.com\"");
        assert!(serde_json::from_str::<SecretHost>("\"*.com\"").is_err());
    }
}
