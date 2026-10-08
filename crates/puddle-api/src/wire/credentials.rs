// SPDX-License-Identifier: GPL-3.0-or-later
//! What the identities screens ask the host about credentials (credentials spec §3, §8): the
//! accounts already signed in on this computer, whether puddle can read one now, a pasted token
//! (write-only), and signing in on a click. No response carries a secret value, and the one request
//! that carries one never echoes it.

use puddle_secrets::{
    DiscoveredAccount, HostName, Listing, OrgName, SignInStart, SourceError, TokenScope,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::identities::CredentialSource;
use crate::error::ApiError;

/// Which listing found an account.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum FoundVia {
    /// The GitHub CLI (`gh auth status`).
    Gh,
    /// Git Credential Manager's GitHub accounts.
    GcmGithub,
    /// Git Credential Manager's Azure DevOps accounts.
    GcmAzureRepos,
}

impl FoundVia {
    pub(crate) fn from_listing(listing: Listing) -> Self {
        match listing {
            Listing::GhAuthStatus => Self::Gh,
            Listing::GcmGithub => Self::GcmGithub,
            // `Listing` grows with the Azure CLI; an unknown listing is shown as the nearest one.
            _ => Self::GcmAzureRepos,
        }
    }
}

/// An account that is already signed in on this computer. Names only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct FoundAccount {
    /// Which tool knows it.
    pub via: FoundVia,
    /// The Git host.
    pub host: String,
    /// The account.
    pub account: String,
    /// The Azure DevOps organisation the account is bound to, when the listing says.
    #[schema(required = true)]
    pub org: Option<String>,
    /// False when the tool lists the account but its token no longer works.
    pub signed_in: bool,
}

impl FoundAccount {
    pub(crate) fn from_discovered(account: &DiscoveredAccount) -> Self {
        Self {
            via: FoundVia::from_listing(account.via),
            host: account.host.to_string(),
            account: account.account.to_string(),
            org: account.org.as_ref().map(ToString::to_string),
            signed_in: account.signed_in,
        }
    }
}

/// A listing that could not run, so its accounts are missing from the list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct FoundProblem {
    /// Which tool.
    pub via: FoundVia,
    /// Why, in words ("gh is not installed or not on PATH").
    pub message: String,
}

/// What puddle found signed in on this computer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct FoundAccounts {
    /// The accounts, without duplicates.
    pub accounts: Vec<FoundAccount>,
    /// The listings that could not run.
    pub problems: Vec<FoundProblem>,
}

/// A credential to try.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CheckRequest {
    /// Where its value comes from.
    pub source: CredentialSource,
}

/// Whether puddle can read a credential's value now. Never the value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct CheckResult {
    /// True when the source gave a value.
    pub readable: bool,
    /// Why not, in words; `null` when it is readable.
    #[schema(required = true)]
    pub problem: Option<String>,
    /// True when the way out is for the user to sign in.
    pub needs_sign_in: bool,
}

impl CheckResult {
    pub(crate) const fn readable() -> Self {
        Self {
            readable: true,
            problem: None,
            needs_sign_in: false,
        }
    }

    pub(crate) fn from_error(err: &SourceError) -> Self {
        Self {
            readable: false,
            problem: Some(source_problem(err)),
            needs_sign_in: err.needs_sign_in(),
        }
    }
}

/// A source's refusal in words the user can act on.
pub(crate) fn source_problem(err: &SourceError) -> String {
    match err {
        SourceError::NotSignedIn => "not signed in, or the sign-in has expired".to_owned(),
        SourceError::Timeout(tool) => format!(
            "{} did not answer in time; it may be waiting for a sign-in",
            tool.name()
        ),
        other => other.to_string(),
    }
}

/// A token the user pasted. It is kept in the operating system's credential store under puddle's
/// own name and never read back through the API.
#[derive(Clone, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct StoreTokenRequest {
    /// The Git host the token is for.
    pub host: String,
    /// The organisation, for tokens that belong to one (Azure DevOps).
    #[serde(default)]
    #[schema(required = false)]
    pub org: Option<String>,
    /// The token. Write-only.
    #[schema(format = Password, write_only)]
    pub token: String,
}

impl StoreTokenRequest {
    /// What the token is for, and the token.
    pub(crate) fn into_parts(self) -> Result<(TokenScope, String), ApiError> {
        let host = HostName::new(self.host).map_err(|_| ApiError::invalid("not a valid host"))?;
        let org = self
            .org
            .map(OrgName::new)
            .transpose()
            .map_err(|_| ApiError::invalid("not a valid organisation"))?;
        Ok((TokenScope { host, org }, self.token))
    }
}

impl std::fmt::Debug for StoreTokenRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoreTokenRequest")
            .field("host", &self.host)
            .field("org", &self.org)
            .field("token", &"<redacted>")
            .finish()
    }
}

/// Where a stored token went: the source to put in a credential.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct StoredToken {
    /// A `stored` source naming the new entry.
    pub source: CredentialSource,
}

/// A sign-in to start.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SignInRequest {
    /// The credential to sign in to.
    pub source: CredentialSource,
}

/// What the user does to finish a sign-in puddle started. Poll the credential's check to learn
/// when it worked; puddle ends a sign-in nobody finished after five minutes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SignInStarted {
    /// The one-time code to type at `url`; `null` when the tool opens its own window.
    #[schema(required = true)]
    pub code: Option<String>,
    /// Where to type it; `null` when the tool opens its own window.
    #[schema(required = true)]
    pub url: Option<String>,
}

impl From<SignInStart> for SignInStarted {
    fn from(start: SignInStart) -> Self {
        Self {
            code: start.code,
            url: start.url,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use puddle_secrets::Tool;

    #[test]
    fn a_pasted_token_never_shows_in_debug_output() {
        let request: StoreTokenRequest =
            serde_json::from_str(r#"{"host":"github.com","token":"CANARY-9"}"#).unwrap();
        assert!(!format!("{request:?}").contains("CANARY-9"));
        assert!(format!("{request:?}").contains("<redacted>"));
        assert!(
            serde_json::from_str::<StoreTokenRequest>(r#"{"host":"h","token":"t","extra":1}"#)
                .is_err()
        );
    }

    #[test]
    fn problems_are_worded_for_the_user() {
        let text = |e: SourceError| CheckResult::from_error(&e);
        let not_signed_in = text(SourceError::NotSignedIn);
        assert!(not_signed_in.needs_sign_in);
        assert_eq!(
            not_signed_in.problem.as_deref(),
            Some("not signed in, or the sign-in has expired")
        );
        let slow = text(SourceError::Timeout(Tool::Git));
        assert!(slow.needs_sign_in);
        assert!(slow.problem.unwrap().contains("git did not answer in time"));
        let missing = text(SourceError::ToolMissing(Tool::Gh));
        assert!(!missing.needs_sign_in);
        assert_eq!(
            missing.problem.as_deref(),
            Some("gh is not installed or not on PATH")
        );
        assert!(CheckResult::readable().readable);
    }
}
