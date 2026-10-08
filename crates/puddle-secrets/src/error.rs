// SPDX-License-Identifier: GPL-3.0-or-later
//! Why a source could not supply a secret. No variant carries a secret or tool output.

/// A tool puddle runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Tool {
    /// The GitHub CLI.
    Gh,
    /// Git (and through it, Git Credential Manager).
    Git,
}

impl Tool {
    /// The name the user knows it by.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Gh => "gh",
            Self::Git => "git",
        }
    }
}

/// Why a secret could not be read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SourceError {
    /// Nothing is signed in for this source, or its login expired. The user must sign in from
    /// puddle; a request never does it.
    #[error("not signed in")]
    NotSignedIn,
    /// The tool is not installed or not on `PATH`.
    #[error("{} is not installed or not on PATH", .0.name())]
    ToolMissing(Tool),
    /// The tool exists but could not be run (not permitted, or it died).
    #[error("{} could not be run", .0.name())]
    CouldNotRun(Tool),
    /// The tool did not answer in time (it may be waiting for a sign-in window).
    #[error("{} did not answer in time", .0.name())]
    Timeout(Tool),
    /// The tool answered, but the answer was not used.
    #[error("the answer was not used: {0}")]
    Refused(Refusal),
    /// The OS credential store is not available.
    #[error("the OS credential store is not available")]
    StoreUnavailable,
}

/// Why an answer was not used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Refusal {
    /// The credential helper answered for another host or path than the one asked for.
    #[error("it was for another host or path")]
    WrongTarget,
    /// The token has characters a header cannot carry, or is too long.
    #[error("the value is not a usable token")]
    Malformed,
    /// The tool answered something this version cannot read.
    #[error("unreadable answer")]
    Unreadable,
}

impl SourceError {
    /// True when the fix is for the user to sign in (so the proxy answers 502 and the UI shows a
    /// "Sign in" notice), false when something is broken or missing.
    #[must_use]
    pub fn needs_sign_in(&self) -> bool {
        matches!(self, Self::NotSignedIn | Self::Timeout(_))
    }
}
