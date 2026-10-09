// SPDX-License-Identifier: GPL-3.0-or-later
//! The store's error type.

use puddle_types::{PendingId, RuleId};

use crate::identity::{Collision, IdentityId};

use crate::audit::AuditError;
use crate::pattern::PatternError;
use crate::pending::PendingState;

/// What went wrong in the store. Messages name ids and states, never secret values.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// SQLite failed.
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),
    /// The database was written by a newer puddle; it is never downgraded.
    #[error("database schema version {found} is newer than this puddle supports ({supported})")]
    SchemaTooNew {
        /// The database's version.
        found: u32,
        /// The newest version this build knows.
        supported: u32,
    },
    /// A stored row doesn't parse (edited by hand, or a bug).
    #[error("stored {table} row {id} is invalid: {reason}")]
    Corrupt {
        /// The table, such as `rules` or `pending`.
        table: &'static str,
        /// The row id.
        id: i64,
        /// What doesn't parse.
        reason: String,
    },
    /// No pending row has this id (R-17).
    #[error("no pending request {0}")]
    UnknownPending(PendingId),
    /// The pending row was already decided or expired (R-17).
    #[error("pending request {id} is already {}", state.as_str())]
    PendingNotOpen {
        /// The row.
        id: PendingId,
        /// Its current state.
        state: PendingState,
    },
    /// No rule has this id.
    #[error("no rule {0}")]
    UnknownRule(RuleId),
    /// The pattern was refused.
    #[error(transparent)]
    Pattern(#[from] PatternError),
    /// An expiry that is not in the future.
    #[error("expiry must be in the future")]
    ExpiryNotInFuture,
    /// Rules are made by a user (`cli`, `ui`, `api`), never by `system`.
    #[error("rules can only be created or changed by cli, ui or api")]
    SystemActor,
    /// No rule set has this id (`builtin:<slug>`, `user:<id>`).
    #[error("no rule set {0}")]
    UnknownRuleSet(String),
    /// System managed has no switch: it follows the user's setup (R-40).
    #[error(
        "System managed can't be switched; it follows your setup (add a deny rule to block one of its hosts)"
    )]
    NotSwitchable,
    /// A rule set's name is empty, too long, or already used by another set.
    #[error("rule set name: {0}")]
    RuleSetName(String),
    /// Approving into a set that is off for the request's workspace would not allow it (R-38).
    #[error("rule set {set} is off for {workspace}; switch it on there first")]
    RuleSetOff {
        /// The set.
        set: String,
        /// The workspace.
        workspace: String,
    },
    /// No identity has this id.
    #[error("no identity {0}")]
    UnknownIdentity(IdentityId),
    /// No repository row has this id on this workspace.
    #[error("no repository row {0}")]
    UnknownRepo(i64),
    /// An identity, credential, author or repository was refused; the text says why.
    #[error("{0}")]
    IdentityInvalid(String),
    /// Another identity has this label.
    #[error("another identity is already called {0}")]
    IdentityLabelTaken(String),
    /// Two identities on one workspace cover the same owner or both cover the rest of a host.
    #[error("{0}")]
    IdentityCollision(Collision),
    /// The identity is already on the workspace.
    #[error("{label} is already on this workspace")]
    IdentityAttached {
        /// Its label.
        label: String,
    },
    /// The repository is already in the workspace's table.
    #[error("{0} is already in the repository table")]
    RepoListed(String),
    /// An environment variable, secret or host was refused; the text says why.
    #[error("{0}")]
    EnvInvalid(String),
    /// No such variable in this scope.
    #[error("no variable {name} in {scope}")]
    UnknownEnv {
        /// The scope, in words.
        scope: String,
        /// The variable.
        name: String,
    },
    /// An audit record couldn't be written.
    #[error(transparent)]
    Audit(#[from] AuditError),
}
