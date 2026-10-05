// SPDX-License-Identifier: GPL-3.0-or-later
//! The store's error type.

use puddle_types::{PendingId, RuleId};

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
        /// `rules` or `pending`.
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
    /// An audit record couldn't be written.
    #[error(transparent)]
    Audit(#[from] AuditError),
}
