// SPDX-License-Identifier: GPL-3.0-or-later
//! Storage and rules engine: SQLite schema and migrations, rules with expiry, pending requests,
//! the audit log and the sweeper. The behaviour is specified rule by rule in
//! `docs/spec/rules.md`; the tests named `rNN_*` pin each rule.
//!
//! The proxy asks for decisions through [`puddle_types::Policy`], which [`Store`] implements.
#![forbid(unsafe_code)]

mod audit;
mod catalogue;
mod clock;
mod engine;
mod error;
mod identity;
mod pattern;
mod pending;
mod ratelimit;
mod rule;
mod schema;
mod store;
mod sweeper;
mod workspace_git;

pub use audit::{
    AuditError, AuditOutcome, AuditRecord, ConnectionRecord, MAX_FIELD_BYTES, MAX_LINE_BYTES,
    PendingExpiryReason, PendingWire, RuleDeleteReason, RuleSetWire, RuleWire,
};
pub use catalogue::{BUILT_IN_SETS, BuiltInSet, CatalogueEntry, SystemReason, built_in};
pub use clock::{Clock, ManualClock, SystemClock};
pub use error::StoreError;
pub use identity::{
    Author, Collision, CollisionWhat, Coverage, CredentialBinding, CredentialChoice, Identity,
    IdentityDraft, IdentityId, MAX_CREDENTIALS, Owner, Signing, check_attachable, collision,
    resolve,
};
pub use pattern::{Pattern, PatternError, SuffixPattern, registrable_domain};
pub use pending::{
    Decided, InboxGroup, PatternChoice, PendingRow, PendingState, Resolution, ScopeChoice,
    Suppression,
};
pub use rule::{Actor, Effect, NewRule, Rule, Scope};
pub use schema::SCHEMA_VERSION;
pub use store::{
    AuditCursor, AuditFilter, Limits, RuleSetEntryInfo, RuleSetInfo, Store, SweepReport,
    SystemHost, SystemPlan, WorkspaceDeletion, parse_rule_set,
};
pub use sweeper::{DEFAULT_SWEEP_PERIOD, Sweeper};
pub use workspace_git::{RepoEntry, RepoRef, WorkspaceGit};
