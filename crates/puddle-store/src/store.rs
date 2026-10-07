// SPDX-License-Identifier: GPL-3.0-or-later
//! The SQLite-backed store: rules, pending requests, audit, sweeper work.
//!
//! Decisions read an in-memory [`RuleSet`] snapshot without touching SQLite unless no rule
//! matches. Every change commits to SQLite first and then swaps in a new snapshot built inside
//! the same transaction (R-8). Lock order, where two are held: `conn`, then `sandboxes`.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, RwLock};
use std::time::Duration;

use puddle_types::{
    ConnectionEvent, ConnectionLog, ConnectionOrigin, Decision, EgressRequest, Event, EventSink,
    Host, NullSink, PendingEnd, PendingId, PendingOutcome, PendingSummary, Policy, PolicyError,
    RuleId, SandboxName, SuffixAllows,
};
use rusqlite::{Connection, OptionalExtension, Row, Transaction, params};

use crate::audit::{
    AuditOutcome, AuditRecord, ConnectionRecord, ConnectionWindow, PendingExpiryReason,
    PendingWire, RuleDeleteReason, RuleWire, actor_str,
};
use crate::clock::Clock;
use crate::engine::RuleSet;
use crate::error::StoreError;
use crate::pattern::{Pattern, SuffixPattern, registrable_domain};
use crate::pending::{
    Decided, InboxGroup, PatternChoice, PendingRow, PendingState, Resolution, ScopeChoice,
    Suppression,
};
use crate::ratelimit::TokenBucket;
use crate::rule::{Actor, Effect, NewRule, Rule, Scope};
use crate::schema;

/// Tunable limits. The defaults are the spec's *(default)* values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Limits {
    /// New pending rows a sandbox may open in a burst (R-13).
    pub new_rows_burst: u32,
    /// One more new row allowed per this many ms (R-13).
    pub new_rows_refill_ms: u64,
    /// Most open rows per sandbox (R-13).
    pub max_open_rows: u64,
    /// A `pending_suppressed` record at most this often while suppression lasts (R-13).
    pub suppressed_record_every_ms: u64,
    /// Open rows with no repeat for this long expire (R-20).
    pub pending_stale_after_ms: u64,
    /// The audit is trimmed when its lines exceed this many bytes (R-26).
    pub audit_max_bytes: u64,
    /// A trim deletes the oldest records until this many bytes remain.
    pub audit_trim_to_bytes: u64,
    /// `connection` records per sandbox per second (R-26).
    pub connection_records_per_second: u32,
}

impl Default for Limits {
    fn default() -> Self {
        const MIB: u64 = 1024 * 1024;
        Self {
            new_rows_burst: 60,
            new_rows_refill_ms: 1000,
            max_open_rows: 500,
            suppressed_record_every_ms: 60_000,
            pending_stale_after_ms: 7 * 24 * 60 * 60 * 1000,
            audit_max_bytes: 256 * MIB,
            audit_trim_to_bytes: 230 * MIB,
            connection_records_per_second: 200,
        }
    }
}

/// Which audit records to read. Every field left `None` matches everything; the set
/// ones all have to match.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuditFilter {
    /// Records about this sandbox.
    pub sandbox: Option<SandboxName>,
    /// Records of this `type` (one of [`AuditRecord::KINDS`]).
    pub kind: Option<&'static str>,
    /// Records with this outcome. Records that have none never match.
    pub outcome: Option<AuditOutcome>,
    /// `connection` records with this origin; other records have none and never match.
    pub origin: Option<ConnectionOrigin>,
    /// Records whose host (or a rule's pattern) contains this text, compared case-folded.
    pub host_contains: Option<String>,
    /// Records at or after this epoch ms.
    pub from: Option<u64>,
    /// Records before this epoch ms.
    pub to: Option<u64>,
}

/// Where a page of audit records starts and which way it runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditCursor {
    /// Oldest first, from the record after this id (for following the log's tail).
    After(i64),
    /// Newest first, from the record before this id, or from the newest (for paging back).
    Before(Option<i64>),
}

/// What one sweep did (R-19 to R-22).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SweepReport {
    /// Expired rules deleted.
    pub rules_expired: u64,
    /// Stale pending rows expired.
    pub pending_expired: u64,
    /// Audit records deleted by the size cap.
    pub audit_records_trimmed: u64,
}

/// What deleting a sandbox removed (R-21).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SandboxDeletion {
    /// Its rules, deleted.
    pub rules_deleted: u64,
    /// Its open pending rows, expired.
    pub pending_expired: u64,
}

/// The least time between two [`Event::SuppressionChanged`] for a growing count.
const SUPPRESSION_EVENT_EVERY_MS: u64 = 500;

/// Per-sandbox in-memory limits state (R-13, R-26). Lost on restart, which only resets the
/// limits.
#[derive(Debug)]
struct SandboxState {
    bucket: TokenBucket,
    suppressing: bool,
    episode: u64,
    unrecorded: u64,
    last_record_at: u64,
    last_event_at: u64,
    connections: ConnectionWindow,
}

impl SandboxState {
    fn new(limits: &Limits, now: u64) -> Self {
        Self {
            bucket: TokenBucket::new(limits.new_rows_burst, limits.new_rows_refill_ms, now),
            suppressing: false,
            episode: 0,
            unrecorded: 0,
            last_record_at: 0,
            last_event_at: 0,
            connections: ConnectionWindow::default(),
        }
    }

    /// Counts one suppressed request; returns a count to record when suppression starts or the
    /// record interval has passed.
    fn suppress(&mut self, now: u64, every: u64) -> Option<u64> {
        if !self.suppressing {
            self.suppressing = true;
            self.episode = 0;
        }
        self.episode += 1;
        self.unrecorded += 1;
        if self.episode == 1 || now.saturating_sub(self.last_record_at) >= every {
            self.last_record_at = now;
            return Some(std::mem::take(&mut self.unrecorded));
        }
        None
    }

    /// Ends a suppression episode; returns the count not yet recorded.
    fn end_suppression(&mut self) -> Option<u64> {
        if !self.suppressing {
            return None;
        }
        self.suppressing = false;
        Some(std::mem::take(&mut self.unrecorded)).filter(|n| *n > 0)
    }

    /// The count not yet recorded, if the record interval has passed.
    fn flush_due(&mut self, now: u64, every: u64) -> Option<u64> {
        if self.unrecorded > 0 && now.saturating_sub(self.last_record_at) >= every {
            self.last_record_at = now;
            return Some(std::mem::take(&mut self.unrecorded));
        }
        None
    }
}

/// puddle's rules, pending requests and audit log, in one SQLite database.
pub struct Store {
    conn: Mutex<Connection>,
    rules: RwLock<Arc<RuleSet>>,
    sandboxes: Mutex<HashMap<SandboxName, SandboxState>>,
    /// The connection limit of puddle's own connections, which have no sandbox.
    puddle_connections: Mutex<ConnectionWindow>,
    clock: Arc<dyn Clock>,
    limits: Limits,
    events: Arc<dyn EventSink>,
}

impl std::fmt::Debug for Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Store")
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    // A panic while holding the lock can't leave SQLite half-written (the transaction rolls
    // back on drop), and the other guarded state is counters, so carry on.
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Epoch ms as SQLite stores it. Times past year 292 million saturate.
fn sql_ts(ms: u64) -> i64 {
    i64::try_from(ms).unwrap_or(i64::MAX)
}

fn plus(now: u64, duration: Duration) -> u64 {
    now.saturating_add(u64::try_from(duration.as_millis()).unwrap_or(u64::MAX))
}

impl Store {
    /// Opens (creating if needed) the database at `path` and migrates it.
    ///
    /// # Errors
    /// [`StoreError`] if the file can't be opened, is from a newer puddle, or holds invalid rows.
    pub fn open(path: &Path, clock: Arc<dyn Clock>, limits: Limits) -> Result<Self, StoreError> {
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "journal_mode", "wal")?;
        conn.pragma_update(None, "synchronous", "normal")?;
        Self::init(conn, clock, limits)
    }

    /// An in-memory store, for tests.
    ///
    /// # Errors
    /// [`StoreError`] if SQLite can't create it.
    pub fn open_in_memory(clock: Arc<dyn Clock>, limits: Limits) -> Result<Self, StoreError> {
        Self::init(Connection::open_in_memory()?, clock, limits)
    }

    fn init(
        mut conn: Connection,
        clock: Arc<dyn Clock>,
        limits: Limits,
    ) -> Result<Self, StoreError> {
        conn.busy_timeout(Duration::from_secs(5))?;
        conn.pragma_update(None, "foreign_keys", true)?;
        schema::migrate(&mut conn)?;
        let rules = RuleSet::new(load_rules(&conn)?);
        Ok(Self {
            conn: Mutex::new(conn),
            rules: RwLock::new(Arc::new(rules)),
            sandboxes: Mutex::new(HashMap::new()),
            puddle_connections: Mutex::new(ConnectionWindow::default()),
            clock,
            limits,
            events: Arc::new(NullSink),
        })
    }

    /// Sends the events of every change (pending requests opened, updated and closed, rules
    /// changed, audit records appended, suppression changed) to `sink`, after the change has
    /// committed. Nothing is emitted by default. Events carry ids, not decisions: a client that
    /// misses one refetches.
    #[must_use]
    pub fn with_events(mut self, sink: Arc<dyn EventSink>) -> Self {
        self.events = sink;
        self
    }

    fn snapshot(&self) -> Arc<RuleSet> {
        Arc::clone(&self.rules.read().unwrap_or_else(PoisonError::into_inner))
    }

    /// Every rule, including expired ones the sweeper hasn't removed yet.
    #[must_use]
    pub fn rules(&self) -> Vec<Rule> {
        self.snapshot().rules().to_vec()
    }

    /// Decides one request (R-5 to R-13): the deciding rule, or a pending outcome.
    ///
    /// # Errors
    /// [`StoreError`] if the pending row can't be written. The caller fails closed.
    pub fn decide(
        &self,
        request: &EgressRequest,
        suffix_allows: SuffixAllows,
    ) -> Result<Decision, StoreError> {
        let now = self.clock.now_ms();
        if let Some(decision) = self.match_rules(request, now, suffix_allows) {
            return Ok(decision);
        }
        let mut conn = lock(&self.conn);
        // Snapshots are only swapped under `conn`; look again so a rule committed while we
        // waited for the lock decides instead of a new pending row.
        if let Some(decision) = self.match_rules(request, now, suffix_allows) {
            return Ok(decision);
        }
        let tx = conn.transaction()?;
        let head = audit_head(&tx)?;
        let mut fx = Vec::new();
        let outcome = self.record_pending(&tx, request, now, &mut fx)?;
        self.commit(tx, head, fx)?;
        Ok(Decision::Pending(outcome))
    }

    fn match_rules(
        &self,
        request: &EgressRequest,
        now: u64,
        suffix_allows: SuffixAllows,
    ) -> Option<Decision> {
        let set = self.snapshot();
        let rule = set.decide(&request.sandbox, &request.host, now, suffix_allows)?;
        let (rule_id, pattern) = (rule.id, rule.pattern.kind());
        Some(match rule.effect {
            Effect::Allow => Decision::Allow { rule_id, pattern },
            Effect::Deny => Decision::Deny { rule_id, pattern },
        })
    }

    fn record_pending(
        &self,
        tx: &Transaction<'_>,
        request: &EgressRequest,
        now: u64,
        fx: &mut Vec<Event>,
    ) -> Result<PendingOutcome, StoreError> {
        let (sandbox, host) = (request.sandbox.as_str(), request.host.to_string());
        let existing: Option<i64> = tx
            .query_row(
                "SELECT id FROM pending
                 WHERE sandbox_id = ?1 AND host = ?2 AND port = ?3 AND state = 'requested'",
                params![sandbox, host, request.port],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(id) = existing {
            let (attempts, last_seen): (i64, i64) = tx.query_row(
                "UPDATE pending SET last_seen = max(last_seen, ?1), attempts = attempts + 1
                 WHERE id = ?2 RETURNING attempts, last_seen",
                params![sql_ts(now), id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?;
            fx.push(Event::PendingUpdated {
                sandbox: request.sandbox.clone(),
                id,
                attempts: stored_ts("pending", id, attempts)?,
                last_seen: stored_ts("pending", id, last_seen)?,
            });
            return Ok(PendingOutcome::Repeat(PendingId(id)));
        }
        let open: i64 = tx.query_row(
            "SELECT count(*) FROM pending WHERE sandbox_id = ?1 AND state = 'requested'",
            [sandbox],
            |row| row.get(0),
        )?;
        let below_cap = u64::try_from(open).unwrap_or(u64::MAX) < self.limits.max_open_rows;
        let (admitted, to_record) = {
            let mut sandboxes = lock(&self.sandboxes);
            let state = sandboxes
                .entry(request.sandbox.clone())
                .or_insert_with(|| SandboxState::new(&self.limits, now));
            if below_cap && state.bucket.try_take(now) {
                if state.suppressing {
                    fx.push(Event::SuppressionChanged {
                        sandbox: request.sandbox.clone(),
                        active: false,
                        count: state.episode,
                    });
                }
                (true, state.end_suppression())
            } else {
                let every = self.limits.suppressed_record_every_ms;
                let recorded = state.suppress(now, every);
                if state.episode == 1
                    || now.saturating_sub(state.last_event_at) >= SUPPRESSION_EVENT_EVERY_MS
                {
                    state.last_event_at = now;
                    fx.push(Event::SuppressionChanged {
                        sandbox: request.sandbox.clone(),
                        active: true,
                        count: state.episode,
                    });
                }
                (false, recorded)
            }
        };
        if let Some(count) = to_record {
            append(
                tx,
                &AuditRecord::PendingSuppressed {
                    ts: now,
                    sandbox_id: sandbox.to_owned(),
                    count,
                },
            )?;
        }
        if !admitted {
            return Ok(PendingOutcome::Suppressed);
        }
        tx.execute(
            "INSERT INTO pending (sandbox_id, host, port, first_seen, last_seen)
             VALUES (?1, ?2, ?3, ?4, ?4)",
            params![sandbox, host, request.port, sql_ts(now)],
        )?;
        let id = PendingId(tx.last_insert_rowid());
        let row = load_pending(tx, id)?;
        append(
            tx,
            &AuditRecord::PendingCreated {
                ts: now,
                pending: PendingWire::from(&row),
            },
        )?;
        fx.push(Event::PendingOpened {
            request: PendingSummary {
                id: id.0,
                sandbox: row.sandbox.clone(),
                host: row.host.to_string(),
                registrable_domain: registrable_domain(&row.host),
                port: row.port,
                first_seen: row.first_seen,
                last_seen: row.last_seen,
                attempts: row.attempts,
            },
        });
        Ok(PendingOutcome::New(id))
    }

    /// Commits `tx`, then emits `fx` and, if the transaction appended audit records (the audit's
    /// newest id passed `head`), one [`Event::AuditAppended`]. Called with `conn` held, so
    /// events leave in commit order.
    fn commit(&self, tx: Transaction<'_>, head: i64, fx: Vec<Event>) -> Result<(), StoreError> {
        let newest = audit_head(&tx)?;
        tx.commit()?;
        self.emit_all(fx, head, newest);
        Ok(())
    }

    fn emit_all(&self, fx: Vec<Event>, head: i64, newest: i64) {
        for event in fx {
            self.events.emit(event);
        }
        if newest > head {
            self.events.emit(Event::AuditAppended { id: newest });
        }
    }

    /// Runs `change` in one transaction, then swaps in the rule set as committed (R-8). The
    /// closure pushes the events its change deserves; they are emitted after the commit.
    fn change<T>(
        &self,
        change: impl FnOnce(&Transaction<'_>, u64, &mut Vec<Event>) -> Result<T, StoreError>,
    ) -> Result<T, StoreError> {
        let mut conn = lock(&self.conn);
        let now = self.clock.now_ms();
        let tx = conn.transaction()?;
        let head = audit_head(&tx)?;
        let mut fx = Vec::new();
        let out = change(&tx, now, &mut fx)?;
        let set = RuleSet::new(load_rules(&tx)?);
        let newest = audit_head(&tx)?;
        tx.commit()?;
        *self.rules.write().unwrap_or_else(PoisonError::into_inner) = Arc::new(set);
        self.emit_all(fx, head, newest);
        Ok(out)
    }

    /// Creates a rule and closes the open rows it now decides (R-16).
    ///
    /// # Errors
    /// [`StoreError::SystemActor`], [`StoreError::ExpiryNotInFuture`], or a database error.
    pub fn add_rule(&self, new: &NewRule) -> Result<Rule, StoreError> {
        if new.created_by == Actor::System {
            return Err(StoreError::SystemActor);
        }
        let rule = self.change(|tx, now, fx| {
            if new.expires_at.is_some_and(|at| at <= now) {
                return Err(StoreError::ExpiryNotInFuture);
            }
            let rule = insert_rule(tx, new, now, None)?;
            close_decided_rows(tx, &rule, None, new.created_by, now, fx)?;
            fx.push(Event::RulesChanged {});
            Ok(rule)
        })?;
        tracing::info!(rule = %rule.id, pattern = %rule.pattern, effect = rule.effect.as_str(), "rule created");
        Ok(rule)
    }

    /// Deletes a rule.
    ///
    /// # Errors
    /// [`StoreError::UnknownRule`] or a database error.
    pub fn delete_rule(&self, id: RuleId, actor: Actor) -> Result<Rule, StoreError> {
        let rule = self.change(|tx, now, fx| {
            let rule = load_rule(tx, id)?;
            tx.execute("DELETE FROM rules WHERE id = ?1", [id.0])?;
            append(
                tx,
                &AuditRecord::RuleDeleted {
                    ts: now,
                    rule: RuleWire::from(&rule),
                    reason: RuleDeleteReason::User,
                    actor: actor_str(actor),
                },
            )?;
            fx.push(Event::RulesChanged {});
            Ok(rule)
        })?;
        tracing::info!(rule = %id, "rule deleted");
        Ok(rule)
    }

    /// Changes a rule's expiry (`None` makes it permanent).
    ///
    /// # Errors
    /// [`StoreError::UnknownRule`], [`StoreError::ExpiryNotInFuture`],
    /// [`StoreError::SystemActor`], or a database error.
    pub fn set_rule_expiry(
        &self,
        id: RuleId,
        expires_at: Option<u64>,
        actor: Actor,
    ) -> Result<Rule, StoreError> {
        if actor == Actor::System {
            return Err(StoreError::SystemActor);
        }
        self.change(|tx, now, fx| {
            if expires_at.is_some_and(|at| at <= now) {
                return Err(StoreError::ExpiryNotInFuture);
            }
            let before = load_rule(tx, id)?;
            tx.execute(
                "UPDATE rules SET expires_at = ?1 WHERE id = ?2",
                params![expires_at.map(sql_ts), id.0],
            )?;
            let after = load_rule(tx, id)?;
            append(
                tx,
                &AuditRecord::RuleUpdated {
                    ts: now,
                    before: RuleWire::from(&before),
                    rule: RuleWire::from(&after),
                    actor: actor_str(actor),
                },
            )?;
            fx.push(Event::RulesChanged {});
            Ok(after)
        })
    }

    /// Approves or denies an open pending row (R-15 to R-17), in one transaction.
    ///
    /// # Errors
    /// [`StoreError::UnknownPending`] or [`StoreError::PendingNotOpen`] for a stale id (nothing
    /// changes), [`StoreError::Pattern`] for a suffix that doesn't cover the host or is a public
    /// suffix, [`StoreError::ExpiryNotInFuture`] for a zero duration,
    /// [`StoreError::SystemActor`], or a database error.
    pub fn resolve_pending(
        &self,
        id: PendingId,
        resolution: &Resolution,
        actor: Actor,
    ) -> Result<Decided, StoreError> {
        if actor == Actor::System {
            return Err(StoreError::SystemActor);
        }
        if resolution.expires_in.is_some_and(|d| d.is_zero()) {
            return Err(StoreError::ExpiryNotInFuture);
        }
        let decided = self.change(|tx, now, fx| {
            let row = load_pending(tx, id)?;
            if row.state != PendingState::Requested {
                return Err(StoreError::PendingNotOpen {
                    id,
                    state: row.state,
                });
            }
            let pattern = match &resolution.pattern {
                PatternChoice::Exact => Pattern::Exact(row.host.clone()),
                PatternChoice::Suffix(suffix) => Pattern::suffix_covering(&row.host, suffix)?,
            };
            let scope = match resolution.scope {
                ScopeChoice::Sandbox => Scope::Sandbox(row.sandbox.clone()),
                ScopeChoice::Global => Scope::Global,
            };
            let new = NewRule {
                scope,
                pattern,
                effect: resolution.effect,
                expires_at: resolution.expires_in.map(|d| plus(now, d)),
                created_by: actor,
            };
            let rule = insert_rule(tx, &new, now, Some(id))?;
            decide_row(tx, &row, &rule, actor, now, fx)?;
            let also_closed = close_decided_rows(tx, &rule, Some(id), actor, now, fx)?;
            fx.push(Event::RulesChanged {});
            Ok(Decided {
                row: load_pending(tx, id)?,
                rule,
                also_closed,
            })
        })?;
        tracing::info!(
            pending = %id,
            sandbox = %decided.row.sandbox,
            host = %decided.row.host,
            rule = %decided.rule.id,
            effect = decided.rule.effect.as_str(),
            "pending request decided"
        );
        Ok(decided)
    }

    /// One pending row.
    ///
    /// # Errors
    /// [`StoreError::UnknownPending`] or a database error.
    pub fn pending(&self, id: PendingId) -> Result<PendingRow, StoreError> {
        load_pending(&lock(&self.conn), id)
    }

    /// Open (`requested`) rows, of one sandbox or all, most recent first.
    ///
    /// # Errors
    /// A database error, or [`StoreError::Corrupt`].
    pub fn open_pending(
        &self,
        sandbox: Option<&SandboxName>,
    ) -> Result<Vec<PendingRow>, StoreError> {
        let conn = lock(&self.conn);
        let mut stmt = conn.prepare(&format!(
            "SELECT {PENDING_COLUMNS} FROM pending
             WHERE state = 'requested' AND (?1 IS NULL OR sandbox_id = ?1)
             ORDER BY last_seen DESC, id DESC"
        ))?;
        let rows = stmt.query_map([sandbox.map(SandboxName::as_str)], raw_pending)?;
        rows.map(|raw| pending_from_raw(&raw?)).collect()
    }

    /// Open rows grouped by registrable domain for the inbox (R-18), most recent group first.
    /// Grouping is for display only and decides nothing.
    ///
    /// # Errors
    /// As [`Store::open_pending`].
    pub fn inbox(&self) -> Result<Vec<InboxGroup>, StoreError> {
        let mut groups: Vec<InboxGroup> = Vec::new();
        for row in self.open_pending(None)? {
            let domain = registrable_domain(&row.host);
            match groups.iter_mut().find(|g| g.registrable_domain == domain) {
                Some(group) => group.rows.push(row),
                None => groups.push(InboxGroup {
                    registrable_domain: domain,
                    rows: vec![row],
                }),
            }
        }
        Ok(groups)
    }

    /// A sandbox's suppression state, for the inbox's "N requests suppressed" line (R-13).
    #[must_use]
    pub fn suppression(&self, sandbox: &SandboxName) -> Suppression {
        lock(&self.sandboxes)
            .get(sandbox)
            .map(|s| Suppression {
                active: s.suppressing,
                count: s.episode,
            })
            .unwrap_or_default()
    }

    /// Writes a `connection` record (R-24), subject to the per-sandbox limit (R-26).
    ///
    /// # Errors
    /// A database or audit error.
    pub fn record_connection(&self, event: &ConnectionEvent) -> Result<(), StoreError> {
        let now = self.clock.now_ms();
        let limit = self.limits.connection_records_per_second;
        let (admitted, summary) = match &event.sandbox {
            Some(sandbox) => lock(&self.sandboxes)
                .entry(sandbox.clone())
                .or_insert_with(|| SandboxState::new(&self.limits, now))
                .connections
                .admit(now, limit),
            None => lock(&self.puddle_connections).admit(now, limit),
        };
        if !admitted && summary.is_none() {
            return Ok(());
        }
        let mut conn = lock(&self.conn);
        let tx = conn.transaction()?;
        let head = audit_head(&tx)?;
        if let Some((ts, count)) = summary {
            let record = ConnectionRecord::suppressed_summary(ts, event.sandbox.as_ref(), count);
            append(&tx, &AuditRecord::Connection(record))?;
        }
        if admitted {
            let record = ConnectionRecord::from_event(now, event);
            append(&tx, &AuditRecord::Connection(record))?;
        }
        self.commit(tx, head, Vec::new())
    }

    /// Removes a deleted sandbox's rules and expires its open rows, in one transaction (R-21).
    /// Call it from the transaction-equivalent step of sandbox deletion, not on stop.
    ///
    /// # Errors
    /// A database or audit error; nothing changes then.
    pub fn delete_sandbox(&self, sandbox: &SandboxName) -> Result<SandboxDeletion, StoreError> {
        let deletion = self.change(|tx, now, fx| {
            let mut stmt = tx.prepare(&format!(
                "SELECT {RULE_COLUMNS} FROM rules WHERE sandbox_id = ?1 ORDER BY id"
            ))?;
            let rules = stmt
                .query_map([sandbox.as_str()], raw_rule)?
                .map(|raw| rule_from_raw(&raw?))
                .collect::<Result<Vec<_>, _>>()?;
            drop(stmt);
            tx.execute(
                "DELETE FROM rules WHERE sandbox_id = ?1",
                [sandbox.as_str()],
            )?;
            for rule in &rules {
                append(
                    tx,
                    &AuditRecord::RuleDeleted {
                        ts: now,
                        rule: RuleWire::from(rule),
                        reason: RuleDeleteReason::SandboxDeleted,
                        actor: actor_str(Actor::System),
                    },
                )?;
            }
            let expired = expire_rows(
                tx,
                "sandbox_id = ?2",
                &sandbox.as_str(),
                now,
                PendingExpiryReason::SandboxDeleted,
                fx,
            )?;
            if !rules.is_empty() {
                fx.push(Event::RulesChanged {});
            }
            Ok(SandboxDeletion {
                rules_deleted: rules.len() as u64,
                pending_expired: expired,
            })
        })?;
        let state = lock(&self.sandboxes).remove(sandbox);
        if let Some(state) = state.filter(|s| s.suppressing) {
            self.events.emit(Event::SuppressionChanged {
                sandbox: sandbox.clone(),
                active: false,
                count: state.episode,
            });
        }
        tracing::info!(sandbox = %sandbox, rules = deletion.rules_deleted, "sandbox rules removed");
        Ok(deletion)
    }

    /// One sweeper pass (R-19 to R-22), each step its own short transaction.
    ///
    /// # Errors
    /// The first failing step's error; earlier steps stay committed.
    pub fn sweep(&self) -> Result<SweepReport, StoreError> {
        let rules_expired = self.change(|tx, now, fx| {
            let mut stmt = tx.prepare(&format!(
                "SELECT {RULE_COLUMNS} FROM rules
                 WHERE expires_at IS NOT NULL AND expires_at <= ?1 ORDER BY id"
            ))?;
            let rules = stmt
                .query_map([sql_ts(now)], raw_rule)?
                .map(|raw| rule_from_raw(&raw?))
                .collect::<Result<Vec<_>, _>>()?;
            drop(stmt);
            for rule in &rules {
                tx.execute("DELETE FROM rules WHERE id = ?1", [rule.id.0])?;
                append(
                    tx,
                    &AuditRecord::RuleExpired {
                        ts: now,
                        rule: RuleWire::from(rule),
                    },
                )?;
            }
            if !rules.is_empty() {
                fx.push(Event::RulesChanged {});
            }
            Ok(rules.len() as u64)
        })?;
        let pending_expired = {
            let mut conn = lock(&self.conn);
            let now = self.clock.now_ms();
            let cutoff = sql_ts(now.saturating_sub(self.limits.pending_stale_after_ms));
            let tx = conn.transaction()?;
            let head = audit_head(&tx)?;
            let mut fx = Vec::new();
            let n = expire_rows(
                &tx,
                "last_seen <= ?2",
                &cutoff,
                now,
                PendingExpiryReason::Stale,
                &mut fx,
            )?;
            self.commit(tx, head, fx)?;
            n
        };
        self.flush_limits()?;
        let audit_records_trimmed = self.trim_audit()?;
        Ok(SweepReport {
            rules_expired,
            pending_expired,
            audit_records_trimmed,
        })
    }

    /// Writes suppression counts and connection summaries that are due.
    fn flush_limits(&self) -> Result<(), StoreError> {
        let now = self.clock.now_ms();
        let every = self.limits.suppressed_record_every_ms;
        let mut records = Vec::new();
        for (sandbox, state) in lock(&self.sandboxes).iter_mut() {
            if let Some(count) = state.flush_due(now, every) {
                records.push(AuditRecord::PendingSuppressed {
                    ts: now,
                    sandbox_id: sandbox.to_string(),
                    count,
                });
            }
            if let Some((ts, count)) = state.connections.roll(now) {
                let record = ConnectionRecord::suppressed_summary(ts, Some(sandbox), count);
                records.push(AuditRecord::Connection(record));
            }
        }
        if let Some((ts, count)) = lock(&self.puddle_connections).roll(now) {
            let record = ConnectionRecord::suppressed_summary(ts, None, count);
            records.push(AuditRecord::Connection(record));
        }
        if records.is_empty() {
            return Ok(());
        }
        let mut conn = lock(&self.conn);
        let tx = conn.transaction()?;
        let head = audit_head(&tx)?;
        for record in &records {
            append(&tx, record)?;
        }
        self.commit(tx, head, Vec::new())
    }

    /// Deletes the oldest audit records while the audit is over its cap, then records the trim.
    fn trim_audit(&self) -> Result<u64, StoreError> {
        const CHUNK: i64 = 5000;
        let mut deleted = 0u64;
        if self.audit_bytes()? <= self.limits.audit_max_bytes {
            return Ok(0);
        }
        loop {
            let mut conn = lock(&self.conn);
            let tx = conn.transaction()?;
            let total = audit_bytes(&tx)?;
            let Some(excess) = total.checked_sub(self.limits.audit_trim_to_bytes) else {
                break;
            };
            if excess == 0 {
                break;
            }
            let mut stmt = tx
                .prepare("SELECT id, length(CAST(line AS BLOB)) FROM audit ORDER BY id LIMIT ?1")?;
            let mut freed = 0u64;
            let mut cutoff = None;
            for item in stmt.query_map([CHUNK], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?))
            })? {
                let (id, len) = item?;
                freed += u64::try_from(len).unwrap_or(0);
                cutoff = Some(id);
                if freed >= excess {
                    break;
                }
            }
            drop(stmt);
            let Some(cutoff) = cutoff else { break };
            deleted += u64::try_from(tx.execute("DELETE FROM audit WHERE id <= ?1", [cutoff])?)
                .unwrap_or(0);
            tx.commit()?;
        }
        let mut conn = lock(&self.conn);
        let tx = conn.transaction()?;
        let head = audit_head(&tx)?;
        let oldest: Option<i64> = tx
            .query_row("SELECT ts FROM audit ORDER BY id LIMIT 1", [], |row| {
                row.get(0)
            })
            .optional()?;
        append(
            &tx,
            &AuditRecord::AuditTrimmed {
                ts: self.clock.now_ms(),
                deleted_records: deleted,
                oldest_ts_kept: oldest.and_then(|ts| u64::try_from(ts).ok()),
            },
        )?;
        self.commit(tx, head, Vec::new())?;
        tracing::info!(deleted, "audit trimmed to its size cap");
        Ok(deleted)
    }

    /// Total bytes of audit lines.
    ///
    /// # Errors
    /// A database error.
    pub fn audit_bytes(&self) -> Result<u64, StoreError> {
        audit_bytes(&lock(&self.conn))
    }

    /// Audit records after id `after`, oldest first, as `(id, JSONL line)`.
    ///
    /// # Errors
    /// A database error.
    pub fn audit_lines(&self, after: i64, limit: u32) -> Result<Vec<(i64, String)>, StoreError> {
        let conn = lock(&self.conn);
        let mut stmt =
            conn.prepare("SELECT id, line FROM audit WHERE id > ?1 ORDER BY id LIMIT ?2")?;
        let rows = stmt.query_map(params![after, limit], |row| Ok((row.get(0)?, row.get(1)?)))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }
}

impl Store {
    /// A page of up to `limit` audit records matching `filter`, as `(id, JSONL line)`: oldest
    /// first for [`AuditCursor::After`], newest first for [`AuditCursor::Before`].
    ///
    /// Filters run on indexed columns (`sandbox_id`, `type`, `outcome`, `ts`) and the stored
    /// `host`; no JSON is parsed. Values are bound, never spliced into the SQL.
    ///
    /// # Errors
    /// A database error.
    pub fn audit_query(
        &self,
        filter: &AuditFilter,
        cursor: AuditCursor,
        limit: u32,
    ) -> Result<Vec<(i64, String)>, StoreError> {
        let (sql, args) = audit_query_sql(filter, cursor, limit);
        let conn = lock(&self.conn);
        let mut stmt = conn.prepare_cached(&sql)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(args), |row| {
            Ok((row.get(0)?, row.get(1)?))
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// SQLite's query plan for [`Store::audit_query`] with these arguments, one line per step.
    /// Lets a test check that a filter combination uses an index instead of timing it.
    ///
    /// # Errors
    ///
    /// Fails if the database can't be read.
    pub fn audit_query_plan(
        &self,
        filter: &AuditFilter,
        cursor: AuditCursor,
        limit: u32,
    ) -> Result<Vec<String>, StoreError> {
        let (sql, args) = audit_query_sql(filter, cursor, limit);
        let conn = lock(&self.conn);
        let mut stmt = conn.prepare(&format!("EXPLAIN QUERY PLAN {sql}"))?;
        let rows = stmt.query_map(rusqlite::params_from_iter(args), |row| row.get(3))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }
}

/// The SQL and bound values for one audit page; every value is bound, never spliced in.
fn audit_query_sql(
    filter: &AuditFilter,
    cursor: AuditCursor,
    limit: u32,
) -> (String, Vec<rusqlite::types::Value>) {
    use rusqlite::types::Value;
    let mut sql = String::from("SELECT id, line FROM audit WHERE 1");
    let mut args: Vec<Value> = Vec::new();
    let mut clause = |text: &str, value: Option<Value>| {
        sql.push_str(" AND ");
        sql.push_str(text);
        args.extend(value);
    };
    match cursor {
        AuditCursor::After(id) => clause("id > ?", Some(Value::Integer(id))),
        AuditCursor::Before(Some(id)) => clause("id < ?", Some(Value::Integer(id))),
        AuditCursor::Before(None) => {}
    }
    if let Some(sandbox) = &filter.sandbox {
        clause("sandbox_id = ?", Some(Value::Text(sandbox.to_string())));
    }
    if let Some(kind) = filter.kind {
        clause("type = ?", Some(Value::Text(kind.to_owned())));
    }
    if let Some(outcome) = filter.outcome {
        clause(
            "outcome = ?",
            Some(Value::Text(outcome.as_str().to_owned())),
        );
    }
    match filter.origin {
        None => {}
        // A connection record names a sandbox unless puddle made the connection itself.
        Some(ConnectionOrigin::Puddle) => {
            clause("type = 'connection' AND sandbox_id IS NULL", None);
        }
        Some(_) => clause("type = 'connection' AND sandbox_id IS NOT NULL", None),
    }
    if let Some(from) = filter.from {
        clause("ts >= ?", Some(Value::Integer(sql_ts(from))));
    }
    if let Some(to) = filter.to {
        clause("ts < ?", Some(Value::Integer(sql_ts(to))));
    }
    if let Some(needle) = &filter.host_contains {
        clause(
            "instr(host, ?) > 0",
            Some(Value::Text(needle.to_lowercase())),
        );
    }
    sql.push_str(match cursor {
        AuditCursor::After(_) => " ORDER BY id LIMIT ?",
        AuditCursor::Before(_) => " ORDER BY id DESC LIMIT ?",
    });
    args.push(Value::Integer(i64::from(limit)));
    (sql, args)
}

impl Policy for Store {
    fn decide(
        &self,
        request: &EgressRequest,
        suffix_allows: SuffixAllows,
    ) -> Result<Decision, PolicyError> {
        Self::decide(self, request, suffix_allows).map_err(|err| PolicyError {
            reason: err.to_string(),
        })
    }

    fn lookup(
        &self,
        request: &EgressRequest,
        suffix_allows: SuffixAllows,
    ) -> Result<Option<Decision>, PolicyError> {
        Ok(self.match_rules(request, self.clock.now_ms(), suffix_allows))
    }
}

/// The proxy's [`ConnectionLog`]: each event becomes a `connection` record through
/// [`Store::record_connection`]. A failed write is logged and dropped; the connection it describes
/// has already been handled.
impl ConnectionLog for Store {
    fn record(&self, event: &ConnectionEvent) {
        if let Err(err) = self.record_connection(event) {
            tracing::warn!(origin = %event.origin, error = %err, "connection record not written");
        }
    }
}

fn audit_bytes(conn: &Connection) -> Result<u64, StoreError> {
    let bytes: i64 = conn.query_row("SELECT bytes FROM audit_size WHERE id = 1", [], |row| {
        row.get(0)
    })?;
    Ok(u64::try_from(bytes).unwrap_or(0))
}

fn append(conn: &Connection, record: &AuditRecord) -> Result<(), StoreError> {
    let line = record.to_line()?;
    conn.execute(
        "INSERT INTO audit (ts, type, sandbox_id, host, outcome, line)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            sql_ts(record.ts()),
            record.kind(),
            record.sandbox_id(),
            record.host(),
            record.outcome().map(AuditOutcome::as_str),
            line
        ],
    )?;
    Ok(())
}

/// The newest audit record's id (0 for an empty audit). Ids only grow (`AUTOINCREMENT`), so a
/// transaction that appended anything ends with a larger value than it started with.
fn audit_head(conn: &Connection) -> Result<i64, StoreError> {
    Ok(
        conn.query_row("SELECT coalesce(max(id), 0) FROM audit", [], |row| {
            row.get(0)
        })?,
    )
}

fn insert_rule(
    tx: &Transaction<'_>,
    new: &NewRule,
    now: u64,
    source: Option<PendingId>,
) -> Result<Rule, StoreError> {
    let (scope, sandbox) = match &new.scope {
        Scope::Global => ("global", None),
        Scope::Sandbox(id) => ("sandbox", Some(id.as_str())),
    };
    let kind = match new.pattern {
        Pattern::Exact(_) => "exact",
        Pattern::Suffix(_) => "suffix",
    };
    tx.execute(
        "INSERT INTO rules (scope, sandbox_id, pattern_kind, pattern, effect, expires_at,
                            created_at, created_by, source_pending_id)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            scope,
            sandbox,
            kind,
            new.pattern.to_string(),
            new.effect.as_str(),
            new.expires_at.map(sql_ts),
            sql_ts(now),
            new.created_by.as_str(),
            source.map(|id| id.0),
        ],
    )?;
    let rule = load_rule(tx, RuleId(tx.last_insert_rowid()))?;
    append(
        tx,
        &AuditRecord::RuleCreated {
            ts: now,
            rule: RuleWire::from(&rule),
        },
    )?;
    Ok(rule)
}

/// Sets an open row to the state `rule` gives it and records that.
fn decide_row(
    tx: &Transaction<'_>,
    row: &PendingRow,
    rule: &Rule,
    actor: Actor,
    now: u64,
    fx: &mut Vec<Event>,
) -> Result<(), StoreError> {
    tx.execute(
        "UPDATE pending SET state = ?1, decided_at = ?2, decided_by = ?3, rule_id = ?4
         WHERE id = ?5 AND state = 'requested'",
        params![
            PendingState::decided_by(rule.effect).as_str(),
            sql_ts(now),
            actor.as_str(),
            rule.id.0,
            row.id.0
        ],
    )?;
    append(
        tx,
        &AuditRecord::PendingDecided {
            ts: now,
            pending: PendingWire::from(&load_pending(tx, row.id)?),
        },
    )?;
    fx.push(Event::PendingClosed {
        sandbox: row.sandbox.clone(),
        id: row.id.0,
        state: match rule.effect {
            Effect::Allow => PendingEnd::Allowed,
            Effect::Deny => PendingEnd::Denied,
        },
        rule_id: Some(rule.id.0),
    });
    Ok(())
}

/// Closes every other open row that `rule` now decides, the same way (R-16): rows in the rule's
/// sandbox (any sandbox for a global rule) for which `rule` is the winning rule.
fn close_decided_rows(
    tx: &Transaction<'_>,
    rule: &Rule,
    except: Option<PendingId>,
    actor: Actor,
    now: u64,
    fx: &mut Vec<Event>,
) -> Result<Vec<PendingId>, StoreError> {
    let set = RuleSet::new(load_rules(tx)?);
    let mut stmt = tx.prepare(&format!(
        "SELECT {PENDING_COLUMNS} FROM pending
         WHERE state = 'requested' AND (?1 IS NULL OR sandbox_id = ?1) ORDER BY id"
    ))?;
    let open = stmt
        .query_map([rule.scope.sandbox().map(SandboxName::as_str)], raw_pending)?
        .map(|raw| pending_from_raw(&raw?))
        .collect::<Result<Vec<_>, _>>()?;
    drop(stmt);
    let mut closed = Vec::new();
    for row in open {
        if Some(row.id) == except || !rule.pattern.matches(&row.host) {
            continue;
        }
        let winner = set.decide(&row.sandbox, &row.host, now, SuffixAllows::Count);
        if winner.is_some_and(|w| w.id == rule.id) {
            decide_row(tx, &row, rule, actor, now, fx)?;
            closed.push(row.id);
        }
    }
    Ok(closed)
}

/// Expires open rows matching `filter` (which binds `?2` to `value`) and records each.
fn expire_rows(
    tx: &Transaction<'_>,
    filter: &str,
    value: &dyn rusqlite::ToSql,
    now: u64,
    reason: PendingExpiryReason,
    fx: &mut Vec<Event>,
) -> Result<u64, StoreError> {
    let mut stmt = tx.prepare(&format!(
        "UPDATE pending SET state = 'expired', decided_at = ?1, decided_by = 'system'
         WHERE state = 'requested' AND {filter}
         RETURNING {PENDING_COLUMNS}"
    ))?;
    let rows = stmt
        .query_map(params![sql_ts(now), value], raw_pending)?
        .map(|raw| pending_from_raw(&raw?))
        .collect::<Result<Vec<_>, _>>()?;
    drop(stmt);
    for row in &rows {
        append(
            tx,
            &AuditRecord::PendingExpired {
                ts: now,
                pending: PendingWire::from(row),
                reason,
            },
        )?;
        fx.push(Event::PendingClosed {
            sandbox: row.sandbox.clone(),
            id: row.id.0,
            state: PendingEnd::Expired,
            rule_id: None,
        });
    }
    Ok(rows.len() as u64)
}

const RULE_COLUMNS: &str = "id, scope, sandbox_id, pattern_kind, pattern, effect, expires_at, \
                            created_at, created_by, source_pending_id";

/// A `rules` row as SQLite holds it, before validation.
struct RawRule {
    id: i64,
    scope: String,
    sandbox_id: Option<String>,
    pattern_kind: String,
    pattern: String,
    effect: String,
    expires_at: Option<i64>,
    created_at: i64,
    created_by: String,
    source_pending_id: Option<i64>,
}

fn raw_rule(row: &Row<'_>) -> rusqlite::Result<RawRule> {
    Ok(RawRule {
        id: row.get(0)?,
        scope: row.get(1)?,
        sandbox_id: row.get(2)?,
        pattern_kind: row.get(3)?,
        pattern: row.get(4)?,
        effect: row.get(5)?,
        expires_at: row.get(6)?,
        created_at: row.get(7)?,
        created_by: row.get(8)?,
        source_pending_id: row.get(9)?,
    })
}

fn corrupt(table: &'static str, id: i64, reason: impl Into<String>) -> StoreError {
    StoreError::Corrupt {
        table,
        id,
        reason: reason.into(),
    }
}

fn stored_ts(table: &'static str, id: i64, value: i64) -> Result<u64, StoreError> {
    u64::try_from(value).map_err(|_| corrupt(table, id, "negative timestamp"))
}

fn rule_from_raw(raw: &RawRule) -> Result<Rule, StoreError> {
    let bad = |reason: &str| corrupt("rules", raw.id, reason);
    let scope = match (raw.scope.as_str(), raw.sandbox_id.as_deref()) {
        ("global", None) => Scope::Global,
        ("sandbox", Some(id)) => {
            Scope::Sandbox(SandboxName::new(id).map_err(|e| bad(&e.to_string()))?)
        }
        _ => return Err(bad("scope")),
    };
    let host = |text: &str| Host::parse_normalised(text).map_err(|e| bad(&e.to_string()));
    // Stored suffixes are not re-checked against the public suffix list: a list update must not
    // make an existing database unreadable.
    let pattern = match (raw.pattern_kind.as_str(), raw.pattern.strip_prefix('.')) {
        ("exact", None) => Pattern::Exact(host(&raw.pattern)?),
        ("suffix", Some(base)) => match host(base)? {
            Host::Name(name) => Pattern::Suffix(SuffixPattern::from_stored(name)),
            Host::Ip(_) => return Err(bad("suffix of an ip literal")),
        },
        _ => return Err(bad("pattern")),
    };
    let effect = match raw.effect.as_str() {
        "allow" => Effect::Allow,
        "deny" => Effect::Deny,
        _ => return Err(bad("effect")),
    };
    Ok(Rule {
        id: RuleId(raw.id),
        scope,
        pattern,
        effect,
        expires_at: raw
            .expires_at
            .map(|t| stored_ts("rules", raw.id, t))
            .transpose()?,
        created_at: stored_ts("rules", raw.id, raw.created_at)?,
        created_by: Actor::parse(&raw.created_by).ok_or_else(|| bad("created_by"))?,
        source_pending_id: raw.source_pending_id.map(PendingId),
    })
}

fn load_rules(conn: &Connection) -> Result<Vec<Rule>, StoreError> {
    let mut stmt = conn.prepare(&format!("SELECT {RULE_COLUMNS} FROM rules ORDER BY id"))?;
    let rules = stmt.query_map([], raw_rule)?;
    rules.map(|raw| rule_from_raw(&raw?)).collect()
}

fn load_rule(conn: &Connection, id: RuleId) -> Result<Rule, StoreError> {
    let raw = conn
        .query_row(
            &format!("SELECT {RULE_COLUMNS} FROM rules WHERE id = ?1"),
            [id.0],
            raw_rule,
        )
        .optional()?
        .ok_or(StoreError::UnknownRule(id))?;
    rule_from_raw(&raw)
}

const PENDING_COLUMNS: &str = "id, sandbox_id, host, port, first_seen, last_seen, attempts, \
                               state, decided_at, decided_by, rule_id";

/// A `pending` row as SQLite holds it, before validation.
struct RawPending {
    id: i64,
    sandbox_id: String,
    host: String,
    port: i64,
    first_seen: i64,
    last_seen: i64,
    attempts: i64,
    state: String,
    decided_at: Option<i64>,
    decided_by: Option<String>,
    rule_id: Option<i64>,
}

fn raw_pending(row: &Row<'_>) -> rusqlite::Result<RawPending> {
    Ok(RawPending {
        id: row.get(0)?,
        sandbox_id: row.get(1)?,
        host: row.get(2)?,
        port: row.get(3)?,
        first_seen: row.get(4)?,
        last_seen: row.get(5)?,
        attempts: row.get(6)?,
        state: row.get(7)?,
        decided_at: row.get(8)?,
        decided_by: row.get(9)?,
        rule_id: row.get(10)?,
    })
}

fn pending_from_raw(raw: &RawPending) -> Result<PendingRow, StoreError> {
    let bad = |reason: &str| corrupt("pending", raw.id, reason);
    let ts = |value: i64| stored_ts("pending", raw.id, value);
    Ok(PendingRow {
        id: PendingId(raw.id),
        sandbox: SandboxName::new(&raw.sandbox_id).map_err(|e| bad(&e.to_string()))?,
        host: Host::parse_normalised(&raw.host).map_err(|e| bad(&e.to_string()))?,
        port: u16::try_from(raw.port).map_err(|_| bad("port"))?,
        first_seen: ts(raw.first_seen)?,
        last_seen: ts(raw.last_seen)?,
        attempts: u64::try_from(raw.attempts).map_err(|_| bad("attempts"))?,
        state: PendingState::parse(&raw.state).ok_or_else(|| bad("state"))?,
        decided_at: raw.decided_at.map(ts).transpose()?,
        decided_by: raw
            .decided_by
            .as_deref()
            .map(|a| Actor::parse(a).ok_or_else(|| bad("decided_by")))
            .transpose()?,
        rule_id: raw.rule_id.map(RuleId),
    })
}

fn load_pending(conn: &Connection, id: PendingId) -> Result<PendingRow, StoreError> {
    let raw = conn
        .query_row(
            &format!("SELECT {PENDING_COLUMNS} FROM pending WHERE id = ?1"),
            [id.0],
            raw_pending,
        )
        .optional()?
        .ok_or(StoreError::UnknownPending(id))?;
    pending_from_raw(&raw)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::ManualClock;

    fn store() -> (Arc<ManualClock>, Store) {
        let clock = Arc::new(ManualClock::new(1_000_000));
        let store = Store::open_in_memory(clock.clone(), Limits::default()).unwrap();
        (clock, store)
    }

    #[test]
    fn corrupt_rows_are_reported_not_trusted() {
        let (_, store) = store();
        {
            let conn = lock(&store.conn);
            conn.execute(
                "INSERT INTO rules (scope, sandbox_id, pattern_kind, pattern, effect, created_at, created_by)
                 VALUES ('global', NULL, 'exact', 'NOT A HOST', 'allow', 0, 'cli')",
                [],
            )
            .unwrap();
        }
        let err = store
            .set_rule_expiry(RuleId(1), None, Actor::Cli)
            .unwrap_err();
        assert!(
            matches!(
                err,
                StoreError::Corrupt {
                    table: "rules",
                    id: 1,
                    ..
                }
            ),
            "{err}"
        );
        // The bad row also blocks reloading the rule set, so no change commits on top of it.
        assert_eq!(store.rules(), Vec::<Rule>::new());
    }

    #[test]
    fn raw_rows_with_bad_fields_are_corrupt() {
        let base = || RawRule {
            id: 1,
            scope: "global".into(),
            sandbox_id: None,
            pattern_kind: "exact".into(),
            pattern: "example.com".into(),
            effect: "allow".into(),
            expires_at: None,
            created_at: 0,
            created_by: "cli".into(),
            source_pending_id: None,
        };
        assert!(rule_from_raw(&base()).is_ok());
        let cases: Vec<fn(&mut RawRule)> = vec![
            |r| r.scope = "sandbox".into(),
            |r| r.sandbox_id = Some("x".into()),
            |r| r.pattern_kind = "suffix".into(),
            |r| r.pattern_kind = "regex".into(),
            |r| r.effect = "maybe".into(),
            |r| r.created_by = "system".into(),
            |r| r.created_by = "guest".into(),
            |r| r.created_at = -1,
            |r| r.expires_at = Some(-5),
            |r| {
                r.pattern_kind = "suffix".into();
                r.pattern = ".10.0.0.1".into();
            },
        ];
        for (index, case) in cases.into_iter().enumerate() {
            let mut raw = base();
            case(&mut raw);
            let parsed = rule_from_raw(&raw);
            // `created_by = system` parses as an actor; the schema's CHECK keeps it out of rules.
            if index == 5 {
                continue;
            }
            assert!(parsed.is_err(), "case {index}");
        }
    }

    #[test]
    fn raw_pending_rows_with_bad_fields_are_corrupt() {
        let base = || RawPending {
            id: 1,
            sandbox_id: "sb".into(),
            host: "example.com".into(),
            port: 443,
            first_seen: 0,
            last_seen: 0,
            attempts: 1,
            state: "requested".into(),
            decided_at: None,
            decided_by: None,
            rule_id: None,
        };
        assert!(pending_from_raw(&base()).is_ok());
        let cases: Vec<fn(&mut RawPending)> = vec![
            |r| r.sandbox_id = String::new(),
            |r| r.host = "Example.com".into(),
            |r| r.port = 70_000,
            |r| r.attempts = -1,
            |r| r.state = "open".into(),
            |r| r.decided_by = Some("guest".into()),
            |r| r.decided_at = Some(-1),
        ];
        for (index, case) in cases.into_iter().enumerate() {
            let mut raw = base();
            case(&mut raw);
            assert!(pending_from_raw(&raw).is_err(), "case {index}");
        }
    }

    #[test]
    fn suppression_episode_records_start_interval_and_end() {
        let limits = Limits::default();
        let mut state = SandboxState::new(&limits, 0);
        assert_eq!(state.end_suppression(), None);
        assert_eq!(state.suppress(0, 60_000), Some(1));
        assert_eq!(state.suppress(1_000, 60_000), None);
        assert_eq!(state.flush_due(30_000, 60_000), None);
        assert_eq!(state.suppress(60_000, 60_000), Some(2));
        assert_eq!(state.suppress(61_000, 60_000), None);
        assert_eq!(state.flush_due(120_000, 60_000), Some(1));
        assert_eq!(state.end_suppression(), None);
        assert_eq!(state.suppress(130_000, 60_000), Some(1));
        assert_eq!(state.suppress(130_001, 60_000), None);
        assert_eq!(state.end_suppression(), Some(1));
    }

    #[test]
    fn debug_does_not_dump_the_database() {
        let (_, store) = store();
        assert!(format!("{store:?}").starts_with("Store { limits"));
    }

    #[test]
    fn timestamp_helpers_saturate() {
        assert_eq!(sql_ts(u64::MAX), i64::MAX);
        assert_eq!(plus(u64::MAX - 1, Duration::from_secs(1)), u64::MAX);
        assert!(stored_ts("rules", 1, -1).is_err());
    }
}
