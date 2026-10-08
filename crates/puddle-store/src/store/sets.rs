// SPDX-License-Identifier: GPL-3.0-or-later
//! Rule sets and System managed in the store (`docs/spec/rules.md` §7, R-36 to R-43): the sets
//! the user makes, the switches of every set, the built-in sets' update record, and the reasons
//! behind the System managed hosts.

use std::collections::{BTreeMap, BTreeSet};

use puddle_types::{Event, PendingId, RuleId, RuleSetId, SuffixAllows, WorkspaceName};
use rusqlite::{Connection, OptionalExtension, Transaction, params};

use super::{
    PENDING_COLUMNS, Store, append, decide_row_by, load_rules, lock, pending_from_raw, raw_pending,
    sql_ts, stored_ts,
};
use crate::audit::{AuditRecord, RuleDeleteReason, RuleSetWire, RuleWire, actor_str};
use crate::catalogue::{self, BUILT_IN_SETS, SystemReason};
use crate::engine::{RuleIndex, SetEntry, Switches, default_on};
use crate::error::StoreError;
use crate::rule::{Actor, Effect, Rule, Scope};

/// The longest rule set name, in characters.
const MAX_SET_NAME: usize = 64;
/// The longest rule set description, in characters.
const MAX_SET_DESCRIPTION: usize = 500;

/// A rule set as the Rules screen shows it: what it is, where it is on, and its entries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleSetInfo {
    /// `builtin:<slug>` or `user:<id>`.
    pub id: RuleSetId,
    /// Display name.
    pub name: String,
    /// What it is for.
    pub description: String,
    /// Whether it is on where nobody switched it.
    pub default_on: bool,
    /// The switch for every workspace, if set.
    pub global: Option<bool>,
    /// Workspaces that override the switch, by name.
    pub overrides: Vec<(WorkspaceName, bool)>,
    /// Its entries.
    pub entries: Vec<RuleSetEntryInfo>,
    /// Built-in sets: when a puddle update last changed the entries (R-36), else `None`.
    pub changed_at: Option<u64>,
    /// Sets the user made: when.
    pub created_at: Option<u64>,
}

impl RuleSetInfo {
    /// Whether the set is on for `workspace` (R-37).
    #[must_use]
    pub fn is_on(&self, workspace: &WorkspaceName) -> bool {
        self.overrides
            .iter()
            .find(|(s, _)| s == workspace)
            .map(|(_, on)| *on)
            .or(self.global)
            .unwrap_or(self.default_on)
    }

    /// Whether the set is on where no workspace overrides it.
    #[must_use]
    pub fn on_by_default(&self) -> bool {
        self.global.unwrap_or(self.default_on)
    }
}

/// One entry of a rule set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleSetEntryInfo {
    /// `example.com` or `.example.com`.
    pub pattern: String,
    /// Allow or deny (built-in entries only allow).
    pub effect: Effect,
    /// What it is for (built-in entries).
    pub note: String,
    /// The rule row, for a set the user made.
    pub rule_id: Option<RuleId>,
    /// Epoch ms after which the entry no longer counts.
    pub expires_at: Option<u64>,
}

/// One host puddle allows because of the user's setup (R-40, R-41).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemHost {
    /// The pattern as written in the catalogue (`*.gallery.vsassets.io`).
    pub pattern: &'static str,
    /// What the host is for.
    pub note: &'static str,
    /// Why it is allowed.
    pub reason: SystemReason,
    /// The one workspace it is allowed for, or `None` for every workspace.
    pub workspace: Option<WorkspaceName>,
}

/// Which System managed reasons apply where, as derived from the user's setup (R-41).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SystemPlan {
    /// Reasons for every workspace (global choices).
    pub everywhere: BTreeSet<SystemReason>,
    /// Reasons for one workspace each (per-workspace choices).
    pub workspaces: BTreeMap<WorkspaceName, BTreeSet<SystemReason>>,
}

/// The set with this wire id (`builtin:<slug>`, `user:<id>`, `system`), if it parses. A built-in
/// slug must be one this puddle ships.
///
/// ```
/// use puddle_store::parse_rule_set;
/// use puddle_types::RuleSetId;
/// assert_eq!(parse_rule_set("user:3"), Some(RuleSetId::User(3)));
/// assert_eq!(parse_rule_set("builtin:github"), Some(RuleSetId::BuiltIn("github")));
/// assert_eq!(parse_rule_set("system"), Some(RuleSetId::System));
/// assert_eq!(parse_rule_set("builtin:nope"), None);
/// assert_eq!(parse_rule_set("user:x"), None);
/// ```
#[must_use]
pub fn parse_rule_set(text: &str) -> Option<RuleSetId> {
    if text == "system" {
        return Some(RuleSetId::System);
    }
    if let Some(slug) = text.strip_prefix("builtin:") {
        return catalogue::built_in(slug).map(|set| RuleSetId::BuiltIn(set.slug));
    }
    let id = text.strip_prefix("user:")?;
    if id.starts_with('+') {
        return None;
    }
    id.parse().ok().map(RuleSetId::User)
}

/// Builds the engine's snapshot from the database and the catalogue.
pub(super) fn load_index(conn: &Connection) -> Result<RuleIndex, StoreError> {
    let rules = load_rules(conn)?;
    let mut entries = Vec::new();
    for set in BUILT_IN_SETS {
        for pattern in catalogue::patterns(set.entries) {
            entries.push(SetEntry {
                set: RuleSetId::BuiltIn(set.slug),
                pattern,
                workspace: None,
            });
        }
    }
    for (workspace, reason) in load_reasons(conn)? {
        for pattern in catalogue::patterns(reason.hosts()) {
            entries.push(SetEntry {
                set: RuleSetId::System,
                pattern,
                workspace: workspace.clone(),
            });
        }
    }
    Ok(RuleIndex::new(rules, entries, load_switches(conn)?))
}

fn load_switches(conn: &Connection) -> Result<Switches, StoreError> {
    let mut stmt =
        conn.prepare("SELECT rowid, rule_set, workspace_id, enabled FROM rule_set_switches")?;
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, Option<String>>(2)?,
            row.get::<_, i64>(3)?,
        ))
    })?;
    let mut switches = Switches::default();
    for row in rows {
        let (rowid, set, workspace, enabled) = row?;
        // A switch of a built-in set this version no longer ships is kept but means nothing.
        let Some(set) = parse_rule_set(&set) else {
            continue;
        };
        let workspace = match workspace {
            Some(name) => match WorkspaceName::new(&name) {
                Ok(name) => Some(name),
                // A name this version can't parse is skipped like a set or reason it doesn't
                // know (R-37: such rows are ignored); the log keeps it from being silent.
                Err(e) => {
                    tracing::warn!(rowid, workspace = %name, error = %e, "rule set switch for a workspace name this version can't read; ignored");
                    continue;
                }
            },
            None => None,
        };
        switches.insert(set, workspace, enabled != 0);
    }
    Ok(switches)
}

fn load_reasons(
    conn: &Connection,
) -> Result<Vec<(Option<WorkspaceName>, SystemReason)>, StoreError> {
    let mut stmt = conn
        .prepare("SELECT workspace_id, reason FROM system_reasons ORDER BY workspace_id, reason")?;
    let rows = stmt.query_map([], |row| {
        Ok((row.get::<_, Option<String>>(0)?, row.get::<_, String>(1)?))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (workspace, reason) = row?;
        // Reasons are derived again from the settings at every start; one this version doesn't
        // know is dropped then.
        let Some(reason) = SystemReason::parse(&reason) else {
            continue;
        };
        let workspace = match workspace {
            Some(name) => match WorkspaceName::new(&name) {
                Ok(name) => Some(name),
                Err(_) => continue,
            },
            None => None,
        };
        out.push((workspace, reason));
    }
    Ok(out)
}

/// Records what a puddle update changed in the built-in sets since this database last saw them
/// (R-36): one `rule_set_changed` per changed set. A set seen for the first time is only noted.
pub(super) fn note_built_in_changes(conn: &mut Connection, now: u64) -> Result<(), StoreError> {
    let tx = conn.transaction()?;
    for set in BUILT_IN_SETS {
        let current: BTreeSet<String> = catalogue::patterns(set.entries)
            .iter()
            .map(ToString::to_string)
            .collect();
        let stored: Option<(i64, String)> = tx
            .query_row(
                "SELECT rowid, entries FROM builtin_sets_seen WHERE slug = ?1",
                [set.slug],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let json = serde_json::to_string(&current).map_err(crate::audit::AuditError::from)?;
        match stored {
            None => {
                tx.execute(
                    "INSERT INTO builtin_sets_seen (slug, entries) VALUES (?1, ?2)",
                    params![set.slug, json],
                )?;
            }
            Some((rowid, stored)) => {
                // Reading damage as "no entries" would audit every pattern of the set as added.
                let before: BTreeSet<String> = serde_json::from_str(&stored).map_err(|e| {
                    super::corrupt(
                        "builtin_sets_seen",
                        rowid,
                        format!("entries of {}: {e}", set.slug),
                    )
                })?;
                if before == current {
                    continue;
                }
                tx.execute(
                    "UPDATE builtin_sets_seen SET entries = ?2, changed_at = ?3 WHERE slug = ?1",
                    params![set.slug, json, sql_ts(now)],
                )?;
                let record = AuditRecord::RuleSetChanged {
                    ts: now,
                    set_id: RuleSetId::BuiltIn(set.slug).to_string(),
                    added: current.difference(&before).cloned().collect(),
                    removed: before.difference(&current).cloned().collect(),
                };
                append(&tx, &record)?;
            }
        }
    }
    tx.commit()?;
    Ok(())
}

/// Fails unless the user made a set with this id.
pub(super) fn require_user_set(conn: &Connection, id: i64) -> Result<RuleSetWire, StoreError> {
    conn.query_row(
        "SELECT id, name, description, created_at, created_by FROM rule_sets WHERE id = ?1",
        [id],
        |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, String>(4)?,
            ))
        },
    )
    .optional()?
    .ok_or_else(|| StoreError::UnknownRuleSet(RuleSetId::User(id).to_string()))
    .and_then(|(id, name, description, created_at, created_by)| {
        Ok(RuleSetWire {
            id,
            name,
            description,
            created_at: stored_ts("rule_sets", id, created_at)?,
            created_by,
        })
    })
}

/// Fails unless the set the user made is on for `workspace`: approving into a set that is off
/// there would not allow the request (R-38).
pub(super) fn require_on(
    conn: &Connection,
    id: i64,
    workspace: &WorkspaceName,
) -> Result<(), StoreError> {
    require_user_set(conn, id)?;
    if load_switches(conn)?.is_on(RuleSetId::User(id), workspace) {
        Ok(())
    } else {
        Err(StoreError::RuleSetOff {
            set: RuleSetId::User(id).to_string(),
            workspace: workspace.to_string(),
        })
    }
}

/// A trimmed name of 1 to [`MAX_SET_NAME`] characters without control characters, not used by
/// another set (case-insensitive), and a description of at most [`MAX_SET_DESCRIPTION`].
fn checked_names(
    conn: &Connection,
    name: &str,
    description: &str,
    except: Option<i64>,
) -> Result<(String, String), StoreError> {
    let name = name.trim();
    let description = description.trim();
    let bad = |why: &str| Err(StoreError::RuleSetName(why.to_owned()));
    if name.is_empty() {
        return bad("a name is needed");
    }
    if name.chars().count() > MAX_SET_NAME {
        return bad("at most 64 characters");
    }
    if description.chars().count() > MAX_SET_DESCRIPTION {
        return bad("the description is longer than 500 characters");
    }
    if name
        .chars()
        .chain(description.chars())
        .any(char::is_control)
    {
        return bad("no control characters");
    }
    let taken: Option<i64> = conn
        .query_row(
            "SELECT id FROM rule_sets WHERE name = ?1 COLLATE NOCASE AND id IS NOT ?2",
            params![name, except],
            |row| row.get(0),
        )
        .optional()?;
    if taken.is_some()
        || BUILT_IN_SETS
            .iter()
            .any(|s| s.name.eq_ignore_ascii_case(name))
    {
        return bad("another rule set has this name");
    }
    Ok((name.to_owned(), description.to_owned()))
}

/// Closes the open rows (in `workspace`, or in any workspace) that `index` now decides, the way it
/// decides them (R-37: like a new rule, R-16). Returns the rows it closed.
fn close_rows_now_decided(
    tx: &Transaction<'_>,
    index: &RuleIndex,
    workspace: Option<&WorkspaceName>,
    actor: Actor,
    now: u64,
    fx: &mut Vec<Event>,
) -> Result<Vec<PendingId>, StoreError> {
    let mut stmt = tx.prepare(&format!(
        "SELECT {PENDING_COLUMNS} FROM pending
         WHERE state = 'requested' AND (?1 IS NULL OR workspace_id = ?1) ORDER BY id"
    ))?;
    let open = stmt
        .query_map([workspace.map(WorkspaceName::as_str)], raw_pending)?
        .map(|raw| pending_from_raw(&raw?))
        .collect::<Result<Vec<_>, _>>()?;
    drop(stmt);
    let mut closed = Vec::new();
    for row in &open {
        let Some(hit) = index.decide(&row.workspace, &row.host, now, SuffixAllows::Count) else {
            continue;
        };
        decide_row_by(tx, row, hit, actor, now, fx)?;
        closed.push(row.id);
    }
    Ok(closed)
}

impl Store {
    /// Every rule set: the built-in ones in catalogue order, then the user's by name.
    ///
    /// # Errors
    /// A database error.
    pub fn rule_sets(&self) -> Result<Vec<RuleSetInfo>, StoreError> {
        let index = self.snapshot();
        let conn = lock(&self.conn);
        let mut out = Vec::new();
        for set in BUILT_IN_SETS {
            let id = RuleSetId::BuiltIn(set.slug);
            let changed_at: Option<(i64, Option<i64>)> = conn
                .query_row(
                    "SELECT rowid, changed_at FROM builtin_sets_seen WHERE slug = ?1",
                    [set.slug],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()?;
            let changed_at = match changed_at {
                Some((rowid, Some(t))) => Some(stored_ts("builtin_sets_seen", rowid, t)?),
                _ => None,
            };
            out.push(RuleSetInfo {
                id,
                name: set.name.to_owned(),
                description: set.description.to_owned(),
                default_on: set.default_on,
                global: index.switches().global(id),
                overrides: index.switches().overrides(id),
                entries: set
                    .entries
                    .iter()
                    .map(|entry| RuleSetEntryInfo {
                        pattern: entry.pattern.to_owned(),
                        effect: Effect::Allow,
                        note: entry.note.to_owned(),
                        rule_id: None,
                        expires_at: None,
                    })
                    .collect(),
                changed_at,
                created_at: None,
            });
        }
        let mut stmt = conn.prepare("SELECT id FROM rule_sets ORDER BY name COLLATE NOCASE, id")?;
        let ids = stmt
            .query_map([], |row| row.get::<_, i64>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        drop(stmt);
        for id in ids {
            out.push(user_set_info(&conn, &index, id)?);
        }
        Ok(out)
    }

    /// One rule set.
    ///
    /// # Errors
    /// [`StoreError::UnknownRuleSet`] (also for System managed, which is not a set: see
    /// [`Store::system_managed`]), or a database error.
    pub fn rule_set(&self, id: RuleSetId) -> Result<RuleSetInfo, StoreError> {
        match id {
            RuleSetId::User(user) => {
                let index = self.snapshot();
                user_set_info(&lock(&self.conn), &index, user)
            }
            _ => self
                .rule_sets()?
                .into_iter()
                .find(|set| set.id == id)
                .ok_or_else(|| StoreError::UnknownRuleSet(id.to_string())),
        }
    }

    /// Makes an empty rule set, on by default (R-38).
    ///
    /// # Errors
    /// [`StoreError::RuleSetName`], [`StoreError::SystemActor`], or a database error.
    pub fn create_rule_set(
        &self,
        name: &str,
        description: &str,
        actor: Actor,
    ) -> Result<RuleSetInfo, StoreError> {
        if actor == Actor::System {
            return Err(StoreError::SystemActor);
        }
        let id = self.change(|tx, now, fx| {
            let (name, description) = checked_names(tx, name, description, None)?;
            tx.execute(
                "INSERT INTO rule_sets (name, description, created_at, created_by)
                 VALUES (?1, ?2, ?3, ?4)",
                params![name, description, sql_ts(now), actor.as_str()],
            )?;
            let id = tx.last_insert_rowid();
            let record = AuditRecord::RuleSetCreated {
                ts: now,
                rule_set: require_user_set(tx, id)?,
                actor: actor_str(actor),
            };
            append(tx, &record)?;
            fx.push(Event::RulesChanged {});
            Ok(id)
        })?;
        tracing::info!(set = id, "rule set created");
        self.rule_set(RuleSetId::User(id))
    }

    /// Renames a rule set the user made, or changes its description.
    ///
    /// # Errors
    /// [`StoreError::UnknownRuleSet`], [`StoreError::RuleSetName`],
    /// [`StoreError::SystemActor`], or a database error.
    pub fn update_rule_set(
        &self,
        id: i64,
        name: &str,
        description: &str,
        actor: Actor,
    ) -> Result<RuleSetInfo, StoreError> {
        if actor == Actor::System {
            return Err(StoreError::SystemActor);
        }
        self.change(|tx, now, fx| {
            let before = require_user_set(tx, id)?;
            let (name, description) = checked_names(tx, name, description, Some(id))?;
            tx.execute(
                "UPDATE rule_sets SET name = ?2, description = ?3 WHERE id = ?1",
                params![id, name, description],
            )?;
            let record = AuditRecord::RuleSetUpdated {
                ts: now,
                before,
                rule_set: require_user_set(tx, id)?,
                actor: actor_str(actor),
            };
            append(tx, &record)?;
            fx.push(Event::RulesChanged {});
            Ok(())
        })?;
        self.rule_set(RuleSetId::User(id))
    }

    /// Deletes a rule set the user made, with its entries and switches.
    ///
    /// # Errors
    /// [`StoreError::UnknownRuleSet`], [`StoreError::SystemActor`], or a database error.
    pub fn delete_rule_set(&self, id: i64, actor: Actor) -> Result<RuleSetInfo, StoreError> {
        if actor == Actor::System {
            return Err(StoreError::SystemActor);
        }
        let info = self.rule_set(RuleSetId::User(id))?;
        self.change(|tx, now, fx| {
            let set = require_user_set(tx, id)?;
            let entries: Vec<Rule> = load_rules(tx)?
                .into_iter()
                .filter(|rule| rule.scope == Scope::Set(id))
                .collect();
            tx.execute("DELETE FROM rules WHERE set_id = ?1", [id])?;
            for rule in &entries {
                let record = AuditRecord::RuleDeleted {
                    ts: now,
                    rule: RuleWire::from(rule),
                    reason: RuleDeleteReason::SetDeleted,
                    actor: actor_str(actor),
                };
                append(tx, &record)?;
            }
            tx.execute(
                "DELETE FROM rule_set_switches WHERE rule_set = ?1",
                [RuleSetId::User(id).to_string()],
            )?;
            tx.execute("DELETE FROM rule_sets WHERE id = ?1", [id])?;
            let record = AuditRecord::RuleSetDeleted {
                ts: now,
                rule_set: set,
                actor: actor_str(actor),
            };
            append(tx, &record)?;
            fx.push(Event::RulesChanged {});
            Ok(())
        })?;
        tracing::info!(set = id, entries = info.entries.len(), "rule set deleted");
        Ok(info)
    }

    /// Switches a set on or off for every workspace (`workspace` `None`) or for one, or back to
    /// following the next level (`enabled` `None`), and closes the open requests the set now
    /// decides (R-37). Returns the rows it closed.
    ///
    /// # Errors
    /// [`StoreError::NotSwitchable`] for System managed, [`StoreError::UnknownRuleSet`],
    /// [`StoreError::SystemActor`], or a database error.
    pub fn switch_rule_set(
        &self,
        set: RuleSetId,
        workspace: Option<&WorkspaceName>,
        enabled: Option<bool>,
        actor: Actor,
    ) -> Result<Vec<PendingId>, StoreError> {
        if actor == Actor::System {
            return Err(StoreError::SystemActor);
        }
        let closed = self.change(|tx, now, fx| {
            match set {
                RuleSetId::System => return Err(StoreError::NotSwitchable),
                RuleSetId::User(id) => {
                    require_user_set(tx, id)?;
                }
                RuleSetId::BuiltIn(slug) => {
                    catalogue::built_in(slug)
                        .ok_or_else(|| StoreError::UnknownRuleSet(set.to_string()))?;
                }
                _ => return Err(StoreError::UnknownRuleSet(set.to_string())),
            }
            let key = set.to_string();
            let name = workspace.map(WorkspaceName::as_str);
            tx.execute(
                "DELETE FROM rule_set_switches WHERE rule_set = ?1 AND workspace_id IS ?2",
                params![key, name],
            )?;
            if let Some(on) = enabled {
                tx.execute(
                    "INSERT INTO rule_set_switches (rule_set, workspace_id, enabled, changed_at)
                     VALUES (?1, ?2, ?3, ?4)",
                    params![key, name, i64::from(on), sql_ts(now)],
                )?;
            }
            let record = AuditRecord::RuleSetSwitched {
                ts: now,
                set_id: key,
                workspace_id: name.map(str::to_owned),
                enabled,
                actor: actor_str(actor),
            };
            append(tx, &record)?;
            let index = load_index(tx)?;
            let closed = close_rows_now_decided(tx, &index, workspace, actor, now, fx)?;
            fx.push(Event::RulesChanged {});
            Ok(closed)
        })?;
        tracing::info!(%set, workspace = ?workspace.map(WorkspaceName::as_str), ?enabled, closed = closed.len(), "rule set switched");
        Ok(closed)
    }

    /// The System managed hosts and why each is allowed (R-40), in catalogue order per reason.
    ///
    /// # Errors
    /// A database error.
    pub fn system_managed(&self) -> Result<Vec<SystemHost>, StoreError> {
        let reasons = load_reasons(&lock(&self.conn))?;
        Ok(reasons
            .into_iter()
            .flat_map(|(workspace, reason)| {
                reason.hosts().iter().map(move |entry| SystemHost {
                    pattern: entry.pattern,
                    note: entry.note,
                    reason,
                    workspace: workspace.clone(),
                })
            })
            .collect())
    }

    /// Replaces the System managed reasons with `plan`, derived from the user's setup (R-41).
    /// Records each scope whose reasons changed and closes the open requests the new hosts
    /// decide (by `system`). Returns the rows it closed; a plan equal to the stored one changes
    /// and records nothing.
    ///
    /// # Errors
    /// A database error; nothing changes then.
    pub fn set_system_managed(&self, plan: &SystemPlan) -> Result<Vec<PendingId>, StoreError> {
        let mut wanted: BTreeMap<Option<WorkspaceName>, BTreeSet<SystemReason>> = BTreeMap::new();
        if !plan.everywhere.is_empty() {
            wanted.insert(None, plan.everywhere.clone());
        }
        for (workspace, reasons) in &plan.workspaces {
            if !reasons.is_empty() {
                wanted.insert(Some(workspace.clone()), reasons.clone());
            }
        }
        let current: BTreeMap<Option<WorkspaceName>, BTreeSet<SystemReason>> = {
            let mut map: BTreeMap<_, BTreeSet<_>> = BTreeMap::new();
            for (workspace, reason) in load_reasons(&lock(&self.conn))? {
                map.entry(workspace).or_default().insert(reason);
            }
            map
        };
        if current == wanted {
            return Ok(Vec::new());
        }
        let closed = self.change(|tx, now, fx| {
            tx.execute("DELETE FROM system_reasons", [])?;
            for (workspace, reasons) in &wanted {
                for reason in reasons {
                    tx.execute(
                        "INSERT INTO system_reasons (workspace_id, reason) VALUES (?1, ?2)",
                        params![
                            workspace.as_ref().map(WorkspaceName::as_str),
                            reason.as_str()
                        ],
                    )?;
                }
            }
            let scopes: BTreeSet<&Option<WorkspaceName>> =
                current.keys().chain(wanted.keys()).collect();
            let empty = BTreeSet::new();
            for scope in scopes {
                let before = current.get(scope).unwrap_or(&empty);
                let after = wanted.get(scope).unwrap_or(&empty);
                if before == after {
                    continue;
                }
                let record = AuditRecord::SystemManagedChanged {
                    ts: now,
                    workspace_id: scope.as_ref().map(ToString::to_string),
                    added: after
                        .difference(before)
                        .map(|r| r.as_str().to_owned())
                        .collect(),
                    removed: before
                        .difference(after)
                        .map(|r| r.as_str().to_owned())
                        .collect(),
                };
                append(tx, &record)?;
            }
            let index = load_index(tx)?;
            let closed = close_rows_now_decided(tx, &index, None, Actor::System, now, fx)?;
            fx.push(Event::RulesChanged {});
            Ok(closed)
        })?;
        tracing::info!(closed = closed.len(), "System managed hosts changed");
        Ok(closed)
    }
}

/// A set the user made, with its switches from `index` and its entries.
fn user_set_info(conn: &Connection, index: &RuleIndex, id: i64) -> Result<RuleSetInfo, StoreError> {
    let wire = require_user_set(conn, id)?;
    let set = RuleSetId::User(id);
    Ok(RuleSetInfo {
        id: set,
        name: wire.name,
        description: wire.description,
        default_on: default_on(set),
        global: index.switches().global(set),
        overrides: index.switches().overrides(set),
        entries: index
            .rules()
            .iter()
            .filter(|rule| rule.scope == Scope::Set(id))
            .map(|rule| RuleSetEntryInfo {
                pattern: rule.pattern.to_string(),
                effect: rule.effect,
                note: String::new(),
                rule_id: Some(rule.id),
                expires_at: rule.expires_at,
            })
            .collect(),
        changed_at: None,
        created_at: Some(wire.created_at),
    })
}
