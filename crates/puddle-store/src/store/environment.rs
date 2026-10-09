// SPDX-License-Identifier: GPL-3.0-or-later
//! Environment variables and secrets in the store (`docs/arch/spec/credentials.md` §9). A
//! secret's value never passes through here: only the id it is filed under in the operating
//! system's credential store, the hosts it is for, and each workspace's stand-in for it.

use std::collections::BTreeMap;

use puddle_secrets::StoredId;
use puddle_types::{Event, WorkspaceName};
use rusqlite::{Connection, OptionalExtension, Transaction, params};

use super::{Store, lock, sql_ts};
use crate::environment::{
    EnvChange, EnvDraft, EnvEntry, EnvName, EnvRow, EnvScope, EnvSecret, EnvValue,
    MAX_ENTRIES_PER_SCOPE, MAX_SCOPE_BYTES, SecretHost, StartValue, StartVar,
};
use crate::error::StoreError;

const COLUMNS: &str = "id, workspace_id, name, kind, value, secret_id, hosts, changed_at";

/// The same scope in SQL: the global scope is a NULL workspace, which an expression index and the
/// `ifnull` make comparable.
const IN_SCOPE: &str = "ifnull(workspace_id, '') = ?1";

struct Raw {
    id: i64,
    workspace: Option<String>,
    name: String,
    kind: String,
    value: Option<String>,
    secret_id: Option<String>,
    hosts: Option<String>,
    changed_at: i64,
}

fn raw(row: &rusqlite::Row<'_>) -> rusqlite::Result<Raw> {
    Ok(Raw {
        id: row.get(0)?,
        workspace: row.get(1)?,
        name: row.get(2)?,
        kind: row.get(3)?,
        value: row.get(4)?,
        secret_id: row.get(5)?,
        hosts: row.get(6)?,
        changed_at: row.get(7)?,
    })
}

fn entry_of(raw: Raw) -> Result<EnvEntry, StoreError> {
    let corrupt = |reason: String| StoreError::Corrupt {
        table: "env_vars",
        id: raw.id,
        reason,
    };
    let scope = match &raw.workspace {
        None => EnvScope::Global,
        Some(name) => {
            EnvScope::Workspace(WorkspaceName::new(name).map_err(|e| corrupt(e.to_string()))?)
        }
    };
    let name = EnvName::existing(&raw.name).map_err(|e| corrupt(e.to_string()))?;
    let value = match (raw.kind.as_str(), raw.value, raw.secret_id, raw.hosts) {
        ("plain", Some(value), None, None) => EnvValue::Plain(value),
        ("secret", None, Some(id), Some(hosts)) => {
            let id = StoredId::new(id).map_err(|e| corrupt(e.to_string()))?;
            let hosts: Vec<SecretHost> =
                serde_json::from_str(&hosts).map_err(|e| corrupt(e.to_string()))?;
            EnvValue::Secret(EnvSecret { id, hosts })
        }
        (kind, ..) => return Err(corrupt(format!("a {kind} variable of the wrong shape"))),
    };
    Ok(EnvEntry {
        id: raw.id,
        scope,
        name,
        value,
        changed_at: u64::try_from(raw.changed_at).unwrap_or(0),
    })
}

fn list(conn: &Connection, scope: &EnvScope) -> Result<Vec<EnvEntry>, StoreError> {
    let mut stmt = conn.prepare(&format!(
        "SELECT {COLUMNS} FROM env_vars WHERE {IN_SCOPE} ORDER BY name"
    ))?;
    let rows = stmt
        .query_map([scope.column().unwrap_or("")], raw)?
        .collect::<Result<Vec<_>, _>>()?;
    rows.into_iter().map(entry_of).collect()
}

fn find(
    conn: &Connection,
    scope: &EnvScope,
    name: &EnvName,
) -> Result<Option<EnvEntry>, StoreError> {
    conn.query_row(
        &format!("SELECT {COLUMNS} FROM env_vars WHERE {IN_SCOPE} AND name = ?2"),
        params![scope.column().unwrap_or(""), name.as_str()],
        raw,
    )
    .optional()?
    .map(entry_of)
    .transpose()
}

/// What a scope holds, in the unit the limits count.
fn scope_bytes(entries: &[EnvEntry]) -> usize {
    entries
        .iter()
        .map(|e| {
            e.name.as_str().len()
                + match &e.value {
                    EnvValue::Plain(value) => value.len(),
                    EnvValue::Secret(_) => 0,
                }
        })
        .sum()
}

fn changed(fx: &mut Vec<Event>, scope: &EnvScope) {
    fx.push(match scope {
        EnvScope::Global => Event::GlobalEnvChanged {},
        EnvScope::Workspace(workspace) => Event::WorkspaceEnvChanged {
            workspace: workspace.clone(),
        },
    });
}

fn hosts_json(hosts: &[SecretHost]) -> Result<String, StoreError> {
    serde_json::to_string(hosts)
        .map_err(|e| StoreError::EnvInvalid(format!("hosts can't be stored: {e}")))
}

impl Store {
    /// The variables of one scope, by name.
    ///
    /// # Errors
    /// A database error, or a stored row that doesn't parse.
    pub fn env_entries(&self, scope: &EnvScope) -> Result<Vec<EnvEntry>, StoreError> {
        list(&lock(&self.conn), scope)
    }

    /// One variable of a scope, if set.
    ///
    /// # Errors
    /// A database error, or a stored row that doesn't parse.
    pub fn env_entry(
        &self,
        scope: &EnvScope,
        name: &EnvName,
    ) -> Result<Option<EnvEntry>, StoreError> {
        find(&lock(&self.conn), scope, name)
    }

    /// What `workspace` sees: its own variables and the global ones, each global one marked when
    /// the workspace's own of the same name hides it. By name; a workspace's own entry comes
    /// before the global one it hides.
    ///
    /// # Errors
    /// A database error, or a stored row that doesn't parse.
    pub fn workspace_env(&self, workspace: &WorkspaceName) -> Result<Vec<EnvRow>, StoreError> {
        let conn = lock(&self.conn);
        let own = list(&conn, &EnvScope::Workspace(workspace.clone()))?;
        let global = list(&conn, &EnvScope::Global)?;
        let hidden: Vec<EnvName> = own.iter().map(|e| e.name.clone()).collect();
        let mut rows: Vec<EnvRow> = global
            .into_iter()
            .map(|entry| EnvRow {
                overridden: hidden.contains(&entry.name),
                entry,
            })
            .chain(own.into_iter().map(|entry| EnvRow {
                entry,
                overridden: false,
            }))
            .collect();
        // Stable: within a name the workspace's own entry sorts first.
        rows.sort_by(|a, b| {
            a.entry
                .name
                .cmp(&b.entry.name)
                .then_with(|| a.overridden.cmp(&b.overridden))
        });
        Ok(rows)
    }

    /// Sets `name` in `scope`, replacing what was there.
    ///
    /// A replaced secret keeps its stand-ins when it stays a secret, so a new value (or new
    /// hosts) never changes what a workspace holds; one that becomes a plain variable loses them.
    ///
    /// # Errors
    /// [`StoreError::EnvInvalid`] when the scope would hold more than 256 variables or 256 KiB of
    /// names and values, or a database error. Nothing changes then.
    pub fn set_env(
        &self,
        scope: &EnvScope,
        name: &EnvName,
        draft: EnvDraft,
    ) -> Result<EnvChange, StoreError> {
        self.change(|tx, now, fx| {
            let before = list(tx, scope)?;
            let replaced = before.iter().find(|e| &e.name == name).cloned();
            let (kind, value, secret_id, hosts) = match &draft {
                EnvDraft::Plain(value) => ("plain", Some(value.as_str()), None, None),
                EnvDraft::Secret { id, hosts } => {
                    ("secret", None, Some(id.as_str()), Some(hosts_json(hosts)?))
                }
            };
            let others: Vec<EnvEntry> = before
                .iter()
                .filter(|e| &e.name != name)
                .cloned()
                .collect();
            if replaced.is_none() && others.len() >= MAX_ENTRIES_PER_SCOPE {
                return Err(StoreError::EnvInvalid(format!(
                    "{scope} already holds {MAX_ENTRIES_PER_SCOPE} variables, the most one can"
                )));
            }
            let added = name.as_str().len() + value.map_or(0, str::len);
            if scope_bytes(&others) + added > MAX_SCOPE_BYTES {
                return Err(StoreError::EnvInvalid(format!(
                    "{scope} would hold more than {} KiB of names and values",
                    MAX_SCOPE_BYTES / 1024
                )));
            }
            let id = if let Some(old) = &replaced {
                tx.execute(
                    "UPDATE env_vars SET kind = ?2, value = ?3, secret_id = ?4, hosts = ?5, changed_at = ?6
                     WHERE id = ?1",
                    params![old.id, kind, value, secret_id, hosts, sql_ts(now)],
                )?;
                if kind == "plain" {
                    tx.execute("DELETE FROM env_stand_ins WHERE env_id = ?1", [old.id])?;
                }
                old.id
            } else {
                tx.execute(
                    "INSERT INTO env_vars (workspace_id, name, kind, value, secret_id, hosts, changed_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    params![
                        scope.column(),
                        name.as_str(),
                        kind,
                        value,
                        secret_id,
                        hosts,
                        sql_ts(now)
                    ],
                )?;
                tx.last_insert_rowid()
            };
            changed(fx, scope);
            let entry = find(tx, scope, name)?.ok_or(StoreError::Corrupt {
                table: "env_vars",
                id,
                reason: "a variable that was just written is missing".to_owned(),
            })?;
            Ok(EnvChange { entry, replaced })
        })
    }

    /// Removes `name` from `scope`, with its stand-ins.
    ///
    /// # Errors
    /// [`StoreError::UnknownEnv`] when it isn't set, or a database error. Whoever calls this
    /// removes a removed secret's value from the credential store.
    pub fn delete_env(&self, scope: &EnvScope, name: &EnvName) -> Result<EnvEntry, StoreError> {
        self.change(|tx, _now, fx| {
            let entry = find(tx, scope, name)?.ok_or_else(|| StoreError::UnknownEnv {
                scope: scope.to_string(),
                name: name.to_string(),
            })?;
            tx.execute("DELETE FROM env_vars WHERE id = ?1", [entry.id])?;
            changed(fx, scope);
            Ok(entry)
        })
    }

    /// What `workspace` starts with: the global variables, then its own over them by name. Every
    /// secret gets its stand-in here: the one this workspace already holds for it, else one made
    /// by `mint` (given the secret's name) and kept, so the same stand-in is there at every start.
    ///
    /// # Errors
    /// [`StoreError::EnvInvalid`] when `mint` fails (its message), or a database error.
    pub fn env_for_start(
        &self,
        workspace: &WorkspaceName,
        mint: &mut dyn FnMut(&EnvName) -> Result<String, String>,
    ) -> Result<Vec<StartVar>, StoreError> {
        self.change(|tx, _now, _fx| {
            let mut effective: BTreeMap<EnvName, EnvEntry> = BTreeMap::new();
            for scope in [EnvScope::Global, EnvScope::Workspace(workspace.clone())] {
                for entry in list(tx, &scope)? {
                    effective.insert(entry.name.clone(), entry);
                }
            }
            effective
                .into_values()
                .map(|entry| {
                    let value = match entry.value {
                        EnvValue::Plain(value) => StartValue::Plain(value),
                        EnvValue::Secret(EnvSecret { id, hosts }) => StartValue::Secret {
                            stand_in: stand_in(tx, workspace, entry.id, &entry.name, mint)?,
                            id,
                            hosts,
                        },
                    };
                    Ok(StartVar {
                        name: entry.name,
                        value,
                    })
                })
                .collect()
        })
    }
}

/// The stand-in `workspace` holds for the secret row `env_id`, made when it has none.
fn stand_in(
    tx: &Transaction<'_>,
    workspace: &WorkspaceName,
    env_id: i64,
    name: &EnvName,
    mint: &mut dyn FnMut(&EnvName) -> Result<String, String>,
) -> Result<String, StoreError> {
    let held: Option<String> = tx
        .query_row(
            "SELECT stand_in FROM env_stand_ins WHERE workspace_id = ?1 AND env_id = ?2",
            params![workspace.as_str(), env_id],
            |r| r.get(0),
        )
        .optional()?;
    if let Some(held) = held {
        return Ok(held);
    }
    let made = mint(name).map_err(StoreError::EnvInvalid)?;
    tx.execute(
        "INSERT INTO env_stand_ins (workspace_id, env_id, stand_in) VALUES (?1, ?2, ?3)",
        params![workspace.as_str(), env_id, made],
    )?;
    Ok(made)
}

/// What a deleted workspace held: its own variables and every stand-in it held. The ids of its own
/// secrets are returned, so their values can leave the credential store.
pub(super) fn delete_workspace_rows(
    tx: &Transaction<'_>,
    workspace: &WorkspaceName,
) -> Result<(Vec<StoredId>, bool), StoreError> {
    let own = list(tx, &EnvScope::Workspace(workspace.clone()))?;
    let held = tx.execute(
        "DELETE FROM env_stand_ins WHERE workspace_id = ?1",
        [workspace.as_str()],
    )?;
    tx.execute(
        "DELETE FROM env_vars WHERE workspace_id = ?1",
        [workspace.as_str()],
    )?;
    let secrets = own
        .iter()
        .filter_map(|e| match &e.value {
            EnvValue::Secret(secret) => Some(secret.id.clone()),
            EnvValue::Plain(_) => None,
        })
        .collect();
    Ok((secrets, !own.is_empty() || held > 0))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use puddle_types::EventSink;

    use super::*;
    use crate::clock::ManualClock;
    use crate::store::Limits;

    fn store() -> Store {
        Store::open_in_memory(Arc::new(ManualClock::new(1)), Limits::default()).unwrap()
    }

    fn name(text: &str) -> EnvName {
        EnvName::new(text).unwrap()
    }

    fn ws(text: &str) -> WorkspaceName {
        WorkspaceName::new(text).unwrap()
    }

    fn plain(value: &str) -> EnvDraft {
        EnvDraft::plain(value).unwrap()
    }

    fn secret(id: &str, hosts: &[&str]) -> EnvDraft {
        EnvDraft::secret(
            StoredId::new(id).unwrap(),
            hosts.iter().map(|h| SecretHost::new(h).unwrap()).collect(),
        )
        .unwrap()
    }

    fn mint(name: &EnvName) -> Result<String, String> {
        Ok(format!("stand-in-for-{name}-{:04}", rand_counter()))
    }

    fn rand_counter() -> u32 {
        use std::sync::atomic::{AtomicU32, Ordering};
        static NEXT: AtomicU32 = AtomicU32::new(0);
        NEXT.fetch_add(1, Ordering::Relaxed)
    }

    fn start(store: &Store, workspace: &str) -> Vec<StartVar> {
        store
            .env_for_start(&ws(workspace), &mut |n| mint(n))
            .unwrap()
    }

    #[test]
    fn a_variable_is_set_listed_replaced_and_removed_per_scope() {
        let store = store();
        let global = EnvScope::Global;
        let shop = EnvScope::Workspace(ws("shop"));
        let made = store
            .set_env(&global, &name("EDITOR"), plain("vim"))
            .unwrap();
        assert_eq!(made.replaced, None);
        assert_eq!(made.entry.value, EnvValue::Plain("vim".into()));
        assert_eq!(made.entry.scope, EnvScope::Global);
        store
            .set_env(&shop, &name("EDITOR"), plain("nano"))
            .unwrap();
        store.set_env(&shop, &name("A"), plain("1")).unwrap();

        let second = store
            .set_env(&global, &name("EDITOR"), plain("emacs"))
            .unwrap();
        assert_eq!(
            second.replaced.unwrap().value,
            EnvValue::Plain("vim".into())
        );
        assert_eq!(second.entry.id, made.entry.id, "the row stays");
        let names = |scope: &EnvScope| -> Vec<(String, EnvValue)> {
            store
                .env_entries(scope)
                .unwrap()
                .into_iter()
                .map(|e| (e.name.to_string(), e.value))
                .collect()
        };
        assert_eq!(
            names(&global),
            [("EDITOR".into(), EnvValue::Plain("emacs".into()))]
        );
        assert_eq!(
            names(&shop),
            [
                ("A".into(), EnvValue::Plain("1".into())),
                ("EDITOR".into(), EnvValue::Plain("nano".into()))
            ]
        );
        assert_eq!(
            store.env_entry(&shop, &name("A")).unwrap().unwrap().value,
            EnvValue::Plain("1".into())
        );
        assert!(store.env_entry(&shop, &name("B")).unwrap().is_none());

        let gone = store.delete_env(&shop, &name("A")).unwrap();
        assert_eq!(gone.name, name("A"));
        assert!(matches!(
            store.delete_env(&shop, &name("A")),
            Err(StoreError::UnknownEnv { .. })
        ));
        let text = store.delete_env(&shop, &name("A")).unwrap_err().to_string();
        assert_eq!(text, "no variable A in shop's environment");
    }

    #[test]
    fn a_workspace_sees_its_own_variables_and_the_global_ones_it_does_not_hide() {
        let store = store();
        store
            .set_env(&EnvScope::Global, &name("EDITOR"), plain("vim"))
            .unwrap();
        store
            .set_env(&EnvScope::Global, &name("LANG_X"), plain("en"))
            .unwrap();
        let shop = ws("shop");
        store
            .set_env(
                &EnvScope::Workspace(shop.clone()),
                &name("EDITOR"),
                plain("nano"),
            )
            .unwrap();
        store
            .set_env(
                &EnvScope::Workspace(ws("other")),
                &name("ZZ"),
                plain("not mine"),
            )
            .unwrap();
        let rows: Vec<(String, bool, bool)> = store
            .workspace_env(&shop)
            .unwrap()
            .into_iter()
            .map(|r| {
                (
                    r.entry.name.to_string(),
                    r.entry.scope == EnvScope::Global,
                    r.overridden,
                )
            })
            .collect();
        assert_eq!(
            rows,
            [
                ("EDITOR".into(), false, false),
                ("EDITOR".into(), true, true),
                ("LANG_X".into(), true, false),
            ]
        );
    }

    #[test]
    fn a_secret_keeps_its_id_and_hosts_and_never_a_value() {
        let store = store();
        let scope = EnvScope::Workspace(ws("shop"));
        let made = store
            .set_env(
                &scope,
                &name("NPM_TOKEN"),
                secret("env-1", &["registry.npmjs.org"]),
            )
            .unwrap();
        let EnvValue::Secret(kept) = made.entry.value else {
            panic!("a secret")
        };
        assert_eq!(kept.id.as_str(), "env-1");
        assert_eq!(kept.hosts[0].as_str(), "registry.npmjs.org");
        // The database holds the reference and the hosts, no value column filled.
        let conn = lock(&store.conn);
        let (value, secret_id): (Option<String>, Option<String>) = conn
            .query_row("SELECT value, secret_id FROM env_vars", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
        assert_eq!((value, secret_id.as_deref()), (None, Some("env-1")));
    }

    #[test]
    fn a_stand_in_is_made_once_per_workspace_and_secret_and_kept() {
        let store = store();
        store
            .set_env(
                &EnvScope::Global,
                &name("TOKEN"),
                secret("env-g", &["api.example.com"]),
            )
            .unwrap();
        let first = start(&store, "a");
        let again = start(&store, "a");
        assert_eq!(first, again, "the same stand-in at every start");
        let other = start(&store, "b");
        let text = |vars: &[StartVar]| match &vars[0].value {
            StartValue::Secret { stand_in, .. } => stand_in.clone(),
            StartValue::Plain(_) => panic!("a secret"),
        };
        assert_ne!(text(&first), text(&other), "each workspace has its own");

        // A new value or new hosts under the same row keep the stand-in.
        store
            .set_env(
                &EnvScope::Global,
                &name("TOKEN"),
                secret("env-g", &["other.example.com"]),
            )
            .unwrap();
        let moved = start(&store, "a");
        assert_eq!(text(&moved), text(&first));
        let StartValue::Secret { hosts, .. } = &moved[0].value else {
            panic!("a secret")
        };
        assert_eq!(hosts[0].as_str(), "other.example.com");

        // Removing the secret and making it again is a new secret with a new stand-in.
        store.delete_env(&EnvScope::Global, &name("TOKEN")).unwrap();
        assert!(start(&store, "a").is_empty());
        store
            .set_env(
                &EnvScope::Global,
                &name("TOKEN"),
                secret("env-g2", &["api.example.com"]),
            )
            .unwrap();
        assert_ne!(text(&start(&store, "a")), text(&first));
    }

    #[test]
    fn a_secret_that_becomes_plain_loses_its_stand_ins() {
        let store = store();
        let scope = EnvScope::Workspace(ws("a"));
        store
            .set_env(&scope, &name("T"), secret("env-1", &["x.example.com"]))
            .unwrap();
        start(&store, "a");
        let n = |sql: &str| -> i64 { lock(&store.conn).query_row(sql, [], |r| r.get(0)).unwrap() };
        assert_eq!(n("SELECT count(*) FROM env_stand_ins"), 1);
        let change = store
            .set_env(&scope, &name("T"), plain("now plain"))
            .unwrap();
        assert!(matches!(
            change.replaced.unwrap().value,
            EnvValue::Secret(_)
        ));
        assert_eq!(n("SELECT count(*) FROM env_stand_ins"), 0);
        assert_eq!(
            start(&store, "a")[0].value,
            StartValue::Plain("now plain".into())
        );
    }

    #[test]
    fn the_workspace_entry_wins_over_the_global_one_at_start_and_only_the_winner_has_a_stand_in() {
        let store = store();
        store
            .set_env(
                &EnvScope::Global,
                &name("T"),
                secret("env-g", &["g.example.com"]),
            )
            .unwrap();
        store
            .set_env(&EnvScope::Workspace(ws("a")), &name("T"), plain("mine"))
            .unwrap();
        let vars = start(&store, "a");
        assert_eq!(vars.len(), 1);
        assert_eq!(vars[0].value, StartValue::Plain("mine".into()));
        let held: i64 = lock(&store.conn)
            .query_row("SELECT count(*) FROM env_stand_ins", [], |r| r.get(0))
            .unwrap();
        assert_eq!(held, 0, "the hidden global secret got none");
        // Another workspace still gets the global one.
        assert!(matches!(
            start(&store, "b")[0].value,
            StartValue::Secret { .. }
        ));
    }

    #[test]
    fn a_stand_in_that_cannot_be_made_stops_the_start_with_its_reason() {
        let store = store();
        store
            .set_env(
                &EnvScope::Global,
                &name("T"),
                secret("env-g", &["g.example.com"]),
            )
            .unwrap();
        let err = store
            .env_for_start(&ws("a"), &mut |_| Err("no randomness".into()))
            .unwrap_err();
        assert_eq!(err.to_string(), "no randomness");
        // Nothing half-made was kept.
        assert!(matches!(
            start(&store, "a")[0].value,
            StartValue::Secret { .. }
        ));
    }

    #[test]
    fn a_scope_holds_at_most_256_variables_and_256_kib() {
        let store = store();
        let scope = EnvScope::Workspace(ws("a"));
        for i in 0..MAX_ENTRIES_PER_SCOPE {
            store
                .set_env(&scope, &name(&format!("V{i}")), plain("x"))
                .unwrap();
        }
        let err = store
            .set_env(&scope, &name("ONE_MORE"), plain("x"))
            .unwrap_err();
        assert!(err.to_string().contains("256 variables"), "{err}");
        // Replacing one is not adding one.
        store.set_env(&scope, &name("V0"), plain("y")).unwrap();
        // Another scope is counted on its own.
        store
            .set_env(&EnvScope::Global, &name("ONE_MORE"), plain("x"))
            .unwrap();

        let big = EnvScope::Workspace(ws("big"));
        let chunk = "x".repeat(crate::environment::MAX_PLAIN_VALUE_BYTES);
        let fits = MAX_SCOPE_BYTES / (chunk.len() + 2);
        for i in 0..fits {
            store
                .set_env(&big, &name(&format!("B{i:x}")), plain(&chunk))
                .unwrap();
        }
        let err = store
            .set_env(&big, &name("BIG"), plain(&chunk))
            .unwrap_err();
        assert!(err.to_string().contains("256 KiB"), "{err}");
        // A shorter value of an existing name that frees room is accepted.
        store.set_env(&big, &name("B0"), plain("")).unwrap();
        store.set_env(&big, &name("BIG"), plain(&chunk)).unwrap();
    }

    #[test]
    fn changes_say_which_scope_changed() {
        #[derive(Default)]
        struct Events(std::sync::Mutex<Vec<Event>>);
        impl EventSink for Events {
            fn emit(&self, event: Event) {
                self.0.lock().unwrap().push(event);
            }
        }
        let events = Arc::new(Events::default());
        let store = Store::open_in_memory(Arc::new(ManualClock::new(1)), Limits::default())
            .unwrap()
            .with_events(events.clone());
        store
            .set_env(&EnvScope::Global, &name("A"), plain("1"))
            .unwrap();
        store
            .set_env(&EnvScope::Workspace(ws("shop")), &name("A"), plain("1"))
            .unwrap();
        store
            .delete_env(&EnvScope::Workspace(ws("shop")), &name("A"))
            .unwrap();
        store.delete_env(&EnvScope::Global, &name("A")).unwrap();
        assert_eq!(
            *events.0.lock().unwrap(),
            [
                Event::GlobalEnvChanged {},
                Event::WorkspaceEnvChanged {
                    workspace: ws("shop")
                },
                Event::WorkspaceEnvChanged {
                    workspace: ws("shop")
                },
                Event::GlobalEnvChanged {},
            ]
        );
    }

    #[test]
    fn deleting_a_workspace_removes_its_variables_and_every_stand_in_it_held() {
        let store = store();
        let shop = ws("shop");
        store
            .set_env(
                &EnvScope::Global,
                &name("G"),
                secret("env-g", &["g.example.com"]),
            )
            .unwrap();
        store
            .set_env(
                &EnvScope::Workspace(shop.clone()),
                &name("W"),
                secret("env-w", &["w.example.com"]),
            )
            .unwrap();
        store
            .set_env(&EnvScope::Workspace(shop.clone()), &name("P"), plain("p"))
            .unwrap();
        store
            .set_env(
                &EnvScope::Workspace(ws("other")),
                &name("W"),
                secret("env-o", &["w.example.com"]),
            )
            .unwrap();
        start(&store, "shop");
        start(&store, "other");

        let deletion = store.delete_workspace(&shop).unwrap();
        assert_eq!(
            deletion
                .secret_ids
                .iter()
                .map(StoredId::as_str)
                .collect::<Vec<_>>(),
            ["env-w"],
            "only the workspace's own secrets: the global one still serves the others"
        );
        assert!(
            store
                .env_entries(&EnvScope::Workspace(shop))
                .unwrap()
                .is_empty()
        );
        assert_eq!(store.env_entries(&EnvScope::Global).unwrap().len(), 1);
        assert_eq!(
            store
                .env_entries(&EnvScope::Workspace(ws("other")))
                .unwrap()
                .len(),
            1
        );
        let held: Vec<String> = {
            let conn = lock(&store.conn);
            let mut stmt = conn
                .prepare("SELECT workspace_id FROM env_stand_ins ORDER BY 1")
                .unwrap();
            stmt.query_map([], |r| r.get(0))
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap()
        };
        assert_eq!(held, ["other", "other"], "other's two stand-ins stay");
    }

    #[test]
    fn a_row_edited_by_hand_to_something_that_does_not_parse_is_reported() {
        let store = store();
        let scope = EnvScope::Workspace(ws("a"));
        store
            .set_env(&scope, &name("T"), secret("env-1", &["x.example.com"]))
            .unwrap();
        lock(&store.conn)
            .execute("UPDATE env_vars SET hosts = 'not json'", [])
            .unwrap();
        assert!(matches!(
            store.env_entries(&scope),
            Err(StoreError::Corrupt {
                table: "env_vars",
                ..
            })
        ));
        lock(&store.conn)
            .execute("UPDATE env_vars SET hosts = '[\"*.com\"]'", [])
            .unwrap();
        assert!(
            store.env_entries(&scope).is_err(),
            "a host list that fails its own rules"
        );
        lock(&store.conn)
            .execute(
                "UPDATE env_vars SET hosts = '[]', secret_id = 'has space'",
                [],
            )
            .unwrap();
        assert!(
            store.env_entries(&scope).is_err(),
            "an id the credential store would not take"
        );
        lock(&store.conn)
            .execute("UPDATE env_vars SET name = '1bad', secret_id = 'env-1'", [])
            .unwrap();
        assert!(store.env_entries(&scope).is_err(), "a name that is not one");
    }

    #[test]
    fn a_name_a_later_release_reserves_stays_listable_and_removable() {
        let store = store();
        let scope = EnvScope::Workspace(ws("a"));
        store.set_env(&scope, &name("T"), plain("v")).unwrap();
        lock(&store.conn)
            .execute("UPDATE env_vars SET name = 'HTTPS_PROXY'", [])
            .unwrap();
        let listed = store.env_entries(&scope).unwrap();
        assert_eq!(listed[0].name.as_str(), "HTTPS_PROXY");
        let proxy = EnvName::existing("HTTPS_PROXY").unwrap();
        store.delete_env(&scope, &proxy).unwrap();
        assert!(store.env_entries(&scope).unwrap().is_empty());
    }
}
