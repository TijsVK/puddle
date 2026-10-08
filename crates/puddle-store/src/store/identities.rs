// SPDX-License-Identifier: GPL-3.0-or-later
//! Identities and each workspace's Git settings in the store (`docs/arch/spec/credentials.md`
//! §7 and §8). Credentials are stored as references to their sources; no value passes through.

use puddle_types::{Event, WorkspaceName};
use rusqlite::{Connection, OptionalExtension, Transaction, params};

use super::{Store, lock, sql_ts};
use crate::error::StoreError;
use crate::identity::{
    Author, CredentialBinding, Identity, IdentityDraft, IdentityId, Signing, check_attachable,
    collision,
};
use crate::workspace_git::{RepoEntry, RepoRef, WorkspaceGit};

const COLUMNS: &str = "id, label, author_name, author_email, credentials, signing, is_default, \
                       created_at, changed_at";

struct Raw {
    id: i64,
    label: String,
    name: String,
    email: String,
    credentials: String,
    signing: String,
    is_default: bool,
    created_at: i64,
    changed_at: i64,
}

fn raw(row: &rusqlite::Row<'_>) -> rusqlite::Result<Raw> {
    Ok(Raw {
        id: row.get(0)?,
        label: row.get(1)?,
        name: row.get(2)?,
        email: row.get(3)?,
        credentials: row.get(4)?,
        signing: row.get(5)?,
        is_default: row.get(6)?,
        created_at: row.get(7)?,
        changed_at: row.get(8)?,
    })
}

fn identity_of(raw: Raw) -> Result<Identity, StoreError> {
    let corrupt = |reason: String| StoreError::Corrupt {
        table: "identities",
        id: raw.id,
        reason,
    };
    let credentials: Vec<CredentialBinding> =
        serde_json::from_str(&raw.credentials).map_err(|e| corrupt(e.to_string()))?;
    let author = Author::new(&raw.name, &raw.email).map_err(|e| corrupt(e.to_string()))?;
    let signing = match raw.signing.as_str() {
        "none" => Signing::None,
        other => return Err(corrupt(format!("unknown signing {other}"))),
    };
    Ok(Identity {
        id: IdentityId(raw.id),
        label: raw.label,
        author,
        credentials,
        signing,
        is_default: raw.is_default,
        created_at: u64::try_from(raw.created_at).unwrap_or(0),
        changed_at: u64::try_from(raw.changed_at).unwrap_or(0),
    })
}

fn all(conn: &Connection) -> Result<Vec<Identity>, StoreError> {
    let mut stmt = conn.prepare(&format!(
        "SELECT {COLUMNS} FROM identities ORDER BY position, id"
    ))?;
    let rows = stmt.query_map([], raw)?.collect::<Result<Vec<_>, _>>()?;
    rows.into_iter().map(identity_of).collect()
}

fn one(conn: &Connection, id: IdentityId) -> Result<Identity, StoreError> {
    let raw = conn
        .query_row(
            &format!("SELECT {COLUMNS} FROM identities WHERE id = ?1"),
            [id.0],
            raw,
        )
        .optional()?
        .ok_or(StoreError::UnknownIdentity(id))?;
    identity_of(raw)
}

fn attached_ids(conn: &Connection, ws: &WorkspaceName) -> Result<Vec<IdentityId>, StoreError> {
    let mut stmt = conn.prepare(
        "SELECT identity_id FROM workspace_identities WHERE workspace_id = ?1 ORDER BY position",
    )?;
    let ids = stmt
        .query_map([ws.as_str()], |r| r.get::<_, i64>(0).map(IdentityId))?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ids)
}

fn attached(conn: &Connection, ws: &WorkspaceName) -> Result<Vec<Identity>, StoreError> {
    attached_ids(conn, ws)?
        .into_iter()
        .map(|id| one(conn, id))
        .collect()
}

fn workspaces_using(conn: &Connection, id: IdentityId) -> Result<Vec<WorkspaceName>, StoreError> {
    let mut stmt = conn.prepare(
        "SELECT DISTINCT workspace_id FROM workspace_identities WHERE identity_id = ?1 ORDER BY 1",
    )?;
    let names = stmt
        .query_map([id.0], |r| r.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(names
        .into_iter()
        .filter_map(|n| WorkspaceName::new(&n).ok())
        .collect())
}

fn write_list(
    tx: &Transaction<'_>,
    ws: &WorkspaceName,
    ids: &[IdentityId],
) -> Result<(), StoreError> {
    tx.execute(
        "DELETE FROM workspace_identities WHERE workspace_id = ?1",
        [ws.as_str()],
    )?;
    for (position, id) in ids.iter().enumerate() {
        tx.execute(
            "INSERT INTO workspace_identities (workspace_id, identity_id, position) VALUES (?1, ?2, ?3)",
            params![ws.as_str(), id.0, i64::try_from(position).unwrap_or(i64::MAX)],
        )?;
    }
    Ok(())
}

/// Refuses a list of identities in which two cover the same place.
fn check_list(list: &[Identity]) -> Result<(), StoreError> {
    for (i, a) in list.iter().enumerate() {
        if let Some(c) = list.iter().skip(i + 1).find_map(|b| collision(a, b)) {
            return Err(StoreError::IdentityCollision(c));
        }
    }
    Ok(())
}

fn label_free(
    tx: &Transaction<'_>,
    label: &str,
    except: Option<IdentityId>,
) -> Result<(), StoreError> {
    let taken: Option<i64> = tx
        .query_row(
            "SELECT id FROM identities WHERE label = ?1 AND id IS NOT ?2",
            params![label, except.map(|i| i.0)],
            |r| r.get(0),
        )
        .optional()?;
    if taken.is_some() {
        return Err(StoreError::IdentityLabelTaken(label.to_owned()));
    }
    Ok(())
}

fn credentials_json(credentials: &[CredentialBinding]) -> Result<String, StoreError> {
    serde_json::to_string(credentials)
        .map_err(|e| StoreError::IdentityInvalid(format!("credentials can't be stored: {e}")))
}

fn changed_for(fx: &mut Vec<Event>, workspaces: Vec<WorkspaceName>) {
    fx.push(Event::IdentitiesChanged {});
    fx.extend(
        workspaces
            .into_iter()
            .map(|workspace| Event::WorkspaceGitChanged { workspace }),
    );
}

impl Store {
    /// Every identity, in the order the user keeps them.
    ///
    /// # Errors
    /// A database error, or a stored row that doesn't parse.
    pub fn identities(&self) -> Result<Vec<Identity>, StoreError> {
        all(&lock(&self.conn))
    }

    /// One identity.
    ///
    /// # Errors
    /// [`StoreError::UnknownIdentity`], or a database error.
    pub fn identity(&self, id: IdentityId) -> Result<Identity, StoreError> {
        one(&lock(&self.conn), id)
    }

    /// The default identity: the one a new workspace gets when none covers its URL.
    ///
    /// # Errors
    /// A database error.
    pub fn default_identity(&self) -> Result<Option<Identity>, StoreError> {
        Ok(all(&lock(&self.conn))?.into_iter().find(|i| i.is_default))
    }

    /// The workspaces an identity is on.
    ///
    /// # Errors
    /// A database error.
    pub fn identity_workspaces(&self, id: IdentityId) -> Result<Vec<WorkspaceName>, StoreError> {
        workspaces_using(&lock(&self.conn), id)
    }

    /// Makes an identity, last in the order; the first one made is the default.
    ///
    /// # Errors
    /// [`StoreError::IdentityInvalid`], [`StoreError::IdentityLabelTaken`], or a database error.
    pub fn create_identity(&self, draft: IdentityDraft) -> Result<Identity, StoreError> {
        let draft = draft.checked()?;
        let id = self.change(|tx, now, fx| {
            label_free(tx, &draft.label, None)?;
            let first: bool =
                tx.query_row("SELECT count(*) = 0 FROM identities", [], |r| r.get(0))?;
            tx.execute(
                "INSERT INTO identities (label, author_name, author_email, credentials, position,
                                         is_default, created_at, changed_at)
                 VALUES (?1, ?2, ?3, ?4, (SELECT coalesce(max(position) + 1, 0) FROM identities),
                         ?5, ?6, ?6)",
                params![
                    draft.label,
                    draft.author.name,
                    draft.author.email,
                    credentials_json(&draft.credentials)?,
                    first,
                    sql_ts(now),
                ],
            )?;
            changed_for(fx, Vec::new());
            Ok(IdentityId(tx.last_insert_rowid()))
        })?;
        tracing::info!(identity = %id, "identity created");
        self.identity(id)
    }

    /// Replaces an identity's label, author and credentials. Refused with a collision when the new
    /// coverage meets another identity on a workspace that has both.
    ///
    /// # Errors
    /// [`StoreError::UnknownIdentity`], [`StoreError::IdentityInvalid`],
    /// [`StoreError::IdentityLabelTaken`], [`StoreError::IdentityCollision`], or a database error.
    pub fn update_identity(
        &self,
        id: IdentityId,
        draft: IdentityDraft,
    ) -> Result<Identity, StoreError> {
        let draft = draft.checked()?;
        self.change(|tx, now, fx| {
            let before = one(tx, id)?;
            label_free(tx, &draft.label, Some(id))?;
            let mut after = before.clone();
            after.label.clone_from(&draft.label);
            after.author = draft.author.clone();
            after.credentials.clone_from(&draft.credentials);
            let workspaces = workspaces_using(tx, id)?;
            for ws in &workspaces {
                check_attachable(&attached(tx, ws)?, &after)
                    .map_err(StoreError::IdentityCollision)?;
            }
            tx.execute(
                "UPDATE identities SET label = ?2, author_name = ?3, author_email = ?4,
                        credentials = ?5, changed_at = ?6 WHERE id = ?1",
                params![
                    id.0,
                    draft.label,
                    draft.author.name,
                    draft.author.email,
                    credentials_json(&draft.credentials)?,
                    sql_ts(now),
                ],
            )?;
            changed_for(fx, workspaces);
            Ok(())
        })?;
        self.identity(id)
    }

    /// Deletes an identity and takes it off every workspace; returns the workspaces it left. The
    /// default passes to the first identity in the order.
    ///
    /// # Errors
    /// [`StoreError::UnknownIdentity`], or a database error.
    pub fn delete_identity(&self, id: IdentityId) -> Result<Vec<WorkspaceName>, StoreError> {
        let left = self.change(|tx, _now, fx| {
            let gone = one(tx, id)?;
            let workspaces = workspaces_using(tx, id)?;
            tx.execute(
                "DELETE FROM workspace_identities WHERE identity_id = ?1",
                [id.0],
            )?;
            tx.execute("DELETE FROM identities WHERE id = ?1", [id.0])?;
            if gone.is_default {
                tx.execute(
                    "UPDATE identities SET is_default = 1
                     WHERE id = (SELECT id FROM identities ORDER BY position, id LIMIT 1)",
                    [],
                )?;
            }
            for ws in &workspaces {
                let rest: Vec<IdentityId> = attached_ids(tx, ws)?;
                write_list(tx, ws, &rest)?;
            }
            changed_for(fx, workspaces.clone());
            Ok(workspaces)
        })?;
        tracing::info!(identity = %id, workspaces = left.len(), "identity deleted");
        Ok(left)
    }

    /// Makes `id` the default identity.
    ///
    /// # Errors
    /// [`StoreError::UnknownIdentity`], or a database error.
    pub fn set_default_identity(&self, id: IdentityId) -> Result<Identity, StoreError> {
        self.change(|tx, _now, fx| {
            one(tx, id)?;
            tx.execute(
                "UPDATE identities SET is_default = 0 WHERE is_default = 1",
                [],
            )?;
            tx.execute("UPDATE identities SET is_default = 1 WHERE id = ?1", [id.0])?;
            changed_for(fx, Vec::new());
            Ok(())
        })?;
        self.identity(id)
    }

    /// Puts the identities in a new order; `ids` must name every identity once.
    ///
    /// # Errors
    /// [`StoreError::IdentityInvalid`] when `ids` is not a permutation of the identities, or a
    /// database error.
    pub fn reorder_identities(&self, ids: &[IdentityId]) -> Result<Vec<Identity>, StoreError> {
        self.change(|tx, _now, fx| {
            let mut have: Vec<IdentityId> = all(tx)?.into_iter().map(|i| i.id).collect();
            let mut want = ids.to_vec();
            have.sort();
            want.sort();
            if have != want {
                return Err(StoreError::IdentityInvalid(
                    "the order must list every identity exactly once".into(),
                ));
            }
            for (position, id) in ids.iter().enumerate() {
                tx.execute(
                    "UPDATE identities SET position = ?2 WHERE id = ?1",
                    params![id.0, i64::try_from(position).unwrap_or(i64::MAX)],
                )?;
            }
            changed_for(fx, Vec::new());
            Ok(())
        })?;
        self.identities()
    }

    /// A workspace's Git settings: its identities in order, its repository table and the two
    /// switches. A workspace nobody configured gets the defaults.
    ///
    /// # Errors
    /// A database error, or a stored row that doesn't parse.
    pub fn workspace_git(&self, ws: &WorkspaceName) -> Result<WorkspaceGit, StoreError> {
        let conn = lock(&self.conn);
        let (only_push_listed, only_pull_listed) = conn
            .query_row(
                "SELECT only_push_listed, only_pull_listed FROM workspace_git WHERE workspace_id = ?1",
                [ws.as_str()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?
            .unwrap_or((true, false));
        let mut stmt = conn.prepare(
            "SELECT id, host, owner, repo, pull, push, created_at FROM workspace_repos
             WHERE workspace_id = ?1 ORDER BY id",
        )?;
        let rows = stmt
            .query_map([ws.as_str()], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, bool>(4)?,
                    r.get::<_, bool>(5)?,
                    r.get::<_, i64>(6)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        let repos = rows
            .into_iter()
            .map(|(id, host, owner, repo, pull, push, at)| {
                let repo = RepoRef::new(&host, &owner, &repo).map_err(|e| StoreError::Corrupt {
                    table: "workspace_repos",
                    id,
                    reason: e.to_string(),
                })?;
                Ok(RepoEntry {
                    id,
                    repo,
                    pull,
                    push,
                    created_at: u64::try_from(at).unwrap_or(0),
                })
            })
            .collect::<Result<Vec<_>, StoreError>>()?;
        Ok(WorkspaceGit {
            identities: attached(&conn, ws)?,
            repos,
            only_push_listed,
            only_pull_listed,
        })
    }

    /// Replaces the workspace's ordered identity list.
    ///
    /// # Errors
    /// [`StoreError::UnknownIdentity`], [`StoreError::IdentityInvalid`] for a repeated id,
    /// [`StoreError::IdentityCollision`] naming both when two cover the same place, or a
    /// database error. Nothing changes on an error.
    pub fn set_workspace_identities(
        &self,
        ws: &WorkspaceName,
        ids: &[IdentityId],
    ) -> Result<WorkspaceGit, StoreError> {
        self.change(|tx, _now, fx| {
            let mut list = Vec::with_capacity(ids.len());
            for id in ids {
                if list.iter().any(|i: &Identity| i.id == *id) {
                    return Err(StoreError::IdentityInvalid(
                        "an identity is listed twice".into(),
                    ));
                }
                list.push(one(tx, *id)?);
            }
            check_list(&list)?;
            write_list(tx, ws, ids)?;
            fx.push(Event::WorkspaceGitChanged {
                workspace: ws.clone(),
            });
            Ok(())
        })?;
        self.workspace_git(ws)
    }

    /// Adds an identity to the workspace, last unless `position` says otherwise.
    ///
    /// # Errors
    /// As [`Store::set_workspace_identities`], and [`StoreError::IdentityAttached`] when it is
    /// already there.
    pub fn attach_identity(
        &self,
        ws: &WorkspaceName,
        id: IdentityId,
        position: Option<usize>,
    ) -> Result<WorkspaceGit, StoreError> {
        let current = {
            let conn = lock(&self.conn);
            let candidate = one(&conn, id)?;
            let ids = attached_ids(&conn, ws)?;
            if ids.contains(&id) {
                return Err(StoreError::IdentityAttached {
                    label: candidate.label,
                });
            }
            ids
        };
        let mut ids = current;
        ids.insert(position.unwrap_or(ids.len()).min(ids.len()), id);
        self.set_workspace_identities(ws, &ids)
    }

    /// Takes an identity off the workspace.
    ///
    /// # Errors
    /// [`StoreError::UnknownIdentity`] when it is not on the workspace, or a database error.
    pub fn detach_identity(
        &self,
        ws: &WorkspaceName,
        id: IdentityId,
    ) -> Result<WorkspaceGit, StoreError> {
        let mut ids = attached_ids(&lock(&self.conn), ws)?;
        let before = ids.len();
        ids.retain(|i| *i != id);
        if ids.len() == before {
            return Err(StoreError::UnknownIdentity(id));
        }
        self.set_workspace_identities(ws, &ids)
    }

    /// Sets either "only listed" switch; `None` leaves it as it is.
    ///
    /// # Errors
    /// A database error.
    pub fn set_git_switches(
        &self,
        ws: &WorkspaceName,
        only_push_listed: Option<bool>,
        only_pull_listed: Option<bool>,
    ) -> Result<WorkspaceGit, StoreError> {
        let now = self.workspace_git(ws)?;
        self.change(|tx, _now, fx| {
            tx.execute(
                "INSERT INTO workspace_git (workspace_id, only_push_listed, only_pull_listed)
                 VALUES (?1, ?2, ?3)
                 ON CONFLICT (workspace_id) DO UPDATE
                 SET only_push_listed = ?2, only_pull_listed = ?3",
                params![
                    ws.as_str(),
                    only_push_listed.unwrap_or(now.only_push_listed),
                    only_pull_listed.unwrap_or(now.only_pull_listed),
                ],
            )?;
            fx.push(Event::WorkspaceGitChanged {
                workspace: ws.clone(),
            });
            Ok(())
        })?;
        self.workspace_git(ws)
    }

    /// Adds a repository to the table.
    ///
    /// # Errors
    /// [`StoreError::RepoListed`] when it is already there, or a database error.
    pub fn add_repo(
        &self,
        ws: &WorkspaceName,
        repo: &RepoRef,
        pull: bool,
        push: bool,
    ) -> Result<RepoEntry, StoreError> {
        let id = self.change(|tx, now, fx| {
            let added = tx.execute(
                "INSERT INTO workspace_repos (workspace_id, host, owner, repo, pull, push, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                 ON CONFLICT DO NOTHING",
                params![
                    ws.as_str(),
                    repo.host.as_str(),
                    repo.owner.as_str(),
                    repo.repo,
                    pull,
                    push,
                    sql_ts(now)
                ],
            )?;
            if added == 0 {
                return Err(StoreError::RepoListed(repo.to_string()));
            }
            fx.push(Event::WorkspaceGitChanged { workspace: ws.clone() });
            Ok(tx.last_insert_rowid())
        })?;
        self.repo_entry(ws, id)
    }

    fn repo_entry(&self, ws: &WorkspaceName, id: i64) -> Result<RepoEntry, StoreError> {
        self.workspace_git(ws)?
            .repos
            .into_iter()
            .find(|entry| entry.id == id)
            .ok_or(StoreError::UnknownRepo(id))
    }

    /// Sets a row's Pull and Push toggles.
    ///
    /// # Errors
    /// [`StoreError::UnknownRepo`], or a database error.
    pub fn set_repo_toggles(
        &self,
        ws: &WorkspaceName,
        id: i64,
        pull: bool,
        push: bool,
    ) -> Result<RepoEntry, StoreError> {
        self.change(|tx, _now, fx| {
            let n = tx.execute(
                "UPDATE workspace_repos SET pull = ?3, push = ?4 WHERE id = ?1 AND workspace_id = ?2",
                params![id, ws.as_str(), pull, push],
            )?;
            if n == 0 {
                return Err(StoreError::UnknownRepo(id));
            }
            fx.push(Event::WorkspaceGitChanged { workspace: ws.clone() });
            Ok(())
        })?;
        self.repo_entry(ws, id)
    }

    /// Removes a row from the table.
    ///
    /// # Errors
    /// [`StoreError::UnknownRepo`], or a database error.
    pub fn remove_repo(&self, ws: &WorkspaceName, id: i64) -> Result<(), StoreError> {
        self.change(|tx, _now, fx| {
            let n = tx.execute(
                "DELETE FROM workspace_repos WHERE id = ?1 AND workspace_id = ?2",
                params![id, ws.as_str()],
            )?;
            if n == 0 {
                return Err(StoreError::UnknownRepo(id));
            }
            fx.push(Event::WorkspaceGitChanged {
                workspace: ws.clone(),
            });
            Ok(())
        })
    }
}

/// Drops what a deleted workspace held in the Git tables.
pub(super) fn delete_workspace_rows(
    tx: &Transaction<'_>,
    ws: &WorkspaceName,
) -> Result<bool, StoreError> {
    let mut any = 0;
    for table in ["workspace_identities", "workspace_git", "workspace_repos"] {
        any += tx.execute(
            &format!("DELETE FROM {table} WHERE workspace_id = ?1"),
            [ws.as_str()],
        )?;
    }
    Ok(any > 0)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use puddle_secrets::{AccountName, HostName, SourceSpec};

    use super::*;
    use crate::clock::ManualClock;
    use crate::identity::{Coverage, Owner};
    use crate::store::Limits;

    fn store() -> Store {
        Store::open_in_memory(Arc::new(ManualClock::new(1)), Limits::default()).unwrap()
    }

    fn made(store: &Store) -> IdentityId {
        let host = HostName::new("github.com").unwrap();
        let source = SourceSpec::Gh {
            host: host.clone(),
            account: AccountName::new("me").unwrap(),
        };
        let covers = Coverage::new([Owner::new("acme").unwrap()].into(), false).unwrap();
        store
            .create_identity(IdentityDraft {
                label: "Work".into(),
                author: Author::new("Me", "me@example.com").unwrap(),
                credentials: vec![CredentialBinding::new(&host, source, covers).unwrap()],
            })
            .unwrap()
            .id
    }

    /// A row edited by hand to something that does not parse is reported, never trusted.
    #[test]
    fn a_hand_edited_identity_row_is_reported_as_corrupt() {
        let store = store();
        let id = made(&store);
        lock(&store.conn)
            .execute("UPDATE identities SET credentials = 'not json'", [])
            .unwrap();
        assert!(matches!(
            store.identity(id),
            Err(StoreError::Corrupt {
                table: "identities",
                ..
            })
        ));
        assert!(store.identities().is_err());
    }

    #[test]
    fn a_hand_edited_repository_row_is_reported_as_corrupt() {
        let store = store();
        let ws = WorkspaceName::new("shop").unwrap();
        lock(&store.conn)
            .execute(
                "INSERT INTO workspace_repos (workspace_id, host, owner, repo, pull, push, created_at)
                 VALUES ('shop', 'github.com', 'acme', 'a/../b', 1, 1, 1)",
                [],
            )
            .unwrap();
        assert!(matches!(
            store.workspace_git(&ws),
            Err(StoreError::Corrupt {
                table: "workspace_repos",
                ..
            })
        ));
    }

    #[test]
    fn an_identity_listed_twice_is_refused() {
        let store = store();
        let id = made(&store);
        let ws = WorkspaceName::new("shop").unwrap();
        assert!(matches!(
            store.set_workspace_identities(&ws, &[id, id]),
            Err(StoreError::IdentityInvalid(_))
        ));
        assert_eq!(store.workspace_git(&ws).unwrap().identities.len(), 0);
    }
}
