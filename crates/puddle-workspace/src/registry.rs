// SPDX-License-Identifier: GPL-3.0-or-later
//! Which sandbox holds which workspace (ADR 0006 point 8). In memory: after a restart puddle
//! rebuilds it with [`crate::Workspaces::adopt`] (at reconcile), and running holders are
//! also seen through the runtime's own holder lookup.

use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard, PoisonError};

use puddle_types::{SandboxName, WorkspaceId};

/// How a sandbox holds a workspace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HoldKind {
    /// A create with this workspace is in progress.
    Attaching,
    /// The sandbox was created with the workspace: it holds it while it exists, running or not,
    /// because a start attaches the volume again.
    Attached,
    /// puddle's short-lived maintenance sandbox (delete check, reclaim space).
    Maintenance,
}

/// A workspace's holder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Holder {
    /// The sandbox.
    pub sandbox: SandboxName,
    /// How it holds the workspace.
    pub kind: HoldKind,
}

#[derive(Debug, Default)]
struct Entry {
    /// The sandbox the workspace belongs to (created with it).
    owner: Option<Holder>,
    /// A maintenance sandbox borrowing the workspace while its owner is down.
    borrower: Option<SandboxName>,
}

#[derive(Debug, Default)]
pub(crate) struct Registry {
    entries: Mutex<BTreeMap<WorkspaceId, Entry>>,
}

impl Registry {
    fn lock(&self) -> MutexGuard<'_, BTreeMap<WorkspaceId, Entry>> {
        self.entries.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The current holder: a borrowing maintenance sandbox first, else the owner.
    pub(crate) fn holder(&self, id: &WorkspaceId) -> Option<Holder> {
        let entries = self.lock();
        let entry = entries.get(id)?;
        entry
            .borrower
            .as_ref()
            .map(|b| Holder {
                sandbox: b.clone(),
                kind: HoldKind::Maintenance,
            })
            .or_else(|| entry.owner.clone())
    }

    /// The owner, ignoring a borrower.
    pub(crate) fn owner(&self, id: &WorkspaceId) -> Option<Holder> {
        self.lock().get(id).and_then(|e| e.owner.clone())
    }

    /// Reserves `id` for `sandbox` while it is created. Refused with the current holder when
    /// another sandbox holds or borrows it.
    pub(crate) fn reserve(&self, id: &WorkspaceId, sandbox: &SandboxName) -> Result<(), Holder> {
        let mut entries = self.lock();
        let entry = entries.entry(id.clone()).or_default();
        if let Some(b) = &entry.borrower {
            return Err(Holder {
                sandbox: b.clone(),
                kind: HoldKind::Maintenance,
            });
        }
        match &entry.owner {
            Some(h) if h.sandbox != *sandbox || h.kind == HoldKind::Attaching => Err(h.clone()),
            _ => {
                entry.owner = Some(Holder {
                    sandbox: sandbox.clone(),
                    kind: HoldKind::Attaching,
                });
                Ok(())
            }
        }
    }

    /// Turns a reservation into an attachment (or records one directly: adoption).
    pub(crate) fn attach(&self, id: &WorkspaceId, sandbox: &SandboxName) {
        let mut entries = self.lock();
        entries.entry(id.clone()).or_default().owner = Some(Holder {
            sandbox: sandbox.clone(),
            kind: HoldKind::Attached,
        });
    }

    /// Drops `sandbox`'s hold on `id` (a reservation or an attachment), if it has one.
    pub(crate) fn release(&self, id: &WorkspaceId, sandbox: &SandboxName) {
        let mut entries = self.lock();
        if let Some(entry) = entries.get_mut(id)
            && entry.owner.as_ref().is_some_and(|h| h.sandbox == *sandbox)
        {
            entry.owner = None;
        }
        Self::prune(&mut entries, id);
    }

    /// Lends `id` to maintenance sandbox `sandbox` while its owner is down. Refused when another
    /// maintenance sandbox has it or a create is in progress.
    pub(crate) fn borrow(&self, id: &WorkspaceId, sandbox: &SandboxName) -> Result<(), Holder> {
        let mut entries = self.lock();
        let entry = entries.entry(id.clone()).or_default();
        if let Some(b) = &entry.borrower {
            return Err(Holder {
                sandbox: b.clone(),
                kind: HoldKind::Maintenance,
            });
        }
        if let Some(h) = entry
            .owner
            .as_ref()
            .filter(|h| h.kind == HoldKind::Attaching)
        {
            return Err(h.clone());
        }
        entry.borrower = Some(sandbox.clone());
        Ok(())
    }

    /// Ends a maintenance loan.
    pub(crate) fn give_back(&self, id: &WorkspaceId) {
        let mut entries = self.lock();
        if let Some(entry) = entries.get_mut(id) {
            entry.borrower = None;
        }
        Self::prune(&mut entries, id);
    }

    /// Forgets `id` entirely (its volume is gone).
    pub(crate) fn forget(&self, id: &WorkspaceId) {
        self.lock().remove(id);
    }

    /// Every workspace `sandbox` owns, in id order.
    pub(crate) fn owned_by(&self, sandbox: &SandboxName) -> Vec<WorkspaceId> {
        self.lock()
            .iter()
            .filter(|(_, e)| {
                e.owner
                    .as_ref()
                    .is_some_and(|h| h.sandbox == *sandbox && h.kind == HoldKind::Attached)
            })
            .map(|(id, _)| id.clone())
            .collect()
    }

    fn prune(entries: &mut BTreeMap<WorkspaceId, Entry>, id: &WorkspaceId) {
        if entries
            .get(id)
            .is_some_and(|e| e.owner.is_none() && e.borrower.is_none())
        {
            entries.remove(id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ws(s: &str) -> WorkspaceId {
        WorkspaceId::new(s).unwrap()
    }

    fn sb(s: &str) -> SandboxName {
        SandboxName::new(s).unwrap()
    }

    #[test]
    fn a_reservation_blocks_everyone_until_attached_or_released() {
        let r = Registry::default();
        r.reserve(&ws("a"), &sb("one")).unwrap();
        let held = r.reserve(&ws("a"), &sb("two")).unwrap_err();
        assert_eq!(held.sandbox, sb("one"));
        assert_eq!(held.kind, HoldKind::Attaching);
        // Even the same sandbox can't create twice at once.
        assert!(r.reserve(&ws("a"), &sb("one")).is_err());
        assert!(r.borrow(&ws("a"), &sb("m")).is_err());
        r.attach(&ws("a"), &sb("one"));
        assert_eq!(r.holder(&ws("a")).unwrap().kind, HoldKind::Attached);
        // The owner may attach again (a recreate under the same name); others may not.
        r.reserve(&ws("a"), &sb("one")).unwrap();
        r.attach(&ws("a"), &sb("one"));
        assert_eq!(
            r.reserve(&ws("a"), &sb("two")).unwrap_err().sandbox,
            sb("one")
        );
        assert_eq!(r.owned_by(&sb("one")), vec![ws("a")]);
        r.release(&ws("a"), &sb("two"));
        assert!(
            r.owner(&ws("a")).is_some(),
            "another sandbox can't release it"
        );
        r.release(&ws("a"), &sb("one"));
        assert_eq!(r.holder(&ws("a")), None);
        r.reserve(&ws("a"), &sb("two")).unwrap();
    }

    #[test]
    fn a_borrower_shows_as_holder_and_blocks_attaches() {
        let r = Registry::default();
        r.attach(&ws("a"), &sb("owner"));
        r.borrow(&ws("a"), &sb("maint")).unwrap();
        assert_eq!(
            r.holder(&ws("a")),
            Some(Holder {
                sandbox: sb("maint"),
                kind: HoldKind::Maintenance
            })
        );
        assert_eq!(r.owner(&ws("a")).unwrap().sandbox, sb("owner"));
        assert_eq!(
            r.reserve(&ws("a"), &sb("owner")).unwrap_err().sandbox,
            sb("maint")
        );
        assert_eq!(
            r.borrow(&ws("a"), &sb("m2")).unwrap_err().sandbox,
            sb("maint")
        );
        r.give_back(&ws("a"));
        assert_eq!(r.holder(&ws("a")).unwrap().sandbox, sb("owner"));
        r.forget(&ws("a"));
        assert_eq!(r.holder(&ws("a")), None);
        // A loan of an unowned workspace leaves nothing behind.
        r.borrow(&ws("b"), &sb("maint")).unwrap();
        r.give_back(&ws("b"));
        assert!(r.lock().is_empty());
    }
}
