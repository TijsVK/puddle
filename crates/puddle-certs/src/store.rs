// SPDX-License-Identifier: GPL-3.0-or-later
//! The host certificate stores puddle reads, and a snapshot of their contents.
//!
//! Which stores (T-026 §2b option C, D-24): every root an admin or the user deliberately added,
//! so the physical `Root` stores `.Default`, `.GroupPolicy` and `.Enterprise` (Intune lands in
//! `LocalMachine\Root\.Default`, GPO in `.GroupPolicy`, AD in `.Enterprise`), the same for the
//! intermediate `CA` stores, and the logical `Disallowed` stores. Not `AuthRoot`: those are the
//! Microsoft program's public roots, which the guest's distro bundle already has.

use std::fmt;

/// A certificate store location.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum Location {
    /// The machine's stores (admin-managed, Intune, GPO, AD).
    LocalMachine,
    /// The signed-in user's stores (user-added roots, user GPO).
    CurrentUser,
}

/// Which logical store a certificate came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum StoreName {
    /// `Root`: trust anchors.
    Root,
    /// `CA`: intermediate CAs.
    Intermediate,
    /// `Disallowed`: certificates Windows distrusts.
    Disallowed,
}

/// The physical store inside a logical one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum Physical {
    /// `.Default`: added by an admin, Intune or the user.
    Default,
    /// `.GroupPolicy`: pushed by Group Policy.
    GroupPolicy,
    /// `.Enterprise`: published by Active Directory.
    Enterprise,
    /// The whole logical store (used for `Disallowed`, where every source counts).
    Logical,
}

/// Where a certificate came from, shown on the network health page
/// (`LocalMachine\Root\.GroupPolicy`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StoreSource {
    /// The location.
    pub location: Location,
    /// The logical store.
    pub store: StoreName,
    /// The physical store.
    pub physical: Physical,
}

impl StoreSource {
    /// A source.
    #[must_use]
    pub const fn new(location: Location, store: StoreName, physical: Physical) -> Self {
        Self {
            location,
            store,
            physical,
        }
    }
}

impl fmt::Display for StoreSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let location = match self.location {
            Location::LocalMachine => "LocalMachine",
            Location::CurrentUser => "CurrentUser",
        };
        let store = match self.store {
            StoreName::Root => "Root",
            StoreName::Intermediate => "CA",
            StoreName::Disallowed => "Disallowed",
        };
        let physical = match self.physical {
            Physical::Default => "\\.Default",
            Physical::GroupPolicy => "\\.GroupPolicy",
            Physical::Enterprise => "\\.Enterprise",
            Physical::Logical => "",
        };
        write!(f, "{location}\\{store}{physical}")
    }
}

/// Every store [`read_host_stores`] reads, in reading order.
pub const SOURCES: [StoreSource; 12] = {
    use Location::{CurrentUser, LocalMachine};
    use Physical::{Default, Enterprise, GroupPolicy, Logical};
    use StoreName::{Disallowed, Intermediate, Root};
    [
        StoreSource::new(LocalMachine, Root, Default),
        StoreSource::new(LocalMachine, Root, GroupPolicy),
        StoreSource::new(LocalMachine, Root, Enterprise),
        StoreSource::new(CurrentUser, Root, Default),
        StoreSource::new(CurrentUser, Root, GroupPolicy),
        StoreSource::new(LocalMachine, Intermediate, Default),
        StoreSource::new(LocalMachine, Intermediate, GroupPolicy),
        StoreSource::new(LocalMachine, Intermediate, Enterprise),
        StoreSource::new(CurrentUser, Intermediate, Default),
        StoreSource::new(CurrentUser, Intermediate, GroupPolicy),
        StoreSource::new(LocalMachine, Disallowed, Logical),
        StoreSource::new(CurrentUser, Disallowed, Logical),
    ]
};

/// One certificate as found in a store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostCert {
    /// Where it was found.
    pub source: StoreSource,
    /// The certificate, DER.
    pub der: Vec<u8>,
}

/// A store that could not be read; its certificates are missing from the snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnreadableStore {
    /// The store.
    pub source: StoreSource,
    /// The OS error.
    pub reason: String,
}

/// What the host stores held at one moment. Built by [`read_host_stores`], or by hand in tests.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StoreSnapshot {
    certs: Vec<HostCert>,
    unreadable: Vec<UnreadableStore>,
}

impl StoreSnapshot {
    /// An empty snapshot.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records `der` as found in `source`.
    pub fn add(&mut self, source: StoreSource, der: Vec<u8>) {
        self.certs.push(HostCert { source, der });
    }

    /// Records that `source` could not be read.
    pub fn note_unreadable(&mut self, source: StoreSource, reason: impl Into<String>) {
        self.unreadable.push(UnreadableStore {
            source,
            reason: reason.into(),
        });
    }

    /// Every certificate found, in reading order (duplicates across stores included).
    #[must_use]
    pub fn certs(&self) -> &[HostCert] {
        &self.certs
    }

    /// The stores that could not be read.
    #[must_use]
    pub fn unreadable(&self) -> &[UnreadableStore] {
        &self.unreadable
    }
}

/// Why the host stores could not be read at all.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum StoreError {
    /// A `Disallowed` store failed to open. Exporting without it could hand the guest a root
    /// Windows distrusts, so nothing is exported (fail closed).
    #[error("cannot read the {store} certificate store: {reason}")]
    DisallowedUnreadable {
        /// The store.
        store: StoreSource,
        /// The OS error.
        reason: String,
    },
}

/// Reads [`SOURCES`] from the host. A `Root` or `CA` store that is missing counts as empty; one
/// that fails otherwise is listed in [`StoreSnapshot::unreadable`] and the rest still count. On
/// hosts other than Windows there are no such stores and the snapshot is empty.
///
/// # Errors
///
/// [`StoreError::DisallowedUnreadable`] when a `Disallowed` store exists but can't be read.
pub fn read_host_stores() -> Result<StoreSnapshot, StoreError> {
    crate::platform::read(&SOURCES)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sources_print_as_windows_store_paths() {
        let shown: Vec<String> = SOURCES.iter().map(ToString::to_string).collect();
        assert_eq!(
            shown,
            [
                "LocalMachine\\Root\\.Default",
                "LocalMachine\\Root\\.GroupPolicy",
                "LocalMachine\\Root\\.Enterprise",
                "CurrentUser\\Root\\.Default",
                "CurrentUser\\Root\\.GroupPolicy",
                "LocalMachine\\CA\\.Default",
                "LocalMachine\\CA\\.GroupPolicy",
                "LocalMachine\\CA\\.Enterprise",
                "CurrentUser\\CA\\.Default",
                "CurrentUser\\CA\\.GroupPolicy",
                "LocalMachine\\Disallowed",
                "CurrentUser\\Disallowed",
            ]
        );
    }

    #[test]
    fn snapshot_keeps_certs_and_unreadable_stores_in_order() {
        let mut s = StoreSnapshot::new();
        s.add(SOURCES[0], vec![1]);
        s.add(SOURCES[3], vec![2]);
        s.note_unreadable(SOURCES[1], "access denied");
        assert_eq!(s.certs().len(), 2);
        assert_eq!(s.certs()[1].der, [2]);
        assert_eq!(s.unreadable()[0].source, SOURCES[1]);
        let err = StoreError::DisallowedUnreadable {
            store: SOURCES[10],
            reason: "error 5".into(),
        };
        assert_eq!(
            err.to_string(),
            "cannot read the LocalMachine\\Disallowed certificate store: error 5"
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn other_hosts_have_no_stores() {
        assert_eq!(read_host_stores(), Ok(StoreSnapshot::new()));
    }
}
