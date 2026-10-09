// SPDX-License-Identifier: GPL-3.0-or-later
//! The operating system's own credential store, where the computer has one that works (a Windows
//! runner, a desktop): a value much longer than one entry holds round-trips through
//! [`ChunkedStore`], and what it writes is gone after the delete. A computer with no usable store
//! (a Linux runner without a Secret Service) skips, and says so.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test code: a panic is how a test fails"
)]

use std::fmt::Write as _;

use puddle_secrets::{
    ChunkedStore, KeyringStore, Secret, SecretStore, StoredId, keyring_available,
};

/// A value of `len` characters that is not the same in two places, so a piece in the wrong order
/// reads back as a different value.
fn long_value(len: usize) -> String {
    (0..len)
        .map(|i| char::from(b'a' + u8::try_from((i * 7 + i / 26) % 26).unwrap()))
        .collect()
}

fn fresh_id() -> StoredId {
    let mut bytes = [0_u8; 8];
    getrandom::fill(&mut bytes).unwrap();
    let mut id = String::from("test-");
    for byte in bytes {
        write!(id, "{byte:02x}").unwrap();
    }
    StoredId::new(id).unwrap()
}

#[test]
fn a_value_longer_than_one_entry_round_trips_through_the_real_credential_store() {
    if !keyring_available() {
        eprintln!("skipped: this computer has no credential store that works");
        return;
    }
    let store = ChunkedStore::new(KeyringStore);
    let id = fresh_id();
    let long = long_value(5000);

    // The Windows store keeps 2560 bytes per entry: the plain store refuses what chunking stores.
    #[cfg(windows)]
    assert!(
        KeyringStore
            .set(&fresh_id(), &Secret::new(long.clone()))
            .is_err(),
        "the platform limit is gone, so the chunking may be too"
    );

    store.set(&id, &Secret::new(long.clone())).unwrap();
    let read = store.get(&id).unwrap().unwrap();
    assert_eq!(read.expose(), long);
    // A shorter value replaces it in place and leaves no piece behind.
    store.set(&id, &Secret::new("short".to_owned())).unwrap();
    assert_eq!(store.get(&id).unwrap().unwrap().expose(), "short");
    store.set(&id, &Secret::new(long_value(3000))).unwrap();
    assert_eq!(store.get(&id).unwrap().unwrap().expose(), long_value(3000));

    store.delete(&id).unwrap();
    assert!(store.get(&id).unwrap().is_none());
    store.delete(&id).unwrap();
}
