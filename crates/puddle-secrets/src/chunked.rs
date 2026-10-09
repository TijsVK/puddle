// SPDX-License-Identifier: GPL-3.0-or-later
//! A store that spreads a long value over several entries of the store underneath.
//!
//! The Windows credential store keeps at most 2560 bytes per entry, which is 1280 UTF-16 code
//! units: a longer token (an AWS session token, a long JWT) would be refused there and work
//! elsewhere. [`ChunkedStore`] hides that: a value that fits is stored as it is, a longer one goes
//! in pieces of at most [`CHUNK_UNITS`] code units under ids made from the entry's own, and the
//! entry itself then holds only a small head that names them. Reading puts the pieces back
//! together, so callers see one value of any length.
//!
//! A replacement writes the new pieces under a fresh generation before it swaps the head, so an
//! entry that fails half-way still holds its old value, and the old pieces are removed after.

use crate::name::StoredId;
use crate::secret::Secret;
use crate::store::{SecretStore, StoreError};

/// The most UTF-16 code units in one entry: 2000 bytes as the Windows store holds them, under its
/// 2560-byte limit.
pub const CHUNK_UNITS: usize = 1000;

/// The most pieces one value has. A value of 8192 characters needs at most 17.
const MAX_PIECES: usize = 64;

/// What a head starts with. A value that starts the same way is stored in pieces too, so a head is
/// never taken for a value.
const HEAD_PREFIX: &str = "puddle-chunks:1:";

/// Wraps the store underneath.
#[derive(Debug, Default)]
pub struct ChunkedStore<S> {
    inner: S,
}

impl<S: SecretStore> ChunkedStore<S> {
    /// A store over `inner`.
    #[must_use]
    pub fn new(inner: S) -> Self {
        Self { inner }
    }
}

/// What a head says: which generation's pieces make the value, and how many.
struct Head {
    generation: String,
    pieces: usize,
}

impl Head {
    fn parse(text: &str) -> Option<Self> {
        let rest = text.strip_prefix(HEAD_PREFIX)?;
        let (generation, pieces) = rest.split_once(':')?;
        let pieces: usize = pieces.parse().ok()?;
        let valid = !generation.is_empty()
            && generation.bytes().all(|b| b.is_ascii_hexdigit())
            && (1..=MAX_PIECES).contains(&pieces);
        valid.then(|| Self {
            generation: generation.to_owned(),
            pieces,
        })
    }

    fn text(&self) -> String {
        format!("{HEAD_PREFIX}{}:{}", self.generation, self.pieces)
    }

    fn piece(&self, id: &StoredId, index: usize) -> Result<StoredId, StoreError> {
        StoredId::new(format!("{id}-{}-{index}", self.generation)).map_err(|_| StoreError)
    }
}

/// `value` cut into pieces of at most [`CHUNK_UNITS`] UTF-16 code units, at character boundaries.
fn pieces_of(value: &str) -> Vec<&str> {
    let mut pieces = Vec::new();
    let (mut start, mut units) = (0, 0);
    for (at, c) in value.char_indices() {
        if units + c.len_utf16() > CHUNK_UNITS {
            pieces.push(&value[start..at]);
            (start, units) = (at, 0);
        }
        units += c.len_utf16();
    }
    pieces.push(&value[start..]);
    pieces
}

fn generation() -> Result<String, StoreError> {
    let mut bytes = [0_u8; 4];
    getrandom::fill(&mut bytes).map_err(|_| StoreError)?;
    Ok(bytes.iter().fold(String::new(), |mut hex, b| {
        use std::fmt::Write as _;
        let _ = write!(hex, "{b:02x}");
        hex
    }))
}

impl<S: SecretStore> ChunkedStore<S> {
    /// The head of the entry under `id`, if it is one.
    fn head(&self, id: &StoredId) -> Result<Option<Head>, StoreError> {
        Ok(self
            .inner
            .get(id)?
            .and_then(|stored| Head::parse(stored.expose())))
    }

    /// Removes the pieces `head` names, as far as they are there.
    fn drop_pieces(&self, id: &StoredId, head: &Head) {
        for index in 0..head.pieces {
            if let Ok(piece) = head.piece(id, index) {
                // A piece that cannot be removed is an orphan nothing refers to; the entry's
                // own removal or the next write is not stopped by it.
                let _ = self.inner.delete(&piece);
            }
        }
    }
}

impl<S: SecretStore> SecretStore for ChunkedStore<S> {
    fn get(&self, id: &StoredId) -> Result<Option<Secret>, StoreError> {
        let Some(stored) = self.inner.get(id)? else {
            return Ok(None);
        };
        let Some(head) = Head::parse(stored.expose()) else {
            return Ok(Some(stored));
        };
        let mut value = String::new();
        for index in 0..head.pieces {
            // A missing piece is a damaged entry, never a shorter value.
            let piece = self.inner.get(&head.piece(id, index)?)?.ok_or(StoreError)?;
            value.push_str(piece.expose());
        }
        Ok(Some(Secret::new(value)))
    }

    fn set(&self, id: &StoredId, secret: &Secret) -> Result<(), StoreError> {
        let value = secret.expose();
        let before = self.head(id)?;
        let pieces = pieces_of(value);
        if pieces.len() == 1 && !value.starts_with(HEAD_PREFIX) {
            self.inner.set(id, secret)?;
        } else {
            if pieces.len() > MAX_PIECES {
                return Err(StoreError);
            }
            let head = Head {
                generation: generation()?,
                pieces: pieces.len(),
            };
            for (index, piece) in pieces.iter().enumerate() {
                let written = self
                    .inner
                    .set(&head.piece(id, index)?, &Secret::new((*piece).to_owned()));
                if let Err(err) = written {
                    self.drop_pieces(id, &head);
                    return Err(err);
                }
            }
            if let Err(err) = self.inner.set(id, &Secret::new(head.text())) {
                self.drop_pieces(id, &head);
                return Err(err);
            }
        }
        if let Some(old) = before {
            self.drop_pieces(id, &old);
        }
        Ok(())
    }

    fn delete(&self, id: &StoredId) -> Result<(), StoreError> {
        let before = self.head(id)?;
        self.inner.delete(id)?;
        if let Some(old) = before {
            self.drop_pieces(id, &old);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::store::MemoryStore;

    /// A store like Windows': an entry of more than 1280 UTF-16 code units is refused; it can also
    /// be made to fail on the nth write.
    #[derive(Default)]
    struct Limited {
        inner: MemoryStore,
        writes: AtomicUsize,
        fail_at: Mutex<Option<usize>>,
    }

    impl SecretStore for Limited {
        fn get(&self, id: &StoredId) -> Result<Option<Secret>, StoreError> {
            self.inner.get(id)
        }

        fn set(&self, id: &StoredId, secret: &Secret) -> Result<(), StoreError> {
            let n = self.writes.fetch_add(1, Ordering::SeqCst);
            if *self.fail_at.lock().unwrap() == Some(n) {
                return Err(StoreError);
            }
            if secret.expose().encode_utf16().count() > 1280 {
                return Err(StoreError);
            }
            self.inner.set(id, secret)
        }

        fn delete(&self, id: &StoredId) -> Result<(), StoreError> {
            self.inner.delete(id)
        }
    }

    fn id(text: &str) -> StoredId {
        StoredId::new(text).unwrap()
    }

    fn store() -> ChunkedStore<Limited> {
        ChunkedStore::new(Limited::default())
    }

    fn held(store: &ChunkedStore<Limited>) -> Vec<String> {
        store.inner.inner.ids()
    }

    fn get(store: &ChunkedStore<Limited>, name: &str) -> Option<String> {
        store.get(&id(name)).unwrap().map(|s| s.expose().to_owned())
    }

    #[test]
    fn a_short_value_is_stored_as_it_is() {
        let store = store();
        store
            .set(&id("env-1"), &Secret::new("short".into()))
            .unwrap();
        assert_eq!(held(&store), ["env-1"]);
        assert_eq!(
            store
                .inner
                .inner
                .get(&id("env-1"))
                .unwrap()
                .unwrap()
                .expose(),
            "short"
        );
        assert_eq!(get(&store, "env-1").as_deref(), Some("short"));
        assert_eq!(get(&store, "env-2"), None);
    }

    #[test]
    fn a_value_the_store_underneath_would_refuse_goes_in_pieces_and_comes_back_whole() {
        let store = store();
        let long: String = (0..8000)
            .map(|i| char::from(b'a' + u8::try_from(i % 26).unwrap()))
            .collect();
        // The store underneath refuses it as one entry.
        assert!(
            store
                .inner
                .set(&id("env-1"), &Secret::new(long.clone()))
                .is_err()
        );
        store.set(&id("env-1"), &Secret::new(long.clone())).unwrap();
        assert_eq!(get(&store, "env-1").as_deref(), Some(long.as_str()));
        // The entry itself holds a head, and eight pieces of at most 1000 units sit beside it.
        let ids = held(&store);
        assert_eq!(ids.len(), 9, "{ids:?}");
        assert!(ids.contains(&"env-1".to_owned()));
        let head = store.inner.inner.get(&id("env-1")).unwrap().unwrap();
        assert!(head.expose().starts_with("puddle-chunks:1:"));
        assert!(!head.expose().contains(&long[..20]));
    }

    #[test]
    fn pieces_are_cut_between_characters_and_counted_in_utf16_units() {
        let text: String = "😀".repeat(1200);
        let pieces = pieces_of(&text);
        assert!(
            pieces
                .iter()
                .all(|p| p.encode_utf16().count() <= CHUNK_UNITS)
        );
        assert_eq!(pieces.concat(), text);
        let store = store();
        store.set(&id("env-1"), &Secret::new(text.clone())).unwrap();
        assert_eq!(get(&store, "env-1").as_deref(), Some(text.as_str()));
        assert_eq!(pieces_of(""), [""]);
        let exact = "x".repeat(CHUNK_UNITS);
        assert_eq!(pieces_of(&exact).len(), 1);
        assert_eq!(pieces_of(&format!("{exact}y")).len(), 2);
    }

    #[test]
    fn a_value_that_looks_like_a_head_is_stored_in_pieces_so_it_is_read_back_as_a_value() {
        let store = store();
        let odd = "puddle-chunks:1:abcd:2";
        store.set(&id("env-1"), &Secret::new(odd.into())).unwrap();
        assert_eq!(get(&store, "env-1").as_deref(), Some(odd));
        assert_eq!(held(&store).len(), 2);
    }

    #[test]
    fn replacing_and_removing_leave_no_pieces_behind() {
        let store = store();
        let long = "x".repeat(3500);
        store.set(&id("env-1"), &Secret::new(long.clone())).unwrap();
        assert_eq!(held(&store).len(), 5);
        // Long to shorter-long: the old generation's pieces go.
        store
            .set(&id("env-1"), &Secret::new("y".repeat(1500)))
            .unwrap();
        assert_eq!(held(&store).len(), 3);
        // Long to short: back to one entry.
        store.set(&id("env-1"), &Secret::new("z".into())).unwrap();
        assert_eq!(held(&store), ["env-1"]);
        assert_eq!(get(&store, "env-1").as_deref(), Some("z"));
        // Short to long, then delete.
        store.set(&id("env-1"), &Secret::new(long)).unwrap();
        store.delete(&id("env-1")).unwrap();
        assert_eq!(held(&store), Vec::<String>::new());
        store.delete(&id("env-1")).unwrap();
        // Another entry is not touched.
        store
            .set(&id("env-2"), &Secret::new("keep".into()))
            .unwrap();
        store
            .set(&id("env-1"), &Secret::new("x".repeat(2500)))
            .unwrap();
        store.delete(&id("env-1")).unwrap();
        assert_eq!(held(&store), ["env-2"]);
    }

    #[test]
    fn a_write_that_fails_half_way_keeps_the_old_value_and_leaves_nothing_behind() {
        let store = store();
        let old = "o".repeat(2500);
        store.set(&id("env-1"), &Secret::new(old.clone())).unwrap();
        let before = held(&store);
        let writes = store.inner.writes.load(Ordering::SeqCst);
        for step in 0..4 {
            *store.inner.fail_at.lock().unwrap() = Some(writes + step);
            let err = store.set(&id("env-1"), &Secret::new("n".repeat(3500)));
            assert_eq!(err, Err(StoreError), "step {step}");
            assert_eq!(
                get(&store, "env-1").as_deref(),
                Some(old.as_str()),
                "step {step}"
            );
            assert_eq!(
                held(&store).len(),
                before.len(),
                "step {step}: {:?}",
                held(&store)
            );
            store.inner.writes.store(writes, Ordering::SeqCst);
        }
        // The head write (the fifth for a value of four pieces) failing is covered too.
        *store.inner.fail_at.lock().unwrap() = Some(writes + 4);
        assert!(
            store
                .set(&id("env-1"), &Secret::new("n".repeat(3500)))
                .is_err()
        );
        assert_eq!(get(&store, "env-1").as_deref(), Some(old.as_str()));
        assert_eq!(held(&store).len(), before.len());
    }

    #[test]
    fn a_damaged_entry_is_an_error_never_a_shorter_value() {
        let store = store();
        store
            .set(&id("env-1"), &Secret::new("x".repeat(2500)))
            .unwrap();
        let victim = held(&store).into_iter().find(|i| i != "env-1").unwrap();
        store.inner.inner.delete(&id(&victim)).unwrap();
        assert_eq!(store.get(&id("env-1")).unwrap_err(), StoreError);
        // A head that names too many pieces, or has no generation, is just a value.
        for odd in [
            "puddle-chunks:1:zz:2",
            "puddle-chunks:1:ab:0",
            "puddle-chunks:1:ab:65",
            "puddle-chunks:1::2",
        ] {
            store
                .inner
                .inner
                .set(&id("env-2"), &Secret::new(odd.into()))
                .unwrap();
            assert_eq!(get(&store, "env-2").as_deref(), Some(odd));
        }
    }

    #[test]
    fn a_value_needing_more_than_the_most_pieces_is_refused() {
        let store = store();
        let huge = "x".repeat(CHUNK_UNITS * MAX_PIECES + 1);
        assert!(store.set(&id("env-1"), &Secret::new(huge)).is_err());
        assert_eq!(held(&store), Vec::<String>::new());
        let most = "x".repeat(CHUNK_UNITS * MAX_PIECES);
        store.set(&id("env-1"), &Secret::new(most.clone())).unwrap();
        assert_eq!(get(&store, "env-1").as_deref(), Some(most.as_str()));
    }

    #[test]
    fn an_unavailable_store_underneath_is_an_error_at_every_call() {
        let store = ChunkedStore::new(MemoryStore::new());
        store.set(&id("a"), &Secret::new("v".into())).unwrap();
        store.inner.break_it();
        assert!(store.get(&id("a")).is_err());
        assert!(store.set(&id("a"), &Secret::new("v".into())).is_err());
        assert!(store.delete(&id("a")).is_err());
    }
}
