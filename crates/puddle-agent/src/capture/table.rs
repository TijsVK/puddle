// SPDX-License-Identifier: GPL-3.0-or-later
//! The stand-in table: which name a stand-in address stands for.
//!
//! A client that resolves a name through the stub gets an address from `198.18.0.0/15`, and the
//! guest's network rules send its connection to the agent, which reads the address it was aimed
//! at and finds the name here. So the table has to be:
//!
//! - **stable**: a name keeps its address for the sandbox's life (clients cache addresses for as
//!   long as they like), also across an agent restart (the table is kept in a file);
//! - **bounded**: `/15` has about 131,000 addresses; when all are taken, the least recently used
//!   one is given to the new name. An address with a live connection on it ([`Hold`]) is never
//!   given away.

use std::collections::{BTreeMap, HashMap};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write as _};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

/// The first address of the stand-in range, `198.18.0.0/15` (the benchmarking block, which no
/// real network routes).
pub const POOL_BASE: u32 = 0xC612_0000;
/// Addresses in the range.
const POOL_SIZE: u32 = 1 << 17;
/// The stub DNS server's own address, `198.18.0.1`: never a stand-in.
pub const STUB_ADDR: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 1);
/// Offsets handed out: not the network address (0), the stub (1) or the broadcast address.
const FIRST: u32 = 2;
const LAST: u32 = POOL_SIZE - 2;
/// The most names the table holds.
pub const CAPACITY: usize = (LAST - FIRST + 1) as usize;
/// Longest table file read at start.
const MAX_FILE: u64 = 16 << 20;

/// Whether `ip` is in the stand-in range (including the stub's own address): what the capture
/// rules redirect.
#[must_use]
pub fn in_range(ip: Ipv4Addr) -> bool {
    u32::from(ip) & !(POOL_SIZE - 1) == POOL_BASE
}

/// Every address is taken and has a live connection, so none can be reused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("every stand-in address is in use by a live connection")]
pub struct Exhausted;

#[derive(Debug)]
struct Entry {
    name: Arc<str>,
    tick: u64,
    holds: u32,
}

#[derive(Debug)]
struct Inner {
    by_name: HashMap<Arc<str>, u32>,
    slots: Vec<Option<Entry>>,
    /// Entries by last use, oldest first.
    lru: BTreeMap<u64, u32>,
    /// Offsets below `next` with no entry.
    free: Vec<u32>,
    next: u32,
    tick: u64,
    limit: u32,
    log: Option<Log>,
}

#[derive(Debug)]
struct Log {
    path: PathBuf,
    file: File,
    lines: usize,
}

/// The table, shared by the stub and the transparent listener that maps a redirected connection back to its name.
#[derive(Debug, Clone)]
pub struct StandIns {
    inner: Arc<Mutex<Inner>>,
}

/// A name with an address that must stay as it is while the guard lives (a connection is open on
/// it).
#[derive(Debug)]
pub struct Hold {
    table: StandIns,
    offset: u32,
    name: Arc<str>,
}

impl Hold {
    /// The name the address stands for.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
}

impl Drop for Hold {
    fn drop(&mut self) {
        let mut inner = self.table.lock();
        if let Some(Some(entry)) = inner.slots.get_mut(slot(self.offset)) {
            entry.holds = entry.holds.saturating_sub(1);
        }
    }
}

fn slot(offset: u32) -> usize {
    usize::try_from(offset).unwrap_or(usize::MAX)
}

fn address(offset: u32) -> Ipv4Addr {
    Ipv4Addr::from(POOL_BASE + offset)
}

fn offset_of(ip: Ipv4Addr) -> Option<u32> {
    let offset = u32::from(ip).checked_sub(POOL_BASE)?;
    (FIRST..=LAST).contains(&offset).then_some(offset)
}

impl StandIns {
    /// A table with no file: nothing survives a restart.
    #[must_use]
    pub fn in_memory() -> Self {
        Self::build(None, CAPACITY)
    }

    /// A table kept in `path`: its lines are read now, and each new mapping is appended. A file
    /// that can't be read or written costs only persistence, never the lookups.
    #[must_use]
    pub fn open(path: &Path) -> Self {
        Self::build(Some(path), CAPACITY)
    }

    /// [`StandIns::open`] with room for `limit` names (tests).
    #[must_use]
    pub fn open_with_capacity(path: Option<&Path>, limit: usize) -> Self {
        Self::build(path, limit.min(CAPACITY))
    }

    fn build(path: Option<&Path>, limit: usize) -> Self {
        let mut inner = Inner {
            by_name: HashMap::new(),
            slots: Vec::new(),
            lru: BTreeMap::new(),
            free: Vec::new(),
            next: FIRST,
            tick: 0,
            limit: u32::try_from(limit).unwrap_or(u32::MAX),
            log: None,
        };
        if let Some(path) = path {
            let long = inner.load(path);
            inner.open_log(path, long);
        }
        Self {
            inner: Arc::new(Mutex::new(inner)),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The address standing for `name` (a plain name: lower case, no trailing dot): its own if it
    /// has one, else the next free or least recently used one. Counts as a use.
    ///
    /// # Errors
    ///
    /// [`Exhausted`] when every address is held by a live connection.
    pub fn address_for(&self, name: &str) -> Result<Ipv4Addr, Exhausted> {
        self.lock().address_for(name).map(address)
    }

    /// The name `ip` stands for, if it is a stand-in in use. Counts as a use.
    #[must_use]
    pub fn name_for(&self, ip: Ipv4Addr) -> Option<Arc<str>> {
        let offset = offset_of(ip)?;
        let mut inner = self.lock();
        let name = inner.slots.get(slot(offset))?.as_ref()?.name.clone();
        inner.touch(offset);
        Some(name)
    }

    /// Like [`StandIns::name_for`], and keeps the address from being given to another name until
    /// the [`Hold`] is dropped: for a connection that is open on it.
    #[must_use]
    pub fn hold(&self, ip: Ipv4Addr) -> Option<Hold> {
        let offset = offset_of(ip)?;
        let mut inner = self.lock();
        let entry = inner.slots.get_mut(slot(offset))?.as_mut()?;
        entry.holds += 1;
        let name = entry.name.clone();
        inner.touch(offset);
        Some(Hold {
            table: self.clone(),
            offset,
            name,
        })
    }

    /// How many names the table holds.
    #[must_use]
    pub fn len(&self) -> usize {
        self.lock().by_name.len()
    }

    /// Whether the table holds no names.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Inner {
    fn touch(&mut self, offset: u32) {
        self.tick += 1;
        let tick = self.tick;
        if let Some(Some(entry)) = self.slots.get_mut(slot(offset)) {
            self.lru.remove(&entry.tick);
            entry.tick = tick;
            self.lru.insert(tick, offset);
        }
    }

    fn address_for(&mut self, name: &str) -> Result<u32, Exhausted> {
        if let Some(&offset) = self.by_name.get(name) {
            self.touch(offset);
            return Ok(offset);
        }
        let offset = self.take_offset()?;
        let name: Arc<str> = Arc::from(name);
        self.place(offset, name.clone());
        self.append(offset, &name);
        Ok(offset)
    }

    /// An offset for a new name: a freed one, a never-used one, else the least recently used
    /// entry that has no live connection (its name is forgotten).
    fn take_offset(&mut self) -> Result<u32, Exhausted> {
        if let Some(offset) = self.free.pop() {
            return Ok(offset);
        }
        if self.next < FIRST + self.limit && self.next <= LAST {
            let offset = self.next;
            self.next += 1;
            return Ok(offset);
        }
        let victim = self
            .lru
            .values()
            .copied()
            .find(|&o| matches!(self.slots.get(slot(o)), Some(Some(e)) if e.holds == 0))
            .ok_or(Exhausted)?;
        self.clear(victim);
        Ok(victim)
    }

    /// Empties `offset`, forgetting its name.
    fn clear(&mut self, offset: u32) {
        if let Some(entry) = self.slots.get_mut(slot(offset)).and_then(Option::take) {
            self.lru.remove(&entry.tick);
            self.by_name.remove(&entry.name);
        }
    }

    fn place(&mut self, offset: u32, name: Arc<str>) {
        if self.slots.len() <= slot(offset) {
            self.slots.resize_with(slot(offset) + 1, || None);
        }
        self.tick += 1;
        let tick = self.tick;
        if let Some(cell) = self.slots.get_mut(slot(offset)) {
            *cell = Some(Entry {
                name: name.clone(),
                tick,
                holds: 0,
            });
        }
        self.lru.insert(tick, offset);
        self.by_name.insert(name, offset);
    }

    /// Reads a table file: later lines override earlier ones; bad lines are skipped. Returns
    /// whether the file is long enough to be worth rewriting.
    fn load(&mut self, path: &Path) -> bool {
        let text = match File::open(path).and_then(|f| {
            use std::io::Read as _;
            let mut text = String::new();
            f.take(MAX_FILE).read_to_string(&mut text)?;
            Ok(text)
        }) {
            Ok(text) => text,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return false,
            Err(err) => {
                tracing::warn!(path = %path.display(), error = %err, "stand-in table not read; starting empty");
                return false;
            }
        };
        let mut lines = 0;
        for line in text.lines() {
            lines += 1;
            let Some((ip, name)) = line.split_once(' ') else {
                continue;
            };
            let Some(offset) = ip.parse().ok().and_then(offset_of) else {
                continue;
            };
            if !super::names::is_plain(name) || offset >= FIRST + self.limit {
                continue;
            }
            self.clear(offset);
            if let Some(&old) = self.by_name.get(name) {
                self.clear(old);
            }
            self.place(offset, Arc::from(name));
            self.next = self.next.max(offset + 1);
        }
        self.free = (FIRST..self.next)
            .filter(|&o| matches!(self.slots.get(slot(o)), None | Some(None)))
            .rev()
            .collect();
        tracing::info!(path = %path.display(), names = self.by_name.len(), "stand-in table loaded");
        lines > 2 * self.by_name.len() + 1024
    }

    /// Opens the file for appending (after rewriting it first when `compact`).
    fn open_log(&mut self, path: &Path, compact: bool) {
        if let Some(dir) = path.parent()
            && let Err(err) = fs::create_dir_all(dir)
        {
            tracing::warn!(path = %path.display(), error = %err, "stand-in table folder not created; names are not kept across restarts");
            return;
        }
        if compact {
            match self.rewrite(path) {
                Ok(()) => {}
                Err(err) => {
                    tracing::warn!(path = %path.display(), error = %err, "stand-in table not compacted");
                }
            }
        }
        match OpenOptions::new().create(true).append(true).open(path) {
            Ok(file) => {
                self.log = Some(Log {
                    path: path.to_owned(),
                    file,
                    lines: self.by_name.len(),
                });
            }
            Err(err) => {
                tracing::warn!(path = %path.display(), error = %err, "stand-in table not writable; names are not kept across restarts");
            }
        }
    }

    /// Writes the whole table (oldest use first) to a temporary file and moves it over `path`.
    fn rewrite(&self, path: &Path) -> io::Result<()> {
        let temp = path.with_extension("tmp");
        let mut out = io::BufWriter::new(File::create(&temp)?);
        for &offset in self.lru.values() {
            if let Some(Some(entry)) = self.slots.get(slot(offset)) {
                writeln!(out, "{} {}", address(offset), entry.name)?;
            }
        }
        out.flush()?;
        drop(out);
        fs::rename(&temp, path)
    }

    fn append(&mut self, offset: u32, name: &str) {
        let Some(log) = self.log.as_mut() else {
            return;
        };
        let line = format!("{} {name}\n", address(offset));
        if let Err(err) = log.file.write_all(line.as_bytes()) {
            tracing::warn!(path = %log.path.display(), error = %err, "stand-in table not written; names are not kept across restarts");
            self.log = None;
            return;
        }
        log.lines += 1;
        if log.lines > 2 * self.by_name.len() + 1024 {
            let path = log.path.clone();
            self.log = None;
            match self.rewrite(&path) {
                Ok(()) => self.open_log(&path, false),
                Err(err) => {
                    tracing::warn!(path = %path.display(), error = %err, "stand-in table not compacted; names are not kept across restarts");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;
