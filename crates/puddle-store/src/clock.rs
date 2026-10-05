// SPDX-License-Identifier: GPL-3.0-or-later
//! The host clock, in epoch milliseconds. The guest's clock plays no part (R-7).

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// A source of the current time in epoch milliseconds.
pub trait Clock: Send + Sync {
    /// Milliseconds since the Unix epoch.
    fn now_ms(&self) -> u64;
}

/// The host's wall clock.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> u64 {
        // A clock before 1970 reads as 0; one past u64 milliseconds (year 584 million) saturates.
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
    }
}

/// A clock that only moves when told to, for tests here and in other crates.
#[derive(Debug, Default)]
pub struct ManualClock(AtomicU64);

impl ManualClock {
    /// A clock reading `now_ms`.
    #[must_use]
    pub fn new(now_ms: u64) -> Self {
        Self(AtomicU64::new(now_ms))
    }

    /// Sets the time.
    pub fn set(&self, now_ms: u64) {
        self.0.store(now_ms, Ordering::SeqCst);
    }

    /// Moves the time forward by `ms`.
    pub fn advance(&self, ms: u64) {
        self.0.fetch_add(ms, Ordering::SeqCst);
    }
}

impl Clock for ManualClock {
    fn now_ms(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_clock_is_after_2026() {
        assert!(SystemClock.now_ms() > 1_767_225_600_000);
    }

    #[test]
    fn manual_clock_moves_only_when_told() {
        let clock = ManualClock::new(5);
        assert_eq!(clock.now_ms(), 5);
        clock.advance(10);
        assert_eq!(clock.now_ms(), 15);
        clock.set(2);
        assert_eq!(clock.now_ms(), 2);
    }
}
