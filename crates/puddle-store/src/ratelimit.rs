// SPDX-License-Identifier: GPL-3.0-or-later
//! The per-sandbox token bucket for new pending rows (R-13).

/// Up to `capacity` tokens; one more every `refill_ms`. Time only counts forward: a clock that
/// steps back neither refills nor drains.
#[derive(Debug, Clone)]
pub(crate) struct TokenBucket {
    capacity: u32,
    refill_ms: u64,
    tokens: u32,
    last_refill: u64,
}

impl TokenBucket {
    /// A full bucket at `now`.
    pub(crate) fn new(capacity: u32, refill_ms: u64, now: u64) -> Self {
        Self {
            capacity,
            refill_ms: refill_ms.max(1),
            tokens: capacity,
            last_refill: now,
        }
    }

    /// Takes a token if there is one.
    pub(crate) fn try_take(&mut self, now: u64) -> bool {
        self.refill(now);
        if self.tokens == 0 {
            return false;
        }
        self.tokens -= 1;
        true
    }

    fn refill(&mut self, now: u64) {
        if now <= self.last_refill {
            self.last_refill = self.last_refill.min(now);
            return;
        }
        if self.tokens >= self.capacity {
            self.last_refill = now;
            return;
        }
        let earned = (now - self.last_refill) / self.refill_ms;
        let room = u64::from(self.capacity - self.tokens);
        let add = earned.min(room);
        // `add` is at most `room`, which came from a u32.
        self.tokens += u32::try_from(add).unwrap_or(0);
        self.last_refill = if self.tokens >= self.capacity {
            now
        } else {
            self.last_refill + add * self.refill_ms
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn burst_then_one_per_interval() {
        let mut bucket = TokenBucket::new(3, 1000, 0);
        assert!(bucket.try_take(0) && bucket.try_take(0) && bucket.try_take(0));
        assert!(!bucket.try_take(999));
        assert!(bucket.try_take(1000));
        assert!(!bucket.try_take(1500));
        assert!(bucket.try_take(2000));
        // A long idle time refills to capacity, not beyond.
        for _ in 0..3 {
            assert!(bucket.try_take(1_000_000));
        }
        assert!(!bucket.try_take(1_000_000));
    }

    #[test]
    fn clock_stepping_back_does_not_refill() {
        let mut bucket = TokenBucket::new(1, 1000, 10_000);
        assert!(bucket.try_take(10_000));
        assert!(!bucket.try_take(5_000));
        assert!(!bucket.try_take(5_999));
        assert!(bucket.try_take(6_000));
    }

    proptest! {
        #[test]
        fn never_grants_more_than_burst_plus_refill(
            capacity in 1u32..20,
            refill in 1u64..2000,
            steps in proptest::collection::vec(0u64..3000, 1..200),
        ) {
            let mut bucket = TokenBucket::new(capacity, refill, 0);
            let mut now = 0;
            let mut granted = 0u64;
            for step in steps {
                now += step;
                if bucket.try_take(now) {
                    granted += 1;
                }
            }
            prop_assert!(granted <= u64::from(capacity) + now / refill);
        }
    }
}
