//! The server clock, behind a trait so tests can control time.
//!
//! Spec: `spec/zip-draft-1435.md` § Notation (L184–185): times are hours since
//! the Unix epoch; § Mailbox Servers (L328): Fetch `time` is checked against the
//! server's clock.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// A source of the current time.
/// Spec: § Mailbox Servers (L328).
pub trait Clock: Send + Sync + 'static {
    /// Seconds since the Unix epoch. Spec: § Notation (L184–185).
    fn now_secs(&self) -> u64;

    /// Hours since the Unix epoch, rounded down, saturating at `u32::MAX`.
    /// Spec: § Notation (L184–185).
    fn now_hours(&self) -> u32 {
        u32::try_from(self.now_secs() / 3600).unwrap_or(u32::MAX)
    }
}

/// The system clock. Spec: § Mailbox Servers (L328).
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    /// Spec: § Notation (L184–185).
    fn now_secs(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
}

/// A clock that only moves when told to, for tests.
/// Spec: § Mailbox Servers (L328).
#[derive(Debug, Default)]
pub struct ManualClock(AtomicU64);

impl ManualClock {
    /// A clock reading `secs`. Spec: § Notation (L184–185).
    pub fn new(secs: u64) -> Self {
        ManualClock(AtomicU64::new(secs))
    }

    /// Moves the clock forward. Spec: § Notation (L184–185).
    pub fn advance(&self, secs: u64) {
        self.0.fetch_add(secs, Ordering::SeqCst);
    }
}

impl Clock for ManualClock {
    /// Spec: § Notation (L184–185).
    fn now_secs(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Hours are rounded down. Spec: § Notation (L184–185).
    #[test]
    fn hours_round_down() {
        let c = ManualClock::new(3600 * 10 + 3599);
        assert_eq!(c.now_hours(), 10);
        c.advance(1);
        assert_eq!(c.now_hours(), 11);
        assert!(SystemClock.now_hours() > 490_000);
    }
}
