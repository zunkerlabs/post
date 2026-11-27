//! Randomized fetch schedule: each mailbox is fetched on its own timer.
//!
//! Spec: `spec/zip-draft-1435.md` § Wallet behaviour (L374–376): "fetch each
//! mailbox on its own randomized schedule, independent of user actions and of
//! their other mailboxes", and § Privacy Implications (L120–122): fetching
//! mailboxes together lets a server link them.
//!
//! Intervals are exponentially distributed (a Poisson process per mailbox),
//! drawn from the operating system's random generator. Sending a message never
//! moves a timer.

use std::collections::BTreeMap;
use std::time::Duration;

/// A mailbox the client fetches. Spec: § Mailboxes (L260–277).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MailboxRef {
    /// The Contact Mailbox of the account address at this diversifier index.
    Contact(u32),
    /// A Pairwise Mailbox: Conversation id and epoch (receiving direction).
    Pairwise {
        /// Conversation id.
        conversation: String,
        /// Epoch.
        epoch: u32,
    },
}

/// Default mean time between fetches of one mailbox. Spec: § Wallet behaviour
/// (L374–375); the draft leaves the rate to wallets.
pub const DEFAULT_MEAN: Duration = Duration::from_secs(15 * 60);

/// Next fetch time (Unix seconds) for each mailbox.
/// Spec: § Wallet behaviour (L374–376).
#[derive(Debug)]
pub struct Schedule {
    mean_secs: f64,
    next: BTreeMap<MailboxRef, u64>,
}

impl Schedule {
    /// A schedule with the given mean interval. Spec: § Wallet behaviour (L374–375).
    pub fn new(mean: Duration) -> Self {
        Schedule {
            mean_secs: mean.as_secs_f64().max(1.0),
            next: BTreeMap::new(),
        }
    }

    /// Adds newly active mailboxes, each with its own random first fetch time,
    /// and drops ones no longer active. Spec: § Wallet behaviour (L374–376).
    pub fn sync(&mut self, active: &[MailboxRef], now: u64) {
        self.next.retain(|m, _| active.contains(m));
        for m in active {
            if !self.next.contains_key(m) {
                let at = now + self.interval();
                self.next.insert(m.clone(), at);
            }
        }
    }

    /// Mailboxes due at `now`. Spec: § Wallet behaviour (L374–375).
    pub fn due(&self, now: u64) -> Vec<MailboxRef> {
        self.next
            .iter()
            .filter(|(_, &at)| at <= now)
            .map(|(m, _)| m.clone())
            .collect()
    }

    /// Reschedules `m` after a fetch at `now`. Spec: § Wallet behaviour (L374–375).
    pub fn fetched(&mut self, m: &MailboxRef, now: u64) {
        let at = now + self.interval();
        if let Some(slot) = self.next.get_mut(m) {
            *slot = at;
        }
    }

    /// The earliest next fetch time, if any mailbox is scheduled.
    /// Spec: § Wallet behaviour (L374–375).
    pub fn next_wake(&self) -> Option<u64> {
        self.next.values().copied().min()
    }

    /// An exponentially distributed interval with mean `mean_secs`, at least
    /// one second and at most ten means. Spec: § Wallet behaviour (L374–375).
    fn interval(&self) -> u64 {
        let mut b = [0u8; 8];
        // A predictable schedule would let a server link mailboxes, so stop
        // rather than fall back to fixed intervals.
        getrandom::fill(&mut b).expect("the OS random generator is available");
        // U in (0, 1]: 53 random bits.
        let u = ((u64::from_le_bytes(b) >> 11) + 1) as f64 / (1u64 << 53) as f64;
        let secs = -self.mean_secs * u.ln();
        secs.clamp(1.0, 10.0 * self.mean_secs) as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each mailbox gets its own timer; fetching one moves only its timer.
    /// Spec: § Wallet behaviour (L374–376).
    #[test]
    fn independent_timers() {
        let mut s = Schedule::new(Duration::from_secs(600));
        let a = MailboxRef::Contact(0);
        let b = MailboxRef::Pairwise {
            conversation: "c".into(),
            epoch: 7,
        };
        s.sync(&[a.clone(), b.clone()], 1000);
        assert!(s.due(1000).is_empty());
        let (ta, tb) = (s.next[&a], s.next[&b]);
        assert!(ta > 1000 && tb > 1000);
        s.fetched(&a, ta);
        assert_eq!(s.next[&b], tb);
        assert!(s.next[&a] > ta);
        // Due mailboxes are reported; inactive ones are dropped.
        assert_eq!(s.due(u64::MAX).len(), 2);
        s.sync(std::slice::from_ref(&b), 2000);
        assert_eq!(s.due(u64::MAX), [b]);
    }

    /// Intervals are random, bounded, and average close to the mean.
    /// Spec: § Wallet behaviour (L374–375).
    #[test]
    fn intervals_are_random_with_the_right_mean() {
        let s = Schedule::new(Duration::from_secs(600));
        let xs: Vec<u64> = (0..20_000).map(|_| s.interval()).collect();
        assert!(xs.iter().all(|&x| (1..=6000).contains(&x)));
        let mean = xs.iter().sum::<u64>() as f64 / xs.len() as f64;
        assert!((540.0..660.0).contains(&mean), "mean {mean}");
        let distinct: std::collections::HashSet<_> = xs.iter().collect();
        assert!(distinct.len() > 1000);
    }
}
