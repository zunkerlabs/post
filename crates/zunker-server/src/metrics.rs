//! Aggregate counters. The server logs nothing per request: no Mailbox IDs, no
//! Envelope contents, no peer addresses.
//!
//! Spec: `spec/zip-draft-1435.md` § Privacy Implications (L112–118): a server
//! should learn as little as possible about who uses which mailbox.

use std::sync::atomic::{AtomicU64, Ordering};

/// Process-wide counters. Spec: § Privacy Implications (L112–118).
#[derive(Debug, Default)]
pub struct Metrics {
    connections: AtomicU64,
    deposits_stored: AtomicU64,
    deposits_dropped: AtomicU64,
    fetches_served: AtomicU64,
    fetches_dropped: AtomicU64,
    envelopes_served: AtomicU64,
    envelopes_deleted: AtomicU64,
    envelopes_expired: AtomicU64,
    storage_errors: AtomicU64,
}

/// A point-in-time copy of [`Metrics`]. Spec: § Privacy Implications (L112–118).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MetricsSnapshot {
    /// Connections accepted.
    pub connections: u64,
    /// Deposits stored.
    pub deposits_stored: u64,
    /// Deposits dropped (malformed, over quota, or mailbox full).
    pub deposits_dropped: u64,
    /// Fetches answered.
    pub fetches_served: u64,
    /// Fetches dropped (malformed, out of time window, or bad signature).
    pub fetches_dropped: u64,
    /// Envelopes returned by Fetches.
    pub envelopes_served: u64,
    /// Envelopes deleted after a Fetch acknowledged them.
    pub envelopes_deleted: u64,
    /// Envelopes discarded by the retention period.
    pub envelopes_expired: u64,
    /// Storage operations that failed.
    pub storage_errors: u64,
}

/// Which counter to bump. Spec: § Privacy Implications (L112–118).
#[derive(Clone, Copy, Debug)]
pub(crate) enum Counter {
    Connections,
    DepositsStored,
    DepositsDropped,
    FetchesServed,
    FetchesDropped,
    EnvelopesServed,
    EnvelopesDeleted,
    EnvelopesExpired,
    StorageErrors,
}

impl Metrics {
    /// Adds `n` to a counter. Spec: § Privacy Implications (L112–118).
    pub(crate) fn add(&self, counter: Counter, n: u64) {
        let c = match counter {
            Counter::Connections => &self.connections,
            Counter::DepositsStored => &self.deposits_stored,
            Counter::DepositsDropped => &self.deposits_dropped,
            Counter::FetchesServed => &self.fetches_served,
            Counter::FetchesDropped => &self.fetches_dropped,
            Counter::EnvelopesServed => &self.envelopes_served,
            Counter::EnvelopesDeleted => &self.envelopes_deleted,
            Counter::EnvelopesExpired => &self.envelopes_expired,
            Counter::StorageErrors => &self.storage_errors,
        };
        c.fetch_add(n, Ordering::Relaxed);
    }

    /// Reads every counter. Spec: § Privacy Implications (L112–118).
    pub fn snapshot(&self) -> MetricsSnapshot {
        let r = |c: &AtomicU64| c.load(Ordering::Relaxed);
        MetricsSnapshot {
            connections: r(&self.connections),
            deposits_stored: r(&self.deposits_stored),
            deposits_dropped: r(&self.deposits_dropped),
            fetches_served: r(&self.fetches_served),
            fetches_dropped: r(&self.fetches_dropped),
            envelopes_served: r(&self.envelopes_served),
            envelopes_deleted: r(&self.envelopes_deleted),
            envelopes_expired: r(&self.envelopes_expired),
            storage_errors: r(&self.storage_errors),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Counters add up. Spec: § Privacy Implications (L112–118).
    #[test]
    fn counts() {
        let m = Metrics::default();
        m.add(Counter::DepositsStored, 2);
        m.add(Counter::FetchesDropped, 1);
        let s = m.snapshot();
        assert_eq!(
            (s.deposits_stored, s.fetches_dropped, s.connections),
            (2, 1, 0)
        );
    }
}
