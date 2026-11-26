//! Envelope storage: a trait, and its SQLite implementation.
//!
//! Spec: `spec/zip-draft-1435.md` § Mailbox Servers (L314–318).

use std::fmt;
use std::path::Path;
use std::sync::Mutex;

use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use zunker_core::mailbox::MailboxId;

use crate::wire::{fetch_item_len, FetchedEnvelope};

/// Limits applied to a Deposit. Spec: § Open issues (L450–451), § Privacy
/// Implications (L138–139).
#[derive(Clone, Copy, Debug)]
pub struct DepositLimits {
    /// Deposits are refused while the mailbox holds this many Envelopes.
    pub max_envelopes: u32,
    /// Deposits accepted per mailbox in one quota window.
    pub quota: u32,
    /// Quota window length in seconds.
    pub quota_window_secs: u64,
}

/// What happened to a Deposit. The server treats all three the same way on
/// the wire (no response); the distinction is only counted.
///
/// Spec: § Mailbox Servers (L311, L314–315).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DepositOutcome {
    /// Stored under this `seq`.
    Stored(u64),
    /// The mailbox's deposit quota for the current window is used up.
    OverQuota,
    /// The mailbox already holds `max_envelopes` Envelopes.
    Full,
}

/// A storage failure. Carries no request data, so it is safe to count.
#[derive(Debug)]
pub struct StoreError(rusqlite::Error);

impl fmt::Display for StoreError {
    /// Spec: none (diagnostics only).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "storage error: {}", self.0)
    }
}

impl std::error::Error for StoreError {}

impl From<rusqlite::Error> for StoreError {
    /// Spec: none (error conversion).
    fn from(e: rusqlite::Error) -> Self {
        StoreError(e)
    }
}

/// Storage of `(mailbox_id, seq, envelope, received_at)`.
///
/// Implementations must give each stored Envelope a nonzero `seq`, strictly
/// greater than any `seq` ever given under that Mailbox ID, even after
/// deletions. Times are seconds since the Unix epoch.
///
/// Spec: § Mailbox Servers (L314–318).
pub trait Store: Send + Sync + 'static {
    /// Stores an Envelope unless the mailbox is full or over quota.
    /// Spec: § Mailbox Servers (L311, L314–315).
    fn deposit(
        &self,
        mailbox: &MailboxId,
        envelope: &[u8],
        now: u64,
        limits: &DepositLimits,
    ) -> Result<DepositOutcome, StoreError>;

    /// Envelopes with `seq > after`, in order, whose `(seq, len, Envelope)`
    /// triples fit in `byte_budget` bytes. An unknown mailbox and an empty one
    /// both give an empty list.
    /// Spec: § Mailbox Servers (L315–317, L329–330).
    fn fetch(
        &self,
        mailbox: &MailboxId,
        after: u64,
        byte_budget: usize,
    ) -> Result<Vec<FetchedEnvelope>, StoreError>;

    /// Deletes Envelopes with `seq <= up_to` received at or before
    /// `received_at_or_before`. Returns how many were deleted.
    /// Spec: § Mailbox Servers (L316–317).
    fn delete_acknowledged(
        &self,
        mailbox: &MailboxId,
        up_to: u64,
        received_at_or_before: u64,
    ) -> Result<u64, StoreError>;

    /// Discards every Envelope received before `received_before`, and quota
    /// records for windows that ended before it. Returns how many Envelopes
    /// were discarded.
    /// Spec: § Mailbox Servers (L317–318).
    fn purge(&self, received_before: u64) -> Result<u64, StoreError>;
}

/// `seq` and times are stored as SQLite INTEGER (i64). Values above `i64::MAX`
/// cannot occur for `seq` (it counts up from 1) and are clamped for cursors.
/// Spec: § Mailbox Servers (L312 `after` is a u64).
fn to_sql_int(v: u64) -> i64 {
    i64::try_from(v).unwrap_or(i64::MAX)
}

/// SQLite-backed [`Store`].
///
/// `mailboxes` keeps the last `seq` of every Mailbox ID that ever received an
/// Envelope, so `seq`s are never reused after deletion or expiry. The cost is
/// one 72-byte row per such Mailbox ID, kept indefinitely.
///
/// Spec: § Mailbox Servers (L314–318).
pub struct SqliteStore {
    conn: Mutex<Connection>,
}

impl SqliteStore {
    /// Opens (creating if needed) a database file. Spec: § Mailbox Servers (L314–318).
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        Self::init(Connection::open(path)?)
    }

    /// An in-memory database, for tests and `database = ":memory:"`.
    /// Spec: § Mailbox Servers (L314–318).
    pub fn open_in_memory() -> Result<Self, StoreError> {
        Self::init(Connection::open_in_memory()?)
    }

    /// Creates the schema. Spec: § Mailbox Servers (L314–318).
    fn init(conn: Connection) -> Result<Self, StoreError> {
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA secure_delete = ON;
             CREATE TABLE IF NOT EXISTS mailboxes (
                 id BLOB PRIMARY KEY,
                 last_seq INTEGER NOT NULL
             ) WITHOUT ROWID;
             CREATE TABLE IF NOT EXISTS envelopes (
                 mailbox_id BLOB NOT NULL,
                 seq INTEGER NOT NULL,
                 envelope BLOB NOT NULL,
                 received_at INTEGER NOT NULL,
                 UNIQUE (mailbox_id, seq)
             );
             CREATE INDEX IF NOT EXISTS envelopes_received_at ON envelopes (received_at);
             CREATE TABLE IF NOT EXISTS deposit_quota (
                 mailbox_id BLOB NOT NULL,
                 window INTEGER NOT NULL,
                 window_end INTEGER NOT NULL,
                 count INTEGER NOT NULL,
                 PRIMARY KEY (mailbox_id, window)
             ) WITHOUT ROWID;",
        )?;
        Ok(SqliteStore {
            conn: Mutex::new(conn),
        })
    }

    /// Locks the connection, recovering from a poisoned lock (a panic while
    /// holding it cannot leave SQLite in a half-written state, since every
    /// write is in a transaction). Spec: none (concurrency).
    fn conn(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl Store for SqliteStore {
    /// One IMMEDIATE transaction: check quota and capacity, bump `last_seq`,
    /// insert the Envelope, count it against the quota.
    /// Spec: § Mailbox Servers (L311, L314–315).
    fn deposit(
        &self,
        mailbox: &MailboxId,
        envelope: &[u8],
        now: u64,
        limits: &DepositLimits,
    ) -> Result<DepositOutcome, StoreError> {
        let mut conn = self.conn();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let id = &mailbox.as_bytes()[..];
        let window = to_sql_int(now / limits.quota_window_secs);
        let window_end = to_sql_int(
            (now / limits.quota_window_secs + 1).saturating_mul(limits.quota_window_secs),
        );

        let used: i64 = tx
            .query_row(
                "SELECT count FROM deposit_quota WHERE mailbox_id = ?1 AND window = ?2",
                params![id, window],
                |r| r.get(0),
            )
            .optional()?
            .unwrap_or(0);
        if used >= i64::from(limits.quota) {
            return Ok(DepositOutcome::OverQuota);
        }

        let held: i64 = tx.query_row(
            "SELECT COUNT(*) FROM envelopes WHERE mailbox_id = ?1",
            params![id],
            |r| r.get(0),
        )?;
        if held >= i64::from(limits.max_envelopes) {
            return Ok(DepositOutcome::Full);
        }

        let seq: i64 = tx.query_row(
            "INSERT INTO mailboxes (id, last_seq) VALUES (?1, 1)
             ON CONFLICT (id) DO UPDATE SET last_seq = last_seq + 1
             RETURNING last_seq",
            params![id],
            |r| r.get(0),
        )?;
        tx.execute(
            "INSERT INTO envelopes (mailbox_id, seq, envelope, received_at) VALUES (?1, ?2, ?3, ?4)",
            params![id, seq, envelope, to_sql_int(now)],
        )?;
        tx.execute(
            "INSERT INTO deposit_quota (mailbox_id, window, window_end, count) VALUES (?1, ?2, ?3, 1)
             ON CONFLICT (mailbox_id, window) DO UPDATE SET count = count + 1",
            params![id, window, window_end],
        )?;
        tx.commit()?;
        Ok(DepositOutcome::Stored(seq as u64))
    }

    /// Spec: § Mailbox Servers (L315–317, L329–330).
    fn fetch(
        &self,
        mailbox: &MailboxId,
        after: u64,
        byte_budget: usize,
    ) -> Result<Vec<FetchedEnvelope>, StoreError> {
        let conn = self.conn();
        let mut stmt = conn.prepare_cached(
            "SELECT seq, envelope FROM envelopes WHERE mailbox_id = ?1 AND seq > ?2 ORDER BY seq",
        )?;
        let mut rows = stmt.query(params![&mailbox.as_bytes()[..], to_sql_int(after)])?;
        let mut out = Vec::new();
        let mut used = 0usize;
        while let Some(row) = rows.next()? {
            let seq: i64 = row.get(0)?;
            let envelope: Vec<u8> = row.get(1)?;
            let size = fetch_item_len(envelope.len());
            if used + size > byte_budget {
                break;
            }
            used += size;
            out.push(FetchedEnvelope {
                seq: seq as u64,
                envelope,
            });
        }
        Ok(out)
    }

    /// Spec: § Mailbox Servers (L316–317).
    fn delete_acknowledged(
        &self,
        mailbox: &MailboxId,
        up_to: u64,
        received_at_or_before: u64,
    ) -> Result<u64, StoreError> {
        let conn = self.conn();
        let n = conn.execute(
            "DELETE FROM envelopes WHERE mailbox_id = ?1 AND seq <= ?2 AND received_at <= ?3",
            params![
                &mailbox.as_bytes()[..],
                to_sql_int(up_to),
                to_sql_int(received_at_or_before)
            ],
        )?;
        Ok(n as u64)
    }

    /// Spec: § Mailbox Servers (L317–318).
    fn purge(&self, received_before: u64) -> Result<u64, StoreError> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        let n = tx.execute(
            "DELETE FROM envelopes WHERE received_at < ?1",
            params![to_sql_int(received_before)],
        )?;
        tx.execute(
            "DELETE FROM deposit_quota WHERE window_end < ?1",
            params![to_sql_int(received_before)],
        )?;
        tx.commit()?;
        Ok(n as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{envelope, mailbox_id};

    const LIMITS: DepositLimits = DepositLimits {
        max_envelopes: 1000,
        quota: 1000,
        quota_window_secs: 3600,
    };

    /// `seq` starts at 1 and increases by mailbox.
    /// Spec: § Mailbox Servers (L314–315).
    #[test]
    fn seq_per_mailbox_nonzero_increasing() {
        let s = SqliteStore::open_in_memory().unwrap();
        let (a, b) = (mailbox_id(1), mailbox_id(2));
        let mut last = 0;
        for i in 0..5 {
            let DepositOutcome::Stored(seq) = s.deposit(&a, &envelope(i), 100, &LIMITS).unwrap()
            else {
                panic!()
            };
            assert!(seq > last && seq != 0);
            last = seq;
            assert_eq!(
                s.deposit(&b, &envelope(i), 100, &LIMITS).unwrap(),
                DepositOutcome::Stored(i as u64 + 1)
            );
        }
    }

    /// `seq` is never reused after deletion or expiry.
    /// Spec: § Mailbox Servers (L314–315: "greater than any it has ever given").
    #[test]
    fn seq_never_reused() {
        let s = SqliteStore::open_in_memory().unwrap();
        let a = mailbox_id(1);
        for i in 0..3 {
            s.deposit(&a, &envelope(i), 100, &LIMITS).unwrap();
        }
        assert_eq!(s.delete_acknowledged(&a, 3, 100).unwrap(), 3);
        assert_eq!(
            s.deposit(&a, &envelope(9), 100, &LIMITS).unwrap(),
            DepositOutcome::Stored(4)
        );
        assert_eq!(s.purge(u64::MAX).unwrap(), 1);
        assert_eq!(
            s.deposit(&a, &envelope(9), 200, &LIMITS).unwrap(),
            DepositOutcome::Stored(5)
        );
    }

    /// The cursor and the byte budget. Spec: § Mailbox Servers (L315–316).
    #[test]
    fn fetch_cursor_and_budget() {
        let s = SqliteStore::open_in_memory().unwrap();
        let a = mailbox_id(1);
        for i in 0..4 {
            s.deposit(&a, &envelope(i), 100, &LIMITS).unwrap();
        }
        let seqs = |v: Vec<FetchedEnvelope>| v.into_iter().map(|e| e.seq).collect::<Vec<_>>();
        assert_eq!(seqs(s.fetch(&a, 0, usize::MAX).unwrap()), [1, 2, 3, 4]);
        assert_eq!(seqs(s.fetch(&a, 2, usize::MAX).unwrap()), [3, 4]);
        assert_eq!(seqs(s.fetch(&a, 4, usize::MAX).unwrap()), Vec::<u64>::new());
        assert_eq!(
            seqs(s.fetch(&a, u64::MAX, usize::MAX).unwrap()),
            Vec::<u64>::new()
        );
        let two = 2 * fetch_item_len(envelope(0).len());
        assert_eq!(seqs(s.fetch(&a, 0, two).unwrap()), [1, 2]);
        assert_eq!(seqs(s.fetch(&a, 0, two - 1).unwrap()), [1]);
        assert_eq!(s.fetch(&a, 0, usize::MAX).unwrap()[2].envelope, envelope(2));
    }

    /// Unknown and emptied mailboxes look the same.
    /// Spec: § Mailbox Servers (L329–330).
    #[test]
    fn unknown_equals_empty() {
        let s = SqliteStore::open_in_memory().unwrap();
        let a = mailbox_id(1);
        s.deposit(&a, &envelope(0), 100, &LIMITS).unwrap();
        s.delete_acknowledged(&a, 1, 100).unwrap();
        assert_eq!(
            s.fetch(&a, 0, usize::MAX).unwrap(),
            s.fetch(&mailbox_id(2), 0, usize::MAX).unwrap()
        );
    }

    /// Acknowledged deletion respects the age cutoff and the cursor.
    /// Spec: § Mailbox Servers (L316–317).
    #[test]
    fn delete_respects_age_and_cursor() {
        let s = SqliteStore::open_in_memory().unwrap();
        let a = mailbox_id(1);
        s.deposit(&a, &envelope(0), 100, &LIMITS).unwrap();
        s.deposit(&a, &envelope(1), 200, &LIMITS).unwrap();
        s.deposit(&a, &envelope(2), 100, &LIMITS).unwrap();
        assert_eq!(s.delete_acknowledged(&a, 2, 150).unwrap(), 1); // seq 1 only
        let left: Vec<u64> = s
            .fetch(&a, 0, usize::MAX)
            .unwrap()
            .iter()
            .map(|e| e.seq)
            .collect();
        assert_eq!(left, [2, 3]);
    }

    /// Retention purge. Spec: § Mailbox Servers (L317–318).
    #[test]
    fn purge_by_age() {
        let s = SqliteStore::open_in_memory().unwrap();
        let a = mailbox_id(1);
        s.deposit(&a, &envelope(0), 100, &LIMITS).unwrap();
        s.deposit(&a, &envelope(1), 300, &LIMITS).unwrap();
        assert_eq!(s.purge(200).unwrap(), 1);
        assert_eq!(s.fetch(&a, 0, usize::MAX).unwrap()[0].seq, 2);
    }

    /// Quota per window, and the per-mailbox cap.
    /// Spec: § Open issues (L450–451), § Privacy Implications (L138–139).
    #[test]
    fn quota_and_capacity() {
        let s = SqliteStore::open_in_memory().unwrap();
        let a = mailbox_id(1);
        let limits = DepositLimits {
            max_envelopes: 3,
            quota: 2,
            quota_window_secs: 60,
        };
        assert!(matches!(
            s.deposit(&a, &envelope(0), 0, &limits).unwrap(),
            DepositOutcome::Stored(1)
        ));
        assert!(matches!(
            s.deposit(&a, &envelope(1), 10, &limits).unwrap(),
            DepositOutcome::Stored(2)
        ));
        assert_eq!(
            s.deposit(&a, &envelope(2), 59, &limits).unwrap(),
            DepositOutcome::OverQuota
        );
        // Another mailbox has its own quota.
        assert!(matches!(
            s.deposit(&mailbox_id(2), &envelope(2), 59, &limits)
                .unwrap(),
            DepositOutcome::Stored(1)
        ));
        // Next window.
        assert!(matches!(
            s.deposit(&a, &envelope(3), 60, &limits).unwrap(),
            DepositOutcome::Stored(3)
        ));
        assert_eq!(
            s.deposit(&a, &envelope(4), 61, &limits).unwrap(),
            DepositOutcome::Full
        );
        // Quota records are purged with old windows.
        s.purge(1000).unwrap();
        let n: i64 = s
            .conn()
            .query_row("SELECT COUNT(*) FROM deposit_quota", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 0);
    }
}
