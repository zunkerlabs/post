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
/// deletions, and must keep nothing about a mailbox once it holds no
/// Envelopes. Times are seconds since the Unix epoch.
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
    /// `received_at_or_before`, and the mailbox's quota records if it is left
    /// empty. Returns how many were deleted.
    /// Spec: § Mailbox Servers (L316–317).
    fn delete_acknowledged(
        &self,
        mailbox: &MailboxId,
        up_to: u64,
        received_at_or_before: u64,
    ) -> Result<u64, StoreError>;

    /// Discards every Envelope received before `received_before`, quota
    /// records for windows that ended before it, and quota records of
    /// mailboxes left empty. Returns how many Envelopes were discarded.
    /// Spec: § Mailbox Servers (L317–318).
    fn purge(&self, received_before: u64) -> Result<u64, StoreError>;
}

/// `seq` and times are stored as SQLite INTEGER (i64). Values above `i64::MAX`
/// cannot occur for `seq` (see [`next_seq`]) and are clamped for cursors.
/// Spec: § Mailbox Servers (L312 `after` is a u64).
fn to_sql_int(v: u64) -> i64 {
    i64::try_from(v).unwrap_or(i64::MAX)
}

/// Bits of `seq` below the deposit time. `unix_seconds << 20` leaves room for
/// about a million deposits per second before the counter runs ahead of the
/// clock, and stays below `i64::MAX` until the year 280 000.
/// Spec: § Mailbox Servers (L314–315).
pub const SEQ_TIME_SHIFT: u32 = 20;

/// The `seq` for the next Envelope: `max(last_seq + 1, unix_seconds << 20)`.
///
/// One counter serves every mailbox, so `seq` is greater than any ever given
/// under any Mailbox ID, and nothing per mailbox has to be kept to guarantee
/// it. Because the counter never falls behind the clock, it also survives a
/// lost database row: after a restart the clock alone keeps `seq` increasing.
/// The cost is that `seq` tells a fetcher roughly when an Envelope was
/// deposited, to the second.
///
/// Spec: § Mailbox Servers (L314–315).
pub fn next_seq(last_seq: u64, now: u64) -> u64 {
    let from_clock = now.saturating_mul(1 << SEQ_TIME_SHIFT);
    last_seq
        .saturating_add(1)
        .max(from_clock)
        .min(i64::MAX as u64)
}

/// SQLite-backed [`Store`].
///
/// `seq` comes from one persisted global counter ([`next_seq`]), so the store
/// keeps no row for a mailbox beyond its Envelopes. Deposit-quota rows for a
/// mailbox are removed with its last Envelope, and otherwise when their window
/// ends.
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
             CREATE TABLE IF NOT EXISTS seq_counter (
                 id INTEGER PRIMARY KEY CHECK (id = 0),
                 last_seq INTEGER NOT NULL
             );
             INSERT OR IGNORE INTO seq_counter (id, last_seq) VALUES (0, 0);
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
        Self::drop_per_mailbox_counters(&conn)?;
        Ok(SqliteStore {
            conn: Mutex::new(conn),
        })
    }

    /// Databases created before the global counter kept a `mailboxes` table
    /// with one row per Mailbox ID ever seen. Carry its largest `seq` into the
    /// global counter, then drop it, so no record of past mailboxes remains.
    /// Spec: § Mailbox Servers (L314–315).
    fn drop_per_mailbox_counters(conn: &Connection) -> Result<(), StoreError> {
        let old: bool = conn.query_row(
            "SELECT EXISTS (SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'mailboxes')",
            [],
            |r| r.get(0),
        )?;
        if old {
            conn.execute_batch(
                "BEGIN IMMEDIATE;
                 UPDATE seq_counter SET last_seq =
                     MAX(last_seq, (SELECT COALESCE(MAX(last_seq), 0) FROM mailboxes));
                 DROP TABLE mailboxes;
                 COMMIT;",
            )?;
        }
        Ok(())
    }

    /// Locks the connection, recovering from a poisoned lock (a panic while
    /// holding it cannot leave SQLite in a half-written state, since every
    /// write is in a transaction). Spec: none (concurrency).
    fn conn(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl Store for SqliteStore {
    /// One IMMEDIATE transaction: check quota and capacity, advance the global
    /// counter, insert the Envelope, count it against the quota.
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

        let last: i64 = tx.query_row("SELECT last_seq FROM seq_counter WHERE id = 0", [], |r| {
            r.get(0)
        })?;
        let seq = to_sql_int(next_seq(u64::try_from(last).unwrap_or(0), now));
        tx.execute(
            "UPDATE seq_counter SET last_seq = ?1 WHERE id = 0",
            params![seq],
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
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        let id = &mailbox.as_bytes()[..];
        let n = tx.execute(
            "DELETE FROM envelopes WHERE mailbox_id = ?1 AND seq <= ?2 AND received_at <= ?3",
            params![id, to_sql_int(up_to), to_sql_int(received_at_or_before)],
        )?;
        tx.execute(
            "DELETE FROM deposit_quota WHERE mailbox_id = ?1
             AND NOT EXISTS (SELECT 1 FROM envelopes WHERE mailbox_id = ?1)",
            params![id],
        )?;
        tx.commit()?;
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
            "DELETE FROM deposit_quota WHERE window_end < ?1
             OR NOT EXISTS (SELECT 1 FROM envelopes WHERE envelopes.mailbox_id = deposit_quota.mailbox_id)",
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

    /// The `seq` a deposit at `now` gets on an otherwise idle server.
    /// Spec: § Mailbox Servers (L314–315).
    fn at(now: u64) -> u64 {
        now << SEQ_TIME_SHIFT
    }

    /// Stores and returns the `seq`. Spec: § Mailbox Servers (L314–315).
    fn put(s: &SqliteStore, m: &MailboxId, i: u8, now: u64) -> u64 {
        match s.deposit(m, &envelope(i), now, &LIMITS).unwrap() {
            DepositOutcome::Stored(seq) => seq,
            other => panic!("{other:?}"),
        }
    }

    /// `max(last_seq + 1, unix_seconds << 20)`, saturating.
    /// Spec: § Mailbox Servers (L314–315).
    #[test]
    fn next_seq_formula() {
        assert_eq!(next_seq(0, 0), 1);
        assert_eq!(next_seq(0, 100), at(100));
        assert_eq!(next_seq(at(100), 100), at(100) + 1);
        assert_eq!(next_seq(at(200), 100), at(200) + 1); // clock went back
        assert_eq!(next_seq(u64::MAX, u64::MAX), i64::MAX as u64);
    }

    /// One counter for every mailbox: nonzero, strictly increasing across
    /// mailboxes, and following the clock.
    /// Spec: § Mailbox Servers (L314–315).
    #[test]
    fn seq_global_nonzero_increasing() {
        let s = SqliteStore::open_in_memory().unwrap();
        let (a, b) = (mailbox_id(1), mailbox_id(2));
        assert_eq!(put(&s, &a, 0, 100), at(100));
        assert_eq!(put(&s, &b, 0, 100), at(100) + 1);
        assert_eq!(put(&s, &a, 1, 100), at(100) + 2);
        assert_eq!(put(&s, &b, 1, 101), at(101));
        // The clock going backwards does not make `seq` go backwards.
        assert_eq!(put(&s, &a, 2, 50), at(101) + 1);
    }

    /// `seq` is never reused after deletion or expiry, with nothing kept per
    /// mailbox. Spec: § Mailbox Servers (L314–315: "greater than any it has ever given").
    #[test]
    fn seq_never_reused() {
        let s = SqliteStore::open_in_memory().unwrap();
        let a = mailbox_id(1);
        let last = (0..3).map(|i| put(&s, &a, i, 100)).last().unwrap();
        assert_eq!(s.delete_acknowledged(&a, last, 100).unwrap(), 3);
        let next = put(&s, &a, 9, 100);
        assert!(next > last);
        assert_eq!(s.purge(u64::MAX).unwrap(), 1);
        assert!(put(&s, &a, 9, 100) > next);
    }

    /// The counter is persisted: reopening a database file continues it, and a
    /// database with the old per-mailbox `mailboxes` table is migrated and the
    /// table dropped. Spec: § Mailbox Servers (L314–315).
    #[test]
    fn counter_persists_and_old_table_is_dropped() {
        let dir = std::env::temp_dir().join(format!("zunker-store-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("counter.sqlite");
        let _ = std::fs::remove_file(&path);
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE mailboxes (id BLOB PRIMARY KEY, last_seq INTEGER NOT NULL) WITHOUT ROWID;
                 INSERT INTO mailboxes VALUES (x'01', 5), (x'02', 9000000000000000000);",
            )
            .unwrap();
        }
        let first = {
            let s = SqliteStore::open(&path).unwrap();
            let tables: i64 = s
                .conn()
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE name = 'mailboxes'",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(tables, 0);
            put(&s, &mailbox_id(1), 0, 100)
        };
        assert_eq!(first, 9_000_000_000_000_000_001);
        let s = SqliteStore::open(&path).unwrap();
        assert_eq!(put(&s, &mailbox_id(2), 0, 100), first + 1);
        drop(s);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Nothing about a mailbox outlives its Envelopes: once the last one is
    /// deleted or purged, no row mentions its ID.
    /// Spec: § Mailbox Servers (L314–318), § Privacy Implications (L112–118).
    #[test]
    fn nothing_outlives_envelopes() {
        let rows_for = |s: &SqliteStore, m: &MailboxId| -> i64 {
            let c = s.conn();
            let id = &m.as_bytes()[..];
            let q = |sql: &str| -> i64 { c.query_row(sql, params![id], |r| r.get(0)).unwrap() };
            q("SELECT COUNT(*) FROM envelopes WHERE mailbox_id = ?1")
                + q("SELECT COUNT(*) FROM deposit_quota WHERE mailbox_id = ?1")
        };
        let s = SqliteStore::open_in_memory().unwrap();
        let (a, b) = (mailbox_id(1), mailbox_id(2));
        let seq = put(&s, &a, 0, 100);
        put(&s, &b, 0, 200);
        assert!(rows_for(&s, &a) > 0);
        s.delete_acknowledged(&a, seq, 100).unwrap();
        assert_eq!(rows_for(&s, &a), 0);
        assert!(rows_for(&s, &b) > 0);
        // Purging b's Envelope also removes its quota row, though its quota
        // window (3600 s from 0) has not ended at the cutoff.
        s.purge(201).unwrap();
        assert_eq!(rows_for(&s, &b), 0);
    }

    /// The cursor and the byte budget. Spec: § Mailbox Servers (L315–316).
    #[test]
    fn fetch_cursor_and_budget() {
        let s = SqliteStore::open_in_memory().unwrap();
        let a = mailbox_id(1);
        for i in 0..4 {
            s.deposit(&a, &envelope(i), 100, &LIMITS).unwrap();
        }
        let seqs = |v: Vec<FetchedEnvelope>| {
            v.into_iter()
                .map(|e| e.seq - at(100) + 1)
                .collect::<Vec<_>>()
        };
        assert_eq!(seqs(s.fetch(&a, 0, usize::MAX).unwrap()), [1, 2, 3, 4]);
        assert_eq!(seqs(s.fetch(&a, at(100) + 1, usize::MAX).unwrap()), [3, 4]);
        assert_eq!(
            seqs(s.fetch(&a, at(100) + 3, usize::MAX).unwrap()),
            Vec::<u64>::new()
        );
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
        let seq = put(&s, &a, 0, 100);
        s.delete_acknowledged(&a, seq, 100).unwrap();
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
        let s1 = put(&s, &a, 0, 100);
        let s2 = put(&s, &a, 1, 200);
        let s3 = put(&s, &a, 2, 100);
        assert_eq!(s.delete_acknowledged(&a, s2, 150).unwrap(), 1); // s1 only
        let left: Vec<u64> = s
            .fetch(&a, 0, usize::MAX)
            .unwrap()
            .iter()
            .map(|e| e.seq)
            .collect();
        assert_eq!(left, [s2, s3]);
        assert!(s1 < s2 && s2 < s3);
    }

    /// Retention purge. Spec: § Mailbox Servers (L317–318).
    #[test]
    fn purge_by_age() {
        let s = SqliteStore::open_in_memory().unwrap();
        let a = mailbox_id(1);
        put(&s, &a, 0, 100);
        let kept = put(&s, &a, 1, 300);
        assert_eq!(s.purge(200).unwrap(), 1);
        assert_eq!(s.fetch(&a, 0, usize::MAX).unwrap()[0].seq, kept);
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
            DepositOutcome::Stored(_)
        ));
        assert!(matches!(
            s.deposit(&a, &envelope(1), 10, &limits).unwrap(),
            DepositOutcome::Stored(_)
        ));
        assert_eq!(
            s.deposit(&a, &envelope(2), 59, &limits).unwrap(),
            DepositOutcome::OverQuota
        );
        // Another mailbox has its own quota.
        assert!(matches!(
            s.deposit(&mailbox_id(2), &envelope(2), 59, &limits)
                .unwrap(),
            DepositOutcome::Stored(_)
        ));
        // Next window.
        assert!(matches!(
            s.deposit(&a, &envelope(3), 60, &limits).unwrap(),
            DepositOutcome::Stored(_)
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
