//! End-to-end tests over real TCP connections, with Fetch requests signed by
//! `zunker-core` and a manual clock.
//!
//! Spec: `spec/zip-draft-1435.md` § Mailbox Servers (L307–330); framing per
//! Appendix A, Tor (L497–498).

use std::net::SocketAddr;
use std::sync::Arc;

use group::{Group, GroupEncoding};
use pasta_curves::pallas;
use rand::rngs::StdRng;
use rand::SeedableRng;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use zunker_core::envelope::{Conversation, Direction};
use zunker_core::mailbox::{pairwise_mailbox_key, MailboxKey};
use zunker_core::receiver::Receiver;
use zunker_core::sig::FetchRequest;
use zunker_server::{Config, CoreVerifier, ManualClock, Server, SqliteStore};
use zunker_wire::{decode_fetch_response, encode_deposit, FetchedEnvelope};

const SERVER_ID: [u8; 32] = [0x5e; 32];
const NOW_HOURS: u64 = 500_000;

/// A running server and its clock. Spec: § Mailbox Servers (L307–330).
struct Harness {
    addr: SocketAddr,
    server: Arc<Server>,
    clock: Arc<ManualClock>,
    rng: StdRng,
}

/// Starts a server on an ephemeral port with an in-memory store.
/// Spec: § Mailbox Servers (L307–330).
async fn start(tweak: impl FnOnce(&mut Config)) -> Harness {
    let mut config = Config::from_toml(&format!(
        "listen = \"127.0.0.1:0\"\nserver_id = \"{}\"\ndatabase = \":memory:\"\n",
        hex(&SERVER_ID)
    ))
    .unwrap();
    tweak(&mut config);
    config.validate().unwrap();
    let clock = Arc::new(ManualClock::new(NOW_HOURS * 3600));
    let server = Arc::new(Server::new(
        config,
        Arc::new(SqliteStore::open_in_memory().unwrap()),
        Arc::new(CoreVerifier),
        clock.clone(),
    ));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(server.clone().serve(listener));
    Harness {
        addr,
        server,
        clock,
        rng: StdRng::seed_from_u64(7),
    }
}

/// Lowercase hex. Spec: none (test helper).
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Sends raw bytes, half-closes, and returns everything the server sent
/// before closing. Spec: Appendix A, Tor (L497–498).
async fn send_raw(addr: SocketAddr, bytes: &[u8]) -> Vec<u8> {
    let mut s = TcpStream::connect(addr).await.unwrap();
    s.write_all(bytes).await.unwrap();
    s.shutdown().await.unwrap();
    let mut out = Vec::new();
    s.read_to_end(&mut out).await.unwrap();
    out
}

/// Sends one length-prefixed request; returns the raw reply bytes (empty if
/// the server closed without replying). Spec: Appendix A, Tor (L497–498).
async fn send(addr: SocketAddr, request: &[u8]) -> Vec<u8> {
    let mut framed = (request.len() as u32).to_le_bytes().to_vec();
    framed.extend_from_slice(request);
    send_raw(addr, &framed).await
}

/// Decodes a reply: `None` for no reply, else the Fetch triples.
/// Spec: § Mailbox Servers (L312).
fn decode(reply: &[u8]) -> Option<Vec<FetchedEnvelope>> {
    if reply.is_empty() {
        return None;
    }
    let len = u32::from_le_bytes(reply[..4].try_into().unwrap()) as usize;
    assert_eq!(reply.len(), 4 + len, "one frame per connection");
    Some(decode_fetch_response(&reply[4..]).unwrap())
}

/// A mailbox key distinct for each `n`, from a Pairwise derivation.
/// Spec: § Mailboxes (L272–275).
fn key(n: u8) -> MailboxKey {
    let mut raw = [0u8; 43];
    raw[11..]
        .copy_from_slice(&(pallas::Point::generator() * pallas::Scalar::from(7u64)).to_bytes());
    let conv = Conversation::from_parts([n; 32], Receiver::from_raw(&raw).unwrap());
    pairwise_mailbox_key(&conv, Direction::Initiator, 0).unwrap()
}

/// An Envelope of plaintext size `n` filled with `tag`. Spec: § Envelopes (L194–198).
fn envelope(n: usize, tag: u8) -> Vec<u8> {
    let mut e = vec![tag; n + 49];
    e[0] = 1;
    e
}

impl Harness {
    /// Current server time in hours. Spec: § Notation (L184–185).
    fn hours(&self) -> u32 {
        (self.clock_secs() / 3600) as u32
    }

    /// Spec: none (test helper).
    fn clock_secs(&self) -> u64 {
        use zunker_server::Clock;
        self.clock.now_secs()
    }

    /// Deposits and asserts that no reply came back. Spec: § Mailbox Servers (L311).
    async fn deposit(&self, key: &MailboxKey, envelope: &[u8]) {
        let reply = send(self.addr, &encode_deposit(&key.id(), envelope)).await;
        assert!(reply.is_empty(), "Deposit has no response");
    }

    /// A signed Fetch at the current time. Spec: § Mailbox Servers (L312, L320–322).
    fn fetch_request(&mut self, key: &MailboxKey, after: u64) -> [u8; 141] {
        let time = self.hours();
        FetchRequest::sign(key, after, time, &SERVER_ID, &mut self.rng).unwrap()
    }

    /// Fetches; `None` means the server dropped the request.
    /// Spec: § Mailbox Servers (L312, L315–317).
    async fn fetch(&mut self, key: &MailboxKey, after: u64) -> Option<Vec<FetchedEnvelope>> {
        let req = self.fetch_request(key, after);
        decode(&send(self.addr, &req).await)
    }
}

/// The fill byte of each fetched Envelope (see [`envelope`]), to tell them
/// apart. `seq`s come from a clock-based global counter, so tests compare
/// those by order rather than by value. Spec: § Mailbox Servers (L312).
fn tags(items: &[FetchedEnvelope]) -> Vec<u8> {
    items.iter().map(|i| i.envelope[1]).collect()
}

/// The `seq` of the only Envelope in a mailbox. Spec: § Mailbox Servers (L312).
async fn only_seq(h: &mut Harness, key: &MailboxKey) -> u64 {
    let items = h.fetch(key, 0).await.unwrap();
    assert_eq!(items.len(), 1);
    items[0].seq
}

/// Spec: § Mailbox Servers (L311–312, L314–316): Deposit then Fetch returns
/// the Envelopes, in order, with nonzero `seq`s.
#[tokio::test]
async fn deposit_then_fetch_round_trip() {
    let mut h = start(|_| {}).await;
    let k = key(1);
    let small = envelope(2048, 0xaa);
    let medium = envelope(32768, 0xbb);
    h.deposit(&k, &small).await;
    h.deposit(&k, &medium).await;
    let items = h.fetch(&k, 0).await.unwrap();
    assert_eq!(tags(&items), [0xaa, 0xbb]);
    assert!(items[0].seq != 0 && items[0].seq < items[1].seq);
    assert_eq!(items[0].envelope, small);
    assert_eq!(items[1].envelope, medium);
    let m = h.server.metrics().snapshot();
    assert_eq!(
        (m.deposits_stored, m.fetches_served, m.envelopes_served),
        (2, 1, 2)
    );
}

/// Spec: § Mailbox Servers (L314–315): `seq` comes from one counter for every
/// mailbox, starts at the deposit time shifted left 20 bits, increases
/// strictly, and is never reused after deletion.
#[tokio::test]
async fn seq_monotonic_and_never_reused() {
    let mut h = start(|c| {
        c.retention.delete_on_fetch = true;
        c.retention.min_age_before_delete_hours = 0;
    })
    .await;
    let (a, b) = (key(1), key(2));
    for i in 0..3 {
        h.deposit(&a, &envelope(2048, i)).await;
        h.deposit(&b, &envelope(2048, i)).await;
    }
    let fa = h.fetch(&a, 0).await.unwrap();
    let fb = h.fetch(&b, 0).await.unwrap();
    assert_eq!((tags(&fa), tags(&fb)), (vec![0, 1, 2], vec![0, 1, 2]));
    assert_eq!(fa[0].seq, h.clock_secs() << 20);
    // Interleaved deposits get interleaved `seq`s.
    assert!(fa[0].seq < fb[0].seq && fb[0].seq < fa[1].seq && fa[2].seq < fb[2].seq);
    // Acknowledge (and delete) a's Envelopes, then deposit again.
    assert!(h.fetch(&a, fa[2].seq).await.unwrap().is_empty());
    assert!(h.fetch(&a, 0).await.unwrap().is_empty());
    h.deposit(&a, &envelope(2048, 9)).await;
    assert!(only_seq(&mut h, &a).await > fb[2].seq);
}

/// Spec: § Mailbox Servers (L315–317): `after` is a cursor, the byte budget
/// limits a response, and with deletion off (the default) every device can
/// fetch from 0 again.
#[tokio::test]
async fn cursor_and_byte_budget() {
    let mut h = start(|c| c.limits.fetch_byte_budget = 262_205).await;
    let k = key(1);
    for i in 0..10 {
        h.deposit(&k, &envelope(32768, i)).await;
    }
    // 262205 / (12 + 32817) = 7 triples per response.
    let first = h.fetch(&k, 0).await.unwrap();
    assert_eq!(tags(&first), (0..7).collect::<Vec<_>>());
    let rest = h.fetch(&k, first[6].seq).await.unwrap();
    assert_eq!(tags(&rest), [7, 8, 9]);
    assert_eq!(rest[2].envelope, envelope(32768, 9));
    assert!(h.fetch(&k, rest[2].seq).await.unwrap().is_empty());
    assert!(h.fetch(&k, u64::MAX).await.unwrap().is_empty());
    // Deletion is off by default: a second device still sees everything.
    assert_eq!(
        tags(&h.fetch(&k, 0).await.unwrap()),
        (0..7).collect::<Vec<_>>()
    );
    // A largest-size Envelope always fits the minimum budget.
    let big = key(2);
    h.deposit(&big, &envelope(262_144, 1)).await;
    assert_eq!(tags(&h.fetch(&big, 0).await.unwrap()), [1]);
}

/// Spec: § Mailbox Servers (L326–328): malformed requests are dropped without
/// a reply and store nothing.
#[tokio::test]
async fn malformed_requests_dropped() {
    let mut h = start(|_| {}).await;
    let k = key(1);
    let good = encode_deposit(&k.id(), &envelope(2048, 1));

    let mut identity_half = good.clone();
    identity_half[33..65].fill(0);
    let mut not_a_point = good.clone();
    not_a_point[1..33].fill(0xff);
    let mut unknown_type = good.clone();
    unknown_type[0] = 3;
    let bad_len = encode_deposit(&k.id(), &vec![1u8; 2048 + 48]);
    let fetch = h.fetch_request(&k, 0);

    for req in [
        &identity_half[..],
        &not_a_point,
        &unknown_type,
        &bad_len,
        &good[..good.len() - 1],
        &[],
        &[1],
        &fetch[..140],
    ] {
        assert!(send(h.addr, req).await.is_empty());
    }
    // Framing errors: oversized length, truncated frame, no length at all.
    assert!(send_raw(h.addr, &u32::MAX.to_le_bytes()).await.is_empty());
    let mut truncated = 100u32.to_le_bytes().to_vec();
    truncated.extend_from_slice(&[1; 10]);
    assert!(send_raw(h.addr, &truncated).await.is_empty());
    assert!(send_raw(h.addr, &[1, 0]).await.is_empty());

    assert!(
        h.fetch(&k, 0).await.unwrap().is_empty(),
        "nothing was stored"
    );
    let m = h.server.metrics().snapshot();
    assert_eq!(m.deposits_stored, 0);
    assert!(m.deposits_dropped >= 6 && m.fetches_dropped >= 1);
}

/// Spec: § Mailbox Servers (L328): `time` must be within an hour of the
/// server clock; an old request cannot be replayed hours later.
#[tokio::test]
async fn time_window() {
    let mut h = start(|_| {}).await;
    let k = key(1);
    let now = h.hours();
    for (time, ok) in [
        (now - 2, false),
        (now - 1, true),
        (now, true),
        (now + 1, true),
        (now + 2, false),
    ] {
        let req = FetchRequest::sign(&k, 0, time, &SERVER_ID, &mut h.rng).unwrap();
        assert_eq!(
            decode(&send(h.addr, &req).await).is_some(),
            ok,
            "time {time}"
        );
    }
    let req = h.fetch_request(&k, 0);
    h.clock.advance(2 * 3600);
    assert!(send(h.addr, &req).await.is_empty());
}

/// Spec: § Mailbox Servers (L320–322, L328): a bad signature, a signature for
/// another server, or an altered signed field is dropped.
#[tokio::test]
async fn bad_signature_dropped() {
    let mut h = start(|_| {}).await;
    let k = key(1);
    h.deposit(&k, &envelope(2048, 1)).await;
    let good = h.fetch_request(&k, 0);
    for i in [100, 140, 65, 73] {
        let mut bad = good;
        bad[i] ^= 1;
        assert!(send(h.addr, &bad).await.is_empty(), "byte {i}");
    }
    let other_server = FetchRequest::sign(&k, 0, h.hours(), &[0x11; 32], &mut h.rng).unwrap();
    assert!(send(h.addr, &other_server).await.is_empty());
    // Another mailbox's key cannot fetch this one: swap in k's ID.
    let mut wrong_key = FetchRequest::sign(&key(2), 0, h.hours(), &SERVER_ID, &mut h.rng).unwrap();
    wrong_key[1..65].copy_from_slice(k.id().as_bytes());
    assert!(send(h.addr, &wrong_key).await.is_empty());
    assert_eq!(tags(&decode(&send(h.addr, &good).await).unwrap()), [1]);
}

/// Spec: § Mailbox Servers (L329–330): an unknown mailbox and an emptied one
/// give byte-identical responses.
#[tokio::test]
async fn empty_equals_unknown() {
    let mut h = start(|c| {
        c.retention.delete_on_fetch = true;
        c.retention.min_age_before_delete_hours = 0;
    })
    .await;
    let used = key(1);
    let never = key(2);
    h.deposit(&used, &envelope(2048, 1)).await;
    let seq = only_seq(&mut h, &used).await;
    let _ = h.fetch(&used, seq).await.unwrap(); // deletes it
    let req_used = h.fetch_request(&used, 0);
    let req_never = h.fetch_request(&never, 0);
    let a = send(h.addr, &req_used).await;
    let b = send(h.addr, &req_never).await;
    assert_eq!(a, b);
    assert_eq!(a, 0u32.to_le_bytes());

    // With deletion off, a cursor past the end looks the same too.
    let mut h = start(|_| {}).await;
    h.deposit(&used, &envelope(2048, 1)).await;
    let seq = only_seq(&mut h, &used).await;
    let past = h.fetch_request(&used, seq);
    let unknown = h.fetch_request(&never, seq);
    assert_eq!(send(h.addr, &past).await, send(h.addr, &unknown).await);
}

/// Spec: § Mailbox Servers (L316–318): Envelopes expire after the retention
/// period; deletion on fetch is off by default and, when on, waits for the
/// minimum age.
#[tokio::test]
async fn retention() {
    // Expiry.
    let mut h = start(|c| c.retention.max_age_hours = 2).await;
    let k = key(1);
    h.deposit(&k, &envelope(2048, 1)).await;
    h.clock.advance(3600);
    h.deposit(&k, &envelope(2048, 2)).await;
    h.clock.advance(3600 + 1);
    h.server.purge_expired().await;
    assert_eq!(tags(&h.fetch(&k, 0).await.unwrap()), [2]);
    assert_eq!(h.server.metrics().snapshot().envelopes_expired, 1);

    // Default: acknowledging never deletes.
    let mut h = start(|_| {}).await;
    h.deposit(&k, &envelope(2048, 1)).await;
    let seq = only_seq(&mut h, &k).await;
    h.clock.advance(30 * 24 * 3600);
    let _ = h.fetch(&k, seq).await.unwrap();
    assert_eq!(tags(&h.fetch(&k, 0).await.unwrap()), [1]);

    // Opt-in deletion respects the 7-day default minimum age.
    let mut h = start(|c| c.retention.delete_on_fetch = true).await;
    h.deposit(&k, &envelope(2048, 1)).await;
    let seq = only_seq(&mut h, &k).await;
    let _ = h.fetch(&k, seq).await.unwrap();
    assert_eq!(
        tags(&h.fetch(&k, 0).await.unwrap()),
        [1],
        "too young to delete"
    );
    h.clock.advance(7 * 24 * 3600);
    let _ = h.fetch(&k, seq).await.unwrap();
    assert!(h.fetch(&k, 0).await.unwrap().is_empty());
    assert_eq!(h.server.metrics().snapshot().envelopes_deleted, 1);
}

/// Spec: § Open issues (L450–451), § Privacy Implications (L138–139):
/// per-mailbox deposit quota and capacity; excess Deposits are dropped silently.
#[tokio::test]
async fn quota_and_capacity() {
    let mut h = start(|c| {
        c.limits.deposit_quota = 2;
        c.limits.deposit_quota_window_secs = 3600;
        c.limits.max_envelopes_per_mailbox = 3;
    })
    .await;
    let k = key(1);
    for i in 0..3 {
        h.deposit(&k, &envelope(2048, i)).await;
    }
    assert_eq!(tags(&h.fetch(&k, 0).await.unwrap()), [0, 1]);
    // Another mailbox is unaffected.
    h.deposit(&key(2), &envelope(2048, 0)).await;
    assert_eq!(tags(&h.fetch(&key(2), 0).await.unwrap()), [0]);
    // Next window: one more fits, then the mailbox is full.
    h.clock.advance(3600);
    h.deposit(&k, &envelope(2048, 7)).await;
    h.deposit(&k, &envelope(2048, 8)).await;
    assert_eq!(tags(&h.fetch(&k, 0).await.unwrap()), [0, 1, 7]);
    assert_eq!(h.server.metrics().snapshot().deposits_dropped, 2);
}

/// Spec: Appendix A, Tor (L497–498); § Privacy Implications (L138–139): a
/// connection that sends nothing is closed after the I/O timeout.
#[tokio::test]
async fn idle_connection_times_out() {
    let h = start(|c| c.limits.io_timeout_secs = 1).await;
    let mut s = TcpStream::connect(h.addr).await.unwrap();
    let mut buf = Vec::new();
    let read =
        tokio::time::timeout(std::time::Duration::from_secs(5), s.read_to_end(&mut buf)).await;
    assert!(matches!(read, Ok(Ok(0))));
}
