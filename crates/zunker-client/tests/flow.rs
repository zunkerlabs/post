//! Client flow against one in-process Mailbox Server: first contact, the
//! initiator's wait for a reply, Pairwise Mailboxes across an epoch boundary,
//! cursors and replay protection.
//!
//! Uses the loopback test transport; the server is the real `zunker-server`.

use std::collections::HashMap;
use std::sync::Arc;

use orchard::keys::{FullViewingKey, Scope, SpendingKey};
use tokio::net::TcpListener;
use zunker_client::address::{text, unified_address};
use zunker_client::client::hours;
use zunker_client::state::Role;
use zunker_client::{
    Account, Client, ClientError, MailboxRef, OnionAddr, ServerEntry, ServerList, StateFile,
    Transport,
};
use zunker_core::envelope::payload_type;
use zunker_core::mailbox::EPOCH_HOURS;
use zunker_server::{Config, CoreVerifier, ManualClock, Server, SqliteStore};

const ONION: &str = "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion:7878";
const SERVER_ID: [u8; 32] = [0x42; 32];
/// Two hours into an epoch, in seconds. Spec: § Mailboxes (L277).
const T0: u64 = (2900 * EPOCH_HOURS as u64 + 2) * 3600;

/// A deterministic account `n` and its Unified Address. Spec: none (fixture).
fn account(n: u8) -> (Account, String) {
    let sk = (0u8..=255)
        .find_map(|i| {
            SpendingKey::from_bytes([n, i, 0x77, 0x11].repeat(8).try_into().unwrap()).into_option()
        })
        .unwrap();
    let fvk = FullViewingKey::from(&sk);
    let ua = unified_address(fvk.address_at(0u32, Scope::External));
    (Account::new(fvk.to_ivk(Scope::External), vec![0]), ua)
}

/// Starts a server on loopback with a manual clock. Spec: § Mailbox Servers (L307–330).
async fn server() -> (std::net::SocketAddr, Arc<ManualClock>) {
    let config = Config::from_toml(&format!(
        "listen = \"127.0.0.1:0\"\nserver_id = \"{}\"\ndatabase = \":memory:\"\n",
        hex::encode(SERVER_ID)
    ))
    .unwrap();
    let clock = Arc::new(ManualClock::new(T0));
    let server = Arc::new(Server::new(
        config,
        Arc::new(SqliteStore::open_in_memory().unwrap()),
        Arc::new(CoreVerifier),
        clock.clone(),
    ));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(server.serve(listener));
    (addr, clock)
}

/// A client with its own state file. Spec: none (fixture).
fn client(dir: &std::path::Path, name: &str, addr: std::net::SocketAddr) -> Client {
    let onion: OnionAddr = ONION.parse().unwrap();
    let transport = Transport::insecure_loopback(HashMap::from([(onion.clone(), addr)])).unwrap();
    let servers = ServerList::new(vec![ServerEntry {
        server_id: SERVER_ID,
        onion,
    }])
    .unwrap();
    Client::new(transport, servers, StateFile::new(dir.join(name))).unwrap()
}

/// A fresh temporary directory. Spec: none (fixture).
fn tempdir(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("zunker-flow-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Spec: § Conversations (L287–301), § Envelopes (L243), § Wallet behaviour (L374–376).
#[tokio::test]
async fn first_contact_reply_and_epochs() {
    let dir = tempdir("flow");
    let (addr, clock) = server().await;
    let (a_acct, _) = account(1);
    let (b_acct, b_ua) = account(2);
    let mut a = client(&dir, "a.json", addr);
    let mut b = client(&dir, "b.json", addr);
    let mut now = T0;

    // A starts a Conversation; it may not send again before a reply.
    let a_conv = a
        .deposit_at(&b_ua, &text("hi B", hours(now)), now)
        .await
        .unwrap();
    assert!(matches!(
        a.reply_at(&a_conv, &text("again", hours(now)), now).await,
        Err(ClientError::AwaitingReply)
    ));

    // B fetches its Contact Mailbox and gets the first Envelope.
    let got = b.fetch_at(&b_acct, now).await.unwrap();
    assert!(got.failed.is_empty(), "{:?}", got.failed);
    assert_eq!(got.received.len(), 1);
    let first = &got.received[0];
    assert_eq!(first.mailbox, MailboxRef::Contact(0));
    assert_eq!(first.message.payload_type, payload_type::TEXT);
    assert_eq!(first.message.payload, b"hi B");
    let b_conv = first.conversation.clone();
    assert_eq!(b.state().conversations[&b_conv].role, Role::Responder);
    // The responder fetches nothing in the Conversation until it sends.
    assert_eq!(b.active_mailboxes(&b_acct, now), [MailboxRef::Contact(0)]);

    // The cursor moved, so a second fetch returns nothing.
    assert!(b.fetch_at(&b_acct, now).await.unwrap().received.is_empty());
    assert!(b.state().contacts[&0] > 0);

    // With the cursor reset (as after losing it), replay protection still
    // stops the same Envelope being delivered twice.
    {
        let path = dir.join("b.json");
        let mut json: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        json["contacts"] = serde_json::json!({});
        std::fs::write(&path, serde_json::to_vec(&json).unwrap()).unwrap();
        let mut b2 = client(&dir, "b.json", addr);
        assert!(b2.fetch_at(&b_acct, now).await.unwrap().received.is_empty());
        b = b2;
    }

    // B replies; that starts its fetching of A's Pairwise Mailboxes.
    b.reply_at(&b_conv, &text("hello A", hours(now)), now)
        .await
        .unwrap();
    assert_eq!(b.active_mailboxes(&b_acct, now).len(), 2);

    // A gets the reply from the Pairwise Mailbox, and may now send again.
    let got = a.fetch_at(&a_acct, now).await.unwrap();
    assert_eq!(got.received.len(), 1);
    assert!(matches!(
        got.received[0].mailbox,
        MailboxRef::Pairwise { .. }
    ));
    assert_eq!(got.received[0].conversation, a_conv);
    assert_eq!(got.received[0].message.payload, b"hello A");
    assert!(a.state().conversations[&a_conv].received_reply);
    a.reply_at(&a_conv, &text("second", hours(now)), now)
        .await
        .unwrap();
    let got = b.fetch_at(&b_acct, now).await.unwrap();
    assert_eq!(got.received.len(), 1);
    assert_eq!(got.received[0].message.payload, b"second");

    // Next epoch: B sends a late message in the old epoch's last hour and
    // one in the new epoch; A still fetches the ended epoch.
    let epoch_end = (T0 / 3600 / EPOCH_HOURS as u64 + 1) * EPOCH_HOURS as u64 * 3600;
    let late = epoch_end - 600;
    clock.advance(late - now);
    now = late;
    b.reply_at(&b_conv, &text("late", hours(now)), now)
        .await
        .unwrap();
    clock.advance(epoch_end + 3600 - now);
    now = epoch_end + 3600;
    b.reply_at(&b_conv, &text("new epoch", hours(now)), now)
        .await
        .unwrap();
    let a_mailboxes = a.active_mailboxes(&a_acct, now);
    assert_eq!(a_mailboxes.len(), 3, "contact + two epochs");
    let mut texts: Vec<Vec<u8>> = a
        .fetch_at(&a_acct, now)
        .await
        .unwrap()
        .received
        .into_iter()
        .map(|r| r.message.payload.clone())
        .collect();
    texts.sort();
    assert_eq!(texts, [b"late".to_vec(), b"new epoch".to_vec()]);

    // 24 hours after the old epoch ended, one more fetch retires it.
    clock.advance(epoch_end + 24 * 3600 - now);
    now = epoch_end + 24 * 3600;
    a.fetch_at(&a_acct, now).await.unwrap();
    assert_eq!(
        a.active_mailboxes(&a_acct, now).len(),
        2,
        "contact + current epoch"
    );

    std::fs::remove_dir_all(&dir).unwrap();
}

/// A server that is not reachable is reported per mailbox and does not
/// advance cursors. Spec: § Wallet behaviour (L374–376).
#[tokio::test]
async fn unreachable_server_is_reported() {
    let dir = tempdir("down");
    let unused = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = unused.local_addr().unwrap();
    drop(unused);
    let (acct, _) = account(3);
    let mut c = client(&dir, "c.json", addr);
    let out = c.fetch_at(&acct, T0).await.unwrap();
    assert!(out.received.is_empty());
    assert_eq!(out.failed.len(), 1);
    assert!(c.state().contacts.is_empty());
    std::fs::remove_dir_all(&dir).unwrap();
}
