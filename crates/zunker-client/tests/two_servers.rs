//! Integration test: two in-process Mailbox Servers and a two-entry Server
//! List. A sends a payment request to B's Unified Address; B fetches and
//! decrypts it; B replies; the reply reaches A through the Pairwise Mailbox.
//! Every Deposit is checked to have gone to the server the Server List
//! selects for its mailbox, and nowhere else.
//!
//! Spec: `spec/zip-draft-1435.md` § Mailboxes (L262–283), § Conversations
//! (L287–301), § Mailbox Servers (L307–330), § Payloads (L253).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use orchard::keys::{FullViewingKey, Scope, SpendingKey};
use tokio::net::TcpListener;
use zunker_client::address::{payment_request, text, unified_address};
use zunker_client::client::hours;
use zunker_client::state::Role;
use zunker_client::{
    orchard_receiver, Account, Client, MailboxRef, OnionAddr, ServerEntry, ServerList, StateFile,
    Transport,
};
use zunker_core::envelope::{payload_type, Conversation, Direction};
use zunker_core::mailbox::{contact_mailbox_id, epoch, pairwise_mailbox_key, MailboxId};
use zunker_core::receiver::Receiver;
use zunker_server::{Config, CoreVerifier, ManualClock, Server, SqliteStore};

const ONIONS: [&str; 2] = [
    "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion:7878",
    "vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd.onion:7878",
];
const SERVER_IDS: [[u8; 32]; 2] = [[0xa1; 32], [0xb2; 32]];
/// Some hours into an epoch, in seconds. Spec: § Mailboxes (L277).
const NOW: u64 = (2901 * 168 + 30) * 3600;

/// A running server. Spec: § Mailbox Servers (L307–330).
struct Running {
    addr: SocketAddr,
    server: Arc<Server>,
}

/// Starts server `i` on loopback. Spec: § Mailbox Servers (L307–330).
async fn start(i: usize) -> Running {
    let config = Config::from_toml(&format!(
        "listen = \"127.0.0.1:0\"\nserver_id = \"{}\"\ndatabase = \":memory:\"\n",
        hex::encode(SERVER_IDS[i])
    ))
    .unwrap();
    let server = Arc::new(Server::new(
        config,
        Arc::new(SqliteStore::open_in_memory().unwrap()),
        Arc::new(CoreVerifier),
        Arc::new(ManualClock::new(NOW)),
    ));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(server.clone().serve(listener));
    Running { addr, server }
}

/// The two-entry Server List. Spec: § Mailboxes (L279–280).
fn server_list() -> ServerList {
    ServerList::new(
        (0..2)
            .map(|i| ServerEntry {
                server_id: SERVER_IDS[i],
                onion: ONIONS[i].parse().unwrap(),
            })
            .collect(),
    )
    .unwrap()
}

/// A deterministic account `n` and its Unified Address. Spec: none (fixture).
fn account(n: u8) -> (Account, String) {
    let sk = (0u8..=255)
        .find_map(|i| {
            SpendingKey::from_bytes([n, i, 0x3c, 0xc3].repeat(8).try_into().unwrap()).into_option()
        })
        .unwrap();
    let fvk = FullViewingKey::from(&sk);
    let ua = unified_address(fvk.address_at(0u32, Scope::External));
    (Account::new(fvk.to_ivk(Scope::External), vec![0]), ua)
}

/// Index of the server the list selects for `id`. Spec: § Mailboxes (L281–283).
fn selected(list: &ServerList, id: &MailboxId) -> usize {
    let entry = list.server_for(id);
    SERVER_IDS
        .iter()
        .position(|s| *s == entry.server_id)
        .unwrap()
}

/// Deposits stored by each server. Spec: § Mailbox Servers (L311).
fn deposits(servers: &[Running]) -> [u64; 2] {
    [0, 1].map(|i| servers[i].server.metrics().snapshot().deposits_stored)
}

/// Spec: § Mailboxes (L262–283), § Conversations (L287–301), § Payloads (L253).
#[tokio::test]
async fn payment_request_and_reply_across_two_servers() {
    let dir = std::env::temp_dir().join(format!("zunker-two-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let servers = [start(0).await, start(1).await];
    let map: HashMap<OnionAddr, SocketAddr> = (0..2)
        .map(|i| (ONIONS[i].parse().unwrap(), servers[i].addr))
        .collect();
    let list = server_list();
    let mk = |name: &str| {
        Client::new(
            Transport::insecure_loopback(map.clone()).unwrap(),
            list.clone(),
            StateFile::new(dir.join(name)),
        )
        .unwrap()
    };
    let (a_acct, a_ua) = account(1);
    let (b_acct, b_ua) = account(2);
    let (mut a, mut b) = (mk("a.json"), mk("b.json"));
    let now_h = hours(NOW);

    // A sends B a payment request. It must land on the server selected for
    // B's Contact Mailbox.
    let uri = format!("zcash:{a_ua}?amount=1.25&message=Invoice%2042");
    let a_conv = a
        .deposit_at(&b_ua, &payment_request(&uri, now_h).unwrap(), NOW)
        .await
        .unwrap();
    let contact = contact_mailbox_id(&orchard_receiver(&b_ua).unwrap()).unwrap();
    let s_contact = selected(&list, &contact);
    let mut expected = [0u64; 2];
    expected[s_contact] += 1;
    // A Deposit returns once the server has handled it, so the count is
    // already up to date.
    assert_eq!(
        deposits(&servers),
        expected,
        "first Envelope routed by selection"
    );

    // B fetches and decrypts it.
    let got = b.fetch_at(&b_acct, NOW).await.unwrap();
    assert!(got.failed.is_empty(), "{:?}", got.failed);
    assert_eq!(got.received.len(), 1);
    let req = &got.received[0];
    assert_eq!(req.mailbox, MailboxRef::Contact(0));
    assert_eq!(req.message.payload_type, payload_type::PAYMENT_REQUEST);
    assert_eq!(req.message.payload, uri.as_bytes());
    let parsed =
        zip321::TransactionRequest::from_uri(std::str::from_utf8(&req.message.payload).unwrap())
            .unwrap();
    let payment = &parsed.payments()[&0];
    assert_eq!(payment.amount().unwrap().into_u64(), 125_000_000);
    assert_eq!(payment.message().unwrap(), "Invoice 42");
    let b_conv = req.conversation.clone();
    assert_eq!(b.state().conversations[&b_conv].role, Role::Responder);

    // B replies. The reply goes to the Pairwise Mailbox for δ = 1 and this
    // epoch, on the server selected for that mailbox.
    b.reply_at(&b_conv, &text("Paying now", now_h), NOW)
        .await
        .unwrap();
    let cs = &b.state().conversations[&b_conv];
    let conv = Conversation::from_parts(
        hex::decode(&cs.kappa).unwrap().try_into().unwrap(),
        Receiver::from_raw(&hex::decode(&cs.responder).unwrap().try_into().unwrap()).unwrap(),
    );
    let pairwise = pairwise_mailbox_key(&conv, Direction::Responder, epoch(now_h))
        .unwrap()
        .id();
    expected[selected(&list, &pairwise)] += 1;
    assert_eq!(deposits(&servers), expected, "reply routed by selection");
    // Both sides derived the same Conversation.
    assert_eq!(a.state().conversations[&a_conv].kappa, cs.kappa);

    // A fetches: the reply arrives through the Pairwise Mailbox.
    let got = a.fetch_at(&a_acct, NOW).await.unwrap();
    assert!(got.failed.is_empty(), "{:?}", got.failed);
    assert_eq!(got.received.len(), 1);
    let reply = &got.received[0];
    assert_eq!(
        reply.mailbox,
        MailboxRef::Pairwise {
            conversation: a_conv.clone(),
            epoch: epoch(now_h)
        }
    );
    assert_eq!(reply.message.payload_type, payload_type::TEXT);
    assert_eq!(reply.message.payload, b"Paying now");
    assert!(a.state().conversations[&a_conv].received_reply);

    // Nothing is delivered twice.
    assert!(a.fetch_at(&a_acct, NOW).await.unwrap().received.is_empty());
    assert!(b.fetch_at(&b_acct, NOW).await.unwrap().received.is_empty());

    std::fs::remove_dir_all(&dir).unwrap();
}

/// Mailboxes spread over both servers: with many Contact Mailboxes, each
/// server is selected for some. Spec: § Mailboxes (L281–283).
#[test]
fn selection_uses_both_servers() {
    let list = server_list();
    let mut counts = [0; 2];
    for n in 10..40 {
        let (_, ua) = account(n);
        let id = contact_mailbox_id(&orchard_receiver(&ua).unwrap()).unwrap();
        counts[selected(&list, &id)] += 1;
    }
    assert!(counts[0] > 0 && counts[1] > 0, "{counts:?}");
}
