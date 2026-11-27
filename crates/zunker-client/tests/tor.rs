//! End-to-end over the real Tor network. Ignored by default: it needs a
//! Mailbox Server behind an onion service (for example `deploy/docker-compose.yml`)
//! and network access. Run with:
//!
//! ```sh
//! ZUNKER_TOR_ONION=<56 chars>.onion:7878 \
//! ZUNKER_TOR_SERVER_ID=<64 hex> \
//! cargo test -p zunker-client --test tor -- --ignored --nocapture
//! ```
//!
//! Set `ZUNKER_TOR_MODE=system` to use a local tor at 127.0.0.1:9050 instead
//! of arti.
//!
//! Spec: `spec/zip-draft-1435.md` § Routing (L332–350), Appendix A, Tor (L490–501).

use orchard::keys::{FullViewingKey, Scope, SpendingKey};
use zunker_client::address::{payment_request, text, unified_address};
use zunker_client::client::{hours, now_secs};
use zunker_client::transport::{ArtiDirs, DEFAULT_SOCKS_PROXY};
use zunker_client::{Account, Client, ServerEntry, ServerList, StateFile, Transport};

/// A fresh random account and its Unified Address. Spec: none (fixture).
fn account() -> (Account, String) {
    let sk = loop {
        let mut b = [0u8; 32];
        getrandom::fill(&mut b).unwrap();
        if let Some(sk) = SpendingKey::from_bytes(b).into_option() {
            break sk;
        }
    };
    let fvk = FullViewingKey::from(&sk);
    let ua = unified_address(fvk.address_at(0u32, Scope::External));
    (Account::new(fvk.to_ivk(Scope::External), vec![0]), ua)
}

/// Spec: § Routing (L348–350), § Conversations (L287–301).
#[tokio::test]
#[ignore = "needs Tor, network access, and a server behind an onion service"]
async fn payment_request_and_reply_over_tor() {
    let onion = std::env::var("ZUNKER_TOR_ONION").expect("set ZUNKER_TOR_ONION");
    let server_id: [u8; 32] =
        hex::decode(std::env::var("ZUNKER_TOR_SERVER_ID").expect("set ZUNKER_TOR_SERVER_ID"))
            .unwrap()
            .try_into()
            .unwrap();
    let dir = std::env::temp_dir().join(format!("zunker-tor-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let dirs = ArtiDirs {
        state: dir.join("arti/state"),
        cache: dir.join("arti/cache"),
    };
    let transport = match std::env::var("ZUNKER_TOR_MODE").as_deref() {
        Ok("system") => Transport::socks5(DEFAULT_SOCKS_PROXY.parse().unwrap()).await,
        _ => Transport::arti(&dirs).await,
    }
    .expect("Tor is available");
    assert!(transport.is_tor());
    let list = ServerList::new(vec![ServerEntry {
        server_id,
        onion: onion.parse().unwrap(),
    }])
    .unwrap();
    let mk = |name: &str| {
        Client::new(
            transport.clone(),
            list.clone(),
            StateFile::new(dir.join(name)),
        )
        .unwrap()
    };
    let (a_acct, a_ua) = account();
    let (b_acct, b_ua) = account();
    let (mut a, mut b) = (mk("a.json"), mk("b.json"));
    let h = hours(now_secs());

    let uri = format!("zcash:{a_ua}?amount=0.1");
    let a_conv = a
        .deposit(&b_ua, &payment_request(&uri, h).unwrap())
        .await
        .unwrap();
    eprintln!("deposited over Tor");

    let got = b.fetch(&b_acct).await.unwrap();
    assert!(got.failed.is_empty(), "{:?}", got.failed);
    assert_eq!(got.received.len(), 1);
    assert_eq!(got.received[0].message.payload, uri.as_bytes());
    let b_conv = got.received[0].conversation.clone();
    eprintln!("fetched the payment request over Tor");

    b.reply(&b_conv, &text("ok", h)).await.unwrap();
    let got = a.fetch(&a_acct).await.unwrap();
    assert!(got.failed.is_empty(), "{:?}", got.failed);
    assert_eq!(got.received.len(), 1);
    assert_eq!(got.received[0].conversation, a_conv);
    assert_eq!(got.received[0].message.payload, b"ok");
    eprintln!("reply arrived through the Pairwise Mailbox over Tor");

    std::fs::remove_dir_all(&dir).unwrap();
}
