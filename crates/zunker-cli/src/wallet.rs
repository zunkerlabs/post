//! `keygen`, `address`, `send`, `reply` and `fetch`: messaging from the
//! command line. No chain or lightwalletd access: only keys and addresses.
//!
//! Spec: `spec/zip-draft-1435.md` § Conversations (L287–305), § Routing
//! (L348–350), § Wallet behaviour (L372–386).

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use clap::{Args, ValueEnum};
use zunker_client::address::{payment_request, text};
use zunker_client::client::{hours, now_secs};
use zunker_client::transport::{ArtiDirs, DEFAULT_SOCKS_PROXY};
use zunker_client::{Client, MailboxRef, Received, Schedule, ServerList, StateFile, Transport};
use zunker_core::envelope::{payload_type, Message};

use crate::keys;

/// Printed by every key-handling command. Spec: none (project status).
const TESTNET_WARNING: &str = "\
WARNING: TESTNET ONLY. These keys are stored unencrypted on this machine.
Never send mainnet funds to this address or reuse this seed elsewhere.";

/// How to reach Tor. Spec: § Routing (L349–350): never directly.
#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum TorMode {
    /// arti, falling back to the system tor's SOCKS port.
    Auto,
    /// arti only.
    Arti,
    /// The system tor's SOCKS port only.
    System,
}

/// Options shared by commands that talk to Mailbox Servers.
#[derive(Args, Debug)]
pub struct NetArgs {
    /// Server List JSON (provisional format). Default: servers.json in the data directory.
    #[arg(long)]
    servers: Option<PathBuf>,
    /// How to reach Tor.
    #[arg(long, value_enum, default_value_t = TorMode::Auto)]
    tor: TorMode,
    /// The system tor's SOCKS address (loopback only).
    #[arg(long, default_value = DEFAULT_SOCKS_PROXY)]
    socks: SocketAddr,
}

/// What to send: a payment request, a text, or both.
#[derive(Args, Debug)]
pub struct Payload {
    /// A ZIP 321 payment request URI.
    #[arg(long)]
    request: Option<String>,
    /// A text message.
    #[arg(long)]
    text: Option<String>,
}

impl Payload {
    /// The messages to send, payment request first. Spec: § Payloads (L248–258).
    fn messages(&self, now_hours: u32) -> Result<Vec<Message>, String> {
        let mut out = Vec::new();
        if let Some(uri) = &self.request {
            out.push(payment_request(uri, now_hours).map_err(|e| e.to_string())?);
        }
        if let Some(t) = &self.text {
            out.push(text(t, now_hours));
        }
        if out.is_empty() {
            return Err("give --request, --text, or both".into());
        }
        Ok(out)
    }
}

/// Paths inside the data directory. Spec: none (storage).
struct Paths {
    keys: PathBuf,
    state: PathBuf,
    servers: PathBuf,
    arti: ArtiDirs,
}

impl Paths {
    /// Spec: none (storage).
    fn new(dir: &Path, servers: Option<&Path>) -> Self {
        Paths {
            keys: dir.join("keys.json"),
            state: dir.join("state.json"),
            servers: servers.map_or_else(|| dir.join("servers.json"), Path::to_path_buf),
            arti: ArtiDirs {
                state: dir.join("arti").join("state"),
                cache: dir.join("arti").join("cache"),
            },
        }
    }
}

/// Creates the data directory, owner-only on Unix. Spec: none (storage).
fn ensure_dir(dir: &Path) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// `keygen`: a new testnet account; prints its Unified Address.
/// Spec: § Requirements (L142–146).
pub fn keygen(dir: &Path) -> Result<(), String> {
    ensure_dir(dir)?;
    let paths = Paths::new(dir, None);
    let k = keys::generate(&paths.keys)?;
    eprintln!("{TESTNET_WARNING}\n");
    eprintln!("Keys written to {}", paths.keys.display());
    println!("{}", k.address(0));
    Ok(())
}

/// `address`: prints the Unified Addresses whose mailboxes `fetch` checks.
/// Spec: § Mailboxes (L266–270).
pub fn address(dir: &Path) -> Result<(), String> {
    let k = keys::load(&Paths::new(dir, None).keys)?;
    eprintln!("{TESTNET_WARNING}\n");
    for &j in k.indices() {
        println!("{}", k.address(j));
    }
    Ok(())
}

/// Connects to Tor as chosen; never directly. Spec: § Routing (L349–350).
async fn transport(net: &NetArgs, arti: &ArtiDirs) -> Result<Transport, String> {
    eprintln!("Connecting to Tor...");
    let t = match net.tor {
        TorMode::Auto => Transport::tor(arti, net.socks).await,
        TorMode::Arti => Transport::arti(arti).await,
        TorMode::System => Transport::socks5(net.socks).await,
    };
    t.map_err(|e| e.to_string())
}

/// Loads the Server List and state and connects. Spec: § Mailboxes (L279–283).
async fn client(dir: &Path, net: &NetArgs) -> Result<Client, String> {
    ensure_dir(dir)?;
    let paths = Paths::new(dir, net.servers.as_deref());
    let servers = ServerList::load(&paths.servers).map_err(|e| {
        format!(
            "{e} ({}; see README, 'Server List')",
            paths.servers.display()
        )
    })?;
    let transport = transport(net, &paths.arti).await?;
    Client::new(transport, servers, StateFile::new(paths.state)).map_err(|e| e.to_string())
}

/// `send`: first Envelopes to a Unified Address, each starting its own
/// Conversation. With both `--request` and `--text`, two are sent: the
/// initiator MUST NOT send a second Envelope in a Conversation before a reply.
/// Spec: § Conversations (L289–290, L296–299).
pub async fn send(dir: &Path, net: &NetArgs, to: &str, payload: &Payload) -> Result<(), String> {
    zunker_client::orchard_receiver(to).map_err(|e| e.to_string())?;
    let messages = payload.messages(hours(now_secs()))?;
    let mut c = client(dir, net).await?;
    for m in &messages {
        let id = c.deposit(to, m).await.map_err(|e| e.to_string())?;
        println!("sent {} (conversation {id})", kind(m.payload_type));
    }
    Ok(())
}

/// `reply`: sends in an existing Conversation.
/// Spec: § Conversations (L292–299).
pub async fn reply(
    dir: &Path,
    net: &NetArgs,
    conversation: &str,
    payload: &Payload,
) -> Result<(), String> {
    let messages = payload.messages(hours(now_secs()))?;
    let mut c = client(dir, net).await?;
    for m in &messages {
        c.reply(conversation, m).await.map_err(|e| e.to_string())?;
        println!(
            "sent {} in conversation {conversation}",
            kind(m.payload_type)
        );
    }
    Ok(())
}

/// `fetch`: one pass over every mailbox, or with `watch`, each mailbox on
/// its own randomized schedule until Ctrl-C.
/// Spec: § Wallet behaviour (L374–376).
pub async fn fetch(
    dir: &Path,
    net: &NetArgs,
    watch: bool,
    mean_interval: Duration,
) -> Result<(), String> {
    let k = keys::load(&Paths::new(dir, None).keys)?;
    let account = k.account();
    let mut c = client(dir, net).await?;
    if !watch {
        let out = c.fetch(&account).await.map_err(|e| e.to_string())?;
        report(&out);
        return Ok(());
    }
    let mut schedule = Schedule::new(mean_interval);
    eprintln!("Watching; each mailbox is fetched on its own random schedule. Ctrl-C to stop.");
    loop {
        let out = c
            .fetch_due(&account, &mut schedule, now_secs())
            .await
            .map_err(|e| e.to_string())?;
        report(&out);
        let wake = schedule.next_wake().unwrap_or(now_secs() + 60);
        let wait = Duration::from_secs(wake.saturating_sub(now_secs()).clamp(1, 60));
        tokio::select! {
            _ = tokio::time::sleep(wait) => {}
            _ = tokio::signal::ctrl_c() => return Ok(()),
        }
    }
}

/// Prints received messages and fetch failures. Spec: § Wallet behaviour
/// (L381): never present a message as coming from a named party.
fn report(out: &zunker_client::FetchOutcome) {
    for r in &out.received {
        print_message(r);
    }
    for (m, why) in &out.failed {
        eprintln!("fetch failed for {}: {why}", describe(m));
    }
    if out.received.is_empty() && out.failed.is_empty() {
        eprintln!("No new messages.");
    }
}

/// Spec: § Payloads (L250–255).
fn kind(t: u16) -> &'static str {
    match t {
        payload_type::ACK => "ack",
        payload_type::TEXT => "text",
        payload_type::PAYMENT_REQUEST => "payment request",
        payload_type::PCZT => "PCZT",
        _ => "unknown payload type",
    }
}

/// Spec: § Mailboxes (L260–277).
fn describe(m: &MailboxRef) -> String {
    match m {
        MailboxRef::Contact(j) => format!("contact mailbox of address {j}"),
        MailboxRef::Pairwise {
            conversation,
            epoch,
        } => {
            format!("conversation {conversation}, epoch {epoch}")
        }
    }
}

/// Prints one message. Sender-controlled text is stripped of control
/// characters so it cannot drive the terminal.
/// Spec: § Payloads (L250–258), § Wallet behaviour (L381).
fn print_message(r: &Received) {
    let m = &r.message;
    let origin = match r.mailbox {
        MailboxRef::Contact(_) => "new conversation",
        MailboxRef::Pairwise { .. } => "reply",
    };
    println!("--- {} ({origin}) ---", kind(m.payload_type));
    println!("conversation: {}", r.conversation);
    println!("sender:       unauthenticated (envelopes do not identify their sender)");
    match m.payload_type {
        payload_type::TEXT => println!("text:         {}", clean(&m.payload)),
        payload_type::PAYMENT_REQUEST => print_payment_request(&m.payload),
        payload_type::ACK => println!("acknowledges: {}", hex::encode(&m.payload)),
        t => println!("(payload type {t} not supported; ignored)"),
    }
    println!(
        "reply with:   zunker-cli reply --conversation {} --text \"...\"",
        r.conversation
    );
}

/// Shows each payment in a ZIP 321 request. Spec: § Payloads (L253).
fn print_payment_request(payload: &[u8]) {
    let uri = clean(payload);
    match zip321::TransactionRequest::from_uri(&uri) {
        Ok(req) => {
            for p in req.payments().values() {
                println!(
                    "pay to:       {}",
                    clean(p.recipient_address().encode().as_bytes())
                );
                if let Some(a) = p.amount() {
                    println!("amount:       {} TAZ", zec(a.into_u64()));
                }
                if let Some(msg) = p.message() {
                    println!("message:      {}", clean(msg.as_bytes()));
                }
                if let Some(label) = p.label() {
                    println!("label:        {}", clean(label.as_bytes()));
                }
            }
            println!("uri:          {uri}");
        }
        Err(_) => println!("invalid payment request (not shown)"),
    }
}

/// Zatoshis as a decimal ZEC amount. Spec: none (display).
fn zec(zat: u64) -> String {
    let s = format!("{}.{:08}", zat / 100_000_000, zat % 100_000_000);
    s.trim_end_matches('0').trim_end_matches('.').to_owned()
}

/// UTF-8 with control characters (other than newline and tab) replaced, so
/// a sender cannot inject terminal escape sequences. Spec: none (display safety).
fn clean(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .chars()
        .map(|c| {
            if c.is_control() && c != '\n' && c != '\t' {
                '\u{fffd}'
            } else {
                c
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Spec: none (display safety).
    #[test]
    fn control_characters_are_removed() {
        assert_eq!(clean(b"hi\x1b[31mred\x07"), "hi\u{fffd}[31mred\u{fffd}");
        assert_eq!(clean("a\nb\tc é".as_bytes()), "a\nb\tc é");
        assert_eq!(clean(&[0xff, b'x']), "\u{fffd}x");
    }

    /// Spec: none (display).
    #[test]
    fn zec_amounts() {
        assert_eq!(zec(50_000_000), "0.5");
        assert_eq!(zec(100_000_000), "1");
        assert_eq!(zec(1), "0.00000001");
        assert_eq!(zec(0), "0");
    }

    /// At least one payload is required; both give request then text.
    /// Spec: § Payloads (L248–258).
    #[test]
    fn payload_choice() {
        let none = Payload {
            request: None,
            text: None,
        };
        assert!(none.messages(0).is_err());
        let t = Payload {
            request: None,
            text: Some("hi".into()),
        };
        assert_eq!(t.messages(0).unwrap().len(), 1);
        let bad = Payload {
            request: Some("https://x".into()),
            text: None,
        };
        assert!(bad.messages(0).is_err());
    }
}
