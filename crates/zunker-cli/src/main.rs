//! `zunker-cli`: command-line entry point for Zunker Post: run a Mailbox
//! Server, or send and fetch messages with a testnet account.
//!
//! Spec: `spec/zip-draft-1435.md` § Mailbox Servers (L307–330), § Conversations
//! (L287–305), § Routing (L332–350).

#![forbid(unsafe_code)]

mod keys;
mod wallet;

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use clap::{Parser, Subcommand};
use tokio::net::TcpListener;
use zunker_server::{Config, CoreVerifier, Server, SqliteStore, Store, SystemClock};

/// How often expired Envelopes are purged.
const PURGE_INTERVAL: Duration = Duration::from_secs(600);
/// How often aggregate counters are logged.
const METRICS_INTERVAL: Duration = Duration::from_secs(60);

#[derive(Parser)]
#[command(
    name = "zunker-cli",
    version,
    about = "Zunker Post: Zcash wallet-to-wallet messaging"
)]
struct Cli {
    /// Where keys, state and Tor data are kept. Default: ~/.zunker-post.
    #[arg(long, global = true)]
    data_dir: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run a Mailbox Server (plain TCP; put it behind a Tor onion service).
    Serve {
        /// Path to the server's TOML config.
        #[arg(long)]
        config: PathBuf,
    },
    /// Generate a testnet Orchard account and print its Unified Address.
    Keygen,
    /// Print the account's Unified Addresses.
    Address,
    /// Send a payment request and/or a text to a Unified Address (over Tor).
    Send {
        /// Recipient testnet Unified Address with an Orchard receiver.
        #[arg(long)]
        to: String,
        #[command(flatten)]
        payload: wallet::Payload,
        #[command(flatten)]
        net: wallet::NetArgs,
    },
    /// Reply in a Conversation (over Tor).
    Reply {
        /// Conversation id, as printed by `fetch` or `send`.
        #[arg(long)]
        conversation: String,
        #[command(flatten)]
        payload: wallet::Payload,
        #[command(flatten)]
        net: wallet::NetArgs,
    },
    /// Fetch and print received messages and payment requests (over Tor).
    Fetch {
        /// Keep running, fetching each mailbox on its own random schedule.
        #[arg(long)]
        watch: bool,
        /// Mean seconds between fetches of one mailbox with --watch.
        #[arg(long, default_value_t = 900)]
        mean_interval_secs: u64,
        #[command(flatten)]
        net: wallet::NetArgs,
    },
}

/// `~/.zunker-post`, or `--data-dir`. Spec: none (storage).
fn data_dir(arg: Option<PathBuf>) -> Result<PathBuf, String> {
    arg.or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".zunker-post")))
        .ok_or_else(|| "set --data-dir (HOME is not set)".to_owned())
}

/// Runs a messaging command. Spec: § Conversations (L287–305).
async fn messaging(
    dir: Result<PathBuf, String>,
    command: Command,
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = dir?;
    match command {
        Command::Serve { .. } => unreachable!("handled in main"),
        Command::Keygen => wallet::keygen(&dir)?,
        Command::Address => wallet::address(&dir)?,
        Command::Send { to, payload, net } => wallet::send(&dir, &net, &to, &payload).await?,
        Command::Reply {
            conversation,
            payload,
            net,
        } => wallet::reply(&dir, &net, &conversation, &payload).await?,
        Command::Fetch {
            watch,
            mean_interval_secs,
            net,
        } => wallet::fetch(&dir, &net, watch, Duration::from_secs(mean_interval_secs)).await?,
    }
    Ok(())
}

/// Parses arguments and runs the chosen command. Spec: § Mailbox Servers (L307–330).
fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_target(false)
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stdout()))
        .init();
    let cli = Cli::parse();
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            tracing::error!("cannot start runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    let result = match cli.command {
        Command::Serve { config } => runtime.block_on(serve(&config)),
        command => runtime.block_on(messaging(data_dir(cli.data_dir), command)),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!("{e}");
            ExitCode::FAILURE
        }
    }
}

/// Loads the config, opens the store, and serves until Ctrl-C. Logs only
/// aggregate counters: never Mailbox IDs, Envelopes or peer addresses.
///
/// Spec: § Mailbox Servers (L307–330), § Privacy Implications (L112–118).
async fn serve(config_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::load(config_path)?;
    let store: Arc<dyn Store> = if config.database.as_os_str() == ":memory:" {
        Arc::new(SqliteStore::open_in_memory()?)
    } else {
        Arc::new(SqliteStore::open(&config.database)?)
    };
    let listener = TcpListener::bind(config.listen).await?;
    tracing::info!(
        listen = %listener.local_addr()?,
        delete_on_fetch = config.retention.delete_on_fetch,
        "mailbox server started"
    );
    let server = Arc::new(Server::new(
        config,
        store,
        Arc::new(CoreVerifier),
        Arc::new(SystemClock),
    ));

    let maintenance = {
        let server = server.clone();
        tokio::spawn(async move {
            let mut purge = tokio::time::interval(PURGE_INTERVAL);
            let mut report = tokio::time::interval(METRICS_INTERVAL);
            loop {
                tokio::select! {
                    _ = purge.tick() => server.purge_expired().await,
                    _ = report.tick() => {
                        let m = server.metrics().snapshot();
                        tracing::info!(
                            connections = m.connections,
                            deposits_stored = m.deposits_stored,
                            deposits_dropped = m.deposits_dropped,
                            fetches_served = m.fetches_served,
                            fetches_dropped = m.fetches_dropped,
                            envelopes_served = m.envelopes_served,
                            envelopes_deleted = m.envelopes_deleted,
                            envelopes_expired = m.envelopes_expired,
                            storage_errors = m.storage_errors,
                            "counters"
                        );
                    }
                }
            }
        })
    };

    let result = tokio::select! {
        r = server.clone().serve(listener) => r.map_err(Into::into),
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("shutting down");
            Ok(())
        }
    };
    maintenance.abort();
    result
}
