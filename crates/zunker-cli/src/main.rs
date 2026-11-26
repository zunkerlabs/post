//! `zunker-cli`: command-line entry point for Zunker Post.
//!
//! Spec: `spec/zip-draft-1435.md` § Mailbox Servers (L307–330).

#![forbid(unsafe_code)]

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
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run a Mailbox Server (plain TCP).
    Serve {
        /// Path to the server's TOML config.
        #[arg(long)]
        config: PathBuf,
    },
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
