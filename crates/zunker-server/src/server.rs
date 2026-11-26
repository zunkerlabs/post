//! The Mailbox Server: accepts connections, handles one request each.
//!
//! Spec: `spec/zip-draft-1435.md` § Mailbox Servers (L307–330); framing per
//! Appendix A, Tor (L497–498), TBD.

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;

use crate::clock::Clock;
use crate::config::Config;
use crate::metrics::{Counter, Metrics};
use crate::store::{DepositLimits, DepositOutcome, Store};
use crate::verify::FetchVerifier;
use crate::wire::{
    parse_request, push_fetch_item, read_frame, write_frame, Request, MAX_REQUEST_LEN,
};

/// A Mailbox Server. Cheap to share: wrap it in an [`Arc`].
///
/// Spec: § Mailbox Servers (L307–330).
pub struct Server {
    config: Config,
    store: Arc<dyn Store>,
    verifier: Arc<dyn FetchVerifier>,
    clock: Arc<dyn Clock>,
    metrics: Metrics,
}

impl Server {
    /// Builds a server. Spec: § Mailbox Servers (L307–330).
    pub fn new(
        config: Config,
        store: Arc<dyn Store>,
        verifier: Arc<dyn FetchVerifier>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Server {
            config,
            store,
            verifier,
            clock,
            metrics: Metrics::default(),
        }
    }

    /// The server's counters. Spec: § Privacy Implications (L112–118).
    pub fn metrics(&self) -> &Metrics {
        &self.metrics
    }

    /// Accepts connections until the listener fails. Peer addresses are
    /// discarded on accept and never stored or logged.
    ///
    /// Spec: § Mailbox Servers (L307–330), § Privacy Implications (L112).
    pub async fn serve(self: Arc<Self>, listener: TcpListener) -> std::io::Result<()> {
        let slots = Arc::new(Semaphore::new(self.config.limits.max_connections));
        loop {
            let permit = slots
                .clone()
                .acquire_owned()
                .await
                .expect("semaphore never closed");
            let (stream, _peer) = listener.accept().await?;
            self.metrics.add(Counter::Connections, 1);
            let server = self.clone();
            tokio::spawn(async move {
                server.handle_connection(stream).await;
                drop(permit);
            });
        }
    }

    /// Reads one request, answers it if it is a valid Fetch, then closes. Any
    /// failure (timeout, oversized or truncated frame, malformed request, bad
    /// signature) closes the connection without a reply.
    ///
    /// Spec: § Mailbox Servers (L311–312, L326–328); Appendix A, Tor (L497–498).
    pub async fn handle_connection<S: AsyncRead + AsyncWrite + Unpin>(&self, mut stream: S) {
        let timeout = Duration::from_secs(self.config.limits.io_timeout_secs);
        let _ = tokio::time::timeout(timeout, async {
            let Ok(Some(frame)) = read_frame(&mut stream, MAX_REQUEST_LEN).await else {
                return;
            };
            if let Some(body) = self.process(&frame).await {
                let _ = write_frame(&mut stream, &body).await;
            }
        })
        .await;
        let _ = stream.shutdown().await;
    }

    /// Handles one request frame. Returns the response body for a valid Fetch,
    /// `None` for everything else (Deposits never get a response; malformed or
    /// unauthorized requests are dropped).
    ///
    /// Spec: § Mailbox Servers (L309–330).
    pub async fn process(&self, frame: &[u8]) -> Option<Vec<u8>> {
        match parse_request(frame) {
            Some(Request::Deposit {
                mailbox_id,
                envelope,
            }) => {
                self.deposit(mailbox_id, envelope.to_vec()).await;
                None
            }
            Some(Request::Fetch(bytes)) => self.fetch(bytes).await,
            None => {
                // Without a valid type byte we cannot tell which kind it was.
                let counter = if frame.first() == Some(&zunker_core::sig::FETCH) {
                    Counter::FetchesDropped
                } else {
                    Counter::DepositsDropped
                };
                self.metrics.add(counter, 1);
                None
            }
        }
    }

    /// Stores a validated Deposit, subject to quota and capacity.
    /// Spec: § Mailbox Servers (L311, L314–315), § Open issues (L450–451).
    async fn deposit(&self, mailbox_id: zunker_core::mailbox::MailboxId, envelope: Vec<u8>) {
        let store = self.store.clone();
        let now = self.clock.now_secs();
        let l = &self.config.limits;
        let limits = DepositLimits {
            max_envelopes: l.max_envelopes_per_mailbox,
            quota: l.deposit_quota,
            quota_window_secs: l.deposit_quota_window_secs,
        };
        let result = tokio::task::spawn_blocking(move || {
            store.deposit(&mailbox_id, &envelope, now, &limits)
        })
        .await;
        match result {
            Ok(Ok(DepositOutcome::Stored(_))) => self.metrics.add(Counter::DepositsStored, 1),
            Ok(Ok(DepositOutcome::OverQuota | DepositOutcome::Full)) => {
                self.metrics.add(Counter::DepositsDropped, 1)
            }
            _ => self.metrics.add(Counter::StorageErrors, 1),
        }
    }

    /// Verifies a Fetch, optionally deletes acknowledged Envelopes, and returns
    /// the `(seq, len, Envelope)` triples with `seq > after` that fit the byte
    /// budget. An unknown mailbox and an empty one give the same empty body.
    ///
    /// Spec: § Mailbox Servers (L312, L315–317, L320–330).
    async fn fetch(&self, bytes: &[u8]) -> Option<Vec<u8>> {
        let now = self.clock.now_secs();
        let Some(req) = self
            .verifier
            .verify(&self.config.server_id, bytes, self.clock.now_hours())
        else {
            self.metrics.add(Counter::FetchesDropped, 1);
            return None;
        };

        let store = self.store.clone();
        let retention = self.config.retention.clone();
        let budget = self.config.limits.fetch_byte_budget;
        let result = tokio::task::spawn_blocking(move || {
            let mut deleted = 0;
            if retention.delete_on_fetch && req.after > 0 {
                let cutoff =
                    now.saturating_sub(retention.min_age_before_delete_hours.saturating_mul(3600));
                deleted = store.delete_acknowledged(&req.mailbox_id, req.after, cutoff)?;
            }
            store
                .fetch(&req.mailbox_id, req.after, budget)
                .map(|items| (items, deleted))
        })
        .await;

        let Ok(Ok((items, deleted))) = result else {
            // Answering differently on a storage error would be observable;
            // drop it like any other failure.
            self.metrics.add(Counter::StorageErrors, 1);
            return None;
        };
        self.metrics.add(Counter::EnvelopesDeleted, deleted);
        self.metrics
            .add(Counter::EnvelopesServed, items.len() as u64);
        self.metrics.add(Counter::FetchesServed, 1);
        let mut body = Vec::with_capacity(items.iter().map(|i| 12 + i.envelope.len()).sum());
        for item in &items {
            push_fetch_item(&mut body, item.seq, &item.envelope);
        }
        Some(body)
    }

    /// Discards Envelopes older than the retention period. Call periodically.
    /// Spec: § Mailbox Servers (L317–318).
    pub async fn purge_expired(&self) {
        let store = self.store.clone();
        let max_age = self.config.retention.max_age_hours.saturating_mul(3600);
        let cutoff = self.clock.now_secs().saturating_sub(max_age);
        match tokio::task::spawn_blocking(move || store.purge(cutoff)).await {
            Ok(Ok(n)) => self.metrics.add(Counter::EnvelopesExpired, n),
            _ => self.metrics.add(Counter::StorageErrors, 1),
        }
    }
}
