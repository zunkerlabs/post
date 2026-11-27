//! Mailbox Server for Zcash Wallet-to-Wallet Messaging, following
//! § Mailbox Servers of [`spec/zip-draft-1435.md`](../../spec/zip-draft-1435.md).
//!
//! Plain TCP for now, with the length-prefixed framing sketched for Tor in the
//! draft's Appendix A (TBD). The server logs no Mailbox IDs, Envelope contents
//! or peer addresses, only aggregate [`metrics`].

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod clock;
pub mod config;
pub mod metrics;
pub mod server;
pub mod store;
pub mod verify;

pub use clock::{Clock, ManualClock, SystemClock};
pub use config::Config;
pub use server::Server;
pub use store::{SqliteStore, Store};
pub use verify::{CoreVerifier, FetchVerifier};

/// Fixtures shared by unit tests.
#[cfg(test)]
pub(crate) mod test_support {
    use group::{Group, GroupEncoding};
    use pasta_curves::pallas;
    use zunker_core::mailbox::MailboxId;

    /// A valid Mailbox ID distinct for each `n`. Spec: § Mailboxes (L262–264).
    pub(crate) fn mailbox_id(n: u64) -> MailboxId {
        let g = pallas::Point::generator() * pallas::Scalar::from(n + 1);
        let p = g.double();
        let mut id = [0u8; 64];
        id[..32].copy_from_slice(&g.to_bytes());
        id[32..].copy_from_slice(&p.to_bytes());
        MailboxId::from_bytes(&id).unwrap()
    }

    /// A smallest-size-class Envelope filled with `tag`. Spec: § Envelopes (L194–198).
    pub(crate) fn envelope(tag: u8) -> Vec<u8> {
        let mut e = vec![tag; 2048 + 49];
        e[0] = 1;
        e
    }
}
