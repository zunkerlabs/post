//! Wallet-side client for Zcash Wallet-to-Wallet Messaging, following
//! [`spec/zip-draft-1435.md`](../../spec/zip-draft-1435.md).
//!
//! [`transport`] carries requests to Mailbox Servers over Tor, one circuit per
//! request (§ Routing).

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod transport;

pub use transport::{OnionAddr, Transport, TransportError};
