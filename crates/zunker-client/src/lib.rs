//! Wallet-side client for Zcash Wallet-to-Wallet Messaging, following
//! [`spec/zip-draft-1435.md`](../../spec/zip-draft-1435.md).
//!
//! - [`transport`]: requests to Mailbox Servers over Tor, one circuit per
//!   request (§ Routing).
//! - [`server_list`]: the provisional Server List file.
//! - [`address`]: Unified Addresses, account keys and payloads.
//! - [`client`]: deposit, reply and fetch (§ Conversations, § Wallet behaviour).
//! - [`state`]: cursors, Conversations and processed `ephemeralKey`s, on disk.
//! - [`schedule`]: a randomized fetch timer per mailbox.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod address;
pub mod client;
pub mod schedule;
pub mod server_list;
pub mod state;
pub mod transport;

pub use address::{orchard_receiver, Account};
pub use client::{Client, ClientError, FetchOutcome, Received};
pub use schedule::{MailboxRef, Schedule};
pub use server_list::{ServerEntry, ServerList};
pub use state::StateFile;
pub use transport::{OnionAddr, Transport, TransportError};
