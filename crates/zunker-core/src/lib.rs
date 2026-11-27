//! Core cryptography for Zcash Wallet-to-Wallet Messaging, following the ZIP
//! draft in [`spec/zip-draft-1435.md`](../../spec/zip-draft-1435.md)
//! (zcash/zips PR #1435).
//!
//! Every function cites the section and lines of that file it implements.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod encoding;
pub mod envelope;
pub mod mailbox;
pub mod receiver;
