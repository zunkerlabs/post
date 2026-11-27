//! Fetch authorization, behind a trait so the transport does not depend on how
//! signatures are checked.
//!
//! Spec: `spec/zip-draft-1435.md` § Mailbox Servers (L320–328).

use zunker_core::sig::FetchRequest;

/// Checks a Fetch request.
///
/// Spec: § Mailbox Servers (L320–328).
pub trait FetchVerifier: Send + Sync + 'static {
    /// Returns the parsed request if it is well formed, addressed to
    /// `server_id`, has `time` within an hour of `now_hours`, and carries a
    /// valid `sig`; otherwise `None`, and the server drops it without replying.
    ///
    /// Spec: § Mailbox Servers (L312, L320–328).
    fn verify(&self, server_id: &[u8; 32], request: &[u8], now_hours: u32) -> Option<FetchRequest>;
}

/// The [`FetchVerifier`] from `zunker-core`: RedPallas with the mailbox's `G`.
///
/// Spec: § Mailbox Servers (L320–328), protocol spec §5.4.7.
#[derive(Clone, Copy, Debug, Default)]
pub struct CoreVerifier;

impl FetchVerifier for CoreVerifier {
    /// Spec: § Mailbox Servers (L320–328).
    fn verify(&self, server_id: &[u8; 32], request: &[u8], now_hours: u32) -> Option<FetchRequest> {
        FetchRequest::verify(server_id, request, now_hours)
    }
}
