//! Wire format shared by Mailbox Servers and wallets: request and response
//! encoding, and length-prefixed framing.
//!
//! Spec: `spec/zip-draft-1435.md` § Mailbox Servers (L309–312) for requests and
//! responses; Appendix A, Tor (L497–498) for framing.
//!
//! **TBD:** the framing follows the Tor sketch in the draft's non-normative
//! Appendix A: one request per connection, request and response each preceded
//! by a `u32` length. The draft marks this TBD; the length is little-endian
//! here, following § Notation (L184). It will change if the draft does.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use zunker_core::envelope::SIZE_CLASSES;
use zunker_core::mailbox::MailboxId;
use zunker_core::sig::{DEPOSIT, FETCH, FETCH_LEN};

/// `version || ephemeralKey` before, and the Poly1305 tag after, the `N`-byte
/// ciphertext body. Spec: § Envelopes (L194–198).
const ENVELOPE_OVERHEAD: usize = 1 + 32 + 16;

/// Length of the largest Envelope. Spec: § Envelopes (L198).
pub const MAX_ENVELOPE_LEN: usize = ENVELOPE_OVERHEAD + SIZE_CLASSES[2];

/// `[1] || mailbox_id`. Spec: § Mailbox Servers (L311).
const DEPOSIT_HEADER_LEN: usize = 1 + 64;

/// Largest request frame the server reads: a Deposit of the largest Envelope.
/// Spec: § Mailbox Servers (L311–312).
pub const MAX_REQUEST_LEN: usize = DEPOSIT_HEADER_LEN + MAX_ENVELOPE_LEN;

/// `seq (u64) || len (u32)` before each Envelope in a Fetch response.
/// Spec: § Mailbox Servers (L312).
const FETCH_ITEM_HEADER_LEN: usize = 8 + 4;

/// Size of one Fetch response triple carrying the largest Envelope.
/// Spec: § Mailbox Servers (L312).
pub const MAX_FETCH_ITEM_LEN: usize = FETCH_ITEM_HEADER_LEN + MAX_ENVELOPE_LEN;

/// Whether `len` is the length of an Envelope in one of the three size classes.
/// Spec: § Envelopes (L194–198).
pub fn is_envelope_len(len: usize) -> bool {
    SIZE_CLASSES.iter().any(|n| len == ENVELOPE_OVERHEAD + n)
}

/// A parsed request. A Fetch is kept as raw bytes because its signature covers
/// them; it is parsed by the verifier.
///
/// Spec: § Mailbox Servers (L309–312).
#[derive(Debug, PartialEq, Eq)]
pub enum Request<'a> {
    /// `[1] || mailbox_id || Envelope`.
    Deposit {
        /// Validated Mailbox ID (both halves non-identity points).
        mailbox_id: MailboxId,
        /// Envelope bytes, of a valid size-class length.
        envelope: &'a [u8],
    },
    /// `[2] || mailbox_id || after || time || sig`, of the right length.
    Fetch(&'a [u8]),
}

/// Parses a request frame. Returns `None` for anything malformed: an unknown
/// type, a wrong length, an envelope length outside the size classes, or a
/// `mailbox_id` half that is not a non-identity Pallas point (checked here for
/// Deposits and by the verifier for Fetches).
///
/// Spec: § Mailbox Servers (L309–312, L326–328), § Envelopes (L194–198).
pub fn parse_request(frame: &[u8]) -> Option<Request<'_>> {
    match *frame.first()? {
        DEPOSIT => {
            let envelope = frame.get(DEPOSIT_HEADER_LEN..)?;
            if !is_envelope_len(envelope.len()) {
                return None;
            }
            let id: &[u8; 64] = frame[1..DEPOSIT_HEADER_LEN].try_into().ok()?;
            let mailbox_id = MailboxId::from_bytes(id)?;
            Some(Request::Deposit {
                mailbox_id,
                envelope,
            })
        }
        FETCH if frame.len() == FETCH_LEN => Some(Request::Fetch(frame)),
        _ => None,
    }
}

/// Builds a Deposit request (unframed).
/// Spec: § Mailbox Servers (L311).
pub fn encode_deposit(mailbox_id: &MailboxId, envelope: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(DEPOSIT_HEADER_LEN + envelope.len());
    out.push(DEPOSIT);
    out.extend_from_slice(mailbox_id.as_bytes());
    out.extend_from_slice(envelope);
    out
}

/// One Envelope in a Fetch response.
/// Spec: § Mailbox Servers (L312, L314–315).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FetchedEnvelope {
    /// The nonzero `seq` the server gave the Envelope.
    pub seq: u64,
    /// The Envelope.
    pub envelope: Vec<u8>,
}

/// Appends one `(seq, len, Envelope)` triple, little-endian.
/// Spec: § Mailbox Servers (L312), § Notation (L184).
pub fn push_fetch_item(out: &mut Vec<u8>, seq: u64, envelope: &[u8]) {
    out.extend_from_slice(&seq.to_le_bytes());
    let len = u32::try_from(envelope.len()).expect("envelopes are at most 262193 bytes");
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(envelope);
}

/// Size of a triple for an Envelope of `envelope_len` bytes.
/// Spec: § Mailbox Servers (L312).
pub fn fetch_item_len(envelope_len: usize) -> usize {
    FETCH_ITEM_HEADER_LEN + envelope_len
}

/// Decodes a Fetch response body into its triples, or `None` if malformed.
/// Spec: § Mailbox Servers (L312).
pub fn decode_fetch_response(mut body: &[u8]) -> Option<Vec<FetchedEnvelope>> {
    let mut out = Vec::new();
    while !body.is_empty() {
        let seq = u64::from_le_bytes(body.get(..8)?.try_into().ok()?);
        let len = u32::from_le_bytes(body.get(8..12)?.try_into().ok()?) as usize;
        let envelope = body.get(12..12 + len)?.to_vec();
        body = &body[12 + len..];
        out.push(FetchedEnvelope { seq, envelope });
    }
    Some(out)
}

/// Reads one length-prefixed frame. Returns `Ok(None)` if the declared length
/// exceeds `max` (the caller then drops the connection without reading more).
///
/// Spec: Appendix A, Tor (L497–498), marked TBD in the draft.
pub async fn read_frame<R: AsyncRead + Unpin>(
    r: &mut R,
    max: usize,
) -> std::io::Result<Option<Vec<u8>>> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len).await?;
    let len = u32::from_le_bytes(len) as usize;
    if len > max {
        return Ok(None);
    }
    let mut frame = vec![0u8; len];
    r.read_exact(&mut frame).await?;
    Ok(Some(frame))
}

/// Writes one length-prefixed frame.
/// Spec: Appendix A, Tor (L497–498), marked TBD in the draft.
pub async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, body: &[u8]) -> std::io::Result<()> {
    let len = u32::try_from(body.len())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "frame too large"))?;
    w.write_all(&len.to_le_bytes()).await?;
    w.write_all(body).await?;
    w.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use group::{Group, GroupEncoding};
    use pasta_curves::pallas;

    /// A valid Mailbox ID distinct for each `n`. Spec: § Mailboxes (L262–264).
    fn mailbox_id(n: u64) -> MailboxId {
        let g = pallas::Point::generator() * pallas::Scalar::from(n + 1);
        let mut id = [0u8; 64];
        id[..32].copy_from_slice(&g.to_bytes());
        id[32..].copy_from_slice(&g.double().to_bytes());
        MailboxId::from_bytes(&id).unwrap()
    }

    /// A smallest-size-class Envelope. Spec: § Envelopes (L194–198).
    fn envelope(tag: u8) -> Vec<u8> {
        let mut e = vec![tag; 2048 + 49];
        e[0] = 1;
        e
    }

    /// The three Envelope lengths and nothing else. Spec: § Envelopes (L194–198).
    #[test]
    fn envelope_lengths() {
        for n in SIZE_CLASSES {
            assert!(is_envelope_len(n + 49));
            assert!(!is_envelope_len(n + 48));
            assert!(!is_envelope_len(n + 50));
        }
        assert!(!is_envelope_len(0));
        assert_eq!(MAX_ENVELOPE_LEN, 262_193);
    }

    /// Deposits parse; malformed ones do not.
    /// Spec: § Mailbox Servers (L311, L326–328).
    #[test]
    fn parse_deposit() {
        let id = mailbox_id(1);
        let env = envelope(0);
        let frame = encode_deposit(&id, &env);
        assert_eq!(
            parse_request(&frame),
            Some(Request::Deposit {
                mailbox_id: id,
                envelope: &env
            })
        );
        assert_eq!(parse_request(&frame[..frame.len() - 1]), None);
        let mut identity = frame.clone();
        identity[1..33].fill(0);
        assert_eq!(parse_request(&identity), None);
        let mut not_point = frame.clone();
        not_point[33..65].fill(0xff);
        assert_eq!(parse_request(&not_point), None);
        assert_eq!(parse_request(&[]), None);
        assert_eq!(parse_request(&[1]), None);
        let mut unknown = frame;
        unknown[0] = 3;
        assert_eq!(parse_request(&unknown), None);
    }

    /// A Fetch must have exactly the Fetch length.
    /// Spec: § Mailbox Servers (L312, L326).
    #[test]
    fn parse_fetch_length() {
        let mut f = vec![0u8; FETCH_LEN];
        f[0] = FETCH;
        assert_eq!(parse_request(&f), Some(Request::Fetch(&f)));
        assert_eq!(parse_request(&f[..FETCH_LEN - 1]), None);
        f.push(0);
        assert_eq!(parse_request(&f), None);
    }

    /// Response triples round-trip; truncation is rejected.
    /// Spec: § Mailbox Servers (L312).
    #[test]
    fn fetch_response_round_trip() {
        let mut body = Vec::new();
        push_fetch_item(&mut body, 1, &[1, 2, 3]);
        push_fetch_item(&mut body, 5, &[]);
        assert_eq!(body.len(), fetch_item_len(3) + fetch_item_len(0));
        let items = decode_fetch_response(&body).unwrap();
        assert_eq!(
            items[0],
            FetchedEnvelope {
                seq: 1,
                envelope: vec![1, 2, 3]
            }
        );
        assert_eq!(items[1].seq, 5);
        assert!(decode_fetch_response(&body[..body.len() - 1]).is_none());
        assert_eq!(decode_fetch_response(&[]), Some(vec![]));
    }

    /// Frames round-trip, and an oversized length is refused before reading.
    /// Spec: Appendix A, Tor (L497–498).
    #[tokio::test]
    async fn frames() {
        let mut buf = Vec::new();
        write_frame(&mut buf, b"hello").await.unwrap();
        assert_eq!(&buf[..4], &5u32.to_le_bytes());
        let mut r = &buf[..];
        assert_eq!(
            read_frame(&mut r, 5).await.unwrap(),
            Some(b"hello".to_vec())
        );
        let mut r = &buf[..];
        assert_eq!(read_frame(&mut r, 4).await.unwrap(), None);
    }
}
