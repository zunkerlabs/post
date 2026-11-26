//! Envelopes: plaintext layout, encryption, and the recipient's drop rules.
//!
//! Spec: `spec/zip-draft-1435.md` § Envelopes (L192–246) and § Payloads
//! (L248–258).

use core::fmt;
use std::collections::HashSet;

use ff::Field;
use group::Group;
use pasta_curves::pallas;
use rand_core::CryptoRng;
use subtle::{
    Choice, ConditionallySelectable, ConstantTimeEq, ConstantTimeGreater, ConstantTimeLess,
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::encoding::{
    blake2b_256, personalization, point_bytes, point_from_bytes, scalar, sym_decrypt, sym_encrypt,
    TAG_LEN,
};
use crate::receiver::{OwnedReceiver, Receiver};

/// The only defined `version`. ZIP § Envelopes (L196).
pub const VERSION: u8 = 1;

/// Plaintext sizes `N`, smallest first. ZIP § Envelopes (L198, L212).
pub const SIZE_CLASSES: [usize; 3] = [2048, 32768, 262144];

/// `seed || payload_type || flags || expiry_time || fast_len || payload_len`.
/// ZIP § Envelopes (L202–211).
const HEADER_LEN: usize = 32 + 2 + 1 + 4 + 1 + 4;

/// `version || ephemeralKey`. ZIP § Envelopes (L194–197).
const PREFIX_LEN: usize = 1 + 32;

/// Bit 0 of `flags`. ZIP § Envelopes (L206).
const FLAG_ACK_REQUESTED: u8 = 0x01;

/// Payload types. ZIP § Payloads (L250–255).
pub mod payload_type {
    /// `ephemeralKey` of the acknowledged Envelope.
    pub const ACK: u16 = 1;
    /// UTF-8 text for display to the user.
    pub const TEXT: u16 = 2;
    /// UTF-8 ZIP 321 URI.
    pub const PAYMENT_REQUEST: u16 = 3;
    /// Serialized PCZT.
    pub const PCZT: u16 = 4;
}

/// Who sent an Envelope in a Conversation: `δ = 0` or `δ = 1`.
///
/// Spec: ZIP § Envelopes (L214–215).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    /// The sender of the first Envelope (`δ = 0`).
    Initiator,
    /// The owner of the Receiver the first Envelope was sent to (`δ = 1`).
    Responder,
}

impl Direction {
    /// `δ` as the one-byte string `[δ]`. Spec: ZIP § Notation (L182), § Envelopes (L215).
    pub fn delta(self) -> u8 {
        match self {
            Direction::Initiator => 0,
            Direction::Responder => 1,
        }
    }
}

/// The decoded fields of an Envelope plaintext, without `seed` and padding.
/// Zeroized on drop.
///
/// Spec: ZIP § Envelopes (L200–212).
#[derive(Clone, PartialEq, Eq, Default, Zeroize, ZeroizeOnDrop)]
pub struct Message {
    /// `payload_type`. Unknown values are delivered; the caller ignores them.
    pub payload_type: u16,
    /// Bit 0 of `flags`. Other bits are sent as zero and ignored on receipt.
    pub ack_requested: bool,
    /// `expiry_time`, in hours since the Unix epoch.
    pub expiry_time: u32,
    /// `fast_reply`, at most 255 bytes; empty if none. See ZIP § Fast mode.
    pub fast_reply: Vec<u8>,
    /// `payload`.
    pub payload: Vec<u8>,
}

impl fmt::Debug for Message {
    /// Spec: none (diagnostics only; never prints content).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Message")
            .field("payload_type", &self.payload_type)
            .field("ack_requested", &self.ack_requested)
            .field("expiry_time", &self.expiry_time)
            .finish_non_exhaustive()
    }
}

/// The state two wallets share after a first Envelope: `κ`, and the responder's
/// Receiver, whose `g_d` every Envelope in the Conversation is checked against.
/// `κ` is zeroized on drop.
///
/// Spec: ZIP § Terminology (L29–32), § Envelopes (L214–231).
#[derive(Clone)]
pub struct Conversation {
    kappa: Zeroizing<[u8; 32]>,
    responder: Receiver,
}

impl Conversation {
    /// Rebuilds a Conversation from stored `κ` and the responder's Receiver.
    /// Spec: ZIP § Envelopes (L214–217).
    pub fn from_parts(kappa: [u8; 32], responder: Receiver) -> Self {
        Conversation {
            kappa: Zeroizing::new(kappa),
            responder,
        }
    }

    /// Takes ownership of an already-wrapped `κ`, so it is never copied out
    /// of its zeroizing wrapper. Spec: ZIP § Envelopes (L214–231).
    fn from_secret(kappa: Zeroizing<[u8; 32]>, responder: Receiver) -> Self {
        Conversation { kappa, responder }
    }

    /// `κ`, for storage. Treat it as a secret: it reads and writes the
    /// Conversation. Spec: ZIP § Envelopes (L214), § Privacy Implications (L97–104).
    pub fn kappa(&self) -> &[u8; 32] {
        &self.kappa
    }

    /// The responder's Receiver. Spec: ZIP § Envelopes (L216–217).
    pub fn responder(&self) -> &Receiver {
        &self.responder
    }
}

impl fmt::Debug for Conversation {
    /// Spec: none (diagnostics only; never prints `κ`).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Conversation").finish_non_exhaustive()
    }
}

/// Why a [`Message`] cannot be sealed.
///
/// Spec: ZIP § Envelopes (L198, L208–212), § Payloads (L257).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SealError {
    /// The plaintext does not fit in the largest size class.
    TooLarge,
    /// `fast_reply` is longer than 255 bytes (`fast_len` is one byte).
    FastReplyTooLong,
    /// An Ack MUST NOT set `ack_requested`.
    AckRequestsAck,
}

impl fmt::Display for SealError {
    /// Spec: none (diagnostics only).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            SealError::TooLarge => "plaintext exceeds the largest envelope size",
            SealError::FastReplyTooLong => "fast_reply exceeds 255 bytes",
            SealError::AckRequestsAck => "an Ack must not set ack_requested",
        })
    }
}

impl std::error::Error for SealError {}

/// The one result of every failed drop rule. It deliberately carries no detail.
///
/// Spec: ZIP § Envelopes (L236–237): "with no behaviour that depends on which
/// check failed".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Dropped;

impl fmt::Display for Dropped {
    /// Spec: none (diagnostics only).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("envelope dropped")
    }
}

impl std::error::Error for Dropped {}

/// The set of `ephemeralKey`s already processed. Only Envelopes that pass every
/// other check are inserted, so a forged copy cannot block the real one.
///
/// Spec: ZIP § Envelopes (L243).
pub trait ReplayGuard {
    /// Whether an Envelope with this `ephemeralKey` was already processed.
    /// Spec: ZIP § Envelopes (L243).
    fn contains(&self, ephemeral_key: &[u8; 32]) -> bool;
    /// Records a processed `ephemeralKey`. Spec: ZIP § Envelopes (L243).
    fn insert(&mut self, ephemeral_key: [u8; 32]);
}

impl ReplayGuard for HashSet<[u8; 32]> {
    /// Spec: ZIP § Envelopes (L243).
    fn contains(&self, ephemeral_key: &[u8; 32]) -> bool {
        HashSet::contains(self, ephemeral_key)
    }

    /// Spec: ZIP § Envelopes (L243).
    fn insert(&mut self, ephemeral_key: [u8; 32]) {
        HashSet::insert(self, ephemeral_key);
    }
}

/// Seals a first Envelope to `to`, starting a Conversation in which the caller
/// is the initiator. Returns the Envelope bytes and the Conversation.
///
/// Spec: ZIP § Envelopes (L219–231).
pub fn seal_first<R: CryptoRng + ?Sized>(
    to: &Receiver,
    msg: &Message,
    rng: &mut R,
) -> Result<(Vec<u8>, Conversation), SealError> {
    let (seed, esk) = fresh_seed_and_esk(rng);
    let ek = point_bytes(&(to.g_d() * *esk));
    let shared = Zeroizing::new(to.pk_d() * *esk);
    let kappa = first_kappa(&shared, &ek);
    let envelope = seal_with(&kappa, Direction::Initiator, &ek, &seed, msg)?;
    Ok((envelope, Conversation::from_secret(kappa, *to)))
}

/// Seals an Envelope in `conv`, sent by `from`.
///
/// Spec: ZIP § Envelopes (L214–223).
pub fn seal<R: CryptoRng + ?Sized>(
    conv: &Conversation,
    from: Direction,
    msg: &Message,
    rng: &mut R,
) -> Result<Vec<u8>, SealError> {
    let (seed, esk) = fresh_seed_and_esk(rng);
    let ek = point_bytes(&(conv.responder.g_d() * *esk));
    seal_with(&conv.kappa, from, &ek, &seed, msg)
}

/// Opens a first Envelope fetched from the Contact Mailbox of `at`, at time
/// `now` (hours). On success returns the Message and the Conversation, in which
/// the caller is the responder.
///
/// Spec: ZIP § Envelopes (L225–246).
pub fn open_first(
    at: &OwnedReceiver,
    envelope: &[u8],
    now: u32,
    seen: &mut impl ReplayGuard,
) -> Result<(Message, Conversation), Dropped> {
    let checks = check_first(at, envelope, now, &*seen).ok_or(Dropped)?;
    let (msg, kappa) = checks.accept(seen)?;
    Ok((msg, Conversation::from_secret(kappa, *at.receiver())))
}

/// Opens an Envelope in `conv` that `from` sent, fetched from the matching
/// Pairwise Mailbox or `fast_reply` address, at time `now` (hours).
///
/// Spec: ZIP § Envelopes (L214–223, L233–246).
pub fn open(
    conv: &Conversation,
    from: Direction,
    envelope: &[u8],
    now: u32,
    seen: &mut impl ReplayGuard,
) -> Result<Message, Dropped> {
    let checks = check(
        conv.kappa.clone(),
        Choice::from(1),
        from,
        conv.responder.g_d(),
        envelope,
        now,
        &*seen,
    )
    .ok_or(Dropped)?;
    checks.accept(seen).map(|(msg, _)| msg)
}

/// Samples `seed` and derives `esk = Scalar("Zcash_WMsgEsk___", seed)`,
/// resampling in the negligible case `esk = 0`, for which `epk` would be the
/// identity.
///
/// Spec: ZIP § Envelopes (L204, L219).
fn fresh_seed_and_esk<R: CryptoRng + ?Sized>(
    rng: &mut R,
) -> (Zeroizing<[u8; 32]>, Zeroizing<pallas::Scalar>) {
    loop {
        let mut seed = Zeroizing::new([0u8; 32]);
        rng.fill_bytes(&mut *seed);
        let esk = Zeroizing::new(esk_from_seed(&seed));
        if !bool::from(esk.is_zero()) {
            return (seed, esk);
        }
    }
}

/// `esk = Scalar("Zcash_WMsgEsk___", seed)`. Spec: ZIP § Envelopes (L219).
fn esk_from_seed(seed: &[u8; 32]) -> pallas::Scalar {
    scalar(personalization::ESK, &[seed])
}

/// `κ = BLAKE2b-256("Zcash_WMsgPairS_", PointBytes([esk] pk_d) || ephemeralKey)`.
///
/// Spec: ZIP § Envelopes (L227).
fn first_kappa(shared: &pallas::Point, ek: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let shared_bytes = Zeroizing::new(point_bytes(shared));
    Zeroizing::new(blake2b_256(personalization::PAIR_S, &[&*shared_bytes, ek]))
}

/// `K = BLAKE2b-256("Zcash_WMsgPairK_", κ || [δ] || ephemeralKey)`.
///
/// Spec: ZIP § Envelopes (L221).
fn envelope_key(kappa: &[u8; 32], from: Direction, ek: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(blake2b_256(
        personalization::PAIR_K,
        &[kappa, &[from.delta()], ek],
    ))
}

/// The smallest `N` that fits a plaintext of `len` bytes before padding.
///
/// Spec: ZIP § Envelopes (L198, L212).
fn size_class_for(len: usize) -> Option<usize> {
    SIZE_CLASSES.iter().copied().find(|&n| len <= n)
}

/// The `N` of an Envelope of `len` bytes, if `len` is one of the three lengths.
///
/// Spec: ZIP § Envelopes (L194–198, L239).
fn size_class_of_envelope(len: usize) -> Option<usize> {
    SIZE_CLASSES
        .iter()
        .copied()
        .find(|&n| len == PREFIX_LEN + n + TAG_LEN)
}

/// Encodes the plaintext, little-endian, padded with zeros to the smallest `N`.
///
/// Spec: ZIP § Envelopes (L200–212), § Notation (L184), § Payloads (L257).
fn encode_plaintext(seed: &[u8; 32], msg: &Message) -> Result<Zeroizing<Vec<u8>>, SealError> {
    if msg.payload_type == payload_type::ACK && msg.ack_requested {
        return Err(SealError::AckRequestsAck);
    }
    let fast_len = u8::try_from(msg.fast_reply.len()).map_err(|_| SealError::FastReplyTooLong)?;
    let payload_len = u32::try_from(msg.payload.len()).map_err(|_| SealError::TooLarge)?;
    let used = HEADER_LEN + msg.fast_reply.len() + msg.payload.len();
    let n = size_class_for(used).ok_or(SealError::TooLarge)?;

    let mut buf = Zeroizing::new(Vec::with_capacity(n + TAG_LEN));
    buf.extend_from_slice(seed);
    buf.extend_from_slice(&msg.payload_type.to_le_bytes());
    buf.push(if msg.ack_requested {
        FLAG_ACK_REQUESTED
    } else {
        0
    });
    buf.extend_from_slice(&msg.expiry_time.to_le_bytes());
    buf.push(fast_len);
    buf.extend_from_slice(&msg.fast_reply);
    buf.extend_from_slice(&payload_len.to_le_bytes());
    buf.extend_from_slice(&msg.payload);
    buf.resize(n, 0);
    Ok(buf)
}

/// Builds `version || ephemeralKey || Sym.Encrypt_K(plaintext)`.
///
/// Spec: ZIP § Envelopes (L194–198, L221–223).
fn seal_with(
    kappa: &[u8; 32],
    from: Direction,
    ek: &[u8; 32],
    seed: &[u8; 32],
    msg: &Message,
) -> Result<Vec<u8>, SealError> {
    let mut plaintext = encode_plaintext(seed, msg)?;
    Ok(seal_plaintext(kappa, from, ek, &mut plaintext))
}

/// Encrypts an already-encoded plaintext in place and frames it.
///
/// Spec: ZIP § Envelopes (L194–198, L221–223).
fn seal_plaintext(
    kappa: &[u8; 32],
    from: Direction,
    ek: &[u8; 32],
    plaintext: &mut [u8],
) -> Vec<u8> {
    let key = envelope_key(kappa, from, ek);
    let tag = sym_encrypt(&key, plaintext);
    let mut out = Vec::with_capacity(PREFIX_LEN + plaintext.len() + TAG_LEN);
    out.push(VERSION);
    out.extend_from_slice(ek);
    out.extend_from_slice(plaintext);
    out.extend_from_slice(&tag);
    out
}

/// The outcome of every drop rule for one Envelope, kept separate so that the
/// result is combined in one place and tests can see which rule fired.
///
/// Spec: ZIP § Envelopes (L233–246).
struct Checks {
    ek: [u8; 32],
    kappa: Zeroizing<[u8; 32]>,
    fields: Fields,
    plaintext: Zeroizing<Vec<u8>>,
    /// `version` is known.
    version_ok: Choice,
    /// `ephemeralKey` is a valid point encoding (first Envelopes only).
    point_ok: Choice,
    aead_ok: Choice,
    parse_ok: Choice,
    padding_ok: Choice,
    ek_ok: Choice,
    not_expired: Choice,
    fresh: Choice,
}

impl Checks {
    /// Combines every rule; on success records `ephemeralKey` and returns the
    /// Message and `κ`. Every failure returns the same [`Dropped`].
    ///
    /// Spec: ZIP § Envelopes (L236–246).
    fn accept(
        self,
        seen: &mut impl ReplayGuard,
    ) -> Result<(Message, Zeroizing<[u8; 32]>), Dropped> {
        let ok = self.version_ok
            & self.point_ok
            & self.aead_ok
            & self.parse_ok
            & self.padding_ok
            & self.ek_ok
            & self.not_expired
            & self.fresh;
        if !bool::from(ok) {
            return Err(Dropped);
        }
        seen.insert(self.ek);
        let f = &self.fields;
        let msg = Message {
            payload_type: f.payload_type,
            ack_requested: f.flags & FLAG_ACK_REQUESTED != 0,
            expiry_time: f.expiry_time,
            fast_reply: self.plaintext[f.fast_start..f.fast_end].to_vec(),
            payload: self.plaintext[f.payload_start..f.payload_end].to_vec(),
        };
        Ok((msg, self.kappa))
    }
}

/// Evaluates the drop rules for a first Envelope to `at`. Returns `None` only
/// for an unknown length: without a known `N` there is nothing to decrypt, and
/// the length is visible to anyone and chosen by the sender, so rejecting it
/// early reveals nothing. Every other rule, including `version`, is evaluated
/// in full and combined in [`Checks::accept`].
///
/// Spec: ZIP § Envelopes (L225–246); `[esk] pk_d = [ivk] epk` (L229–231).
fn check_first(
    at: &OwnedReceiver,
    envelope: &[u8],
    now: u32,
    seen: &impl ReplayGuard,
) -> Option<Checks> {
    let ek = framed_ephemeral_key(envelope)?;
    let epk = point_from_bytes(&ek);
    let point_ok = epk.is_some();
    // Continue with a dummy point so the remaining work does not depend on it.
    let epk = epk.unwrap_or(pallas::Point::generator());
    let shared = Zeroizing::new(epk * at.ivk().scalar());
    let kappa = first_kappa(&shared, &ek);
    check(
        kappa,
        point_ok,
        Direction::Initiator,
        at.receiver().g_d(),
        envelope,
        now,
        seen,
    )
}

/// Evaluates the drop rules for an Envelope under `κ` from `from`, checking
/// `ephemeralKey` against the responder's `g_d`. Decryption, parsing and every
/// check run whether or not earlier checks failed; only an unknown length
/// returns early (see [`check_first`]).
///
/// Spec: ZIP § Envelopes (L221–223, L233–246).
fn check(
    kappa: Zeroizing<[u8; 32]>,
    point_ok: Choice,
    from: Direction,
    g_d: &pallas::Point,
    envelope: &[u8],
    now: u32,
    seen: &impl ReplayGuard,
) -> Option<Checks> {
    let ek = framed_ephemeral_key(envelope)?;
    let n = size_class_of_envelope(envelope.len())?;
    let version_ok = envelope[0].ct_eq(&VERSION);

    let key = envelope_key(&kappa, from, &ek);
    let mut plaintext = Zeroizing::new(envelope[PREFIX_LEN..PREFIX_LEN + n].to_vec());
    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(&envelope[PREFIX_LEN + n..]);
    let aead_ok = sym_decrypt(&key, &mut plaintext, &tag);

    let (fields, parse_ok, padding_ok) = parse_plaintext(&plaintext);

    let esk = Zeroizing::new(esk_from_seed(&fields.seed));
    let ek_ok = point_bytes(&(g_d * *esk)).ct_eq(&ek);
    let not_expired = fields.expiry_time.ct_gt(&now);
    let fresh = Choice::from(u8::from(!seen.contains(&ek)));

    Some(Checks {
        ek,
        kappa,
        fields,
        plaintext,
        version_ok,
        point_ok,
        aead_ok,
        parse_ok,
        padding_ok,
        ek_ok,
        not_expired,
        fresh,
    })
}

/// Returns `ephemeralKey` if the length is one of the three Envelope lengths.
/// `version` is checked with the other rules, not here.
///
/// Spec: ZIP § Envelopes (L194–198, L239).
fn framed_ephemeral_key(envelope: &[u8]) -> Option<[u8; 32]> {
    size_class_of_envelope(envelope.len())?;
    let mut ek = [0u8; 32];
    ek.copy_from_slice(&envelope[1..PREFIX_LEN]);
    Some(ek)
}

/// Field offsets and fixed fields of a plaintext. Zeroized on drop.
///
/// Spec: ZIP § Envelopes (L200–212).
#[derive(Zeroize, ZeroizeOnDrop)]
struct Fields {
    seed: [u8; 32],
    payload_type: u16,
    flags: u8,
    expiry_time: u32,
    fast_start: usize,
    fast_end: usize,
    payload_start: usize,
    payload_end: usize,
}

/// Parses a plaintext of length `N` without branching on its contents. Returns
/// the fields, whether the lengths fit, and whether every byte after the payload
/// is zero. If the lengths do not fit, the payload is taken to run to the end so
/// that the offsets stay in bounds.
///
/// Spec: ZIP § Envelopes (L200–212, L240), § Notation (L184).
fn parse_plaintext(pt: &[u8]) -> (Fields, Choice, Choice) {
    let n = pt.len();
    let payload_type = u16::from_le_bytes([pt[32], pt[33]]);
    let flags = pt[34];
    let expiry_time = u32::from_le_bytes([pt[35], pt[36], pt[37], pt[38]]);
    let fast_len = usize::from(pt[39]);
    // HEADER_LEN + 255 < 2048, so the fixed header always fits.
    let fast_start = 40;
    let fast_end = fast_start + fast_len;
    let payload_len = u32::from_le_bytes([
        pt[fast_end],
        pt[fast_end + 1],
        pt[fast_end + 2],
        pt[fast_end + 3],
    ]);
    let payload_start = fast_end + 4;

    let room = (n - payload_start) as u64;
    let parse_ok = !u64::from(payload_len).ct_gt(&room);
    let claimed_end = payload_start as u64 + u64::from(payload_len);
    let payload_end = u64::conditional_select(&(n as u64), &claimed_end, parse_ok) as usize;

    let mut nonzero = 0u8;
    for (i, byte) in pt.iter().enumerate() {
        let in_padding = !(i as u64).ct_lt(&(payload_end as u64));
        nonzero |= u8::conditional_select(&0, byte, in_padding);
    }
    let padding_ok = nonzero.ct_eq(&0);

    let mut fields = Fields {
        seed: [0u8; 32],
        payload_type,
        flags,
        expiry_time,
        fast_start,
        fast_end,
        payload_start,
        payload_end,
    };
    // Copied straight into the zeroize-on-drop struct, never via a local.
    fields.seed.copy_from_slice(&pt[..32]);
    (fields, parse_ok, padding_ok)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::receiver::testing::Wallet;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    const NOW: u32 = 500_000;

    /// Test fixture. Spec: ZIP § Envelopes (L200–212).
    fn text(len: usize) -> Message {
        Message {
            payload_type: payload_type::TEXT,
            ack_requested: true,
            expiry_time: NOW + 24,
            fast_reply: vec![],
            payload: (0..len).map(|i| i as u8).collect(),
        }
    }

    /// Whether a result is the drop outcome. Spec: ZIP § Envelopes (L236–237).
    fn dropped<T>(r: Result<T, Dropped>) -> bool {
        matches!(r, Err(Dropped))
    }

    /// Test fixture. Spec: none.
    fn rng() -> StdRng {
        StdRng::seed_from_u64(1435)
    }

    /// Builds a first Envelope to `to` from a raw plaintext whose `seed` may not
    /// match `ek_seed`, for testing the drop rules. Spec: ZIP § Envelopes (L219–231).
    fn forge_first(to: &Receiver, ek_seed: &[u8; 32], plaintext: &mut [u8]) -> Vec<u8> {
        let esk = esk_from_seed(ek_seed);
        let ek = point_bytes(&(to.g_d() * esk));
        let kappa = first_kappa(&(to.pk_d() * esk), &ek);
        seal_plaintext(&kappa, Direction::Initiator, &ek, plaintext)
    }

    /// Spec: ZIP § Envelopes (L198, L212): round trip in each size class, with
    /// the smallest class chosen and boundary lengths handled.
    #[test]
    fn round_trip_each_size_class() {
        let w = Wallet::new(0);
        let me = w.owned(0);
        let mut rng = rng();
        let cases = [
            (0, 2048),
            (2048 - HEADER_LEN, 2048),
            (2048 - HEADER_LEN + 1, 32768),
            (32768 - HEADER_LEN, 32768),
            (32768 - HEADER_LEN + 1, 262144),
            (262144 - HEADER_LEN, 262144),
        ];
        for (len, n) in cases {
            let msg = text(len);
            let (env, sender_conv) = seal_first(me.receiver(), &msg, &mut rng).unwrap();
            assert_eq!(env.len(), PREFIX_LEN + n + TAG_LEN, "payload {len}");
            let mut seen = HashSet::new();
            let (got, conv) = open_first(&me, &env, NOW, &mut seen).unwrap();
            assert_eq!(got, msg);
            assert_eq!(conv.kappa(), sender_conv.kappa());
        }
        assert_eq!(
            seal_first(me.receiver(), &text(262144 - HEADER_LEN + 1), &mut rng).unwrap_err(),
            SealError::TooLarge
        );
    }

    /// Spec: ZIP § Envelopes (L208–209), § Fast mode (L356–362): `fast_reply`
    /// round-trips and is limited to 255 bytes.
    #[test]
    fn fast_reply_round_trip() {
        let me = Wallet::new(0).owned(0);
        let mut rng = rng();
        let mut msg = text(10);
        msg.fast_reply = vec![1, 0xff, 0xff, 0xff, 0x7f, 9, 9, 9];
        let (env, _) = seal_first(me.receiver(), &msg, &mut rng).unwrap();
        let (got, _) = open_first(&me, &env, NOW, &mut HashSet::new()).unwrap();
        assert_eq!(got.fast_reply, msg.fast_reply);

        msg.fast_reply = vec![0; 256];
        assert_eq!(
            seal_first(me.receiver(), &msg, &mut rng).unwrap_err(),
            SealError::FastReplyTooLong
        );
    }

    /// Spec: ZIP § Envelopes (L214–223), § Conversations (L289–299): both
    /// directions work and are not interchangeable.
    #[test]
    fn conversation_both_directions() {
        let me = Wallet::new(0).owned(0);
        let mut rng = rng();
        let (first, initiator) = seal_first(me.receiver(), &text(5), &mut rng).unwrap();
        let mut responder_seen = HashSet::new();
        let (_, responder) = open_first(&me, &first, NOW, &mut responder_seen).unwrap();

        let reply = seal(&responder, Direction::Responder, &text(6), &mut rng).unwrap();
        let mut initiator_seen = HashSet::new();
        assert_eq!(
            open(
                &initiator,
                Direction::Responder,
                &reply,
                NOW,
                &mut initiator_seen
            )
            .unwrap(),
            text(6)
        );
        // The same bytes are not valid as an initiator Envelope.
        assert_eq!(
            open(
                &initiator,
                Direction::Initiator,
                &reply,
                NOW,
                &mut HashSet::new()
            ),
            Err(Dropped)
        );

        let next = seal(&initiator, Direction::Initiator, &text(7), &mut rng).unwrap();
        assert_eq!(
            open(
                &responder,
                Direction::Initiator,
                &next,
                NOW,
                &mut responder_seen
            )
            .unwrap(),
            text(7)
        );
    }

    /// Spec: ZIP § Envelopes (L239): unknown `version` or length is dropped.
    #[test]
    fn drop_unknown_version_or_length() {
        let me = Wallet::new(0).owned(0);
        let (env, _) = seal_first(me.receiver(), &text(1), &mut rng()).unwrap();

        let mut bad_version = env.clone();
        bad_version[0] = 2;
        // Evaluated with the other rules, not by an early return.
        let checks = check_first(&me, &bad_version, NOW, &HashSet::new()).unwrap();
        assert!(!bool::from(checks.version_ok));
        assert!(bool::from(checks.aead_ok & checks.ek_ok & checks.parse_ok));
        assert!(dropped(open_first(
            &me,
            &bad_version,
            NOW,
            &mut HashSet::new()
        )));

        let mut longer = env.clone();
        longer.push(0);
        assert!(dropped(open_first(&me, &longer, NOW, &mut HashSet::new())));
        assert!(dropped(open_first(
            &me,
            &env[..env.len() - 1],
            NOW,
            &mut HashSet::new()
        )));
        assert!(dropped(open_first(&me, &[], NOW, &mut HashSet::new())));
    }

    /// Spec: ZIP § Envelopes (L240): decryption failure is dropped, whether the
    /// ciphertext, the tag, or `ephemeralKey` is altered.
    #[test]
    fn drop_aead_failure() {
        let me = Wallet::new(0).owned(0);
        let (env, _) = seal_first(me.receiver(), &text(1), &mut rng()).unwrap();
        for i in [PREFIX_LEN, PREFIX_LEN + 100, env.len() - 1, 1] {
            let mut bad = env.clone();
            bad[i] ^= 0x01;
            assert!(
                dropped(open_first(&me, &bad, NOW, &mut HashSet::new())),
                "byte {i}"
            );
        }
    }

    /// Spec: ZIP § Envelopes (L240): a plaintext whose `payload_len` overruns
    /// `N` does not parse and is dropped, although it decrypts.
    #[test]
    fn drop_bad_parse() {
        let me = Wallet::new(0).owned(0);
        let seed = [4u8; 32];
        let mut pt = encode_plaintext(&seed, &text(3)).unwrap();
        pt[40..44].copy_from_slice(&(2048u32 - 43).to_le_bytes());
        let env = forge_first(me.receiver(), &seed, &mut pt);
        let checks = check_first(&me, &env, NOW, &HashSet::new()).unwrap();
        assert!(bool::from(checks.aead_ok));
        assert!(!bool::from(checks.parse_ok));
        assert!(dropped(open_first(&me, &env, NOW, &mut HashSet::new())));

        // The largest payload_len that fits is accepted (padding then empty).
        let mut pt = encode_plaintext(&seed, &text(3)).unwrap();
        pt[40..44].copy_from_slice(&(2048u32 - 44).to_le_bytes());
        let env = forge_first(me.receiver(), &seed, &mut pt);
        assert!(open_first(&me, &env, NOW, &mut HashSet::new()).is_ok());
    }

    /// Spec: ZIP § Envelopes (L212, L240): nonzero padding is dropped.
    #[test]
    fn drop_nonzero_padding() {
        let me = Wallet::new(0).owned(0);
        let seed = [5u8; 32];
        for pos in [HEADER_LEN + 3, 1000, 2047] {
            let mut pt = encode_plaintext(&seed, &text(3)).unwrap();
            pt[pos] = 1;
            let env = forge_first(me.receiver(), &seed, &mut pt);
            let checks = check_first(&me, &env, NOW, &HashSet::new()).unwrap();
            assert!(bool::from(checks.aead_ok & checks.parse_ok));
            assert!(!bool::from(checks.padding_ok));
            assert!(
                dropped(open_first(&me, &env, NOW, &mut HashSet::new())),
                "pos {pos}"
            );
        }
    }

    /// Spec: ZIP § Envelopes (L241): `ephemeralKey` not derived from `seed` is
    /// dropped, although it decrypts.
    #[test]
    fn drop_ephemeral_key_mismatch() {
        let me = Wallet::new(0).owned(0);
        let mut pt = encode_plaintext(&[6u8; 32], &text(3)).unwrap();
        let env = forge_first(me.receiver(), &[7u8; 32], &mut pt);
        let checks = check_first(&me, &env, NOW, &HashSet::new()).unwrap();
        assert!(bool::from(
            checks.aead_ok & checks.parse_ok & checks.padding_ok
        ));
        assert!(!bool::from(checks.ek_ok));
        assert!(dropped(open_first(&me, &env, NOW, &mut HashSet::new())));
    }

    /// Spec: ZIP § Envelopes (L207, L242): dropped from `expiry_time` on.
    #[test]
    fn drop_expired() {
        let me = Wallet::new(0).owned(0);
        let (env, _) = seal_first(me.receiver(), &text(1), &mut rng()).unwrap();
        let expiry = text(1).expiry_time;
        assert!(open_first(&me, &env, expiry - 1, &mut HashSet::new()).is_ok());
        assert!(dropped(open_first(&me, &env, expiry, &mut HashSet::new())));
        assert!(dropped(open_first(
            &me,
            &env,
            u32::MAX,
            &mut HashSet::new()
        )));
    }

    /// Spec: ZIP § Envelopes (L243): a repeated `ephemeralKey` is dropped, and a
    /// forged Envelope reusing it does not block the real one.
    #[test]
    fn drop_duplicate() {
        let me = Wallet::new(0).owned(0);
        let (env, _) = seal_first(me.receiver(), &text(1), &mut rng()).unwrap();
        let mut seen = HashSet::new();

        let mut forged = env.clone();
        forged[PREFIX_LEN] ^= 1;
        assert!(dropped(open_first(&me, &forged, NOW, &mut seen)));
        assert!(seen.is_empty());

        assert!(open_first(&me, &env, NOW, &mut seen).is_ok());
        assert!(dropped(open_first(&me, &env, NOW, &mut seen)));
    }

    /// Spec: ZIP § Envelopes (L241), § Rationale (L408–413), ZIP 212: an Envelope
    /// moved to another address with the same `ivk` decrypts there but is
    /// dropped by the `ephemeralKey` check.
    #[test]
    fn drop_zip212_cross_address() {
        let w = Wallet::new(0);
        let addr0 = w.owned(0);
        let addr1 = w.owned(1);
        let (env, _) = seal_first(addr0.receiver(), &text(1), &mut rng()).unwrap();

        let checks = check_first(&addr1, &env, NOW, &HashSet::new()).unwrap();
        assert!(
            bool::from(checks.aead_ok),
            "same ivk, so decryption succeeds"
        );
        assert!(!bool::from(checks.ek_ok));
        assert!(dropped(open_first(&addr1, &env, NOW, &mut HashSet::new())));
        assert!(open_first(&addr0, &env, NOW, &mut HashSet::new()).is_ok());
    }

    /// Spec: ZIP § Envelopes (L240): an `ephemeralKey` that is not a point is
    /// dropped through the same path.
    #[test]
    fn drop_invalid_point() {
        let me = Wallet::new(0).owned(0);
        let (mut env, _) = seal_first(me.receiver(), &text(1), &mut rng()).unwrap();
        env[1..PREFIX_LEN].fill(0xff);
        let checks = check_first(&me, &env, NOW, &HashSet::new()).unwrap();
        assert!(!bool::from(checks.point_ok));
        assert!(dropped(open_first(&me, &env, NOW, &mut HashSet::new())));
    }

    /// Spec: ZIP § Envelopes (L245–246): unknown `flags` bits and
    /// `payload_type`s are delivered, not dropped.
    #[test]
    fn unknown_flags_and_types_ignored() {
        let me = Wallet::new(0).owned(0);
        let seed = [8u8; 32];
        let mut msg = text(3);
        msg.payload_type = 0xbeef;
        let mut pt = encode_plaintext(&seed, &msg).unwrap();
        pt[34] = 0xfe;
        let env = forge_first(me.receiver(), &seed, &mut pt);
        let (got, _) = open_first(&me, &env, NOW, &mut HashSet::new()).unwrap();
        assert_eq!(got.payload_type, 0xbeef);
        assert!(!got.ack_requested);
    }

    /// Spec: ZIP § Payloads (L257): an Ack MUST NOT set `ack_requested`.
    #[test]
    fn ack_must_not_request_ack() {
        let me = Wallet::new(0).owned(0);
        let msg = Message {
            payload_type: payload_type::ACK,
            ack_requested: true,
            expiry_time: NOW + 1,
            fast_reply: vec![],
            payload: vec![0; 32],
        };
        assert_eq!(
            seal_first(me.receiver(), &msg, &mut rng()).unwrap_err(),
            SealError::AckRequestsAck
        );
    }

    /// Spec: ZIP § Envelopes (L200–212), § Notation (L184): exact byte layout.
    #[test]
    fn plaintext_layout() {
        let msg = Message {
            payload_type: 0x0102,
            ack_requested: true,
            expiry_time: 0x0304_0506,
            fast_reply: vec![0xaa, 0xbb],
            payload: vec![0xcc; 3],
        };
        let pt = encode_plaintext(&[0x11; 32], &msg).unwrap();
        assert_eq!(pt.len(), 2048);
        assert_eq!(&pt[..32], &[0x11; 32]);
        assert_eq!(&pt[32..34], &[0x02, 0x01]);
        assert_eq!(pt[34], 0x01);
        assert_eq!(&pt[35..39], &[0x06, 0x05, 0x04, 0x03]);
        assert_eq!(pt[39], 2);
        assert_eq!(&pt[40..42], &[0xaa, 0xbb]);
        assert_eq!(&pt[42..46], &[3, 0, 0, 0]);
        assert_eq!(&pt[46..49], &[0xcc; 3]);
        assert!(pt[49..].iter().all(|&b| b == 0));
    }

    /// Spec: ZIP § Envelopes (L219): `epk = [esk] g_d` with `esk` from `seed`.
    #[test]
    fn ephemeral_key_is_esk_times_gd() {
        let me = Wallet::new(0).owned(0);
        let seed = [9u8; 32];
        let mut pt = encode_plaintext(&seed, &text(1)).unwrap();
        let env = forge_first(me.receiver(), &seed, &mut pt);
        let expected = point_bytes(&(me.receiver().g_d() * esk_from_seed(&seed)));
        assert_eq!(&env[1..PREFIX_LEN], &expected);
    }
}
