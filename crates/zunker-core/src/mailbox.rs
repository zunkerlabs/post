//! Mailbox IDs and the scalars that authorize fetching from them.
//!
//! Spec: `spec/zip-draft-1435.md` § Mailboxes (L260–277).

use core::fmt;

use group::Group;
use pasta_curves::pallas;
use subtle::CtOption;
use zeroize::Zeroizing;

use crate::encoding::{
    group_hash, personalization, point_bytes, point_from_bytes, scalar, PAIRWISE_GROUP_HASH_DOMAIN,
};
use crate::envelope::{Conversation, Direction};
use crate::receiver::{OwnedReceiver, Receiver};

/// Hours per epoch. ZIP § Mailboxes (L277).
pub const EPOCH_HOURS: u32 = 168;

/// `PointBytes(G) || PointBytes(P)`, with neither point the identity.
///
/// Spec: ZIP § Mailboxes (L262–264).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct MailboxId([u8; 64]);

impl MailboxId {
    /// Parses a Mailbox ID, returning `None` unless both halves are canonical
    /// encodings of Pallas points other than the identity.
    ///
    /// Spec: ZIP § Mailboxes (L262–264), § Mailbox Servers (L326–328).
    pub fn from_bytes(bytes: &[u8; 64]) -> Option<Self> {
        let (g, p) = split_points(bytes)?;
        Some(Self::from_points(&g, &p))
    }

    /// The 64-byte encoding. Spec: ZIP § Mailboxes (L262).
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }

    /// `PointBytes(G) || PointBytes(P)`. Spec: ZIP § Mailboxes (L262).
    fn from_points(g: &pallas::Point, p: &pallas::Point) -> Self {
        let mut id = [0u8; 64];
        id[..32].copy_from_slice(&point_bytes(g));
        id[32..].copy_from_slice(&point_bytes(p));
        MailboxId(id)
    }

    /// `(G, P)`, both non-identity. Spec: ZIP § Mailboxes (L262–264).
    #[allow(dead_code)] // used by the sig module
    pub(crate) fn points(&self) -> (pallas::Point, pallas::Point) {
        split_points(&self.0).expect("a MailboxId always holds two valid points")
    }
}

impl fmt::Debug for MailboxId {
    /// Spec: none (diagnostics only).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MailboxId(")?;
        for b in &self.0[..8] {
            write!(f, "{b:02x}")?;
        }
        write!(f, "..)")
    }
}

/// Decodes both halves of a Mailbox ID as non-identity points.
///
/// Spec: ZIP § Mailboxes (L262–264), § Mailbox Servers (L326–328).
fn split_points(bytes: &[u8; 64]) -> Option<(pallas::Point, pallas::Point)> {
    let mut g = [0u8; 32];
    let mut p = [0u8; 32];
    g.copy_from_slice(&bytes[..32]);
    p.copy_from_slice(&bytes[32..]);
    let non_identity = |q: pallas::Point| CtOption::new(q, !q.is_identity());
    let g = Option::from(point_from_bytes(&g).and_then(non_identity))?;
    let p = Option::from(point_from_bytes(&p).and_then(non_identity))?;
    Some((g, p))
}

/// A mailbox the holder may fetch from: `G`, `P = [a] G`, and `a`, which is
/// zeroized on drop.
///
/// Spec: ZIP § Mailboxes (L262–264).
#[derive(Clone)]
pub struct MailboxKey {
    g: pallas::Point,
    p: pallas::Point,
    a: Zeroizing<pallas::Scalar>,
}

impl MailboxKey {
    /// Builds a key, returning `None` if `G` or `P` is the identity, since such
    /// a derivation defines no mailbox.
    ///
    /// Spec: ZIP § Mailboxes (L263–264).
    fn new(g: pallas::Point, p: pallas::Point, a: Zeroizing<pallas::Scalar>) -> Option<Self> {
        if bool::from(g.is_identity() | p.is_identity()) {
            return None;
        }
        Some(MailboxKey { g, p, a })
    }

    /// The Mailbox ID `PointBytes(G) || PointBytes(P)`. Spec: ZIP § Mailboxes (L262).
    pub fn id(&self) -> MailboxId {
        MailboxId::from_points(&self.g, &self.p)
    }

    /// The generator `G`. Spec: ZIP § Mailboxes (L262–263).
    #[allow(dead_code)] // used by the sig module
    pub(crate) fn g(&self) -> &pallas::Point {
        &self.g
    }

    /// The validating key `P`. Spec: ZIP § Mailboxes (L262–263).
    #[allow(dead_code)] // used by the sig module
    pub(crate) fn p(&self) -> &pallas::Point {
        &self.p
    }

    /// The fetch-authorizing scalar `a`. Spec: ZIP § Mailboxes (L263).
    #[allow(dead_code)] // used by the sig module
    pub(crate) fn a(&self) -> &pallas::Scalar {
        &self.a
    }
}

impl fmt::Debug for MailboxKey {
    /// Spec: none (diagnostics only; never prints `a`).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MailboxKey")
            .field("id", &self.id())
            .finish_non_exhaustive()
    }
}

/// `r = Scalar("Zcash_WMsgMbxOrc", rcv)`, `G = [r] g_d`, `P = [r] pk_d`.
///
/// Spec: ZIP § Mailboxes (L266–268).
fn contact_points(rcv: &Receiver) -> (pallas::Point, pallas::Point) {
    let r = scalar(personalization::MBX_ORC, &[rcv.raw()]);
    (rcv.g_d() * r, rcv.pk_d() * r)
}

/// The Contact Mailbox ID of a Receiver, as a sender computes it to deposit a
/// first Envelope. `None` if the derivation yields the identity.
///
/// Spec: ZIP § Mailboxes (L262–268), § Conversations (L289–290).
pub fn contact_mailbox_id(rcv: &Receiver) -> Option<MailboxId> {
    let (g, p) = contact_points(rcv);
    if bool::from(g.is_identity() | p.is_identity()) {
        return None;
    }
    Some(MailboxId::from_points(&g, &p))
}

/// The Contact Mailbox of an owned Receiver, with `a = ivk`: since
/// `pk_d = [ivk] g_d`, `P = [r] pk_d = [ivk] G`.
///
/// Spec: ZIP § Mailboxes (L266–270).
pub fn contact_mailbox_key(owned: &OwnedReceiver) -> Option<MailboxKey> {
    let (g, p) = contact_points(owned.receiver());
    MailboxKey::new(g, p, Zeroizing::new(*owned.ivk().scalar()))
}

/// The epoch at time `hours` (hours since the Unix epoch): `floor(t / 168)`.
///
/// Spec: ZIP § Mailboxes (L277), § Notation (L184–185).
pub fn epoch(hours: u32) -> u32 {
    hours / EPOCH_HOURS
}

/// The Pairwise Mailbox of `conv` for direction `from` and `epoch`:
/// `m = κ || [δ] || I2LEOSP_32(e)`, `G = GroupHash^P("z.cash:WalletMsg-pair", m)`,
/// `a = Scalar("Zcash_WMsgPairX_", m)`, `P = [a] G`.
///
/// Spec: ZIP § Mailboxes (L272–277).
pub fn pairwise_mailbox_key(
    conv: &Conversation,
    from: Direction,
    epoch: u32,
) -> Option<MailboxKey> {
    let mut m = Zeroizing::new([0u8; 37]);
    m[..32].copy_from_slice(conv.kappa());
    m[32] = from.delta();
    m[33..].copy_from_slice(&epoch.to_le_bytes());
    let g = group_hash(PAIRWISE_GROUP_HASH_DOMAIN, &*m);
    let a = Zeroizing::new(scalar(personalization::PAIR_X, &[&*m]));
    let p = g * *a;
    MailboxKey::new(g, p, a)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::{open_first, seal_first, Message};
    use crate::receiver::testing::Wallet;
    use ff::Field;
    use rand::rngs::StdRng;
    use rand::SeedableRng;
    use std::collections::HashSet;

    /// A Conversation both sides share. Spec: ZIP § Envelopes (L225–231).
    fn conversation_pair() -> (Conversation, Conversation) {
        let me = Wallet::new(0).owned(0);
        let mut msg = Message::default();
        msg.expiry_time = u32::MAX;
        let (env, initiator) =
            seal_first(me.receiver(), &msg, &mut StdRng::seed_from_u64(7)).unwrap();
        let (_, responder) = open_first(&me, &env, 0, &mut HashSet::new()).unwrap();
        (initiator, responder)
    }

    /// Spec: ZIP § Mailboxes (L262–263): `[a] G == P` for a Mailbox key.
    fn assert_authorizes(key: &MailboxKey) {
        assert_eq!(key.g() * key.a(), *key.p());
        let (g, p) = key.id().points();
        assert_eq!((g, p), (*key.g(), *key.p()));
    }

    /// Spec: ZIP § Mailboxes (L266–270): `[a] G == P` with `a = ivk`, and the
    /// sender's and recipient's derivations agree.
    #[test]
    fn contact_mailbox_authorizes_with_ivk() {
        let w = Wallet::new(0);
        for j in [0u32, 1, 2] {
            let owned = w.owned(j);
            let key = contact_mailbox_key(&owned).unwrap();
            assert_authorizes(&key);
            assert_eq!(contact_mailbox_id(owned.receiver()).unwrap(), key.id());
        }
    }

    /// Spec: ZIP § Mailboxes (L266–268), § Privacy Implications (L120–121):
    /// diversified addresses of one wallet give unrelated Contact Mailbox IDs.
    /// Unlinkability rests on DDH; this checks that no half is shared and that
    /// neither half is `g_d` or `pk_d` of either address.
    #[test]
    fn diversified_contact_mailboxes_are_unrelated() {
        let w = Wallet::new(0);
        let a = w.owned(0);
        let b = w.owned(1);
        let ka = contact_mailbox_key(&a).unwrap();
        let kb = contact_mailbox_key(&b).unwrap();
        let (ga, pa) = ka.id().points();
        let (gb, pb) = kb.id().points();
        let halves = [ga, pa, gb, pb];
        for (i, x) in halves.iter().enumerate() {
            for y in &halves[i + 1..] {
                assert_ne!(x, y);
            }
            for r in [a.receiver(), b.receiver()] {
                assert_ne!(x, r.g_d());
                assert_ne!(x, r.pk_d());
            }
        }
        // Both are fetched with the same a = ivk, yet the IDs share nothing.
        assert_eq!(ka.a(), kb.a());
    }

    /// Spec: ZIP § Mailboxes (L272–277): both wallets derive the same Pairwise
    /// Mailbox, `[a] G == P`, and it changes with direction and epoch.
    #[test]
    fn pairwise_mailbox() {
        let (initiator, responder) = conversation_pair();
        let k = pairwise_mailbox_key(&initiator, Direction::Initiator, 100).unwrap();
        assert_authorizes(&k);
        assert_eq!(
            k.id(),
            pairwise_mailbox_key(&responder, Direction::Initiator, 100)
                .unwrap()
                .id()
        );
        let other_dir = pairwise_mailbox_key(&initiator, Direction::Responder, 100).unwrap();
        let other_epoch = pairwise_mailbox_key(&initiator, Direction::Initiator, 101).unwrap();
        assert_authorizes(&other_dir);
        assert_ne!(k.id(), other_dir.id());
        assert_ne!(k.id(), other_epoch.id());
    }

    /// Spec: ZIP § Mailboxes (L273): `m = κ || [δ] || I2LEOSP_32(e)`, checked
    /// against an independent recomputation.
    #[test]
    fn pairwise_mailbox_matches_definition() {
        let (initiator, _) = conversation_pair();
        let e: u32 = 0x0102_0304;
        let mut m = initiator.kappa().to_vec();
        m.push(1);
        m.extend_from_slice(&[0x04, 0x03, 0x02, 0x01]);
        let g = group_hash("z.cash:WalletMsg-pair", &m);
        let a = scalar(b"Zcash_WMsgPairX_", &[&m]);
        let k = pairwise_mailbox_key(&initiator, Direction::Responder, e).unwrap();
        assert_eq!((*k.g(), *k.p()), (g, g * a));
    }

    /// Spec: ZIP § Mailboxes (L277): `floor(t / 168)`.
    #[test]
    fn epoch_boundaries() {
        assert_eq!(epoch(0), 0);
        assert_eq!(epoch(167), 0);
        assert_eq!(epoch(168), 1);
        assert_eq!(epoch(168 * 5000 + 3), 5000);
        assert_eq!(epoch(u32::MAX), u32::MAX / 168);
    }

    /// Spec: ZIP § Mailboxes (L263–264): an identity `G` or `P` defines no mailbox,
    /// and such IDs do not parse.
    #[test]
    fn identity_rejected() {
        let g = pallas::Point::generator();
        let zero = Zeroizing::new(pallas::Scalar::ZERO);
        assert!(MailboxKey::new(g, pallas::Point::identity(), zero.clone()).is_none());
        assert!(MailboxKey::new(pallas::Point::identity(), g, zero).is_none());

        let good = contact_mailbox_key(&Wallet::new(0).owned(0)).unwrap().id();
        assert_eq!(MailboxId::from_bytes(good.as_bytes()), Some(good));
        let mut bad = *good.as_bytes();
        bad[..32].fill(0);
        assert!(MailboxId::from_bytes(&bad).is_none());
        let mut bad = *good.as_bytes();
        bad[32..].fill(0xff);
        assert!(MailboxId::from_bytes(&bad).is_none());
    }
}
