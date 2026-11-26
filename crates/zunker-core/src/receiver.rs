//! Orchard inputs, taken from their raw encodings.
//!
//! The `orchard` crate exposes `Address::to_raw_address_bytes` and
//! `IncomingViewingKey::to_bytes` publicly, but `g_d`, `pk_d` and
//! `diversify_hash` are `pub(crate)`. Rather than fork it, this module parses the
//! raw encodings and reimplements `DiversifyHash^Orchard` from the protocol spec;
//! the tests cross-check `[ivk] g_d == pk_d` against addresses the `orchard`
//! crate generates.
//!
//! Spec: `spec/zip-draft-1435.md` § Notation (L187–190), protocol spec §5.4.1.6,
//! §5.6.4.2 and §5.6.4.3.

use core::fmt;

use ff::{Field, PrimeField};
use group::Group;
use pasta_curves::pallas;
use subtle::{ConditionallySelectable, ConstantTimeEq, CtOption};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::encoding::{group_hash, point_from_bytes};

/// GroupHash^P domain of `DiversifyHash^Orchard`. Protocol spec §5.4.1.6.
const ORCHARD_GD_DOMAIN: &str = "z.cash:Orchard-gd";

/// `DiversifyHash^Orchard(d)`: `GroupHash^P("z.cash:Orchard-gd", d)`, replaced by
/// `GroupHash^P("z.cash:Orchard-gd", "")` if that is the identity. Never the identity.
///
/// Spec: ZIP § Notation (L190) → protocol spec §5.4.1.6.
pub fn diversify_hash(d: &[u8; 11]) -> pallas::Point {
    non_identity_or_fallback(group_hash(ORCHARD_GD_DOMAIN, d))
}

/// The identity substitution step of `DiversifyHash^Orchard`, done in constant time.
///
/// Spec: protocol spec §5.4.1.6.
fn non_identity_or_fallback(h: pallas::Point) -> pallas::Point {
    let fallback = group_hash(ORCHARD_GD_DOMAIN, &[]);
    pallas::Point::conditional_select(&h, &fallback, h.is_identity())
}

/// An Orchard Receiver `(d, pk_d)` with raw encoding `rcv`, and `g_d`.
///
/// Spec: ZIP § Notation (L187–190) → protocol spec §5.6.4.2.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Receiver {
    raw: [u8; 43],
    g_d: pallas::Point,
    pk_d: pallas::Point,
}

impl Receiver {
    /// Parses the 43-byte raw encoding `d || repr_P(pk_d)`. Returns `None` if
    /// `pk_d` is not the canonical encoding of a non-identity Pallas point.
    ///
    /// Spec: protocol spec §5.6.4.2 (`KA^Orchard.Public` is `P*`).
    pub fn from_raw(raw: &[u8; 43]) -> Option<Self> {
        let mut d = [0u8; 11];
        d.copy_from_slice(&raw[..11]);
        let mut pk_bytes = [0u8; 32];
        pk_bytes.copy_from_slice(&raw[11..]);
        let pk_d = point_from_bytes(&pk_bytes);
        let valid = pk_d.and_then(|p| CtOption::new(p, !p.is_identity()));
        Option::from(valid).map(|pk_d| Receiver {
            raw: *raw,
            g_d: diversify_hash(&d),
            pk_d,
        })
    }

    /// The raw encoding `rcv`. Spec: ZIP § Notation (L187–188).
    pub fn raw(&self) -> &[u8; 43] {
        &self.raw
    }

    /// `g_d = DiversifyHash^Orchard(d)`. Spec: ZIP § Notation (L190).
    pub fn g_d(&self) -> &pallas::Point {
        &self.g_d
    }

    /// `pk_d`. Spec: ZIP § Notation (L187).
    pub fn pk_d(&self) -> &pallas::Point {
        &self.pk_d
    }
}

impl fmt::Debug for Receiver {
    /// Spec: none (diagnostics only).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Receiver").finish_non_exhaustive()
    }
}

/// The `ivk` component of an Orchard incoming viewing key, as a Pallas scalar.
/// Zeroized on drop.
///
/// Spec: ZIP § Notation (L189) → protocol spec §5.6.4.3.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct IncomingViewingKey {
    ivk: pallas::Scalar,
}

impl IncomingViewingKey {
    /// Parses the 64-byte raw encoding `dk || I2LEOSP_256(ivk)`. Returns `None`
    /// unless `ivk` is a canonical, nonzero Pallas base field element. `dk` is not
    /// needed by this protocol and is ignored.
    ///
    /// Spec: protocol spec §5.6.4.3. `ivk` lies in `{1 .. q_P - 1}`, and since
    /// `q_P < r_P` it is used unchanged as a scalar (protocol spec §5.4.5.5).
    pub fn from_bytes(bytes: &[u8; 64]) -> Option<Self> {
        let mut repr = [0u8; 32];
        repr.copy_from_slice(&bytes[32..]);
        let base = pallas::Base::from_repr(repr);
        let scalar = base.and_then(|b| {
            let s = pallas::Scalar::from_repr(b.to_repr());
            s.and_then(|s| CtOption::new(s, !b.is_zero()))
        });
        repr.zeroize();
        Option::from(scalar).map(|ivk| IncomingViewingKey { ivk })
    }

    /// The scalar `ivk`. Spec: ZIP § Notation (L189).
    pub(crate) fn scalar(&self) -> &pallas::Scalar {
        &self.ivk
    }
}

impl fmt::Debug for IncomingViewingKey {
    /// Spec: none (diagnostics only; never prints the key).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("IncomingViewingKey(..)")
    }
}

/// A Receiver together with the incoming viewing key that owns it, checked by
/// `[ivk] g_d == pk_d`. This is what a recipient needs to open first Envelopes
/// and fetch its Contact Mailbox.
///
/// Spec: ZIP § Envelopes (L229–231), § Mailboxes (L266–270).
#[derive(Clone)]
pub struct OwnedReceiver {
    receiver: Receiver,
    ivk: IncomingViewingKey,
}

impl OwnedReceiver {
    /// Pairs `receiver` with `ivk`, returning `None` unless `[ivk] g_d == pk_d`
    /// (compared in constant time).
    ///
    /// Spec: protocol spec §4.2.3 (`pk_d = KA^Orchard.DerivePublic(ivk, g_d)`).
    pub fn new(ivk: IncomingViewingKey, receiver: Receiver) -> Option<Self> {
        let derived = receiver.g_d * ivk.scalar();
        if bool::from(derived.ct_eq(&receiver.pk_d)) {
            Some(OwnedReceiver { receiver, ivk })
        } else {
            None
        }
    }

    /// The Receiver. Spec: ZIP § Notation (L187).
    pub fn receiver(&self) -> &Receiver {
        &self.receiver
    }

    /// The incoming viewing key. Spec: ZIP § Notation (L189).
    pub fn ivk(&self) -> &IncomingViewingKey {
        &self.ivk
    }
}

impl fmt::Debug for OwnedReceiver {
    /// Spec: none (diagnostics only).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OwnedReceiver").finish_non_exhaustive()
    }
}

/// Test fixtures built with the `orchard` crate.
#[cfg(test)]
pub(crate) mod testing {
    use orchard::keys::{FullViewingKey, Scope, SpendingKey};

    /// A wallet: raw IVK encoding and a way to derive raw receivers.
    /// Spec: protocol spec §4.2.3 (key derivation is the orchard crate's).
    pub(crate) struct Wallet {
        fvk: FullViewingKey,
    }

    impl Wallet {
        /// Deterministic wallet number `n`. Spec: protocol spec §4.2.3.
        pub(crate) fn new(n: u8) -> Self {
            let sk = (0u8..=255)
                .find_map(|i| {
                    let bytes: [u8; 32] = [n, i, 0x5a, 0xa5].repeat(8).try_into().unwrap();
                    SpendingKey::from_bytes(bytes).into_option()
                })
                .expect("some spending key bytes are valid");
            Wallet {
                fvk: FullViewingKey::from(&sk),
            }
        }

        /// Raw 64-byte external IVK. Spec: protocol spec §5.6.4.3.
        pub(crate) fn ivk_bytes(&self) -> [u8; 64] {
            self.fvk.to_ivk(Scope::External).to_bytes()
        }

        /// Raw 64-byte IVK for `scope`. Spec: protocol spec §5.6.4.3.
        pub(crate) fn ivk_bytes_for(&self, scope: Scope) -> [u8; 64] {
            self.fvk.to_ivk(scope).to_bytes()
        }

        /// Raw 43-byte receiver for `scope` at index `j`. Spec: protocol spec §5.6.4.2.
        pub(crate) fn receiver_bytes_for(&self, j: u32, scope: Scope) -> [u8; 43] {
            self.fvk.address_at(j, scope).to_raw_address_bytes()
        }

        /// Raw 43-byte external receiver at diversifier index `j`.
        /// Spec: protocol spec §5.6.4.2.
        pub(crate) fn receiver_bytes(&self, j: u32) -> [u8; 43] {
            self.fvk
                .address_at(j, Scope::External)
                .to_raw_address_bytes()
        }

        /// Parsed owned receiver at index `j`. Spec: ZIP § Notation (L187–190).
        pub(crate) fn owned(&self, j: u32) -> super::OwnedReceiver {
            let ivk = super::IncomingViewingKey::from_bytes(&self.ivk_bytes()).unwrap();
            let rcv = super::Receiver::from_raw(&self.receiver_bytes(j)).unwrap();
            super::OwnedReceiver::new(ivk, rcv).expect("orchard-generated receiver")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::Wallet;
    use super::*;
    use orchard::keys::Scope;

    /// Cross-check: for orchard-generated addresses, our `g_d` satisfies
    /// `[ivk] g_d == pk_d`. Protocol spec §4.2.3, §5.4.1.6.
    #[test]
    fn ivk_times_gd_is_pk_d() {
        for n in 0..3 {
            let w = Wallet::new(n);
            let ivk = IncomingViewingKey::from_bytes(&w.ivk_bytes()).unwrap();
            for j in [0u32, 1, 7, 1000, u32::MAX] {
                let rcv = Receiver::from_raw(&w.receiver_bytes(j)).unwrap();
                assert_eq!(
                    rcv.g_d() * ivk.scalar(),
                    *rcv.pk_d(),
                    "wallet {n} index {j}"
                );
                assert!(OwnedReceiver::new(ivk.clone(), rcv).is_some());
                assert_eq!(w.owned(j).receiver(), &rcv);
            }
        }
    }

    /// Internal-scope addresses use the internal IVK; the external IVK must not
    /// claim them. Protocol spec §4.2.3.
    #[test]
    fn scopes_are_distinct() {
        let w = Wallet::new(3);
        let rcv = Receiver::from_raw(&w.receiver_bytes_for(0, Scope::Internal)).unwrap();
        let int = IncomingViewingKey::from_bytes(&w.ivk_bytes_for(Scope::Internal)).unwrap();
        let ext = IncomingViewingKey::from_bytes(&w.ivk_bytes_for(Scope::External)).unwrap();
        assert!(OwnedReceiver::new(int, rcv).is_some());
        assert!(OwnedReceiver::new(ext, rcv).is_none());
    }

    /// A different wallet's IVK does not own the receiver. Protocol spec §4.2.3.
    #[test]
    fn foreign_ivk_rejected() {
        let a = Wallet::new(0);
        let b = Wallet::new(1);
        let ivk_b = IncomingViewingKey::from_bytes(&b.ivk_bytes()).unwrap();
        let rcv_a = Receiver::from_raw(&a.receiver_bytes(0)).unwrap();
        assert!(OwnedReceiver::new(ivk_b, rcv_a).is_none());
    }

    /// Raw receiver encoding round-trips and rejects a bad or identity `pk_d`.
    /// Protocol spec §5.6.4.2.
    #[test]
    fn receiver_parsing() {
        let raw = Wallet::new(0).receiver_bytes(0);
        assert_eq!(Receiver::from_raw(&raw).unwrap().raw(), &raw);

        let mut identity = raw;
        identity[11..].fill(0);
        assert!(Receiver::from_raw(&identity).is_none());

        let mut non_canonical = raw;
        non_canonical[11..].fill(0xff);
        assert!(Receiver::from_raw(&non_canonical).is_none());
    }

    /// IVK parsing rejects zero and non-canonical `ivk`. Protocol spec §5.6.4.3.
    #[test]
    fn ivk_parsing() {
        let mut zero = Wallet::new(0).ivk_bytes();
        zero[32..].fill(0);
        assert!(IncomingViewingKey::from_bytes(&zero).is_none());

        let mut big = Wallet::new(0).ivk_bytes();
        big[32..].fill(0xff);
        assert!(IncomingViewingKey::from_bytes(&big).is_none());
    }

    /// `DiversifyHash^Orchard` substitutes the fallback point for the identity.
    /// Protocol spec §5.4.1.6.
    #[test]
    fn diversify_hash_fallback() {
        let fallback = group_hash(ORCHARD_GD_DOMAIN, &[]);
        assert_eq!(
            non_identity_or_fallback(pallas::Point::identity()),
            fallback
        );
        let h = group_hash(ORCHARD_GD_DOMAIN, &[1u8; 11]);
        assert_eq!(non_identity_or_fallback(h), h);
        assert_eq!(diversify_hash(&[1u8; 11]), h);
        assert!(!bool::from(fallback.is_identity()));
    }
}
