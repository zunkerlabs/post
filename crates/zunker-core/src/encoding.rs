//! Primitives shared by every part of the protocol.
//!
//! Spec: `spec/zip-draft-1435.md` § Specification / Notation (L170–190), plus the
//! Zcash Protocol Specification sections it references (§5.4.1.2 BLAKE2,
//! §4.2.3 ToScalar^Orchard, §5.4.3 Sym, §5.4.9.6 repr_P, §5.4.9.8 GroupHash^P).

use chacha20poly1305::{AeadInOut, ChaCha20Poly1305, KeyInit, Nonce, Tag};
use ff::FromUniformBytes;
use group::GroupEncoding;
use pasta_curves::arithmetic::CurveExt;
use pasta_curves::pallas;
use subtle::CtOption;

/// BLAKE2b personalizations used by the ZIP. Typing them as `&[u8; 16]` makes
/// a wrong length a compile error; `personalizations_are_exact` checks the text.
pub mod personalization {
    /// `esk = Scalar("Zcash_WMsgEsk___", seed)`. ZIP § Envelopes (L219).
    pub const ESK: &[u8; 16] = b"Zcash_WMsgEsk___";
    /// `K = BLAKE2b-256("Zcash_WMsgPairK_", ...)`. ZIP § Envelopes (L221).
    pub const PAIR_K: &[u8; 16] = b"Zcash_WMsgPairK_";
    /// `kappa = BLAKE2b-256("Zcash_WMsgPairS_", ...)`. ZIP § Envelopes (L227).
    pub const PAIR_S: &[u8; 16] = b"Zcash_WMsgPairS_";
    /// `r = Scalar("Zcash_WMsgMbxOrc", rcv)`. ZIP § Mailboxes (L268).
    pub const MBX_ORC: &[u8; 16] = b"Zcash_WMsgMbxOrc";
    /// `a = Scalar("Zcash_WMsgPairX_", m)`. ZIP § Mailboxes (L275).
    pub const PAIR_X: &[u8; 16] = b"Zcash_WMsgPairX_";
    /// Server selection hash. ZIP § Mailboxes (L282).
    pub const SRV_SEL: &[u8; 16] = b"Zcash_WMsgSrvSel";
    /// RedPallas `H*`. Protocol spec §5.4.7 (via ZIP § Mailbox Servers, L320).
    pub const RED_PALLAS_H: &[u8; 16] = b"Zcash_RedPallasH";
}

/// GroupHash^P domain for Pairwise Mailbox generators. ZIP § Mailboxes (L275).
pub const PAIRWISE_GROUP_HASH_DOMAIN: &str = "z.cash:WalletMsg-pair";

/// BLAKE2b-256 with a 16-byte personalization over the concatenation of `parts`.
///
/// Spec: ZIP § Notation (L172–173) → protocol spec §5.4.1.2.
pub fn blake2b_256(personalization: &[u8; 16], parts: &[&[u8]]) -> [u8; 32] {
    let mut state = blake2b_simd::Params::new()
        .hash_length(32)
        .personal(personalization)
        .to_state();
    for part in parts {
        state.update(part);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(state.finalize().as_bytes());
    out
}

/// BLAKE2b-512 with a 16-byte personalization over the concatenation of `parts`.
///
/// Spec: ZIP § Notation (L172–173) → protocol spec §5.4.1.2.
pub fn blake2b_512(personalization: &[u8; 16], parts: &[&[u8]]) -> [u8; 64] {
    let mut state = blake2b_simd::Params::new()
        .hash_length(64)
        .personal(personalization)
        .to_state();
    for part in parts {
        state.update(part);
    }
    let mut out = [0u8; 64];
    out.copy_from_slice(state.finalize().as_bytes());
    out
}

/// `ToScalar^Orchard(x) = LEOS2IP_512(x) mod r_P`.
///
/// Spec: ZIP § Notation (L174) → protocol spec §4.2.3.
pub fn to_scalar(x: &[u8; 64]) -> pallas::Scalar {
    pallas::Scalar::from_uniform_bytes(x)
}

/// `Scalar(p, x) = ToScalar^Orchard(BLAKE2b-512(p, x))`, with `x` the
/// concatenation of `parts`.
///
/// Spec: ZIP § Notation (L181).
pub fn scalar(personalization: &[u8; 16], parts: &[&[u8]]) -> pallas::Scalar {
    let mut h = blake2b_512(personalization, parts);
    let s = to_scalar(&h);
    zeroize::Zeroize::zeroize(&mut h);
    s
}

/// `PointBytes(Q) = LEBS2OSP_256(repr_P(Q))`. The identity encodes as 32 zero bytes.
///
/// Spec: ZIP § Notation (L180) → protocol spec §5.4.9.6.
pub fn point_bytes(q: &pallas::Point) -> [u8; 32] {
    q.to_bytes()
}

/// Inverse of [`point_bytes`]: `abst_P`, rejecting non-canonical encodings.
/// The identity is accepted; callers that need a non-identity point check it.
///
/// Spec: ZIP § Notation (L176–177) → protocol spec §5.4.9.6.
pub fn point_from_bytes(bytes: &[u8; 32]) -> CtOption<pallas::Point> {
    pallas::Point::from_bytes(bytes)
}

/// `GroupHash^P(D, M)`: hash-to-curve into Pallas with domain prefix `D`.
///
/// Spec: ZIP § Notation (L175) → protocol spec §5.4.9.8.
pub fn group_hash(domain: &str, msg: &[u8]) -> pallas::Point {
    pallas::Point::hash_to_curve(domain)(msg)
}

/// Length of the Poly1305 tag appended by [`sym_encrypt`].
pub const TAG_LEN: usize = 16;

/// `Sym.Encrypt_K(P)`: AEAD_CHACHA20_POLY1305 with an all-zero nonce and empty
/// associated data, encrypting `buf` in place and returning the 16-byte tag.
///
/// The all-zero nonce is safe only because every key passed here is used for
/// exactly one encryption. In this protocol each `K` is derived from a fresh
/// `ephemeralKey` (ZIP § Envelopes, L219–223), so a key is never reused.
///
/// Spec: ZIP § Notation (L174) → protocol spec §5.4.3.
pub fn sym_encrypt(key: &[u8; 32], buf: &mut [u8]) -> [u8; TAG_LEN] {
    let cipher = ChaCha20Poly1305::new(key.into());
    let tag = cipher
        .encrypt_inout_detached(&Nonce::default(), &[], buf.into())
        .expect("ChaCha20-Poly1305 accepts any plaintext length used by this protocol");
    let mut out = [0u8; TAG_LEN];
    out.copy_from_slice(&tag);
    out
}

/// `Sym.Decrypt_K(C)`: inverse of [`sym_encrypt`]. On success `buf` holds the
/// plaintext; on failure it is left as ciphertext and `false` is returned.
/// Single-use keys make the all-zero nonce safe, as for [`sym_encrypt`].
///
/// Spec: ZIP § Notation (L174) → protocol spec §5.4.3.
pub fn sym_decrypt(key: &[u8; 32], buf: &mut [u8], tag: &[u8; TAG_LEN]) -> bool {
    let cipher = ChaCha20Poly1305::new(key.into());
    let tag = Tag::from(*tag);
    cipher
        .decrypt_inout_detached(&Nonce::default(), &[], buf.into(), &tag)
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ff::{Field, PrimeField};
    use group::Group;

    /// ZIP § Notation / § Envelopes / § Mailboxes: personalizations as written.
    #[test]
    fn personalizations_are_exact() {
        use personalization::*;
        let expected: [(&[u8; 16], &str); 7] = [
            (ESK, "Zcash_WMsgEsk___"),
            (PAIR_K, "Zcash_WMsgPairK_"),
            (PAIR_S, "Zcash_WMsgPairS_"),
            (MBX_ORC, "Zcash_WMsgMbxOrc"),
            (PAIR_X, "Zcash_WMsgPairX_"),
            (SRV_SEL, "Zcash_WMsgSrvSel"),
            (RED_PALLAS_H, "Zcash_RedPallasH"),
        ];
        for (p, s) in expected {
            assert_eq!(s.len(), 16, "{s}");
            assert_eq!(&p[..], s.as_bytes());
        }
    }

    /// Protocol spec §5.4.1.2: personalization and output length change the hash,
    /// and multi-part input equals concatenated input.
    #[test]
    fn blake2b_personalized() {
        let a = blake2b_256(personalization::PAIR_K, &[b"abc"]);
        let b = blake2b_256(personalization::PAIR_S, &[b"abc"]);
        assert_ne!(a, b);
        assert_eq!(a, blake2b_256(personalization::PAIR_K, &[b"a", b"bc"]));
        let reference = blake2b_simd::Params::new()
            .hash_length(32)
            .personal(b"Zcash_WMsgPairK_")
            .hash(b"abc");
        assert_eq!(&a[..], reference.as_bytes());
        let wide = blake2b_512(personalization::PAIR_K, &[b"abc"]);
        assert_ne!(&wide[..32], &a[..]);
    }

    /// Protocol spec §4.2.3: ToScalar is little-endian and reduces mod r_P.
    #[test]
    fn to_scalar_is_le_mod_q() {
        let mut x = [0u8; 64];
        x[0] = 5;
        assert_eq!(to_scalar(&x), pallas::Scalar::from(5u64));

        // r_P itself reduces to zero, r_P + 1 to one.
        let mut q = [0u8; 64];
        q[..32].copy_from_slice((-pallas::Scalar::ONE).to_repr().as_ref());
        q[0] += 1; // -1 + 1 = r_P (no carry: low byte of r_P - 1 is 0x00)
        assert_eq!(to_scalar(&q), pallas::Scalar::ZERO);
        q[0] += 1;
        assert_eq!(to_scalar(&q), pallas::Scalar::ONE);

        // 2^256 mod r_P, from the high half.
        let mut hi = [0u8; 64];
        hi[32] = 1;
        let two_256 = pallas::Scalar::from(2u64).pow_vartime([256u64]);
        assert_eq!(to_scalar(&hi), two_256);
    }

    /// ZIP § Notation (L181): Scalar(p, x) = ToScalar(BLAKE2b-512(p, x)).
    #[test]
    fn scalar_matches_definition() {
        let h = blake2b_512(personalization::ESK, &[&[7u8; 32]]);
        assert_eq!(scalar(personalization::ESK, &[&[7u8; 32]]), to_scalar(&h));
    }

    /// ZIP § Notation (L180): PointBytes round-trips; identity is all zeros.
    #[test]
    fn point_bytes_round_trip() {
        let g = pallas::Point::generator() * pallas::Scalar::from(1234u64);
        let enc = point_bytes(&g);
        assert_eq!(point_from_bytes(&enc).unwrap(), g);
        assert_eq!(point_bytes(&pallas::Point::identity()), [0u8; 32]);
        // An x-coordinate >= p is not canonical.
        assert!(bool::from(point_from_bytes(&[0xff; 32]).is_none()));
    }

    /// Protocol spec §5.4.9.8: GroupHash is deterministic and domain-separated.
    #[test]
    fn group_hash_domain_separated() {
        let a = group_hash(PAIRWISE_GROUP_HASH_DOMAIN, b"m");
        assert_eq!(a, group_hash(PAIRWISE_GROUP_HASH_DOMAIN, b"m"));
        assert_ne!(a, group_hash("z.cash:Orchard-gd", b"m"));
        assert_ne!(a, group_hash(PAIRWISE_GROUP_HASH_DOMAIN, b"n"));
        assert!(!bool::from(a.is_identity()));
    }

    /// Protocol spec §5.4.3: Sym round-trips and rejects tampering or a wrong key.
    #[test]
    fn sym_round_trip_and_tamper() {
        let key = [9u8; 32];
        let mut buf = b"wallet to wallet".to_vec();
        let tag = sym_encrypt(&key, &mut buf);
        assert_ne!(&buf[..], b"wallet to wallet");

        let mut ok = buf.clone();
        assert!(sym_decrypt(&key, &mut ok, &tag));
        assert_eq!(&ok[..], b"wallet to wallet");

        let mut flipped = buf.clone();
        flipped[0] ^= 1;
        assert!(!sym_decrypt(&key, &mut flipped, &tag));

        let mut wrong_key = buf.clone();
        assert!(!sym_decrypt(&[8u8; 32], &mut wrong_key, &tag));
    }

    /// Protocol spec §5.4.3: known answer for key = 0, nonce = 0, empty plaintext.
    /// The expected tag was computed independently from the RFC 8439 definitions
    /// (ChaCha20 zero-key keystream as in RFC 8439 A.1 #1, then Poly1305 over the
    /// 16-byte length block).
    #[test]
    fn sym_zero_nonce_known_answer() {
        let mut empty: [u8; 0] = [];
        let tag = sym_encrypt(&[0u8; 32], &mut empty);
        assert_eq!(
            tag,
            [
                0x4e, 0xb9, 0x72, 0xc9, 0xa8, 0xfb, 0x3a, 0x1b, 0x38, 0x2b, 0xb4, 0xd3, 0x6f, 0x5f,
                0xfa, 0xd1
            ]
        );
    }
}
