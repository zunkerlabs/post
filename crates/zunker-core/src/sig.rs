//! Fetch request signatures: RedPallas with a per-mailbox generator `G`.
//!
//! The ZIP replaces RedPallas's fixed generator with the Mailbox's `G`, so the
//! `reddsa` crate (whose basepoint is fixed) is not used; this is RedDSA from
//! protocol spec §5.4.7 written out with `G` as a parameter.
//!
//! Spec: `spec/zip-draft-1435.md` § Mailbox Servers (L307–330), protocol spec
//! §5.4.7.

use ff::PrimeField;
use group::Group;

use pasta_curves::pallas;
use rand_core::CryptoRng;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::encoding::{blake2b_512, personalization, point_bytes, point_from_bytes, to_scalar};
use crate::mailbox::{MailboxId, MailboxKey};

/// Request type byte of a Deposit. ZIP § Mailbox Servers (L311).
pub const DEPOSIT: u8 = 1;
/// Request type byte of a Fetch. ZIP § Mailbox Servers (L312).
pub const FETCH: u8 = 2;

/// `[2] || mailbox_id || after || time`. ZIP § Mailbox Servers (L312).
const FETCH_UNSIGNED_LEN: usize = 1 + 64 + 8 + 4;
/// A Fetch request with `sig`. ZIP § Mailbox Servers (L312).
pub const FETCH_LEN: usize = FETCH_UNSIGNED_LEN + 64;

/// Bytes of randomness `T`: `(ℓ_H + 128) / 8` with `ℓ_H = 512`. Protocol spec §5.4.7.
const T_LEN: usize = 80;

/// Bytes of `T` always taken from the operating system's random generator,
/// whatever RNG the caller passes. ZIP § Mailbox Servers (L322–324).
const T_OS_LEN: usize = 32;
const _: () = assert!(T_OS_LEN >= 32 && T_OS_LEN < T_LEN);

/// The operating system's random generator failed, so no signature was made.
///
/// Spec: ZIP § Mailbox Servers (L322–324): `T` needs fresh randomness.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OsRandomUnavailable;

impl core::fmt::Display for OsRandomUnavailable {
    /// Spec: none (diagnostics only).
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("operating system random generator unavailable")
    }
}

impl std::error::Error for OsRandomUnavailable {}

/// `H*(B) = ToScalar^Orchard(BLAKE2b-512("Zcash_RedPallasH", B))`.
///
/// Spec: protocol spec §5.4.7 (RedPallas `H*`), §4.2.3 (ToScalar).
fn h_star(parts: &[&[u8]]) -> pallas::Scalar {
    let mut h = Zeroizing::new(blake2b_512(personalization::RED_PALLAS_H, parts));
    let s = to_scalar(&h);
    h.iter_mut().for_each(|b| *b = 0);
    s
}

/// `RedDSA.Sign` with generator `G`, signing key `a`, validating key `P = [a]G`,
/// given the random input `T`.
///
/// The nonce is `H*(LEBS2OSP(a) || T || M)`. Protocol spec §5.4.7 uses
/// `H*(T || vkBytes || M)`; including `a` follows the ZIP's advice that `T`
/// depend on `a` as well as on fresh randomness, so a repeated or predictable
/// `T` alone does not reveal `a`. Verifiers cannot tell the difference.
///
/// Spec: ZIP § Mailbox Servers (L320–324), protocol spec §5.4.7.
fn sign_with_t(
    g: &pallas::Point,
    a: &pallas::Scalar,
    p: &pallas::Point,
    msg: &[u8],
    t: &[u8; T_LEN],
) -> [u8; 64] {
    let a_bytes = Zeroizing::new(a.to_repr());
    let nonce = Zeroizing::new(h_star(&[a_bytes.as_ref(), t, msg]));
    let r_bytes = point_bytes(&(g * *nonce));
    let c = h_star(&[&r_bytes, &point_bytes(p), msg]);
    // c·a reveals a given c, so it is wiped like the nonce.
    let ca = Zeroizing::new(c * a);
    let s = Zeroizing::new(*nonce + *ca);
    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(&r_bytes);
    sig[32..].copy_from_slice(&s.to_repr());
    sig
}

/// `RedDSA.Sign` with generator `G`, sampling a fresh `T`: the first 32 bytes
/// always come from the operating system's random generator, the other 48
/// from `rng`, so a weak or seeded `rng` cannot make `T` predictable.
///
/// Spec: ZIP § Mailbox Servers (L320–324), protocol spec §5.4.7.
fn sign<R: CryptoRng + ?Sized>(
    g: &pallas::Point,
    a: &pallas::Scalar,
    p: &pallas::Point,
    msg: &[u8],
    rng: &mut R,
) -> Result<[u8; 64], OsRandomUnavailable> {
    let mut t = Zeroizing::new([0u8; T_LEN]);
    getrandom::fill(&mut t[..T_OS_LEN]).map_err(|_| OsRandomUnavailable)?;
    rng.fill_bytes(&mut t[T_OS_LEN..]);
    Ok(sign_with_t(g, a, p, msg, &t))
}

/// `RedDSA.Validate` with generator `G`: rejects a non-canonical `R̄`,
/// `S ≥ r_P`, and an identity `R`, `P` or `G`, and otherwise accepts iff
/// `[S] G == R + [c] P` with `c = H*(R̄ || repr(P) || M)` (the Pallas
/// cofactor is 1).
///
/// Spec: ZIP § Mailbox Servers (L320–322), protocol spec §5.4.7.
fn verify(g: &pallas::Point, p: &pallas::Point, msg: &[u8], sig: &[u8; 64]) -> bool {
    let mut r_bytes = [0u8; 32];
    let mut s_bytes = [0u8; 32];
    r_bytes.copy_from_slice(&sig[..32]);
    s_bytes.copy_from_slice(&sig[32..]);
    let Some(r) = Option::<pallas::Point>::from(point_from_bytes(&r_bytes)) else {
        return false;
    };
    let Some(s) = Option::<pallas::Scalar>::from(pallas::Scalar::from_repr(s_bytes)) else {
        return false;
    };
    if bool::from(r.is_identity() | p.is_identity() | g.is_identity()) {
        return false;
    }
    let c = h_star(&[&r_bytes, &point_bytes(p), msg]);
    bool::from((g * s).ct_eq(&(r + p * c)))
}

/// A Fetch request: return Envelopes under `mailbox_id` with `seq > after`.
///
/// Spec: ZIP § Mailbox Servers (L309–318).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FetchRequest {
    /// The Mailbox to fetch from.
    pub mailbox_id: MailboxId,
    /// The last `seq` received, or 0.
    pub after: u64,
    /// The wallet's clock, in hours since the Unix epoch.
    pub time: u32,
}

impl FetchRequest {
    /// `[2] || mailbox_id || after || time`, little-endian: the request without
    /// `sig`.
    ///
    /// Spec: ZIP § Mailbox Servers (L312, L321–322), § Notation (L184).
    fn unsigned_bytes(&self) -> [u8; FETCH_UNSIGNED_LEN] {
        let mut out = [0u8; FETCH_UNSIGNED_LEN];
        out[0] = FETCH;
        out[1..65].copy_from_slice(self.mailbox_id.as_bytes());
        out[65..73].copy_from_slice(&self.after.to_le_bytes());
        out[73..77].copy_from_slice(&self.time.to_le_bytes());
        out
    }

    /// The signed message: `server_id` followed by the request without `sig`.
    ///
    /// Spec: ZIP § Mailbox Servers (L321–322).
    fn signed_message(&self, server_id: &[u8; 32]) -> [u8; 32 + FETCH_UNSIGNED_LEN] {
        let mut msg = [0u8; 32 + FETCH_UNSIGNED_LEN];
        msg[..32].copy_from_slice(server_id);
        msg[32..].copy_from_slice(&self.unsigned_bytes());
        msg
    }

    /// Builds and signs a Fetch for `key`'s mailbox, addressed to `server_id`.
    /// Returns the full request bytes, ending in `sig`. `T` takes 32 bytes from
    /// the operating system's random generator in addition to `rng`.
    ///
    /// Spec: ZIP § Mailbox Servers (L312, L320–324).
    pub fn sign<R: CryptoRng + ?Sized>(
        key: &MailboxKey,
        after: u64,
        time: u32,
        server_id: &[u8; 32],
        rng: &mut R,
    ) -> Result<[u8; FETCH_LEN], OsRandomUnavailable> {
        let req = FetchRequest {
            mailbox_id: key.id(),
            after,
            time,
        };
        let sig = sign(
            key.g(),
            key.a(),
            key.p(),
            &req.signed_message(server_id),
            rng,
        )?;
        let mut out = [0u8; FETCH_LEN];
        out[..FETCH_UNSIGNED_LEN].copy_from_slice(&req.unsigned_bytes());
        out[FETCH_UNSIGNED_LEN..].copy_from_slice(&sig);
        Ok(out)
    }

    /// Server side: parses and checks a Fetch addressed to `server_id` at server
    /// time `now` (hours). Returns `None`, and the server MUST then drop the
    /// request without responding, if it is malformed, either half of
    /// `mailbox_id` is not a non-identity point, `time` is more than an hour
    /// from `now`, or `sig` does not validate.
    ///
    /// Spec: ZIP § Mailbox Servers (L312, L320–330).
    pub fn verify(server_id: &[u8; 32], request: &[u8], now: u32) -> Option<FetchRequest> {
        let request: &[u8; FETCH_LEN] = request.try_into().ok()?;
        if request[0] != FETCH {
            return None;
        }
        let mut id = [0u8; 64];
        id.copy_from_slice(&request[1..65]);
        let mailbox_id = MailboxId::from_bytes(&id)?;
        let mut after = [0u8; 8];
        after.copy_from_slice(&request[65..73]);
        let mut time = [0u8; 4];
        time.copy_from_slice(&request[73..77]);
        let req = FetchRequest {
            mailbox_id,
            after: u64::from_le_bytes(after),
            time: u32::from_le_bytes(time),
        };
        if req.time.abs_diff(now) > 1 {
            return None;
        }
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&request[FETCH_UNSIGNED_LEN..]);
        let (g, p) = mailbox_id.points();
        verify(&g, &p, &req.signed_message(server_id), &sig).then_some(req)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mailbox::{contact_mailbox_key, MailboxKey};
    use crate::receiver::testing::Wallet;
    use ff::Field;
    use group::Group;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    const SERVER_A: [u8; 32] = [0xaa; 32];
    const SERVER_B: [u8; 32] = [0xbb; 32];
    const NOW: u32 = 500_000;

    /// Test fixture. Spec: none.
    fn rng() -> StdRng {
        StdRng::seed_from_u64(312)
    }

    /// A random generator, key, and validating key. Spec: ZIP § Mailboxes (L262–263).
    fn keypair(rng: &mut StdRng) -> (pallas::Point, pallas::Scalar, pallas::Point) {
        let g = pallas::Point::random(&mut *rng);
        let a = pallas::Scalar::random(&mut *rng);
        assert!(!bool::from(g.is_identity()));
        (g, a, g * a)
    }

    /// The Contact Mailbox of wallet 0, address 0. Spec: ZIP § Mailboxes (L266–270).
    fn mailbox() -> MailboxKey {
        contact_mailbox_key(&Wallet::new(0).owned(0)).unwrap()
    }

    /// Spec: protocol spec §5.4.7: sign then verify with generator `G`.
    #[test]
    fn sign_verify() {
        let mut rng = rng();
        let (g, a, p) = keypair(&mut rng);
        let sig = sign(&g, &a, &p, b"msg", &mut rng).unwrap();
        assert!(verify(&g, &p, b"msg", &sig));
        assert!(!verify(&g, &p, b"msh", &sig));
    }

    /// Spec: protocol spec §5.4.7: a signature by another key, or checked
    /// against another validating key or generator, fails.
    #[test]
    fn wrong_key_fails() {
        let mut rng = rng();
        let (g, a, p) = keypair(&mut rng);
        let (g2, a2, p2) = keypair(&mut rng);
        let sig = sign(&g, &a, &p, b"msg", &mut rng).unwrap();
        assert!(!verify(&g, &p2, b"msg", &sig));
        assert!(!verify(&g2, &p, b"msg", &sig));
        assert!(!verify(&pallas::Point::generator(), &p, b"msg", &sig));
        // Signing with the wrong scalar for P.
        let forged = sign(&g, &a2, &p, b"msg", &mut rng).unwrap();
        assert!(!verify(&g, &p, b"msg", &forged));
    }

    /// Spec: ZIP § Mailbox Servers (L323–324): `T` (here visible as `R`) differs
    /// across signatures of the same message, and the nonce depends on `a` even
    /// for a repeated `T`.
    #[test]
    fn nonce_is_fresh_and_hedged() {
        let mut rng = rng();
        let (g, a, p) = keypair(&mut rng);
        let s1 = sign(&g, &a, &p, b"msg", &mut rng).unwrap();
        let s2 = sign(&g, &a, &p, b"msg", &mut rng).unwrap();
        assert_ne!(s1[..32], s2[..32]);
        assert!(verify(&g, &p, b"msg", &s1) && verify(&g, &p, b"msg", &s2));

        let t = [7u8; T_LEN];
        let (_, a2, _) = keypair(&mut rng);
        let p2 = g * a2;
        let same_t_1 = sign_with_t(&g, &a, &p, b"msg", &t);
        let same_t_2 = sign_with_t(&g, &a2, &p2, b"msg", &t);
        assert_ne!(same_t_1[..32], same_t_2[..32]);
        assert_eq!(same_t_1, sign_with_t(&g, &a, &p, b"msg", &t));
    }

    /// Spec: protocol spec §5.4.7: a non-canonical `R̄`, or `S ≥ r_P`, is
    /// rejected, including `S + r_P`, which would verify if it were reduced.
    #[test]
    fn non_canonical_rejected() {
        let mut rng = rng();
        let (g, a, p) = keypair(&mut rng);
        let sig = sign(&g, &a, &p, b"msg", &mut rng).unwrap();

        let mut bad_r = sig;
        bad_r[..32].fill(0xff);
        assert!(!verify(&g, &p, b"msg", &bad_r));

        let mut max_s = sig;
        max_s[32..].fill(0xff);
        assert!(!verify(&g, &p, b"msg", &max_s));

        // r_P = (r_P - 1) + 1; S + r_P < 2^256 because S < r_P < 2^255.
        let mut q = (-pallas::Scalar::ONE).to_repr();
        q[0] += 1; // the low byte of r_P - 1 is 0x00
        let mut s_plus_q = sig;
        let mut carry = 0u16;
        for i in 0..32 {
            let v = u16::from(sig[32 + i]) + u16::from(q[i]) + carry;
            s_plus_q[32 + i] = v as u8;
            carry = v >> 8;
        }
        assert_eq!(carry, 0);
        assert!(!verify(&g, &p, b"msg", &s_plus_q));
    }

    /// Interop: with `G` set to the Orchard SpendAuth basepoint, our verifier
    /// accepts signatures from the `reddsa` crate and vice versa, so the
    /// challenge hash and encodings match RedPallas. Spec: protocol spec §5.4.7.
    #[test]
    fn interoperates_with_reddsa_at_spend_auth_basepoint() {
        use reddsa::orchard::SpendAuth;
        let mut rng = rng();
        let g = crate::encoding::group_hash("z.cash:Orchard", b"G");
        let a = pallas::Scalar::random(&mut rng);
        let p = g * a;

        let sk = reddsa::SigningKey::<SpendAuth>::from_bytes(&a.to_repr()).unwrap();
        let vk = reddsa::VerificationKey::from(&sk);
        assert_eq!(<[u8; 32]>::from(vk), point_bytes(&p));

        let theirs: [u8; 64] = sk.sign(&mut rng, b"interop").into();
        assert!(verify(&g, &p, b"interop", &theirs));

        let ours = sign(&g, &a, &p, b"interop", &mut rng).unwrap();
        assert!(vk
            .verify(b"interop", &reddsa::Signature::from(ours))
            .is_ok());
    }

    /// Spec: ZIP § Mailbox Servers (L312, L320–322): a signed Fetch verifies at
    /// the server it names and round-trips its fields.
    #[test]
    fn fetch_round_trip() {
        let key = mailbox();
        let req = FetchRequest::sign(&key, 42, NOW, &SERVER_A, &mut rng()).unwrap();
        assert_eq!(req.len(), FETCH_LEN);
        let got = FetchRequest::verify(&SERVER_A, &req, NOW).unwrap();
        assert_eq!(
            got,
            FetchRequest {
                mailbox_id: key.id(),
                after: 42,
                time: NOW
            }
        );
    }

    /// Spec: ZIP § Mailbox Servers (L321–322): a Fetch signed for one
    /// `server_id` fails at another.
    #[test]
    fn fetch_bound_to_server() {
        let req = FetchRequest::sign(&mailbox(), 0, NOW, &SERVER_A, &mut rng()).unwrap();
        assert!(FetchRequest::verify(&SERVER_B, &req, NOW).is_none());
    }

    /// Spec: ZIP § Mailbox Servers (L326–328): `time` more than an hour off is dropped.
    #[test]
    fn fetch_time_window() {
        let req = FetchRequest::sign(&mailbox(), 0, NOW, &SERVER_A, &mut rng()).unwrap();
        for now in [NOW - 1, NOW, NOW + 1] {
            assert!(
                FetchRequest::verify(&SERVER_A, &req, now).is_some(),
                "{now}"
            );
        }
        for now in [NOW - 2, NOW + 2, 0, u32::MAX] {
            assert!(
                FetchRequest::verify(&SERVER_A, &req, now).is_none(),
                "{now}"
            );
        }
    }

    /// Spec: ZIP § Mailbox Servers (L326–328): malformed requests are dropped:
    /// wrong length or type, an identity half in `mailbox_id`, or any altered
    /// signed byte.
    #[test]
    fn fetch_malformed_dropped() {
        let req = FetchRequest::sign(&mailbox(), 9, NOW, &SERVER_A, &mut rng()).unwrap();
        assert!(FetchRequest::verify(&SERVER_A, &req[..FETCH_LEN - 1], NOW).is_none());
        let mut longer = req.to_vec();
        longer.push(0);
        assert!(FetchRequest::verify(&SERVER_A, &longer, NOW).is_none());

        let mut deposit = req;
        deposit[0] = DEPOSIT;
        assert!(FetchRequest::verify(&SERVER_A, &deposit, NOW).is_none());

        let mut identity = req;
        identity[33..65].fill(0);
        assert!(FetchRequest::verify(&SERVER_A, &identity, NOW).is_none());

        for i in [5, 66, 74, FETCH_UNSIGNED_LEN, FETCH_LEN - 1] {
            let mut bad = req;
            bad[i] ^= 1;
            assert!(
                FetchRequest::verify(&SERVER_A, &bad, NOW).is_none(),
                "byte {i}"
            );
        }
    }

    /// Spec: ZIP § Mailbox Servers (L312), § Notation (L184): exact request layout.
    #[test]
    fn fetch_layout() {
        let key = mailbox();
        let req = FetchRequest::sign(
            &key,
            0x0102_0304_0506_0708,
            0x0a0b_0c0d,
            &SERVER_A,
            &mut rng(),
        )
        .unwrap();
        assert_eq!(req[0], 2);
        assert_eq!(&req[1..65], key.id().as_bytes());
        assert_eq!(&req[65..73], &[8, 7, 6, 5, 4, 3, 2, 1]);
        assert_eq!(&req[73..77], &[0x0d, 0x0c, 0x0b, 0x0a]);
    }

    /// Spec: ZIP § Mailbox Servers (L322–324): `T` mixes in operating-system
    /// randomness, so two signers with identically seeded RNGs still get
    /// different `R`.
    #[test]
    fn t_uses_os_randomness() {
        let (g, a, p) = keypair(&mut rng());
        let s1 = sign(&g, &a, &p, b"msg", &mut StdRng::seed_from_u64(9)).unwrap();
        let s2 = sign(&g, &a, &p, b"msg", &mut StdRng::seed_from_u64(9)).unwrap();
        assert_ne!(s1[..32], s2[..32]);
        assert!(verify(&g, &p, b"msg", &s1) && verify(&g, &p, b"msg", &s2));
    }

    /// Spec: protocol spec §5.4.7, ZIP § Mailboxes (L263–264): an identity `R`,
    /// `P` or `G` is rejected, even for signatures that satisfy the equation.
    #[test]
    fn identity_points_rejected() {
        let (g, a, p) = keypair(&mut rng());
        let id = pallas::Point::identity();

        // R = O with S = c·a satisfies [S]G = R + [c]P.
        let r_bytes = [0u8; 32];
        let c = h_star(&[&r_bytes, &point_bytes(&p), b"msg"]);
        let mut sig = [0u8; 64];
        sig[32..].copy_from_slice(&(c * a).to_repr());
        assert_eq!(g * (c * a), id + p * c, "equation holds");
        assert!(!verify(&g, &p, b"msg", &sig));

        // P = O (a = 0) satisfies the equation for any honest-looking R.
        let zero = pallas::Scalar::ZERO;
        let sig = sign_with_t(&g, &zero, &id, b"msg", &[1u8; T_LEN]);
        assert!(!verify(&g, &id, b"msg", &sig));

        // G = O makes every point equal; reject it too.
        let sig = sign_with_t(&id, &a, &id, b"msg", &[2u8; T_LEN]);
        assert!(!verify(&id, &id, b"msg", &sig));
    }

    /// Spec: protocol spec §5.4.7: the challenge is exactly
    /// BLAKE2b-512("Zcash_RedPallasH", R̄ || repr(P) || M) reduced mod r_P,
    /// recomputed here independently of `h_star`.
    #[test]
    fn challenge_is_r_then_p_then_msg() {
        let (g, a, p) = keypair(&mut rng());
        let sig = sign(&g, &a, &p, b"order", &mut rng()).unwrap();
        let mut input = sig[..32].to_vec();
        input.extend_from_slice(&point_bytes(&p));
        input.extend_from_slice(b"order");
        let h = blake2b_simd::Params::new()
            .hash_length(64)
            .personal(b"Zcash_RedPallasH")
            .hash(&input);
        let c = to_scalar(h.as_bytes().try_into().unwrap());
        let r =
            Option::<pallas::Point>::from(point_from_bytes(sig[..32].try_into().unwrap())).unwrap();
        let s = pallas::Scalar::from_repr(sig[32..].try_into().unwrap()).unwrap();
        assert_eq!(g * s, r + p * c);
    }
}
