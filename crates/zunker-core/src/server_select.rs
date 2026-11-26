//! Choosing the Mailbox Server for a Mailbox ID from a Server List.
//!
//! Spec: `spec/zip-draft-1435.md` § Mailboxes (L279–285). The Server List
//! itself is still a TODO in the draft (L285, § Open issues L446–449), so this
//! module only takes each entry's 32-byte `server_id`.

use crate::encoding::{blake2b_256, personalization};
use crate::mailbox::MailboxId;

/// `BLAKE2b-256("Zcash_WMsgSrvSel", server_id || id)`.
///
/// Spec: ZIP § Mailboxes (L281–283).
pub fn selection_hash(server_id: &[u8; 32], id: &MailboxId) -> [u8; 32] {
    blake2b_256(personalization::SRV_SEL, &[server_id, id.as_bytes()])
}

/// Returns the entry whose `server_id` gives the smallest [`selection_hash`],
/// compared as a byte string, or `None` for an empty list. The result does not
/// depend on the order of `entries`, except that among entries with equal
/// `server_id`s the first is returned.
///
/// Spec: ZIP § Mailboxes (L279–283).
pub fn select<'a, T>(
    entries: &'a [T],
    server_id: impl Fn(&T) -> &[u8; 32],
    id: &MailboxId,
) -> Option<&'a T> {
    entries
        .iter()
        .map(|e| (selection_hash(server_id(e), id), e))
        .min_by(|(a, _), (b, _)| a.cmp(b))
        .map(|(_, e)| e)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::point_bytes;
    use ff::Field;
    use group::Group;
    use pasta_curves::pallas;
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};

    /// A random valid Mailbox ID. Spec: ZIP § Mailboxes (L262–264).
    fn random_id(rng: &mut StdRng) -> MailboxId {
        let g = pallas::Point::generator() * pallas::Scalar::random(&mut *rng);
        let p = pallas::Point::generator() * pallas::Scalar::random(&mut *rng);
        let mut bytes = [0u8; 64];
        bytes[..32].copy_from_slice(&point_bytes(&g));
        bytes[32..].copy_from_slice(&point_bytes(&p));
        MailboxId::from_bytes(&bytes).unwrap()
    }

    /// A Server List of `n` random `server_id`s. Spec: ZIP § Mailboxes (L279–280).
    fn servers(rng: &mut StdRng, n: usize) -> Vec<[u8; 32]> {
        (0..n)
            .map(|_| {
                let mut id = [0u8; 32];
                rng.fill_bytes(&mut id);
                id
            })
            .collect()
    }

    /// Spec: ZIP § Mailboxes (L281–283): the winner has the smallest hash.
    #[test]
    fn picks_smallest_hash() {
        let mut rng = StdRng::seed_from_u64(1);
        let list = servers(&mut rng, 8);
        let id = random_id(&mut rng);
        let chosen = select(&list, |s| s, &id).unwrap();
        let best = list.iter().map(|s| selection_hash(s, &id)).min().unwrap();
        assert_eq!(selection_hash(chosen, &id), best);
        assert!(select::<[u8; 32]>(&[], |s| s, &id).is_none());
    }

    /// Spec: ZIP § Mailboxes (L282): the hash is exactly
    /// BLAKE2b-256("Zcash_WMsgSrvSel", server_id || id).
    #[test]
    fn hash_matches_definition() {
        let mut rng = StdRng::seed_from_u64(2);
        let id = random_id(&mut rng);
        let server = [0x42u8; 32];
        let mut input = server.to_vec();
        input.extend_from_slice(id.as_bytes());
        let expected = blake2b_simd::Params::new()
            .hash_length(32)
            .personal(b"Zcash_WMsgSrvSel")
            .hash(&input);
        assert_eq!(&selection_hash(&server, &id)[..], expected.as_bytes());
    }

    /// Spec: ZIP § Mailboxes (L281–283): deterministic and independent of the
    /// order of the Server List.
    #[test]
    fn deterministic_and_order_independent() {
        let mut rng = StdRng::seed_from_u64(3);
        let list = servers(&mut rng, 6);
        let mut reversed = list.clone();
        reversed.reverse();
        for _ in 0..50 {
            let id = random_id(&mut rng);
            let a = select(&list, |s| s, &id).unwrap();
            assert_eq!(a, select(&list, |s| s, &id).unwrap());
            assert_eq!(a, select(&reversed, |s| s, &id).unwrap());
        }
    }

    /// Spec: ZIP § Mailboxes (L281–283): over 1,000 random Mailbox IDs the
    /// choice is roughly uniform. With 5 servers each expects 200; the
    /// chi-squared statistic must stay below 18.47 (df = 4, p = 0.001).
    #[test]
    fn roughly_uniform() {
        let mut rng = StdRng::seed_from_u64(4);
        let list = servers(&mut rng, 5);
        let mut counts = [0u32; 5];
        for _ in 0..1000 {
            let id = random_id(&mut rng);
            let chosen = select(&list, |s| s, &id).unwrap();
            counts[list.iter().position(|s| s == chosen).unwrap()] += 1;
        }
        let chi2: f64 = counts
            .iter()
            .map(|&c| (f64::from(c) - 200.0).powi(2) / 200.0)
            .sum();
        assert!(chi2 < 18.47, "counts {counts:?}, chi2 {chi2}");
        assert!(
            counts.iter().all(|&c| (140..=260).contains(&c)),
            "{counts:?}"
        );
    }

    /// Spec: ZIP § Mailboxes (L279–280): entries can carry more than the
    /// `server_id` (network addresses), selected through the accessor.
    #[test]
    fn works_on_entries() {
        struct Entry {
            server_id: [u8; 32],
            name: &'static str,
        }
        let mut rng = StdRng::seed_from_u64(5);
        let ids = servers(&mut rng, 2);
        let entries = [
            Entry {
                server_id: ids[0],
                name: "a",
            },
            Entry {
                server_id: ids[1],
                name: "b",
            },
        ];
        let id = random_id(&mut rng);
        let e = select(&entries, |e| &e.server_id, &id).unwrap();
        let s = select(&ids, |s| s, &id).unwrap();
        assert_eq!(&e.server_id, s);
        assert!(["a", "b"].contains(&e.name));
    }
}
