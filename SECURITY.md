# Security

## Status

Zunker Post is in progress and **testnet only**. It has not been audited. Do
not use it with mainnet funds, or for messages that must stay private.

The protocol's own limits (no sender authentication, no forward secrecy, and
incoming viewing key holders can read every Envelope sent to an account) are
set out in the draft's Privacy Implications section,
[`spec/zip-draft-1435.md`](spec/zip-draft-1435.md) L95–139.

## Reporting a vulnerability

Please do not open a public issue. Report it privately through GitHub's
private vulnerability reporting for this repository (**Security → Report a
vulnerability**).

## Known limitations

### Secrets inside BLAKE2b's internal state are not wiped

`zunker-core` zeroizes every secret buffer it holds. It also enables the
`zeroize` features of `chacha20poly1305`, `chacha20` and `poly1305`, so the
cipher and MAC state holding an Envelope key is wiped on drop.

BLAKE2b comes from `blake2b_simd`, which does **not** wipe its internal state
when dropped. Transient copies of secret hash inputs and outputs can therefore
remain in freed stack memory:

- **Envelopes:** `κ` (the output of the first-Envelope derivation, and an input
  to `K`), `K`, `seed` (the input to `esk`), and `PointBytes([esk] pk_d)`.
- **Pairwise Mailboxes:** `m = κ || [δ] || I2LEOSP_32(e)`.

The `orchard` and `reddsa` crates have the same property, since they use
`blake2b_simd` too. We accept it while Zunker Post is testnet only, and will
revisit it before any mainnet use.

### Zeroization is best-effort

`zeroize` clears the memory it is given. The compiler may still leave copies it
was not given: field elements are `Copy`, and scalar multiplication takes its
scalar by value.

### Envelopes of unknown length are rejected early

Every drop rule for a received Envelope is evaluated in full and combined
once, so the work done does not depend on which rule failed. The exception is
an Envelope whose length is not one of the three sizes: it is rejected before
anything else, because there is nothing to decrypt. Its length is visible to
anyone and chosen by the sender, so this reveals nothing.
