# Contributing

## Rules for code

- **No `unsafe`.** Crates declare `#![forbid(unsafe_code)]`.
- **Constant-time comparisons.** Compare anything derived from secrets with
  [`subtle`](https://docs.rs/subtle) (`ConstantTimeEq`, `Choice`,
  `ConditionallySelectable`), never with `==` or an early return.
- **Zeroize secrets.** Keys, seeds, shared secrets, nonces and plaintexts are
  wrapped in `zeroize::Zeroizing` or types that derive `ZeroizeOnDrop`, and
  their `Debug` output never prints them.
- **Cite the spec.** Every function names the section and lines of
  [`spec/zip-draft-1435.md`](spec/zip-draft-1435.md) (or the Zcash Protocol
  Specification section) it implements, as `Spec: ZIP § Section (Lx–y)`.
- **Green before review.** `cargo fmt --all --check`,
  `cargo clippy --all-targets -- -D warnings` and `cargo test` all pass.

## Updating the spec

`spec/zip-draft-1435.md` is pinned to one revision of the draft. When moving
to a newer revision, update [`spec/README.md`](spec/README.md) and every line
citation that moved, in the same pull request.

## Crypto review

Pull requests that touch envelope encryption or signatures are labelled
**needs human crypto review** and are not merged until someone has reviewed
them against the spec.
