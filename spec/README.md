# Spec

`zip-draft-1435.md` is an unmodified copy of
`zips/draft-arya-wallet-to-wallet-messaging.md` from
[zcash/zips#1435](https://github.com/zcash/zips/pull/1435) at commit
[`312dace`](https://github.com/zcash/zips/blob/312dace3397a8e207a73c0ccf57765bf5a95450e/zips/draft-arya-wallet-to-wallet-messaging.md)
(the PR head on 2026-11-26). The draft is MIT licensed; its owners are Arya and
Ying Tong Lai.

Line numbers cited in the code refer to this copy. The draft is still changing;
see [CONTRIBUTING.md](../CONTRIBUTING.md#updating-the-spec) for how to update it.

## Where we differ from the draft

Each item is something to raise upstream on zcash/zips#1435.

- **Oversized Envelopes are dropped.** The draft requires senders to pad to
  the smallest `N` that fits (L212), but its drop list (L238–243) does not drop
  an Envelope padded further. `zunker-core` drops it, so senders can't use a
  size class to mark their Envelopes. This is stricter than the draft.
- **`seq` follows the clock.** The Mailbox Server gives `seq` from one global
  counter, `max(last_seq + 1, unix_seconds << 20)`, so it keeps nothing about a
  mailbox once its Envelopes are gone (L314–315 allows this). The cost is that
  a fetcher learns roughly when each Envelope was deposited.
