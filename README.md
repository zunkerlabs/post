# Zunker Post

Reference implementation of Zcash Wallet-to-Wallet Messaging, following the ZIP draft in [zcash/zips#1435](https://github.com/zcash/zips/pull/1435).

> **Status:** in progress, testnet only. Do not use with mainnet funds.

## Layout

| Path | What it is |
|------|------------|
| [`spec/zip-draft-1435.md`](spec/zip-draft-1435.md) | The ZIP draft this code implements, pinned to one revision (see [`spec/README.md`](spec/README.md)) |
| [`crates/zunker-core`](crates/zunker-core) | Envelopes, mailboxes, server selection and fetch signatures |
| [`crates/zunker-server`](crates/zunker-server) | Mailbox Server: Deposit and Fetch over TCP, SQLite storage |
| [`crates/zunker-cli`](crates/zunker-cli) | `zunker-cli` command-line entry point |

Every function in `zunker-core` cites the section and lines of `spec/zip-draft-1435.md` it implements.

## Building

```sh
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo test
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the rules code in this repository follows.

## Running a Mailbox Server

```sh
cp crates/zunker-server/server.example.toml server.toml   # set server_id
cargo run -p zunker-cli -- serve --config server.toml
```

Plain TCP for now, with the length-prefixed framing from the draft's Tor
sketch (TBD); a Tor onion service comes next. The server logs only aggregate
counters, never Mailbox IDs, Envelope contents or peer addresses. Deletion on
Fetch is off by default (see `[retention]` in the example config).

## Development note

AI tools were used during development. The direction, design and ideas behind Zunker Post are the author's, Jatin Sahijwani, who is responsible for the code in this repository.

## License

MIT, see [LICENSE](LICENSE).
