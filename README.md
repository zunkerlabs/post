# Zunker Post

Reference implementation of Zcash Wallet-to-Wallet Messaging, following the ZIP draft in [zcash/zips#1435](https://github.com/zcash/zips/pull/1435).

> **Status:** in progress, testnet only. Do not use with mainnet funds.

## Layout

| Path | What it is |
|------|------------|
| [`spec/zip-draft-1435.md`](spec/zip-draft-1435.md) | The ZIP draft this code implements, pinned to one revision (see [`spec/README.md`](spec/README.md)) |
| [`crates/zunker-core`](crates/zunker-core) | Envelopes, mailboxes, server selection and fetch signatures |
| [`crates/zunker-server`](crates/zunker-server) | Mailbox Server: Deposit and Fetch over TCP, SQLite storage |
| [`crates/zunker-client`](crates/zunker-client) | Wallet side: Tor transport (arti, or a local tor over SOCKS5) |
| [`deploy`](deploy) | torrc example, Dockerfiles and docker-compose for a server behind an onion service |
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

The server speaks plain TCP on a loopback address, and is reached only
through a Tor v3 onion service that forwards to it (spec Appendix A, Tor). It
logs only aggregate counters, never Mailbox IDs, Envelope contents or peer
addresses; behind Tor every connection comes from 127.0.0.1 anyway. Deletion
on Fetch is off by default (see `[retention]` in
[`server.example.toml`](crates/zunker-server/server.example.toml)).

### With Docker (tor + server)

```sh
cp deploy/server.toml.example deploy/server.toml   # set server_id: openssl rand -hex 32
docker compose -f deploy/docker-compose.yml up -d --build
docker compose -f deploy/docker-compose.yml exec tor cat /var/lib/tor/zunker/hostname
```

No ports are published: the server runs in tor's network namespace and the
onion service is its only way in. The onion address plus port 7878 is the
server's entry in a Server List. The `tor-data` volume holds the onion
service's keys, which *are* the address, so back it up.

### With a system tor

```sh
cp crates/zunker-server/server.example.toml server.toml   # set server_id
cargo run --release -p zunker-cli -- serve --config server.toml
```

Add the onion service to `/etc/tor/torrc` (see
[`deploy/tor/torrc`](deploy/tor/torrc)), with `HiddenServicePort` pointing at
the server's `listen` address:

```
HiddenServiceDir /var/lib/tor/zunker/
HiddenServicePort 7878 127.0.0.1:7878
```

Restart tor and read the address from `/var/lib/tor/zunker/hostname`. Keep
`listen` on a loopback address so the server can't be reached around Tor.

## Connecting as a client

`zunker-client` reaches servers only over Tor, opening a new circuit for every
request. That makes every Deposit, and every Fetch, its own session
(spec § Routing).

- **arti (default).** The client runs Tor in-process with
  [`arti-client`](https://crates.io/crates/arti-client) and gives each request
  a fresh isolation token.
- **System tor (fallback).** If arti can't bootstrap, the client uses a local
  tor's SOCKS port at `127.0.0.1:9050`. It sends fresh random SOCKS
  credentials with each request, which tor's default `IsolateSOCKSAuth` puts
  on a separate circuit.

If neither is available, requests fail. The client never falls back to a
direct connection (spec § Routing: a wallet MUST NOT bypass the anonymity
network).

## Development note

AI tools were used during development. The direction, design and ideas behind Zunker Post are the author's, Jatin Sahijwani, who is responsible for the code in this repository.

## License

MIT, see [LICENSE](LICENSE).
