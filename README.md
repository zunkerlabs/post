# Zunker Post

Reference implementation of Zcash Wallet-to-Wallet Messaging, following the ZIP draft in [zcash/zips#1435](https://github.com/zcash/zips/pull/1435).

> **Status:** in progress, testnet only. Do not use with mainnet funds.

## Layout

| Path | What it is |
|------|------------|
| [`spec/zip-draft-1435.md`](spec/zip-draft-1435.md) | The ZIP draft this code implements, pinned to one revision (see [`spec/README.md`](spec/README.md)) |
| [`crates/zunker-core`](crates/zunker-core) | Envelopes, mailboxes, server selection and fetch signatures |
| [`crates/zunker-server`](crates/zunker-server) | Mailbox Server: Deposit and Fetch over TCP, SQLite storage |
| [`crates/zunker-client`](crates/zunker-client) | Wallet side: deposit, reply and fetch over Tor (arti, or a local tor over SOCKS5); provisional Server List |
| [`deploy`](deploy) | torrc example, Dockerfiles and docker-compose for a server behind an onion service |
| [`crates/zunker-cli`](crates/zunker-cli) | `zunker-cli` command-line entry point |

Every function in `zunker-core` cites the section and lines of `spec/zip-draft-1435.md` it implements.

## Building

```sh
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo test
```

`cargo test` includes an integration test with two in-process Mailbox
Servers (`crates/zunker-client/tests/two_servers.rs`). The end-to-end test
over the real Tor network is ignored by default, because it needs a server
behind an onion service, such as the Docker setup below:

```sh
ZUNKER_TOR_ONION=<56 chars>.onion:7878 ZUNKER_TOR_SERVER_ID=<64 hex> \
  cargo test -p zunker-client --test tor -- --ignored --nocapture
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

## Messaging from the command line

`zunker-cli` sends and fetches messages with a testnet Orchard account. It
uses only keys and addresses, with no chain or lightwalletd. Everything goes
over Tor (see above).

```sh
zunker-cli keygen        # new testnet account; prints its Unified Address
zunker-cli address       # print it again

zunker-cli send --to utest1... --request "zcash:utest1...?amount=0.5&message=lunch"
zunker-cli send --to utest1... --text "hello"
zunker-cli fetch         # print received messages and payment requests
zunker-cli fetch --watch # keep fetching, each mailbox on its own random schedule
zunker-cli reply --conversation <id> --text "thanks"
```

- **Data.** Keys, state and Tor data live in `~/.zunker-post` (override with
  `--data-dir`). The seed in `keys.json` and each Conversation's secret in
  `state.json` are stored unencrypted, readable only by you: **testnet only**.
- **Payload.** `--request` must be a valid ZIP 321 URI. With both
  `--request` and `--text`, two first messages are sent, each starting its
  own conversation. The draft doesn't let the sender send a second message in
  a conversation until it gets a reply.
- **Tor.** `--tor auto|arti|system` picks how to reach Tor, and `--socks`
  sets the system tor's SOCKS address.

### Server List

Until the ZIP specifies a Server List, the client reads a provisional JSON
file, `~/.zunker-post/servers.json` by default (or `--servers`):

```json
{
  "format": "zunker-provisional-1",
  "servers": [
    { "server_id": "<64 hex: the server's server_id>", "onion": "<56 base32>.onion:7878" }
  ]
}
```

Sender and recipient must use the same list, because each mailbox's server is
chosen from it (spec § Mailboxes).

## Development note

AI tools were used during development. The direction, design and ideas behind Zunker Post are the author's, Jatin Sahijwani, who is responsible for the code in this repository.

## License

MIT, see [LICENSE](LICENSE).
