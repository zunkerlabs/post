#!/usr/bin/env bash
# Zunker Post demo: Alice sends Bob a payment request over Tor, Bob reads it
# and replies, Alice reads the reply.
#
#   scripts/demo.sh servers.json [work-dir]
#
# servers.json must list two Mailbox Servers behind onion services (build the
# entries with scripts/server-info.sh). Testnet only: the keys created here are
# throwaway and stored unencrypted in the work directory.
#
# Environment:
#   ZUNKER_CLI   path to a zunker-cli binary (default: build target/release/zunker-cli)
#   ZUNKER_TOR   auto | arti | system (default: auto)
#   ZUNKER_PAUSE seconds to pause between steps, for recordings (default: 2)

set -euo pipefail

usage() {
    echo "usage: $0 servers.json [work-dir]" >&2
    exit 2
}

[[ $# -ge 1 && $# -le 2 ]] || usage
SERVERS=$1
[[ -f $SERVERS ]] || { echo "error: $SERVERS not found" >&2; exit 1; }
SERVERS=$(cd "$(dirname "$SERVERS")" && pwd)/$(basename "$SERVERS")

ONIONS=$(grep -o '"onion"' "$SERVERS" | wc -l | tr -d ' ')
if [[ $ONIONS -ne 2 ]]; then
    echo "error: $SERVERS lists $ONIONS servers; the demo expects 2 onion servers" >&2
    exit 1
fi

WORK=${2:-$(mktemp -d "${TMPDIR:-/tmp}/zunker-demo.XXXXXX")}
mkdir -p "$WORK"
ALICE=$WORK/alice
BOB=$WORK/bob
if [[ -e $ALICE || -e $BOB ]]; then
    echo "error: $WORK already has alice/ or bob/; use an empty work directory" >&2
    exit 1
fi

TOR=${ZUNKER_TOR:-auto}
PAUSE=${ZUNKER_PAUSE:-2}
ROOT=$(cd "$(dirname "$0")/.." && pwd)

if [[ -n ${ZUNKER_CLI:-} ]]; then
    CLI=$ZUNKER_CLI
else
    echo "Building zunker-cli (release)..."
    cargo build --quiet --release --manifest-path "$ROOT/Cargo.toml" -p zunker-cli
    CLI=$ROOT/target/release/zunker-cli
fi

if [[ -t 1 ]]; then
    BOLD=$(tput bold 2>/dev/null || true)
    DIM=$(tput dim 2>/dev/null || true)
    RESET=$(tput sgr0 2>/dev/null || true)
else
    BOLD="" DIM="" RESET=""
fi

STEP=0
# Prints a numbered step header that reads well on a screen recording.
header() {
    STEP=$((STEP + 1))
    local title="Step $STEP: $1"
    local rule
    rule=$(printf '%*s' "${#title}" '' | tr ' ' '=')
    echo
    echo "${BOLD}${rule}${RESET}"
    echo "${BOLD}${title}${RESET}"
    echo "${BOLD}${rule}${RESET}"
    [[ -n ${2:-} ]] && echo "${DIM}$2${RESET}"
    echo
    sleep "$PAUSE"
}

# As alice|bob, shows a zunker-cli command (without the data-dir, server
# list and Tor flags, to keep recordings readable), then runs it with them.
as() {
    local who=$1 cmd=$2
    shift 2
    local dir=$ALICE
    [[ $who == bob ]] && dir=$BOB
    local shown=""
    (($#)) && shown=" $(printf '%q ' "$@")"
    echo "${DIM}${who}\$ zunker-cli ${cmd}${shown% }${RESET}"
    case $cmd in
        keygen | address) "$CLI" --data-dir "$dir" "$cmd" "$@" ;;
        *) "$CLI" --data-dir "$dir" "$cmd" --servers "$SERVERS" --tor "$TOR" "$@" ;;
    esac
}

# Fetches as alice|bob until a message arrives (onion circuits can be slow
# to come up). Prints the output and leaves it in $FETCHED.
fetch_until_message() {
    local who=$1 attempt
    for attempt in 1 2 3; do
        FETCHED=$(as "$who" fetch 2>&1) || true
        echo "$FETCHED"
        if grep -q '^conversation:' <<<"$FETCHED"; then
            return 0
        fi
        echo "${DIM}(nothing yet; trying again, $attempt/3)${RESET}"
        sleep 5
    done
    echo "error: no message arrived" >&2
    exit 1
}

echo "${BOLD}Zunker Post demo: Zcash wallet-to-wallet messaging over Tor (testnet)${RESET}"
echo "${DIM}work directory: $WORK${RESET}"
echo "${DIM}server list:    $SERVERS${RESET}"

header "Create two testnet wallets" \
    "Each gets an Orchard account; the address is all a sender needs."
as alice keygen 2>/dev/null
echo
BOB_OUT=$(as bob keygen 2>/dev/null)
echo "$BOB_OUT"
BOB_UA=$(tail -n 1 <<<"$BOB_OUT")

header "Bob's address" "Bob shares this Unified Address with Alice."
echo "$BOB_UA"

URI="zcash:${BOB_UA}?amount=0.1&message=Zunker%20Post%20demo"
header "Alice sends Bob a payment request" \
    "The Envelope goes over Tor to the server selected for Bob's Contact Mailbox."
as alice send --to "$BOB_UA" --request "$URI"

header "Bob fetches and decodes the request" \
    "Bob's wallet fetches its mailboxes over Tor and decrypts the Envelope."
fetch_until_message bob
CONV=$(sed -n 's/^conversation: *//p' <<<"$FETCHED" | head -n 1)

header "Bob replies \"received\"" \
    "The reply goes to a Pairwise Mailbox that only this conversation can find."
as bob reply --conversation "$CONV" --text "received"

header "Alice fetches the reply" \
    "Alice's wallet finds the reply in the conversation's Pairwise Mailbox."
fetch_until_message alice

echo
echo "${BOLD}Done.${RESET} Wallet data is in $WORK (testnet keys; delete it when finished)."
