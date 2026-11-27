#!/usr/bin/env bash
# Prints a running Mailbox Server's server_id and onion address as a
# servers.json entry.
#
# Docker (deploy/docker-compose.yml), from the repository root:
#   scripts/server-info.sh
#   scripts/server-info.sh --compose deploy/docker-compose.yml --config deploy/server.toml
#
# System tor:
#   scripts/server-info.sh --config server.toml --hostname-file /var/lib/tor/zunker/hostname
#
# Options:
#   --config FILE         server TOML holding server_id (default: deploy/server.toml)
#   --compose FILE        docker compose file; reads the onion from the tor service
#                         (default when --hostname-file is not given)
#   --hostname-file FILE  tor's HiddenServiceDir/hostname
#   --port N              onion service port (default: 7878)

set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
CONFIG=$ROOT/deploy/server.toml
COMPOSE=$ROOT/deploy/docker-compose.yml
HOSTNAME_FILE=""
PORT=7878

die() {
    echo "error: $*" >&2
    exit 1
}

while [[ $# -gt 0 ]]; do
    case $1 in
        --config) CONFIG=${2:?}; shift 2 ;;
        --compose) COMPOSE=${2:?}; shift 2 ;;
        --hostname-file) HOSTNAME_FILE=${2:?}; shift 2 ;;
        --port) PORT=${2:?}; shift 2 ;;
        -h | --help) sed -n '2,19p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) die "unknown option $1 (see --help)" ;;
    esac
done

[[ -f $CONFIG ]] || die "$CONFIG not found"
SERVER_ID=$(sed -n 's/^[[:space:]]*server_id[[:space:]]*=[[:space:]]*"\([0-9a-fA-F]*\)".*/\1/p' "$CONFIG" | head -n 1)
SERVER_ID=$(tr 'A-F' 'a-f' <<<"$SERVER_ID")
[[ ${#SERVER_ID} -eq 64 ]] || die "no 64-hex-character server_id in $CONFIG"
[[ $SERVER_ID =~ ^0+$ ]] && die "server_id in $CONFIG is the all-zero placeholder; set it (openssl rand -hex 32)"

if [[ -n $HOSTNAME_FILE ]]; then
    [[ -r $HOSTNAME_FILE ]] || die "cannot read $HOSTNAME_FILE (it is usually readable only by the tor user; try sudo)"
    ONION=$(tr -d '[:space:]' <"$HOSTNAME_FILE")
else
    [[ -f $COMPOSE ]] || die "$COMPOSE not found"
    ONION=$(docker compose -f "$COMPOSE" exec -T tor cat /var/lib/tor/zunker/hostname 2>/dev/null | tr -d '[:space:]') ||
        die "cannot read the onion address from the tor service; is the compose stack running?"
fi
[[ $ONION =~ ^[a-z2-7]{55}d\.onion$ ]] || die "'$ONION' is not a v3 onion address"
[[ $PORT =~ ^[0-9]+$ && $PORT -ge 1 && $PORT -le 65535 ]] || die "bad port $PORT"

printf '{ "server_id": "%s", "onion": "%s:%s" }\n' "$SERVER_ID" "$ONION" "$PORT"
