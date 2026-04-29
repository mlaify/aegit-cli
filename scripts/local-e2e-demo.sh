#!/bin/sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
RELAY_MANIFEST="$ROOT_DIR/aegis-relay/Cargo.toml"
CLI_MANIFEST="$ROOT_DIR/aegit-cli/Cargo.toml"
RELAY_URL="http://127.0.0.1:8787"
RECIPIENT_ID="amp:did:key:z6MkRecipientDemo"
PASSPHRASE="demo-passphrase"

TMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/aegis-e2e.XXXXXX")
AEGIT_STATE_DIR="$TMP_DIR/state"
export AEGIT_STATE_DIR

RELAY_PID=""
cleanup() {
  if [ -n "$RELAY_PID" ] && kill -0 "$RELAY_PID" >/dev/null 2>&1; then
    kill "$RELAY_PID" >/dev/null 2>&1 || true
    wait "$RELAY_PID" >/dev/null 2>&1 || true
  fi
  echo "artifacts: $TMP_DIR"
}
trap cleanup EXIT INT TERM

step() {
  printf '\n==> %s\n' "$1"
}

aegit() {
  cargo run --quiet --manifest-path "$CLI_MANIFEST" -- "$@"
}

step "starting relay (temporary data dir)"
(
  cd "$TMP_DIR"
  cargo run --quiet --manifest-path "$RELAY_MANIFEST" >"$TMP_DIR/relay.log" 2>&1
) &
RELAY_PID=$!

step "waiting for relay health endpoint"
READY=0
for _ in 1 2 3 4 5 6 7 8 9 10; do
  if curl -fsS "$RELAY_URL/healthz" >/dev/null 2>&1; then
    READY=1
    break
  fi
  sleep 1
done
if [ "$READY" -ne 1 ]; then
  echo "relay failed to become healthy; see $TMP_DIR/relay.log" >&2
  exit 1
fi

step "initializing local identity"
aegit id init --alias demo@mesh
SENDER_ID=$(aegit id show | awk '/^identity / {print $2; exit}')
if [ -z "$SENDER_ID" ]; then
  echo "failed to parse sender identity" >&2
  exit 1
fi
echo "default sender: $SENDER_ID"

ENVELOPE_PATH="$TMP_DIR/envelope.json"
FETCH_DIR="$TMP_DIR/fetched"
OPENED_PATH="$TMP_DIR/opened.json"

step "sealing message using default identity"
aegit msg seal \
  --to "$RECIPIENT_ID" \
  --body "hello from local e2e demo" \
  --passphrase "$PASSPHRASE" \
  --out "$ENVELOPE_PATH"

step "pushing envelope to relay"
aegit relay push \
  --relay "$RELAY_URL" \
  --input "$ENVELOPE_PATH"

step "fetching envelope for recipient"
aegit relay fetch \
  --relay "$RELAY_URL" \
  --recipient "$RECIPIENT_ID" \
  --out "$FETCH_DIR"

FETCHED_ENVELOPE=$(find "$FETCH_DIR" -type f -name '*.json' | head -n 1)
if [ -z "$FETCHED_ENVELOPE" ]; then
  echo "no fetched envelope found in $FETCH_DIR" >&2
  exit 1
fi

step "opening fetched envelope (includes signature verification when present)"
aegit msg open \
  --input "$FETCHED_ENVELOPE" \
  --passphrase "$PASSPHRASE" \
  --out "$OPENED_PATH"

step "demo complete"
echo "envelope: $ENVELOPE_PATH"
echo "fetched:  $FETCHED_ENVELOPE"
echo "opened:   $OPENED_PATH"
echo "relay log: $TMP_DIR/relay.log"
