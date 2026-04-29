#!/bin/sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
RELAY_MANIFEST="$ROOT_DIR/aegis-relay/Cargo.toml"
CLI_MANIFEST="$ROOT_DIR/aegit-cli/Cargo.toml"
RELAY_URL="http://127.0.0.1:8787"
RECIPIENT_ID="amp:did:key:z6MkRecipientDemo"
PASSPHRASE="demo-passphrase"
RELAY_TOKEN="dev-relay-token"

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
  AEGIS_RELAY_CAPABILITY_TOKEN="$RELAY_TOKEN" \
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
  --token "$RELAY_TOKEN" \
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

ENVELOPE_ID=$(aegit msg list --recipient "$RECIPIENT_ID" | awk '/^[0-9]{4}-/ {print $2; exit}')
if [ -z "$ENVELOPE_ID" ]; then
  ENVELOPE_ID=$(basename "$FETCHED_ENVELOPE" .json)
fi

step "acknowledging fetched envelope on relay"
aegit relay ack \
  --relay "$RELAY_URL" \
  --token "$RELAY_TOKEN" \
  --recipient "$RECIPIENT_ID" \
  --envelope-id "$ENVELOPE_ID"

POST_ACK_FETCH_DIR="$TMP_DIR/post-ack-fetch"
step "verifying acknowledged envelope is not returned by fetch"
aegit relay fetch \
  --relay "$RELAY_URL" \
  --recipient "$RECIPIENT_ID" \
  --out "$POST_ACK_FETCH_DIR"
POST_ACK_COUNT=$(find "$POST_ACK_FETCH_DIR" -type f -name '*.json' | wc -l | tr -d ' ')
if [ "$POST_ACK_COUNT" -ne 0 ]; then
  echo "expected zero envelopes after ack; got $POST_ACK_COUNT" >&2
  exit 1
fi

SECOND_ENVELOPE_PATH="$TMP_DIR/envelope-2.json"
SECOND_FETCH_DIR="$TMP_DIR/fetched-2"
step "sealing and pushing second envelope for delete flow"
aegit msg seal \
  --to "$RECIPIENT_ID" \
  --body "second message for delete flow" \
  --passphrase "$PASSPHRASE" \
  --out "$SECOND_ENVELOPE_PATH"
aegit relay push \
  --relay "$RELAY_URL" \
  --token "$RELAY_TOKEN" \
  --input "$SECOND_ENVELOPE_PATH"
aegit relay fetch \
  --relay "$RELAY_URL" \
  --recipient "$RECIPIENT_ID" \
  --out "$SECOND_FETCH_DIR"
SECOND_FETCHED_ENVELOPE=$(find "$SECOND_FETCH_DIR" -type f -name '*.json' | head -n 1)
if [ -z "$SECOND_FETCHED_ENVELOPE" ]; then
  echo "no fetched second envelope found in $SECOND_FETCH_DIR" >&2
  exit 1
fi
SECOND_ENVELOPE_ID=$(basename "$SECOND_FETCHED_ENVELOPE" .json)

step "deleting second envelope on relay"
aegit relay delete \
  --relay "$RELAY_URL" \
  --token "$RELAY_TOKEN" \
  --recipient "$RECIPIENT_ID" \
  --envelope-id "$SECOND_ENVELOPE_ID"

POST_DELETE_FETCH_DIR="$TMP_DIR/post-delete-fetch"
step "verifying deleted envelope is not returned by fetch"
aegit relay fetch \
  --relay "$RELAY_URL" \
  --recipient "$RECIPIENT_ID" \
  --out "$POST_DELETE_FETCH_DIR"
POST_DELETE_COUNT=$(find "$POST_DELETE_FETCH_DIR" -type f -name '*.json' | wc -l | tr -d ' ')
if [ "$POST_DELETE_COUNT" -ne 0 ]; then
  echo "expected zero envelopes after delete; got $POST_DELETE_COUNT" >&2
  exit 1
fi

step "running relay cleanup (token protected)"
aegit relay cleanup \
  --relay "$RELAY_URL" \
  --token "$RELAY_TOKEN"

step "demo complete"
echo "envelope: $ENVELOPE_PATH"
echo "fetched:  $FETCHED_ENVELOPE"
echo "acked id: $ENVELOPE_ID"
echo "deleted id: $SECOND_ENVELOPE_ID"
echo "opened:   $OPENED_PATH"
echo "relay log: $TMP_DIR/relay.log"
