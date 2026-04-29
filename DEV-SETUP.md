# Aegis v0.1 Local Dev Setup

This guide provides a repeatable local end-to-end demo for current Aegis v0.1 behavior.

## Scope

The demo exercises:

1. Start relay locally
2. Initialize local identity with `aegit id init`
3. Seal a message using default identity
4. Push envelope to relay
5. Fetch envelope for recipient
6. Open fetched envelope
7. Verify demo signature (if present)

## Quick Run (Recommended)

From the Aegis workspace root:

```sh
sh aegit-cli/scripts/local-e2e-demo.sh
```

The script:

- uses a temporary state directory (`AEGIT_STATE_DIR`)
- runs relay with temporary working data
- fails fast on errors
- leaves artifacts in a temporary directory for inspection

## Manual Verification Path

### 1. Start relay

```sh
cd aegis-relay
cargo run
```

Relay default URL: `http://127.0.0.1:8787`

### 2. Use temporary CLI state

```sh
export AEGIT_STATE_DIR="$(mktemp -d)/aegit-state"
```

### 3. Initialize local identity

```sh
cd ../aegit-cli
cargo run -- id init --alias dev@mesh
cargo run -- id show
cargo run -- id list
```

### 4. Seal message with default identity

```sh
cargo run -- msg seal \
  --to amp:did:key:z6MkRecipientDemo \
  --body "hello from local demo" \
  --passphrase demo-passphrase \
  --out /tmp/aegis-envelope.json
```

### 5. Push to relay

```sh
cargo run -- relay push \
  --relay http://127.0.0.1:8787 \
  --input /tmp/aegis-envelope.json
```

### 6. Fetch for recipient

```sh
cargo run -- relay fetch \
  --relay http://127.0.0.1:8787 \
  --recipient amp:did:key:z6MkRecipientDemo \
  --out /tmp/aegis-fetched
```

### 7. Open fetched envelope

```sh
cargo run -- msg open \
  --input /tmp/aegis-fetched/<envelope-id>.json \
  --passphrase demo-passphrase \
  --out /tmp/aegis-opened.json
```

Expected output includes either:

- `signature verified` when an envelope signature is present
- `signature <none>` when no signature is present

## Notes

- Demo crypto and demo signatures are non-production.
- Relay remains untrusted storage; verification is client-side.
