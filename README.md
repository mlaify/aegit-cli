# aegit-cli

A git-flavored operator CLI for Aegis.

## Protocol References

- `../aegis-spec/docs/protocol-index.md`
- `../aegis-spec/docs/implementation-conformance-v0.1.md`
- `../aegis-docs/docs/getting-started.md` (developer onboarding)

## Commands

- `aegit id init`
- `aegit id show`
- `aegit id list`
- `aegit msg seal`
- `aegit msg open`
- `aegit msg list`
- `aegit relay push`
- `aegit relay fetch`
- `aegit relay ack`
- `aegit relay delete`
- `aegit relay cleanup`

## Local state

Default state root:

- `$HOME/.aegis/aegit`

Override with:

- `AEGIT_STATE_DIR=/path/to/state`

Default locations:

- Identities: `identities/<identity-id>.json`
- Default identity pointer: `default_identity`
- Sealed envelopes: `sealed/<recipient>/<envelope-id>.json`
- Fetched envelopes: `fetched/<recipient>/<envelope-id>.json`
- Opened payloads: `opened/<recipient>/<envelope-id>.json`

## Identity workflow

- `aegit id init --alias matt@mesh` creates a local `IdentityDocument` and sets it as default.
- `aegit id show` prints the default identity document details.
- `aegit id show --identity amp:did:key:...` prints a specific stored identity.
- `aegit id list` lists stored identities and marks the default.

`aegit msg seal` uses `--from` when provided. If omitted, it uses the default local identity. If no default identity exists, it returns a helpful error prompting `aegit id init`.
When `--to` is not a canonical `IdentityId`, `aegit msg seal --relay <url>` can resolve aliases via relay resolver endpoint.

Local-dev identity signing behavior:

- `id init` creates identity-linked local signing key material in local state.
- `msg seal` signs with that identity-linked local-dev key material.
- `msg open` reports explicit signature status:
  - `unsigned`
  - `present_verified`
  - `present_failed`
  - `verification_unavailable`

## Local E2E Demo

See [DEV-SETUP.md](./DEV-SETUP.md) for a repeatable local end-to-end workflow and smoke script:

```sh
sh scripts/local-e2e-demo.sh
```

## Relay workflow

`aegit relay push` posts a sealed envelope JSON file to `POST /v1/envelopes`.
When relay token support is configured, `--token` MAY be passed for compatibility.

`aegit relay fetch` reads `GET /v1/envelopes/:recipient_id`.

- Without `--out`, it writes into the default fetched directory for that recipient.
- With `--out <dir>`, it writes one `<envelope-id>.json` file per fetched envelope into that directory.

`aegit relay ack` calls `POST /v1/envelopes/:recipient_id/:envelope_id/ack` to acknowledge an envelope without deleting ciphertext content.
Use `--token` when relay capability token protection is enabled.

`aegit relay delete` calls `DELETE /v1/envelopes/:recipient_id/:envelope_id` to remove a specific envelope file from relay storage.
Use `--token` when relay capability token protection is enabled.

`aegit relay cleanup` calls `POST /v1/cleanup` to trigger local-dev relay cleanup for expired envelopes and orphan ack markers.

## Current v0.1.0-alpha Status

CLI flows for `v0.1.0-alpha` are development-oriented.

- demo crypto/signing is non-production
- no production PQ cryptography
- resolver integration is available through relay-backed identity/alias endpoints; production trust policy remains in-progress

## Development Workflow

```sh
cargo fmt
cargo clippy --workspace --all-targets -- -D warnings
cargo test
sh scripts/local-e2e-demo.sh
```

## CI Expectations

GitHub Actions runs `fmt`, `clippy`, and tests for this repo.

## Protocol Change Policy

- Protocol field changes MUST update RFC/schema/fixture artifacts.
- Relay behavior changes MUST update `RFC-0004` and conformance docs.
- Identity behavior changes MUST update `RFC-0002` and conformance docs.

## Contributing

See `CONTRIBUTING.md`.
