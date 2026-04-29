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

## Local E2E Demo

See [DEV-SETUP.md](./DEV-SETUP.md) for a repeatable local end-to-end workflow and smoke script:

```sh
sh scripts/local-e2e-demo.sh
```

## Relay workflow

`aegit relay push` posts a sealed envelope JSON file to `POST /v1/envelopes`.

`aegit relay fetch` reads `GET /v1/envelopes/:recipient_id`.

- Without `--out`, it writes into the default fetched directory for that recipient.
- With `--out <dir>`, it writes one `<envelope-id>.json` file per fetched envelope into that directory.

## Current v0.1 Status

CLI flows are development-oriented.

- demo crypto/signing is non-production
- no production PQ cryptography
- no production resolver integration

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
