# aegit-cli

A git-flavored operator CLI for Aegis.

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
