# aegit-cli

A git-flavored operator CLI for Aegis.

## Commands

- `aegit id init`
- `aegit id show`
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

- Sealed envelopes: `sealed/<recipient>/<envelope-id>.json`
- Fetched envelopes: `fetched/<recipient>/<envelope-id>.json`
- Opened payloads: `opened/<recipient>/<envelope-id>.json`

## Relay workflow

`aegit relay push` posts a sealed envelope JSON file to `POST /v1/envelopes`.

`aegit relay fetch` reads `GET /v1/envelopes/:recipient_id`.

- Without `--out`, it writes into the default fetched directory for that recipient.
- With `--out <dir>`, it writes one `<envelope-id>.json` file per fetched envelope into that directory.
