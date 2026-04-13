# aegit-cli

A git-flavored operator CLI for Aegis.

## Commands

- `aegit id init`
- `aegit id show`
- `aegit msg seal`
- `aegit msg open`
- `aegit relay push`
- `aegit relay fetch`

## Relay workflow

`aegit relay push` posts a sealed envelope JSON file to `POST /v1/envelopes`.

`aegit relay fetch` reads `GET /v1/envelopes/:recipient_id`.

- Without `--out`, it prints the relay JSON response.
- With `--out <dir>`, it writes one `<envelope-id>.json` file per fetched envelope so you can open one with `aegit msg open`.
