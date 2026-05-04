# Changelog

All notable changes to this repository are documented here.

## [Unreleased]

### v0.3.0-alpha — phase 2 (prekey publish + atomic claim)

- New `aegit id publish-prekeys --relay <url> [--count N=10] [--identity <id>]` command:
  - Generates `count` fresh ML-KEM-768 one-time prekeys via `aegis-identity::generate_prekey_bundle()`.
  - Signs the bundle in place using the identity's existing hybrid PQ signing keys.
  - Persists private halves to `<id>.prekey-secrets.json` (append-merging across runs so the local pool grows; secrets are written BEFORE the network call so a failed publish doesn't lose key material that may already be on the relay).
  - POSTs the signed bundle to the relay's `POST /v1/identities/:id/prekeys` endpoint.
- New `state::prekey_secrets_path(identity_id)` returns the local path of the secrets file.

## [v0.2.0-alpha] - 2026-05-03

### Crypto

- PQ key generation via `aegit id init` produces hybrid X25519 + ML-KEM-768 material
- `aegit msg seal` / `aegit msg open` auto-select the suite advertised by the recipient identity (hybrid PQ when available, demo otherwise)

### Identity workflow

- `aegit id publish` publishes the local identity document to a relay (`PUT /v1/identities/:id`)
- `aegit msg seal` auto-resolves recipient identity via the relay's identity/alias endpoints when only an `amp:did:key:` or alias is supplied

## [v0.1.0-alpha] - 2026-04-29

- Initial public alpha baseline for the Aegis multi-repo project.
- Scope is explicitly draft/prototype and non-production.
- Demo/local-development crypto workflows only; production PQ is not implemented.
