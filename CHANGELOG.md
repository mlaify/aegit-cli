# Changelog

All notable changes to this repository are documented here.

## [Unreleased]

- Ongoing `v0.2.0-alpha` stabilization.

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
