# Changelog

All notable changes to this repository are documented here.

## [Unreleased]

### v0.3.0-alpha — phase 3 (send-side integration; end-to-end forward secrecy)

- `aegit msg seal`: when `--relay <url>` is configured and the recipient's identity advertises the hybrid PQ suite, calls `aegis_identity::resolver::claim_one_time_prekey()` to atomically pull one one-time prekey from the recipient's published pool. The claimed Kyber768 public key replaces the recipient's long-term Kyber768 in the hybrid combine; `envelope.used_prekey_ids` is stamped with the claimed `key_id` before signing so the outer signatures cover it.
- `aegit msg seal`: graceful fallback on `PrekeyPoolExhausted` — falls back to long-term Kyber768 from the IdentityDocument with a stderr warning that forward secrecy is degraded for that message. Other claim errors are surfaced (the user's relay is unreachable; push will fail too).
- `aegit msg seal`: new `--no-prekey` escape hatch to force long-term Kyber768. Useful for offline use, diagnostics, and deterministic fallback testing.
- `aegit msg open`: when `envelope.used_prekey_ids` is non-empty, looks up the matching `OneTimePrekeySecret` in the local `<id>.prekey-secrets.json` (via the `state::prekey_secrets_path()` shipped in phase 2) and substitutes the prekey's Kyber768 secret in `HybridPqSuite::for_recipient`. Clear error messages distinguish "no prekey-secrets file" from "key_id not in pool (already consumed or stale claim)".
- `aegit msg open`: **forward-secrecy delete** — only after a successful AEAD-verified `decrypt_payload`, the consumed `OneTimePrekeySecret` is spliced out of the local `PrekeyBundlePrivateMaterial` and the file is rewritten via tmp-file + rename. Persistence failure surfaces as a stderr warning but does not poison the returned plaintext.
- 6 new unit tests covering the load + consume contract: matching key returns bytes; missing key gives clear error; missing file gives clear error; consume removes only the matching entry; consume is idempotent on already-removed key; consume is a no-op when the file is absent.

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
