# Changelog

All notable changes to this repository are documented here.

## [Unreleased]

### Resolver-aware identity lookup (closes #5)

- Wires the CLI through the new `aegis-identity::resolver::Resolver` trait (shipped in aegis-core PR #21). The five resolver call sites — `aegit msg seal` (alias resolution, identity resolution, prekey claim), `aegit id publish`, `aegit id publish-prekeys` — now construct an `HttpResolver` instance and go through trait methods instead of free functions. Behavior unchanged; behavior contract is now testable.
- New testable async helper `resolve_recipient_target_with<R: Resolver>(to, resolver)` extracts the alias-resolution branch of `resolve_recipient_target`. The sync entry point still drives the seal command; the async helper is the seam.
- 4 new pure-local tests use `aegis_identity::resolver::StaticResolver` (no HTTP) to validate fallback behavior:
  - Canonical `amp:did:key:*` identifier short-circuits — resolver is never queried
  - Known alias resolves and returns the cached doc for downstream PQ-suite detection
  - Unknown alias surfaces a descriptive error mentioning the alias name
  - The doc returned by an alias hit is `Some(...)` (regression guard for the supports_pq path)
- Local-dev default behavior preserved: free-function wrappers in core are still valid; the CLI just now goes through `HttpResolver` directly so consumers reading the source can see the resolver-aware code path.

### Lifecycle output polish + error hints on `aegit relay ...` (closes #6)

- Every relay subcommand now leads its stdout with a `status <verb>` line — `pushed` / `fetched` / `acknowledged` / `deleted` / `cleaned` — so quick-glance output answers "did it work?" first. Subsequent key=value lines are unchanged in spirit; some reordering for consistency.
- **Bug fix**: `aegit relay cleanup` was silently dropping `old_removed` from its output (the relay returns it; the CLI just never printed it). Now prints all three counters: `expired_removed`, `orphan_ack_removed`, `old_removed`.
- New 4xx/5xx error hint mapping. On non-2xx responses, the CLI now emits to stderr:
  - The relay's structured `relay_error_code` + `relay_error_message` lines when the body decodes as `RelayErrorResponse` (raw body otherwise)
  - A `hint:` line with operator-targeted guidance, varied by HTTP status × operation. Examples:
    - `401` → `relay requires authentication. Pass --token, set AEGIS_RELAY_TOKEN, or add 'token = "..."' to ~/.aegis/aegit/config.toml`
    - `403` → `token lacks the required scope (push needs PushEnvelope; ack/delete/cleanup need LifecycleChange; identity puts need IdentityWrite)`
    - `404` on `ack` → `envelope not found (it may already have been acknowledged or deleted, or the recipient ID is wrong)`
    - `404` on `delete` → similar but distinguishes "may already have been deleted"
    - `404` on `fetch` → `no envelopes for recipient (or recipient ID is unknown to this relay)`
    - `409` on `push` → `envelope rejected by relay (commonly: prekey already used or unknown). Re-claim a fresh prekey with 'aegit msg seal --relay ...' and retry.`
    - `413` on `push` → mentions size limit
    - generic `5xx` → `try again later`
- 8 new unit tests on `relay_error_hint` cover each case + the 2xx-returns-None safety property.

### CLI config file support (closes #7)

- New `~/.aegis/aegit/config.toml` config file with per-user defaults for `relay`, `token`, and `state_dir`. All keys optional. Override file location with `AEGIT_CONFIG=/path/to/config.toml`.
- Resolution order for each setting: explicit CLI flag → env var (`AEGIS_RELAY_URL` / `AEGIS_RELAY_TOKEN` / `AEGIT_STATE_DIR`) → config file → built-in default.
- All five relay subcommands (`push`, `fetch`, `ack`, `delete`, `cleanup`) now have `--relay` and `--token` as **optional** flags backed by the config-file fallback. `--relay` was previously required on every invocation; existing scripts continue to work since explicit flags still win. `aegit relay fetch` gains `--token` (was previously omitted by accident).
- `aegit msg seal --relay` now also falls back to the config file when neither flag nor `AEGIS_RELAY_URL` env is set.
- `aegit relay ...` without any relay source emits a clear error pointing at the three resolution paths: `no relay URL configured. Pass --relay <url>, set AEGIS_RELAY_URL, or add 'relay = "..."' to ~/.aegis/aegit/config.toml`.
- Malformed config files are a hard error (silent typos can't masquerade as "no config"). Unknown keys are tolerated for forward compatibility.
- New deps: `serde` (with `derive`), `toml`, `thiserror`. New module `src/config.rs`.
- 13 new unit tests cover load semantics (missing / valid / partial / empty / malformed / unknown-keys), the resolution-order matrix (flag > env > config > none), empty-string-arg-as-unset edge case, and `config_path` resolution from `AEGIT_CONFIG` and `HOME`.
- README documents the schema, file location, override env, and resolution order.

### Configurable signature verification policy on `aegit msg open` (closes #4)

- New `--signature-policy <mode>` flag on `aegit msg open`. Modes: `none`, `best-effort` (default — mirrors v0.2 behavior), `require-classical`, `require-pq`, `require-both`. Wires through to the new `SignaturePolicy` types from `aegis-crypto` (closes aegis-core#6).
- New stdout line printed after the existing per-slot lines: `signature_policy accept (best-effort)` or `signature_policy reject (require-pq): <reason>`. Existing `classical_signature verified/FAILED/absent`, `pq_signature ...`, and demo-suite `signature_status ...` lines are preserved verbatim so anything parsing aegit's output still works.
- On `Reject`, the CLI returns a non-zero exit and **does not decrypt or write the payload** — strict modes are real gates, not warnings. On `Accept`, the existing decrypt/write/print flow is unchanged.
- Demo-suite path: legacy `SignatureStatus` (`Unsigned` / `Verified` / `Failed` / `Unavailable`) is mapped to the unified `SignatureCheck` so all five policy modes work for demo envelopes too. `Unavailable` → `Failed` (a present-but-unverified signature must not pass policy checks).
- Hybrid-PQ path: per-slot results are built directly from the existing `verify_envelope` / `verify_envelope_pq` calls.
- 14 new unit tests cover the CLI flag wiring: enum mapping, default-is-best-effort, kebab-case label round-trip, `SignatureStatus` → `SignatureCheck` adapter, and `enforce_policy` Accept/Reject behavior across each mode.

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
