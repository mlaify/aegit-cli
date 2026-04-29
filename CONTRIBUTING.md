# Contributing to aegit-cli

## Scope

`aegit-cli` is a thin CLI over Aegis core crates and protocol semantics.

Protocol references:

- `../aegis-spec/docs/protocol-index.md`
- `../aegis-spec/docs/implementation-conformance-v0.1.md`

Local E2E setup:

- `DEV-SETUP.md`

## Development Workflow

```sh
cargo fmt
cargo clippy --workspace --all-targets -- -D warnings
cargo test
sh scripts/local-e2e-demo.sh
```

## CI Expectations

This repo runs Rust CI for `fmt`, `clippy`, and tests.

## Protocol Change Policy

- Protocol field changes MUST update RFC/schema/fixture artifacts.
- Relay behavior assumptions MUST stay aligned with `RFC-0004` and conformance docs.
- Identity behavior changes MUST update `RFC-0002` and conformance docs.

## Current v0.1 Status

CLI flows are development-oriented.

- demo crypto/signing is non-production
- no production PQ cryptography
- no production resolver integration
