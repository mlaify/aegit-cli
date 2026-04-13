# aegit-cli

`aegit-cli` is the git-flavored command line interface for the Aegis ecosystem.

Think:

- `git`, but for encrypted message objects and identity flows
- protocol and relay tooling that feels sharp, scriptable, and composable
- a clean operator/developer surface over `aegis-core`

## Vibe

- terse commands
- readable output
- sane defaults
- subcommands that map to real protocol actions

## Early commands

- `aegit id init`
- `aegit id show`
- `aegit msg seal`
- `aegit msg open`
- `aegit relay push`
- `aegit relay fetch`

## Current status

This first cut supports local message sealing and opening using the demo crypto suite from `aegis-core`.
