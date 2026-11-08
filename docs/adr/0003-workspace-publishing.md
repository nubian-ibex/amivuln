# ADR-0003: Multi-crate workspace, all crates published

- Status: Accepted (amended 2026-11-08)
- Date: 2026-11-07

## Context

Library API stability is a contract the project does not want to maintain before 1.0. The first plan was to publish only the `amivuln` binary and mark the internal crates `publish = false`.

## Options

- Single crate.
- Multi-crate workspace, only the binary published.
- Multi-crate workspace, all crates published.

## Decision

Multi-crate workspace with **all crates published**. The first plan does not work: `cargo publish` for a crate requires every dependency to exist on crates.io, so the binary cannot be published while its internal crates are `publish = false` (confirmed on 2026-11-08, the six names returned 404 and `cargo publish -p amivuln --dry-run` failed). Accepted by the maintainer.

## Consequences

- The internal crates (`amivuln-core`, `-resolve`, `-version`, `-sources`, `-cache`, `-report`) are on crates.io. Their descriptions state that they are internal and carry no API stability promise before 1.0.
- All crates share one version and release together. `cargo publish --workspace` publishes them in dependency order.
- Trusted Publishing must be configured for each crate on crates.io.
- `xtask` stays `publish = false`.
