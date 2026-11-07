# ADR-0002: Rust edition 2024 and MSRV policy

- Status: Proposed
- Date: 2026-11-07

## Context

A security tool benefits from memory safety, static binaries and a mature supply-chain ecosystem.

## Options

- Rust, MSRV = latest stable minus 2.
- Rust, MSRV = latest stable (no policy).
- Go: simpler distribution, weaker type-level guarantees for parsers.

## Decision

Recommended: Rust edition 2024, pinned toolchain in `rust-toolchain.toml`, MSRV declared as stable minus 2 and checked in CI.

## Consequences

- MSRV is bumped deliberately, not accidentally.
- The pinned toolchain and the MSRV differ; CI checks both.
