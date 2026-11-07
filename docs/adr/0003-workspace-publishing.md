# ADR-0003: Multi-crate workspace, only amivuln published

- Status: Proposed
- Date: 2026-11-07

## Context

Library API stability is a contract the project does not want to maintain before 1.0.

## Options

- Single crate.
- Multi-crate workspace, all published.
- Multi-crate workspace, only the binary published.

## Decision

Recommended: multi-crate workspace; internal crates use `publish = false`.

## Consequences

- No semver obligations for internal crates before 1.0.
- Compile-time boundaries between domain and I/O are enforced by crate edges.
- Crates may be published later if a real library use case appears.
