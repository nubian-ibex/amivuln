# ADR-0001: Dual MIT/Apache-2.0 license and DCO

- Status: Proposed
- Date: 2026-11-07

## Context

The project must be free, open source and easy to package for Linux distributions and to embed in other Rust software.

## Options

- MIT OR Apache-2.0 (Rust ecosystem default, patent grant via Apache-2.0).
- MIT only: simpler, no patent grant.
- GPL-3.0: strong copyleft, friction for Rust library reuse.
Contributor terms: CLA or DCO.

## Decision

Recommended: MIT OR Apache-2.0 with DCO sign-off and no CLA.

## Consequences

- Every commit needs a Signed-off-by trailer.
- REUSE compliance is enforced in CI.
- Relicensing later requires contributor consent.
