# ADR-0004: Async runtime and TLS stack

- Status: Proposed
- Date: 2026-11-07

## Context

Sources are queried concurrently over HTTPS and releases are static musl binaries for x86_64 and aarch64.

## Options

- tokio + reqwest (rustls, ring provider).
- ureq (blocking) with a thread pool.
- native-tls/OpenSSL: complicates static and cross builds (banned in deny.toml).

## Decision

Recommended: tokio with minimal features and reqwest with `default-features = false` and rustls using the `ring` provider. TODO(verify): confirm the binary-size budget (15 MB) with this stack once real code exists.

## Consequences

- Simple musl cross-compilation.
- Larger dependency tree than ureq; every addition must pass cargo-deny and cargo-vet.
