# ADR-0005: SQLite for cache and offline database

- Status: Proposed
- Date: 2026-11-07

## Context

The HTTP cache and the offline vulnerability database need transactional, queryable local storage.

## Options

- rusqlite with the bundled feature.
- Flat files (JSON) with a custom index.
- Embedded KV store (redb, sled).

## Decision

Recommended: rusqlite (bundled), with versioned migrations in code.

## Consequences

- Compiles a C library (SQLite) into the binary; requires a C toolchain for builds.
- One storage format for cache and offline DB, inspectable with standard tools.
