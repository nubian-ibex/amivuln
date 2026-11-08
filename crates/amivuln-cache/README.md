# amivuln-cache

SQLite-backed HTTP cache with ETag revalidation, for amivuln.

> **Internal crate.** `amivuln-cache` is part of [amivuln](https://crates.io/crates/amivuln). It is published because the binary depends on it, and it carries **no API stability promise** before 1.0: any release may change or remove public items. If you want the tool, install `amivuln`.

## What is in it

`Cache` stores response bodies with their `ETag` and `Last-Modified` validators and classifies each lookup against two ages:

- **Fresh**: younger than the TTL, use without asking the network.
- **Stale**: older than the TTL but within `stale_max_age`, revalidate and fall back to it when the network fails.
- **Expired**: only the validators are useful.

Time is always passed in as Unix seconds, so tests control the clock. The database file is created with mode `0600` in a `0700` directory, bodies are capped at 64 MiB, the schema is versioned with `PRAGMA user_version`, and keys are bound parameters (never interpolated).

## Example

```rust
use amivuln_cache::{Cache, Lookup, Policy};

let cache = Cache::in_memory()?;
let policy = Policy { ttl: 3600, stale_max_age: 72 * 3600 };
cache.put("https://example.org/data", b"body", Some("\"v1\""), None, 1_000)?;
assert!(matches!(cache.get("https://example.org/data", 1_100, policy)?, Lookup::Fresh(_)));
# Ok::<(), amivuln_cache::CacheError>(())
```

## Part of amivuln

[amivuln](https://github.com/nubian-ibex/amivuln) reports which CVEs apply to the packages on a Linux host, taking the patches the distribution already shipped into account. Documentation: <https://nubian-ibex.github.io/amivuln/>. Architecture: <https://nubian-ibex.github.io/amivuln/architecture.html>.

## License

Licensed under either of [Apache License, Version 2.0](https://github.com/nubian-ibex/amivuln/blob/main/LICENSE-APACHE) or [MIT license](https://github.com/nubian-ibex/amivuln/blob/main/LICENSE-MIT) at your option.
