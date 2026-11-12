# amivuln-version

Version comparison for RPM and pacman packages, verified against the reference implementations.

> **Internal crate.** `amivuln-version` is part of [amivuln](https://crates.io/crates/amivuln). It is published because the binary depends on it, and it carries **no API stability promise** before 1.0: any release may change or remove public items. If you want the tool, install `amivuln`.

## What is in it

- `rpmvercmp` and `RpmEvr`: RPM `epoch:version-release` ordering, including `~` and `^`.
- `alpm_vercmp`, `pacman_vercmp` and `PacmanVersion`: the libalpm algorithm used by pacman.

Both are pure functions over strings with no dependencies. They compare ASCII segments exactly as the reference tools do, so non-ASCII bytes act as separators, and numeric segments are unbounded integers (no overflow).

## How it is tested

The rpm table from the upstream test suite, property checks (reflexive, antisymmetric, transitive) over generated corpora, and differential runs against the real tools: about 4000 generated pairs against `rpm` and 2300 against `vercmp` from pacman 7.1, with no divergence.

## Example

```rust
use amivuln_version::rpmvercmp;
use std::cmp::Ordering;

assert_eq!(rpmvercmp("1.0~rc1", "1.0"), Ordering::Less);
assert_eq!(rpmvercmp("1.0^git1", "1.0"), Ordering::Greater);
```

## Part of amivuln

[amivuln](https://github.com/nubian-ibex/amivuln) reports which CVEs apply to the packages on a Linux host, taking the patches the distribution already shipped into account. Documentation: <https://ibexwall.com/amivuln/>. Architecture: <https://ibexwall.com/amivuln/architecture.html>.

## License

Licensed under either of [Apache License, Version 2.0](https://github.com/nubian-ibex/amivuln/blob/main/LICENSE-APACHE) or [MIT license](https://github.com/nubian-ibex/amivuln/blob/main/LICENSE-MIT) at your option.
