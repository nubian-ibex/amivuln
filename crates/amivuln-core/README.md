# amivuln-core

Domain types, matching rules, policy and exit codes for amivuln. No I/O.

> **Internal crate.** `amivuln-core` is part of [amivuln](https://crates.io/crates/amivuln). It is published because the binary depends on it, and it carries **no API stability promise** before 1.0: any release may change or remove public items. If you want the tool, install `amivuln`.

## What is in it

- `Version`, `PackageRef`, `Ecosystem`: package identity, with the comparison algorithm tied to the ecosystem.
- `classify`: the rule that **the distribution status decides**. `Fixed(v)` with an installed version at or above `v` is patched, an older one is affected and names the fix, and an unknown or incomparable status is *unverified*, never affected.
- `Finding`, `Summary`, `RunReport`, `SourceReport` and `is_complete`: what a run produces. A failed required source makes the result incomplete.
- `Policy` and `FailOn`: `--fail-on`, `--fail-on-epss` and `--strict`.
- `exit_code`: the precedence 70, 64, 2, 3, 1, 0, so an incomplete result outranks findings.
- `ProcessRunner`: the port for running the allowlisted system tools.

## Example

```rust
use amivuln_core::{classify, DistroStatus, Verdict, Version};

let installed = Version::Rpm("1.3.0-1.fc43".parse().unwrap());
let fixed = Version::Rpm("1.3.1-1.fc43".parse().unwrap());
let verdict = classify(&installed, &DistroStatus::Fixed(fixed));
assert!(matches!(verdict, Verdict::Affected { .. }));
```

## Part of amivuln

[amivuln](https://github.com/nubian-ibex/amivuln) reports which CVEs apply to the packages on a Linux host, taking the patches the distribution already shipped into account. Documentation: <https://nubian-ibex.github.io/amivuln/>. Architecture: <https://nubian-ibex.github.io/amivuln/architecture.html>.

## License

Licensed under either of [Apache License, Version 2.0](https://github.com/nubian-ibex/amivuln/blob/main/LICENSE-APACHE) or [MIT license](https://github.com/nubian-ibex/amivuln/blob/main/LICENSE-MIT) at your option.
