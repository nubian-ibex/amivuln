# amivuln-report

Output formatters for amivuln: summary, detail and versioned JSON.

> **Internal crate.** `amivuln-report` is part of [amivuln](https://crates.io/crates/amivuln). It is published because the binary depends on it, and it carries **no API stability promise** before 1.0: any release may change or remove public items. If you want the tool, install `amivuln`.

## What is in it

- `render_summary` and `render_detail`: human-readable output with optional ANSI color. Affected and unverified findings are listed apart, and an incomplete result is printed loudly.
- `render_json`: schema version 1, fixed field order, one document per run. The schema is published at <https://ibexwall.com/amivuln/schema/v1.json> and the real output is validated against it in the tests.
- `sanitize_terminal`: replaces control characters, including ESC, so text from advisories cannot inject escape sequences.

The host object never contains a host name, address or user.

## Part of amivuln

[amivuln](https://github.com/nubian-ibex/amivuln) reports which CVEs apply to the packages on a Linux host, taking the patches the distribution already shipped into account. Documentation: <https://ibexwall.com/amivuln/>. Architecture: <https://ibexwall.com/amivuln/architecture.html>.

## License

Licensed under either of [Apache License, Version 2.0](https://github.com/nubian-ibex/amivuln/blob/main/LICENSE-APACHE) or [MIT license](https://github.com/nubian-ibex/amivuln/blob/main/LICENSE-MIT) at your option.
