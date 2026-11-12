# amivuln-sources

Parsers for the vulnerability data sources used by amivuln, and the bounded HTTPS client that fetches them.

> **Internal crate.** `amivuln-sources` is part of [amivuln](https://crates.io/crates/amivuln). It is published because the binary depends on it, and it carries **no API stability promise** before 1.0: any release may change or remove public items. If you want the tool, install `amivuln`.

## What is in it

- `arch`: the Arch Security Tracker (`issues/all.json`).
- `fedora`: `repomd.xml` (with SHA-256 verification of the metadata) and `updateinfo`, plain or zstd. Only CVE ids that open a bugzilla bug title count as fixed CVEs, and security updates that name no CVE are kept under their update id.
- `kev` and `epss`: CISA Known Exploited Vulnerabilities and FIRST EPSS.
- `http`: reqwest with rustls (`ring`), HTTPS only, at most three redirects, no referrer, a fixed user agent, a timeout and a body limit enforced while streaming.
- `fetch`: `fetch_cached` prefers fresh cache, then a conditional request, then a stale copy, and reports which one it used.

Every parser takes bytes, caps its input size, drops identifiers that do not look right and is covered by tests against fixtures recorded from the real services. No test uses the network.

## Part of amivuln

[amivuln](https://github.com/nubian-ibex/amivuln) reports which CVEs apply to the packages on a Linux host, taking the patches the distribution already shipped into account. Documentation: <https://ibexwall.com/amivuln/>. Architecture: <https://ibexwall.com/amivuln/architecture.html>.

## License

Licensed under either of [Apache License, Version 2.0](https://github.com/nubian-ibex/amivuln/blob/main/LICENSE-APACHE) or [MIT license](https://github.com/nubian-ibex/amivuln/blob/main/LICENSE-MIT) at your option.
