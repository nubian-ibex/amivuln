# Contributing

## Setup

Required tools: a Rust toolchain via `rustup` (the version is pinned in `rust-toolchain.toml`), `just`, `cargo-nextest`, `cargo-deny`, `cargo-audit`, `cargo-vet`, `typos`, `reuse`, `actionlint` and `zizmor`. Run `just ci` before opening a PR.

## Commits

- Conventional Commits, in English, imperative mood, subject up to 50 characters.
- Sign off every commit (`git commit -s`) to certify the [DCO](https://developercertificate.org/). No CLA.
- One logical change per commit and per PR.

## Tests

Tests must not touch the network. HTTP behavior is tested with recorded fixtures and `wiremock`. Synthetic fixtures use obviously fictional IDs such as `CVE-0000-0001`.

## Reporting false positives and negatives

Use the issue forms. Include the distro and version, the `--format json` output and any evidence of the patch (changelog, advisory).

## AI-assisted contributions

Assisted contributions are welcome. The human author is fully responsible for the change and must disclose assistance with an `Assisted-by:` trailer in the commit message.

## Dependencies

A new dependency needs a justification in the PR (alternatives, maintenance status, license, binary size) and must pass `cargo deny check` and `cargo vet`.
