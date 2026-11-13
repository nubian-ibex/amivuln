# Contributing

## Setup

Required tools: a Rust toolchain via `rustup` (the version is pinned in `rust-toolchain.toml`), `just`, `cargo-nextest`, `cargo-deny`, `cargo-audit`, `cargo-vet`, `typos`, `reuse`, `actionlint` and `zizmor`. Run `just ci` before opening a PR.

## Coding standards

- Rust 2024, formatted with `rustfmt` (`rustfmt.toml`); CI runs `cargo fmt --check`.
- `clippy` with the pedantic set and `-D warnings`, configured in the workspace `Cargo.toml` and `clippy.toml`. `unwrap`, `expect`, `panic!` and `unsafe` are denied outside tests; the only `unsafe` lives in one module of `amivuln-sandbox`, with a `SAFETY` comment on every block.
- Every source file starts with an SPDX header; public items have doc comments; comments explain why, not what.
- External text is sanitised before it reaches a terminal, CSV, Markdown or SARIF, and every file read, HTTP response and subprocess has a size or time limit.

CI enforces the formatting and lint rules, so a pull request that does not follow them cannot merge.

## Commits

- Conventional Commits, in English, imperative mood, subject up to 50 characters.
- Sign off every commit (`git commit -s`) to certify the [DCO](https://developercertificate.org/). No CLA.
- One logical change per commit and per PR.

## Tests

Tests must not touch the network. HTTP behavior is tested with recorded fixtures and `wiremock`. Synthetic fixtures use obviously fictional IDs such as `CVE-0000-0001`.

## Messages and languages

Text meant for a person is not written in the code. It lives in
`crates/amivuln-core/locales/en.txt` as `key = text` lines with `{name}`
placeholders, and the code asks for it with `tr("key")` or
`tr_args("key", &[("name", &value)])`. English is the source: another language
file may leave a key out (English is used) but may not add one or change its
placeholders; a test checks that, and that every key the code uses exists and
every key in `en.txt` is used. To add a language, add `locales/<code>.txt` and
a `Language` variant in `crates/amivuln-core/src/i18n.rs`; to correct a
translation, edit its file. Output that other programs read (JSON, SARIF, CSV,
CycloneDX, OpenVEX, Prometheus) is never translated.

## Reporting false positives and negatives

Use the issue forms. Include the distro and version, the `--format json` output and any evidence of the patch (changelog, advisory).

## AI-assisted contributions

Assisted contributions are welcome. The human author is fully responsible for the change and must disclose assistance with an `Assisted-by:` trailer in the commit message.

## Dependencies

A new dependency needs a justification in the PR (alternatives, maintenance status, license, binary size) and must pass `cargo deny check` and `cargo vet`.
