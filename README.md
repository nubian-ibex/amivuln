<p align="center">
  <img src="https://raw.githubusercontent.com/nubian-ibex/amivuln/main/assets/banner.jpg" alt="amivuln: Am I vulnerable? Backport-aware CVE checks for Linux" width="800">
</p>

<p align="center">
  <a href="https://github.com/nubian-ibex/amivuln/actions/workflows/ci.yml"><img src="https://github.com/nubian-ibex/amivuln/actions/workflows/ci.yml/badge.svg?branch=main" alt="CI"></a>
  <a href="https://crates.io/crates/amivuln"><img src="https://img.shields.io/crates/v/amivuln.svg" alt="crates.io"></a>
  <a href="https://ibexwall.com/amivuln/"><img src="https://img.shields.io/badge/docs-amivuln-4de6b8" alt="Documentation"></a>
  <img src="https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue" alt="License: MIT OR Apache-2.0">
  <a href="https://www.bestpractices.dev/projects/16540"><img src="https://www.bestpractices.dev/projects/16540/badge" alt="OpenSSF Best Practices"></a>
  <a href="https://scorecard.dev/viewer/?uri=github.com/nubian-ibex/amivuln"><img src="https://api.scorecard.dev/projects/github.com/nubian-ibex/amivuln/badge" alt="OpenSSF Scorecard"></a>
</p>

# amivuln

**Am I vulnerable?** amivuln tells you which CVEs apply to a package, a file or a version on *this* host, taking the patches your distribution already shipped into account.

Generic scanners compare upstream version ranges, so they report CVEs your distribution fixed long ago through backports, and they miss the security update you have not installed yet. amivuln asks the distribution's own security data first.

```console
$ amivuln pcre2 --format detail
pcre2 10.47-1.fc44.1 (Fedora 44)
  CRITICAL 0   HIGH 8   MEDIUM 0   LOW 0   KEV 0   EPSS max 0.00
  Fixed in: 10.49-1.fc44  (dnf upgrade pcre2)
  Affected:
    CVE-2026-103111  HIGH   fix: 10.49-1.fc44  EPSS 0.00
    ...

source fedora-updateinfo  ok  age 0s  required
source kev                ok  age 0s
source epss               ok  age 0s
result: complete
```

**Status:** beta (0.x). The JSON output (schema version 1) and the exit codes are the contract and are tested against golden documents. Flags and configuration keys may still change in a minor release before 1.0; the changelog names every such change. See [Supported distributions](https://ibexwall.com/amivuln/sources.html#supported-distributions) for exactly what each distribution gives you.

## Highlights

- **Backport-aware.** The distribution's status decides, never an upstream version range.
- **Honest about gaps.** Every result lists the status of each data source. If a required source is down the result is *incomplete* and the exit code is `2`, so an outage never looks like a clean scan.
- **Unverified is not affected.** Findings the distribution cannot confirm are listed apart and never counted with the affected ones.
- **Built for CI.** `amivuln --all --fail-on high`, versioned JSON with a published schema, deterministic output, stable exit codes.
- **Private.** Only the ecosystem, package name and version leave the host. No telemetry.
- **Safe to run.** It never executes the target, runs system tools from fixed paths with limits, and treats advisory data as untrusted.
- **Verifiable releases.** Checksums, GitHub build attestations, a cosign signature and an SBOM.

## Install

Download a release from [GitHub Releases](https://github.com/nubian-ibex/amivuln/releases): static `musl` binaries for `x86_64` and `aarch64`, `gnu` binaries (glibc 2.34 or newer), and `.deb`, `.rpm`, `.apk` and Arch packages that also install the man pages and shell completions. Or build from source:

```bash
cargo install amivuln --locked
```

Verify a download before running it:

```bash
gh attestation verify amivuln-x86_64-unknown-linux-musl.tar.zst --repo nubian-ibex/amivuln
cosign verify-blob SHA256SUMS --bundle SHA256SUMS.sigstore.json \
  --certificate-identity-regexp '^https://github.com/nubian-ibex/amivuln/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
sha256sum -c SHA256SUMS --ignore-missing
```

The `.rpm` and `.deb` packages are not signed with a repository key yet; use `rpm -i --nosignature` after the checks above.

## Usage

```bash
amivuln nginx                          # an installed package
amivuln /usr/sbin/nginx                # the package that owns a file
amivuln nginx.service                  # the package behind a systemd unit
amivuln openssl@3.5.1-1 --distro arch  # a version, without reading the host
amivuln --all --fail-on high           # every installed package; exit 1 on HIGH or worse
amivuln --all -f json > report.json    # machine-readable, schema version 1
```

More ways to ask: `amivuln cve CVE-2024-6387` (is this host affected?), `amivuln pending` (which updates close the most risk), `amivuln restart` (processes still running replaced files), `amivuln --container ID` (a podman or docker container), `amivuln --packages-from list.txt` (a list exported from another host), `amivuln --sbom FILE`, `amivuln --pid PID`, `amivuln tui` (full-screen view, built with `--features tui`), `amivuln mcp` (a read-only server for AI assistants) and `amivuln db` (an offline database for hosts without internet).

Formats: `summary` (default), `detail`, `json`, `sarif`, `markdown`, `csv`, `prometheus`, `cyclonedx` (an SBOM with its vulnerability analysis) and `openvex`. Exit codes: `0` clean, `1` findings at or above `--fail-on`, `2` incomplete, `3` target not resolved, `64` usage error, `70` internal error. See `man amivuln` and `amivuln --help`.

In a CI pipeline, `amivuln --all --fail-on high` fails the job when an installed package has a pending high-severity security fix. To check a version for a distribution other than the runner's, use `name@version --distro fedora:44` or `--distro arch`.

Configuration is optional: `amivuln config init` writes a commented file. Search order, first file found wins: `./.amivuln.toml`, `$XDG_CONFIG_HOME/amivuln/config.toml`, `/etc/amivuln/config.toml`. Flags and `AMIVULN_*` variables override the file.

## Documentation

The full documentation is at **[ibexwall.com/amivuln](https://ibexwall.com/amivuln/)**: installation, quick start, user guide, reference, the JSON schema, architecture, data sources, and a false-positive FAQ.

## How it works

Target, then package identity (read from `rpm` or `pacman` on the host, from a container's package database, or from a list you provide), then the distribution's advisory data, then matching by distribution status, then KEV and EPSS enrichment, then policy and report. The workspace crates (`amivuln-core`, `-resolve`, `-version`, `-sources`, `-cache`, `-report`, `-sandbox`) are published because the binary depends on them; they carry no API stability promise before 1.0.

## Limitations

- **Hosts are read from their package database** on Fedora, RHEL, Rocky, AlmaLinux, openSUSE and Arch (through `rpm` and `pacman`), on Gentoo (the Portage database and the GLSAs of its own tree) and on Debian, Ubuntu and Alpine (the dpkg and apk files, nothing is run). Releases of Debian and Ubuntu without a stable `VERSION_ID` (testing, unstable, interim) and Alpine edge are not recognised: pass `--distro`, or check a package list.
- **The data decides what is visible.** Fedora's `updateinfo`, and the Alpine, openSUSE, Red Hat, Rocky and AlmaLinux advisories in OSV, only describe CVEs that shipped a fix: a CVE with no fix yet is not visible there. The Debian and Ubuntu records in OSV also include open issues, which are reported as affected with no fix version. Arch's tracker lists vulnerable packages without a fix. A result for RHEL is a lower bound.
- On Arch, a tracker entry marked *Vulnerable* with no fix is reported as affected only for the same upstream version as the recorded build; newer versions are listed as unverified.
- Binaries that no package owns are identified by their package note, Go build information or Rust `cargo-auditable` data, or (low confidence, marked as such) by the version banners of a short list of C products. Dependencies in a lockfile are out of scope: use a scanner such as osv-scanner for those.
- Kernel CVEs are out of scope until after 1.0. Windows and macOS hosts are not supported.

## Comparison

Trivy and Grype scan images and filesystems; osv-scanner scans lockfiles; arch-audit and debsecan cover one distribution each. amivuln starts from a single installed target and applies the distribution's patch status, with an explicit statement of what it could not verify. It complements the others rather than replacing them.

## Security

Report vulnerabilities privately through [GitHub security advisories](https://github.com/nubian-ibex/amivuln/security/advisories/new). See [SECURITY.md](https://github.com/nubian-ibex/amivuln/blob/main/SECURITY.md).

## Contributing

See [CONTRIBUTING.md](https://github.com/nubian-ibex/amivuln/blob/main/CONTRIBUTING.md). Wrong results are the most valuable reports: use the *false positive* or *false negative* issue form with the output of `amivuln PACKAGE -f json`.

## License

Licensed under either of [Apache License, Version 2.0](https://github.com/nubian-ibex/amivuln/blob/main/LICENSE-APACHE) or [MIT license](https://github.com/nubian-ibex/amivuln/blob/main/LICENSE-MIT) at your option.
