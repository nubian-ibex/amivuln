# Security and privacy

## What leaves the host

Only the ecosystem, the package name and the version, in requests to the
sources listed in [Data sources](sources.md). EPSS requests carry CVE ids. No
host name, path, user name or address is ever sent, and a test inspects every
request to make sure of it. There is no telemetry and no update check.

## How the tool protects itself

- It never runs the target binary. Versions come from the package manager.
- System tools run from fixed absolute paths with a cleared environment,
  `LC_ALL=C`, fixed arguments, a timeout and an output limit.
- Advisory data is untrusted: sizes and nesting depth are limited, identifiers
  that do not look like CVE ids are dropped, and control characters never
  reach the terminal.
- The Fedora metadata is checked against the SHA-256 in `repomd.xml`, so a
  mirror serving other bytes is rejected.
- Network access uses HTTPS only, with rustls, and at most three redirects.

## Reporting a vulnerability

Use GitHub private vulnerability reporting:
[github.com/nubian-ibex/amivuln/security/advisories/new](https://github.com/nubian-ibex/amivuln/security/advisories/new).
See the repository's `SECURITY.md` for response targets.

## Release integrity

Releases are built by GitHub Actions from a signed tag and ship build
provenance attestations, a cosign signature over `SHA256SUMS` and an SBOM.
Release builds are reproducible when built in the same environment; see
`docs/reproducible-builds.md` in the repository.
