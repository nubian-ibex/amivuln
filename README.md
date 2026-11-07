# amivuln

> Am I vulnerable? Backport-aware CVE checks for the binaries, services and packages on *this* host.

**Status:** pre-alpha (Phase 0, project foundation). Nothing is usable yet.

## Why

Generic scanners compare upstream versions and report CVEs that your distribution has already patched via backports. amivuln asks the distribution's own security data first, so a package fixed by your distro is not reported as vulnerable.

## Install

No release is published yet. Each release will provide:

- Static `musl` binaries (`x86_64`, `aarch64`) that run on any Linux distribution.
- `gnu` binaries (`x86_64`, `aarch64`) linked against glibc 2.34 or newer (Debian 12, Ubuntu 22.04, Fedora 35, RHEL 9 and later).
- `.deb`, `.rpm`, `.apk` and Arch (`.pkg.tar.zst`) packages wrapping the static binary.
- `SHA256SUMS` signed with cosign (keyless), GitHub build provenance attestations, and a CycloneDX SBOM.

Verify a download before running it:

```bash
gh attestation verify amivuln-x86_64-unknown-linux-musl.tar.zst --repo nubian-ibex/amivuln
cosign verify-blob SHA256SUMS --bundle SHA256SUMS.sigstore.json \
  --certificate-identity-regexp '^https://github.com/nubian-ibex/amivuln/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
sha256sum -c SHA256SUMS --ignore-missing
```

The `.rpm` and `.deb` packages are not signed with a package-manager key yet. Install the `.rpm` with `rpm -i --nosignature` only after the checks above.

## Usage

Planned, not implemented:

```text
amivuln nginx.service
amivuln /usr/sbin/nginx
amivuln cve CVE-2024-6387
amivuln pending
```

## How it works

Target, then resolver, then package identity, then advisory query, then distro-aware matching, then enrichment (KEV, EPSS), then policy and report. Only ecosystem, package name and version ever leave the host. No telemetry.

## Limitations

Linux only (Fedora and Arch first). Kernel CVEs, container image scanning and lockfile analysis are out of scope until after 1.0.

## Comparison

Trivy and Grype scan images and filesystems; osv-scanner scans lockfiles; arch-audit and debsecan cover one distro each. amivuln starts from a single installed target and applies distro patch status.

## Security

See [SECURITY.md](SECURITY.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT) at your option.
