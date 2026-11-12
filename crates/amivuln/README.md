# amivuln

**Am I vulnerable?** Backport-aware CVE checks for the packages on a Linux host.


```console
$ amivuln --all --fail-on high
```

amivuln tells you which CVEs apply to a package, a file, a systemd service or a version on *this* host, using your distribution's own security data, so backported fixes are not reported and pending security updates are. Fedora and Arch Linux are supported.

## Install

```bash
cargo install amivuln --locked
```

Prebuilt static binaries, `.deb`, `.rpm`, `.apk` and Arch packages with man pages and completions are attached to every [GitHub release](https://github.com/nubian-ibex/amivuln/releases), together with checksums, build attestations, a cosign signature and an SBOM.

## Usage

```bash
amivuln nginx                          # an installed package
amivuln /usr/sbin/nginx                # the package that owns a file
amivuln nginx.service                  # the package behind a systemd unit
amivuln openssl@3.5.1-1 --distro arch  # a version, without reading the host
amivuln --all --fail-on high           # every installed package, exit 1 on HIGH or worse
amivuln --all -f json > report.json    # versioned JSON
```

Exit codes: `0` clean, `1` findings at or above `--fail-on`, `2` incomplete (a required source was unavailable), `3` target not resolved, `64` usage error, `70` internal error.

Only the ecosystem, package name and version leave the host. There is no telemetry.

Full documentation: <https://ibexwall.com/amivuln/>.

## Project

Source, issues and releases: <https://github.com/nubian-ibex/amivuln>. Architecture: <https://ibexwall.com/amivuln/architecture.html>.

## License

Licensed under either of [Apache License, Version 2.0](https://github.com/nubian-ibex/amivuln/blob/main/LICENSE-APACHE) or [MIT license](https://github.com/nubian-ibex/amivuln/blob/main/LICENSE-MIT) at your option.
