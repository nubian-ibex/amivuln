# Quick start

```bash
amivuln nginx                          # an installed package
amivuln /usr/sbin/nginx                # the package that owns a file
amivuln nginx.service                  # the package behind a systemd unit
amivuln openssl@3.5.1-1 --distro arch  # a version, without reading the host
amivuln --all                          # every installed package
```

## Questions about the whole host

```bash
amivuln cve CVE-2024-6387      # is any installed package affected?
amivuln pending                # which updates close the most risk, riskiest first
amivuln services               # check the package behind every running service
amivuln restart                # which processes still run files an update replaced
amivuln --packages-from list.txt   # check a package list exported from another host
```

`cve` exits 1 when a package is affected. When the distribution data has no
record of the CVE it says so explicitly: that is not a statement that the host
is safe. `pending` groups subpackages built from one source into one update and
ranks by exploited (KEV) findings, severity and EPSS. `restart` reads `/proc` (run it as root to see every process; the output says how many it could not inspect) and exits 1 when something needs a restart. `services` lists running systemd services that are not packaged without failing the run. A whole-system scan also
prints a host score from A to F (see ADR-0011 in the repository).

## Read the result

For every package you get the number of affected findings by severity, how
many are known to be exploited (CISA KEV), the highest EPSS score, and the
version that fixes them with the command you would run. amivuln never runs
that command.

Findings the distribution cannot confirm are listed apart as *unverified* and
are not counted with the affected ones.

## Fail a build

```bash
amivuln --all --fail-on high           # exit 1 on HIGH or worse
amivuln --all --fail-on kev            # exit 1 only on exploited CVEs
amivuln --all -f sarif > amivuln.sarif # SARIF 2.1.0 for code scanning
amivuln --all -f csv > amivuln.csv     # spreadsheet-safe (formula injection guarded)
```

Exit codes: `0` clean, `1` findings at or above `--fail-on`, `2` incomplete,
`3` target not resolved, `64` usage error, `70` internal error. Exit code `2`
keeps an outage of the advisory data from passing as a clean scan.

## A GitHub Actions step

```yaml
- name: Download amivuln
  run: |
    gh release download --repo nubian-ibex/amivuln --pattern 'amivuln-x86_64-unknown-linux-musl.tar.zst'
    gh attestation verify amivuln-x86_64-unknown-linux-musl.tar.zst --repo nubian-ibex/amivuln
    tar --zstd -xf amivuln-x86_64-unknown-linux-musl.tar.zst --strip-components=1
- name: Check packages
  run: ./amivuln --all --fail-on high
```

Next: the [User guide](guide.md) and the [Reference](reference.md).
