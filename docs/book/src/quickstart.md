# Quick start

```bash
amivuln nginx                          # an installed package
amivuln /usr/sbin/nginx                # the package that owns a file
amivuln nginx.service                  # the package behind a systemd unit
amivuln openssl@3.5.1-1 --distro arch  # a version, without reading the host
amivuln --all                          # every installed package
```

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
amivuln --all -f json > amivuln.json   # keep a machine-readable record
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
