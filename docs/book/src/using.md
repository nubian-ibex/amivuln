# Using amivuln

Recipes for the places amivuln usually runs. Each one is complete enough to
copy; the [User guide](guide.md) explains the options in depth and the
[Reference](reference.md) lists them all.

Two things hold everywhere. Read `complete` and the `source` lines before you
trust an empty result: exit code `2` means a required source was unavailable,
which is not the same as clean. And only the ecosystem, package name and
version leave the machine.

## On your laptop or workstation

```bash
amivuln --all                      # score and totals for every installed package
amivuln pending                    # which updates close the most risk, riskiest first
amivuln openssl --format detail    # one package, every finding with its fix
amivuln /usr/bin/ssh               # the package that owns a file
```

`pending` is the most useful one on a desktop: it groups subpackages built from
one source, ranks by exploited (KEV) findings, severity and EPSS, and prints
the update command. amivuln never runs it.

For a full-screen view with filters, build with the `tui` feature:

```bash
cargo install amivuln --locked --features tui
amivuln tui          # up/down or j/k to move, K: KEV only, H: HIGH only, q: quit
```

## When a new CVE makes the news

```bash
amivuln cve CVE-2024-6387          # exit 1 when an installed package is affected
amivuln cve CVE-2024-6387 CVE-2025-26465
amivuln restart                    # processes still running files an update replaced
```

`cve` answers `affected`, `not affected` or `unknown`. `unknown` means the
distribution has no record of the CVE: it is not a statement that the host is
safe. After you install the update, `restart` lists the processes
that still run the old code.

## On a server, on a schedule

The units in `contrib/systemd` scan every six hours and write metrics for the
node_exporter textfile collector.

```bash
sudo install -m 0644 contrib/systemd/amivuln.{service,timer} /etc/systemd/system/
sudo systemctl enable --now amivuln.timer
```

Import `contrib/grafana/amivuln.json` into Grafana for the dashboard. For a
plain cron job that mails the result only when something is wrong:

```cron
17 6 * * *  root  amivuln --all --fail-on high -f markdown || mail -s "amivuln: $(hostname)" ops@example.org
```

To get a message instead of a dashboard, add a webhook to the configuration:

```toml
[notify]
webhook = "https://ntfy.sh/example-topic"
on = "violation"
```

## In a CI pipeline

GitHub Actions, with the verified release and code scanning:

```yaml
permissions:
  contents: read
  attestations: read
  security-events: write
steps:
  - uses: nubian-ibex/amivuln-action@5c61781a5497fbcb34401a5b2d2eee54a59e9ebc # v0.1.1
    with:
      args: --all --fail-on high -f sarif --output amivuln.sarif
  - uses: github/codeql-action/upload-sarif@33d7b85da1a04171e211befe2c739303b9a4c066 # v4.39.3
    if: always()
    with:
      sarif_file: amivuln.sarif
```

Pin third-party actions to a full commit SHA, as the first one is. GitLab CI
or any other runner:

```yaml
amivuln:
  image: fedora:44
  script:
    - curl -sSLO https://github.com/nubian-ibex/amivuln/releases/latest/download/amivuln-x86_64-unknown-linux-musl.tar.zst
    - tar --zstd -xf amivuln-x86_64-unknown-linux-musl.tar.zst --strip-components=1
    - ./amivuln --all --fail-on kev -f json --output amivuln.json
  artifacts:
    when: always
    paths: [amivuln.json]
```

Verify the download as shown in [Installation](installation.md) before you
rely on it. To fail a pull request only on findings it introduced, compare
with a report from the main branch:

```bash
amivuln --all -f json --output baseline.json        # on main, kept as an artifact
amivuln --all --baseline baseline.json --fail-on high   # on the pull request
```

## Containers and images

Scan a container by id or name; the runtime may be podman or docker. amivuln
reads its package database from an exported root file system and never runs
anything inside it.

```bash
id=$(podman create docker.io/library/alpine:3.18.0 true)
amivuln --container "$id" --fail-on high
podman rm "$id"
```

Alpine, Debian, Ubuntu, Fedora, Rocky, AlmaLinux and Red Hat (UBI) containers
are judged against their own release. An Alpine edge or alpha image has no
advisory data and is refused instead of reported clean. Pass several
`--container` options to check a whole stack in one report.

## Many hosts, or a host you cannot install anything on

On the host itself amivuln reads the installed packages, so none of this is
needed there. To check a machine from somewhere else, export a list from it and
check the list from wherever amivuln runs. One
`name@version` per line; `--distro` says which release the list belongs to.

```bash
# Fedora, RHEL, Rocky, AlmaLinux (on the target host)
rpm -qa --qf '%{NAME}@%|EPOCH?{%{EPOCH}:}|%{VERSION}-%{RELEASE}\n' > host.txt
# Debian and Ubuntu: advisories use the source package name
dpkg-query -W -f '${source:Package}@${Version}\n' > host.txt
# Alpine: advisories use the origin package
awk -F: '/^P:/{p=$2} /^V:/{v=$2} /^o:/{o=$2} /^$/{print (o?o:p)"@"v; p="";v="";o=""}' \
  /lib/apk/db/installed > host.txt

amivuln --packages-from host.txt --distro debian:12 --fail-on high
```

For a list of components from a build instead, point at a CycloneDX SBOM:

```bash
amivuln --sbom product.cdx.json --distro debian:12
```

## No internet on the host

Build the advisory database where there is a network, move one file, and
answer from it offline.

```bash
amivuln --all -f json > /dev/null                 # warm the cache once
amivuln db build --archive db.tar.zst
# copy db.tar.zst to the isolated host, then:
amivuln db verify db.tar.zst --key amivuln.pub --sig db.tar.zst.minisig
amivuln db pull db.tar.zst
amivuln --all --offline --fail-on high
```

Results from the database are reported as `stale`, with their age. The
project publishes a signed database per distribution family; see the guide.

## Behind a proxy or a corporate CA

```toml
[network]
proxy = "http://proxy.corp.example:3128"
ca_file = "/etc/pki/ca-trust/source/anchors/corp.pem"
```

Or point `sources.<name>.url` at an internal mirror. See the guide.

## From scripts and dashboards

The JSON report is a versioned contract, so `jq` is enough:

```bash
amivuln --all -f json | jq -r '.targets[] | select(.summary.kev > 0) | .package.name'
amivuln --all -f json | jq '[.targets[].findings[]] | group_by(.severity) | map({(.[0].severity): length}) | add'
amivuln --all -f csv > findings.csv        # spreadsheet-safe
amivuln --all -f prometheus --output /var/lib/node_exporter/textfile_collector/amivuln.prom
```

## From an AI assistant

`amivuln mcp` is a read-only Model Context Protocol server. Register it once:

```json
{ "mcpServers": { "amivuln": { "command": "amivuln", "args": ["mcp"] } } }
```

The assistant can then check packages, ask whether a CVE affects the host and
list pending updates. It has no shell, no path input and no way to pass
options.

## Files no package owns

A binary copied into `/opt`, a Go program or a Rust program from a build:

```bash
amivuln /opt/tool/bin/server          # note, Go build info or cargo-auditable data
```

If the file declares nothing, amivuln looks for the version banners of a short
list of C products and marks the result low confidence. With
`exec_version_probe = true` in `[general]` it also runs `--version` on the
file inside a Landlock and seccomp sandbox, which is off by default.
