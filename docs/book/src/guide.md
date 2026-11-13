# User guide

## Checking packages

```bash
amivuln nginx                 # installed package by name
amivuln /usr/sbin/nginx       # the package that owns this file
amivuln openssl@3.5.1-1       # a specific version, without reading the host
amivuln pkg:rpm/fedora/nginx@1.26.2-1.fc44?arch=x86_64   # a package URL
amivuln --all                 # every installed package
```

`--file PATH`, `--package NAME[@VERSION]` and `--purl PURL` are explicit forms
of the same targets and can be repeated. When a name is ambiguous (for
example several kernel versions installed) amivuln fails with exit code 3 and
tells you which selector to use. It never guesses.

## Reading the result

The summary prints, per package, the number of affected findings by
severity, how many are in the CISA KEV catalog, the highest EPSS score, and
the fixed version with the command you would run to apply it. amivuln never
runs that command.

Findings the distribution could not confirm are listed apart as *unverified*
and are not counted with the affected ones. `--strict` makes them count for
`--fail-on`.

The last lines list every source that was consulted, its status
(`ok`, `stale`, `failed`, `skipped`), its age, and whether the result is
complete. A required source that failed makes the result **incomplete**: the
output says so loudly and the exit code is 2, so an outage can never look like
a clean scan.

## Use in CI

```bash
amivuln --all --fail-on high           # fail the job on HIGH or worse
amivuln --all --fail-on kev            # fail only on actively exploited CVEs
amivuln --all --fail-on-epss 0.5       # fail on high exploitation probability
amivuln --all -f json > amivuln.json   # keep a machine-readable record
```

To check a version for another distribution, for example a Fedora package in a
Debian-based runner, pass `--distro fedora:44` or `--distro arch` together
with `name@version`. Only the ecosystem, package name and version are sent over
the network.

## Offline and caching

Responses are cached in `$XDG_CACHE_HOME/amivuln/cache.sqlite` (default
`~/.cache/amivuln`). A response younger than `cache_ttl` (6 h) is used without
asking the network; when the network fails, one up to `stale_max_age` (72 h)
old is used and reported as `stale`. `--offline` never touches the network and
fails closed (exit 2) when the cache has nothing usable. `amivuln cache info`
and `amivuln cache clear` manage the cache; `--no-cache` skips the disk cache.

## Configuration

`amivuln config init` writes a commented default file; `amivuln config show`
prints the effective configuration and `amivuln config validate` checks it.
Unknown keys are rejected so typos do not pass silently.

## SBOM and VEX

`amivuln --all -f cyclonedx` writes a CycloneDX 1.6 document: every installed
package is a component, with its purl and how it was identified
(`amivuln:provenance`), and every finding is a vulnerability with its analysis.
`amivuln --all -f openvex` writes an OpenVEX 0.2.0 document with one statement
per package and CVE. Both are for `check`; `pending`, `cve` and `restart` refuse
them.

The state comes from the distribution's own data:

- affected, with the version that fixes it when one is published: `exploitable`
  in CycloneDX, `affected` in OpenVEX;
- fixed at or before the installed version, which includes fixes a distribution
  backported: `resolved` and `fixed`;
- declared not affected, by the distribution or by a VEX file you passed with
  `--vex`: `not_affected` in both, with the reason;
- not verifiable (no distribution statement, or versions that cannot be
  compared): `in_triage` and `under_investigation`.

Which of these appear depends on what the source lists. Fedora's `updateinfo`
and the Arch Security Tracker list what they fixed, so fixed CVEs show up
there. OSV is asked about the installed version, so on Debian, Ubuntu, Alpine
and Red Hat hosts the documents list the open issues, not the ones already
closed.

The statements are this tool's assessment of this host, not an attestation
by the distribution. A run that was incomplete is marked
`amivuln:complete = false` in the CycloneDX metadata, and a package amivuln
could not resolve is counted in `amivuln:unresolved`; the exit code is 2 as
usual. The output is deterministic: components and statements are sorted by
purl, and nothing random (no serial number) is added. The tests validate both
documents against the official schemas.

## Prometheus and the node_exporter textfile collector

`amivuln --all -f prometheus` writes text metrics: `amivuln_findings{severity,kev}`,
`amivuln_unverified_findings`, `amivuln_source_up{source}`,
`amivuln_source_age_seconds{source}`, `amivuln_run_complete` and
`amivuln_last_run_timestamp_seconds`. Labels come from fixed vocabularies, so
no package name, hostname or path reaches the metrics store. Write the output
to a `.prom` file in the textfile directory through a temporary file and a
rename so the collector never reads a partial file.

## Running on a timer

`contrib/systemd/amivuln.service` and `amivuln.timer` scan the host every six
hours and write `amivuln.prom` for the textfile collector, through `--output`
so the file is replaced atomically. The service runs as a dynamic user with no
capabilities, a read-only file system and a system call filter;
`systemd-analyze security amivuln.service` reports an exposure of 1.2.

```bash
sudo install -m 0644 contrib/systemd/amivuln.{service,timer} /etc/systemd/system/
sudo systemctl enable --now amivuln.timer
```

Adjust `ExecStart` and `ReadWritePaths` when the textfile directory differs.
Exit codes 1 (policy), 2 (incomplete) and 3 (unresolved) still write a valid
file, so the unit only fails on a usage or internal error.

## Behind a proxy or a corporate CA

Set the `[network]` table in the configuration file:

```toml
[network]
proxy = "http://proxy.corp.example:3128"   # default: HTTPS_PROXY and NO_PROXY
ca_file = "/etc/pki/ca-trust/source/anchors/corp.pem"
user_agent_suffix = "team-sre"
```

`ca_file` adds trusted roots to the built-in ones (PEM, at most 1 MiB).
`user_agent_suffix` is appended to the `User-Agent` and is the only
host-specific text that can leave the machine, only when you set it. A proxy
URL may carry credentials; amivuln never prints it. To use an internal mirror
instead, set `sources.<name>.url`.

## For AI agents: the MCP server

`amivuln mcp` speaks the Model Context Protocol over stdio (newline-delimited
JSON-RPC 2.0, protocol revisions 2025-06-18, 2025-03-26 and 2024-11-05). Register
it in a client such as:

```json
{ "mcpServers": { "amivuln": { "command": "amivuln", "args": ["mcp"] } } }
```

The tools are read-only and each one runs a fixed command line with `-f json`;
the result is the same versioned report the command line prints.

- `check_target`: `targets` (1 to 20 package names, `name@version` or `pkg:` URLs) and an optional `distro`.
- `check_cve`: `id` such as `CVE-2024-6387`; scans every installed package.
- `pending_updates`, `needs_restart` and `list_services`: no arguments.

There is no shell, no file path input and no way to pass options: a target that
starts with `-` or holds control characters is refused. The server updates the
local cache like any other run; pass `--offline` or `--no-cache` to
`amivuln mcp` to restrict that. Always read `complete` and `sources` in a
result before treating an empty list as clean.

## Checking an SBOM

`amivuln --sbom bom.cdx.json --distro fedora:44 --fail-on high` reads a
CycloneDX JSON document (any 1.x), checks every component whose purl is an
`rpm`, `deb` or `alpm` package and leaves the host alone. A purl whose
namespace disagrees with `--distro` is an error. Components that are not OS
packages (npm, PyPI, Maven and so on) are not dropped silently: they appear as
`unresolved` entries, one per purl type with a count, and the run exits with 3.
To gate only on OS packages, filter the SBOM first, for example with
`jq '.components |= map(select(.purl // "" | startswith("pkg:rpm/")))'`.

## Resilient networks

Sources can have mirrors. A source that fails on its primary endpoint is asked
again on each mirror in `fallback`, in the order written, before it counts as
failed. Every failing call is retried with exponential backoff and jitter
(`retries`, default 2, at most 10); a `Retry-After` the server sends is honored
inside the retry budget. An endpoint that fails repeatedly trips a per-endpoint
circuit breaker and is skipped for the remainder of a run (`cooldown`, 30 s by
default), so a dead mirror does not stall the scan. A slow host can be slowed
down deliberately with `min_interval`, which spaces requests to the same host
(for example `"100ms"`).

The fallback order is: primary endpoint, then mirrors, then the cache, then
the installed offline database (see the offline database section), then failure. `sources` in
every output says which of them answered, their age, and whether the result is
complete.

## Webhook notifications

A `[notify]` section sends a compact summary after a `check` run: host facts,
completeness, score, totals, finding ids. It is opt-in and carries nothing
beyond what the JSON report already states.

```toml
[notify]
webhook = "https://ntfy.sh/example-topic"   # any endpoint that accepts a POST
bearer_file = "/etc/amivuln/notify-token"   # optional; sent as Authorization: Bearer
on = "violation"                            # violation (default) | incomplete | always
```

A failed delivery prints a warning and never changes the exit code: the policy
decision was made from the scan, not from the notification.


## The offline database

`amivuln db` moves advisory data between hosts that may reach the network and
hosts that may not. The archive is a `tar.zst` holding the SQLite cache and a
manifest with a SHA-256 of the database; `--key` and `--sig` add a minisign
signature over the manifest.

```bash
amivuln --all -f json            # warm the cache (needs the network once)
amivuln db build --archive db.tar.zst
amivuln db verify db.tar.zst --key amivuln.pub --sig db.tar.zst.minisig
amivuln db pull db.tar.zst       # verify and install for this user
amivuln db info db.tar.zst
```

`db pull` installs under `$XDG_DATA_HOME/amivuln/offline` and refuses an
archive older than the installed one (anti-rollback); `--force` overrides.
Once installed, a run with `--offline` answers from it and reports those
sources as `stale`, so an air-gapped host produces the same report shapes with
exit codes that still respect `--fail-on`. `amivuln db verify` exits 65 when
an archive is tampered; a regressive `db pull` also exits 65.

Signing is deliberately not built in: generate the project key with the
`minisign` tool and sign outside amivuln
(`minisign -S -s key.sec -m manifest.json -x db.tar.zst.minisig`), so the
secret key never runs through this binary.

## Files no package owns

A path target that the package manager does not know (a binary copied into a
container, vendored software) is identified by its own systemd
`.note.package` when it has one. The package, version and packaging system
come from the file, and the report marks the package with the provenance
`embedded_note`. A note for another packaging system than the host's (a `deb`
note on an RPM host) is refused as unresolved instead of guessed, and the file
is never executed.

## Go and Rust programs nothing owns

When a path target is not owned by a package and has no package note, amivuln
reads the Go modules (build information) or Rust crates (cargo-auditable data)
the program declares and asks OSV about each exact version. Findings show the
lowest fixed version above the installed one, and `update_hint` says the program
has to be rebuilt, because no package manager can update a statically linked
dependency. Files that a package owns are deliberately not expanded this way:
a distribution backports fixes into vendored code without changing versions, so
the module versions of an owned binary would produce false positives.

The OSV endpoint for this pass is `[sources.osv]` (required by default: a
failed pass leaves those modules unjudged, which must not look clean).
Textual severity comes from the advisory when it states one (GitHub advisories
do; RUSTSEC entries do not and report `unknown`).

## The project minisign key

`contrib/offline-db/amivuln.pub` is the project minisign public key. It is
also what the nightly workflow uses to verify the database before it is
published on the release. The project's private key lives only in the
repository secrets (`MINISIGN_SECRET_KEY` plus `MINISIGN_PASSWORD`) and never
on a developer machine, so a compromised mirror cannot fake freshness or
replay an old database past the anti-rollback timestamp.


## Scanning a container

`amivuln --container ID` checks the packages installed inside a container.
The runtime (podman, then docker) is invoked only to export the rootfs,
which never executes anything inside the container. The container's own
`os-release` decides the ecosystem, so the host distribution never leaks
into the answer, and the packages are judged by the matching source (OSV
for Debian, Ubuntu, Rocky, `AlmaLinux`, Red Hat Enterprise Linux (UBI included); the rpm database through the host
`rpm` for Fedora-family containers). Findings are labeled with the
container id, for example `web:nginx`.

```bash
amivuln --container web --container db --fail-on high
```

Alpine containers are judged by OSV (`Alpine:v3.20` for release 3.20). The
installed database names each subpackage's origin, and OSV keys Alpine
advisories by origin, so `libcrypto3` is asked about as `openssl`. Edge and
alpha images have no OSV release and are refused. Versions follow the
`apk` ordering (`1.0_rc1` before `1.0`, `-r1` after `-r0`).

## Version banners in binaries

When nothing else identifies a binary (no package owner, no package note,
no Go or Rust metadata), amivuln scans for the version banners a curated set
of C products prints: OpenSSL, curl, zlib, SQLite, nginx and others. A hit
becomes a target with the upstream version as printed, marked
`string_heuristic` in every format.

This is a **low-confidence** signal: the distribution may have backported
fixes without changing the embedded banner. The verdict is real, but the
user should verify it against the distribution's changelog.

### The sandboxed version probe

With `exec_version_probe = true` in `[general]`, amivuln also runs
`<file> --version` for files nothing else identifies and reads the banners
from what it prints. This is the only place amivuln executes a target, so it
is off by default and runs in a sandbox that is applied before `exec`:

- no file-system writes (Landlock), and reads limited to the system library
  directories and the target's own directory;
- no sockets and no access to other processes (seccomp);
- `no_new_privs`, a drop to `nobody` when started as root, 2 s of CPU time,
  no file growth, no core dumps, 64 open files;
- 2 s of wall-clock time and 64 KiB of output per stream.

When the kernel cannot enforce the sandbox (no Landlock, or an architecture
other than x86_64 and aarch64) the run reports an error for that file. It
never runs the target unconfined. The seccomp filter is a deny list, not an
allow list: targets are arbitrary binaries whose startup syscalls cannot be
listed, and Landlock already removes the file-system side.

## NVD fallback for unowned products

The string heuristic targets (products with no distro data) are also checked
against the NVD 2.0 API by CPE name. The CPE mapping table is curated
(`nginx` maps to `f5:nginx`, `curl` to `haxx:curl`); a product the table does
not cover is skipped. The source is optional (`sources.nvd.required = false`
by default), so a failure does not make the result incomplete. The optional
API key raises the rate limit from 5 to 50 requests per 30 seconds.

```toml
[sources.nvd]
enabled = true
required = false
# api_key_file = "/etc/amivuln/nvd-api-key"
```

NVD findings carry the CVSS severity from the most recent metric version
available, and the verdict is `affected` with no fix version: NVD is a CVE
catalogue, not a distribution fix source.
