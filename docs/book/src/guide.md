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
