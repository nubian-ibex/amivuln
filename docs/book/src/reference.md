# Reference

## Commands

- `amivuln [OPTIONS] TARGET...` is a shortcut for `amivuln check`.
- `amivuln check [TARGET...] [--all]`
- `amivuln cve CVE-ID...`: is this host affected? Exit 1 when it is.
- `amivuln pending`: the updates that close the most risk, ranked.
- `amivuln services`: check the package behind every running systemd service.
- `amivuln restart`: processes that still run files an update replaced. Exit 1 when a restart is needed.
- `amivuln config show | init [--path FILE] | validate`
- `amivuln cache info | clear`
- `amivuln completions bash|zsh|fish|elvish|powershell`
- `amivuln mcp`: a read-only Model Context Protocol server on stdio (see the user guide)
- `amivuln version [--json]`

## Options

- `-f, --format`: `summary`, `detail`, `json`, `sarif`, `markdown`, `csv` or `prometheus`
- `--output FILE`: write the result to FILE instead of stdout; the file is replaced atomically through a rename
- `--fail-on`: `none`, `low`, `medium`, `high`, `critical` or `kev`
- `--fail-on-epss SCORE`: exit 1 when an affected finding reaches this EPSS score
- `--strict`: unverified findings count for `--fail-on`
- `--offline`, `--no-cache`: network and cache behavior
- `--config FILE`: use this configuration file only
- `--color auto|always|never`: `NO_COLOR` is honored
- `--distro fedora:NN|arch`: treat the host as this distribution
- `--baseline FILE`: a previous `-f json` report; only findings absent from it violate `--fail-on`
- `--sbom FILE`: check the OS packages of a CycloneDX JSON SBOM (rpm, deb and alpm purls); other components are listed as unresolved, one entry per purl type
- `--vex FILE`: an `OpenVEX` document; a `not_affected` statement overrides the verdict and shows the author and justification
- `--packages-from FILE`: check the packages listed in FILE (one `name@version` per line) instead of the installed ones
- `ignore_file` (configuration): accepted findings; expired entries are errors
- `-q, --quiet`: only errors

`AMIVULN_FORMAT`, `AMIVULN_FAIL_ON`, `AMIVULN_OFFLINE`, `AMIVULN_CONFIG` and
`AMIVULN_COLOR` set the corresponding options.

## Exit codes

- 0: finished, nothing at or above `--fail-on`
- 1: finished, findings at or above `--fail-on`
- 2: incomplete: a required source was unavailable
- 3: a target could not be resolved
- 64: usage or configuration error
- 70: internal error

When several apply, the precedence is 70, 64, 2, 3, 1, 0.

## JSON output (schema version 1)

```json
{
  "schema_version": 1,
  "tool": {"name": "amivuln", "version": "0.0.3"},
  "generated_at": "2026-11-08T12:00:00Z",
  "host": {"os_id": "fedora", "os_version": "44", "arch": "x86_64"},
  "complete": true,
  "sources": [{"id": "fedora-updateinfo", "status": "ok", "age_s": 0, "required": true}],
  "targets": [{
    "input": "nginx",
    "package": {"name": "nginx", "version": "1:1.26.2-1.fc44", "arch": "x86_64",
                "ecosystem": "fedora", "purl": "pkg:rpm/fedora/nginx@1.26.2-1.fc44?arch=x86_64&epoch=1",
                "provenance": "package_db"},
    "summary": {"critical": 0, "high": 1, "medium": 0, "low": 0, "kev": 0, "epss_max": 0.02, "unverified": 0},
    "findings": [{"id": "CVE-2026-0001", "severity": "high",
                  "distro_status": {"state": "affected", "fixed_in": "1:1.26.3-1.fc44"},
                  "kev": null, "epss": {"score": 0.02, "percentile": 0.6, "date": "2026-11-07"}}],
    "unverified": []
  }],
  "unresolved": []
}
```

The JSON Schema is published at [schema/v1.json](schema/v1.json) and is checked against the real output in CI. Findings and unverified findings are separate arrays. The host block never
contains a host name, address or user. Adding optional fields does not change
`schema_version`; removing or retyping one does.

## Configuration file

```toml
schema_version = 1
[general]
offline = false
cache_ttl = "6h"
stale_max_age = "72h"
timeout = "10s"
[output]
format = "summary"
color = "auto"
[policy]
fail_on = "none"
fail_on_incomplete = true
strict = false
[sources.distro]
enabled = true
required = true
# url = "https://mirror.example/fedora/linux/updates"
[sources.kev]
enabled = true
[sources.epss]
enabled = true
```
