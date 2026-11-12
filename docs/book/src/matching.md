# How matching works

Every verdict answers one question: given the installed version of a package
and everything the consulted sources said about it, is the host affected?

## The distribution wins

The distribution's own advisory data decides. Upstream ranges are never used to
call a package affected: distributors ship fixes without changing the upstream
version, so an upstream range would report false positives on RPM-based and
Debian-based systems alike.

## Precedence

Per CVE and per package the statements merge, most restrictive first:

1. **not-affected** from the distribution or an OpenVEX statement (`--vex`),
   with the justification carried through to every output format.
2. **patched**, when the installed version is at or above the published fix.
3. **affected**, otherwise; the finding names the version that fixes it.
4. **unverified**, when there is a record but no comparable version: the
   distribution says *will not fix* or *fix deferred* (the reporter lists it
   under its own id), or the fixed version cannot be compared with the
   installed version (an rpm fix against a deb install, for instance).

Everything a source could not answer for is listed separately as `unverified`
and never silently counted as affected. Enrichment (KEV, EPSS) never changes a
verdict.

## Per source

- **Fedora.** `updateinfo` publishes the version that fixed the CVE. Installed
  at or above any published fix is patched. A CVE with no published fix is not
  visible in this data.
- **Arch.** The tracker records a build; the same upstream version is
  vulnerable, a rebuild of it too, and a newer one *unverified*.
- **Debian, Ubuntu, Alpine, Red Hat, Rocky, `AlmaLinux`, Go modules and Rust
  crates.** OSV serialises advisories per ecosystem; the fixed versions that
  name the package decide. When several advisories fix one CVE (Red Hat
  issues one per minor stream), installed at or above any of them is patched.
  A record OSV matched to the installed version but that lists no fix at all
  is an open issue: affected, with no version to move to (Debian and Ubuntu
  have such records; Alpine and Red Hat only list advisories that shipped a
  fix). Alpine, Debian and Ubuntu are asked by source package. For language packages OSV answers per exact version, so
  every advisory returned affects the queried version and the fix reported is
  the lowest one above it. A language advisory without a CVE alias is
  reported under its own id (GHSA, GO, RUSTSEC) instead of vanishing.
- **Baseline.** `--baseline prev.json` keeps only findings that are new since
  that report; it never turns an affected call into clean.
- **Ignore file.** An accepted finding is suppressed with its reason, owner
  and expiry shown in the output; an expired entry is an error.

## Determinism

The rules are pure functions in `amivuln_core` (`matching::merge`): two runs
on the same data agree, and the ground truth corpus (Fedora and Arch cases
with recorded HTTP fixtures) pins them against recorded data.
