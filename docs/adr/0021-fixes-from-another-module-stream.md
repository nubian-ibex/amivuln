# ADR-0021: A fix built for another module stream cannot judge a package

- Status: Accepted (2026-11-27, by the maintainer)
- Date: 2026-11-26
- Amends: ADR-0018, ADR-0020

## Context

Advisories of RHEL, Rocky Linux and AlmaLinux are published per module stream,
but OSV records no stream: the fix versions differ by release (`.module+el8.10.0+25285`
or `.module_el8.9.0+3827`) and the summary names the stream in prose. A package
is judged by every advisory that matched its version, of any stream.

## What was measured (2026-11-26)

- An up to date UBI 8 with `nodejs:22` (the newest build of its stream): 82 of
  its 86 CVE findings name the fix of another stream (`1:24.13.0`), so the
  package reads as affected forever. The advisory of its own stream did not
  match, because the installed version already is its fix.
- `perl-Carp` outside a module (base stream): the only advisories that match are
  of the `perl:5.30` and `perl:5.32` modules. 1.2.2 reported them as affected
  with the module's fix; 1.2.3 and 1.2.4 drop them silently. Red Hat states
  nothing for the base package (`CVE-2026-42496`), so neither is right: whether
  it is affected is unknown. `CVE-2023-47038` is `Not affected` for the base
  package, where the drop was right by luck.
- Streams pin the product's major version (`nodejs:20` stays 20.x), so the
  major of the fix version tells the stream for these products.

## Options

1. Unverified: a fix of another stream cannot judge the package. When every fix
   matched for a CVE is another stream's, the CVE is reported as unverified,
   which fails `--fail-on` only with `--strict`. Red Hat's unfixed list for the
   installed stream (ADR-0020) still reports it as affected with its state.
2. Affected with no fix version: never clean, but every up to date module
   package stays noisy, and the unknown cases read as affected.
3. Keep 1.2.4: up to date streams stay affected forever, and base-stream
   packages silently lose the CVE.

## Decision

Option 1, for a package of the Red Hat family:

- A fix built for a module never judges a package outside one.
- On a package of a module stream, a fix whose product major differs from the
  installed one (the stream) cannot judge it either. Same-major fixes apply.
- When every fix the matched advisories name for the package was excluded this
  way, the CVE is unverified, with its severity. Red Hat's unfixed entry for the
  installed stream upgrades it to affected, with the state.

## Consequences

- An up to date module package reads as patched again, and the CVEs that stay
  open are counted separately as unverified. A run that must fail on them uses
  `--strict`.
- The product major is a heuristic for the stream: two streams of one module
  with the same major would be judged as one. None is known.
- Rebuilds that ship a fix before Red Hat's file drops it read as affected until
  then (as ADR-0020 already has).
