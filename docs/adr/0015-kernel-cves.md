# ADR-0015: Kernel CVEs

- Status: Accepted
- Date: 2026-11-14

## Context

The Linux kernel is the largest source of CVEs (the kernel team assigns CVE ids to its fixes in bulk) and the one package where the usual shortcuts fail: several versions are installed at once, only one runs, distributions backport fixes without changing the version, and live patches change what runs without a reboot. The roadmap asked for a design study before any code.

## What was checked (2026-11-14)

- Installed kernels: this Fedora 44 host has kernel-7.2.12, 7.2.15 and 7.3.3 installed and runs 7.2.15. `amivuln kernel-core` fails with "ambiguous" (three versions), and `--all` judges all three, so a kernel that will not boot reads like one that does.
- OSV has a `Linux` ecosystem, but a query with an upstream version (`Kernel`, 6.12.40) returns advisories whose ranges are Git commits, and the CVE document checked (CVE-2024-1086) has no `package` entry to match a version against. A version-only match against the upstream data is not possible, and would be the generic upstream match this project refuses: a distribution kernel 5.14.0-427.el9 carries fixes from many later upstream releases.
- The distribution data already names kernel fixes: Fedora's `updateinfo` (the 7.2.15 kernel above is reported against its 7.3.3 update), Debian and Ubuntu through OSV (`linux`), RHEL through its advisories. Judged like any package, the running kernel gets a correct answer wherever the distribution states one.

## Decision

1. The kernel is judged by the distribution's data, exactly as every other package. The upstream Linux ecosystem is not used for matching.
2. The question people ask is "is the kernel I am running affected", so `--kernel` checks the package that owns the image of the running release (`/proc/sys/kernel/osrelease`, then `/usr/lib/modules/RELEASE/vmlinuz`, `/boot/vmlinuz-RELEASE`, or Alpine's flavor image). It needs no package name, so several installed kernels do not make it ambiguous.
3. `--all` keeps judging every installed kernel: dropping the others would hide the advisory against the kernel the next reboot selects. Telling the running one from the rest in the full report is left for later.
4. Live patches (kpatch, livepatch, canonical-livepatch) are not modelled: amivuln reports what the package version says and does not know a patch is loaded. This is stated as a limit, not hidden.

## Consequences

- Kernel results are only as good as the distribution's statements; a kernel CVE the distribution has not triaged is not visible (as for every package).
- A kernel built from a git checkout or a vendor kernel with no package has no owner and is listed as unresolved.
- Volume is not a problem for this design: the findings are the distribution's, a few dozen at a time.
