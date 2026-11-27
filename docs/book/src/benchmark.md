# Benchmarks

Wall-clock times of 1.2.5, measured on 2026-11-27. One run per case: treat
them as orders of magnitude, not lab numbers. **Cold** starts with an empty
cache, **warm** repeats the same scan immediately after. `docs` is the number
of HTTP documents (queries and advisories) the run downloaded, from the
cache; `RSS` is the peak resident memory of the process.

The machines: the dev workstation (Fedora 45, many cores, NVMe) and three
VirtualBox VMs with 2 vCPUs and 4 GB RAM: EndeavourOS, Ubuntu 26.10 and
Fedora 45. The script is `bench/scan-benchmarks.sh` in the repository.

## A whole host

| Host | Targets | Findings | Docs | Cold | Warm | Offline | RSS |
| --- | --- | --- | --- | --- | --- | --- | --- |
| EndeavourOS (Arch family) | 936 | 0 | 6 | 2.8 s | 0.12 s | 0.14 s | - |
| Fedora 45 VM | 2234 | 10 | 2 | 3.3 s | 1.1 s | 1.0 s | - |
| Ubuntu 26.10 | 2127 | 14479 | 3350 | 185 s | 7.1 s | 0.17 s | - |
| Dev workstation | 2675 | 40 | 4 | 4.0 s | 1.2 s | 0.9 s | 88 MB |

- The Ubuntu cold run is dominated by the advisory downloads (3350 documents,
  14,369 findings): the known gap of the first run.
- A warm scan of a real host is a second or less on everything but the Ubuntu
  desktop, which is bounded by parsing, not network.

## One target at a time (the same hosts)

| Case | EndeavourOS | Ubuntu 26.10 | Fedora 45 VM | Dev workstation |
| --- | --- | --- | --- | --- |
| `--kernel` | 2.8 / 0.18 s | 4.4 / 0.16 s | 2.2 / 0.32 s | 2.0 / 0.37 s |
| `openssl` (a package) | 2.5 / 0.05 s | 3.4 / 0.04 s | 3.5 / 0.26 s | 2.0 / 0.34 s |
| `/usr/bin/bash` (a path) | 1.6 / 0.07 s | 4.4 / 0.08 s | 2.5 / 0.26 s | 2.0 / 0.33 s |
| `pending` | 2.7 / 0.07 s | 158 / 4.1 s | 3.0 / 1.1 s | 3.6 / 1.2 s |
| `services` | 6.4 / 3.3 s | 29 / 4.7 s | 7.8 / 4.9 s | 3.4 / 1.7 s |

A single package costs about the start-up of the process (one OSV query); the
cold part is the first fetch of the sources' metadata.

## Output formats (the same warm host scan)

On the dev workstation, every format of a warm full scan lands between 1.2 s
and 1.3 s; the formats differ by parsing, not network. On the Ubuntu desktop
the same comparison is 4.1 s to 7.5 s.

## Containers

Scanning a container exports its root file system first, and that export
dominates: the warm cache does not make it smaller. Measured on the dev
workstation, cold / warm:

| Image (5.5 G) | Podman, direct | Docker, from a runner |
| --- | --- | --- |
| Rocky Linux 9.3 (141 packages) | 24 s / 26 s | 30 s / 3.7 s |
| AlmaLinux 9.3 (148) | 26 s / 23 s | 13 s / 3.4 s |
| Debian 12 (88) | 7.7 s / 13 s | 2.7 s / 2.5 s |
| Ubuntu 24.04 (92) | 10 s / 5.8 s | 1.9 s / 1.8 s |
| Alpine 3.22 (16) | 2.2 s / 3.2 s | 0.9 s / 1.1 s |

"Docker, from a runner" is amivuln inside a Rocky Linux 9.3 container with the
host's Docker socket mounted, which is also how a host without `rpm` scans
Fedora-family images. On the Flatcar VM (2 vCPUs) the same runner read the same
images in 2.1 s to 10 s with a warm cache, and Debian/Ubuntu/Alpine matched the
workstation's findings exactly.

## Accuracy

A comparison of one target against Grype, Trivy and cve-bin-tool, with a
hand-built ground truth, is in `bench/README.md` in the repository.
