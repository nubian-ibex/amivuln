# Benchmarks

Wall-clock times of 1.3.0, measured on 2026-11-27 and 2026-11-28. One run per
case: treat them as orders of magnitude, not lab numbers. **Cold** starts with
an empty cache, **warm** repeats the same scan immediately after. `docs` is
the number of HTTP documents (queries and advisories) the run downloaded,
read from the cache afterwards; `RSS` is the peak resident memory of the
process, read from `/usr/bin/time` where it exists.

The machines: the development workstation (Fedora 45, many cores, NVMe) and
VirtualBox VMs with 4 vCPUs and 4 to 6 GB of RAM: EndeavourOS (KDE), Ubuntu
26.10 (KDE), Debian 13 (GNOME), Fedora 45 (KDE) and openSUSE Leap 16.1
(XFCE). Flatcar (2 vCPUs) runs the container matrix below. The script is
`bench/scan-benchmarks.sh` in the repository.

## A whole host

| Host | Packages | Findings | Docs | Cold | Warm | Offline | RSS |
| --- | --- | --- | --- | --- | --- | --- | --- |
| EndeavourOS (Arch family) | 936 | 0 | 6 | 2.8 s | 0.13 s | 0.16 s | - |
| Fedora 45 VM | 2234 | 10 | 2 | 3.6 s | 1.0 s | 0.9 s | 48 MB |
| Ubuntu 26.10 | 2127 | 15768 | 3338 | 178 s | 4.0 s | 0.17 s | 34 MB |
| Debian 13 | 2275 | 8232 | 3326 | 230 s | 0.5 s | 0.23 s | - |
| openSUSE Leap 16.1 | 1795 | 3588 | 1114 | 61 s | 1.0 s | 1.0 s | 30 MB |
| Dev workstation | 2675 | 40 | 4 | 8.9 s | 1.2 s | 1.0 s | 88 MB |

- The Ubuntu and Debian cold runs are dominated by the advisory downloads
  (around 3300 documents each): the known gap of the first run.
- A warm scan of a real host is a second or less everywhere but the two
  desktops with the longest advisory lists, which are bounded by parsing,
  not network.
- On Calculate Linux, a Gentoo derivative, the run is refused (exit 64): its
  Portage tree carries no GLSA advisories to read.

## One target at a time (cold / warm, seconds)

| Case | EndeavourOS | Ubuntu 26.10 | Debian 13 | Fedora 45 VM | Leap 16.1 | Dev workstation |
| --- | --- | --- | --- | --- | --- | --- |
| `--kernel` | 2.3 / 0.18 | 52 / 2.9 | 29 / 0.24 | 2.2 / 0.27 | 36 / 0.17 | 6.3 / 0.38 |
| `openssl` (a package) | 2.4 / 0.05 | 3.8 / 0.05 | 3.9 / 0.05 | 2.3 / 0.22 | 1.7 / 0.02 | 6.6 / 0.34 |
| `/usr/bin/bash` (a path) | 1.7 / 0.05 | 4.4 / 0.08 | 3.5 / 0.10 | 2.2 / 0.21 | 2.8 / 0.04 | 6.1 / 0.33 |
| `pending` | 2.9 / 0.06 | 174 / 4.6 | 226 / 0.39 | 3.0 / 1.0 | 52 / 0.94 | 3.6 / 1.5 |
| `services` | 6.7 / 3.4 | 20 / 4.6 | 23 / 5.0 | 4.2 / 2.3 | 9.0 / 1.0 | 3.7 / 1.7 |

The kernel of the Ubuntu desktop has 635 open CVEs, Debian's 338, Leap's
2819: a single kernel target downloads their advisories. One package costs
about the start-up of the process (one OSV query); the cold part is the
first fetch of the sources' metadata.

## Output formats (the same warm host scan)

With a warm cache every format lands between 1.0 s and 1.3 s on the dev
workstation, 0.5 s and 1.0 s on Debian 13, and 4.6 s and 6.7 s on the Ubuntu
desktop, CycloneDX the heaviest (227 MB RSS there, 121 MB for OpenVEX).
Without a cache the format runs are full rescans and cost what a cold scan
costs.

## Containers

Scanning a container exports its root file system first, and that export
dominates: the warm cache does not make it smaller. Measured on the dev
workstation, cold / warm:

| Image (5.5 G) | Podman, direct | Docker, from a runner |
| --- | --- | --- |
| Rocky Linux 9.3 (141 packages) | 23 s / 22 s | 40 s / - |
| AlmaLinux 9.3 (148) | 30 s / 24 s | 26 s / - |
| Debian 13 (78) | 7.2 s / 9.9 s | 8.3 s / - |
| Ubuntu 24.04 (92) | 5.4 s / 6.0 s | 7.2 s / - |
| Alpine 3.22 (16) | 2.6 s / 1.9 s | 3.0 s / - |

"Docker, from a runner" is amivuln inside a Rocky Linux 9.3 container with
the host's Docker socket mounted, which is also how a host without `rpm`
scans Fedora-family images.

The same runner on the Flatcar VM (2 vCPUs, Docker) read nine images with a
warm cache: Rocky Linux 9.3 in 27 s, AlmaLinux 9.3 in 27 s, the UBI 9 image
in 24 s, Fedora 43 in 5.8 s, Debian 13 in 8.0 s, Ubuntu 24.04 in 6.9 s,
Leap 15.6 in 4.1 s and Alpine 3.22 in 2.1 s. Every image's findings matched
the dev workstation's exactly, and a CentOS Stream 9 image is refused
(exit 64) because amivuln does not read CentOS Stream.

## Tested distributions

The releases above are the ones the numbers were measured on. Across this
and earlier runs the tool was compared with the distribution's own data on:
Fedora 44 and 45 (workstation and VM, KDE), EndeavourOS (Arch-based, KDE),
Ubuntu 26.10 (KDE) and 24.04, Debian 13.8 (GNOME) and 12, openSUSE Leap 16.1
(XFCE) and 15.6, Alpine 3.18 to 3.22, Rocky Linux 8 and 9.3, AlmaLinux 8 and
9.3, Red Hat UBI 8, 9 and 10, CentOS Stream 9 (refused), Gentoo derivatives
(Calculate Linux, refused: no GLSA tree) and Flatcar (no package database;
its containers are read through the runner above).

## Accuracy

A comparison of one target against Grype, Trivy and cve-bin-tool, with a
hand-built ground truth, is in `bench/README.md` in the repository.
