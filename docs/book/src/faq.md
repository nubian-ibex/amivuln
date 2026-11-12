# False positive FAQ

**amivuln reports a CVE my distribution already fixed.** Distribution status
overrides version comparison, so this should not happen. Open a
*false positive* issue with the output of `amivuln PACKAGE -f json` and the
link to the advisory or changelog that shows the fix.

**amivuln reports nothing but I know of a CVE.** On Fedora, Red Hat, Rocky and
AlmaLinux, amivuln only sees fixes that were published. A CVE with no update
yet is not in the data, so a result there is a lower bound. Open a *false
negative* issue if the data does have the record.

**`amivuln --all` finds no packages on my Debian, Ubuntu or Alpine machine.**
Those hosts are not read from their package database yet. Export a list and
check it (`--packages-from`, see the Using page), or scan a container.

**The result says INCOMPLETE.** A required source was unreachable and there
was no cached copy within `stale_max_age`. Retry, check the network, or use a
mirror with `sources.distro.url`. The exit code is 2 on purpose.

**Why is a package "unverified"?** The distribution has no statement about it.
It is listed apart and does not fail a build unless you pass `--strict`.

**My `updates` repository is disabled.** amivuln looks at Fedora's published
`updates` data regardless of your local repository configuration, so it can
report an update that your system cannot see yet.
