#!/bin/sh
# SPDX-FileCopyrightText: 2026 amivuln contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Integration checks run inside a distribution container by the `distro`
# workflow. They use the network (OSV, updateinfo) on purpose: the unit suite
# already covers the logic offline, this proves the real resolvers and the
# real advisory data agree.
#
#   run.sh inventory   deterministic CVE answers from a fixed package list
#   run.sh host        the resolvers and commands against this container
#
# Needs jq and an `amivuln` on PATH.
set -eu

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# run NAME CMD...: stdout to $work/NAME.json, exit code in $rc, never aborts.
run() {
    name=$1
    shift
    rc=0
    "$@" >"$work/$name.json" 2>"$work/$name.err" || rc=$?
}

# want_rc "0 1": the last run must have exited with one of those codes.
want_rc() {
    case " $1 " in
    *" $rc "*) ;;
    *)
        cat "$work"/*.err >&2
        fail "exit code $rc, wanted one of: $1"
        ;;
    esac
}

# jq_is NAME FILTER: the filter must print true for the run's JSON.
jq_is() {
    [ "$(jq -r "$2" "$work/$1.json")" = true ] || fail "$1: $2 is not true"
}

mode=${1:-}
case "$mode" in
inventory)
    # Debian 12 openssh before and after the fix for CVE-2024-6387. Both
    # versions are published facts, so the answers never change.
    before='openssh@1:9.2p1-2+deb12u2'
    after='openssh@1:9.2p1-2+deb12u3'
    echo "$before" >"$work/before.txt"
    echo "$after" >"$work/after.txt"
    d="--distro debian:12 --format json"

    # shellcheck disable=SC2086
    run cve-before amivuln cve CVE-2024-6387 --packages-from "$work/before.txt" $d
    want_rc "1"
    jq_is cve-before '.complete'
    jq_is cve-before '.answers[0].state == "affected"'
    jq_is cve-before '.answers[0].packages[0].fixed_in == "1:9.2p1-2+deb12u3"'

    # shellcheck disable=SC2086
    run cve-after amivuln cve CVE-2024-6387 --packages-from "$work/after.txt" $d
    want_rc "0"
    jq_is cve-after '.answers[0].state != "affected"'

    # shellcheck disable=SC2086
    run pending amivuln pending --packages-from "$work/before.txt" $d
    want_rc "0 1"
    jq_is pending '.kind == "pending"'
    jq_is pending '[.updates[]?, .pending[]?] | any(.closes | index("CVE-2024-6387"))'

    # RHEL 9 openssl-libs before and after RHSA-2024:0310 (CVE-2023-5363,
    # fixed in 1:3.0.7-25.el9_3). The repository is not in the rpm database,
    # so this also proves the baseos/appstream/crb fan-out and merge.
    echo 'openssl-libs@1:3.0.7-24.el9' >"$work/rhel-before.txt"
    echo 'openssl-libs@1:3.0.7-27.el9' >"$work/rhel-after.txt"
    # shellcheck disable=SC2086
    run rhel-before amivuln check --packages-from "$work/rhel-before.txt" --distro rhel:9 --format json
    want_rc "0 1"
    jq_is rhel-before '.complete'
    jq_is rhel-before '.targets[0].findings | any(.id == "CVE-2023-5363" and .distro_status.state == "affected" and .distro_status.fixed_in == "1:3.0.7-25.el9_3")'
    # shellcheck disable=SC2086
    run rhel-after amivuln check --packages-from "$work/rhel-after.txt" --distro rhel:9 --format json
    want_rc "0 1"
    jq_is rhel-after '.targets[0].findings | all(.id != "CVE-2023-5363")'

    # Alpine 3.18 openssl before and after the fix for CVE-2023-2650, in the
    # apk version order (`-r` revisions and a patch level that changes).
    echo 'openssl@3.1.0-r4' >"$work/alpine-before.txt"
    echo 'openssl@3.1.1-r0' >"$work/alpine-after.txt"
    # shellcheck disable=SC2086
    run alpine-before amivuln check --packages-from "$work/alpine-before.txt" --distro alpine:3.18 --format json
    want_rc "0 1"
    jq_is alpine-before '.complete'
    jq_is alpine-before '.targets[0].findings | any(.id == "CVE-2023-2650" and .distro_status.state == "affected" and .distro_status.fixed_in == "3.1.1-r0")'
    # shellcheck disable=SC2086
    run alpine-after amivuln check --packages-from "$work/alpine-after.txt" --distro alpine:3.18 --format json
    want_rc "0 1"
    jq_is alpine-after '.targets[0].findings | all(.id != "CVE-2023-2650")'
    ;;
host)
    # shellcheck disable=SC1091
    id=$(. /etc/os-release && echo "$ID")
    case "$id" in
    fedora | arch | rhel)
        # Resolve a package every image has, through the real package manager.
        run check amivuln check bash --format json
        want_rc "0 1"
        jq_is check '.targets[0].package.name == "bash"'
        jq_is check '.host.os_id == "'"$id"'"'
        run cve amivuln cve CVE-2024-6387 --format json
        want_rc "0 1"
        jq_is cve '.kind == "cve" and .complete'
        run pending amivuln pending --format json
        want_rc "0 1"
        jq_is pending '.kind == "pending" and .complete'
        ;;
    debian | ubuntu | alpine)
        # The package database is read from the files of the running system.
        pkg=bash
        [ "$id" = alpine ] && pkg=busybox
        run check amivuln check "$pkg" --format json
        want_rc "0 1"
        jq_is check '.targets[0].package.name == "'"$pkg"'"'
        jq_is check '.host.os_id == "'"$id"'"'
        # A file is traced to its package (merged /usr on Debian and Ubuntu).
        run owner amivuln "$(command -v "$pkg")" --format json
        want_rc "0 1"
        jq_is owner '.targets[0].package.name == "'"$pkg"'"'
        run all amivuln --all --format json
        want_rc "0 1"
        jq_is all '(.targets | length) > 10 and .complete'
        ;;
    *) fail "no host checks for $id" ;;
    esac
    ;;
*)
    echo "usage: $0 inventory|host" >&2
    exit 64
    ;;
esac
echo "ok: $mode"
