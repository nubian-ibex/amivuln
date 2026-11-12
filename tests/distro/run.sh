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
    fedora | arch)
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
    debian | ubuntu)
        # No host package database is read for Debian: the inventory comes
        # from dpkg, the way a user exports it from the machine.
        dpkg-query -W -f '${source:Package}@${Version}\n' bash >"$work/inv.txt"
        [ -s "$work/inv.txt" ] || fail "dpkg-query produced no inventory"
        run check amivuln check --packages-from "$work/inv.txt" --format json
        want_rc "0 1"
        jq_is check '.targets | length > 0'
        jq_is check '.host.os_id == "'"$id"'"'
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
