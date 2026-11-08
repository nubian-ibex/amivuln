#!/bin/sh
# SPDX-FileCopyrightText: 2026 amivuln contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# ADR-0009 evidence: compare amivuln with the OSV API on a real Debian system.
# Run in a debian:stable container with the binary mounted at
# /usr/local/bin/amivuln (needs network):
#   podman run --rm -v ./amivuln:/usr/local/bin/amivuln:ro \
#     -v ./tests/integration/debian-vs-osv.sh:/t.sh:ro \
#     docker.io/library/debian:stable sh -c "apt-get update -qq && sh /t.sh"
# The oracle is the OSV API queried for the same packages and versions that
# dpkg reports. Both must agree on which packages have pending security fixes.
set -eu
apt-get install -y -qq python3 >/dev/null
dpkg-query -W -f='${Package}|${Version}\n' > /tmp/installed.tsv
. /etc/os-release
export AMI_ECO="Debian:${VERSION_ID}"
export AMI_DISTRO="${VERSION_ID}"
python3 - <<'PY' > /tmp/osv-affected.txt
import json, os, urllib.request
ECO = os.environ["AMI_ECO"]
rows = [l.rstrip("\n").split("|") for l in open("/tmp/installed.tsv") if "|" in l]
# In batches: the API caps the request size.
affected = set()
for i in range(0, len(rows), 500):
    batch = rows[i : i + 500]
    queries = [{"package": {"name": n, "ecosystem": ECO}, "version": v} for n, v in batch]
    req = urllib.request.Request(
        "https://api.osv.dev/v1/querybatch",
        data=json.dumps({"queries": queries}).encode(),
        headers={"Content-Type": "application/json", "User-Agent": "amivuln-oracle"},
    )
    r = json.load(urllib.request.urlopen(req))
    # amivuln only reports a finding when OSV states the version that fixes
    # the issue (the ECOSYSTEM range); an advisory with no fix is "known" but
    # not reportable, matching the other sources. The oracle mirrors that by
    # fetching each advisory body and requiring a fixed event for Debian:13.
    batch_ids = [v["id"] for res in r["results"] for v in res.get("vulns", [])]
    for (n, _), res in zip(batch, r["results"]):
        if not res.get("vulns"):
            continue
        for v in res["vulns"]:
            adv = json.load(urllib.request.urlopen(f"https://api.osv.dev/v1/vulns/{v['id']}"))
            for a in adv.get("affected", []):
                if a.get("package", {}).get("ecosystem") != ECO:
                    continue
                if any("fixed" in e for r in a.get("ranges", []) for e in r.get("events", [])):
                    affected.add(n)
                    break
for n in sorted(affected):
    print(n)
PY
sed "s/\([^|]*\)|\(.*\)/\1@\2/" /tmp/installed.tsv > /tmp/inventory.txt
amivuln --distro "debian:$AMI_DISTRO" --packages-from /tmp/inventory.txt -f json > /tmp/amivuln.json
python3 - <<'PY'
import json
d = json.load(open("/tmp/amivuln.json"))
ours = {t["package"]["name"] for t in d["targets"] if t["findings"]}
theirs = {l.strip() for l in open("/tmp/osv-affected.txt") if l.strip()}
print("amivuln sources:", [(s["id"], s["status"], s.get("detail", "")) for s in d["sources"]])
print("amivuln targets:", len(d["targets"]))
print("amivuln:", len(ours), "osv:", len(theirs), "agree:", len(ours & theirs))
print("only amivuln:", sorted(ours - theirs))
print("only osv:", sorted(theirs - ours))
PY
