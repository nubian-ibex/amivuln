// SPDX-FileCopyrightText: 2026 amivuln contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Ground-truth corpus: curated cases with CVEs that must and must not be
//! reported, evaluated against recorded fixtures. Zero false positives is a
//! release criterion, so a `forbid` violation is a hard failure.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use amivuln::pipeline::{arch_findings, fedora_findings};
use amivuln_core::{Ecosystem, Finding, PackageRef, Provenance, Verdict, Version};
use amivuln_sources::arch::ArchTracker;
use amivuln_sources::fedora::Updateinfo;
use serde::Deserialize;

const ARCH_FIXTURE: &[u8] =
    include_bytes!("../../../tests/fixtures/http/arch-tracker/2026-11-07/all.json");
const FEDORA_FIXTURE: &[u8] =
    include_bytes!("../../../tests/fixtures/http/fedora-updateinfo/2026-11-07/updateinfo.xml");

#[derive(Deserialize)]
struct File {
    distro: String,
    #[serde(rename = "case")]
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    name: String,
    package: String,
    source: Option<String>,
    version: String,
    #[serde(default)]
    expect: Vec<String>,
    #[serde(default)]
    forbid: Vec<String>,
    #[serde(default)]
    forbid_all: bool,
    /// CVEs that must not be reported as affected (unverified is acceptable).
    #[serde(default)]
    forbid_affected: Vec<String>,
    #[serde(default)]
    expect_update_id: bool,
    /// At least one affected finding.
    #[serde(default)]
    expect_affected: bool,
    /// The highest fixed version among affected findings, as an EVR.
    expect_fixed_in: Option<String>,
}

fn package(eco: Ecosystem, case: &Case) -> PackageRef {
    let version = match eco {
        Ecosystem::Fedora(_) => Version::Rpm(case.version.parse().unwrap_or_else(|n| match n {})),
        Ecosystem::Arch => Version::Pacman(case.version.parse().unwrap_or_else(|n| match n {})),
        Ecosystem::Debian(_) | Ecosystem::Ubuntu(_) => {
            Version::Deb(case.version.parse().unwrap_or_else(|n| match n {}))
        }
    };
    PackageRef {
        ecosystem: eco,
        name: case.package.clone(),
        source_name: case.source.clone(),
        version,
        arch: None,
        provenance: Provenance::PackageDb,
    }
}

fn check(case: &Case, findings: &[Finding]) {
    let affected: Vec<&str> = findings
        .iter()
        .filter(|f| matches!(f.verdict, Verdict::Affected { .. }))
        .map(|f| f.id.as_str())
        .collect();
    let all: Vec<&str> = findings.iter().map(|f| f.id.as_str()).collect();
    for want in &case.expect {
        assert!(
            affected.contains(&want.as_str()),
            "[{}] missing {want}; got {affected:?}",
            case.name
        );
    }
    for bad in &case.forbid {
        assert!(
            !all.contains(&bad.as_str()),
            "[{}] FALSE POSITIVE {bad}; got {all:?}",
            case.name
        );
    }
    for bad in &case.forbid_affected {
        assert!(
            !affected.contains(&bad.as_str()),
            "[{}] FALSE POSITIVE (affected) {bad}; got {affected:?}",
            case.name
        );
    }
    if case.forbid_all {
        assert!(
            all.is_empty(),
            "[{}] expected no findings, got {all:?}",
            case.name
        );
    }
    if case.expect_affected {
        assert!(
            !affected.is_empty(),
            "[{}] expected an affected finding, got {all:?}",
            case.name
        );
    }
    if let Some(want) = &case.expect_fixed_in {
        let want: amivuln_version::RpmEvr = want.parse().unwrap_or_else(|n| match n {});
        let best = findings
            .iter()
            .filter_map(|f| match &f.verdict {
                Verdict::Affected {
                    fixed_in: Some(Version::Rpm(v)),
                } => Some(v.clone()),
                _ => None,
            })
            .max();
        assert_eq!(
            best.as_ref(),
            Some(&want),
            "[{}] highest fixed version",
            case.name
        );
    }
    if case.expect_update_id {
        assert!(
            affected.iter().any(|id| id.starts_with("FEDORA-")),
            "[{}] expected an update id finding, got {affected:?}",
            case.name
        );
    }
}

#[test]
fn arch_corpus() {
    let file: File = toml::from_str(include_str!("../../../tests/ground-truth/arch.toml")).unwrap();
    assert_eq!(file.distro, "arch");
    let tracker = ArchTracker::parse(ARCH_FIXTURE).unwrap();
    assert!(file.cases.len() >= 9);
    for case in &file.cases {
        check(
            case,
            &arch_findings(&package(Ecosystem::Arch, case), &tracker),
        );
    }
}

const FEDORA_F45_FIXTURE: &[u8] = include_bytes!(
    "../../../tests/fixtures/http/fedora-updateinfo/2026-11-08-f45/updateinfo.xml.zst"
);

const OSV_BATCH: &[u8] =
    include_bytes!("../../../tests/fixtures/http/osv/2026-11-08-batch/batch.json");
#[test]
fn debian_corpus_from_the_real_osv_response() {
    let file: File =
        toml::from_str(include_str!("../../../tests/ground-truth/debian-osv.toml")).unwrap();
    assert_eq!(file.distro, "debian:12");
    // The recorded batch lists 54 advisories for openssl on Debian:12; the
    // corpus only asserts CVEs whose advisory bodies are recorded (the rest is
    // fetched live, which ground truth avoids).
    let ids = amivuln_sources::osv::parse_batch(OSV_BATCH).unwrap();
    assert!(ids.contains(&"DEBIAN-CVE-2023-5363".to_owned()));
    // Four advisory bodies are recorded; each fixes its CVE at a Debian:12
    // version stated by the OSV ecosystem range.
    let recorded: &[(&str, &str, &[u8])] = &[
        (
            "DEBIAN-CVE-2023-5363",
            "3.0.11-1~deb12u2",
            include_bytes!("../../../tests/fixtures/http/osv/2026-11-08/DEBIAN-CVE-2023-5363.json"),
        ),
        (
            "DEBIAN-CVE-2023-5678",
            "3.0.13-1~deb12u1",
            include_bytes!("../../../tests/fixtures/http/osv/2026-11-08/DEBIAN-CVE-2023-5678.json"),
        ),
        (
            "DEBIAN-CVE-2023-6129",
            "3.0.13-1~deb12u1",
            include_bytes!("../../../tests/fixtures/http/osv/2026-11-08/DEBIAN-CVE-2023-6129.json"),
        ),
        (
            "DEBIAN-CVE-2023-6237",
            "3.0.13-1~deb12u1",
            include_bytes!("../../../tests/fixtures/http/osv/2026-11-08/DEBIAN-CVE-2023-6237.json"),
        ),
    ];
    let mut entries = Vec::new();
    for (id, want_fix, body) in recorded {
        let d = amivuln_sources::osv::OsvData::parse_advisory(body, "Debian:12").unwrap();
        let cve = id.strip_prefix("DEBIAN-").unwrap();
        assert_eq!(d.fix_for(cve), Some(*want_fix), "{cve}");
        for mut e in d.entries() {
            e.advisory = (*id).to_owned();
            entries.push(e);
        }
    }
    let osv = amivuln_sources::osv::OsvData::from_entries(entries);
    let affected_pkg = package(
        Ecosystem::Debian(12),
        file.cases.iter().find(|c| c.version == "3.0.10-1").unwrap(),
    );
    let findings = amivuln::pipeline::osv_findings(&affected_pkg, &osv);
    assert_eq!(findings.len(), 4, "{findings:?}");
    for cve in [
        "CVE-2023-5363",
        "CVE-2023-5678",
        "CVE-2023-6129",
        "CVE-2023-6237",
    ] {
        assert!(findings.iter().any(|f| f.id == cve), "{cve}");
    }
    let mid_pkg = package(
        Ecosystem::Debian(12),
        file.cases
            .iter()
            .find(|c| c.version == "3.0.11-1~deb12u1")
            .unwrap(),
    );
    // 3.0.11-1~deb12u1 is below every published fix, so all four still apply.
    assert_eq!(amivuln::pipeline::osv_findings(&mid_pkg, &osv).len(), 4);
    let fixed_pkg = package(
        Ecosystem::Debian(12),
        file.cases
            .iter()
            .find(|c| c.version == "3.0.11-1~deb12u2")
            .unwrap(),
    );
    // At 3.0.11-1~deb12u2 the 5363 fix is applied; the other three fix at
    // 3.0.13-1~deb12u1 and still apply.
    let still = amivuln::pipeline::osv_findings(&fixed_pkg, &osv);
    assert_eq!(still.len(), 3, "{still:?}");
    assert!(!still.iter().any(|f| f.id == "CVE-2023-5363"));
    let latest_pkg = package(
        Ecosystem::Debian(12),
        file.cases
            .iter()
            .find(|c| c.version == "3.0.18-1~deb12u2")
            .unwrap(),
    );
    assert!(amivuln::pipeline::osv_findings(&latest_pkg, &osv).is_empty());
}

#[test]
fn fedora_f45_corpus_from_the_dnf_oracle() {
    let file: File = toml::from_str(include_str!(
        "../../../tests/ground-truth/fedora-f45-dnf.toml"
    ))
    .unwrap();
    assert_eq!(file.distro, "fedora:45");
    let info = Updateinfo::parse_zst(FEDORA_F45_FIXTURE).unwrap();
    assert!(file.cases.len() >= 40, "{} cases", file.cases.len());
    for case in &file.cases {
        check(
            case,
            &fedora_findings(&package(Ecosystem::Fedora(45), case), &info),
        );
    }
}

#[test]
fn fedora_corpus() {
    let file: File =
        toml::from_str(include_str!("../../../tests/ground-truth/fedora.toml")).unwrap();
    assert_eq!(file.distro, "fedora:43");
    let info = Updateinfo::parse(FEDORA_FIXTURE).unwrap();
    assert!(file.cases.len() >= 10);
    for case in &file.cases {
        check(
            case,
            &fedora_findings(&package(Ecosystem::Fedora(43), case), &info),
        );
    }
}
