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

const ARCH_2026_11_08: &[u8] =
    include_bytes!("../../../tests/fixtures/http/arch-tracker/2026-11-08/all.json");

#[test]
fn arch_boundary_corpus_from_real_tracker_groups() {
    let file: File = toml::from_str(include_str!(
        "../../../tests/ground-truth/arch-boundaries.toml"
    ))
    .unwrap();
    assert_eq!(file.distro, "arch");
    let tracker = ArchTracker::parse(ARCH_2026_11_08).unwrap();
    assert!(file.cases.len() >= 60, "{} cases", file.cases.len());
    for case in &file.cases {
        check(
            case,
            &arch_findings(&package(Ecosystem::Arch, case), &tracker),
        );
    }
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
