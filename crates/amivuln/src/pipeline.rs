// SPDX-FileCopyrightText: 2026 amivuln contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Turning distro data into findings. Pure functions: no I/O, no clock.

use std::cmp::Ordering;
use std::collections::BTreeMap;

use amivuln_core::{
    DistroStatus, EpssInfo, Finding, KevInfo, PackageRef, Severity, Verdict, Version, VexStatement,
    apply_vex, classify, sort_findings,
};
use amivuln_sources::arch::{ArchEntry, ArchTracker};
use amivuln_sources::epss::EpssScores;
use amivuln_sources::fedora::Updateinfo;
use amivuln_sources::glsa::GlsaData;
use amivuln_sources::kev::Kev;
use amivuln_sources::osv::OsvData;

/// How serious a verdict is, so statements about one CVE can be merged.
fn rank(v: &Verdict) -> u8 {
    match v {
        Verdict::Affected { .. } => 3,
        Verdict::Unverified => 2,
        Verdict::NotAffected(_) | Verdict::Patched => 1,
    }
}

/// The higher fixed version, when both are comparable.
fn later(a: Option<Version>, b: Option<Version>) -> Option<Version> {
    match (a, b) {
        (Some(x), Some(y)) => match x.compare(&y) {
            Some(core::cmp::Ordering::Less) => Some(y),
            _ => Some(x),
        },
        (x, None) | (None, x) => x,
    }
}

/// Merges per-statement verdicts for one CVE: affected beats unverified beats
/// patched. When several statements say affected, the fix that closes all of
/// them is the highest fixed version.
fn merge(a: (Verdict, Severity), b: (Verdict, Severity)) -> (Verdict, Severity) {
    let severity = a.1.max(b.1);
    let (ra, rb) = (rank(&a.0), rank(&b.0));
    let verdict = match ra.cmp(&rb) {
        core::cmp::Ordering::Equal => match (a.0, b.0) {
            (Verdict::Affected { fixed_in: x }, Verdict::Affected { fixed_in: y }) => {
                Verdict::Affected {
                    fixed_in: later(x, y),
                }
            }
            (first, _) => first,
        },
        core::cmp::Ordering::Greater => a.0,
        core::cmp::Ordering::Less => b.0,
    };
    (verdict, severity)
}

/// The version without its package release: `1.7.0-2` gives `1.7.0`.
fn upstream(v: &Version) -> String {
    let text = v.to_string();
    text.rsplit_once('-')
        .map_or_else(|| text.clone(), |(up, _)| up.to_owned())
}

fn same_upstream(a: &Version, b: &Version) -> bool {
    let (a, b) = (upstream(a), upstream(b));
    amivuln_version::pacman_vercmp(&a, &b) == core::cmp::Ordering::Equal
}

fn one_arch_entry(installed: &Version, e: &ArchEntry) -> Option<Verdict> {
    // A group covers [affected_since, fixed). Older installs are outside it.
    if let (Some(since), DistroStatus::Fixed(_) | DistroStatus::Affected) =
        (&e.affected_since, &e.status)
        && installed.compare(since) == Some(core::cmp::Ordering::Less)
    {
        return None;
    }
    // "Vulnerable" with no fixed version describes the build that was current
    // when the tracker entry was written. A rebuild of that same upstream
    // version is still affected; a newer upstream version may or may not be
    // (the entry can be years stale), so it is reported as unverified instead
    // of affected. A false positive here would erode trust in every result.
    if let (DistroStatus::Affected, Some(since)) = (&e.status, &e.affected_since)
        && !same_upstream(installed, since)
    {
        return Some(Verdict::Unverified);
    }
    Some(classify(installed, &e.status))
}

/// What a package's advisories amount to.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Assessment {
    /// The CVEs to report: affected or not verifiable.
    pub findings: Vec<Finding>,
    /// The CVEs already settled (patched, or declared not affecting this
    /// version). Not reported, but a VEX document states them.
    pub resolved: Vec<Finding>,
}

/// Findings for an Arch package from the Security Tracker.
///
/// Patched and not-affected CVEs are not reported.
#[must_use]
pub fn arch_findings(
    pkg: &PackageRef,
    tracker: &ArchTracker,
    vex: &[VexStatement],
) -> Vec<Finding> {
    arch_assess(pkg, tracker, vex).findings
}

/// Like [`arch_findings`], keeping the settled CVEs too.
#[must_use]
pub fn arch_assess(pkg: &PackageRef, tracker: &ArchTracker, vex: &[VexStatement]) -> Assessment {
    let mut by_cve: BTreeMap<String, (Verdict, Severity)> = BTreeMap::new();
    for e in tracker.entries_for(&pkg.name) {
        let Some(verdict) = one_arch_entry(&pkg.version, &e) else {
            continue;
        };
        let item = (verdict, e.severity);
        match by_cve.remove(&e.cve) {
            Some(prev) => by_cve.insert(e.cve, merge(prev, item)),
            None => by_cve.insert(e.cve, item),
        };
    }
    finish(by_cve, vex)
}

/// Findings for a Gentoo package from the GLSAs.
///
/// An advisory affects the installed version when a `vulnerable` range holds
/// it and no `unaffected` range does (a range limited to a slot only applies to
/// a package in that slot). A package an advisory names, in a slot it covers,
/// outside every vulnerable range is patched. An advisory that names no CVE is
/// reported under its own id, so a fix without one is not lost.
#[must_use]
pub fn glsa_assess(pkg: &PackageRef, glsa: &GlsaData, vex: &[VexStatement]) -> Assessment {
    let (Version::Gentoo(installed), slot) = (&pkg.version, pkg.slot.as_deref()) else {
        return Assessment::default();
    };
    let installed = installed.as_str();
    let mut by_cve: BTreeMap<String, (Verdict, Severity)> = BTreeMap::new();
    for advisory in glsa.for_package(&pkg.name) {
        for entry in advisory.packages.iter().filter(|p| p.name == pkg.name) {
            let covered = entry
                .vulnerable
                .iter()
                .chain(&entry.unaffected)
                .any(|r| r.covers_slot(slot));
            if !covered {
                continue;
            }
            let hit = |ranges: &[amivuln_sources::glsa::Range]| {
                ranges.iter().any(|r| r.matches(installed, slot))
            };
            let verdict = if hit(&entry.vulnerable) && !hit(&entry.unaffected) {
                Verdict::Affected {
                    fixed_in: amivuln_sources::glsa::fixed_version(
                        &entry.unaffected,
                        installed,
                        slot,
                    )
                    .and_then(|v| v.parse().ok())
                    .map(Version::Gentoo),
                }
            } else {
                Verdict::Patched
            };
            let ids: Vec<String> = if advisory.cves.is_empty() {
                vec![format!("GLSA-{}", advisory.id)]
            } else {
                advisory.cves.clone()
            };
            for id in ids {
                let item = (verdict.clone(), advisory.severity);
                match by_cve.remove(&id) {
                    Some(prev) => by_cve.insert(id, merge(prev, item)),
                    None => by_cve.insert(id, item),
                };
            }
        }
    }
    finish(by_cve, vex)
}

/// Findings for a Fedora package from `updateinfo`.
///
/// updateinfo lists the CVEs an update fixed. A fix newer than the installed
/// build means the installed build is affected and names the version that
/// closes it. CVEs without a published Fedora fix are not visible here (see
/// ADR-0007): the result states what Fedora has fixed, not that nothing else
/// applies.
#[must_use]
pub fn fedora_findings(pkg: &PackageRef, info: &Updateinfo, vex: &[VexStatement]) -> Vec<Finding> {
    fedora_assess(pkg, info, vex).findings
}

/// Like [`fedora_findings`], keeping the settled CVEs too.
#[must_use]
pub fn fedora_assess(pkg: &PackageRef, info: &Updateinfo, vex: &[VexStatement]) -> Assessment {
    let mut names = vec![pkg.name.as_str()];
    if let Some(src) = pkg.source_name.as_deref().filter(|s| *s != pkg.name) {
        names.push(src);
    }
    let mut cves: Vec<&str> = names
        .iter()
        .flat_map(|n| info.fixes_for(n))
        .map(|f| f.cve.as_str())
        .collect();
    cves.sort_unstable();
    cves.dedup();

    let mut by_cve = BTreeMap::new();
    for cve in cves {
        let Some((status, severity)) = info.status_for(&names, cve) else {
            continue;
        };
        by_cve.insert(cve.to_owned(), (classify(&pkg.version, &status), severity));
    }
    finish(by_cve, vex)
}

/// Findings for a Debian or Ubuntu package from OSV.
///
/// OSV states the version that fixed each issue. A fix newer than the
/// installed build means the build is affected. An advisory that matched this
/// version but records no fix at all is an open issue: affected, with no
/// version to move to.
#[must_use]
pub fn osv_findings(pkg: &PackageRef, osv: &OsvData, vex: &[VexStatement]) -> Vec<Finding> {
    osv_assess(pkg, osv, vex).findings
}

/// Like [`osv_findings`], keeping the settled CVEs too.
#[must_use]
pub fn osv_assess(pkg: &PackageRef, osv: &OsvData, vex: &[VexStatement]) -> Assessment {
    if let Version::Semver(installed) = &pkg.version {
        return osv_language_assessment(pkg, installed, osv, vex);
    }
    let mut by_cve: BTreeMap<String, Verdict> = BTreeMap::new();
    let mut cves: Vec<String> = osv.ids();
    cves.sort_unstable();
    cves.dedup();
    for cve in cves {
        let candidates = fixes_for_package(pkg, osv, &cve);
        // Several advisories can fix one CVE (Red Hat issues one per minor
        // stream): at or above any published fix is patched, otherwise the
        // lowest fix is the one to move to.
        let chosen = candidates
            .iter()
            .find(|f| {
                matches!(
                    pkg.version.compare(f),
                    Some(Ordering::Greater | Ordering::Equal)
                )
            })
            .or_else(|| {
                candidates
                    .iter()
                    .min_by(|a, b| a.compare(b).unwrap_or(Ordering::Equal))
            });
        // `querybatch` already matched this exact version against the
        // advisory's ranges, so a record that offers no fix at all is an
        // open issue: affected, with nothing to upgrade to.
        let mut verdict = match chosen.cloned() {
            Some(fix_version) => classify(&pkg.version, &DistroStatus::Fixed(fix_version)),
            None => Verdict::Affected { fixed_in: None },
        };
        apply_vex(&mut verdict, vex, &cve);
        by_cve.insert(cve, verdict);
    }
    let (open, settled): (Vec<_>, Vec<_>) = by_cve
        .into_iter()
        .partition(|(_, v)| matches!(v, Verdict::Affected { .. } | Verdict::Unverified));
    let make = |(id, verdict): (String, Verdict)| {
        let severity = osv_severity(osv.severity_for(&id));
        Finding::new(id, severity, verdict)
    };
    let mut assessment = Assessment {
        findings: open.into_iter().map(make).collect(),
        resolved: settled.into_iter().map(make).collect(),
    };
    sort_findings(&mut assessment.findings);
    sort_findings(&mut assessment.resolved);
    assessment
}

/// Every fix OSV records for `cve` that applies to this package, in the
/// package's own version scheme.
///
/// An advisory lists a fix per binary package, so the entries are matched on
/// the installed name and the source name. When none name the package (an
/// older record shape) the advisory's lowest fix is used instead.
fn fixes_for_package(pkg: &PackageRef, osv: &OsvData, cve: &str) -> Vec<Version> {
    let parse = |fix: &str| match &pkg.version {
        Version::Rpm(_) => Version::Rpm(fix.parse().unwrap_or_else(|never| match never {})),
        Version::Apk(_) => Version::Apk(fix.parse().unwrap_or_else(|never| match never {})),
        _ => Version::Deb(fix.parse().unwrap_or_else(|never| match never {})),
    };
    let named: Vec<Version> = osv
        .fixes_for(cve)
        .iter()
        .filter(|(name, _)| *name == pkg.name || Some(name) == pkg.source_name.as_ref())
        .map(|(_, fix)| parse(fix))
        .collect();
    if named.is_empty() {
        osv.fix_for(cve).map(parse).into_iter().collect()
    } else {
        named
    }
}

/// Maps the textual severity of an advisory database to a [`Severity`].
fn osv_severity(text: Option<&str>) -> Severity {
    match text {
        Some("CRITICAL") => Severity::Critical,
        // Red Hat's "Important" is its second level.
        Some("HIGH" | "IMPORTANT") => Severity::High,
        Some("MODERATE" | "MEDIUM") => Severity::Medium,
        Some("LOW") => Severity::Low,
        _ => Severity::Unknown,
    }
}

/// Findings for a Go module or Rust crate from OSV.
///
/// `querybatch` already answered for this exact version, so every advisory it
/// returned affects it. The fix to report is the lowest fixed version above
/// the installed one among the ranges that name this package; none means no
/// fix is published.
fn osv_language_assessment(
    pkg: &PackageRef,
    installed: &amivuln_version::SemverVersion,
    osv: &OsvData,
    vex: &[VexStatement],
) -> Assessment {
    let mut out = Assessment::default();
    for cve in osv.ids() {
        let fixed_in = osv
            .fixes_for(&cve)
            .into_iter()
            .filter(|(name, _)| *name == pkg.name)
            .filter_map(|(_, fix)| amivuln_version::SemverVersion::parse(&fix).ok())
            .filter(|fix| fix > installed)
            .min()
            .map(Version::Semver);
        let mut verdict = Verdict::Affected { fixed_in };
        apply_vex(&mut verdict, vex, &cve);
        let severity = osv_severity(osv.severity_for(&cve));
        if matches!(verdict, Verdict::Affected { .. } | Verdict::Unverified) {
            out.findings.push(Finding::new(cve, severity, verdict));
        } else {
            out.resolved.push(Finding::new(cve, severity, verdict));
        }
    }
    sort_findings(&mut out.findings);
    sort_findings(&mut out.resolved);
    out
}

fn finish(by_cve: BTreeMap<String, (Verdict, Severity)>, vex: &[VexStatement]) -> Assessment {
    let (open, settled): (Vec<_>, Vec<_>) = by_cve
        .into_iter()
        .partition(|(_, (v, _))| matches!(v, Verdict::Affected { .. } | Verdict::Unverified));
    let mut assessment = Assessment {
        findings: open
            .into_iter()
            .map(|(id, (verdict, severity))| {
                let mut verdict = verdict;
                apply_vex(&mut verdict, vex, &id);
                Finding::new(id, severity, verdict)
            })
            .collect(),
        resolved: settled
            .into_iter()
            .map(|(id, (verdict, severity))| Finding::new(id, severity, verdict))
            .collect(),
    };
    sort_findings(&mut assessment.findings);
    sort_findings(&mut assessment.resolved);
    assessment
}

/// Attaches KEV and EPSS data. Missing sources simply leave fields empty; the
/// run report states which sources failed.
pub fn enrich(findings: &mut [Finding], kev: Option<&Kev>, epss: Option<&EpssScores>) {
    for f in findings {
        if let Some(k) = kev.and_then(|k| k.get(&f.id)) {
            f.kev = Some(KevInfo {
                added: k.added.clone(),
                ransomware: k.ransomware,
            });
        }
        if let Some(e) = epss.and_then(|e| e.get(&f.id)) {
            f.epss = Some(EpssInfo {
                score: e.score,
                percentile: e.percentile,
                date: e.date.clone(),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use amivuln_core::{Ecosystem, Provenance, VexStatement};
    use amivuln_sources::glsa::GlsaData;

    const ARCH: &[u8] =
        include_bytes!("../../../tests/fixtures/http/arch-tracker/2026-11-07/all.json");
    const FEDORA: &[u8] =
        include_bytes!("../../../tests/fixtures/http/fedora-updateinfo/2026-11-07/updateinfo.xml");

    fn arch_pkg(name: &str, version: &str) -> PackageRef {
        PackageRef {
            ecosystem: Ecosystem::Arch,
            name: name.into(),
            source_name: None,
            version: Version::Pacman(version.parse().unwrap_or_else(|n| match n {})),
            arch: None,
            slot: None,
            provenance: Provenance::PackageDb,
        }
    }

    fn no_vex() -> Vec<VexStatement> {
        Vec::new()
    }

    fn fedora_pkg(name: &str, source: Option<&str>, version: &str) -> PackageRef {
        PackageRef {
            ecosystem: Ecosystem::Fedora(43),
            name: name.into(),
            source_name: source.map(str::to_owned),
            version: Version::Rpm(version.parse().unwrap_or_else(|n| match n {})),
            arch: None,
            slot: None,
            provenance: Provenance::PackageDb,
        }
    }

    #[test]
    fn arch_older_than_fix_is_affected_with_fix_version() {
        let t = ArchTracker::parse(ARCH).unwrap();
        let f = arch_findings(&arch_pkg("djvulibre", "3.5.28-6"), &t, &no_vex());
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].id, "CVE-2025-53367");
        assert_eq!(f[0].severity, Severity::High);
        assert!(
            matches!(&f[0].verdict, Verdict::Affected { fixed_in: Some(v) } if v.to_string() == "3.5.30-1")
        );
    }

    #[test]
    fn arch_fixed_or_newer_is_clean() {
        let t = ArchTracker::parse(ARCH).unwrap();
        assert!(arch_findings(&arch_pkg("djvulibre", "3.5.30-1"), &t, &no_vex()).is_empty());
        assert!(arch_findings(&arch_pkg("djvulibre", "3.6.0-1"), &t, &no_vex()).is_empty());
    }

    #[test]
    fn arch_install_older_than_the_group_is_not_reported() {
        let t = ArchTracker::parse(ARCH).unwrap();
        // The AVG starts at 3.5.28-6; an older build is outside its range.
        assert!(arch_findings(&arch_pkg("djvulibre", "3.5.20-1"), &t, &no_vex()).is_empty());
    }

    #[test]
    fn arch_vulnerable_entry_for_an_older_upstream_version_is_only_unverified() {
        let t = ArchTracker::parse(ARCH).unwrap();
        // The tracker recorded pam 1.7.0-2 as vulnerable and never published a
        // fix. A newer upstream version must not be claimed as affected.
        let newer = arch_findings(&arch_pkg("pam", "1.8.0-1"), &t, &no_vex());
        assert_eq!(newer.len(), 1);
        assert_eq!(newer[0].verdict, Verdict::Unverified);
        // A rebuild of the same upstream version is still affected.
        let rebuild = arch_findings(&arch_pkg("pam", "1.7.0-3"), &t, &no_vex());
        assert!(matches!(rebuild[0].verdict, Verdict::Affected { .. }));
        // An install older than the recorded build is outside the entry.
        assert!(arch_findings(&arch_pkg("pam", "1.6.0-1"), &t, &no_vex()).is_empty());
    }

    #[test]
    fn arch_vulnerable_without_fix_and_unknown_stay_apart() {
        let t = ArchTracker::parse(ARCH).unwrap();
        let pam = arch_findings(&arch_pkg("pam", "1.7.0-2"), &t, &no_vex());
        assert!(matches!(
            pam[0].verdict,
            Verdict::Affected { fixed_in: None }
        ));
        let vim = arch_findings(&arch_pkg("vim", "9.0.1224-1"), &t, &no_vex());
        assert!(!vim.is_empty());
        assert!(
            vim.iter().all(|f| f.verdict == Verdict::Unverified
                || matches!(f.verdict, Verdict::Affected { .. }))
        );
        // not-affected is suppressed
        assert!(
            arch_findings(&arch_pkg("gnome-remote-desktop", "42.1-1"), &t, &no_vex()).is_empty()
        );
    }

    #[test]
    fn fedora_pending_update_is_affected_and_applied_update_is_clean() {
        let i = Updateinfo::parse(FEDORA).unwrap();
        let old = fedora_findings(
            &fedora_pkg(
                "python3-multipart",
                Some("python-multipart"),
                "0:1.3.0-1.fc43",
            ),
            &i,
            &no_vex(),
        );
        assert_eq!(old.len(), 1);
        assert_eq!(old[0].id, "CVE-2026-28356");
        assert!(
            matches!(&old[0].verdict, Verdict::Affected { fixed_in: Some(v) } if v.to_string() == "1.3.1-1.fc43")
        );
        let new = fedora_findings(
            &fedora_pkg(
                "python3-multipart",
                Some("python-multipart"),
                "0:1.3.1-1.fc43",
            ),
            &i,
            &no_vex(),
        );
        assert!(new.is_empty());
        assert!(
            fedora_findings(&fedora_pkg("nginx", None, "0:1.0-1.fc43"), &i, &no_vex()).is_empty()
        );
    }

    #[test]
    fn fedora_epoch_bump_counts() {
        let i = Updateinfo::parse(FEDORA).unwrap();
        let no_epoch = fedora_findings(
            &fedora_pkg("python3-wheel", None, "0.45.1-20.fc43"),
            &i,
            &no_vex(),
        );
        assert_eq!(no_epoch.len(), 1);
        let with = fedora_findings(
            &fedora_pkg("python3-wheel", None, "1:0.45.1-20.fc43"),
            &i,
            &no_vex(),
        );
        assert!(with.is_empty());
    }

    #[test]
    fn merging_prefers_affected_then_the_highest_fix() {
        let ver = |text: &str| Version::Pacman(text.parse().unwrap_or_else(|never| match never {}));
        let fix = |text: &str| Verdict::Affected {
            fixed_in: Some(ver(text)),
        };
        let (merged, sev) = merge((fix("2-1"), Severity::Low), (fix("3-1"), Severity::High));
        assert_eq!(sev, Severity::High);
        assert!(
            matches!(merged, Verdict::Affected { fixed_in: Some(ref x) } if x.to_string() == "3-1")
        );
        let (merged, _) = merge(
            (Verdict::Patched, Severity::Low),
            (fix("2-1"), Severity::Low),
        );
        assert!(matches!(merged, Verdict::Affected { .. }));
        let (merged, _) = merge(
            (fix("2-1"), Severity::Low),
            (Verdict::Unverified, Severity::Low),
        );
        assert!(matches!(merged, Verdict::Affected { .. }));
        let (merged, _) = merge(
            (Verdict::Unverified, Severity::Low),
            (Verdict::Patched, Severity::Low),
        );
        assert_eq!(merged, Verdict::Unverified);
    }

    #[test]
    fn enrichment_attaches_kev_and_epss() {
        let kev = Kev::parse(include_bytes!(
            "../../../tests/fixtures/http/kev/2026-11-08/known_exploited_vulnerabilities.json"
        ))
        .unwrap();
        let epss = EpssScores::parse(include_bytes!(
            "../../../tests/fixtures/http/epss/2026-11-08/epss.json"
        ))
        .unwrap();
        let mut f = vec![
            Finding::new("CVE-2026-59310", Severity::High, Verdict::Unverified),
            Finding::new("CVE-2024-6387", Severity::High, Verdict::Unverified),
            Finding::new("CVE-0000-0001", Severity::Low, Verdict::Unverified),
        ];
        enrich(&mut f, Some(&kev), Some(&epss));
        assert!(f[0].kev.as_ref().is_some_and(|k| k.ransomware));
        assert!(f[1].epss.as_ref().is_some_and(|e| e.score > 0.99));
        assert!(f[2].kev.is_none() && f[2].epss.is_none());
        let mut g = vec![Finding::new(
            "CVE-2026-59310",
            Severity::High,
            Verdict::Unverified,
        )];
        enrich(&mut g, None, None);
        assert!(g[0].kev.is_none());
    }

    fn rhel_pkg(name: &str, version: &str) -> PackageRef {
        PackageRef {
            ecosystem: Ecosystem::Rhel(9),
            name: name.into(),
            source_name: None,
            version: Version::Rpm(version.parse().unwrap_or_else(|n| match n {})),
            arch: None,
            slot: None,
            provenance: Provenance::PackageDb,
        }
    }

    /// Two RHSAs for one CVE (a GA and a z-stream fix), one of them also
    /// listing another package with a lower fix.
    fn rhsa_data() -> OsvData {
        let entry = |id: &str, fixes: &[(&str, &str)]| amivuln_sources::osv::OsvEntry {
            advisory: id.into(),
            cves: vec!["CVE-2023-5363".into()],
            fixed: fixes.first().map(|(_, f)| (*f).to_owned()),
            fixes: fixes
                .iter()
                .map(|(n, f)| ((*n).to_owned(), (*f).to_owned()))
                .collect(),
            severity: Some("IMPORTANT".into()),
        };
        OsvData::from_entries(vec![
            entry(
                "RHSA-2024:0310",
                &[
                    ("openssl-libs", "1:3.0.7-25.el9_3"),
                    ("openssl", "1:3.0.1-1.el9"),
                ],
            ),
            entry("RHSA-2024:2447", &[("openssl-libs", "1:3.0.7-28.el9_4")]),
        ])
    }

    #[test]
    fn rhel_at_or_above_any_fix_is_patched() {
        let osv = rhsa_data();
        // Below every fix: affected, pointing at the lowest fix of this package
        // (the other package's lower fix must not leak in).
        let below = osv_findings(&rhel_pkg("openssl-libs", "1:3.0.7-24.el9"), &osv, &[]);
        assert_eq!(below.len(), 1);
        assert_eq!(below[0].severity, Severity::High);
        let fixed = match &below[0].verdict {
            Verdict::Affected { fixed_in } => fixed_in.as_ref().map(ToString::to_string),
            _ => None,
        };
        assert_eq!(fixed.as_deref(), Some("1:3.0.7-25.el9_3"));
        // Between the two fixes: the lower one already covers it.
        assert!(osv_findings(&rhel_pkg("openssl-libs", "1:3.0.7-26.el9_3"), &osv, &[]).is_empty());
        assert!(osv_findings(&rhel_pkg("openssl-libs", "1:3.0.7-28.el9_4"), &osv, &[]).is_empty());
    }

    /// Regression: OSV answers a querybatch with records that have an
    /// introduced event and no fixed event. They were dropped for lack of a
    /// fix; they are open issues, affected with nothing to upgrade to.
    #[test]
    fn an_advisory_without_any_fix_is_affected_with_no_version() {
        let osv = OsvData::from_entries(vec![amivuln_sources::osv::OsvEntry {
            advisory: "DEBIAN-CVE-2023-4806".into(),
            cves: vec!["CVE-2023-4806".into()],
            fixed: None,
            fixes: Vec::new(),
            severity: None,
        }]);
        let found = osv_findings(&rhel_pkg("glibc", "2.36-9"), &osv, &[]);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].id, "CVE-2023-4806");
        assert!(matches!(
            found[0].verdict,
            Verdict::Affected { fixed_in: None }
        ));
    }

    fn gentoo_pkg(name: &str, slot: Option<&str>, version: &str) -> PackageRef {
        PackageRef {
            ecosystem: Ecosystem::Gentoo,
            name: name.into(),
            source_name: None,
            version: Version::Gentoo(version.parse().unwrap_or_else(|n| match n {})),
            arch: None,
            slot: slot.map(str::to_owned),
            provenance: Provenance::PackageDb,
        }
    }

    fn glsa_data() -> GlsaData {
        GlsaData::load(
            &std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/glsa"),
        )
        .unwrap()
    }

    fn verdicts(a: &Assessment) -> Vec<(String, String)> {
        a.findings
            .iter()
            .chain(&a.resolved)
            .map(|f| {
                let v = match &f.verdict {
                    Verdict::Affected { fixed_in: Some(v) } => format!("affected {v}"),
                    Verdict::Affected { fixed_in: None } => "affected".to_owned(),
                    Verdict::Patched => "patched".to_owned(),
                    other => format!("{other:?}"),
                };
                (f.id.clone(), v)
            })
            .collect()
    }

    #[test]
    fn a_gentoo_package_below_the_fix_is_affected_and_at_it_is_patched() {
        let data = glsa_data();
        let old = glsa_assess(
            &gentoo_pkg("dev-python/joblib", None, "1.1.0"),
            &data,
            &no_vex(),
        );
        assert_eq!(
            verdicts(&old),
            [("CVE-2022-21797".to_owned(), "affected 1.2.0".to_owned())]
        );
        // The advisory is about this package, the fix is installed: patched,
        // and kept apart from the findings.
        let new = glsa_assess(
            &gentoo_pkg("dev-python/joblib", None, "1.2.0-r1"),
            &data,
            &no_vex(),
        );
        assert!(new.findings.is_empty());
        assert_eq!(
            verdicts(&new),
            [("CVE-2022-21797".to_owned(), "patched".to_owned())]
        );
        // A package no advisory names has nothing, not even resolved entries.
        let other = glsa_assess(
            &gentoo_pkg("dev-libs/untouched", None, "1.0"),
            &data,
            &no_vex(),
        );
        assert_eq!(other, Assessment::default());
    }

    #[test]
    fn a_range_that_names_a_slot_applies_only_to_that_slot() {
        let data = glsa_data();
        // 202501-11: php 8.2 is fixed at 8.2.24, 8.3 at 8.3.12, 8.1 at 8.1.30.
        let at = |slot: &str, version: &str| {
            let a = glsa_assess(
                &gentoo_pkg("dev-lang/php", Some(slot), version),
                &data,
                &no_vex(),
            );
            a.findings.first().map(|f| f.verdict.clone())
        };
        assert_eq!(
            at("8.2", "8.2.20"),
            Some(Verdict::Affected {
                fixed_in: Some(Version::Gentoo(
                    "8.2.24".parse().unwrap_or_else(|n| match n {})
                )),
            })
        );
        assert_eq!(at("8.2", "8.2.24"), None);
        assert!(at("8.3", "8.3.1").is_some());
        // 8.1 has an own fix; it is not judged against the 8.2 one.
        assert!(
            matches!(
                at("8.1", "8.1.2"),
                Some(Verdict::Affected { fixed_in: None })
            ),
            "no fix is published for a slot the advisory only lists as vulnerable"
        );
        // A slot the advisory never mentions is not covered at all.
        assert_eq!(at("7.4", "7.4.1"), None);
        let none = glsa_assess(
            &gentoo_pkg("dev-lang/php", Some("7.4"), "7.4.1"),
            &data,
            &no_vex(),
        );
        assert_eq!(none, Assessment::default());
    }

    #[test]
    fn revision_ranges_and_advisories_without_a_cve_are_handled() {
        let data = glsa_data();
        // dev-vcs/git: unaffected rge 2.21.1, rge 2.23.1-r1, rge 2.24.1.
        let git = |v: &str| {
            verdicts(&glsa_assess(
                &gentoo_pkg("dev-vcs/git", None, v),
                &data,
                &no_vex(),
            ))
        };
        let fixed = |v: &str| git(v).first().map(|(_, state)| state.clone());
        assert_eq!(fixed("2.23.0").as_deref(), Some("affected 2.23.1-r1"));
        assert_eq!(fixed("2.23.1").as_deref(), Some("affected 2.23.1-r1"));
        assert_eq!(fixed("2.23.1-r2").as_deref(), Some("patched"));
        assert_eq!(fixed("2.24.1").as_deref(), Some("patched"));
        assert_eq!(fixed("2.21.1-r3").as_deref(), Some("patched"));
        // An advisory that lists no CVE is reported under its own id.
        let seamonkey = glsa_assess(
            &gentoo_pkg("www-client/seamonkey", None, "2.53.0"),
            &data,
            &no_vex(),
        );
        assert_eq!(
            verdicts(&seamonkey),
            [("GLSA-202402-24".to_owned(), "affected 2.53.10.2".to_owned())]
        );
    }

    #[test]
    fn a_vex_statement_still_overrides_a_gentoo_finding() {
        let data = glsa_data();
        let vex = vec![VexStatement {
            id: "CVE-2022-21797".to_owned(),
            author: "me".to_owned(),
            justification: Some("not used".to_owned()),
        }];
        let a = glsa_assess(&gentoo_pkg("dev-python/joblib", None, "1.1.0"), &data, &vex);
        // Kept in the findings with the statement's verdict, as for every
        // other distribution; no summary counts it.
        assert!(
            matches!(a.findings.as_slice(), [f] if matches!(f.verdict, Verdict::NotAffected(_))),
            "{a:?}"
        );
    }
}
