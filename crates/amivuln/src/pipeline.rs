// SPDX-FileCopyrightText: 2026 amivuln contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Turning distro data into findings. Pure functions: no I/O, no clock.

use std::collections::BTreeMap;

use amivuln_core::{
    DistroStatus, EpssInfo, Finding, KevInfo, PackageRef, Severity, Verdict, Version, classify,
    sort_findings,
};
use amivuln_sources::arch::{ArchEntry, ArchTracker};
use amivuln_sources::epss::EpssScores;
use amivuln_sources::fedora::Updateinfo;
use amivuln_sources::kev::Kev;

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

fn one_arch_entry(installed: &Version, e: &ArchEntry) -> Option<Verdict> {
    // A group covers [affected_since, fixed). Older installs are outside it.
    if let (Some(since), DistroStatus::Fixed(_) | DistroStatus::Affected) =
        (&e.affected_since, &e.status)
        && installed.compare(since) == Some(core::cmp::Ordering::Less)
    {
        return None;
    }
    Some(classify(installed, &e.status))
}

/// Findings for an Arch package from the Security Tracker.
///
/// Patched and not-affected CVEs are not reported.
#[must_use]
pub fn arch_findings(pkg: &PackageRef, tracker: &ArchTracker) -> Vec<Finding> {
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
    finish(by_cve)
}

/// Findings for a Fedora package from `updateinfo`.
///
/// updateinfo lists the CVEs an update fixed. A fix newer than the installed
/// build means the installed build is affected and names the version that
/// closes it. CVEs without a published Fedora fix are not visible here (see
/// ADR-0007): the result states what Fedora has fixed, not that nothing else
/// applies.
#[must_use]
pub fn fedora_findings(pkg: &PackageRef, info: &Updateinfo) -> Vec<Finding> {
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
    finish(by_cve)
}

fn finish(by_cve: BTreeMap<String, (Verdict, Severity)>) -> Vec<Finding> {
    let mut out: Vec<Finding> = by_cve
        .into_iter()
        .filter(|(_, (v, _))| matches!(v, Verdict::Affected { .. } | Verdict::Unverified))
        .map(|(id, (verdict, severity))| Finding::new(id, severity, verdict))
        .collect();
    sort_findings(&mut out);
    out
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
    use amivuln_core::{Ecosystem, Provenance};

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
            provenance: Provenance::PackageDb,
        }
    }

    fn fedora_pkg(name: &str, source: Option<&str>, version: &str) -> PackageRef {
        PackageRef {
            ecosystem: Ecosystem::Fedora(43),
            name: name.into(),
            source_name: source.map(str::to_owned),
            version: Version::Rpm(version.parse().unwrap_or_else(|n| match n {})),
            arch: None,
            provenance: Provenance::PackageDb,
        }
    }

    #[test]
    fn arch_older_than_fix_is_affected_with_fix_version() {
        let t = ArchTracker::parse(ARCH).unwrap();
        let f = arch_findings(&arch_pkg("djvulibre", "3.5.28-6"), &t);
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
        assert!(arch_findings(&arch_pkg("djvulibre", "3.5.30-1"), &t).is_empty());
        assert!(arch_findings(&arch_pkg("djvulibre", "3.6.0-1"), &t).is_empty());
    }

    #[test]
    fn arch_install_older_than_the_group_is_not_reported() {
        let t = ArchTracker::parse(ARCH).unwrap();
        // The AVG starts at 3.5.28-6; an older build is outside its range.
        assert!(arch_findings(&arch_pkg("djvulibre", "3.5.20-1"), &t).is_empty());
    }

    #[test]
    fn arch_vulnerable_without_fix_and_unknown_stay_apart() {
        let t = ArchTracker::parse(ARCH).unwrap();
        let pam = arch_findings(&arch_pkg("pam", "1.7.0-2"), &t);
        assert!(matches!(
            pam[0].verdict,
            Verdict::Affected { fixed_in: None }
        ));
        let vim = arch_findings(&arch_pkg("vim", "9.0.1224-1"), &t);
        assert!(!vim.is_empty());
        assert!(
            vim.iter().all(|f| f.verdict == Verdict::Unverified
                || matches!(f.verdict, Verdict::Affected { .. }))
        );
        // not-affected is suppressed
        assert!(arch_findings(&arch_pkg("gnome-remote-desktop", "42.1-1"), &t).is_empty());
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
        );
        assert!(new.is_empty());
        assert!(fedora_findings(&fedora_pkg("nginx", None, "0:1.0-1.fc43"), &i).is_empty());
    }

    #[test]
    fn fedora_epoch_bump_counts() {
        let i = Updateinfo::parse(FEDORA).unwrap();
        let no_epoch = fedora_findings(&fedora_pkg("python3-wheel", None, "0.45.1-20.fc43"), &i);
        assert_eq!(no_epoch.len(), 1);
        let with = fedora_findings(&fedora_pkg("python3-wheel", None, "1:0.45.1-20.fc43"), &i);
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
}
