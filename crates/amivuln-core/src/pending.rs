// SPDX-FileCopyrightText: 2026 amivuln contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Questions answered from a finished scan: which updates close the most risk,
//! and which installed packages a given CVE affects.

use std::collections::BTreeMap;

use crate::matching::{Finding, Severity, Verdict};
use crate::package::{PackageRef, Version};
use crate::report::TargetReport;

/// An update that would close at least one affected finding.
#[derive(Debug, Clone, PartialEq)]
pub struct PendingUpdate {
    /// A representative installed package: the one named like the source
    /// package when there is one, otherwise the first by name.
    pub package: PackageRef,
    /// The other binary packages built from the same source that this update
    /// also upgrades, sorted.
    pub also: Vec<String>,
    /// The version that closes every finding that has a fix: the highest one.
    pub target: Version,
    /// Ids of the findings the update closes, sorted.
    pub closes: Vec<String>,
    /// Highest severity among them.
    pub severity: Severity,
    /// How many of them are in the CISA KEV catalog.
    pub kev: usize,
    /// Highest EPSS score among them.
    pub epss_max: Option<f64>,
}

/// What a CVE query says about the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CveState {
    /// At least one installed package is affected.
    Affected,
    /// The distribution knows the CVE and no installed package is affected
    /// (fixed already, not affected, or not installed).
    NotAffected,
    /// The distribution data has no record of this CVE. This is **not** a
    /// statement that the host is safe.
    Unknown,
}

/// One installed package affected by a queried CVE.
#[derive(Debug, Clone, PartialEq)]
pub struct CveHit {
    /// The package.
    pub package: PackageRef,
    /// The version that fixes it, when published.
    pub fixed_in: Option<Version>,
    /// The finding, with severity, KEV and EPSS.
    pub finding: Finding,
}

/// The answer for one CVE.
#[derive(Debug, Clone, PartialEq)]
pub struct CveAnswer {
    /// The CVE id as asked.
    pub id: String,
    /// The conclusion.
    pub state: CveState,
    /// Affected installed packages, sorted by name then version.
    pub hits: Vec<CveHit>,
}

/// Groups affected findings into updates, one per source package and installed
/// version, ranked by risk: KEV count, then severity, then EPSS, then name.
///
/// Findings whose id is in `suppressed` are excluded: an accepted finding is
/// not something an update needs to close.
#[must_use]
pub fn pending_updates(
    targets: &[TargetReport],
    suppressed: &std::collections::BTreeMap<String, String>,
) -> Vec<PendingUpdate> {
    let mut groups: BTreeMap<(String, String), Vec<&TargetReport>> = BTreeMap::new();
    for t in targets {
        if !t.findings.iter().any(|f| {
            matches!(f.verdict, Verdict::Affected { fixed_in: Some(_) })
                && !suppressed.contains_key(&f.id)
        }) {
            continue;
        }
        let source = t
            .package
            .source_name
            .clone()
            .unwrap_or_else(|| t.package.name.clone());
        groups
            .entry((source, t.package.version.to_string()))
            .or_default()
            .push(t);
    }
    let mut out: Vec<PendingUpdate> = Vec::new();
    for ((source, _), members) in groups {
        let mut target: Option<Version> = None;
        let mut closes: Vec<String> = Vec::new();
        let mut severity = Severity::Unknown;
        let mut epss_max: Option<f64> = None;
        let mut kev_ids: Vec<&str> = Vec::new();
        for t in &members {
            for f in &t.findings {
                let Verdict::Affected {
                    fixed_in: Some(fix),
                } = &f.verdict
                else {
                    continue;
                };
                target = match target {
                    Some(cur) if cur.compare(fix) != Some(core::cmp::Ordering::Less) => Some(cur),
                    _ => Some(fix.clone()),
                };
                closes.push(f.id.clone());
                severity = severity.max(f.severity);
                if f.kev.is_some() {
                    kev_ids.push(&f.id);
                }
                if let Some(e) = &f.epss {
                    epss_max = Some(epss_max.map_or(e.score, |m| m.max(e.score)));
                }
            }
        }
        closes.sort();
        closes.dedup();
        kev_ids.sort_unstable();
        kev_ids.dedup();
        let Some(target) = target else { continue };
        let mut names: Vec<&TargetReport> = members;
        names.sort_by(|a, b| a.package.name.cmp(&b.package.name));
        let rep = names
            .iter()
            .find(|t| t.package.name == source)
            .or_else(|| names.first())
            .map(|t| t.package.clone());
        let Some(package) = rep else { continue };
        let also = names
            .iter()
            .map(|t| t.package.name.clone())
            .filter(|n| *n != package.name)
            .collect();
        out.push(PendingUpdate {
            package,
            also,
            target,
            closes,
            severity,
            kev: kev_ids.len(),
            epss_max,
        });
    }
    out.sort_by(|a, b| {
        b.kev
            .cmp(&a.kev)
            .then_with(|| b.severity.cmp(&a.severity))
            .then_with(|| {
                b.epss_max
                    .unwrap_or(0.0)
                    .partial_cmp(&a.epss_max.unwrap_or(0.0))
                    .unwrap_or(core::cmp::Ordering::Equal)
            })
            .then_with(|| a.package.name.cmp(&b.package.name))
            .then_with(|| {
                a.package
                    .version
                    .to_string()
                    .cmp(&b.package.version.to_string())
            })
    });
    out
}

/// Answers CVE queries from a finished scan.
///
/// `known` says whether the distribution data has any record of an id, which
/// separates "not affected" from "no statement".
#[must_use]
pub fn cve_answers(
    ids: &[String],
    targets: &[TargetReport],
    known: impl Fn(&str) -> bool,
) -> Vec<CveAnswer> {
    ids.iter()
        .map(|id| {
            let mut hits: Vec<CveHit> = targets
                .iter()
                .flat_map(|t| {
                    t.findings
                        .iter()
                        .filter(|f| {
                            f.id.eq_ignore_ascii_case(id)
                                && matches!(f.verdict, Verdict::Affected { .. })
                        })
                        .map(move |f| CveHit {
                            package: t.package.clone(),
                            fixed_in: match &f.verdict {
                                Verdict::Affected { fixed_in } => fixed_in.clone(),
                                _ => None,
                            },
                            finding: f.clone(),
                        })
                })
                .collect();
            hits.sort_by(|a, b| {
                a.package.name.cmp(&b.package.name).then_with(|| {
                    a.package
                        .version
                        .to_string()
                        .cmp(&b.package.version.to_string())
                })
            });
            let state = if !hits.is_empty() {
                CveState::Affected
            } else if known(id) {
                CveState::NotAffected
            } else {
                CveState::Unknown
            };
            CveAnswer {
                id: id.clone(),
                state,
                hits,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::matching::{EpssInfo, KevInfo};
    use crate::package::{Ecosystem, Provenance};

    fn rpm(s: &str) -> Version {
        Version::Rpm(s.parse().unwrap_or_else(|n| match n {}))
    }

    fn target(name: &str, version: &str, findings: Vec<Finding>) -> TargetReport {
        TargetReport {
            input: name.into(),
            package: PackageRef {
                ecosystem: Ecosystem::Fedora(44),
                name: name.into(),
                source_name: None,
                version: rpm(version),
                arch: None,
                slot: None,
                provenance: Provenance::PackageDb,
            },
            findings,
            resolved: Vec::new(),
        }
    }

    fn fix(id: &str, sev: Severity, v: &str) -> Finding {
        Finding::new(
            id,
            sev,
            Verdict::Affected {
                fixed_in: Some(rpm(v)),
            },
        )
    }

    #[test]
    fn one_update_per_package_with_the_highest_fix() {
        let t = target(
            "nginx",
            "1.0-1",
            vec![
                fix("CVE-0000-0001", Severity::Low, "1.1-1"),
                fix("CVE-0000-0002", Severity::High, "1.2-1"),
            ],
        );
        let u = pending_updates(&[t], &std::collections::BTreeMap::new());
        assert_eq!(u.len(), 1);
        assert_eq!(u[0].target, rpm("1.2-1"));
        assert_eq!(u[0].closes, ["CVE-0000-0001", "CVE-0000-0002"]);
        assert_eq!(u[0].severity, Severity::High);
    }

    #[test]
    fn subpackages_of_one_source_are_one_update() {
        let mk = |name: &str| {
            let mut t = target(
                name,
                "1.0-1",
                vec![fix("CVE-0000-0001", Severity::High, "1.1-1")],
            );
            t.package.source_name = Some("pcre2".into());
            t
        };
        let u = pending_updates(
            &[mk("pcre2-utf16"), mk("pcre2"), mk("pcre2-syntax")],
            &BTreeMap::new(),
        );
        assert_eq!(u.len(), 1);
        assert_eq!(u[0].package.name, "pcre2");
        assert_eq!(u[0].also, ["pcre2-syntax", "pcre2-utf16"]);
        assert_eq!(u[0].closes, ["CVE-0000-0001"]);
    }

    #[test]
    fn findings_without_a_fix_and_unverified_are_not_updates() {
        let t = target(
            "pam",
            "1.0-1",
            vec![
                Finding::new(
                    "CVE-0000-0001",
                    Severity::High,
                    Verdict::Affected { fixed_in: None },
                ),
                Finding::new("CVE-0000-0002", Severity::High, Verdict::Unverified),
            ],
        );
        assert!(pending_updates(&[t], &BTreeMap::new()).is_empty());
        assert!(pending_updates(&[target("bash", "1-1", vec![])], &BTreeMap::new()).is_empty());
    }

    #[test]
    fn ranking_is_kev_then_severity_then_epss_then_name() {
        let mut kev = fix("CVE-0000-0001", Severity::Low, "2-1");
        kev.kev = Some(KevInfo {
            added: "2026-01-01".into(),
            ransomware: false,
        });
        let mut hot = fix("CVE-0000-0002", Severity::High, "2-1");
        hot.epss = Some(EpssInfo {
            score: 0.9,
            percentile: 0.9,
            date: "d".into(),
        });
        let updates = pending_updates(
            &[
                target(
                    "zzz",
                    "1-1",
                    vec![fix("CVE-0000-0003", Severity::High, "2-1")],
                ),
                target("aaa", "1-1", vec![hot]),
                target("kev", "1-1", vec![kev]),
                target(
                    "bbb",
                    "1-1",
                    vec![fix("CVE-0000-0004", Severity::High, "2-1")],
                ),
            ],
            &BTreeMap::new(),
        );
        let names: Vec<&str> = updates.iter().map(|u| u.package.name.as_str()).collect();
        assert_eq!(names, ["kev", "aaa", "bbb", "zzz"]);
    }

    #[test]
    fn cve_states() {
        let t = vec![
            target(
                "nginx",
                "1.0-1",
                vec![fix("CVE-2026-0001", Severity::High, "1.1-1")],
            ),
            target(
                "nginx",
                "0.9-1",
                vec![fix("CVE-2026-0001", Severity::High, "1.1-1")],
            ),
            target("bash", "5-1", vec![]),
        ];
        let known = |id: &str| id == "CVE-2026-0001" || id == "CVE-2026-0002";
        let ids: Vec<String> = ["cve-2026-0001", "CVE-2026-0002", "CVE-2026-9999"]
            .map(str::to_owned)
            .to_vec();
        let a = cve_answers(&ids, &t, known);
        assert_eq!(a[0].state, CveState::Affected);
        assert_eq!(a[0].hits.len(), 2);
        assert_eq!(a[0].hits[0].package.version, rpm("0.9-1"));
        assert_eq!(a[1].state, CveState::NotAffected);
        assert_eq!(a[2].state, CveState::Unknown);
    }
}
