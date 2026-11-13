// SPDX-FileCopyrightText: 2026 amivuln contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! The result of a run, as data. Formatters live in `amivuln-report`.

use core::str::FromStr;

use crate::matching::{Finding, Severity, Verdict};
use crate::package::PackageRef;
use crate::source::SourceReport;

/// Host facts that may appear in output. Nothing here identifies the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostMeta {
    /// `ID` from os-release, for example `fedora`.
    pub os_id: String,
    /// `VERSION_ID` from os-release, for example `44`.
    pub os_version: String,
    /// CPU architecture, for example `x86_64`.
    pub arch: String,
}

/// Counts for one target. Only affected findings are counted; unverified
/// ones are kept apart (invariant: unknown is never mixed with affected).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Summary {
    /// Affected, critical.
    pub critical: usize,
    /// Affected, high.
    pub high: usize,
    /// Affected, medium.
    pub medium: usize,
    /// Affected, low (and unknown severity).
    pub low: usize,
    /// Affected and in KEV.
    pub kev: usize,
    /// Highest EPSS among affected findings.
    pub epss_max: Option<f64>,
    /// Findings the distribution could not confirm.
    pub unverified: usize,
}

impl Summary {
    /// Computes the summary from findings.
    #[must_use]
    pub fn of(findings: &[Finding]) -> Self {
        let mut s = Self::default();
        for f in findings {
            match f.verdict {
                Verdict::Affected { .. } => {
                    match f.severity {
                        Severity::Critical => s.critical += 1,
                        Severity::High => s.high += 1,
                        Severity::Medium => s.medium += 1,
                        Severity::Low | Severity::Unknown => s.low += 1,
                    }
                    if f.kev.is_some() {
                        s.kev += 1;
                    }
                    if let Some(e) = &f.epss {
                        s.epss_max = Some(s.epss_max.map_or(e.score, |m| m.max(e.score)));
                    }
                }
                Verdict::Unverified => s.unverified += 1,
                Verdict::Patched | Verdict::NotAffected(_) => {}
            }
        }
        s
    }

    /// Total affected findings.
    #[must_use]
    pub fn affected(&self) -> usize {
        self.critical + self.high + self.medium + self.low
    }
}

/// Result for one resolved target.
#[derive(Debug, Clone, PartialEq)]
pub struct TargetReport {
    /// What the user asked about.
    pub input: String,
    /// The package it resolved to.
    pub package: PackageRef,
    /// Reportable findings, sorted.
    pub findings: Vec<Finding>,
    /// CVEs the distribution has already settled for this version: fixed
    /// (including by backport) or not affecting it. They are not findings and
    /// no summary, score or exit code counts them; they are kept because a VEX
    /// document states them.
    pub resolved: Vec<Finding>,
}

/// A target that could not be resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unresolved {
    /// What the user asked about.
    pub input: String,
    /// Why, written for the user.
    pub reason: String,
}

/// Everything a formatter needs.
#[derive(Debug, Clone, PartialEq)]
pub struct RunReport {
    /// Tool version.
    pub tool_version: String,
    /// Generation time, RFC 3339 in UTC.
    pub generated_at: String,
    /// Host facts.
    pub host: HostMeta,
    /// False when a required source failed (invariant 3).
    pub complete: bool,
    /// One entry per consulted source.
    pub sources: Vec<SourceReport>,
    /// Resolved targets.
    pub targets: Vec<TargetReport>,
    /// Accepted findings: id -> reason. Suppressed findings stay listed.
    pub suppressed: std::collections::BTreeMap<String, String>,
    /// Targets that failed to resolve.
    pub unresolved: Vec<Unresolved>,
}

/// Result of `amivuln pending`.
#[derive(Debug, Clone, PartialEq)]
pub struct PendingReport {
    /// Tool version.
    pub tool_version: String,
    /// Generation time, RFC 3339 in UTC.
    pub generated_at: String,
    /// Host facts.
    pub host: HostMeta,
    /// False when a required source failed.
    pub complete: bool,
    /// One entry per consulted source.
    pub sources: Vec<SourceReport>,
    /// Accepted findings: id -> reason.
    pub suppressed: std::collections::BTreeMap<String, String>,
    /// Updates that close affected findings, riskiest first.
    pub updates: Vec<crate::pending::PendingUpdate>,
    /// Affected findings no published update closes yet.
    pub without_fix: usize,
}

/// Result of `amivuln cve`.
#[derive(Debug, Clone, PartialEq)]
pub struct CveReport {
    /// Tool version.
    pub tool_version: String,
    /// Generation time, RFC 3339 in UTC.
    pub generated_at: String,
    /// Host facts.
    pub host: HostMeta,
    /// False when a required source failed.
    pub complete: bool,
    /// One entry per consulted source.
    pub sources: Vec<SourceReport>,
    /// Accepted findings: id -> reason.
    pub suppressed: std::collections::BTreeMap<String, String>,
    /// One answer per queried CVE.
    pub answers: Vec<crate::pending::CveAnswer>,
}

/// A process, or the processes of one service, that need a restart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestartItem {
    /// The systemd service, when known.
    pub unit: Option<String>,
    /// Process ids.
    pub pids: Vec<u32>,
    /// Command name of the first process.
    pub comm: String,
    /// The replaced executable and its package.
    pub exe: Option<(String, Option<String>)>,
    /// Replaced libraries and the package that owns each.
    pub libs: Vec<(String, Option<String>)>,
}

/// Result of `amivuln restart`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestartReport {
    /// Tool version.
    pub tool_version: String,
    /// Generation time, RFC 3339 in UTC.
    pub generated_at: String,
    /// Host facts.
    pub host: HostMeta,
    /// Processes inspected.
    pub inspected: usize,
    /// Processes that could not be read (permissions).
    pub unreadable: usize,
    /// Things to restart, by unit.
    pub items: Vec<RestartItem>,
}

/// Threshold for `--fail-on`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailOn {
    /// Never fail on findings.
    None,
    /// Any affected finding at or above this severity.
    Severity(Severity),
    /// Any affected finding in KEV.
    Kev,
}

impl FromStr for FailOn {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "none" => Ok(Self::None),
            "low" => Ok(Self::Severity(Severity::Low)),
            "medium" => Ok(Self::Severity(Severity::Medium)),
            "high" => Ok(Self::Severity(Severity::High)),
            "critical" => Ok(Self::Severity(Severity::Critical)),
            "kev" => Ok(Self::Kev),
            other => Err(format!(
                "invalid --fail-on value {other:?}; use none, low, medium, high, critical or kev"
            )),
        }
    }
}

/// Policy applied to a finished run.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Policy {
    /// Severity or KEV threshold.
    pub fail_on: FailOn,
    /// Fail when an affected finding has at least this EPSS score.
    pub fail_on_epss: Option<f64>,
    /// Count unverified findings as violations (`--strict`).
    pub strict: bool,
}

impl Policy {
    /// True when any finding violates the policy.
    #[must_use]
    pub fn violated_by(&self, findings: &[Finding]) -> bool {
        findings.iter().any(|f| {
            let counts = match f.verdict {
                Verdict::Affected { .. } => true,
                Verdict::Unverified => self.strict,
                Verdict::Patched | Verdict::NotAffected(_) => false,
            };
            if !counts {
                return false;
            }
            let by_level = match self.fail_on {
                FailOn::None => false,
                FailOn::Severity(min) => f.severity >= min,
                FailOn::Kev => f.kev.is_some(),
            };
            let by_epss = match (self.fail_on_epss, &f.epss) {
                (Some(limit), Some(e)) => e.score >= limit,
                _ => false,
            };
            by_level || by_epss
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::matching::{EpssInfo, KevInfo};

    fn affected(id: &str, sev: Severity) -> Finding {
        Finding::new(id, sev, Verdict::Affected { fixed_in: None })
    }

    #[test]
    fn summary_keeps_unverified_apart() {
        let mut kev = affected("CVE-0000-0001", Severity::High);
        kev.kev = Some(KevInfo {
            added: "2026-01-01".into(),
            ransomware: false,
        });
        kev.epss = Some(EpssInfo {
            score: 0.4,
            percentile: 0.9,
            date: "2026-01-02".into(),
        });
        let mut other = affected("CVE-0000-0002", Severity::Critical);
        other.epss = Some(EpssInfo {
            score: 0.9,
            percentile: 0.99,
            date: "2026-01-02".into(),
        });
        let findings = vec![
            kev,
            other,
            affected("CVE-0000-0003", Severity::Unknown),
            Finding::new("CVE-0000-0004", Severity::Critical, Verdict::Unverified),
            Finding::new("CVE-0000-0005", Severity::Critical, Verdict::Patched),
        ];
        let s = Summary::of(&findings);
        assert_eq!((s.critical, s.high, s.medium, s.low), (1, 1, 0, 1));
        assert_eq!((s.kev, s.unverified, s.affected()), (1, 1, 3));
        assert_eq!(s.epss_max, Some(0.9));
    }

    #[test]
    fn fail_on_parses_and_rejects() {
        assert_eq!("high".parse(), Ok(FailOn::Severity(Severity::High)));
        assert_eq!("kev".parse(), Ok(FailOn::Kev));
        assert_eq!("none".parse(), Ok(FailOn::None));
        assert!("urgent".parse::<FailOn>().is_err());
    }

    fn policy(fail_on: FailOn) -> Policy {
        Policy {
            fail_on,
            fail_on_epss: None,
            strict: false,
        }
    }

    #[test]
    fn severity_threshold() {
        let f = [affected("CVE-0000-0001", Severity::High)];
        assert!(policy(FailOn::Severity(Severity::High)).violated_by(&f));
        assert!(policy(FailOn::Severity(Severity::Low)).violated_by(&f));
        assert!(!policy(FailOn::Severity(Severity::Critical)).violated_by(&f));
        assert!(!policy(FailOn::None).violated_by(&f));
    }

    #[test]
    fn unverified_counts_only_when_strict() {
        let f = [Finding::new(
            "CVE-0000-0001",
            Severity::Critical,
            Verdict::Unverified,
        )];
        assert!(!policy(FailOn::Severity(Severity::Low)).violated_by(&f));
        let strict = Policy {
            strict: true,
            ..policy(FailOn::Severity(Severity::Low))
        };
        assert!(strict.violated_by(&f));
    }

    #[test]
    fn kev_and_epss_thresholds() {
        let mut f = affected("CVE-0000-0001", Severity::Low);
        assert!(!policy(FailOn::Kev).violated_by(std::slice::from_ref(&f)));
        f.kev = Some(KevInfo {
            added: "2026-01-01".into(),
            ransomware: true,
        });
        assert!(policy(FailOn::Kev).violated_by(std::slice::from_ref(&f)));
        let mut g = affected("CVE-0000-0002", Severity::Low);
        g.epss = Some(EpssInfo {
            score: 0.5,
            percentile: 0.5,
            date: "2026-01-02".into(),
        });
        let p = Policy {
            fail_on_epss: Some(0.5),
            ..policy(FailOn::None)
        };
        assert!(p.violated_by(std::slice::from_ref(&g)));
        let p = Policy {
            fail_on_epss: Some(0.51),
            ..policy(FailOn::None)
        };
        assert!(!p.violated_by(std::slice::from_ref(&g)));
    }

    #[test]
    fn patched_never_violates() {
        let f = [Finding::new(
            "CVE-0000-0001",
            Severity::Critical,
            Verdict::Patched,
        )];
        let strict = Policy {
            strict: true,
            ..policy(FailOn::Severity(Severity::Low))
        };
        assert!(!strict.violated_by(&f));
    }
}
