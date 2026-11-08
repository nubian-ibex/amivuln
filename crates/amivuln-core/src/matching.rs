// SPDX-FileCopyrightText: 2026 amivuln contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Matching an installed version against distro status.

use core::cmp::Ordering;

use crate::package::Version;

/// Severity, ordered from least to most severe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    /// Severity not provided by any source.
    Unknown,
    /// Low.
    Low,
    /// Medium.
    Medium,
    /// High.
    High,
    /// Critical.
    Critical,
}

/// What the distribution says about one CVE for one package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DistroStatus {
    /// Vulnerable; no fixed version published yet.
    Affected,
    /// Fixed in the given version.
    Fixed(Version),
    /// The distribution states the package is not affected.
    NotAffected(String),
    /// The distribution will not fix it.
    WontFix,
    /// The distribution has no statement.
    Unknown,
}

/// Outcome of matching the installed version against the distro status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// The installed version is vulnerable.
    Affected {
        /// Version that fixes it, when published.
        fixed_in: Option<Version>,
    },
    /// The distribution fixed it at or before the installed version.
    Patched,
    /// The distribution states the package is not affected.
    NotAffected(String),
    /// No distro statement, or versions not comparable: reported separately.
    Unverified,
}

/// Classifies one CVE for the installed version.
///
/// The distro status always decides; upstream version ranges are never
/// consulted here. A `Fixed` version of a different kind than the installed
/// one cannot be compared and yields [`Verdict::Unverified`].
#[must_use]
pub fn classify(installed: &Version, status: &DistroStatus) -> Verdict {
    match status {
        DistroStatus::Affected | DistroStatus::WontFix => Verdict::Affected { fixed_in: None },
        DistroStatus::NotAffected(why) => Verdict::NotAffected(why.clone()),
        DistroStatus::Unknown => Verdict::Unverified,
        DistroStatus::Fixed(fixed) => match installed.compare(fixed) {
            Some(Ordering::Less) => Verdict::Affected {
                fixed_in: Some(fixed.clone()),
            },
            Some(_) => Verdict::Patched,
            None => Verdict::Unverified,
        },
    }
}

/// CISA KEV details for a CVE.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KevInfo {
    /// Date CISA added the CVE, `YYYY-MM-DD`.
    pub added: String,
    /// CISA marks it as used in ransomware campaigns.
    pub ransomware: bool,
}

/// EPSS details for a CVE.
#[derive(Debug, Clone, PartialEq)]
pub struct EpssInfo {
    /// Probability of exploitation in the next 30 days, 0.0 to 1.0.
    pub score: f64,
    /// Percentile among all scored CVEs, 0.0 to 1.0.
    pub percentile: f64,
    /// Date of the score, `YYYY-MM-DD`.
    pub date: String,
}

/// A reportable CVE for a target.
#[derive(Debug, Clone, PartialEq)]
pub struct Finding {
    /// CVE or GHSA identifier.
    pub id: String,
    /// Severity.
    pub severity: Severity,
    /// Matching outcome.
    pub verdict: Verdict,
    /// Present when the CVE is in the CISA KEV catalog.
    pub kev: Option<KevInfo>,
    /// Present when EPSS has a score.
    pub epss: Option<EpssInfo>,
}

impl Finding {
    /// A finding without enrichment.
    #[must_use]
    pub fn new(id: impl Into<String>, severity: Severity, verdict: Verdict) -> Self {
        Self {
            id: id.into(),
            severity,
            verdict,
            kev: None,
            epss: None,
        }
    }
}

/// Sorts findings by severity descending, then id ascending (deterministic output).
pub fn sort_findings(findings: &mut [Finding]) {
    findings.sort_by(|a, b| b.severity.cmp(&a.severity).then_with(|| a.id.cmp(&b.id)));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rpm(s: &str) -> Version {
        Version::Rpm(s.parse().unwrap_or_else(|n| match n {}))
    }

    #[test]
    fn fixed_at_or_before_installed_is_patched() {
        let status = DistroStatus::Fixed(rpm("1:1.26.3-1.fc41"));
        assert_eq!(classify(&rpm("1:1.26.3-1.fc41"), &status), Verdict::Patched);
        assert_eq!(classify(&rpm("1:1.27.0-1.fc41"), &status), Verdict::Patched);
    }

    #[test]
    fn installed_older_than_fix_is_affected() {
        let status = DistroStatus::Fixed(rpm("1:1.26.3-1.fc41"));
        assert_eq!(
            classify(&rpm("1:1.26.2-1.fc41"), &status),
            Verdict::Affected {
                fixed_in: Some(rpm("1:1.26.3-1.fc41"))
            }
        );
    }

    #[test]
    fn backport_is_not_reported_when_distro_says_fixed() {
        // Upstream would call 2.4.57 vulnerable (< 2.4.58); the distro
        // backported the fix into release 3, which must win.
        let status = DistroStatus::Fixed(rpm("2.4.57-3.fc41"));
        assert_eq!(classify(&rpm("2.4.57-3.fc41"), &status), Verdict::Patched);
    }

    #[test]
    fn unknown_is_never_affected() {
        assert_eq!(
            classify(&rpm("1.0-1"), &DistroStatus::Unknown),
            Verdict::Unverified
        );
    }

    #[test]
    fn mismatched_kinds_are_unverified() {
        let pac = Version::Pacman("2.0-1".parse().unwrap_or_else(|n| match n {}));
        assert_eq!(
            classify(&rpm("1.0-1"), &DistroStatus::Fixed(pac)),
            Verdict::Unverified
        );
    }

    #[test]
    fn not_affected_and_wontfix() {
        assert_eq!(
            classify(
                &rpm("1.0-1"),
                &DistroStatus::NotAffected("vulnerable code not present".into())
            ),
            Verdict::NotAffected("vulnerable code not present".into())
        );
        assert_eq!(
            classify(&rpm("1.0-1"), &DistroStatus::WontFix),
            Verdict::Affected { fixed_in: None }
        );
    }

    #[test]
    fn sorting_is_severity_desc_then_id_asc() {
        let f = |id: &str, severity| Finding::new(id, severity, Verdict::Unverified);
        let mut v = vec![
            f("CVE-2", Severity::Low),
            f("CVE-9", Severity::Critical),
            f("CVE-1", Severity::Critical),
            f("CVE-5", Severity::High),
        ];
        sort_findings(&mut v);
        let ids: Vec<&str> = v.iter().map(|x| x.id.as_str()).collect();
        assert_eq!(ids, ["CVE-1", "CVE-9", "CVE-5", "CVE-2"]);
    }
}
