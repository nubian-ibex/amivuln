// SPDX-FileCopyrightText: 2026 amivuln contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Arch Linux Security Tracker (ADR-0008).
//!
//! Source: `https://security.archlinux.org/issues/all.json`, a JSON array of
//! AVG groups. Each group lists affected pacman packages, the CVEs it covers,
//! the first affected version and, when published, the fixed version.

use crate::is_cve_id;
use amivuln_core::{DistroStatus, Severity, Version};
use serde::Deserialize;

/// Upper bound for a tracker response; the file was about 0.9 MB in 2026-11.
pub const MAX_RESPONSE_BYTES: usize = 32 * 1024 * 1024;

/// Errors while reading the tracker response.
#[derive(Debug, thiserror::Error)]
pub enum ArchError {
    /// The response exceeds [`MAX_RESPONSE_BYTES`].
    #[error("arch tracker response is {0} bytes, above the {MAX_RESPONSE_BYTES} byte limit")]
    TooLarge(usize),
    /// The response is not the expected JSON array.
    #[error("arch tracker response is not valid JSON of the expected shape: {0}")]
    Invalid(#[from] serde_json::Error),
}

#[derive(Debug, Deserialize)]
struct RawGroup {
    name: String,
    packages: Vec<String>,
    status: String,
    severity: String,
    #[serde(default)]
    affected: Option<String>,
    #[serde(default)]
    fixed: Option<String>,
    issues: Vec<String>,
}

/// One CVE status for one package, as stated by the tracker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchEntry {
    /// AVG group identifier, for example `AVG-2907`.
    pub avg: String,
    /// CVE identifier.
    pub cve: String,
    /// Severity assigned by the tracker.
    pub severity: Severity,
    /// What the tracker says about this package.
    pub status: DistroStatus,
    /// First affected version. Installed versions older than this are not
    /// covered by the group and must not be reported for it.
    pub affected_since: Option<Version>,
}

/// Parsed tracker data, queryable by package name.
#[derive(Debug, Default)]
pub struct ArchTracker {
    groups: Vec<RawGroup>,
}

fn severity(s: &str) -> Severity {
    match s {
        "Critical" => Severity::Critical,
        "High" => Severity::High,
        "Medium" => Severity::Medium,
        "Low" => Severity::Low,
        _ => Severity::Unknown,
    }
}

fn status(group: &RawGroup) -> DistroStatus {
    match group.status.as_str() {
        "Fixed" => match group.fixed.as_deref().map(str::parse) {
            Some(Ok(v)) => DistroStatus::Fixed(Version::Pacman(v)),
            // "Fixed" without a version cannot be compared: do not guess.
            _ => DistroStatus::Unknown,
        },
        "Vulnerable" => DistroStatus::Affected,
        "Not affected" => DistroStatus::NotAffected("Arch Security Tracker: not affected".into()),
        _ => DistroStatus::Unknown,
    }
}

impl ArchTracker {
    /// Parses a tracker response.
    ///
    /// # Errors
    ///
    /// Fails when the input exceeds [`MAX_RESPONSE_BYTES`] or is not the
    /// expected JSON array.
    pub fn parse(bytes: &[u8]) -> Result<Self, ArchError> {
        if bytes.len() > MAX_RESPONSE_BYTES {
            return Err(ArchError::TooLarge(bytes.len()));
        }
        Ok(Self {
            groups: serde_json::from_slice(bytes)?,
        })
    }

    /// Number of AVG groups loaded.
    #[must_use]
    pub fn len(&self) -> usize {
        self.groups.len()
    }

    /// True when no group was loaded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.groups.is_empty()
    }

    /// All CVE statuses recorded for a pacman package, sorted by CVE then AVG.
    ///
    /// A CVE can appear in several groups; every statement is returned so the
    /// caller can apply its own precedence.
    #[must_use]
    pub fn entries_for(&self, package: &str) -> Vec<ArchEntry> {
        let mut out: Vec<ArchEntry> = self
            .groups
            .iter()
            .filter(|g| g.packages.iter().any(|p| p == package))
            .flat_map(|g| {
                let sev = severity(&g.severity);
                let st = status(g);
                let since = g
                    .affected
                    .as_deref()
                    .and_then(|v| v.parse().ok())
                    .map(Version::Pacman);
                g.issues
                    .iter()
                    .filter(|cve| is_cve_id(cve))
                    .map(move |cve| ArchEntry {
                        avg: g.name.clone(),
                        cve: cve.clone(),
                        severity: sev,
                        status: st.clone(),
                        affected_since: since.clone(),
                    })
            })
            .collect();
        out.sort_by(|a, b| a.cve.cmp(&b.cve).then_with(|| a.avg.cmp(&b.avg)));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::is_cve_id;
    use amivuln_core::{Verdict, classify};

    const FIXTURE: &[u8] =
        include_bytes!("../../../tests/fixtures/http/arch-tracker/2026-11-07/all.json");

    fn pac(s: &str) -> Version {
        Version::Pacman(s.parse().unwrap_or_else(|n| match n {}))
    }

    #[test]
    fn parses_recorded_fixture() {
        let t = ArchTracker::parse(FIXTURE).unwrap();
        assert_eq!(t.len(), 5);
        assert!(!t.is_empty());
    }

    #[test]
    fn fixed_group_classifies_by_version() {
        let t = ArchTracker::parse(FIXTURE).unwrap();
        let e = t.entries_for("djvulibre");
        assert_eq!(e.len(), 1);
        assert_eq!(e[0].cve, "CVE-2025-53367");
        assert_eq!(e[0].severity, Severity::High);
        assert_eq!(e[0].status, DistroStatus::Fixed(pac("3.5.30-1")));
        assert!(matches!(
            classify(&pac("3.5.28-6"), &e[0].status),
            Verdict::Affected { .. }
        ));
        assert_eq!(classify(&pac("3.5.30-1"), &e[0].status), Verdict::Patched);
    }

    #[test]
    fn multi_package_group_applies_to_each_package() {
        let t = ArchTracker::parse(FIXTURE).unwrap();
        for p in ["poppler", "poppler-glib", "poppler-qt5", "poppler-qt6"] {
            let e = t.entries_for(p);
            assert_eq!(e.len(), 2, "{p}");
            assert_eq!(e[0].cve, "CVE-2022-27337");
        }
    }

    #[test]
    fn vulnerable_without_fix_is_affected() {
        let t = ArchTracker::parse(FIXTURE).unwrap();
        let e = t.entries_for("pam");
        assert_eq!(e[0].status, DistroStatus::Affected);
    }

    #[test]
    fn not_affected_and_unknown_are_preserved() {
        let t = ArchTracker::parse(FIXTURE).unwrap();
        assert!(matches!(
            t.entries_for("gnome-remote-desktop")[0].status,
            DistroStatus::NotAffected(_)
        ));
        let e = t.entries_for("vim");
        assert!(e.iter().all(|x| x.status == DistroStatus::Unknown));
        assert_eq!(classify(&pac("1-1"), &e[0].status), Verdict::Unverified);
    }

    #[test]
    fn affected_since_is_kept() {
        let t = ArchTracker::parse(FIXTURE).unwrap();
        let e = t.entries_for("djvulibre");
        assert_eq!(e[0].affected_since, Some(pac("3.5.28-6")));
    }

    #[test]
    fn unknown_package_has_no_entries() {
        let t = ArchTracker::parse(FIXTURE).unwrap();
        assert!(t.entries_for("nonexistent").is_empty());
    }

    #[test]
    fn rejects_invalid_and_oversized_input() {
        assert!(matches!(
            ArchTracker::parse(b"{}"),
            Err(ArchError::Invalid(_))
        ));
        assert!(matches!(
            ArchTracker::parse(b"[{"),
            Err(ArchError::Invalid(_))
        ));
        assert!(matches!(
            ArchTracker::parse(&[0xff, 0xfe]),
            Err(ArchError::Invalid(_))
        ));
        let big = vec![b' '; MAX_RESPONSE_BYTES + 1];
        assert!(matches!(
            ArchTracker::parse(&big),
            Err(ArchError::TooLarge(_))
        ));
    }

    #[test]
    fn deeply_nested_json_is_rejected_not_overflowed() {
        let mut deep = vec![b'['; 100_000];
        deep.extend(vec![b']'; 100_000]);
        assert!(ArchTracker::parse(&deep).is_err());
    }

    #[test]
    fn fixed_without_version_and_bad_ids_are_safe() {
        let json = br#"[{"name":"AVG-1","packages":["pkg"],"status":"Fixed","severity":"Weird",
            "affected":"1","fixed":null,"ticket":null,"type":"x","advisories":[],
            "issues":["CVE-0000-0001","\u001b[31mCVE-0000-0002","CVE-0000-0003 ; rm"]}]"#;
        let e = ArchTracker::parse(json).unwrap().entries_for("pkg");
        assert_eq!(e.len(), 1);
        assert_eq!(e[0].cve, "CVE-0000-0001");
        assert_eq!(e[0].status, DistroStatus::Unknown);
        assert_eq!(e[0].severity, Severity::Unknown);
    }

    #[test]
    fn cve_id_validation() {
        assert!(is_cve_id("CVE-2025-53367"));
        assert!(is_cve_id("CVE-2021-1234567"));
        assert!(!is_cve_id("CVE-25-1234"));
        assert!(!is_cve_id("CVE-2025-12"));
        assert!(!is_cve_id("GHSA-xxxx"));
        assert!(!is_cve_id("CVE-2025-1234a"));
    }
}
