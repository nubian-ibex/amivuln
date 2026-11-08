// SPDX-FileCopyrightText: 2026 amivuln contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! The A to F score of a set of findings.
//!
//! The formula is deliberately simple, deterministic and documented so two
//! runs on the same data always agree and the number can be explained.
//!
//! Each distinct finding id counts once, at its highest points, however many
//! packages carry it: ten subpackages built from one source are one problem
//! with one fix.
//!
//! Points per *affected* finding (unverified findings are not scored):
//! critical 10, high 5, medium 2, low or unknown 1. A finding in the CISA KEV
//! catalog adds 10, and 5 more when it is used in ransomware campaigns. An
//! EPSS score of at least 0.5 adds 3.
//!
//! Grade by total points: 0 is A, 1 to 9 B, 10 to 29 C, 30 to 59 D, 60 to 99 E,
//! 100 or more F. Any exploited (KEV) finding caps the grade at D, because an
//! actively exploited vulnerability is not a "mostly fine" system whatever
//! the total.

use crate::matching::{Finding, Severity, Verdict};

/// Letter grade.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Grade {
    /// Nothing affected.
    A,
    /// A few minor findings.
    B,
    /// Some findings.
    C,
    /// Many findings, or something exploited.
    D,
    /// Serious.
    E,
    /// Severe.
    F,
}

impl Grade {
    /// The letter.
    #[must_use]
    pub fn letter(self) -> char {
        match self {
            Self::A => 'A',
            Self::B => 'B',
            Self::C => 'C',
            Self::D => 'D',
            Self::E => 'E',
            Self::F => 'F',
        }
    }
}

/// Points and grade.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Score {
    /// Total points.
    pub points: u32,
    /// Grade derived from the points and the KEV cap.
    pub grade: Grade,
}

fn finding_points(f: &Finding) -> u32 {
    let base = match f.severity {
        Severity::Critical => 10,
        Severity::High => 5,
        Severity::Medium => 2,
        Severity::Low | Severity::Unknown => 1,
    };
    let kev = f
        .kev
        .as_ref()
        .map_or(0, |k| if k.ransomware { 15 } else { 10 });
    let epss = f.epss.as_ref().map_or(0, |e| u32::from(e.score >= 0.5) * 3);
    base + kev + epss
}

/// Scores the affected findings.
#[must_use]
pub fn score(findings: &[Finding]) -> Score {
    let affected: Vec<&Finding> = findings
        .iter()
        .filter(|f| matches!(f.verdict, Verdict::Affected { .. }))
        .collect();
    let mut per_id: std::collections::BTreeMap<&str, u32> = std::collections::BTreeMap::new();
    for f in &affected {
        let slot = per_id.entry(f.id.as_str()).or_insert(0);
        *slot = (*slot).max(finding_points(f));
    }
    let points = per_id.values().copied().fold(0_u32, u32::saturating_add);
    let by_points = match points {
        0 => Grade::A,
        1..=9 => Grade::B,
        10..=29 => Grade::C,
        30..=59 => Grade::D,
        60..=99 => Grade::E,
        _ => Grade::F,
    };
    let grade = if affected.iter().any(|f| f.kev.is_some()) {
        by_points.max(Grade::D)
    } else {
        by_points
    };
    Score { points, grade }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::matching::{EpssInfo, KevInfo};

    fn aff(sev: Severity) -> Finding {
        Finding::new("CVE-0000-0001", sev, Verdict::Affected { fixed_in: None })
    }

    /// `n` findings with distinct ids.
    fn many(sev: Severity, n: usize) -> Vec<Finding> {
        (0..n)
            .map(|i| {
                Finding::new(
                    format!("CVE-0000-{i:04}"),
                    sev,
                    Verdict::Affected { fixed_in: None },
                )
            })
            .collect()
    }

    #[test]
    fn nothing_is_an_a_and_unverified_is_not_scored() {
        assert_eq!(
            score(&[]),
            Score {
                points: 0,
                grade: Grade::A
            }
        );
        let unverified = Finding::new("CVE-0000-0002", Severity::Critical, Verdict::Unverified);
        assert_eq!(score(&[unverified]).grade, Grade::A);
        let patched = Finding::new("CVE-0000-0003", Severity::Critical, Verdict::Patched);
        assert_eq!(score(&[patched]).points, 0);
    }

    #[test]
    fn severity_points_and_grade_boundaries() {
        assert_eq!(
            score(&[aff(Severity::Low)]),
            Score {
                points: 1,
                grade: Grade::B
            }
        );
        let mut nine = many(Severity::Medium, 2);
        nine.push(Finding::new(
            "CVE-1111-0001",
            Severity::High,
            Verdict::Affected { fixed_in: None },
        ));
        assert_eq!(
            score(&nine),
            Score {
                points: 9,
                grade: Grade::B
            }
        );
        let ten = vec![aff(Severity::Critical)];
        assert_eq!(
            score(&ten),
            Score {
                points: 10,
                grade: Grade::C
            }
        );
        assert_eq!(score(&many(Severity::Critical, 3)).grade, Grade::D);
        assert_eq!(score(&many(Severity::Critical, 6)).grade, Grade::E);
        assert_eq!(score(&many(Severity::Critical, 10)).grade, Grade::F);
    }

    #[test]
    fn kev_adds_points_and_caps_at_d() {
        let mut f = aff(Severity::Low);
        f.kev = Some(KevInfo {
            added: "2026-01-01".into(),
            ransomware: false,
        });
        assert_eq!(
            score(&[f.clone()]),
            Score {
                points: 11,
                grade: Grade::D
            }
        );
        f.kev = Some(KevInfo {
            added: "2026-01-01".into(),
            ransomware: true,
        });
        assert_eq!(score(&[f]).points, 16);
        // Already worse than D: the cap does not improve it.
        let mut big = many(Severity::Critical, 10);
        big[0].kev = Some(KevInfo {
            added: "2026-01-01".into(),
            ransomware: false,
        });
        assert_eq!(score(&big).grade, Grade::F);
    }

    #[test]
    fn the_same_finding_on_many_packages_counts_once() {
        let one = vec![aff(Severity::High)];
        let copies = vec![aff(Severity::High); 10];
        assert_eq!(score(&one), score(&copies));
        let mut other = aff(Severity::Low);
        other.id = "CVE-0000-0002".into();
        assert_eq!(score(&[aff(Severity::High), other]).points, 6);
    }

    #[test]
    fn epss_adds_three_from_half() {
        let mut f = aff(Severity::Low);
        f.epss = Some(EpssInfo {
            score: 0.49,
            percentile: 0.9,
            date: "d".into(),
        });
        assert_eq!(score(&[f.clone()]).points, 1);
        f.epss = Some(EpssInfo {
            score: 0.5,
            percentile: 0.9,
            date: "d".into(),
        });
        assert_eq!(score(&[f]).points, 4);
    }

    #[test]
    fn letters_and_order() {
        assert_eq!(Grade::A.letter(), 'A');
        assert_eq!(Grade::F.letter(), 'F');
        assert!(Grade::F > Grade::A);
    }
}
