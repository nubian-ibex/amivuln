// SPDX-FileCopyrightText: 2026 amivuln contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! A plain-language account of why a finding is reported.
//!
//! It is built only from what the run already holds: the installed version,
//! the version that fixes the CVE, the state the distribution's data gave, how
//! the package was identified, CISA KEV and EPSS, and a vendor mitigation. No
//! model writes it and nothing is sent anywhere; the same finding always gives
//! the same text, so every sentence can be traced to a field.

use amivuln_core::i18n::tr_args;
use amivuln_core::{Finding, Provenance, TargetReport, Verdict};

use crate::sanitize_terminal;

/// The sentences that explain `finding`, in the current language.
#[must_use]
pub fn explain(target: &TargetReport, finding: &Finding) -> Vec<String> {
    let package = sanitize_terminal(&target.package.name);
    let installed = sanitize_terminal(&target.package.version.to_string());
    let mut lines = Vec::new();
    lines.push(match &finding.verdict {
        Verdict::Affected {
            fixed_in: Some(fix),
        } => tr_args(
            "explain.affected_fix",
            &[
                ("package", &package),
                ("installed", &installed),
                ("fixed", &sanitize_terminal(&fix.to_string())),
            ],
        ),
        Verdict::Affected { fixed_in: None } => tr_args(
            "explain.affected_no_fix",
            &[("package", &package), ("installed", &installed)],
        ),
        Verdict::Unverified => tr_args(
            "explain.unverified",
            &[("package", &package), ("installed", &installed)],
        ),
        Verdict::Patched => tr_args(
            "explain.patched",
            &[("package", &package), ("installed", &installed)],
        ),
        Verdict::NotAffected(why) => tr_args(
            "explain.not_affected",
            &[("package", &package), ("why", &sanitize_terminal(why))],
        ),
    });
    match target.package.provenance {
        Provenance::StringHeuristic => lines.push(tr_args("explain.heuristic", &[])),
        Provenance::EmbeddedNote | Provenance::EmbeddedBuildInfo => {
            lines.push(tr_args("explain.embedded", &[]));
        }
        Provenance::PackageDb | Provenance::UserInput => {}
    }
    if let Some(k) = &finding.kev {
        let added = sanitize_terminal(&k.added);
        lines.push(if k.ransomware {
            tr_args("explain.kev_ransomware", &[("added", &added)])
        } else {
            tr_args("explain.kev", &[("added", &added)])
        });
    }
    if let Some(e) = &finding.epss {
        lines.push(tr_args(
            "explain.epss",
            &[
                ("score", &format!("{:.0}", e.score * 100.0)),
                ("percentile", &format!("{:.0}", e.percentile * 100.0)),
            ],
        ));
    }
    if finding.mitigation.is_some() {
        lines.push(tr_args("explain.mitigation", &[]));
    }
    lines
}

#[cfg(test)]
mod tests {
    use amivuln_core::i18n::{Language, set_language};
    use amivuln_core::{EpssInfo, KevInfo, Severity};

    use super::*;
    use crate::text::fixtures::report;

    fn first(r: &amivuln_core::RunReport) -> (&TargetReport, &Finding) {
        let t = &r.targets[0];
        (t, &t.findings[0])
    }

    #[test]
    fn every_sentence_comes_from_a_field_of_the_finding() {
        set_language(Language::English);
        let r = report(true);
        let (t, f) = first(&r);
        let lines = explain(t, f);
        // CVE-0000-0001: affected with a fix, in KEV with ransomware, EPSS 0.91.
        assert!(
            lines[0].contains("nginx") && lines[0].contains("1:1.26.3-1.fc41"),
            "{lines:?}"
        );
        assert!(
            lines
                .iter()
                .any(|l| l.contains("2026-10-30") && l.contains("ransomware"))
        );
        assert!(lines.iter().any(|l| l.contains("91%") && l.contains("99%")));
        assert_eq!(lines.len(), 3, "{lines:?}");
    }

    #[test]
    fn a_finding_with_nothing_extra_gets_one_sentence() {
        set_language(Language::English);
        let r = report(true);
        let t = &r.targets[0];
        let mut plain = t.findings[1].clone();
        plain.kev = None;
        plain.epss = None;
        assert_eq!(explain(t, &plain).len(), 1);
        // No fix published and not verifiable have their own wording.
        let mut open = plain.clone();
        open.verdict = Verdict::Affected { fixed_in: None };
        assert!(explain(t, &open)[0].contains("no fix"));
        open.verdict = Verdict::Unverified;
        assert!(explain(t, &open)[0].contains("not counted"));
        open.verdict = Verdict::NotAffected("not built".to_owned());
        assert!(explain(t, &open)[0].contains("not built"));
        open.verdict = Verdict::Patched;
        assert!(explain(t, &open)[0].contains("already fixed"));
    }

    #[test]
    fn a_weak_identification_and_a_mitigation_are_said() {
        set_language(Language::English);
        let r = report(true);
        let mut t = r.targets[0].clone();
        t.package.provenance = Provenance::StringHeuristic;
        let mut f = t.findings[1].clone();
        f.kev = None;
        f.epss = None;
        f.mitigation = Some(amivuln_core::Mitigation {
            text: "x".to_owned(),
            url: "https://example.invalid".to_owned(),
        });
        let lines = explain(&t, &f);
        assert!(lines.iter().any(|l| l.contains("banner")), "{lines:?}");
        assert!(lines.iter().any(|l| l.contains("mitigation")), "{lines:?}");
        let _ = (
            Severity::Low,
            KevInfo {
                added: String::new(),
                ransomware: false,
            },
            EpssInfo {
                score: 0.0,
                percentile: 0.0,
                date: String::new(),
            },
        );
    }

    #[test]
    fn external_text_cannot_carry_control_characters_into_the_sentence() {
        set_language(Language::English);
        let r = report(true);
        let t = &r.targets[0];
        let mut f = t.findings[1].clone();
        f.verdict = Verdict::NotAffected("bad \u{1b}[31m text".to_owned());
        assert!(!explain(t, &f)[0].contains('\u{1b}'));
    }
}
