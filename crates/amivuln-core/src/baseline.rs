// SPDX-FileCopyrightText: 2026 amivuln contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Regression baselines (`--baseline FILE`).
//!
//! A baseline is a previous `amivuln -f json` document. A run compared against
//! one reports only what is **new**: findings for targets that were clean, or
//! findings absent from the baseline. Everything already present in the
//! baseline is old and does not violate policy, so a CI gate stays green until
//! something new appears.

use serde::Deserialize;

use crate::matching::Verdict;
use crate::report::TargetReport;

/// A baseline document (the `targets` part of a run report).
#[derive(Debug, Default, Clone, PartialEq)]
pub struct Baseline {
    /// Affected finding ids per target input.
    pub affected: std::collections::BTreeMap<String, Vec<String>>,
}

/// A baseline problem.
#[derive(Debug, thiserror::Error)]
pub enum BaselineError {
    /// The file is not a run report JSON.
    #[error("baseline is not valid: {0}")]
    Invalid(String),
    /// The baseline was produced by another schema version.
    #[error(
        "baseline schema_version {0} is not supported; regenerate the baseline with this amivuln"
    )]
    Schema(u64),
}

/// Loads a baseline from a run-report document.
///
/// Only `targets[].findings[].id` entries in the `affected` state count:
/// unverified findings are not part of a gate.
///
/// # Errors
///
/// [`BaselineError::Invalid`] for malformed JSON and
/// [`BaselineError::Schema`] for a different `schema_version`.
pub fn parse_baseline(bytes: &[u8]) -> Result<Baseline, BaselineError> {
    #[derive(Deserialize)]
    struct Doc {
        schema_version: u64,
        #[serde(default)]
        targets: Vec<RawTarget>,
    }
    #[derive(Deserialize)]
    struct RawTarget {
        input: String,
        #[serde(default)]
        findings: Vec<IdOnly>,
    }
    #[derive(Deserialize)]
    struct IdOnly {
        id: String,
        #[serde(default)]
        unverified: Option<String>,
    }
    let doc: Doc =
        serde_json::from_slice(bytes).map_err(|e| BaselineError::Invalid(e.to_string()))?;
    if doc.schema_version != amivuln_report_schema() {
        return Err(BaselineError::Schema(doc.schema_version));
    }
    let mut affected = std::collections::BTreeMap::new();
    for t in doc.targets {
        let ids: Vec<String> = t
            .findings
            .iter()
            .filter(|f| f.unverified.is_none())
            .map(|f| f.id.clone())
            .collect();
        if !ids.is_empty() {
            affected.insert(t.input, ids);
        }
    }
    Ok(Baseline { affected })
}

/// The schema version the report crate produces, as data (no crate cycle).
fn amivuln_report_schema() -> u64 {
    1
}

impl Baseline {
    /// Findings that are new compared to this baseline, keyed by target input.
    ///
    /// A target that did not exist in the baseline counts entirely as new. An
    /// id that moved to *unverified* or disappeared is not reported (a fix
    /// landed; the gate only blocks new problems).
    #[must_use]
    pub fn new_findings(
        &self,
        targets: &[TargetReport],
    ) -> std::collections::BTreeMap<String, Vec<String>> {
        let mut out = std::collections::BTreeMap::new();
        for t in targets {
            let mut new = Vec::new();
            for f in &t.findings {
                if !matches!(f.verdict, Verdict::Affected { .. }) {
                    continue;
                }
                let known = self
                    .affected
                    .get(&t.input)
                    .or_else(|| self.affected.get(&t.package.name))
                    .is_some_and(|ids| ids.iter().any(|id| id.eq_ignore_ascii_case(&f.id)));
                if !known {
                    new.push(f.id.clone());
                }
            }
            if !new.is_empty() {
                out.insert(t.input.clone(), new);
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::matching::{Finding, Severity};
    use crate::package::{Ecosystem, PackageRef, Provenance, Version};

    fn target(input: &str, name: &str, findings: Vec<Finding>) -> TargetReport {
        TargetReport {
            input: input.to_owned(),
            package: PackageRef {
                ecosystem: Ecosystem::Fedora(44),
                name: name.to_owned(),
                source_name: None,
                version: Version::Rpm("1.0-1".parse().unwrap_or_else(|n| match n {})),
                arch: None,
                provenance: Provenance::PackageDb,
            },
            findings,
            resolved: Vec::new(),
        }
    }

    fn aff(id: &str) -> Finding {
        Finding::new(id, Severity::High, Verdict::Affected { fixed_in: None })
    }

    fn aff_unverified(id: &str) -> Finding {
        Finding::new(id, Severity::High, Verdict::Unverified)
    }

    const BASELINE_JSON: &str = r#"{
        "schema_version": 1,
        "targets": [{
            "input": "nginx",
            "package": {"name": "nginx", "version": "1", "arch": null, "ecosystem": "fedora", "purl": "pkg:rpm/fedora/nginx@1", "provenance": "package_db"},
            "summary": {"critical": 1, "high": 0, "medium": 0, "low": 0, "kev": 0, "epss_max": null, "unverified": 0},
            "findings": [{"id": "CVE-2026-0001", "severity": "critical", "distro_status": {"state": "affected", "fixed_in": null}, "kev": null, "epss": null}],
            "unverified": []
        }],
        "unresolved": []
    }"#;

    #[test]
    fn parses_a_run_report_and_ignores_other_fields() {
        let b = parse_baseline(BASELINE_JSON.as_bytes()).unwrap();
        assert_eq!(b.affected.keys().collect::<Vec<_>>(), ["nginx"]);
        assert_eq!(b.affected["nginx"], ["CVE-2026-0001"]);
    }

    #[test]
    fn rejects_malformed_and_wrong_schema() {
        assert!(matches!(
            parse_baseline(b"{"),
            Err(BaselineError::Invalid(_))
        ));
        let bad = BASELINE_JSON.replace("\"schema_version\": 1", "\"schema_version\": 9");
        assert!(matches!(
            parse_baseline(bad.as_bytes()),
            Err(BaselineError::Schema(9))
        ));
    }

    #[test]
    fn only_new_findings_violate() {
        let b = parse_baseline(BASELINE_JSON.as_bytes()).unwrap();
        // Same CVE: old. Plus an unverified one: never a gate.
        let now = vec![aff("CVE-2026-0001"), aff_unverified("CVE-2026-0002")];
        assert!(b.new_findings(&[target("nginx", "nginx", now)]).is_empty());
        // A new CVE: the gate fires.
        let worse = vec![aff("CVE-2026-0001"), aff("CVE-2026-0003")];
        let new = b.new_findings(&[target("nginx", "nginx", worse)]);
        assert_eq!(new["nginx"], ["CVE-2026-0003"]);
        // The CVE disappeared (fix landed): not reported.
        assert!(
            b.new_findings(&[target("nginx", "nginx", vec![])])
                .is_empty()
        );
        // A brand-new target is all new.
        let new = b.new_findings(&[target("curl", "curl", vec![aff("CVE-2026-0004")])]);
        assert_eq!(new["curl"], ["CVE-2026-0004"]);
        // Matching falls back to the package name when the input differs.
        let new = b.new_findings(&[target("nginx.service", "nginx", vec![aff("CVE-2026-0001")])]);
        assert!(new.is_empty());
    }
}
