// SPDX-FileCopyrightText: 2026 amivuln contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Accepted findings: `.amivuln-ignore.toml`.
//!
//! An entry states that a finding is known and accepted, with a reason, an
//! owner and an expiry. An expired entry is an error, not a silent pass, and a
//! suppressed finding is still listed in the output with the reason.

use core::str::FromStr;
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::matching::Finding;

/// One accepted finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IgnoreEntry {
    /// CVE or update id.
    pub id: String,
    /// Restrict to one package name, when given.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub package: Option<String>,
    /// Why this is accepted; shown in the output.
    pub reason: String,
    /// Who to ask; required so entries have a face.
    pub owner: String,
    /// Expiry, `YYYY-MM-DD`. An expired entry fails the run.
    pub expires: String,
}

impl IgnoreEntry {
    /// True at the given UTC date (`YYYY-MM-DD`). The expiry day itself still
    /// counts: a fix agreed "until December" is valid through December 31.
    #[must_use]
    pub fn active_on(&self, today: &str) -> bool {
        self.expires.as_str() >= today
    }
}

/// A malformed ignore file.
#[derive(Debug, thiserror::Error)]
pub enum IgnoreError {
    /// The file is not the expected TOML shape.
    #[error("ignore file is not valid: {0}")]
    Parse(String),
    /// An entry's expiry is in the past (or malformed).
    #[error("ignore entry {id}: {problem}")]
    Expired {
        /// The entry id.
        id: String,
        /// What is wrong.
        problem: String,
    },
}

/// Parses the ignore file.
///
/// # Errors
///
/// [`IgnoreError::Parse`] for a malformed file, [`IgnoreError::Expired`] for
/// an expired or malformed expiry.
pub fn parse_ignore(text: &str) -> Result<Vec<IgnoreEntry>, IgnoreError> {
    #[derive(Deserialize)]
    struct File {
        #[serde(default, rename = "ignore")]
        entries: Vec<IgnoreEntry>,
    }
    let file: File =
        toml::from_str(text).map_err(|e| IgnoreError::Parse(e.message().to_owned()))?;
    for e in &file.entries {
        let ok = e.expires.len() == 10
            && e.expires.as_bytes().get(4) == Some(&b'-')
            && e.expires.as_bytes().get(7) == Some(&b'-')
            && e.expires
                .bytes()
                .enumerate()
                .all(|(i, b)| matches!(i, 4 | 7) || b.is_ascii_digit());
        if !ok {
            return Err(IgnoreError::Expired {
                id: e.id.clone(),
                problem: format!("expires {:?} is not YYYY-MM-DD", e.expires),
            });
        }
    }
    Ok(file.entries)
}

/// Marks the findings accepted by `entries` at `today`.
///
/// The finding itself is untouched (it is still reported); the caller decides
/// how to present and count it. Entries match by id, case-insensitively.
#[must_use]
pub fn suppress(
    findings: &[Finding],
    entries: &[IgnoreEntry],
    today: &str,
) -> BTreeMap<String, String> {
    let mut applied = BTreeMap::new();
    for f in findings {
        if let Some(best) = entries
            .iter()
            .filter(|e| e.id.eq_ignore_ascii_case(&f.id))
            .filter(|e| e.active_on(today))
            .max_by_key(|e| e.expires.clone())
        {
            applied.insert(f.id.clone(), best.reason.clone());
        }
    }
    applied
}

impl FromStr for IgnoreEntry {
    type Err = IgnoreError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let entries = parse_ignore(s)?;
        entries
            .into_iter()
            .next()
            .ok_or_else(|| IgnoreError::Parse("no [[ignore]] entry in the input".to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::matching::{Severity, Verdict};

    fn f(id: &str) -> Finding {
        Finding::new(id, Severity::High, Verdict::Affected { fixed_in: None })
    }

    const SAMPLE: &str = "\
[[ignore]]
id = \"CVE-2024-6387\"
package = \"openssh-server\"
reason = \"LoginGraceTime 0 applied via Ansible (INFRA-123)\"
owner = \"sre@example.com\"
expires = \"2026-12-31\"
";

    #[derive(Deserialize, Serialize)]
    struct File {
        #[serde(default, rename = "ignore")]
        entries: Vec<IgnoreEntry>,
    }

    #[test]
    fn parses_the_documented_shape() {
        let e = parse_ignore(SAMPLE).unwrap();
        assert_eq!(e.len(), 1);
        assert_eq!(e[0].id, "CVE-2024-6387");
        assert_eq!(e[0].package.as_deref(), Some("openssh-server"));
        assert!(e[0].active_on("2026-12-31"));
        assert!(e[0].active_on("2026-01-01"));
        assert!(!e[0].active_on("2027-01-01"));
    }

    #[test]
    fn round_trips_through_toml() {
        let parsed: File = toml::from_str(SAMPLE).unwrap();
        assert_eq!(parsed.entries, parse_ignore(SAMPLE).unwrap());
        let text = toml::to_string(&parsed).unwrap();
        assert!(text.contains("[[ignore]]"), "{text}");
        assert_eq!(parse_ignore(&text).unwrap(), parsed.entries);
    }

    #[test]
    fn bad_files_and_dates() {
        // An array under another key is simply an empty set of entries.
        assert!(parse_ignore("ignore = []").unwrap().is_empty());
        assert!(
            parse_ignore("[[ignore]]\nid = \"CVE-1\"").is_err(),
            "missing fields"
        );
        let e = parse_ignore(
            "[[ignore]]\nid = \"CVE-2024-6387\"\nreason = \"x\"\nowner = \"a@b\"\nexpires = \"soon\"",
        )
        .unwrap_err();
        assert!(matches!(e, IgnoreError::Expired { .. }), "{e}");
        assert!(matches!(
            parse_ignore("not toml"),
            Err(IgnoreError::Parse(_))
        ));
    }

    #[test]
    fn suppression_applies_and_expires() {
        let entries = parse_ignore(SAMPLE).unwrap();
        let findings = vec![f("CVE-2024-6387"), f("CVE-2024-0001")];
        let applied = suppress(&findings, &entries, "2026-06-01");
        assert_eq!(applied.keys().collect::<Vec<_>>(), ["CVE-2024-6387"]);
        assert!(applied["CVE-2024-6387"].contains("Ansible"));
        assert!(!applied.contains_key("CVE-2024-0001"));
        let applied = suppress(&findings, &entries, "2027-01-01");
        assert!(applied.is_empty(), "expired entries stop suppressing");
    }
}
