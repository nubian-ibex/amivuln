// SPDX-FileCopyrightText: 2026 amivuln contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! `OpenVEX` statements (`--vex FILE`).
//!
//! A VEX document states, with an authority, that a product is not affected by
//! a vulnerability. The statement is matched by CVE id only: the product purl
//! identifies the package, but the verdict applies to the CVE as a whole. `not_affected` is respected as a statement (with its
//! justification shown); the other statuses change nothing, because the
//! distribution data already decides affected/patched.

use serde::Deserialize;

use crate::matching::Verdict;

/// One VEX statement relevant to amivuln.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VexStatement {
    /// CVE or GHSA id the statement is about.
    pub id: String,
    /// Who asserted it (shown in the output).
    pub author: String,
    /// Justification for a `not_affected`.
    pub justification: Option<String>,
}

#[derive(Deserialize)]
struct RawDoc {
    #[serde(default)]
    author: String,
    #[serde(default)]
    statements: Vec<RawStatement>,
}

#[derive(Deserialize)]
struct RawStatement {
    status: String,
    #[serde(default)]
    vulnerability_id: Option<String>,
    products: Vec<RawProduct>,
    #[serde(default)]
    justification: Option<String>,
}

#[derive(Deserialize)]
struct RawProduct {
    #[serde(rename = "@id")]
    id: String,
}

/// Parses an `OpenVEX` document, keeping only `not_affected` statements whose
/// product is a purl (so it can be matched to a package name).
///
/// # Errors
///
/// Fails on malformed JSON. Statements with an unknown status, no id or a
/// non-purl product are skipped, not errors.
pub fn parse_vex(bytes: &[u8]) -> Result<Vec<VexStatement>, String> {
    if !bytes.starts_with(b"{") {
        return Err("a VEX document is a JSON object, not an array".to_owned());
    }
    let doc: RawDoc =
        serde_json::from_slice(bytes).map_err(|e| format!("VEX document is not valid: {e}"))?;
    let mut out = Vec::new();
    for st in doc.statements {
        if st.status != "not_affected" {
            continue;
        }
        let Some(id) = st.vulnerability_id else {
            continue;
        };
        for p in st.products {
            let Some(purl) = p.id.strip_prefix("pkg:") else {
                // A bare product name cannot be matched to a distro statement.
                continue;
            };
            let _ = purl.rsplit_once('@');
            out.push(VexStatement {
                id: id.clone(),
                author: doc.author.clone(),
                justification: st.justification.clone(),
            });
        }
    }
    Ok(out)
}

/// Applies VEX statements to one verdict.
///
/// A matching `not_affected` wins over everything and carries the author and
/// justification into the verdict text, so the output shows who claimed it.
pub fn apply_vex(verdict: &mut Verdict, statements: &[VexStatement], cve: &str) {
    for st in statements {
        if !st.id.eq_ignore_ascii_case(cve) {
            continue;
        }
        *verdict = Verdict::NotAffected(match &st.justification {
            Some(j) => format!("VEX by {}: {j}", st.author),
            None => format!("VEX by {}: not affected", st.author),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::matching::Finding;
    use crate::package::Version;

    const DOC: &str = r#"{
        "@context": "https://openvex.dev/ns/v0.2.0",
        "author": "Vendor Security Team",
        "statements": [{
            "status": "not_affected",
            "vulnerability_id": "CVE-2026-0001",
            "justification": "vulnerable code not present",
            "products": [{"@id": "pkg:rpm/fedora/nginx@1.26.2-1.fc41"}]
        }, {
            "status": "under_investigation",
            "vulnerability_id": "CVE-2026-0002",
            "products": [{"@id": "pkg:rpm/fedora/nginx@1.26.2-1.fc41"}]
        }, {
            "status": "affected",
            "vulnerability_id": "CVE-2026-0003",
            "products": [{"@id": "pkg:rpm/fedora/nginx@1.26.2-1.fc41"}]
        }, {
            "status": "not_affected",
            "vulnerability_id": "CVE-2026-0004",
            "products": [{"@id": "nginx"}]
        }]
    }"#;

    #[test]
    fn parses_not_affected_with_justification() {
        let st = parse_vex(DOC.as_bytes()).unwrap();
        assert_eq!(st.len(), 1);
        assert_eq!(st[0].id, "CVE-2026-0001");
        assert_eq!(st[0].author, "Vendor Security Team");
        assert_eq!(
            st[0].justification.as_deref(),
            Some("vulnerable code not present")
        );
    }

    #[test]
    fn not_affected_wins_over_affected() {
        let st = parse_vex(DOC.as_bytes()).unwrap();
        let mut v = Verdict::Affected {
            fixed_in: Some(Version::Rpm(
                "9.9-1".parse().unwrap_or_else(|never| match never {}),
            )),
        };
        apply_vex(&mut v, &st, "CVE-2026-0001");
        match &v {
            Verdict::NotAffected(j) => {
                assert!(j.contains("VEX by Vendor Security Team"), "{j}");
                assert!(j.contains("not present"), "{j}");
            }
            other => unreachable!("expected NotAffected, got {other:?}"),
        }
    }

    #[test]
    fn other_statuses_and_other_cves_change_nothing() {
        let st = parse_vex(DOC.as_bytes()).unwrap();
        for cve in ["CVE-2026-0002", "CVE-2026-0003", "CVE-2026-9999"] {
            let mut v = Verdict::Affected { fixed_in: None };
            apply_vex(&mut v, &st, cve);
            assert!(matches!(v, Verdict::Affected { .. }), "{cve}: {v:?}");
        }
    }

    #[test]
    fn malformed_documents_are_errors() {
        assert!(parse_vex(b"{").is_err());
        assert!(parse_vex(b"[]").is_err(), "an array is not a VEX document");
        assert!(parse_vex(br#"{"statements":[]}"#).unwrap().is_empty());
    }

    #[test]
    fn severities_are_untouched() {
        let st = parse_vex(DOC.as_bytes()).unwrap();
        let mut v = Verdict::Affected { fixed_in: None };
        apply_vex(&mut v, &st, "CVE-2026-0001");
        let f = Finding::new("x", crate::matching::Severity::High, v);
        assert_eq!(f.severity, crate::matching::Severity::High);
    }
}
