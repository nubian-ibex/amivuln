// SPDX-FileCopyrightText: 2026 amivuln contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! SBOM and VEX output: a `CycloneDX` 1.6 BOM with its vulnerability analysis,
//! and an `OpenVEX` 0.2.0 document, both built from a run report.
//!
//! Components and statements are sorted and deduplicated by purl, and nothing
//! random goes in (no serial number, no UUID), so the same report always
//! renders the same bytes.

use std::collections::BTreeMap;
use std::io::{self, Write};

use amivuln_core::{Finding, RunReport, TargetReport, Verdict};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::json::{json_severity, provenance_name, purl};

/// What a verdict means in each format, and the sentence that explains it.
struct Meaning {
    /// `CycloneDX` `analysis.state`.
    cyclonedx: &'static str,
    /// `OpenVEX` `status`.
    openvex: &'static str,
    text: String,
    /// A fix exists, so `CycloneDX` can say `update` as the response.
    update: bool,
}

fn meaning(verdict: &Verdict) -> Meaning {
    match verdict {
        Verdict::Affected {
            fixed_in: Some(fixed),
        } => Meaning {
            cyclonedx: "exploitable",
            openvex: "affected",
            text: format!("Update to {fixed} or later"),
            update: true,
        },
        Verdict::Affected { fixed_in: None } => Meaning {
            cyclonedx: "exploitable",
            openvex: "affected",
            text: "No fixed version is published".to_owned(),
            update: false,
        },
        Verdict::Patched => Meaning {
            cyclonedx: "resolved",
            openvex: "fixed",
            text: "The distribution fixed it at or before the installed version".to_owned(),
            update: false,
        },
        Verdict::NotAffected(why) => Meaning {
            cyclonedx: "not_affected",
            openvex: "not_affected",
            text: why.clone(),
            update: false,
        },
        Verdict::Unverified => Meaning {
            cyclonedx: "in_triage",
            openvex: "under_investigation",
            text: "No distribution statement, or the versions cannot be compared".to_owned(),
            update: false,
        },
    }
}

/// The packages of the report by purl, first occurrence wins.
fn by_purl(r: &RunReport) -> BTreeMap<String, &TargetReport> {
    let mut out = BTreeMap::new();
    for t in &r.targets {
        out.entry(purl(&t.package)).or_insert(t);
    }
    out
}

/// The findings and the settled CVEs of a package by id, each id once. A
/// reported finding wins over a settled one of the same id.
fn sorted_findings(t: &TargetReport) -> Vec<&Finding> {
    let mut found: Vec<&Finding> = t.findings.iter().chain(&t.resolved).collect();
    found.sort_by(|a, b| a.id.cmp(&b.id));
    found.dedup_by(|a, b| a.id == b.id);
    found
}

/// `base` with the members that are present added.
fn with<const N: usize>(base: Value, extra: [(&str, Option<Value>); N]) -> Value {
    let Value::Object(mut map) = base else {
        return base;
    };
    for (key, value) in extra {
        if let Some(value) = value {
            map.insert(key.to_owned(), value);
        }
    }
    Value::Object(map)
}

/// The advisory database an id belongs to, when the id says so.
fn source(id: &str) -> Option<Value> {
    let (name, url) = if id.starts_with("CVE-") {
        ("NVD", format!("https://nvd.nist.gov/vuln/detail/{id}"))
    } else if id.starts_with("GHSA-") {
        (
            "GitHub Advisory Database",
            format!("https://github.com/advisories/{id}"),
        )
    } else if id.starts_with("GO-") {
        (
            "Go Vulnerability Database",
            format!("https://pkg.go.dev/vuln/{id}"),
        )
    } else if id.starts_with("RUSTSEC-") {
        ("RustSec", format!("https://rustsec.org/advisories/{id}"))
    } else {
        return None;
    };
    Some(json!({"name": name, "url": url}))
}

fn cyclonedx_vulnerability(f: &Finding, purl: &str, version: &str) -> Value {
    let m = meaning(&f.verdict);
    let analysis = with(
        json!({"state": m.cyclonedx, "detail": m.text}),
        [("response", m.update.then(|| json!(["update"])))],
    );
    let mut ratings = vec![json!({"severity": json_severity(f.severity)})];
    if let Some(e) = &f.epss {
        ratings.push(json!({
            "source": {"name": "FIRST EPSS", "url": "https://www.first.org/epss/"},
            "score": e.score,
            "method": "other",
        }));
    }
    let status = if matches!(f.verdict, Verdict::Affected { .. }) {
        "affected"
    } else {
        "unaffected"
    };
    with(
        json!({
            "id": f.id,
            "ratings": ratings,
            "analysis": analysis,
            "affects": [{"ref": purl, "versions": [{"version": version, "status": status}]}],
        }),
        [
            ("source", source(&f.id)),
            (
                "properties",
                f.kev.as_ref().map(|k| {
                    json!([
                        {"name": "cisa:kev", "value": "true"},
                        {"name": "cisa:kev:added", "value": k.added},
                        {"name": "cisa:kev:ransomware", "value": k.ransomware.to_string()},
                    ])
                }),
            ),
        ],
    )
}

/// Writes the report as a `CycloneDX` 1.6 BOM: the installed packages as
/// components and each finding as a vulnerability with its analysis.
///
/// A package is a component whether or not it has findings, so the document
/// is also the host's software inventory. The `amivuln:complete` property says
/// whether every required source answered.
///
/// # Errors
///
/// Propagates write errors.
pub fn render_cyclonedx(r: &RunReport, out: &mut dyn Write) -> io::Result<()> {
    let packages = by_purl(r);
    let components: Vec<Value> = packages
        .iter()
        .map(|(purl, t)| {
            json!({
                "type": "library",
                "bom-ref": purl,
                "name": t.package.name,
                "version": t.package.version.to_string(),
                "purl": purl,
                "properties": [
                    {"name": "amivuln:provenance", "value": provenance_name(t.package.provenance)},
                ],
            })
        })
        .collect();
    let vulnerabilities: Vec<Value> = packages
        .iter()
        .flat_map(|(purl, t)| {
            let version = t.package.version.to_string();
            sorted_findings(t)
                .into_iter()
                .map(move |f| cyclonedx_vulnerability(f, purl, &version))
        })
        .collect();
    let mut properties = vec![json!({"name": "amivuln:complete", "value": r.complete.to_string()})];
    if !r.unresolved.is_empty() {
        properties
            .push(json!({"name": "amivuln:unresolved", "value": r.unresolved.len().to_string()}));
    }
    let doc = json!({
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "timestamp": r.generated_at,
            "tools": {"components": [{
                "type": "application",
                "name": "amivuln",
                "version": r.tool_version,
            }]},
            "component": {
                "type": "operating-system",
                "bom-ref": "host",
                "name": r.host.os_id,
                "version": r.host.os_version,
            },
            "properties": properties,
        },
        "components": components,
        "vulnerabilities": vulnerabilities,
    });
    serde_json::to_writer_pretty(&mut *out, &doc).map_err(io::Error::other)?;
    writeln!(out)
}

fn openvex_statement(f: &Finding, purl: &str) -> Value {
    let m = meaning(&f.verdict);
    // OpenVEX asks for an action with `affected` and for an impact statement
    // (or a justification) with `not_affected`; the rest carry notes.
    let key = match m.openvex {
        "affected" => "action_statement",
        "not_affected" => "impact_statement",
        _ => "status_notes",
    };
    with(
        json!({
            "vulnerability": {"name": f.id},
            "products": [{"@id": purl, "identifiers": {"purl": purl}}],
            "status": m.openvex,
        }),
        [(key, Some(json!(m.text)))],
    )
}

/// Writes the report as an `OpenVEX` 0.2.0 document: one statement per package
/// and vulnerability, with the status the distribution data gives it
/// (`affected`, `fixed` for a backported fix, `not_affected` or
/// `under_investigation`).
///
/// The statements are the tool's assessment of this host, not a vendor's
/// attestation. The document id is derived from the statements, so equal
/// reports have equal ids.
///
/// # Errors
///
/// Propagates write errors.
pub fn render_openvex(r: &RunReport, out: &mut dyn Write) -> io::Result<()> {
    let statements: Vec<Value> = by_purl(r)
        .iter()
        .flat_map(|(purl, t)| {
            sorted_findings(t)
                .into_iter()
                .map(move |f| openvex_statement(f, purl))
        })
        .collect();
    let digest = {
        let bytes = serde_json::to_vec(&statements).map_err(io::Error::other)?;
        Sha256::digest(&bytes)
    };
    let id: String = digest.iter().fold(
        String::from("https://ibexwall.com/amivuln/vex/"),
        |mut acc, b| {
            use std::fmt::Write as _;
            let _ = write!(acc, "{b:02x}");
            acc
        },
    );
    let author = format!("amivuln {}", r.tool_version);
    let doc = json!({
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": id,
        "author": author,
        "role": "Software vulnerability scanner",
        "timestamp": r.generated_at,
        "version": 1,
        "tooling": author,
        "statements": statements,
    });
    serde_json::to_writer_pretty(&mut *out, &doc).map_err(io::Error::other)?;
    writeln!(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::text::fixtures::report;
    use amivuln_core::Severity;

    fn render(f: fn(&RunReport, &mut dyn Write) -> io::Result<()>, r: &RunReport) -> Value {
        let mut out = Vec::new();
        f(r, &mut out).unwrap();
        serde_json::from_slice(&out).unwrap()
    }

    #[test]
    fn every_verdict_has_a_state_in_both_formats() {
        let mut r = report(true);
        if let Some(t) = r.targets.first_mut() {
            t.findings = vec![Finding::new(
                "CVE-2026-0001",
                Severity::High,
                Verdict::Unverified,
            )];
            t.resolved = vec![
                Finding::new("CVE-2026-0002", Severity::Low, Verdict::Patched),
                Finding::new(
                    "CVE-2026-0003",
                    Severity::Low,
                    Verdict::NotAffected("the vulnerable code is not built".to_owned()),
                ),
            ];
        }
        let states: Vec<(String, String)> = render(render_cyclonedx, &r)["vulnerabilities"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| {
                (
                    v["id"].as_str().unwrap().to_owned(),
                    v["analysis"]["state"].as_str().unwrap().to_owned(),
                )
            })
            .collect();
        assert_eq!(
            states,
            [
                ("CVE-2026-0001".to_owned(), "in_triage".to_owned()),
                ("CVE-2026-0002".to_owned(), "resolved".to_owned()),
                ("CVE-2026-0003".to_owned(), "not_affected".to_owned()),
            ]
        );
        let vex = render(render_openvex, &r);
        let statuses: Vec<&str> = vex["statements"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|s| s["status"].as_str())
            .collect();
        assert_eq!(statuses, ["under_investigation", "fixed", "not_affected"]);
        // OpenVEX requires an impact statement with not_affected.
        assert_eq!(
            vex["statements"][2]["impact_statement"],
            "the vulnerable code is not built"
        );
    }

    #[test]
    fn an_incomplete_run_says_so_and_a_repeated_package_is_one_component() {
        let mut r = report(false);
        let again = r.targets.first().cloned().unwrap();
        r.targets.push(again);
        let bom = render(render_cyclonedx, &r);
        assert_eq!(bom["components"].as_array().unwrap().len(), 1);
        let complete = bom["metadata"]["properties"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["name"] == "amivuln:complete")
            .unwrap();
        assert_eq!(complete["value"], "false");
        // The same finding twice on one package is one vulnerability.
        let ids: Vec<&str> = bom["vulnerabilities"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|v| v["id"].as_str())
            .collect();
        let mut unique = ids.clone();
        unique.dedup();
        assert_eq!(ids, unique);
    }

    /// The `CycloneDX` schema refers to two more documents by relative URI; they
    /// are copied next to it, so nothing is fetched.
    struct Vendored;

    impl jsonschema::Retrieve for Vendored {
        fn retrieve(
            &self,
            uri: &jsonschema::Uri<String>,
        ) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
            let text = match uri.path().as_str().rsplit('/').next() {
                Some("spdx.schema.json") => {
                    include_str!("../../../tests/vendor/schemas/spdx.schema.json")
                }
                Some("jsf-0.82.schema.json") => {
                    include_str!("../../../tests/vendor/schemas/jsf-0.82.schema.json")
                }
                _ => return Err(format!("unexpected reference {uri}").into()),
            };
            Ok(serde_json::from_str(text)?)
        }
    }

    /// Findings of every verdict, with KEV and EPSS data and ids of several
    /// databases, so every branch of the documents is checked.
    fn rich_report() -> RunReport {
        let mut r = report(false);
        r.unresolved.push(amivuln_core::Unresolved {
            input: "nothing".to_owned(),
            reason: "not installed".to_owned(),
        });
        if let Some(t) = r.targets.first_mut() {
            t.resolved = vec![
                Finding::new("CVE-2026-0002", Severity::Low, Verdict::Patched),
                Finding::new("GHSA-aaaa-bbbb-cccc", Severity::High, Verdict::Patched),
                Finding::new("GO-2026-0001", Severity::Low, Verdict::Patched),
                Finding::new("RUSTSEC-2026-0001", Severity::Low, Verdict::Patched),
                Finding::new(
                    "DSA-1-1",
                    Severity::Unknown,
                    Verdict::NotAffected("not built".to_owned()),
                ),
            ];
        }
        r
    }

    #[test]
    fn the_documents_validate_against_the_official_schemas() {
        let r = rich_report();
        let cyclonedx: Value = serde_json::from_str(include_str!(
            "../../../tests/vendor/schemas/bom-1.6.schema.json"
        ))
        .unwrap();
        let validator = jsonschema::options()
            .with_retriever(Vendored)
            .build(&cyclonedx)
            .unwrap();
        let bom = render(render_cyclonedx, &r);
        let errors: Vec<String> = validator.iter_errors(&bom).map(|e| e.to_string()).collect();
        assert!(errors.is_empty(), "CycloneDX: {errors:#?}");

        let openvex: Value = serde_json::from_str(include_str!(
            "../../../tests/vendor/schemas/openvex_json_schema.json"
        ))
        .unwrap();
        let validator = jsonschema::validator_for(&openvex).unwrap();
        let vex = render(render_openvex, &r);
        let errors: Vec<String> = validator.iter_errors(&vex).map(|e| e.to_string()).collect();
        assert!(errors.is_empty(), "OpenVEX: {errors:#?}");
    }

    #[test]
    fn external_text_cannot_break_out_of_the_documents() {
        let mut r = report(true);
        if let Some(t) = r.targets.first_mut() {
            t.resolved = vec![Finding::new(
                "CVE-2026-0009",
                Severity::Low,
                Verdict::NotAffected("quote \" newline \n and \u{1b}[31m escape".to_owned()),
            )];
        }
        // serde_json escapes everything, so the output parses back to the text.
        let vex = render(render_openvex, &r);
        let last = vex["statements"].as_array().unwrap().last().unwrap();
        assert_eq!(
            last["impact_statement"],
            "quote \" newline \n and \u{1b}[31m escape"
        );
    }
}
