// SPDX-FileCopyrightText: 2026 amivuln contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! JSON output, schema version 1.
//!
//! Field order is fixed by the struct definitions and keys never depend on
//! hash order, so the same run always serialises to the same bytes. The host
//! block holds only `os_id`, `os_version` and `arch`. Adding optional fields
//! does not bump the version; removing or retyping one does.

use std::io::{self, Write};

use amivuln_core::{
    Ecosystem, Finding, RunReport, Severity, SourceReport, SourceStatus, Summary, TargetReport,
    Verdict, Version,
};
use serde::Serialize;

/// Version of the JSON schema produced by [`render_json`].
pub const SCHEMA_VERSION: u32 = 1;

#[derive(Serialize)]
struct JsonReport<'a> {
    schema_version: u32,
    tool: Tool<'a>,
    generated_at: &'a str,
    host: Host<'a>,
    complete: bool,
    sources: Vec<JsonSource<'a>>,
    targets: Vec<JsonTarget<'a>>,
    unresolved: Vec<JsonUnresolved<'a>>,
}

#[derive(Serialize)]
struct Tool<'a> {
    name: &'static str,
    version: &'a str,
}

#[derive(Serialize)]
struct Host<'a> {
    os_id: &'a str,
    os_version: &'a str,
    arch: &'a str,
}

#[derive(Serialize)]
struct JsonSource<'a> {
    id: &'static str,
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<&'a str>,
    age_s: u64,
    required: bool,
}

#[derive(Serialize)]
struct JsonUnresolved<'a> {
    input: &'a str,
    reason: &'a str,
}

#[derive(Serialize)]
struct JsonTarget<'a> {
    input: &'a str,
    package: JsonPackage<'a>,
    summary: JsonSummary,
    findings: Vec<JsonFinding<'a>>,
    unverified: Vec<JsonFinding<'a>>,
}

#[derive(Serialize)]
struct JsonPackage<'a> {
    name: &'a str,
    version: String,
    arch: Option<&'a str>,
    ecosystem: &'static str,
    purl: String,
    provenance: &'static str,
}

#[derive(Serialize)]
struct JsonSummary {
    critical: usize,
    high: usize,
    medium: usize,
    low: usize,
    kev: usize,
    epss_max: Option<f64>,
    unverified: usize,
}

#[derive(Serialize)]
struct JsonFinding<'a> {
    id: &'a str,
    severity: &'static str,
    distro_status: JsonStatus,
    kev: Option<JsonKev<'a>>,
    epss: Option<JsonEpss<'a>>,
}

#[derive(Serialize)]
struct JsonStatus {
    state: &'static str,
    fixed_in: Option<String>,
}

#[derive(Serialize)]
struct JsonKev<'a> {
    added: &'a str,
    ransomware: bool,
}

#[derive(Serialize)]
struct JsonEpss<'a> {
    score: f64,
    percentile: f64,
    date: &'a str,
}

fn severity(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
        Severity::Unknown => "unknown",
    }
}

/// Percent-encodes everything outside the purl-safe set.
fn purl_encode(s: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b'~') {
            out.push(char::from(b));
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

fn purl(t: &TargetReport) -> String {
    let p = &t.package;
    let ns = p.ecosystem.purl_namespace();
    let name = purl_encode(&p.name);
    let mut qualifiers = Vec::new();
    if let Some(a) = &p.arch {
        qualifiers.push(format!("arch={}", purl_encode(a)));
    }
    let version = match &p.version {
        Version::Rpm(evr) => {
            if evr.epoch() != "0" {
                qualifiers.push(format!("epoch={}", purl_encode(evr.epoch())));
            }
            match evr.release() {
                Some(r) => format!("{}-{}", evr.version(), r),
                None => evr.version().to_owned(),
            }
        }
        Version::Pacman(v) => v.to_string(),
    };
    let mut out = format!("{ns}/{name}@{}", purl_encode(&version));
    if !qualifiers.is_empty() {
        out.push('?');
        out.push_str(&qualifiers.join("&"));
    }
    out
}

fn finding(f: &Finding) -> JsonFinding<'_> {
    let (state, fixed_in) = match &f.verdict {
        Verdict::Affected { fixed_in } => ("affected", fixed_in.as_ref().map(ToString::to_string)),
        Verdict::Unverified => ("unknown", None),
        Verdict::Patched => ("fixed", None),
        Verdict::NotAffected(_) => ("not_affected", None),
    };
    JsonFinding {
        id: &f.id,
        severity: severity(f.severity),
        distro_status: JsonStatus { state, fixed_in },
        kev: f.kev.as_ref().map(|k| JsonKev {
            added: &k.added,
            ransomware: k.ransomware,
        }),
        epss: f.epss.as_ref().map(|e| JsonEpss {
            score: e.score,
            percentile: e.percentile,
            date: &e.date,
        }),
    }
}

fn source(s: &SourceReport) -> JsonSource<'_> {
    JsonSource {
        id: s.source.as_str(),
        status: s.status.label(),
        detail: match &s.status {
            SourceStatus::Failed(w) | SourceStatus::Skipped(w) => Some(w),
            _ => None,
        },
        age_s: s.age.as_secs(),
        required: s.required,
    }
}

fn target(t: &TargetReport) -> JsonTarget<'_> {
    let sum = Summary::of(&t.findings);
    let (unverified, findings): (Vec<&Finding>, Vec<&Finding>) = t
        .findings
        .iter()
        .partition(|f| f.verdict == Verdict::Unverified);
    JsonTarget {
        input: &t.input,
        package: JsonPackage {
            name: &t.package.name,
            version: t.package.version.to_string(),
            arch: t.package.arch.as_deref(),
            ecosystem: match t.package.ecosystem {
                Ecosystem::Fedora(_) => "fedora",
                Ecosystem::Arch => "arch",
            },
            purl: purl(t),
            provenance: match t.package.provenance {
                amivuln_core::Provenance::PackageDb => "package_db",
                amivuln_core::Provenance::UserInput => "user_input",
            },
        },
        summary: JsonSummary {
            critical: sum.critical,
            high: sum.high,
            medium: sum.medium,
            low: sum.low,
            kev: sum.kev,
            epss_max: sum.epss_max,
            unverified: sum.unverified,
        },
        findings: findings.into_iter().map(finding).collect(),
        unverified: unverified.into_iter().map(finding).collect(),
    }
}

/// Writes the report as pretty-printed JSON followed by a newline.
///
/// # Errors
///
/// Propagates write errors.
pub fn render_json(r: &RunReport, out: &mut dyn Write) -> io::Result<()> {
    let doc = JsonReport {
        schema_version: SCHEMA_VERSION,
        tool: Tool {
            name: "amivuln",
            version: &r.tool_version,
        },
        generated_at: &r.generated_at,
        host: Host {
            os_id: &r.host.os_id,
            os_version: &r.host.os_version,
            arch: &r.host.arch,
        },
        complete: r.complete,
        sources: r.sources.iter().map(source).collect(),
        targets: r.targets.iter().map(target).collect(),
        unresolved: r
            .unresolved
            .iter()
            .map(|u| JsonUnresolved {
                input: &u.input,
                reason: &u.reason,
            })
            .collect(),
    };
    serde_json::to_writer_pretty(&mut *out, &doc).map_err(io::Error::other)?;
    writeln!(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::text::fixtures::report;

    fn json(complete: bool) -> serde_json::Value {
        let mut buf = Vec::new();
        render_json(&report(complete), &mut buf).unwrap();
        serde_json::from_slice(&buf).unwrap()
    }

    #[test]
    fn top_level_contract() {
        let v = json(true);
        assert_eq!(v["schema_version"], 1);
        assert_eq!(v["tool"]["name"], "amivuln");
        assert_eq!(v["complete"], true);
        assert_eq!(
            v["host"],
            serde_json::json!({"os_id":"fedora","os_version":"41","arch":"x86_64"})
        );
        assert_eq!(v["sources"][0]["id"], "fedora-updateinfo");
        assert_eq!(v["sources"][1]["status"], "failed");
        assert_eq!(v["unresolved"][0]["input"], "ghost");
    }

    #[test]
    fn incomplete_flag_is_carried() {
        assert_eq!(json(false)["complete"], false);
    }

    #[test]
    fn package_and_purl() {
        let p = &json(true)["targets"][0]["package"];
        assert_eq!(
            p["purl"],
            "pkg:rpm/fedora/nginx@1.26.2-1.fc41?arch=x86_64&epoch=1"
        );
        assert_eq!(p["provenance"], "package_db");
        assert_eq!(p["ecosystem"], "fedora");
    }

    #[test]
    fn affected_and_unverified_are_separate_lists() {
        let t = &json(true)["targets"][0];
        let ids = |k: &str| -> Vec<String> {
            t[k].as_array()
                .unwrap()
                .iter()
                .map(|f| f["id"].as_str().unwrap().to_owned())
                .collect()
        };
        assert_eq!(ids("findings"), ["CVE-0000-0001", "CVE-0000-0002"]);
        assert_eq!(ids("unverified"), ["CVE-0000-0003"]);
        assert_eq!(t["summary"]["unverified"], 1);
        assert_eq!(
            t["findings"][0]["distro_status"]["fixed_in"],
            "1:1.26.3-1.fc41"
        );
        assert_eq!(t["findings"][0]["kev"]["ransomware"], true);
        assert_eq!(t["unverified"][0]["distro_status"]["state"], "unknown");
    }

    #[test]
    fn output_is_deterministic_and_has_no_host_identity() {
        let render = || {
            let mut b = Vec::new();
            render_json(&report(true), &mut b).unwrap();
            String::from_utf8(b).unwrap()
        };
        assert_eq!(render(), render());
        let text = render();
        for key in ["hostname", "\"user\"", "\"ip\""] {
            assert!(!text.contains(key), "{key}");
        }
        // Field order is the struct order, not alphabetical.
        assert!(text.find("schema_version").unwrap() < text.find("generated_at").unwrap());
        assert!(text.ends_with("}\n"));
    }

    #[test]
    fn control_characters_are_escaped() {
        let text = {
            let mut b = Vec::new();
            render_json(&report(true), &mut b).unwrap();
            String::from_utf8(b).unwrap()
        };
        assert!(!text.contains('\u{1b}'));
        assert!(text.contains("\\u001b"));
    }

    #[test]
    fn purl_encoding() {
        assert_eq!(purl_encode("libstdc++"), "libstdc%2B%2B");
        assert_eq!(purl_encode("1:2.0-1"), "1%3A2.0-1");
    }
}
