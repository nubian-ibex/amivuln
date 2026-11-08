// SPDX-FileCopyrightText: 2026 amivuln contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! SARIF, Markdown and CSV formatters.

use std::io::{self, Write};

use amivuln_core::{RunReport, Severity, Summary, Verdict};
use serde::Serialize;

use crate::{
    json::{ecosystem_name, json_severity},
    sanitize_terminal,
};

/// The SARIF severity level for a CVSS-style severity.
fn sarif_level(s: Severity) -> &'static str {
    match s {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::Unknown => "note",
    }
}

#[derive(Serialize)]
struct SarifLog<'a> {
    version: &'static str,
    runs: Vec<SarifRun<'a>>,
}

#[derive(Serialize)]
struct SarifRun<'a> {
    tool: SarifTool<'a>,
    results: Vec<SarifResult<'a>>,
}

#[derive(Serialize)]
struct SarifTool<'a> {
    driver: SarifDriver<'a>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifDriver<'a> {
    name: &'static str,
    version: &'a str,
    information_uri: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifResult<'a> {
    rule_id: &'a str,
    level: &'static str,
    message: SarifMessage,
    properties: SarifProps<'a>,
}

#[derive(Serialize)]
struct SarifMessage {
    text: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifProps<'a> {
    package: &'a str,
    version: String,
    state: &'static str,
    severity: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    fixed_in: Option<String>,
}

/// Writes the report as SARIF 2.1.0.
///
/// One result per affected finding; unverified, patched and not-affected
/// findings are not results (SARIF expresses problems, not their absence).
///
/// # Errors
///
/// Propagates write errors.
pub fn render_sarif(r: &RunReport, out: &mut dyn Write) -> io::Result<()> {
    let doc = SarifLog {
        version: "2.1.0",
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: "amivuln",
                    version: &r.tool_version,
                    information_uri: "https://nubian-ibex.github.io/amivuln/",
                },
            },
            results: r
                .targets
                .iter()
                .flat_map(|t| {
                    t.findings.iter().filter_map(move |f| match &f.verdict {
                        Verdict::Affected { fixed_in } => Some(SarifResult {
                            rule_id: &f.id,
                            level: sarif_level(f.severity),
                            message: SarifMessage {
                                text: format!(
                                    "{} {} is affected by {}; {}",
                                    t.package.name,
                                    t.package.version,
                                    f.id,
                                    fixed_in.as_ref().map_or_else(
                                        || "no fix published".to_owned(),
                                        |v| format!("fixed in {v}")
                                    )
                                ),
                            },
                            properties: SarifProps {
                                package: &t.package.name,
                                version: t.package.version.to_string(),
                                state: "affected",
                                severity: json_severity(f.severity),
                                fixed_in: fixed_in.as_ref().map(ToString::to_string),
                            },
                        }),
                        _ => None,
                    })
                })
                .collect(),
        }],
    };
    serde_json::to_writer_pretty(&mut *out, &doc).map_err(io::Error::other)?;
    writeln!(out)
}

/// The CSV header row.
const CSV_HEADER: &str = "package,version,ecosystem,id,severity,state,fixed_in,kev,epss";

/// Quotes a field and neutralises spreadsheet formulas.
fn csv_field(text: &str) -> String {
    let sanitized = sanitize_terminal(text);
    // Formula injection: a leading = + - @ or tab in a cell executes it.
    let guard = if sanitized
        .chars()
        .next()
        .is_some_and(|c| matches!(c, '=' | '+' | '-' | '@' | '\t' | '\r'))
    {
        "'"
    } else {
        ""
    };
    let escaped = sanitized.replace('"', "\"\"");
    format!("{guard}\"{escaped}\"")
}

/// Writes the report as CSV: one row per finding.
///
/// # Errors
///
/// Propagates write errors.
pub fn render_csv(r: &RunReport, out: &mut dyn Write) -> io::Result<()> {
    writeln!(out, "{CSV_HEADER}")?;
    for t in &r.targets {
        for f in &t.findings {
            let (state, fixed) = match &f.verdict {
                Verdict::Affected { fixed_in } => {
                    ("affected", fixed_in.as_ref().map(ToString::to_string))
                }
                Verdict::Unverified => ("unverified", None),
                Verdict::Patched => ("patched", None),
                Verdict::NotAffected(_) => ("not_affected", None),
            };
            let epss = f
                .epss
                .as_ref()
                .map_or(String::new(), |e| format!("{:.3}", e.score));
            writeln!(
                out,
                "{},{},{},{},{},{},{},{},{}",
                csv_field(&t.package.name),
                csv_field(&t.package.version.to_string()),
                csv_field(ecosystem_name(t.package.ecosystem)),
                csv_field(&f.id),
                json_severity(f.severity),
                state,
                csv_field(fixed.as_deref().unwrap_or("")),
                csv_field(if f.kev.is_some() { "yes" } else { "" }),
                csv_field(&epss),
            )?;
        }
    }
    Ok(())
}

/// Writes the report as Markdown: a table per target.
///
/// # Errors
///
/// Propagates write errors.
pub fn render_markdown(r: &RunReport, out: &mut dyn Write) -> io::Result<()> {
    writeln!(out, "# amivuln {}", r.tool_version)?;
    writeln!(
        out,
        "\nGenerated {} for {} {} ({}). Sources: {}.",
        r.generated_at,
        r.host.os_id,
        r.host.os_version,
        r.host.arch,
        if r.complete {
            "complete"
        } else {
            "**incomplete**"
        }
    )?;
    for t in &r.targets {
        let sum = Summary::of(&t.findings);
        writeln!(
            out,
            "\n## {} {} ({})\n",
            md_cell(&t.package.name),
            md_cell(&t.package.version.to_string()),
            ecosystem_name(t.package.ecosystem)
        )?;
        writeln!(
            out,
            "Affected: {} ({} critical, {} high, {} medium, {} low); KEV: {}; unverified: {}.",
            sum.affected(),
            sum.critical,
            sum.high,
            sum.medium,
            sum.low,
            sum.kev,
            sum.unverified
        )?;
        if t.findings.is_empty() {
            writeln!(out, "\nNo reportable findings.")?;
            continue;
        }
        writeln!(
            out,
            "\n| ID | Severity | State | Fixed in | KEV | EPSS |\n|---|---|---|---|---|---|"
        )?;
        for f in &t.findings {
            let (state, fixed) = match &f.verdict {
                Verdict::Affected { fixed_in } => {
                    ("affected", fixed_in.as_ref().map(ToString::to_string))
                }
                Verdict::Unverified => ("unverified", None),
                Verdict::Patched => ("patched", None),
                Verdict::NotAffected(_) => ("not_affected", None),
            };
            writeln!(
                out,
                "| {} | {} | {} | {} | {} | {} |",
                md_cell(&f.id),
                json_severity(f.severity),
                state,
                md_cell(fixed.as_deref().unwrap_or("-")),
                if f.kev.is_some() { "yes" } else { "-" },
                f.epss
                    .as_ref()
                    .map_or_else(|| "-".to_owned(), |e| format!("{:.2}", e.score)),
            )?;
        }
    }
    for u in &r.unresolved {
        writeln!(
            out,
            "\n> unresolved `{}`: {}",
            md_cell(&u.input),
            md_cell(&u.reason)
        )?;
    }
    if !r.complete {
        writeln!(
            out,
            "\n> **incomplete result**: a required source failed; do not treat this as clean"
        )?;
    }
    Ok(())
}

/// Pipes and newlines cannot appear in a Markdown table cell.
fn md_cell(text: &str) -> String {
    sanitize_terminal(text).replace('|', "\\|")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::text::fixtures::report;

    fn render(f: fn(&RunReport, &mut dyn Write) -> io::Result<()>) -> String {
        let mut buf = Vec::new();
        f(&report(true), &mut buf).unwrap();
        String::from_utf8(buf).unwrap()
    }

    #[test]
    fn markdown_tables_and_notes() {
        let text = render(render_markdown);
        assert!(text.contains("## nginx 1:1.26.2-1.fc41 (fedora)"));
        assert!(text.contains("| ID | Severity | State | Fixed in | KEV | EPSS |"));
        assert!(
            text.contains("| CVE-0000-0001 | high | affected | 1:1.26.3-1.fc41 | yes | 0.91 |"),
            "{text}"
        );
        assert!(text.contains("unresolved `ghost`"));
        let mut r = report(false);
        r.targets.clear();
        let mut buf = Vec::new();
        render_markdown(&r, &mut buf).unwrap();
        let text = String::from_utf8(buf).unwrap();
        assert!(text.contains("**incomplete**"));
        assert!(text.contains("incomplete result"));
    }

    #[test]
    fn pipes_never_break_a_table() {
        let mut r = report(true);
        r.targets[0].package.name = "a|b".into();
        r.targets[0].input = "a|b".into();
        let mut buf = Vec::new();
        render_markdown(&r, &mut buf).unwrap();
        let text = String::from_utf8(buf).unwrap();
        let line = text
            .lines()
            .find(|l| l.contains("a|b") || l.contains("a\\|b"))
            .unwrap_or_default();
        assert!(
            line.contains("a\\|b"),
            "the pipe must be escaped, got: {line}"
        );
    }
}
