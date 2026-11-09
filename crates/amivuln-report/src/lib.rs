// SPDX-FileCopyrightText: 2026 amivuln contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Output formatters: summary, detail and JSON.
//!
//! Formatters write to an injected writer and never print on their own.
//! Text from outside the process is passed through [`sanitize_terminal`]
//! before it reaches a terminal; JSON relies on serde's escaping.

#![forbid(unsafe_code)]

mod json;
mod other;
mod prometheus;
mod sanitize;
mod text;

pub use json::{
    SCHEMA_VERSION, json_severity, render_cve_json, render_json, render_pending_json,
    render_restart_json,
};
pub use other::{render_csv, render_markdown, render_sarif};
pub use prometheus::render_prometheus;
pub use sanitize::sanitize_terminal;
pub use text::{
    RenderOptions, render_cve, render_detail, render_pending, render_restart, render_summary,
};

/// Output format selected with `--format`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// Short human-readable summary per target.
    Summary,
    /// Summary plus every finding.
    Detail,
    /// Versioned JSON (`schema_version`).
    Json,
    /// SARIF 2.1.0, for code scanning integrations.
    Sarif,
    /// Markdown, for reports in issues and pull requests.
    Markdown,
    /// CSV, with formula-injection protection.
    Csv,
    /// Prometheus text metrics, for the `node_exporter` textfile collector.
    Prometheus,
}

impl core::str::FromStr for Format {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "summary" => Ok(Self::Summary),
            "detail" => Ok(Self::Detail),
            "json" => Ok(Self::Json),
            "sarif" => Ok(Self::Sarif),
            "markdown" => Ok(Self::Markdown),
            "csv" => Ok(Self::Csv),
            "prometheus" => Ok(Self::Prometheus),
            other => Err(format!(
                "invalid --format value {other:?}; use summary, detail, json, sarif, markdown, csv or prometheus"
            )),
        }
    }
}

/// Renders `report` in the chosen format.
///
/// # Errors
///
/// Propagates write errors from `out`.
pub fn render(
    report: &amivuln_core::RunReport,
    format: Format,
    options: RenderOptions,
    out: &mut dyn std::io::Write,
) -> std::io::Result<()> {
    match format {
        Format::Summary => render_summary(report, options, out),
        Format::Detail => render_detail(report, options, out),
        Format::Json => render_json(report, out),
        Format::Sarif => render_sarif(report, out),
        Format::Markdown => render_markdown(report, out),
        Format::Csv => render_csv(report, out),
        Format::Prometheus => render_prometheus(report, out),
    }
}

/// Renders a pending-updates report. The detail format is the same as summary.
///
/// # Errors
///
/// Propagates write errors.
pub fn render_pending_report(
    report: &amivuln_core::PendingReport,
    format: Format,
    options: RenderOptions,
    out: &mut dyn std::io::Write,
) -> std::io::Result<()> {
    match format {
        Format::Json => render_pending_json(report, out),
        Format::Summary | Format::Detail => render_pending(report, options, out),
        Format::Sarif | Format::Markdown | Format::Csv | Format::Prometheus => Err(
            std::io::Error::other("--format sarif|markdown|csv|prometheus applies to check only"),
        ),
    }
}

/// Renders a CVE report. The detail format is the same as summary.
///
/// # Errors
///
/// Propagates write errors.
pub fn render_cve_report(
    report: &amivuln_core::CveReport,
    format: Format,
    options: RenderOptions,
    out: &mut dyn std::io::Write,
) -> std::io::Result<()> {
    match format {
        Format::Json => render_cve_json(report, out),
        Format::Summary | Format::Detail => render_cve(report, options, out),
        Format::Sarif | Format::Markdown | Format::Csv | Format::Prometheus => Err(
            std::io::Error::other("--format sarif|markdown|csv|prometheus applies to check only"),
        ),
    }
}

/// Renders a restart report. The detail format is the same as summary.
///
/// # Errors
///
/// Propagates write errors.
pub fn render_restart_report(
    report: &amivuln_core::RestartReport,
    format: Format,
    options: RenderOptions,
    out: &mut dyn std::io::Write,
) -> std::io::Result<()> {
    match format {
        Format::Json => render_restart_json(report, out),
        Format::Summary | Format::Detail => render_restart(report, options, out),
        Format::Sarif | Format::Markdown | Format::Csv | Format::Prometheus => Err(
            std::io::Error::other("--format sarif|markdown|csv|prometheus applies to check only"),
        ),
    }
}
