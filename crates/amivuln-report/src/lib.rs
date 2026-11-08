// SPDX-FileCopyrightText: 2026 amivuln contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Output formatters: summary, detail and JSON.
//!
//! Formatters write to an injected writer and never print on their own.
//! Text from outside the process is passed through [`sanitize_terminal`]
//! before it reaches a terminal; JSON relies on serde's escaping.

#![forbid(unsafe_code)]

mod json;
mod sanitize;
mod text;

pub use json::{SCHEMA_VERSION, render_cve_json, render_json, render_pending_json};
pub use sanitize::sanitize_terminal;
pub use text::{RenderOptions, render_cve, render_detail, render_pending, render_summary};

/// Output format selected with `--format`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// Short human-readable summary per target.
    Summary,
    /// Summary plus every finding.
    Detail,
    /// Versioned JSON (`schema_version`).
    Json,
}

impl core::str::FromStr for Format {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "summary" => Ok(Self::Summary),
            "detail" => Ok(Self::Detail),
            "json" => Ok(Self::Json),
            other => Err(format!(
                "invalid --format value {other:?}; use summary, detail or json"
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
    }
}
