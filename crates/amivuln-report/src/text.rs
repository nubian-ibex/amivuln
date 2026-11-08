// SPDX-FileCopyrightText: 2026 amivuln contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Human-readable output.

use std::io::{self, Write};

use amivuln_core::{
    Ecosystem, Finding, RunReport, Severity, SourceStatus, Summary, TargetReport, Verdict, Version,
};

use crate::sanitize_terminal;

/// Rendering switches.
#[derive(Debug, Clone, Copy, Default)]
pub struct RenderOptions {
    /// Use ANSI colors.
    pub color: bool,
    /// Leave out targets without findings (whole-system scans).
    pub hide_clean: bool,
}

fn paint(opts: RenderOptions, code: &str, text: &str) -> String {
    if opts.color {
        format!("\u{1b}[{code}m{text}\u{1b}[0m")
    } else {
        text.to_owned()
    }
}

fn severity_label(opts: RenderOptions, s: Severity) -> String {
    let (text, code) = match s {
        Severity::Critical => ("CRITICAL", "1;31"),
        Severity::High => ("HIGH", "31"),
        Severity::Medium => ("MEDIUM", "33"),
        Severity::Low => ("LOW", "36"),
        Severity::Unknown => ("UNKNOWN", "2"),
    };
    paint(opts, code, text)
}

fn ecosystem_label(e: Ecosystem) -> String {
    match e {
        Ecosystem::Fedora(v) => format!("Fedora {v}"),
        Ecosystem::Arch => "Arch Linux".to_owned(),
    }
}

/// The command a user would run to apply the fix. Suggested, never executed.
fn update_hint(target: &TargetReport) -> String {
    let name = sanitize_terminal(&target.package.name);
    match target.package.ecosystem {
        Ecosystem::Fedora(_) => format!("dnf upgrade {name}"),
        Ecosystem::Arch => "pacman -Syu".to_owned(),
    }
}

/// Highest fixed version among affected findings, when every one has a fix.
fn highest_fix(findings: &[Finding]) -> Option<Version> {
    let mut best: Option<Version> = None;
    for f in findings {
        if let Verdict::Affected { fixed_in: Some(v) } = &f.verdict {
            best = match best {
                Some(b) if b.compare(v) != Some(core::cmp::Ordering::Less) => Some(b),
                _ => Some(v.clone()),
            };
        }
    }
    best
}

fn write_target_header(out: &mut dyn Write, t: &TargetReport) -> io::Result<()> {
    let p = &t.package;
    write!(
        out,
        "{} {} ({})",
        sanitize_terminal(&p.name),
        sanitize_terminal(&p.version.to_string()),
        ecosystem_label(p.ecosystem)
    )?;
    if sanitize_terminal(&t.input) != p.name {
        write!(out, "  <- {}", sanitize_terminal(&t.input))?;
    }
    writeln!(out)
}

fn write_counts(out: &mut dyn Write, opts: RenderOptions, s: &Summary) -> io::Result<()> {
    write!(
        out,
        "  {} {}   {} {}   {} {}   {} {}   KEV {}",
        severity_label(opts, Severity::Critical),
        s.critical,
        severity_label(opts, Severity::High),
        s.high,
        severity_label(opts, Severity::Medium),
        s.medium,
        severity_label(opts, Severity::Low),
        s.low,
        s.kev
    )?;
    if let Some(e) = s.epss_max {
        write!(out, "   EPSS max {e:.2}")?;
    }
    writeln!(out)?;
    if s.unverified > 0 {
        writeln!(
            out,
            "  {} finding(s) could not be verified against distro data (listed apart, not counted above)",
            s.unverified
        )?;
    }
    Ok(())
}

fn write_fix(out: &mut dyn Write, t: &TargetReport) -> io::Result<()> {
    if let Some(v) = highest_fix(&t.findings) {
        writeln!(
            out,
            "  Fixed in: {}  ({})",
            sanitize_terminal(&v.to_string()),
            update_hint(t)
        )?;
    }
    Ok(())
}

fn write_footer(out: &mut dyn Write, opts: RenderOptions, r: &RunReport) -> io::Result<()> {
    writeln!(out)?;
    for u in &r.unresolved {
        writeln!(
            out,
            "{} {}: {}",
            paint(opts, "1;31", "unresolved"),
            sanitize_terminal(&u.input),
            sanitize_terminal(&u.reason)
        )?;
    }
    for s in &r.sources {
        let detail = match &s.status {
            SourceStatus::Failed(why) | SourceStatus::Skipped(why) => {
                format!(" ({})", sanitize_terminal(why))
            }
            _ => String::new(),
        };
        writeln!(
            out,
            "source {:<18} {}{}  age {}s{}",
            s.source.as_str(),
            s.status.label(),
            detail,
            s.age.as_secs(),
            if s.required { "  required" } else { "" }
        )?;
    }
    if r.complete {
        writeln!(out, "result: complete")
    } else {
        writeln!(
            out,
            "{}",
            paint(
                opts,
                "1;31",
                "result: INCOMPLETE (a required source failed); do not treat this as clean"
            )
        )
    }
}

fn is_clean(t: &TargetReport) -> bool {
    t.findings.is_empty()
}

fn write_totals(out: &mut dyn Write, r: &RunReport) -> io::Result<()> {
    if r.targets.len() > 1 {
        let with = r.targets.iter().filter(|t| !is_clean(t)).count();
        writeln!(
            out,
            "checked {} packages, {} with findings",
            r.targets.len(),
            with
        )?;
    }
    Ok(())
}

/// One block per target: counts, the fix to apply, then the footer.
///
/// # Errors
///
/// Propagates write errors.
pub fn render_summary(r: &RunReport, opts: RenderOptions, out: &mut dyn Write) -> io::Result<()> {
    for t in r
        .targets
        .iter()
        .filter(|t| !(opts.hide_clean && is_clean(t)))
    {
        write_target_header(out, t)?;
        write_counts(out, opts, &Summary::of(&t.findings))?;
        write_fix(out, t)?;
        writeln!(out)?;
    }
    write_totals(out, r)?;
    write_footer(out, opts, r)
}

fn write_finding(out: &mut dyn Write, opts: RenderOptions, f: &Finding) -> io::Result<()> {
    let fixed = match &f.verdict {
        Verdict::Affected { fixed_in: Some(v) } => sanitize_terminal(&v.to_string()),
        _ => "no fix published".to_owned(),
    };
    let kev = f.kev.as_ref().map_or(String::new(), |k| {
        format!(
            "  KEV(added {}{})",
            k.added,
            if k.ransomware { ", ransomware" } else { "" }
        )
    });
    let epss = f
        .epss
        .as_ref()
        .map_or(String::new(), |e| format!("  EPSS {:.2}", e.score));
    writeln!(
        out,
        "    {:<16} {:<18} fix: {}{}{}",
        sanitize_terminal(&f.id),
        severity_label(opts, f.severity),
        fixed,
        kev,
        epss
    )
}

/// The summary plus every finding, affected and unverified in separate lists.
///
/// # Errors
///
/// Propagates write errors.
pub fn render_detail(r: &RunReport, opts: RenderOptions, out: &mut dyn Write) -> io::Result<()> {
    for t in r
        .targets
        .iter()
        .filter(|t| !(opts.hide_clean && is_clean(t)))
    {
        write_target_header(out, t)?;
        write_counts(out, opts, &Summary::of(&t.findings))?;
        write_fix(out, t)?;
        let affected: Vec<&Finding> = t
            .findings
            .iter()
            .filter(|f| matches!(f.verdict, Verdict::Affected { .. }))
            .collect();
        if !affected.is_empty() {
            writeln!(out, "  Affected:")?;
            for f in affected {
                write_finding(out, opts, f)?;
            }
        }
        let unverified: Vec<&Finding> = t
            .findings
            .iter()
            .filter(|f| f.verdict == Verdict::Unverified)
            .collect();
        if !unverified.is_empty() {
            writeln!(out, "  Unverified (no distro statement):")?;
            for f in unverified {
                write_finding(out, opts, f)?;
            }
        }
        writeln!(out)?;
    }
    write_totals(out, r)?;
    write_footer(out, opts, r)
}

#[cfg(test)]
pub(crate) mod fixtures {
    use core::time::Duration;

    use amivuln_core::{
        EpssInfo, Finding, HostMeta, KevInfo, PackageRef, Provenance, RunReport, Severity,
        SourceId, SourceReport, SourceStatus, TargetReport, Unresolved, Verdict, Version,
    };

    fn rpm(s: &str) -> Version {
        Version::Rpm(s.parse().unwrap_or_else(|n| match n {}))
    }

    pub(crate) fn report(complete: bool) -> RunReport {
        let mut high = Finding::new(
            "CVE-0000-0001",
            Severity::High,
            Verdict::Affected {
                fixed_in: Some(rpm("1:1.26.3-1.fc41")),
            },
        );
        high.kev = Some(KevInfo {
            added: "2026-10-30".into(),
            ransomware: true,
        });
        high.epss = Some(EpssInfo {
            score: 0.91,
            percentile: 0.99,
            date: "2026-11-06".into(),
        });
        let low = Finding::new(
            "CVE-0000-0002",
            Severity::Low,
            Verdict::Affected {
                fixed_in: Some(rpm("1:1.26.2-2.fc41")),
            },
        );
        let unknown = Finding::new("CVE-0000-0003", Severity::Medium, Verdict::Unverified);
        RunReport {
            tool_version: "0.0.0-test".into(),
            generated_at: "2026-11-08T00:00:00Z".into(),
            host: HostMeta {
                os_id: "fedora".into(),
                os_version: "41".into(),
                arch: "x86_64".into(),
            },
            complete,
            sources: vec![
                SourceReport {
                    source: SourceId::FedoraUpdateinfo,
                    status: SourceStatus::Ok,
                    age: Duration::from_secs(5),
                    required: true,
                },
                SourceReport {
                    source: SourceId::Epss,
                    status: SourceStatus::Failed("timeout \u{1b}[31m".into()),
                    age: Duration::ZERO,
                    required: false,
                },
            ],
            targets: vec![TargetReport {
                input: "nginx.service".into(),
                package: PackageRef {
                    ecosystem: amivuln_core::Ecosystem::Fedora(41),
                    name: "nginx".into(),
                    source_name: Some("nginx".into()),
                    version: rpm("1:1.26.2-1.fc41"),
                    arch: Some("x86_64".into()),
                    provenance: Provenance::PackageDb,
                },
                findings: vec![high, low, unknown],
            }],
            unresolved: vec![Unresolved {
                input: "ghost".into(),
                reason: "no installed package matches \"ghost\"".into(),
            }],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures::report;
    use super::*;

    fn render(
        f: fn(&RunReport, RenderOptions, &mut dyn Write) -> io::Result<()>,
        r: &RunReport,
        color: bool,
    ) -> String {
        let mut buf = Vec::new();
        f(
            r,
            RenderOptions {
                color,
                hide_clean: false,
            },
            &mut buf,
        )
        .unwrap();
        String::from_utf8(buf).unwrap()
    }

    #[test]
    fn summary_shows_counts_fix_and_sources_without_color() {
        let out = render(render_summary, &report(true), false);
        assert!(
            out.contains("nginx 1:1.26.2-1.fc41 (Fedora 41)  <- nginx.service"),
            "{out}"
        );
        assert!(
            out.contains("CRITICAL 0   HIGH 1   MEDIUM 0   LOW 1   KEV 1   EPSS max 0.91"),
            "{out}"
        );
        assert!(out.contains("1 finding(s) could not be verified"), "{out}");
        assert!(
            out.contains("Fixed in: 1:1.26.3-1.fc41  (dnf upgrade nginx)"),
            "{out}"
        );
        assert!(out.contains("result: complete"), "{out}");
        assert!(
            !out.contains('\u{1b}'),
            "no color requested but ESC found: {out:?}"
        );
    }

    #[test]
    fn incomplete_result_is_loud() {
        let out = render(render_summary, &report(false), false);
        assert!(out.contains("result: INCOMPLETE"), "{out}");
    }

    #[test]
    fn external_text_cannot_inject_escapes() {
        let out = render(render_summary, &report(true), false);
        assert!(out.contains("timeout \u{FFFD}[31m"), "{out:?}");
        assert!(!out.contains('\u{1b}'));
    }

    #[test]
    fn detail_lists_affected_and_unverified_apart() {
        let out = render(render_detail, &report(true), false);
        let affected = out.find("Affected:").unwrap();
        let unverified = out.find("Unverified (no distro statement):").unwrap();
        assert!(affected < unverified);
        assert!(out[affected..unverified].contains("CVE-0000-0001"));
        assert!(out[affected..unverified].contains("KEV(added 2026-10-30, ransomware)"));
        assert!(!out[affected..unverified].contains("CVE-0000-0003"));
        assert!(out[unverified..].contains("CVE-0000-0003"));
    }

    #[test]
    fn color_is_applied_only_on_request() {
        let out = render(render_summary, &report(true), true);
        assert!(out.contains("\u{1b}[31mHIGH\u{1b}[0m"));
    }

    #[test]
    fn whole_system_scans_hide_clean_targets_and_count_them() {
        let mut r = report(true);
        let mut clean = r.targets[0].clone();
        clean.input = "zlib".into();
        clean.package.name = "zlib".into();
        clean.findings.clear();
        r.targets.push(clean);
        let mut buf = Vec::new();
        render_summary(
            &r,
            RenderOptions {
                color: false,
                hide_clean: true,
            },
            &mut buf,
        )
        .unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(out.contains("nginx 1:1.26.2"), "{out}");
        assert!(!out.contains("zlib"), "{out}");
        assert!(out.contains("checked 2 packages, 1 with findings"), "{out}");
    }

    #[test]
    fn unresolved_targets_are_listed() {
        let out = render(render_summary, &report(true), false);
        assert!(
            out.contains("unresolved ghost: no installed package matches"),
            "{out}"
        );
    }
}
