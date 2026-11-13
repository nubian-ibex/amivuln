// SPDX-FileCopyrightText: 2026 amivuln contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Human-readable output.

use std::io::{self, Write};

use amivuln_core::{
    Ecosystem, Finding, RunReport, Severity, SourceStatus, Summary, TargetReport, Verdict, Version,
};

use amivuln_core::i18n::{tr, tr_args};

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
        Ecosystem::Debian(v) => format!("Debian {v}"),
        Ecosystem::Ubuntu(v) => format!("Ubuntu {}.{}", v / 100, v % 100),
        Ecosystem::Rocky(v) => format!("Rocky Linux {v}"),
        Ecosystem::Alma(v) => format!("AlmaLinux {v}"),
        Ecosystem::Rhel(v) => format!("Red Hat Enterprise Linux {v}"),
        Ecosystem::Go => "Go module".to_owned(),
        Ecosystem::Crates => "Rust crate".to_owned(),
        Ecosystem::Alpine(v) => format!("Alpine {}.{}", v / 100, v % 100),
    }
}

/// The command a user would run to apply the fix. Suggested, never executed.
fn update_hint(target: &TargetReport) -> String {
    let name = sanitize_terminal(&target.package.name);
    match target.package.ecosystem {
        Ecosystem::Fedora(_) => format!("dnf upgrade {name}"),
        Ecosystem::Arch => "pacman -Syu".to_owned(),
        Ecosystem::Debian(_) | Ecosystem::Ubuntu(_) => "apt-get upgrade".to_owned(),
        Ecosystem::Rocky(_) | Ecosystem::Alma(_) | Ecosystem::Rhel(_) => "dnf upgrade".to_owned(),
        // Nothing on the host's package manager updates a statically linked
        // dependency: the program has to be rebuilt or replaced.
        Ecosystem::Alpine(_) => format!("apk upgrade {name}"),
        Ecosystem::Go | Ecosystem::Crates => tr("hint.rebuild"),
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
            "{}",
            tr_args("counts.unverified", &[("n", &s.unverified)])
        )?;
    }
    Ok(())
}

fn write_fix(out: &mut dyn Write, t: &TargetReport) -> io::Result<()> {
    if let Some(v) = highest_fix(&t.findings) {
        writeln!(
            out,
            "{}",
            tr_args(
                "fix.fixed_in",
                &[
                    ("version", &sanitize_terminal(&v.to_string())),
                    ("hint", &update_hint(t)),
                ],
            )
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
            paint(opts, "1;31", &tr("footer.unresolved")),
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
        writeln!(out, "{}", source_line(s, &detail))?;
    }
    write_result(out, opts, r.complete)
}

/// One `source ...` line of the footer.
fn source_line(s: &amivuln_core::SourceReport, detail: &str) -> String {
    tr_args(
        "footer.source",
        &[
            ("name", &format!("{:<18}", s.source.as_str())),
            ("status", &s.status.label()),
            ("detail", &detail),
            ("age", &s.age.as_secs()),
            (
                "required",
                &if s.required {
                    tr("footer.required")
                } else {
                    String::new()
                },
            ),
        ],
    )
}

/// The last line: complete, or a warning that the result may hide something.
fn write_result(out: &mut dyn Write, opts: RenderOptions, complete: bool) -> io::Result<()> {
    if complete {
        writeln!(out, "{}", tr("footer.complete"))
    } else {
        writeln!(out, "{}", paint(opts, "1;31", &tr("footer.incomplete")))
    }
}

fn is_clean(t: &TargetReport) -> bool {
    t.findings.is_empty()
}

fn write_totals(out: &mut dyn Write, r: &RunReport) -> io::Result<()> {
    if r.targets.len() > 1 {
        let with = r.targets.iter().filter(|t| !is_clean(t)).count();
        let all: Vec<Finding> = r.targets.iter().flat_map(|t| t.findings.clone()).collect();
        let sc = amivuln_core::score(&all);
        let accepted = r.suppressed.len();
        let accepted_note = if accepted > 0 {
            tr_args("totals.accepted", &[("n", &accepted)])
        } else {
            String::new()
        };
        writeln!(
            out,
            "{}",
            tr_args(
                "totals.line",
                &[
                    ("packages", &r.targets.len()),
                    ("with", &with),
                    ("grade", &sc.grade.letter()),
                    ("points", &sc.points),
                    ("accepted", &accepted_note),
                ],
            )
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

fn write_finding(
    out: &mut dyn Write,
    opts: RenderOptions,
    f: &Finding,
    suppressed: Option<&String>,
) -> io::Result<()> {
    let fixed = match &f.verdict {
        Verdict::Affected { fixed_in: Some(v) } => sanitize_terminal(&v.to_string()),
        Verdict::Affected { fixed_in: None } => tr("finding.no_fix"),
        _ => "-".to_owned(),
    };
    let kev = f.kev.as_ref().map_or(String::new(), |k| {
        tr_args(
            "finding.kev",
            &[
                ("added", &k.added),
                (
                    "ransomware",
                    &if k.ransomware {
                        tr("finding.ransomware")
                    } else {
                        String::new()
                    },
                ),
            ],
        )
    });
    let epss = f
        .epss
        .as_ref()
        .map_or(String::new(), |e| format!("  EPSS {:.2}", e.score));
    let note = suppressed.as_ref().map_or(String::new(), |r| {
        format!(
            "  {}",
            paint(
                opts,
                "32",
                &tr_args("finding.accepted", &[("reason", &sanitize_terminal(r))]),
            )
        )
    });
    writeln!(
        out,
        "    {:<16} {:<18} {}{}{}{}",
        sanitize_terminal(&f.id),
        severity_label(opts, f.severity),
        tr_args("finding.fix", &[("fixed", &fixed)]),
        kev,
        epss,
        note
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
            writeln!(out, "{}", tr("detail.affected"))?;
            for f in affected {
                write_finding(out, opts, f, r.suppressed.get(&f.id))?;
            }
        }
        let unverified: Vec<&Finding> = t
            .findings
            .iter()
            .filter(|f| f.verdict == Verdict::Unverified)
            .collect();
        if !unverified.is_empty() {
            writeln!(out, "{}", tr("detail.unverified"))?;
            for f in unverified {
                write_finding(out, opts, f, r.suppressed.get(&f.id))?;
            }
        }
        writeln!(out)?;
    }
    write_totals(out, r)?;
    write_footer(out, opts, r)
}

fn write_sources_footer(
    out: &mut dyn Write,
    opts: RenderOptions,
    sources: &[amivuln_core::SourceReport],
    complete: bool,
) -> io::Result<()> {
    for s in sources {
        let detail = match &s.status {
            SourceStatus::Failed(why) | SourceStatus::Skipped(why) => {
                format!(" ({})", sanitize_terminal(why))
            }
            _ => String::new(),
        };
        writeln!(out, "{}", source_line(s, &detail))?;
    }
    write_result(out, opts, complete)
}

/// `amivuln pending`: the updates that close the most risk first.
///
/// # Errors
///
/// Propagates write errors.
pub fn render_pending(
    r: &amivuln_core::PendingReport,
    opts: RenderOptions,
    out: &mut dyn Write,
) -> io::Result<()> {
    if r.updates.is_empty() {
        writeln!(out, "{}", tr("pending.none"))?;
    } else {
        let closed: usize = r.updates.iter().map(|u| u.closes.len()).sum();
        let kev: usize = r.updates.iter().map(|u| u.kev).sum();
        writeln!(
            out,
            "{}",
            tr_args(
                "pending.summary",
                &[
                    ("updates", &r.updates.len()),
                    ("closed", &closed),
                    ("kev", &kev)
                ],
            )
        )?;
        writeln!(out)?;
        for u in &r.updates {
            let more = if u.also.is_empty() {
                String::new()
            } else {
                tr_args("pending.more", &[("n", &u.also.len())])
            };
            writeln!(
                out,
                "{}",
                tr_args(
                    "pending.line",
                    &[
                        ("package", &sanitize_terminal(&u.package.name)),
                        ("more", &more),
                        (
                            "version",
                            &sanitize_terminal(&u.package.version.to_string())
                        ),
                        ("target", &sanitize_terminal(&u.target.to_string())),
                        ("closes", &u.closes.len()),
                        ("severity", &severity_label(opts, u.severity)),
                        ("kev", &u.kev),
                        (
                            "epss",
                            &u.epss_max
                                .map_or(String::new(), |e| format!("   EPSS max {e:.2}")),
                        ),
                    ],
                )
            )?;
        }
    }
    if r.without_fix > 0 {
        writeln!(
            out,
            "{}",
            tr_args("pending.without_fix", &[("n", &r.without_fix)])
        )?;
    }
    writeln!(out)?;
    write_sources_footer(out, opts, &r.sources, r.complete)
}

/// `amivuln cve`: what each queried CVE means for this host.
///
/// # Errors
///
/// Propagates write errors.
pub fn render_cve(
    r: &amivuln_core::CveReport,
    opts: RenderOptions,
    out: &mut dyn Write,
) -> io::Result<()> {
    use amivuln_core::CveState;
    for a in &r.answers {
        let id = sanitize_terminal(&a.id);
        match a.state {
            CveState::Affected => {
                writeln!(out, "{id}: {}", paint(opts, "1;31", &tr("cve.affected")))?;
                for h in &a.hits {
                    let fix = h.fixed_in.as_ref().map_or_else(
                        || tr("finding.no_fix"),
                        |v| {
                            tr_args(
                                "cve.fixed_in",
                                &[("version", &sanitize_terminal(&v.to_string()))],
                            )
                        },
                    );
                    writeln!(
                        out,
                        "  {} {}  {}  {}{}{}",
                        sanitize_terminal(&h.package.name),
                        sanitize_terminal(&h.package.version.to_string()),
                        severity_label(opts, h.finding.severity),
                        fix,
                        if h.finding.kev.is_some() { "  KEV" } else { "" },
                        h.finding
                            .epss
                            .as_ref()
                            .map_or(String::new(), |e| format!("  EPSS {:.2}", e.score))
                    )?;
                }
            }
            CveState::NotAffected => {
                writeln!(out, "{}", tr_args("cve.not_affected", &[("id", &id)]))?;
            }
            CveState::Unknown => writeln!(out, "{}", tr_args("cve.unknown", &[("id", &id)]))?,
        }
    }
    writeln!(out)?;
    write_sources_footer(out, opts, &r.sources, r.complete)
}

/// `amivuln restart`: what still runs replaced files.
///
/// # Errors
///
/// Propagates write errors.
pub fn render_restart(
    r: &amivuln_core::RestartReport,
    opts: RenderOptions,
    out: &mut dyn Write,
) -> io::Result<()> {
    if r.items.is_empty() {
        writeln!(out, "{}", tr("restart.none"))?;
    }
    for it in &r.items {
        let pids = it
            .pids
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        let name = it.unit.as_deref().map_or_else(
            || {
                tr_args(
                    "restart.no_service",
                    &[("comm", &sanitize_terminal(&it.comm))],
                )
            },
            sanitize_terminal,
        );
        writeln!(out, "{}  pid {}", paint(opts, "1;33", &name), pids)?;
        let owner = |o: &Option<String>| {
            o.as_ref()
                .map_or_else(String::new, |p| format!("  ({})", sanitize_terminal(p)))
        };
        if let Some((path, pkg)) = &it.exe {
            writeln!(
                out,
                "{}",
                tr_args(
                    "restart.exe",
                    &[("path", &sanitize_terminal(path)), ("owner", &owner(pkg))],
                )
            )?;
        }
        for (path, pkg) in &it.libs {
            writeln!(
                out,
                "{}",
                tr_args(
                    "restart.lib",
                    &[("path", &sanitize_terminal(path)), ("owner", &owner(pkg))],
                )
            )?;
        }
        if let Some(u) = &it.unit {
            writeln!(
                out,
                "{}",
                tr_args("restart.with", &[("unit", &sanitize_terminal(u))])
            )?;
        }
    }
    writeln!(out)?;
    writeln!(
        out,
        "{}",
        tr_args("restart.inspected", &[("n", &r.inspected)])
    )?;
    if r.unreadable > 0 {
        writeln!(
            out,
            "{}",
            tr_args("restart.unreadable", &[("n", &r.unreadable)])
        )?;
    }
    Ok(())
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
            suppressed: std::collections::BTreeMap::new(),
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
                resolved: Vec::new(),
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
