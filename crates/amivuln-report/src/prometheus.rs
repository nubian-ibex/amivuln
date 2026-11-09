// SPDX-FileCopyrightText: 2026 amivuln contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Prometheus text exposition, for the `node_exporter` textfile collector.
//!
//! Labels are fixed vocabularies (severity, source id): no package names,
//! hostnames or paths, so nothing host-identifying reaches a metrics store.

use std::io::{self, Write};

use amivuln_core::{RunReport, Severity, SourceStatus, Verdict};

use crate::json::json_severity;

const SEVERITIES: [Severity; 5] = [
    Severity::Critical,
    Severity::High,
    Severity::Medium,
    Severity::Low,
    Severity::Unknown,
];

/// Seconds since the Unix epoch for `YYYY-MM-DDTHH:MM:SSZ`, or `None` when
/// the text is not in that exact UTC form.
fn epoch_of(rfc3339: &str) -> Option<i64> {
    let at = |i: usize| rfc3339.as_bytes().get(i).copied();
    let shaped = rfc3339.len() == 20
        && at(4) == Some(b'-')
        && at(7) == Some(b'-')
        && at(10) == Some(b'T')
        && at(19) == Some(b'Z');
    if !shaped {
        return None;
    }
    let num = |r: core::ops::Range<usize>| rfc3339.get(r)?.parse::<i64>().ok();
    let (y, m, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (hh, mm, ss) = (num(11..13)?, num(14..16)?, num(17..19)?);
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) || hh > 23 || mm > 59 || ss > 60 {
        return None;
    }
    // Days from civil (Howard Hinnant's algorithm).
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(days * 86_400 + hh * 3600 + mm * 60 + ss)
}

/// Writes the report as Prometheus text metrics.
///
/// # Errors
///
/// Propagates write errors.
pub fn render_prometheus(r: &RunReport, out: &mut dyn Write) -> io::Result<()> {
    writeln!(
        out,
        "# HELP amivuln_findings Affected findings by severity and KEV membership."
    )?;
    writeln!(out, "# TYPE amivuln_findings gauge")?;
    for sev in SEVERITIES {
        for kev in [false, true] {
            let n = r
                .targets
                .iter()
                .flat_map(|t| &t.findings)
                .filter(|f| {
                    matches!(f.verdict, Verdict::Affected { .. })
                        && f.severity == sev
                        && f.kev.is_some() == kev
                })
                .count();
            writeln!(
                out,
                "amivuln_findings{{severity=\"{}\",kev=\"{kev}\"}} {n}",
                json_severity(sev)
            )?;
        }
    }
    let unverified = r
        .targets
        .iter()
        .flat_map(|t| &t.findings)
        .filter(|f| matches!(f.verdict, Verdict::Unverified))
        .count();
    writeln!(
        out,
        "# HELP amivuln_unverified_findings Findings without a distro statement."
    )?;
    writeln!(out, "# TYPE amivuln_unverified_findings gauge")?;
    writeln!(out, "amivuln_unverified_findings {unverified}")?;

    writeln!(
        out,
        "# HELP amivuln_source_up 1 when the source answered (fresh or stale), 0 when it failed."
    )?;
    writeln!(out, "# TYPE amivuln_source_up gauge")?;
    for s in r
        .sources
        .iter()
        .filter(|s| !matches!(s.status, SourceStatus::Skipped(_)))
    {
        let up = u8::from(!matches!(s.status, SourceStatus::Failed(_)));
        writeln!(
            out,
            "amivuln_source_up{{source=\"{}\"}} {up}",
            s.source.as_str()
        )?;
    }
    writeln!(
        out,
        "# HELP amivuln_source_age_seconds Age of the data used from each source."
    )?;
    writeln!(out, "# TYPE amivuln_source_age_seconds gauge")?;
    for s in r
        .sources
        .iter()
        .filter(|s| matches!(s.status, SourceStatus::Ok | SourceStatus::Stale))
    {
        writeln!(
            out,
            "amivuln_source_age_seconds{{source=\"{}\"}} {}",
            s.source.as_str(),
            s.age.as_secs()
        )?;
    }
    writeln!(
        out,
        "# HELP amivuln_run_complete 1 when no required source failed."
    )?;
    writeln!(out, "# TYPE amivuln_run_complete gauge")?;
    writeln!(out, "amivuln_run_complete {}", u8::from(r.complete))?;
    if let Some(ts) = epoch_of(&r.generated_at) {
        writeln!(
            out,
            "# HELP amivuln_last_run_timestamp_seconds Unix time of the run."
        )?;
        writeln!(out, "# TYPE amivuln_last_run_timestamp_seconds gauge")?;
        writeln!(out, "amivuln_last_run_timestamp_seconds {ts}")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::text::fixtures::report;

    #[test]
    fn epoch_matches_known_instants() {
        assert_eq!(epoch_of("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(epoch_of("2000-03-01T00:00:00Z"), Some(951_868_800));
        assert_eq!(epoch_of("2026-11-08T23:44:21Z"), Some(1_794_181_461));
        assert_eq!(epoch_of("2026-11-08 23:44:21"), None);
        assert_eq!(epoch_of("2026-13-08T23:44:21Z"), None);
    }

    #[test]
    fn metrics_have_fixed_labels_and_no_host_data() {
        let mut buf = Vec::new();
        render_prometheus(&report(true), &mut buf).unwrap();
        let text = String::from_utf8(buf).unwrap();
        assert!(text.contains("amivuln_run_complete 1"));
        assert!(text.contains("amivuln_findings{severity=\"high\",kev=\"false\"}"));
        assert!(text.contains("amivuln_source_up{source=\""));
        assert!(!text.contains("openssl"), "package names must not leak");
        for line in text.lines().filter(|l| !l.starts_with('#')) {
            let (_, value) = line.rsplit_once(' ').unwrap();
            assert!(value.parse::<i64>().is_ok(), "{line}");
        }
        let mut buf = Vec::new();
        render_prometheus(&report(false), &mut buf).unwrap();
        assert!(
            String::from_utf8(buf)
                .unwrap()
                .contains("amivuln_run_complete 0")
        );
    }
}
