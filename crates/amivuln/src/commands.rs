// SPDX-FileCopyrightText: 2026 amivuln contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Commands that answer a question about the whole host: `cve` and `pending`.

use std::io::Write;

use amivuln_core::{
    Condition, CveReport, CveState, ExitCode, PendingReport, Verdict, cve_answers, exit_code,
    is_complete, pending_updates,
};
use amivuln_report::{RenderOptions, render_cve_report, render_pending_report};

use crate::app::{Env, host_ecosystem, host_meta, settings, usage};
use crate::cli::Cli;
use crate::scan::{evaluate, resolve_scope};

fn now_string(env: &Env) -> String {
    jiff::Timestamp::from_second(env.now)
        .map_or_else(|_| "1970-01-01T00:00:00Z".to_owned(), |t| t.to_string())
}

/// Validates a CVE id from the command line.
fn valid_cve(id: &str) -> bool {
    let Some(rest) = id.strip_prefix("CVE-").or_else(|| id.strip_prefix("cve-")) else {
        return false;
    };
    let Some((year, seq)) = rest.split_once('-') else {
        return false;
    };
    year.len() == 4
        && year.bytes().all(|b| b.is_ascii_digit())
        && (4..=12).contains(&seq.len())
        && seq.bytes().all(|b| b.is_ascii_digit())
}

/// `amivuln cve CVE-ID...`: exit 1 when any installed package is affected.
pub(crate) fn cve(
    cli: &Cli,
    ids: &[String],
    env: &Env,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> ExitCode {
    let (s, _) = match settings(&cli.global, env) {
        Ok(v) => v,
        Err(m) => return usage(err, &m),
    };
    let eco = match host_ecosystem(&cli.global, env) {
        Ok(e) => e,
        Err(m) => return usage(err, &m),
    };
    if let Some(bad) = ids.iter().find(|i| !valid_cve(i)) {
        return usage(
            err,
            &format!("{bad:?} is not a CVE id; expected a form like CVE-2024-6387"),
        );
    }
    let ids: Vec<String> = ids.iter().map(|i| i.to_ascii_uppercase()).collect();
    let (resolved, _) = match resolve_scope(cli, &[], cli.global.packages_from.is_none(), eco) {
        Ok(v) => v,
        Err(m) => return usage(err, &m),
    };
    let ev = match evaluate(cli, &s, env, eco, &resolved, &ids, err) {
        Ok(v) => v,
        Err(code) => return code,
    };
    let known = ev.known.clone();
    let answers = cve_answers(&ids, &ev.targets, |id| known.iter().any(|k| k == id));
    let affected = answers.iter().any(|a| a.state == CveState::Affected);
    let report = CveReport {
        tool_version: env!("CARGO_PKG_VERSION").to_owned(),
        generated_at: now_string(env),
        host: host_meta(eco),
        complete: is_complete(&ev.sources),
        sources: ev.sources,
        answers,
    };
    if let Err(e) = render_cve_report(
        &report,
        s.format,
        RenderOptions {
            color: s.color,
            hide_clean: false,
        },
        out,
    ) {
        if e.kind() != std::io::ErrorKind::BrokenPipe {
            let _ = writeln!(err, "error: cannot write the report: {e}");
        }
        return ExitCode::Internal;
    }
    let mut conditions = Vec::new();
    if !report.complete && s.config.policy.fail_on_incomplete {
        conditions.push(Condition::Incomplete);
    }
    if affected {
        conditions.push(Condition::Violation);
    }
    exit_code(&conditions)
}

/// `amivuln pending`: ranks updates; exit 0 unless `--fail-on` is exceeded.
pub(crate) fn pending(cli: &Cli, env: &Env, out: &mut dyn Write, err: &mut dyn Write) -> ExitCode {
    let (s, _) = match settings(&cli.global, env) {
        Ok(v) => v,
        Err(m) => return usage(err, &m),
    };
    let eco = match host_ecosystem(&cli.global, env) {
        Ok(e) => e,
        Err(m) => return usage(err, &m),
    };
    let (resolved, _) = match resolve_scope(cli, &[], cli.global.packages_from.is_none(), eco) {
        Ok(v) => v,
        Err(m) => return usage(err, &m),
    };
    let ev = match evaluate(cli, &s, env, eco, &resolved, &[], err) {
        Ok(v) => v,
        Err(code) => return code,
    };
    let findings: Vec<_> = ev.targets.iter().flat_map(|t| t.findings.clone()).collect();
    let without_fix = findings
        .iter()
        .filter(|f| matches!(f.verdict, Verdict::Affected { fixed_in: None }))
        .count();
    let report = PendingReport {
        tool_version: env!("CARGO_PKG_VERSION").to_owned(),
        generated_at: now_string(env),
        host: host_meta(eco),
        complete: is_complete(&ev.sources),
        updates: pending_updates(&ev.targets),
        without_fix,
        sources: ev.sources,
    };
    if let Err(e) = render_pending_report(
        &report,
        s.format,
        RenderOptions {
            color: s.color,
            hide_clean: false,
        },
        out,
    ) {
        if e.kind() != std::io::ErrorKind::BrokenPipe {
            let _ = writeln!(err, "error: cannot write the report: {e}");
        }
        return ExitCode::Internal;
    }
    let mut conditions = Vec::new();
    if !report.complete && s.config.policy.fail_on_incomplete {
        conditions.push(Condition::Incomplete);
    }
    if s.policy.violated_by(&findings) {
        conditions.push(Condition::Violation);
    }
    exit_code(&conditions)
}

#[cfg(test)]
mod tests {
    use super::valid_cve;

    #[test]
    fn cve_ids_are_validated() {
        assert!(valid_cve("CVE-2024-6387"));
        assert!(valid_cve("cve-2021-44228"));
        for bad in [
            "",
            "CVE-24-6387",
            "CVE-2024-12",
            "GHSA-xxxx",
            "CVE-2024-63a7",
            "CVE-2024-1234567890123",
        ] {
            assert!(!valid_cve(bad), "{bad:?}");
        }
    }
}
