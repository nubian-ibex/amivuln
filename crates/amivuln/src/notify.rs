// SPDX-FileCopyrightText: 2026 amivuln contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! `[notify]`: POST a compact run summary to a webhook.
//!
//! The payload carries the same facts as the JSON report's headline (host,
//! completeness, score, totals, finding ids) and nothing else. A failed
//! delivery is a warning on stderr; it never changes the exit code, because
//! the policy decision already happened.

use std::io::Write;

use amivuln_core::{ExitCode, RunReport, score};
use serde_json::{Value, json};

use crate::app::Settings;
use amivuln_report::json_severity;

/// Largest payload accepted; the summary is far smaller.
const MAX_PAYLOAD_BYTES: usize = 64 * 1024;

/// Reads the bearer token file (at most 4 KiB, one line).
fn read_bearer(path: &str) -> Result<String, String> {
    let text =
        std::fs::read_to_string(path).map_err(|e| format!("notify.bearer_file {path:?}: {e}"))?;
    let line = text.lines().next().unwrap_or("").trim();
    if line.is_empty() || line.len() > 4096 {
        return Err(format!(
            "notify.bearer_file {path:?} must hold a 1 to 4096 byte token"
        ));
    }
    Ok(line.to_owned())
}

/// Whether `[notify].on` asks for a notification about this run.
fn wanted(s: &Settings, report: &RunReport, violated: bool) -> bool {
    match s.config.notify.on.as_str() {
        "always" => true,
        "incomplete" => !report.complete,
        // `violation`, and any unknown value the config loader already rejected.
        _ => violated,
    }
}

/// The webhook payload: headline facts only.
fn payload(report: &RunReport, violated: bool) -> Value {
    let findings: Vec<_> = report
        .targets
        .iter()
        .flat_map(|t| &t.findings)
        .filter(|f| !report.suppressed.contains_key(&f.id))
        .collect();
    let owned: Vec<amivuln_core::Finding> = findings.iter().map(|f| (*f).clone()).collect();
    let summary_of = amivuln_core::Summary::of(&owned);
    let sc = score(&owned);
    json!({
        "tool": "amivuln",
        "version": report.tool_version,
        "generated_at": report.generated_at,
        "host": {
            "os_id": report.host.os_id,
            "os_version": report.host.os_version,
            "arch": report.host.arch,
        },
        "complete": report.complete,
        "violated": violated,
        "unresolved": report.unresolved.len(),
        "suppressed": report.suppressed.len(),
        "summary": {
            "critical": summary_of.critical,
            "high": summary_of.high,
            "medium": summary_of.medium,
            "low": summary_of.low,
            "kev": summary_of.kev,
            "unverified": summary_of.unverified,
        },
        "score": {"points": sc.points, "grade": sc.grade.letter().to_string()},
        "findings": findings.iter().take(100).map(|f| json!({
            "id": f.id,
            "severity": json_severity(f.severity),
            "kev": f.kev.is_some(),
        })).collect::<Vec<_>>(),
    })
}

/// Sends the notification when configured. Warnings go to `err`; the exit
/// code never changes because of delivery problems.
pub(crate) fn maybe_notify(
    report: &RunReport,
    s: &Settings,
    violated: bool,
    err: &mut dyn Write,
) -> ExitCode {
    let Some(url) = s.config.notify.webhook.clone() else {
        return ExitCode::Success;
    };
    if !wanted(s, report, violated) {
        return ExitCode::Success;
    }
    let bearer = match &s.config.notify.bearer_file {
        Some(p) => match read_bearer(p) {
            Ok(t) => Some(t),
            Err(e) => {
                let _ = writeln!(err, "warning: {e}");
                return ExitCode::Usage;
            }
        },
        None => None,
    };
    let body = payload(report, violated).to_string();
    if body.len() > MAX_PAYLOAD_BYTES {
        let _ = writeln!(err, "warning: notify payload too large; skipped");
        return ExitCode::Success;
    }
    let mut config = match crate::scan::http_config(s) {
        Ok(c) => c,
        Err(e) => {
            let _ = writeln!(err, "warning: notify failed: {e}");
            return ExitCode::Success;
        }
    };
    // A POST that reached the server may have been processed even when the
    // answer was a 5xx, so a retry could send the same alert twice.
    config.retry.retries = 0;
    let http = match amivuln_sources::http::HttpClient::new(config) {
        Ok(c) => c,
        Err(e) => {
            let _ = writeln!(err, "warning: notify failed: {e}");
            return ExitCode::Success;
        }
    };
    let send = async { http.post_bearer(&url, &body, bearer.as_deref()).await };
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .enable_io()
        .build();
    let result = match rt {
        Ok(rt) => rt.block_on(send),
        Err(e) => Err(amivuln_sources::http::HttpError::Network(e.to_string())),
    };
    if let Err(e) = result {
        let _ = writeln!(err, "warning: notify failed: {e}");
    }
    ExitCode::Success
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, Notify};
    use amivuln_core::{Finding, HostMeta, Severity, Verdict};
    use std::time::Duration;

    fn settings(on: &str, webhook: Option<&str>) -> Settings {
        let cfg = Config {
            notify: Notify {
                webhook: webhook.map(str::to_owned),
                bearer_file: None,
                on: on.to_owned(),
            },
            ..Config::default()
        };
        Settings {
            config: cfg,
            format: amivuln_report::Format::Json,
            color: false,
            policy: amivuln_core::Policy {
                fail_on: amivuln_core::FailOn::None,
                fail_on_epss: None,
                strict: false,
            },
            offline: false,
            cache_ttl: 0,
            stale_max_age: 0,
            timeout: Duration::from_secs(1),
            net: crate::config::Network::default(),
            cooldown: Duration::from_secs(30),
            min_interval: None,
            ignores: Vec::new(),
            vex: Vec::new(),
            baseline: None,
        }
    }

    fn report(complete: bool) -> RunReport {
        RunReport {
            tool_version: "0.0.0".to_owned(),
            generated_at: "2026-11-09T00:00:00Z".to_owned(),
            host: HostMeta {
                os_id: "fedora".to_owned(),
                os_version: "43".to_owned(),
                arch: "x86_64".to_owned(),
            },
            complete,
            suppressed: std::collections::BTreeMap::new(),
            sources: Vec::new(),
            targets: vec![amivuln_core::TargetReport {
                input: "nginx".to_owned(),
                package: amivuln_core::PackageRef {
                    ecosystem: amivuln_core::Ecosystem::Fedora(43),
                    name: "nginx".to_owned(),
                    source_name: None,
                    version: amivuln_core::Version::Rpm(
                        "1:1.26.2-1.fc43".parse().unwrap_or_else(|n| match n {}),
                    ),
                    arch: None,
                    provenance: amivuln_core::Provenance::PackageDb,
                },
                findings: vec![Finding::new(
                    "CVE-2026-28356",
                    Severity::High,
                    Verdict::Affected { fixed_in: None },
                )],
                resolved: Vec::new(),
            }],
            unresolved: Vec::new(),
        }
    }

    #[test]
    fn payload_carries_headline_facts_only() {
        let p = payload(&report(true), true);
        let text = p.to_string();
        assert!(text.contains("\"violated\":true"));
        assert!(text.contains("\"os_id\":\"fedora\""));
        assert!(text.contains("CVE-2026-28356"));
        assert!(!text.contains("/usr/bin"), "no paths in the payload");
        assert!(text.len() < MAX_PAYLOAD_BYTES);
    }

    #[test]
    fn conditions() {
        let r = report(false);
        assert!(wanted(&settings("always", None), &r, false));
        assert!(wanted(&settings("incomplete", None), &r, false));
        assert!(!wanted(&settings("violation", None), &r, false));
        assert!(wanted(&settings("violation", None), &r, true));
    }

    #[test]
    fn a_missing_bearer_file_is_reported() {
        let mut s = settings("always", Some("https://ntfy.sh/t"));
        s.config.notify.bearer_file = Some("/nonexistent/token".to_owned());
        let mut err = Vec::new();
        let code = maybe_notify(&report(true), &s, true, &mut err);
        assert_eq!(code, ExitCode::Usage);
        assert!(
            String::from_utf8(err)
                .unwrap()
                .contains("notify.bearer_file")
        );
    }

    #[test]
    fn no_webhook_is_a_no_op() {
        let mut err = Vec::new();
        let code = maybe_notify(&report(true), &settings("always", None), true, &mut err);
        assert_eq!(code, ExitCode::Success);
        assert!(err.is_empty());
    }
}
