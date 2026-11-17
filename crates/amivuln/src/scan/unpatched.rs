// SPDX-FileCopyrightText: 2026 amivuln contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! The CVEs Red Hat has not fixed (ADR-0014): loading Red Hat's OVAL file and
//! adding what it says to the findings of a RHEL host.

use amivuln_cache::Lookup;
use amivuln_core::{
    Finding, SourceId, SourceReport, SourceStatus, TargetReport, Verdict, VexStatement, apply_vex,
    sort_findings,
};
use amivuln_sources::http::{Response, Validators};
use amivuln_sources::redhat_oval::UnpatchedIndex;

use super::{Config, DistroData, Duration, Ecosystem, Fetcher, report_of};

const REDHAT_DATA_URL: &str = "https://security.access.redhat.com";

/// Where Red Hat publishes the file for a release; none exists for RHEL 10.
fn oval_url(base: &str, release: u16) -> String {
    let base = base.trim_end_matches('/');
    format!("{base}/data/oval/v2/RHEL{release}/rhel-{release}-including-unpatched.oval.xml.bz2")
}

fn age_of(now: i64, fetched_at: i64) -> Duration {
    Duration::from_secs(u64::try_from(now.saturating_sub(fetched_at)).unwrap_or(0))
}

/// The index for a RHEL host, with its report. `None` for any other host.
///
/// The reduced index is cached under a key of its own: the 650 MB of XML is
/// read only when it is older than the cache lifetime, not on every run.
pub(super) async fn load_unpatched(
    f: &Fetcher<'_>,
    cfg: &Config,
    eco: Ecosystem,
) -> Option<(Option<UnpatchedIndex>, SourceReport)> {
    let Ecosystem::Rhel(release) = eco else {
        return None;
    };
    let source = &cfg.sources.rhel_unpatched;
    let report = |status: SourceStatus, age: Duration| {
        report_of(SourceId::RedHatOval, source.required, status, age)
    };
    if !source.enabled {
        return Some((
            None,
            report(SourceStatus::Skipped("disabled".into()), Duration::ZERO),
        ));
    }
    if !matches!(release, 8 | 9) {
        let why = format!(
            "Red Hat publishes no list of unfixed CVEs for RHEL {release}: the result is a lower bound"
        );
        return Some((None, report(SourceStatus::Skipped(why), Duration::ZERO)));
    }
    let key = format!("redhat-oval-index:{release}");
    let cached = f.cache.get(&key, f.now, f.policy).ok();
    let reduced = |body: &[u8]| UnpatchedIndex::from_reduced(body).map_err(|e| e.to_string());
    let from_cache = |e: &amivuln_cache::Entry, status: SourceStatus| {
        reduced(&e.body)
            .map(|i| (Some(i), report(status, age_of(f.now, e.fetched_at))))
            .map_err(|why| format!("the cached index is unreadable: {why}"))
    };
    if let Some(Lookup::Fresh(e)) = &cached
        && let Ok(found) = from_cache(e, SourceStatus::Ok)
    {
        return Some(found);
    }
    let usable = |c: Option<Lookup>| match c {
        Some(Lookup::Stale(e)) => Some(e),
        _ => None,
    };
    let fail = |why: String, c: Option<Lookup>| match usable(c)
        .map(|e| from_cache(&e, SourceStatus::Stale))
    {
        Some(Ok(found)) => found,
        _ => (None, report(SourceStatus::Failed(why), Duration::ZERO)),
    };
    if f.offline {
        return Some(fail(
            "offline and no cached index within the allowed age".into(),
            cached,
        ));
    }
    let base = source.url.as_deref().unwrap_or(REDHAT_DATA_URL);
    let body = match f
        .http
        .get(&oval_url(base, release), &Validators::default())
        .await
    {
        Ok(Response::Fresh { body, .. }) => body,
        Ok(Response::NotModified) => {
            return Some(fail("unexpected 304 answer".into(), cached));
        }
        Err(e) => return Some(fail(e.to_string(), cached)),
    };
    // Reading the XML takes seconds of CPU. Nothing else waits on this
    // source, so it runs here rather than on a thread of its own.
    let index = match UnpatchedIndex::parse_bz2(&body) {
        Ok(i) => i,
        Err(e) => return Some(fail(e.to_string(), cached)),
    };
    // A cache that cannot be written only costs the next run a re-read.
    let _ = f.cache.put(&key, &index.to_reduced(), None, None, f.now);
    Some((Some(index), report(SourceStatus::Ok, Duration::ZERO)))
}

/// Adds to each RHEL package the CVEs Red Hat lists as unfixed for it. A CVE
/// the distribution data already has an answer for keeps that answer (a fix
/// exists); only the ones it cannot show are added, as affected with no fix.
pub(super) fn add_unpatched(
    reports: &mut [TargetReport],
    index: &UnpatchedIndex,
    known: Option<&DistroData>,
    vex: &[VexStatement],
) {
    for target in reports {
        if !matches!(target.package.ecosystem, Ecosystem::Rhel(_)) {
            continue;
        }
        let mut added = false;
        // Red Hat names a component by binary or by source package.
        let names = [
            Some(target.package.name.as_str()),
            target.package.source_name.as_deref(),
        ];
        let mut unfixed: Vec<_> = names
            .into_iter()
            .flatten()
            .flat_map(|n| index.for_component(n))
            .collect();
        unfixed.sort_by(|a, b| a.cve.cmp(&b.cve).then(a.state.cmp(&b.state)));
        unfixed.dedup_by(|a, b| a.cve == b.cve);
        for u in unfixed {
            if target.findings.iter().any(|f| f.id == u.cve)
                || known.is_some_and(|d| d.knows(&u.cve))
            {
                continue;
            }
            let mut verdict = Verdict::Affected { fixed_in: None };
            apply_vex(&mut verdict, vex, &u.cve);
            target
                .findings
                .push(Finding::new(u.cve.clone(), u.severity, verdict));
            added = true;
        }
        if added {
            sort_findings(&mut target.findings);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use amivuln_core::{PackageRef, Provenance, Severity, Version};

    fn index() -> UnpatchedIndex {
        UnpatchedIndex::parse_bz2(include_bytes!(
            "../../../../tests/fixtures/redhat-oval/small.oval.xml.bz2"
        ))
        .unwrap()
    }

    fn target(name: &str, eco: Ecosystem, findings: Vec<Finding>) -> TargetReport {
        TargetReport {
            input: name.to_owned(),
            package: PackageRef {
                name: name.to_owned(),
                source_name: None,
                version: Version::Rpm("1-1.el9".parse().unwrap()),
                arch: None,
                upstream: None,
                ecosystem: eco,
                provenance: Provenance::PackageDb,
                slot: None,
            },
            findings,
            resolved: Vec::new(),
        }
    }

    #[test]
    fn the_url_names_the_release_and_has_none_for_rhel_10() {
        assert_eq!(
            oval_url("https://security.access.redhat.com/", 9),
            "https://security.access.redhat.com/data/oval/v2/RHEL9/rhel-9-including-unpatched.oval.xml.bz2"
        );
    }

    #[test]
    fn an_unfixed_cve_is_added_as_affected_with_no_fix() {
        let mut reports = vec![target("openssl", Ecosystem::Rhel(9), Vec::new())];
        add_unpatched(&mut reports, &index(), None, &[]);
        let f = &reports[0].findings;
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].id, "CVE-2024-0001");
        assert_eq!(f[0].severity, Severity::High);
        assert_eq!(f[0].verdict, Verdict::Affected { fixed_in: None });
    }

    #[test]
    fn the_source_package_name_is_tried_too() {
        let mut t = target("openssl-libs", Ecosystem::Rhel(9), Vec::new());
        t.package.source_name = Some("openssl".into());
        let mut reports = vec![t];
        add_unpatched(&mut reports, &index(), None, &[]);
        assert_eq!(reports[0].findings.len(), 1);
    }

    #[test]
    fn a_cve_already_judged_keeps_its_verdict_and_other_hosts_are_untouched() {
        let patched = Finding::new("CVE-2024-0001", Severity::High, Verdict::Patched);
        let mut reports = vec![
            target("openssl", Ecosystem::Rhel(9), vec![patched.clone()]),
            target("openssl", Ecosystem::Rocky(9), Vec::new()),
            target("nginx", Ecosystem::Rhel(9), Vec::new()),
        ];
        add_unpatched(&mut reports, &index(), None, &[]);
        assert_eq!(reports[0].findings, vec![patched]);
        assert!(reports[1].findings.is_empty());
        assert!(reports[2].findings.is_empty());
    }
}
