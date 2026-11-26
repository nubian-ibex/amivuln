// SPDX-FileCopyrightText: 2026 amivuln contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! The CVEs Red Hat has not fixed (ADR-0014): loading Red Hat's OVAL file and
//! adding what it says to the packages of the release it describes.

use amivuln_cache::Lookup;
use amivuln_core::{
    Finding, SourceId, SourceReport, SourceStatus, TargetReport, Verdict, VexStatement, apply_vex,
    sort_findings,
};
use amivuln_sources::http::{Response, Validators};
use amivuln_sources::redhat_oval::UnpatchedIndex;

use super::{Config, Duration, Ecosystem, Fetcher, report_of};

const REDHAT_DATA_URL: &str = "https://security.access.redhat.com";

/// Where Red Hat publishes the file for a release; none exists for RHEL 10.
fn oval_url(base: &str, release: u16) -> String {
    let base = base.trim_end_matches('/');
    format!("{base}/data/oval/v2/RHEL{release}/rhel-{release}-including-unpatched.oval.xml.bz2")
}

fn age_of(now: i64, fetched_at: i64) -> Duration {
    Duration::from_secs(u64::try_from(now.saturating_sub(fetched_at)).unwrap_or(0))
}

/// The RHEL major release whose unfixed list covers a package: that of a RHEL
/// package or of one from a rebuild (Rocky Linux and `AlmaLinux`).
pub(super) fn release_of(eco: Ecosystem) -> Option<u16> {
    match eco {
        Ecosystem::Rhel(value) => Some(Ecosystem::rhel_release(value).0),
        Ecosystem::Rocky(major) | Ecosystem::Alma(major) => Some(major),
        _ => None,
    }
}

/// One report for the lists of several releases: a failure is told first, then
/// a release without a list, then stale data.
pub(super) fn merge_reports(a: SourceReport, b: SourceReport) -> SourceReport {
    let rank = |s: &SourceStatus| match s {
        SourceStatus::Failed(_) => 3,
        SourceStatus::Skipped(_) => 2,
        SourceStatus::Stale => 1,
        SourceStatus::Ok => 0,
    };
    let age = a.age.max(b.age);
    let mut worst = if rank(&b.status) > rank(&a.status) {
        b
    } else {
        a
    };
    worst.age = age;
    worst
}

/// The index of one RHEL major release, with its report.
///
/// A rebuild ships Red Hat's sources, so a CVE Red Hat has not fixed has no fix
/// in the rebuild either, and the file of the same major release applies. The
/// reverse does not: a fix Red Hat has shipped and the rebuild has not yet is
/// not in this file and stays invisible until the rebuild's advisory exists.
///
/// The reduced index is cached under a key of its own: the 650 MB of XML is
/// read only when it is older than the cache lifetime, not on every run.
pub(super) async fn load_unpatched(
    f: &Fetcher<'_>,
    cfg: &Config,
    release: u16,
) -> (Option<UnpatchedIndex>, SourceReport) {
    let source = &cfg.sources.rhel_unpatched;
    let report = |status: SourceStatus, age: Duration| {
        report_of(SourceId::RedHatOval, source.required, status, age)
    };
    if !source.enabled {
        return (
            None,
            report(SourceStatus::Skipped("disabled".into()), Duration::ZERO),
        );
    }
    if !matches!(release, 8 | 9) {
        let why = format!(
            "Red Hat publishes no list of unfixed CVEs for RHEL {release}: the result is a lower bound"
        );
        return (None, report(SourceStatus::Skipped(why), Duration::ZERO));
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
        return found;
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
        return fail(
            "offline and no cached index within the allowed age".into(),
            cached,
        );
    }
    let base = source.url.as_deref().unwrap_or(REDHAT_DATA_URL);
    let body = match f
        .http
        .get(&oval_url(base, release), &Validators::default())
        .await
    {
        Ok(Response::Fresh { body, .. }) => body,
        Ok(Response::NotModified) => {
            return fail("unexpected 304 answer".into(), cached);
        }
        Err(e) => return fail(e.to_string(), cached),
    };
    // Reading the XML takes seconds of CPU. Nothing else waits on this
    // source, so it runs here rather than on a thread of its own.
    let index = match UnpatchedIndex::parse_bz2(&body) {
        Ok(i) => i,
        Err(e) => return fail(e.to_string(), cached),
    };
    // A cache that cannot be written only costs the next run a re-read.
    let _ = f.cache.put(&key, &index.to_reduced(), None, None, f.now);
    (Some(index), report(SourceStatus::Ok, Duration::ZERO))
}

/// Adds to each package of `release` (RHEL, Rocky Linux or `AlmaLinux`) the
/// CVEs Red Hat lists as unfixed for it. A CVE the package already has an answer
/// for, open or settled, keeps it; only the ones it cannot show are added, as
/// affected with no fix. What was answered for another package says nothing:
/// the same CVE can be fixed in one and not in the other.
pub(super) fn add_unpatched(
    reports: &mut [TargetReport],
    release: u16,
    index: &UnpatchedIndex,
    vex: &[VexStatement],
) {
    for target in reports {
        if release_of(target.package.ecosystem) != Some(release) {
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
            if target
                .findings
                .iter()
                .chain(&target.resolved)
                .any(|f| f.id == u.cve)
            {
                continue;
            }
            let mut verdict = Verdict::Affected { fixed_in: None };
            apply_vex(&mut verdict, vex, &u.cve);
            let mut finding = Finding::new(u.cve.clone(), u.severity, verdict);
            finding.vendor_state = Some(u.state.as_str().to_owned());
            target.findings.push(finding);
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
                source_vr: None,
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
            running_kernel: false,
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
        add_unpatched(&mut reports, 9, &index(), &[]);
        let f = &reports[0].findings;
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].id, "CVE-2024-0001");
        assert_eq!(f[0].severity, Severity::High);
        assert_eq!(f[0].verdict, Verdict::Affected { fixed_in: None });
        // Red Hat's own state is kept for the output.
        assert!(f[0].vendor_state.is_some(), "{:?}", f[0]);
    }

    #[test]
    fn rocky_and_alma_get_the_unfixed_cves_of_their_rhel() {
        let mut reports = vec![
            target("openssl", Ecosystem::Rocky(9), Vec::new()),
            target("openssl", Ecosystem::Alma(9), Vec::new()),
        ];
        add_unpatched(&mut reports, 9, &index(), &[]);
        for r in &reports {
            assert_eq!(r.findings.len(), 1, "{:?}", r.package.ecosystem);
            assert_eq!(r.findings[0].id, "CVE-2024-0001");
            assert_eq!(r.findings[0].verdict, Verdict::Affected { fixed_in: None });
        }
    }

    #[test]
    fn the_source_package_name_is_tried_too() {
        let mut t = target("openssl-libs", Ecosystem::Rhel(9), Vec::new());
        t.package.source_name = Some("openssl".into());
        let mut reports = vec![t];
        add_unpatched(&mut reports, 9, &index(), &[]);
        assert_eq!(reports[0].findings.len(), 1);
    }

    #[test]
    fn a_cve_settled_for_the_package_is_not_added_again() {
        let settled = Finding::new("CVE-2024-0001", Severity::High, Verdict::Patched);
        let mut report = target("openssl", Ecosystem::Rhel(9), Vec::new());
        report.resolved = vec![settled];
        let mut reports = vec![report];
        add_unpatched(&mut reports, 9, &index(), &[]);
        assert!(reports[0].findings.is_empty(), "{:?}", reports[0]);
    }

    #[test]
    fn a_cve_already_judged_keeps_its_verdict_and_other_hosts_are_untouched() {
        let patched = Finding::new("CVE-2024-0001", Severity::High, Verdict::Patched);
        let mut reports = vec![
            target("openssl", Ecosystem::Rhel(9), vec![patched.clone()]),
            target("openssl", Ecosystem::Debian(12), Vec::new()),
            target("nginx", Ecosystem::Rhel(9), Vec::new()),
        ];
        add_unpatched(&mut reports, 9, &index(), &[]);
        assert_eq!(reports[0].findings, vec![patched]);
        assert!(reports[1].findings.is_empty());
        assert!(reports[2].findings.is_empty());
    }
}
