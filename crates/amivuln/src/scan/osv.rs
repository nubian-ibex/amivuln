// SPDX-FileCopyrightText: 2026 amivuln contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! OSV loading: one batched query per chunk of packages, then the advisory documents.

use super::{
    Config, DistroData, Duration, Ecosystem, FetchError, Fetched, Fetcher, OsvData, PackageRef,
    SourceId, SourceReport, SourceStatus, describe, fetch_cached_body, report_of, worse,
};

pub(super) const OSV_URL: &str = "https://api.osv.dev";

/// Most advisory documents fetched per run.
pub(super) const MAX_OSV_ADVISORIES: usize = 5000;

/// Package queries per OSV `querybatch` request (the endpoint's limit).
pub(super) const OSV_BATCH: usize = 1000;

/// Advisory documents fetched at the same time.
pub(super) const ADVISORY_PARALLEL: usize = 8;

/// Fetches the advisories of every package, parsing each against the OSV
/// ecosystem that package was asked in, and enforces the fetch limit.
pub(super) async fn fetch_all_advisories(
    f: &Fetcher<'_>,
    base: &str,
    asked: &[(String, Vec<String>)],
) -> (Vec<amivuln_sources::osv::OsvEntry>, SourceStatus, Duration) {
    let mut entries = Vec::new();
    let mut status = SourceStatus::Ok;
    let mut age = Duration::ZERO;
    let distinct: std::collections::BTreeSet<&String> = asked.iter().map(|(eco, _)| eco).collect();
    for osv_eco in distinct {
        let mut mine: Vec<String> = asked
            .iter()
            .filter(|(e, _)| e == osv_eco)
            .flat_map(|(_, found)| found.iter().cloned())
            .collect();
        mine.sort();
        mine.dedup();
        let (mut got, adv_status, adv_age) =
            fetch_advisories(f, base, osv_eco.as_str(), &mine).await;
        entries.append(&mut got);
        status = worse(status, adv_status);
        age = age.max(adv_age);
    }
    (entries, status, age)
}

/// The version string OSV is asked about, or `None` when the version kind does
/// not belong to the ecosystem (an RPM version for Debian, for example).
pub(super) fn osv_query_version(eco: Ecosystem, version: &amivuln_core::Version) -> Option<String> {
    match version {
        amivuln_core::Version::Deb(v) => Some(v.to_string()),
        amivuln_core::Version::Rpm(v)
            if matches!(
                eco,
                Ecosystem::Rocky(_)
                    | Ecosystem::Alma(_)
                    | Ecosystem::Rhel(_)
                    | Ecosystem::Opensuse(_)
            ) =>
        {
            Some(v.to_string())
        }
        amivuln_core::Version::Apk(v) if matches!(eco, Ecosystem::Alpine(_)) => Some(v.to_string()),
        amivuln_core::Version::Semver(v) if eco.is_language() => Some(v.to_string()),
        _ => None,
    }
}

/// Whether a package given without its source can be judged by its name.
/// Debian, Ubuntu, Alpine and openSUSE file advisories by source package, so a
/// name OSV holds no advisory under may be a binary's, and finding nothing for
/// it says nothing (ADR-0019).
async fn name_coverage(
    f: &Fetcher<'_>,
    base: &str,
    packages: &[(String, amivuln_core::PackageRef)],
    ids_by_package: &[Vec<String>],
) -> SourceStatus {
    let unnamed: std::collections::BTreeMap<(&str, String), Ecosystem> = packages
        .iter()
        .zip(ids_by_package)
        .filter(|((_, p), ids)| {
            ids.is_empty()
                && p.source_name.is_none()
                && p.provenance == amivuln_core::Provenance::UserInput
                && matches!(
                    p.ecosystem,
                    Ecosystem::Debian(_)
                        | Ecosystem::Ubuntu(_)
                        | Ecosystem::Alpine(_)
                        | Ecosystem::Opensuse(_)
                )
        })
        .filter_map(|((_, p), _)| {
            let ecosystem = p.ecosystem.osv_ecosystem()?;
            Some(((p.name.as_str(), ecosystem), p.ecosystem))
        })
        .collect();
    let mut queries = Vec::new();
    for ((name, ecosystem), eco) in &unnamed {
        let version = probe_version(*eco);
        let body = match amivuln_sources::osv::batch_request(name, ecosystem, version) {
            Ok(body) => body,
            Err(e) => return SourceStatus::Failed(e.to_string()),
        };
        queries.push(OsvQuery {
            name,
            ecosystem: ecosystem.clone(),
            version: version.to_owned(),
            body,
        });
    }
    let mut unknown = Vec::new();
    for (query, answer) in queries.iter().zip(query_osv(f, base, &queries).await) {
        let ids = answer
            .map_err(|e| describe(&e))
            .and_then(|d| amivuln_sources::osv::parse_batch(&d.body).map_err(|e| e.to_string()));
        match ids {
            Ok(ids) if ids.is_empty() => unknown.push(query.name),
            Ok(_) => {}
            Err(why) => return SourceStatus::Failed(why),
        }
    }
    let Some(first) = unknown.first() else {
        return SourceStatus::Ok;
    };
    let more = match unknown.len() - 1 {
        0 => String::new(),
        n => format!(" (and {n} more)"),
    };
    SourceStatus::Failed(format!(
        "OSV has no advisory under {first}{more}, given without a source package: it may be a binary's name, so the result is not complete"
    ))
}

/// The names and versions OSV is asked about for one package.
fn questions<'a>(pkg: &'a amivuln_core::PackageRef, version: &str) -> Vec<(&'a str, String)> {
    let mut asked = vec![(pkg.osv_name(), version.to_owned())];
    // Rocky Linux files many advisories under the source package alone
    // (ADR-0018). A source release of its own is asked from epoch 0 on: the
    // source's epoch is not known, and the verdict compares the release.
    if let (Ecosystem::Rocky(_), Some(source)) = (pkg.ecosystem, pkg.source_name.as_deref())
        && source != pkg.name
    {
        let at = pkg
            .source_vr
            .as_ref()
            .map_or_else(|| version.to_owned(), |vr| format!("0:{vr}"));
        asked.push((source, at));
    }
    asked
}

/// Splits advisories back per package so each is judged only against the
/// package it was found for.
pub(super) fn split_per_package(
    entries: &[amivuln_sources::osv::OsvEntry],
    ids_by_package: &[Vec<String>],
) -> Vec<OsvData> {
    let mut by_advisory: std::collections::HashMap<&str, Vec<&amivuln_sources::osv::OsvEntry>> =
        std::collections::HashMap::new();
    for e in entries {
        by_advisory.entry(e.advisory.as_str()).or_default().push(e);
    }
    ids_by_package
        .iter()
        .map(|mine| {
            OsvData::from_entries(
                mine.iter()
                    .filter_map(|id| by_advisory.get(id.as_str()))
                    .flatten()
                    .map(|e| (*e).clone())
                    .collect(),
            )
        })
        .collect()
}

/// Fetches one advisory document and parses it for the ecosystem. A failure
/// is reported in the status; the entries are then empty.
pub(super) async fn fetch_advisory(
    f: &Fetcher<'_>,
    base: &str,
    osv_eco: &str,
    id: &str,
) -> (Vec<amivuln_sources::osv::OsvEntry>, SourceStatus, Duration) {
    let url = format!("{base}/v1/vulns/{id}");
    let key = format!("osv-advisory:{id}");
    let doc = match fetch_cached_body(&f.ctx(), &key, &url, None).await {
        Ok(d) => d,
        Err(e) => {
            return (
                Vec::new(),
                SourceStatus::Failed(describe(&e)),
                Duration::ZERO,
            );
        }
    };
    match amivuln_sources::osv::OsvData::parse_advisory(&doc.body, osv_eco) {
        Ok(parsed) => {
            let entries = parsed
                .entries()
                .into_iter()
                .map(|e| amivuln_sources::osv::OsvEntry {
                    advisory: id.to_owned(),
                    ..e
                })
                .collect();
            (entries, doc.status, doc.age)
        }
        Err(e) => (
            Vec::new(),
            SourceStatus::Failed(e.to_string()),
            Duration::ZERO,
        ),
    }
}

/// Fetches the advisory documents for `ids`, a few at a time. More than
/// [`MAX_OSV_ADVISORIES`] ids are cut and the status says so.
pub(super) async fn fetch_advisories(
    f: &Fetcher<'_>,
    base: &str,
    osv_eco: &str,
    ids: &[String],
) -> (Vec<amivuln_sources::osv::OsvEntry>, SourceStatus, Duration) {
    use futures_util::StreamExt;
    let mut status = SourceStatus::Ok;
    if ids.len() > MAX_OSV_ADVISORIES {
        status = SourceStatus::Failed(format!(
            "{} advisories for {osv_eco} exceeded the fetch limit of {MAX_OSV_ADVISORIES}",
            ids.len()
        ));
    }
    // `buffered` keeps the order of `ids`, so the output stays deterministic.
    let results: Vec<_> = futures_util::stream::iter(ids.iter().take(MAX_OSV_ADVISORIES))
        .map(|id| fetch_advisory(f, base, osv_eco, id))
        .buffered(ADVISORY_PARALLEL)
        .collect()
        .await;
    let mut entries = Vec::new();
    let mut age = Duration::ZERO;
    for (mut got, s, a) in results {
        entries.append(&mut got);
        status = worse(status, s);
        age = age.max(a);
    }
    (entries, status, age)
}

/// One package asked about in one OSV ecosystem.
pub(super) struct OsvQuery<'a> {
    name: &'a str,
    ecosystem: String,
    version: String,
    /// The one-query request document, which also names the cache entry.
    body: String,
}

/// A query with the cache key and the answer found so far.
pub(super) struct Slot<'q, 'a> {
    query: &'q OsvQuery<'a>,
    key: String,
    answer: Option<Result<Fetched, FetchError>>,
}

/// The answers to `queries`, in order. Fresh cache entries are used as they
/// are, the rest go to OSV in batches of [`OSV_BATCH`], and each answer is
/// cached as the answer of its own query. Whatever a batch could not answer
/// falls back to the per-query path (stale cache, offline database, error).
pub(super) async fn query_osv(
    f: &Fetcher<'_>,
    base: &str,
    queries: &[OsvQuery<'_>],
) -> Vec<Result<Fetched, FetchError>> {
    let url = format!("{base}/v1/querybatch");
    let mut slots: Vec<Slot<'_, '_>> = queries
        .iter()
        .map(|query| Slot {
            query,
            key: format!("osv:{}", query.body),
            answer: None,
        })
        .collect();
    for slot in &mut slots {
        if let Ok(amivuln_cache::Lookup::Fresh(e)) = f.cache.get(&slot.key, f.now, f.policy) {
            slot.answer = Some(Ok(Fetched {
                age: Duration::from_secs(
                    u64::try_from(f.now.saturating_sub(e.fetched_at)).unwrap_or(0),
                ),
                body: e.body,
                status: SourceStatus::Ok,
            }));
        }
    }
    if !f.offline {
        let mut pending: Vec<&mut Slot<'_, '_>> =
            slots.iter_mut().filter(|s| s.answer.is_none()).collect();
        for chunk in pending.chunks_mut(OSV_BATCH) {
            let asked: Vec<(&str, &str, &str)> = chunk
                .iter()
                .map(|s| {
                    (
                        s.query.name,
                        s.query.ecosystem.as_str(),
                        s.query.version.as_str(),
                    )
                })
                .collect();
            let Ok(request) = amivuln_sources::osv::batch_request_many(&asked) else {
                continue;
            };
            let Ok(amivuln_sources::http::Response::Fresh { body, .. }) =
                f.http.post(&url, &request).await
            else {
                continue;
            };
            let Ok(parts) = amivuln_sources::osv::split_batch(&body, chunk.len()) else {
                continue;
            };
            for (slot, part) in chunk.iter_mut().zip(parts) {
                // A cache write that fails only costs the next run a request.
                let _ = f.cache.put(&slot.key, &part, None, None, f.now);
                slot.answer = Some(Ok(Fetched {
                    body: part,
                    status: SourceStatus::Ok,
                    age: Duration::ZERO,
                }));
            }
        }
    }
    for slot in &mut slots {
        if slot.answer.is_none() {
            slot.answer =
                Some(fetch_cached_body(&f.ctx(), &slot.key, &url, Some(&slot.query.body)).await);
        }
    }
    slots.into_iter().filter_map(|s| s.answer).collect()
}

/// A source package whose advisories every release of a distribution has. The
/// question tells "a clean package" from "a release OSV holds no data for".
fn probe_package(eco: Ecosystem) -> Option<&'static str> {
    match eco {
        Ecosystem::Ubuntu(_) => Some("linux"),
        Ecosystem::Opensuse(_) => Some("openssl-3"),
        Ecosystem::Alpine(_)
        | Ecosystem::Debian(_)
        | Ecosystem::Rocky(_)
        | Ecosystem::Alma(_)
        | Ecosystem::Rhel(_) => Some("openssl"),
        _ => None,
    }
}

/// A version no package ever had, so the probe's answer is about the data, not
/// about the version asked.
fn probe_version(eco: Ecosystem) -> &'static str {
    match eco {
        Ecosystem::Alpine(_) => "0.0.1-r0",
        Ecosystem::Debian(_) | Ecosystem::Ubuntu(_) | Ecosystem::Opensuse(_) => "0.0.1-1",
        _ => "0.0.1-1.el9",
    }
}

/// Fails the source for a distribution release whose answer cannot be trusted
/// as complete.
///
/// An Ubuntu interim release past its support gets no new advisories, and OSV
/// keeps only leftovers for it. For any other release OSV answers "nothing"
/// both for a clean package and for a release it holds no data for, so when no
/// package of a release got an advisory, one more question tells the two apart.
/// Neither case may read as clean.
async fn distro_coverage(
    f: &Fetcher<'_>,
    base: &str,
    packages: &[(String, PackageRef)],
    asked: &[(String, Vec<String>)],
) -> SourceStatus {
    let today = jiff::Timestamp::from_second(f.now)
        .map(|t| jiff::tz::TimeZone::UTC.to_datetime(t).date())
        .unwrap_or_default();
    let mut status = SourceStatus::Ok;
    let mut silent = std::collections::BTreeMap::new();
    for (_, pkg) in packages {
        let Some(probe) = probe_package(pkg.ecosystem) else {
            continue;
        };
        let ecosystems = pkg.ecosystem.osv_ecosystems();
        let Some(first) = ecosystems.first().cloned() else {
            continue;
        };
        if pkg
            .ecosystem
            .interim_support_ended(today.year(), today.month())
        {
            status = SourceStatus::Failed(format!(
                "{first} is past its support and gets no new advisories, so the result is not complete"
            ));
            continue;
        }
        if matches!(pkg.ecosystem, Ecosystem::Rocky(_)) && pkg.source_name.is_none() {
            status = SourceStatus::Failed(
                "Rocky Linux files advisories by source package and an input names none, so the result is not complete"
                    .to_owned(),
            );
        }
        if let Ecosystem::Rhel(value) = pkg.ecosystem
            && matches!(Ecosystem::rhel_release(value), (major, None) if major >= 10)
        {
            status = SourceStatus::Failed(format!(
                "RHEL {value} is judged by its minor release and none is known, so the result is not complete; use --distro rhel:{value}.N"
            ));
        }
        if asked
            .iter()
            .all(|(e, ids)| ids.is_empty() || !ecosystems.contains(e))
        {
            silent.insert(ecosystems, (probe, probe_version(pkg.ecosystem)));
        }
    }
    for (ecosystems, (name, version)) in silent {
        let mut probe = Vec::new();
        for ecosystem in &ecosystems {
            let body = match amivuln_sources::osv::batch_request(name, ecosystem, version) {
                Ok(body) => body,
                Err(e) => return SourceStatus::Failed(e.to_string()),
            };
            probe.push(OsvQuery {
                name,
                ecosystem: ecosystem.clone(),
                version: version.to_owned(),
                body,
            });
        }
        let mut found = false;
        let mut failure = None;
        for answer in query_osv(f, base, &probe).await {
            let ids = answer.map_err(|e| describe(&e)).and_then(|d| {
                amivuln_sources::osv::parse_batch(&d.body).map_err(|e| e.to_string())
            });
            match ids {
                Ok(ids) => found |= !ids.is_empty(),
                Err(why) => failure = Some(why),
            }
        }
        if let Some(why) = failure {
            status = worse(status, SourceStatus::Failed(why));
        } else if !found {
            let first = ecosystems.first().map_or("", String::as_str);
            status = worse(
                status,
                SourceStatus::Failed(format!(
                    "OSV has no data for {first}, so nothing can be said about it"
                )),
            );
        }
    }
    status
}

/// Loads the OSV data for the host's ecosystem.
///
/// Debian and Ubuntu advisories are fetched per package (one batched request
/// per package, then one advisory document per id). The cache key is the
/// request body, so the same package-version pair is not asked twice.
pub(super) async fn load_osv(
    f: &Fetcher<'_>,
    cfg: &Config,
    packages: &[(String, PackageRef)],
    own_pass: bool,
) -> (Option<DistroData>, SourceReport) {
    // A language-only pass reads `sources.osv`; a distro pass reads
    // `sources.distro`, which doubles as the OSV endpoint on OSV distros.
    let (required, url_override) = if own_pass {
        (cfg.sources.osv.required, cfg.sources.osv.url.clone())
    } else {
        (cfg.sources.distro.required, cfg.sources.distro.url.clone())
    };
    let fail = |why: String| {
        (
            None,
            report_of(
                SourceId::Osv,
                required,
                SourceStatus::Failed(why),
                Duration::ZERO,
            ),
        )
    };
    // The endpoint override is the API base (an internal mirror).
    let base = url_override.unwrap_or_else(|| OSV_URL.to_owned());
    let base = base.trim_end_matches('/');
    let mut status = SourceStatus::Ok;
    let mut age = Duration::ZERO;
    // Every (package, OSV ecosystem) question. Red Hat files a package under
    // several repositories, so a package may add more than one.
    let mut queries: Vec<OsvQuery<'_>> = Vec::new();
    let mut owner: Vec<usize> = Vec::new();
    for (index, (_, pkg)) in packages.iter().enumerate() {
        let osv_ecosystems = pkg.ecosystem.osv_ecosystems();
        if osv_ecosystems.is_empty() {
            return fail(format!("package {} has no OSV data", pkg.name));
        }
        let Some(version) = osv_query_version(pkg.ecosystem, &pkg.version) else {
            return fail(format!(
                "package {} has a version kind OSV cannot match for this distro; check the --distro value",
                pkg.name
            ));
        };
        let asked = questions(pkg, &version);
        for osv_eco in osv_ecosystems {
            for (name, version) in &asked {
                let body =
                    match amivuln_sources::osv::batch_request(name, osv_eco.as_str(), version) {
                        Ok(b) => b,
                        Err(e) => return fail(e.to_string()),
                    };
                queries.push(OsvQuery {
                    name,
                    ecosystem: osv_eco.clone(),
                    version: version.clone(),
                    body,
                });
                owner.push(index);
            }
        }
    }
    let answers = query_osv(f, base, &queries).await;
    let mut ids_by_package: Vec<Vec<String>> = vec![Vec::new(); packages.len()];
    // One entry per (OSV ecosystem, advisory ids found there).
    let mut asked: Vec<(String, Vec<String>)> = Vec::new();
    for ((query, index), answer) in queries.iter().zip(owner).zip(answers) {
        let batch = match answer {
            Ok(d) => d,
            Err(e) => return fail(describe(&e)),
        };
        match amivuln_sources::osv::parse_batch(&batch.body) {
            Ok(found) => {
                status = worse(status, batch.status);
                age = age.max(batch.age);
                if let Some(ids) = ids_by_package.get_mut(index) {
                    ids.extend(found.iter().cloned());
                }
                asked.push((query.ecosystem.clone(), found));
            }
            Err(e) => {
                status = worse(status, SourceStatus::Failed(e.to_string()));
                asked.push((query.ecosystem.clone(), Vec::new()));
            }
        }
    }
    status = worse(status, distro_coverage(f, base, packages, &asked).await);
    status = worse(
        status,
        name_coverage(f, base, packages, &ids_by_package).await,
    );
    for ids in &mut ids_by_package {
        ids.sort();
        ids.dedup();
    }
    let (entries, adv_status, adv_age) = fetch_all_advisories(f, base, &asked).await;
    status = worse(status, adv_status);
    age = age.max(adv_age);
    let per_package = split_per_package(&entries, &ids_by_package);
    (
        Some(DistroData::Osv(per_package)),
        report_of(SourceId::Osv, required, status, age),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::{Fetcher, PackageRef};
    use amivuln_cache::{Cache, Policy as CachePolicy};
    use amivuln_sources::http::{HttpClient, HttpConfig};

    #[test]
    fn rocky_is_asked_by_binary_and_source_name() {
        let package = |ecosystem, source: &str, source_vr: Option<&str>| PackageRef {
            module_stream: None,
            ecosystem,
            name: "device-mapper".into(),
            source_name: Some(source.into()),
            source_vr: source_vr.map(str::to_owned),
            version: amivuln_core::Version::Rpm(
                "8:1.02.181-15.el8".parse().unwrap_or_else(|n| match n {}),
            ),
            arch: None,
            upstream: None,
            slot: None,
            provenance: amivuln_core::Provenance::PackageDb,
        };
        let binary = ("device-mapper", "8:1.02.181-15.el8".to_owned());
        // The source's own release, from epoch 0 on: its epoch is not known.
        let rocky = package(Ecosystem::Rocky(8), "lvm2", Some("2.03.14-15.el8"));
        assert_eq!(
            questions(&rocky, "8:1.02.181-15.el8"),
            [binary.clone(), ("lvm2", "0:2.03.14-15.el8".to_owned())]
        );
        let same_release = package(Ecosystem::Rocky(8), "lvm2", None);
        assert_eq!(
            questions(&same_release, "8:1.02.181-15.el8"),
            [binary.clone(), ("lvm2", "8:1.02.181-15.el8".to_owned())]
        );
        let alma = package(Ecosystem::Alma(8), "lvm2", None);
        assert_eq!(questions(&alma, "8:1.02.181-15.el8"), [binary]);
    }

    /// Fetches against an empty offline cache, so every document fails fast.
    async fn offline_fetch(ids: &[String]) -> SourceStatus {
        let http = HttpClient::new(HttpConfig::default()).unwrap();
        let cache = Cache::in_memory().unwrap();
        let f = Fetcher {
            http: &http,
            cache: &cache,
            now: 0,
            policy: CachePolicy {
                ttl: 1,
                stale_max_age: 1,
            },
            offline: true,
            offline_db: None,
            nvd_http: None,
        };
        fetch_advisories(&f, "https://osv.invalid", "Debian:12", ids)
            .await
            .1
    }

    #[tokio::test]
    async fn only_a_real_cut_reports_the_advisory_limit() {
        let ids = |n: usize| {
            (0..n)
                .map(|i| format!("DEBIAN-CVE-2024-{i:04}"))
                .collect::<Vec<_>>()
        };
        // The documents fail (offline), but the limit is not the cause.
        let under = format!("{:?}", offline_fetch(&ids(3)).await);
        assert!(
            under.contains("Failed") && !under.contains("exceeded"),
            "{under}"
        );
        let over = format!("{:?}", offline_fetch(&ids(MAX_OSV_ADVISORIES + 1)).await);
        assert!(over.contains("exceeded the fetch limit"), "{over}");
    }
}
