// SPDX-FileCopyrightText: 2026 amivuln contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Loading each advisory and enrichment source, with its status.

use super::{
    ArchTracker, Config, DistroData, Duration, Ecosystem, EpssScores, FetchCtx, Fetcher, Kev,
    MAX_OSV_ADVISORIES, PackageRef, SourceId, SourceReport, SourceStatus, Updateinfo, cpu_arch,
    describe, fetch_cached_body, load_osv, report_of, updateinfo_location, worse,
};

/// Default endpoints.
pub(super) const ARCH_URL: &str = "https://security.archlinux.org/issues/all.json";

pub(super) const FEDORA_UPDATES: &str = "https://dl.fedoraproject.org/pub/fedora/linux/updates";

pub(super) const NVD_URL: &str = "https://services.nvd.nist.gov";

pub(super) const KEV_URL: &str =
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

pub(super) const EPSS_URL: &str = "https://api.first.org/data/v1/epss";

/// CVE ids per EPSS request, to keep URLs short.
pub(super) const EPSS_BATCH: usize = 50;

pub(super) async fn load_distro(
    f: &Fetcher<'_>,
    eco: Ecosystem,
    cfg: &Config,
    resolved: &[(String, PackageRef)],
) -> (Option<DistroData>, SourceReport) {
    let required = cfg.sources.distro.required;
    let override_url = cfg.sources.distro.url.clone();
    match eco {
        Ecosystem::Debian(_)
        | Ecosystem::Ubuntu(_)
        | Ecosystem::Rocky(_)
        | Ecosystem::Alma(_)
        | Ecosystem::Rhel(_)
        | Ecosystem::Alpine(_)
        | Ecosystem::Opensuse(_)
        | Ecosystem::Go
        | Ecosystem::Crates => load_osv(f, cfg, resolved, false).await,
        Ecosystem::Gentoo => load_glsa(f, cfg),
        Ecosystem::Arch => {
            let url = override_url.unwrap_or_else(|| ARCH_URL.to_owned());
            match f.get(&url).await {
                Ok(d) => match ArchTracker::parse(&d.body) {
                    Ok(t) => (
                        Some(DistroData::Arch(t)),
                        report_of(SourceId::ArchTracker, required, d.status, d.age),
                    ),
                    Err(e) => (
                        None,
                        report_of(
                            SourceId::ArchTracker,
                            required,
                            SourceStatus::Failed(e.to_string()),
                            Duration::ZERO,
                        ),
                    ),
                },
                Err(e) => (
                    None,
                    report_of(
                        SourceId::ArchTracker,
                        required,
                        SourceStatus::Failed(describe(&e)),
                        Duration::ZERO,
                    ),
                ),
            }
        }
        Ecosystem::Fedora(release) => {
            let fail = |why: String| {
                (
                    None,
                    report_of(
                        SourceId::FedoraUpdateinfo,
                        required,
                        SourceStatus::Failed(why),
                        Duration::ZERO,
                    ),
                )
            };
            let base = override_url.unwrap_or_else(|| FEDORA_UPDATES.to_owned());
            let base = base.trim_end_matches('/');
            let repo = format!("{base}/{release}/Everything/{}", cpu_arch());
            let repomd = match f.get(&format!("{repo}/repodata/repomd.xml")).await {
                Ok(d) => d,
                Err(e) => return fail(describe(&e)),
            };
            let location = match updateinfo_location(&repomd.body) {
                Ok(l) => l,
                Err(e) => return fail(e.to_string()),
            };
            let blob = match f.get(&format!("{repo}/{}", location.href)).await {
                Ok(d) => d,
                Err(e) => return fail(describe(&e)),
            };
            if !location.verify(&blob.body) {
                return fail("updateinfo does not match the checksum in repomd.xml".into());
            }
            match Updateinfo::parse_zst(&blob.body) {
                Ok(i) => (
                    Some(DistroData::Fedora(i)),
                    report_of(
                        SourceId::FedoraUpdateinfo,
                        required,
                        worse(repomd.status, blob.status),
                        repomd.age.max(blob.age),
                    ),
                ),
                Err(e) => fail(e.to_string()),
            }
        }
    }
}

/// Where a Gentoo host keeps the advisories: the Portage tree's metadata.
const GLSA_DIRS: [&str; 2] = [
    "/var/db/repos/gentoo/metadata/glsa",
    "/usr/portage/metadata/glsa",
];

/// Reads the GLSAs of the host's own Portage tree (or of `path`), offline.
///
/// The tree's age is the data's age: a host that has not synchronised for
/// longer than `stale_max_age` is reported stale, and a directory that cannot
/// be read or holds no advisory is a failed source, never an empty answer.
fn load_glsa(f: &Fetcher<'_>, cfg: &Config) -> (Option<DistroData>, SourceReport) {
    let required = cfg.sources.distro.required;
    let fail = |why: String| {
        (
            None,
            report_of(
                SourceId::Glsa,
                required,
                SourceStatus::Failed(why),
                Duration::ZERO,
            ),
        )
    };
    let dir = match cfg.sources.distro.path.as_deref() {
        Some(path) => std::path::PathBuf::from(path),
        None => match GLSA_DIRS
            .iter()
            .map(std::path::Path::new)
            .find(|p| p.is_dir())
        {
            Some(found) => found.to_path_buf(),
            None => {
                return fail(format!(
                    "no Portage tree with advisories found ({}); set sources.distro.path",
                    GLSA_DIRS.join(", ")
                ));
            }
        },
    };
    let data = match amivuln_sources::glsa::GlsaData::load(&dir) {
        Ok(d) if d.is_empty() => {
            return fail(format!("{} holds no advisory", dir.display()));
        }
        Ok(d) => d,
        Err(e) => return fail(e.to_string()),
    };
    let age = data
        .updated
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map_or(Duration::ZERO, |t| {
            Duration::from_secs(
                u64::try_from(f.now)
                    .unwrap_or(0)
                    .saturating_sub(t.as_secs()),
            )
        });
    let status = if i64::try_from(age.as_secs()).is_ok_and(|a| a > f.policy.stale_max_age) {
        SourceStatus::Stale
    } else {
        SourceStatus::Ok
    };
    (
        Some(DistroData::Glsa(data)),
        report_of(SourceId::Glsa, required, status, age),
    )
}

pub(super) async fn load_kev(f: &Fetcher<'_>, cfg: &Config) -> (Option<Kev>, SourceReport) {
    let c = &cfg.sources.kev;
    let url = c.url.clone().unwrap_or_else(|| KEV_URL.to_owned());
    match f.get(&url).await {
        Ok(d) => match Kev::parse(&d.body) {
            Ok(k) => (
                Some(k),
                report_of(SourceId::Kev, c.required, d.status, d.age),
            ),
            Err(e) => (
                None,
                report_of(
                    SourceId::Kev,
                    c.required,
                    SourceStatus::Failed(e.to_string()),
                    Duration::ZERO,
                ),
            ),
        },
        Err(e) => (
            None,
            report_of(
                SourceId::Kev,
                c.required,
                SourceStatus::Failed(describe(&e)),
                Duration::ZERO,
            ),
        ),
    }
}

pub(super) async fn load_epss(
    f: &Fetcher<'_>,
    cfg: &Config,
    cves: &[String],
) -> (Option<EpssScores>, SourceReport) {
    let c = &cfg.sources.epss;
    let base = c.url.clone().unwrap_or_else(|| EPSS_URL.to_owned());
    let mut status = SourceStatus::Ok;
    let mut age = Duration::ZERO;
    let mut merged: Vec<EpssScores> = Vec::new();
    for batch in cves.chunks(EPSS_BATCH) {
        let url = format!("{base}?cve={}", batch.join(","));
        match f.get(&url).await {
            Ok(d) => match EpssScores::parse(&d.body) {
                Ok(s) => {
                    merged.push(s);
                    status = worse(status, d.status);
                    age = age.max(d.age);
                }
                Err(e) => status = worse(status, SourceStatus::Failed(e.to_string())),
            },
            Err(e) => status = worse(status, SourceStatus::Failed(describe(&e))),
        }
    }
    let scores = merged
        .into_iter()
        .fold(EpssScores::default(), EpssScores::merged);
    (
        Some(scores),
        report_of(SourceId::Epss, c.required, status, age),
    )
}

/// One pass per distribution for packages whose data is not the host's and not
/// OSV: the ecosystem and the data its source returned.
pub(super) async fn load_foreign(
    fetcher: &Fetcher<'_>,
    cfg: &Config,
    other_resolved: &[(String, PackageRef)],
    sources: &mut Vec<SourceReport>,
) -> Vec<(Ecosystem, DistroData)> {
    let mut ecosystems: Vec<Ecosystem> = other_resolved.iter().map(|(_, p)| p.ecosystem).collect();
    ecosystems.sort_by_key(|e| format!("{e:?}"));
    ecosystems.dedup();
    let mut foreign = Vec::new();
    for eco in ecosystems {
        let group: Vec<(String, PackageRef)> = other_resolved
            .iter()
            .filter(|(_, p)| p.ecosystem == eco)
            .cloned()
            .collect();
        // The configured distro endpoint belongs to the host's distribution.
        let mut attempt = cfg.clone();
        attempt.sources.distro.url = None;
        let (data, report) = load_distro(fetcher, eco, &attempt, &group).await;
        sources.push(report);
        if let Some(data) = data {
            foreign.push((eco, data));
        }
    }
    foreign
}

/// Loads KEV and EPSS with failover over their mirrors, when there are CVE
/// ids to enrich. Sources that are disabled are simply skipped.
pub(super) async fn load_enrichment(
    fetcher: &Fetcher<'_>,
    cfg: &Config,
    cves: &[String],
) -> (Option<Kev>, Option<EpssScores>, Vec<SourceReport>) {
    let mut sources = Vec::new();
    let mut kev = None;
    let mut epss = None;
    if cves.is_empty() {
        return (kev, epss, sources);
    }
    if cfg.sources.kev.enabled {
        let mut attempt = cfg.clone();
        let mut latest = load_kev(fetcher, &attempt).await;
        for mirror_url in &cfg.sources.kev.fallback {
            if !matches!(latest.1.status, SourceStatus::Failed(_)) {
                break;
            }
            attempt.sources.kev.url = Some(mirror_url.clone());
            latest = load_kev(fetcher, &attempt).await;
        }
        let (k, rep) = latest;
        kev = k;
        sources.push(rep);
    }
    if cfg.sources.epss.enabled {
        let mut attempt = cfg.clone();
        let mut latest = load_epss(fetcher, &attempt, cves).await;
        for mirror_url in &cfg.sources.epss.fallback {
            if !matches!(latest.1.status, SourceStatus::Failed(_)) {
                break;
            }
            attempt.sources.epss.url = Some(mirror_url.clone());
            latest = load_epss(fetcher, &attempt, cves).await;
        }
        let (e, rep) = latest;
        epss = e;
        sources.push(rep);
    }
    (kev, epss, sources)
}

/// Loads the NVD entries for string heuristic targets, keyed by product name.
pub(super) async fn load_and_map_nvd(
    fetcher: &Fetcher<'_>,
    cfg: &Config,
    resolved: &[(String, PackageRef)],
    sources: &mut Vec<SourceReport>,
) -> std::collections::BTreeMap<String, Vec<amivuln_sources::nvd::NvdEntry2>> {
    let heuristic: Vec<(String, PackageRef)> = resolved
        .iter()
        .filter(|(_, p)| p.provenance == amivuln_core::Provenance::StringHeuristic)
        .cloned()
        .collect();
    let mut nvd_data = std::collections::BTreeMap::new();
    if heuristic.is_empty() || !cfg.sources.nvd.enabled {
        return nvd_data;
    }
    let (nvd_entries, rep) = load_nvd(fetcher, cfg, &heuristic).await;
    sources.push(rep);
    for entry in nvd_entries {
        nvd_data
            .entry(entry.cpe_package.clone())
            .or_default()
            .push(entry);
    }
    nvd_data
}

/// Loads the NVD 2.0 API entries for a set of string heuristic targets.
/// The CPE name is built from the curated mapping table; a package the
/// table does not cover is skipped.
pub(super) async fn load_nvd(
    f: &Fetcher<'_>,
    cfg: &Config,
    heuristic: &[(String, PackageRef)],
) -> (Vec<amivuln_sources::nvd::NvdEntry2>, SourceReport) {
    use amivuln_sources::nvd::{NvdError, cpe_name};
    let required = cfg.sources.nvd.required;
    let fail = |why: String| {
        (
            Vec::new(),
            report_of(
                SourceId::Nvd,
                required,
                SourceStatus::Failed(why),
                Duration::ZERO,
            ),
        )
    };
    let base = cfg
        .sources
        .nvd
        .url
        .clone()
        .unwrap_or_else(|| NVD_URL.to_owned());
    let base = base.trim_end_matches('/');
    let mut entries = Vec::new();
    let mut status = SourceStatus::Ok;
    let mut age = Duration::ZERO;
    for (_, pkg) in heuristic {
        let Some(cpe) = cpe_name(&pkg.name, &pkg.version.to_string()) else {
            continue;
        };
        let key = format!("nvd:{cpe}");
        let url = format!("{base}/rest/json/cves/2.0?cpeName={cpe}&resultsPerPage=200");
        let doc = match fetch_cached_body(
            &FetchCtx {
                http: f.http,
                cache: f.cache,
                now: f.now,
                policy: f.policy,
                offline: f.offline,
                offline_db: f.offline_db,
            },
            &key,
            &url,
            None,
        )
        .await
        {
            Ok(d) => d,
            Err(e) => return fail(describe(&e)),
        };
        match amivuln_sources::nvd::parse_response(&doc.body, &pkg.name) {
            Ok(mut found) => {
                status = worse(status, doc.status);
                age = age.max(doc.age);
                entries.append(&mut found);
            }
            Err(NvdError::Invalid(e)) => {
                status = worse(status, SourceStatus::Failed(e));
            }
            Err(NvdError::TooLarge(n)) => {
                status = worse(
                    status,
                    SourceStatus::Failed(format!("response too large: {n}")),
                );
            }
            Err(NvdError::NoVulnerabilities) => {}
        }
    }
    if entries.len() > MAX_OSV_ADVISORIES {
        status = worse(
            status,
            SourceStatus::Failed(format!(
                "{} NVD entries exceeded the fetch limit of {MAX_OSV_ADVISORIES}",
                entries.len()
            )),
        );
    }
    (entries, report_of(SourceId::Nvd, required, status, age))
}
