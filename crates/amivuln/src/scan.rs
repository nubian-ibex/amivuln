// SPDX-FileCopyrightText: 2026 amivuln contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Resolving targets, fetching sources and evaluating packages. Shared by
//! `check`, `cve`, `pending` and the other commands that need findings.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use amivuln_cache::{Cache, Policy as CachePolicy};
use amivuln_core::VexStatement;
use amivuln_core::{
    Ecosystem, ExitCode, Finding, PackageRef, Severity, SourceId, SourceReport, SourceStatus,
    TargetReport, Unresolved, Verdict, sort_findings,
};
use amivuln_resolve::{
    PackageResolver, PacmanResolver, ResolveError, RpmResolver, SystemRunner, Target, exe_for_unit,
    from_name_version, from_purl, language_packages, package_from_note, parse_target,
};
use amivuln_sources::arch::ArchTracker;
use amivuln_sources::epss::EpssScores;
use amivuln_sources::fedora::{Updateinfo, updateinfo_location};
use amivuln_sources::fetch::{FetchCtx, FetchError, Fetched, fetch_cached_body};
use amivuln_sources::http::{HttpClient, HttpConfig};
use amivuln_sources::kev::Kev;
use amivuln_sources::osv::OsvData;
use amivuln_sources::resilience::{BreakerPolicy, RetryPolicy};

use crate::app::{Env, Settings, cache_path, cpu_arch};
use crate::cli::{Cli, Global};
use crate::config::Config;
use crate::pipeline::{arch_findings, enrich, fedora_findings, osv_findings};

/// Default endpoints.
const ARCH_URL: &str = "https://security.archlinux.org/issues/all.json";
const FEDORA_UPDATES: &str = "https://dl.fedoraproject.org/pub/fedora/linux/updates";
const OSV_URL: &str = "https://api.osv.dev";
const NVD_URL: &str = "https://services.nvd.nist.gov";
const KEV_URL: &str =
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
const EPSS_URL: &str = "https://api.first.org/data/v1/epss";
/// CVE ids per EPSS request, to keep URLs short.
const EPSS_BATCH: usize = 50;
/// Most advisory documents fetched per run.
const MAX_OSV_ADVISORIES: usize = 5000;

/// The package manager lookups for a host.
enum Backend<'a> {
    Rpm(RpmResolver<'a, SystemRunner>),
    Pacman(PacmanResolver<'a, SystemRunner>),
}

impl Backend<'_> {
    fn resolver(&self) -> &dyn PackageResolver {
        match self {
            Self::Rpm(r) => r,
            Self::Pacman(r) => r,
        }
    }
}

pub(crate) fn expand_targets(cli: &Cli, subcommand_targets: &[String]) -> Vec<String> {
    let mut v: Vec<String> = subcommand_targets.to_vec();
    v.extend(cli.global.package.iter().cloned());
    v.extend(cli.global.file.iter().map(|f| {
        if f.contains('/') {
            f.clone()
        } else {
            format!("./{f}")
        }
    }));
    v.extend(cli.global.purl.iter().cloned());
    v.extend(cli.global.pid.iter().map(|pid| pid_executable(*pid)));
    v
}

/// The path of a process's executable, from `/proc/PID/exe`. A process that
/// is gone, or not readable, or whose binary was replaced on disk
/// (`(deleted)`) keeps the `/proc` path, which then fails to resolve with a
/// message that names the process rather than checking the new file by
/// mistake: the running code is the old one.
fn pid_executable(pid: u32) -> String {
    let link = format!("/proc/{pid}/exe");
    match std::fs::read_link(&link) {
        Ok(path) => {
            let path = path.display().to_string();
            if path.ends_with(" (deleted)") {
                link
            } else {
                path
            }
        }
        Err(_) => link,
    }
}

fn resolve_one(
    input: &str,
    eco: Ecosystem,
    backend: &Backend<'_>,
    runner: &SystemRunner,
) -> Result<PackageRef, ResolveError> {
    let exists = |p: &str| Path::new(p).exists();
    match parse_target(input, exists) {
        // The purl itself carries no release, so the host's --distro fills it
        // in and must agree with the purl's namespace.
        Target::Purl(p) => from_purl(&p, Some(eco)),
        Target::NameVersion(n, v) => from_name_version(eco, &n, &v),
        Target::Path(p) => backend.resolver().owner_of(&p),
        Target::Name(n) => backend.resolver().by_name(&n),
        Target::Unit(u) => {
            let link = |p: &str| std::fs::read_link(p).ok().map(|l| l.display().to_string());
            let exe = exe_for_unit(runner, &link, &u)?;
            backend.resolver().owner_of(&exe.path)
        }
    }
}

/// Identifies a file: its owning package, else its package note, else the Go
/// modules or Rust crates it declares. Modules and crates are used only when
/// nothing else names the file, because a distribution backports fixes into
/// vendored code without changing versions.
fn resolve_path(
    path: &str,
    eco: Ecosystem,
    backend: Option<&Backend<'_>>,
    probe: bool,
) -> Result<Vec<PackageRef>, ResolveError> {
    // `--pid` leaves the /proc path when the process cannot be followed.
    if path.starts_with("/proc/") && path.ends_with("/exe") {
        return Err(ResolveError::NotFound(format!(
            "{path} (the process is gone, unreadable, or its executable was replaced on disk)"
        )));
    }
    let owner = match backend {
        Some(b) => b.resolver().owner_of(path),
        None => Err(ResolveError::NotFound(path.to_owned())),
    };
    match owner {
        Ok(pkg) => return Ok(vec![pkg]),
        // Not owned (or the package manager is unavailable): look inside.
        Err(ResolveError::NotFound(_) | ResolveError::Process(_)) => {}
        Err(other) => return Err(other),
    }
    if let Ok(pkg) = package_from_note(eco, Path::new(path)) {
        return Ok(vec![pkg]);
    }
    let modules = language_packages(Path::new(path))?;
    if !modules.is_empty() {
        return Ok(modules);
    }
    // Last resort: version banners from a curated set of C products. The
    // upstream version is what was compiled in; the distribution may have
    // backported fixes without changing the banner, so every formatter
    // carries the low-confidence mark.
    let mut hits =
        amivuln_resolve::detect_string_hits(Path::new(path)).map_err(ResolveError::Parse)?;
    if probe {
        hits.extend(version_probe(Path::new(path))?);
        hits.sort();
        hits.dedup();
    }
    let mut out = Vec::new();
    for hit in hits {
        if let Ok(pkg) = from_name_version(eco, &hit.name, &hit.version) {
            let mut pkg = pkg;
            pkg.provenance = amivuln_core::Provenance::StringHeuristic;
            out.push(pkg);
        }
    }
    if !out.is_empty() {
        return Ok(out);
    }
    package_from_note(eco, Path::new(path)).map(|pkg| vec![pkg])
}

/// Runs `path --version` in the sandbox (opt-in `exec_version_probe`) and
/// reads the banners from what it prints. The user asked for the probe, so a
/// sandbox that cannot be enforced is an error, never a silent unconfined run.
fn version_probe(path: &Path) -> Result<Vec<amivuln_resolve::StringHit>, ResolveError> {
    let out = amivuln_sandbox::probe(path, &["--version"], Duration::from_secs(2))
        .map_err(|e| ResolveError::Parse(format!("version probe of {}: {e}", path.display())))?;
    Ok(amivuln_resolve::detect_strings(&out.output))
}

/// What a scan produced.
pub(crate) struct Evaluated {
    /// One report per resolved package.
    pub(crate) targets: Vec<TargetReport>,
    /// One entry per consulted source.
    pub(crate) sources: Vec<SourceReport>,
    /// The ids from the probe list that the distribution data has a record of.
    pub(crate) known: Vec<String>,
}

/// Distro data, loaded once per run.
enum DistroData {
    Arch(ArchTracker),
    Fedora(Updateinfo),
    /// One entry per package, in the order of the resolved list: an advisory
    /// found for package A must never be judged against package B.
    Osv(Vec<OsvData>),
}

impl DistroData {
    fn knows(&self, cve: &str) -> bool {
        match self {
            Self::Arch(t) => t.knows(cve),
            Self::Fedora(i) => i.knows(cve),
            Self::Osv(list) => list.iter().any(|o| o.knows(cve)),
        }
    }
}

/// Fetches the advisories of every package, parsing each against the OSV
/// ecosystem that package was asked in, and enforces the fetch limit.
async fn fetch_all_advisories(
    f: &Fetcher<'_>,
    base: &str,
    ids_by_package: &[Vec<String>],
    osv_ecos: &[String],
) -> (Vec<amivuln_sources::osv::OsvEntry>, SourceStatus, Duration) {
    let mut entries = Vec::new();
    let mut status = SourceStatus::Ok;
    let mut age = Duration::ZERO;
    let distinct: std::collections::BTreeSet<&String> = osv_ecos.iter().collect();
    let mut total = 0usize;
    for osv_eco in distinct {
        let mut mine: Vec<String> = ids_by_package
            .iter()
            .zip(osv_ecos)
            .filter(|(_, e)| *e == osv_eco)
            .flat_map(|(found, _)| found.iter().cloned())
            .collect();
        mine.sort();
        mine.dedup();
        total += mine.len();
        let (mut got, adv_status, adv_age) =
            fetch_advisories(f, base, osv_eco.as_str(), &mine).await;
        entries.append(&mut got);
        status = worse(status, adv_status);
        age = age.max(adv_age);
    }
    if total > MAX_OSV_ADVISORIES {
        status = worse(
            status,
            SourceStatus::Failed(format!(
                "{total} advisories exceeded the fetch limit of {MAX_OSV_ADVISORIES}"
            )),
        );
    }
    (entries, status, age)
}

/// The version string OSV is asked about, or `None` when the version kind does
/// not belong to the ecosystem (an RPM version for Debian, for example).
fn osv_query_version(eco: Ecosystem, version: &amivuln_core::Version) -> Option<String> {
    match version {
        amivuln_core::Version::Deb(v) => Some(v.to_string()),
        amivuln_core::Version::Rpm(v)
            if matches!(eco, Ecosystem::Rocky(_) | Ecosystem::Alma(_)) =>
        {
            Some(v.to_string())
        }
        amivuln_core::Version::Semver(v) if eco.is_language() => Some(v.to_string()),
        _ => None,
    }
}

/// Splits advisories back per package so each is judged only against the
/// package it was found for.
fn split_per_package(
    entries: &[amivuln_sources::osv::OsvEntry],
    ids_by_package: &[Vec<String>],
) -> Vec<OsvData> {
    ids_by_package
        .iter()
        .map(|mine| {
            OsvData::from_entries(
                entries
                    .iter()
                    .filter(|e| mine.contains(&e.advisory))
                    .cloned()
                    .collect(),
            )
        })
        .collect()
}

/// Fetches one advisory document per id and parses it for the ecosystem.
async fn fetch_advisories(
    f: &Fetcher<'_>,
    base: &str,
    osv_eco: &str,
    ids: &[String],
) -> (Vec<amivuln_sources::osv::OsvEntry>, SourceStatus, Duration) {
    let mut entries = Vec::new();
    let mut status = SourceStatus::Ok;
    let mut age = Duration::ZERO;
    for id in ids.iter().take(MAX_OSV_ADVISORIES) {
        let url = format!("{base}/v1/vulns/{id}");
        let key = format!("osv-advisory:{id}");
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
            Err(e) => {
                status = worse(status, SourceStatus::Failed(describe(&e)));
                continue;
            }
        };
        match amivuln_sources::osv::OsvData::parse_advisory(&doc.body, osv_eco) {
            Ok(parsed) => {
                for e in parsed.entries() {
                    entries.push(amivuln_sources::osv::OsvEntry {
                        advisory: id.clone(),
                        ..e
                    });
                }
                status = worse(status, doc.status);
                age = age.max(doc.age);
            }
            Err(e) => status = worse(status, SourceStatus::Failed(e.to_string())),
        }
    }
    (entries, status, age)
}

/// Loads the OSV data for the host's ecosystem.
///
/// Debian and Ubuntu advisories are fetched per package (one batched request
/// per package, then one advisory document per id). The cache key is the
/// request body, so the same package-version pair is not asked twice.
async fn load_osv(
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
    let mut ids_by_package: Vec<Vec<String>> = Vec::new();
    let mut status = SourceStatus::Ok;
    let mut age = Duration::ZERO;
    let mut osv_ecos: Vec<String> = Vec::new();
    for (_, pkg) in packages {
        let Some(osv_eco) = pkg.ecosystem.osv_ecosystem() else {
            return fail(format!("package {} has no OSV data", pkg.name));
        };
        let Some(version) = osv_query_version(pkg.ecosystem, &pkg.version) else {
            return fail(format!(
                "package {} has a version kind OSV cannot match for this distro; check the --distro value",
                pkg.name
            ));
        };
        osv_ecos.push(osv_eco.clone());
        let body = match amivuln_sources::osv::batch_request(
            pkg.name.as_str(),
            osv_eco.as_str(),
            version.as_str(),
        ) {
            Ok(b) => b,
            Err(e) => return fail(e.to_string()),
        };
        let key = format!("osv:{body}");
        let batch = match fetch_cached_body(
            &FetchCtx {
                http: f.http,
                cache: f.cache,
                now: f.now,
                policy: f.policy,
                offline: f.offline,
                offline_db: f.offline_db,
            },
            &key,
            &format!("{base}/v1/querybatch"),
            Some(body.as_str()),
        )
        .await
        {
            Ok(d) => d,
            Err(e) => return fail(describe(&e)),
        };
        match amivuln_sources::osv::parse_batch(&batch.body) {
            Ok(found) => {
                status = worse(status, batch.status);
                age = age.max(batch.age);
                ids_by_package.push(found);
            }
            Err(e) => {
                status = worse(status, SourceStatus::Failed(e.to_string()));
                ids_by_package.push(Vec::new());
            }
        }
    }
    let (entries, adv_status, adv_age) =
        fetch_all_advisories(f, base, &ids_by_package, &osv_ecos).await;
    status = worse(status, adv_status);
    age = age.max(adv_age);
    let per_package = split_per_package(&entries, &ids_by_package);
    (
        Some(DistroData::Osv(per_package)),
        report_of(SourceId::Osv, required, status, age),
    )
}

fn report_of(
    source: SourceId,
    required: bool,
    status: SourceStatus,
    age: Duration,
) -> SourceReport {
    SourceReport {
        source,
        status,
        age,
        required,
    }
}

fn worse(a: SourceStatus, b: SourceStatus) -> SourceStatus {
    match (&a, &b) {
        (SourceStatus::Failed(_), _) => a,
        (_, SourceStatus::Failed(_)) => b,
        (SourceStatus::Stale, _) | (_, SourceStatus::Stale) => SourceStatus::Stale,
        _ => a,
    }
}

fn describe(e: &FetchError) -> String {
    e.to_string()
}

struct Fetcher<'a> {
    http: &'a HttpClient,
    cache: &'a Cache,
    now: i64,
    policy: CachePolicy,
    offline: bool,
    /// The installed offline database, consulted when offline.
    offline_db: Option<&'a Cache>,
}

impl Fetcher<'_> {
    async fn get(&self, url: &str) -> Result<Fetched, FetchError> {
        fetch_cached_body(
            &FetchCtx {
                http: self.http,
                cache: self.cache,
                now: self.now,
                policy: self.policy,
                offline: self.offline,
                offline_db: self.offline_db,
            },
            url,
            url,
            None,
        )
        .await
    }
}

async fn load_distro(
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
        | Ecosystem::Go
        | Ecosystem::Crates => load_osv(f, cfg, resolved, false).await,
        // Alpine has no OSV ecosystem in amivuln yet: the honest answer is a
        // failed required source, never a silent clean scan.
        Ecosystem::Alpine => (
            None,
            report_of(
                SourceId::Osv,
                required,
                SourceStatus::Failed("alpine has no OSV ecosystem in amivuln yet".to_owned()),
                Duration::ZERO,
            ),
        ),
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

async fn load_kev(f: &Fetcher<'_>, cfg: &Config) -> (Option<Kev>, SourceReport) {
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

async fn load_epss(
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

/// Resolved packages (with the input that named them) and the inputs that failed.
pub(crate) type Scope = (Vec<(String, PackageRef)>, Vec<Unresolved>);

/// Largest inventory file accepted.
const MAX_INVENTORY_BYTES: u64 = 8 * 1024 * 1024;

/// Reads `--packages-from FILE`: one `name@version` per line, `#` comments and
/// blank lines ignored. Lets a pipeline check a package list exported from
/// another host, for example `rpm -qa --qf '%{NAME}@%{EPOCH}:%{VERSION}-%{RELEASE}\n'`.
fn read_inventory(path: &Path, eco: Ecosystem) -> Result<Vec<(String, PackageRef)>, String> {
    let meta = std::fs::metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if meta.len() > MAX_INVENTORY_BYTES {
        return Err(format!(
            "{} is larger than {MAX_INVENTORY_BYTES} bytes",
            path.display()
        ));
    }
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (name, version) = line.rsplit_once('@').ok_or_else(|| {
            format!(
                "{}:{}: expected name@version, got {:?}",
                path.display(),
                i + 1,
                line.chars().take(60).collect::<String>()
            )
        })?;
        // The epoch of an rpm list may read `(none):1.0-1`.
        let version = version.strip_prefix("(none):").unwrap_or(version);
        let pkg = from_name_version(eco, name, version)
            .map_err(|e| format!("{}:{}: {e}", path.display(), i + 1))?;
        out.push((name.to_owned(), pkg));
    }
    Ok(out)
}

/// Deepest component nesting and most components read from an SBOM.
const MAX_SBOM_DEPTH: usize = 8;
const MAX_SBOM_COMPONENTS: usize = 200_000;

fn collect_purls(
    components: &serde_json::Value,
    depth: usize,
    seen: &mut usize,
    purls: &mut std::collections::BTreeSet<String>,
    without: &mut usize,
) -> Result<(), String> {
    let Some(list) = components.as_array() else {
        return Ok(());
    };
    for c in list {
        *seen += 1;
        if *seen > MAX_SBOM_COMPONENTS {
            return Err(format!(
                "the SBOM has more than {MAX_SBOM_COMPONENTS} components"
            ));
        }
        match c.get("purl").and_then(serde_json::Value::as_str) {
            Some(p) => {
                purls.insert(p.to_owned());
            }
            None => *without += 1,
        }
        if depth < MAX_SBOM_DEPTH
            && let Some(inner) = c.get("components")
        {
            collect_purls(inner, depth + 1, seen, purls, without)?;
        }
    }
    Ok(())
}

/// Reads `--sbom FILE`, a `CycloneDX` JSON document. rpm, deb and alpm purls
/// become packages; every other component is reported as unresolved, one entry
/// per purl type, so nothing is dropped without a trace.
fn read_sbom(path: &Path, eco: Ecosystem) -> Result<Scope, String> {
    use std::io::Read;
    let file = std::fs::File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut buf = Vec::new();
    file.take(MAX_SBOM_BYTES + 1)
        .read_to_end(&mut buf)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    if buf.len() as u64 > MAX_SBOM_BYTES {
        return Err(format!(
            "{} is larger than {MAX_SBOM_BYTES} bytes",
            path.display()
        ));
    }
    let doc: serde_json::Value = serde_json::from_slice(&buf)
        .map_err(|e| format!("{}: not valid JSON: {e}", path.display()))?;
    if doc.get("bomFormat").and_then(serde_json::Value::as_str) != Some("CycloneDX") {
        return Err(format!("{}: not a CycloneDX JSON document", path.display()));
    }
    let mut purls = std::collections::BTreeSet::new();
    let (mut seen, mut without) = (0, 0);
    if let Some(c) = doc.get("components") {
        collect_purls(c, 0, &mut seen, &mut purls, &mut without)?;
    }
    let mut packages = Vec::new();
    let mut skipped: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    for purl in purls {
        let kind = purl
            .strip_prefix("pkg:")
            .and_then(|r| r.split(['/', '@']).next())
            .unwrap_or("invalid")
            .to_owned();
        if matches!(kind.as_str(), "rpm" | "deb" | "alpm") {
            let pkg = amivuln_resolve::from_purl(&purl, Some(eco))
                .map_err(|e| format!("{}: {purl}: {e}", path.display()))?;
            packages.push((purl, pkg));
        } else {
            *skipped.entry(format!("pkg:{kind}")).or_default() += 1;
        }
    }
    let mut unresolved: Vec<Unresolved> = skipped
        .into_iter()
        .map(|(kind, n)| Unresolved {
            input: format!("sbom:{kind}"),
            reason: format!("{n} component(s) are not OS packages, so no distro advisory applies"),
        })
        .collect();
    if without > 0 {
        unresolved.push(Unresolved {
            input: "sbom:no-purl".to_owned(),
            reason: format!("{without} component(s) have no purl"),
        });
    }
    Ok((packages, unresolved))
}

/// Largest SBOM accepted.
const MAX_SBOM_BYTES: u64 = 64 * 1024 * 1024;

/// The packages a command works on: the host's installed packages for `--all`,
/// a `--packages-from` inventory, and any explicit targets.
pub(crate) fn resolve_scope(
    cli: &Cli,
    targets: &[String],
    all: bool,
    eco: Ecosystem,
    probe: bool,
) -> Result<Scope, String> {
    let (mut resolved, unresolved) = resolve_all(targets, all, eco, probe);
    let mut unresolved = unresolved;
    if let Some(path) = &cli.global.packages_from {
        resolved.extend(read_inventory(path, eco)?);
    }
    if let Some(path) = &cli.global.sbom {
        let (pkgs, skipped) = read_sbom(path, eco)?;
        resolved.extend(pkgs);
        unresolved.extend(skipped);
    }
    for container_id in &cli.global.container {
        match read_container(container_id) {
            Ok((container_eco, pkgs)) => {
                // The container's own os-release decides the ecosystem: the
                // host's --distro value is not reused and never overrides it.
                resolved.extend(pkgs.into_iter().map(|pkg| {
                    let label = format!("{container_id}:{pkg_name}", pkg_name = pkg.name);
                    (label, pkg)
                }));
                let _ = container_eco;
            }
            Err(e) => unresolved.push(Unresolved {
                input: format!("--container {container_id}"),
                reason: e.to_string(),
            }),
        }
    }
    Ok((resolved, unresolved))
}

/// Reads a container's installed packages: export, then the package database.
/// Returns the container's ecosystem, for the caller's report labels.
fn read_container(
    container_id: &str,
) -> Result<(Ecosystem, Vec<PackageRef>), amivuln_resolve::ContainerError> {
    use amivuln_resolve::{container_packages, export_container};
    let runner = SystemRunner::default();
    let dir = std::env::temp_dir().join(format!(
        "amivuln-container-{}-{}",
        container_id,
        std::process::id()
    ));
    let result = (|| {
        let eco = export_container(&runner, container_id, &dir)?;
        let packages = container_packages(&runner, eco, &dir)?;
        Ok((eco, packages))
    })();
    // The export can be large; it never outlives the run.
    let _ = std::fs::remove_dir_all(&dir);
    result
}

/// The package that owns each path, or `None` when none does.
pub(crate) fn owners(
    eco: Ecosystem,
    paths: &[String],
) -> std::collections::BTreeMap<String, Option<String>> {
    let runner = SystemRunner::default();
    let backend = match eco {
        Ecosystem::Fedora(_) | Ecosystem::Rocky(_) | Ecosystem::Alma(_) => {
            Backend::Rpm(RpmResolver::new(&runner, eco))
        }
        Ecosystem::Arch => Backend::Pacman(PacmanResolver::new(&runner)),
        // Debian and Ubuntu resolvers come with OSV support; ownership is not
        // needed for the restart command yet.
        Ecosystem::Debian(_)
        | Ecosystem::Ubuntu(_)
        | Ecosystem::Go
        | Ecosystem::Crates
        | Ecosystem::Alpine => {
            return paths.iter().map(|p| (p.clone(), None)).collect();
        }
    };
    paths
        .iter()
        .map(|p| {
            (
                p.clone(),
                backend.resolver().owner_of(p).ok().map(|pkg| pkg.name),
            )
        })
        .collect()
}

/// The running service units, for `amivuln services`.
pub(crate) fn running_services() -> Result<Vec<String>, ResolveError> {
    amivuln_resolve::list_running_services(&SystemRunner::default())
}

pub(crate) fn resolve_all(
    targets: &[String],
    all: bool,
    eco: Ecosystem,
    probe: bool,
) -> (Vec<(String, PackageRef)>, Vec<Unresolved>) {
    // Debian and Ubuntu read no package database on the host: `--all` is only
    // meaningful with `--packages-from` (an inventory exported from a
    // Debian/Ubuntu host), which resolve_scope adds below.
    let runner = SystemRunner::default();
    let mut resolved: Vec<(String, PackageRef)> = Vec::new();
    let mut unresolved: Vec<Unresolved> = Vec::new();
    let backend = match eco {
        Ecosystem::Fedora(_) | Ecosystem::Rocky(_) | Ecosystem::Alma(_) => {
            Some(Backend::Rpm(RpmResolver::new(&runner, eco)))
        }
        Ecosystem::Arch => Some(Backend::Pacman(PacmanResolver::new(&runner))),
        // Debian and Ubuntu read no package database on the host: `--all` is
        // only meaningful with `--packages-from` (an inventory exported from a
        // Debian/Ubuntu host), which resolve_scope adds below.
        Ecosystem::Debian(_)
        | Ecosystem::Ubuntu(_)
        | Ecosystem::Go
        | Ecosystem::Crates
        | Ecosystem::Alpine => None,
    };
    if all {
        match backend.as_ref().map(|b| b.resolver().list_all()) {
            Some(Ok(list)) => resolved.extend(list.into_iter().map(|p| (p.name.clone(), p))),
            Some(Err(e)) => unresolved.push(Unresolved {
                input: "--all".into(),
                reason: e.to_string(),
            }),
            // Debian and Ubuntu: the inventory carries the packages.
            None => {}
        }
    }
    for t in targets {
        // A file is identified by its owner, else its own `.note.package`,
        // else the modules or crates it declares. Debian and Ubuntu have no
        // host package database, so they start at the note.
        if let Target::Path(p) = parse_target(t, |p| Path::new(p).exists()) {
            match resolve_path(&p, eco, backend.as_ref(), probe) {
                Ok(list) => resolved.extend(list.into_iter().map(|pkg| (t.clone(), pkg))),
                Err(e) => unresolved.push(Unresolved {
                    input: t.clone(),
                    reason: e.to_string(),
                }),
            }
            continue;
        }
        let resolved_one = match backend.as_ref() {
            Some(b) => resolve_one(t, eco, b, &runner),
            None => Err(ResolveError::NotFound(t.clone())),
        };
        match resolved_one {
            Ok(p) => resolved.push((t.clone(), p)),
            Err(e) => unresolved.push(Unresolved {
                input: t.clone(),
                reason: e.to_string(),
            }),
        }
    }
    (resolved, unresolved)
}

/// Fetches every source and evaluates every resolved package.
/// The source a host ecosystem's distribution data comes from.
fn host_source_id(eco: Ecosystem) -> SourceId {
    match eco {
        Ecosystem::Arch => SourceId::ArchTracker,
        Ecosystem::Fedora(_) => SourceId::FedoraUpdateinfo,
        Ecosystem::Debian(_)
        | Ecosystem::Ubuntu(_)
        | Ecosystem::Rocky(_)
        | Ecosystem::Alma(_)
        | Ecosystem::Go
        | Ecosystem::Crates
        | Ecosystem::Alpine => SourceId::Osv,
    }
}

/// Packages judged by the host's data, packages with their own OSV pass, and
/// whether such a separate pass exists.
type LanguageSplit = (Vec<(String, PackageRef)>, Vec<(String, PackageRef)>, bool);

/// Splits the resolved packages into those the host's distribution data judges
/// and those that get an OSV pass of their own (Go modules and crates on a
/// host whose own source is not OSV). On OSV hosts everything shares one pass.
fn split_language(eco: Ecosystem, resolved: &[(String, PackageRef)]) -> LanguageSplit {
    // Packages whose source differs from the host's get an OSV pass of their
    // own: Debian or Ubuntu packages on a Fedora host (a `--container` scan)
    // and Go or Rust crates anywhere.
    let host_source = host_source_id(eco);
    let separate = resolved
        .iter()
        .any(|(_, p)| p.ecosystem.is_language() || host_source_id(p.ecosystem) != host_source);
    let pick = |own_source: bool| -> Vec<(String, PackageRef)> {
        resolved
            .iter()
            .filter(|(_, p)| {
                !separate
                    || (p.ecosystem.is_language() || host_source_id(p.ecosystem) != host_source)
                        == own_source
            })
            .cloned()
            .collect()
    };
    let language = if separate { pick(true) } else { Vec::new() };
    (pick(false), language, separate)
}

/// One report per resolved package, each judged by the data that applies to it.
fn build_reports(
    resolved: &[(String, PackageRef)],
    separate_lang: bool,
    data: Option<&DistroData>,
    lang_data: Option<&DistroData>,
    nvd_data: &std::collections::BTreeMap<String, Vec<amivuln_sources::nvd::NvdEntry2>>,
    vex: &[VexStatement],
) -> Vec<TargetReport> {
    let (mut distro_index, mut lang_index) = (0usize, 0usize);
    resolved
        .iter()
        .map(|(input, pkg)| {
            let own_pass = separate_lang && pkg.ecosystem.is_language();
            let findings = if own_pass {
                let found = match lang_data {
                    Some(DistroData::Osv(list)) => list
                        .get(lang_index)
                        .map_or_else(Vec::new, |o| osv_findings(pkg, o, vex)),
                    _ => Vec::new(),
                };
                lang_index += 1;
                found
            } else {
                let found = match data {
                    Some(DistroData::Arch(t)) => arch_findings(pkg, t, vex),
                    Some(DistroData::Fedora(i)) => fedora_findings(pkg, i, vex),
                    Some(DistroData::Osv(list)) => list
                        .get(distro_index)
                        .map_or_else(Vec::new, |o| osv_findings(pkg, o, vex)),
                    None => Vec::new(),
                };
                distro_index += 1;
                found
            };
            // NVD fallback: products with no distro data (the string
            // heuristic targets) get their CVEs from the NVD 2.0 API.
            let mut findings = findings;
            if pkg.provenance == amivuln_core::Provenance::StringHeuristic
                && let Some(entries) = nvd_data.get(&pkg.name)
            {
                for entry in entries {
                    let severity = nvd_severity(entry.severity.as_deref());
                    findings.push(Finding::new(
                        entry.id.clone(),
                        severity,
                        Verdict::Affected { fixed_in: None },
                    ));
                }
                sort_findings(&mut findings);
            }
            TargetReport {
                input: input.clone(),
                package: pkg.clone(),
                findings,
            }
        })
        .collect()
}

/// Maps the textual severity of an NVD metric to a [`Severity`].
fn nvd_severity(text: Option<&str>) -> Severity {
    match text {
        Some("CRITICAL") => Severity::Critical,
        Some("HIGH") => Severity::High,
        Some("MODERATE" | "MEDIUM") => Severity::Medium,
        Some("LOW") => Severity::Low,
        _ => Severity::Unknown,
    }
}

async fn gather(
    fetcher: &Fetcher<'_>,
    cfg: &Config,
    eco: Ecosystem,
    resolved: &[(String, PackageRef)],
    probe: &[String],
    vex: &[VexStatement],
) -> Evaluated {
    let mut sources = Vec::new();
    if resolved.is_empty() {
        return Evaluated {
            targets: Vec::new(),
            sources,
            known: Vec::new(),
        };
    }
    let (distro_resolved, lang_resolved, separate_lang) = split_language(eco, resolved);
    let (data, rep) = if distro_resolved.is_empty() {
        (None, None)
    } else if cfg.sources.distro.enabled {
        let mut attempt = cfg.clone();
        let mut latest = load_distro(fetcher, eco, &attempt, &distro_resolved).await;
        // Then the declared mirrors, only after a failed primary.
        for mirror_url in &cfg.sources.distro.fallback {
            if !matches!(latest.1.status, SourceStatus::Failed(_)) {
                break;
            }
            attempt.sources.distro.url = Some(mirror_url.clone());
            latest = load_distro(fetcher, eco, &attempt, &distro_resolved).await;
        }
        (latest.0, Some(latest.1))
    } else {
        let id = host_source_id(eco);
        (
            None,
            Some(report_of(
                id,
                false,
                SourceStatus::Skipped("disabled".into()),
                Duration::ZERO,
            )),
        )
    };
    sources.extend(rep);
    let lang_data = if lang_resolved.is_empty() {
        None
    } else {
        let mut attempt = cfg.clone();
        let mut latest = load_osv(fetcher, &attempt, &lang_resolved, true).await;
        for mirror_url in &cfg.sources.osv.fallback {
            if !matches!(latest.1.status, SourceStatus::Failed(_)) {
                break;
            }
            attempt.sources.osv.url = Some(mirror_url.clone());
            latest = load_osv(fetcher, &attempt, &lang_resolved, true).await;
        }
        let (d, r) = latest;
        sources.push(r);
        d
    };
    let known: Vec<String> = data
        .as_ref()
        .map(|d: &DistroData| probe.iter().filter(|c| d.knows(c)).cloned().collect())
        .unwrap_or_default();

    let mut nvd_data = std::collections::BTreeMap::new();
    if resolved
        .iter()
        .any(|(_, p)| p.provenance == amivuln_core::Provenance::StringHeuristic)
    {
        nvd_data = load_and_map_nvd(fetcher, cfg, resolved, &mut sources).await;
    }
    let mut reports = build_reports(
        resolved,
        separate_lang,
        data.as_ref(),
        lang_data.as_ref(),
        &nvd_data,
        vex,
    );

    // KEV and EPSS know CVE ids only; a language advisory without a CVE alias
    // keeps its own id and is not looked up there.
    let mut cves: Vec<String> = reports
        .iter()
        .flat_map(|t| t.findings.iter().map(|f| f.id.clone()))
        .filter(|id| id.starts_with("CVE-"))
        .collect();
    cves.sort_unstable();
    cves.dedup();

    let (kev, epss, enrichment_reports) = load_enrichment(fetcher, cfg, &cves).await;
    sources.extend(enrichment_reports);
    for t in &mut reports {
        enrich(&mut t.findings, kev.as_ref(), epss.as_ref());
        sort_findings(&mut t.findings);
    }
    Evaluated {
        targets: reports,
        sources,
        known,
    }
}

/// Sets up the cache, HTTP client and runtime, then runs [`gather`].
pub(crate) fn evaluate(
    cli: &Cli,
    s: &Settings,
    env: &Env,
    eco: Ecosystem,
    resolved: &[(String, PackageRef)],
    probe: &[String],
    err: &mut dyn Write,
) -> Result<Evaluated, ExitCode> {
    let internal = |err: &mut dyn Write, msg: String| {
        let _ = writeln!(err, "error: {msg}");
        ExitCode::Internal
    };

    let cache = open_cache(&cli.global, s, env, err)
        .map_err(|e| internal(err, format!("cannot create a cache: {e}")))?;
    let ca_pem = match &s.config.network.ca_file {
        Some(path) => Some(read_ca_file(path).map_err(|e| {
            let _ = writeln!(err, "error: {e}");
            ExitCode::Usage
        })?),
        None => None,
    };
    let http = HttpClient::new(HttpConfig {
        timeout: s.timeout,
        allow_insecure: s.config.network.allow_insecure_http,
        proxy: s.config.network.proxy.clone(),
        ca_pem,
        user_agent_suffix: s.config.network.user_agent_suffix.clone(),
        retry: RetryPolicy {
            retries: s.net.retries,
            ..RetryPolicy::default()
        },
        breaker: BreakerPolicy {
            cooldown: s.cooldown,
            ..BreakerPolicy::default()
        },
        min_interval: s.min_interval,
        ..HttpConfig::default()
    })
    .map_err(|e| internal(err, e.to_string()))?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .enable_io()
        .build()
        .map_err(|e| internal(err, format!("cannot start the async runtime: {e}")))?;
    // The offline database is read-only and only consulted offline; a missing
    // or broken one is a warning, never a failure.
    let offline_db = if s.offline {
        match amivuln_cache::offline::open_installed(&offline_dir(env)) {
            Ok(db) => db,
            Err(e) => {
                if !cli.global.quiet {
                    let _ = writeln!(err, "warning: offline database unusable: {e}");
                }
                None
            }
        }
    } else {
        None
    };
    let fetcher = Fetcher {
        http: &http,
        cache: &cache,
        now: env.now,
        policy: CachePolicy {
            ttl: s.cache_ttl,
            stale_max_age: s.stale_max_age,
        },
        offline: s.offline,
        offline_db: offline_db.as_ref(),
    };
    Ok(rt.block_on(gather(&fetcher, &s.config, eco, resolved, probe, &s.vex)))
}

/// The offline database directory for this user.
fn offline_dir(env: &Env) -> PathBuf {
    amivuln_cache::offline::default_dir(env.xdg_data_home.as_deref(), env.home.as_deref())
        .unwrap_or_else(|| PathBuf::from("/var/lib/amivuln/offline"))
}

/// Opens the on-disk cache. A cache that cannot be opened is a warning, not
/// a failure: the run continues with a throwaway in-memory cache, and says so.
fn open_cache(g: &Global, s: &Settings, env: &Env, err: &mut dyn Write) -> Result<Cache, String> {
    let memory = |err: &mut dyn Write, why: Option<String>| {
        if let Some(why) = why
            && !g.quiet
        {
            let _ = writeln!(err, "warning: {why}; using an in-memory cache for this run");
        }
        Cache::in_memory().map_err(|e| e.to_string())
    };
    if g.flags.no_cache {
        return memory(err, None);
    }
    let Some(path) = cache_path(&s.config, env) else {
        return memory(err, Some("cannot determine the cache directory".into()));
    };
    match Cache::open(&path) {
        Ok(c) => Ok(c),
        Err(e) => memory(err, Some(format!("{}: {e}", path.display()))),
    }
}

/// Largest CA bundle accepted; a real bundle is far smaller.
const MAX_CA_FILE_BYTES: u64 = 1024 * 1024;

fn read_ca_file(path: &str) -> Result<Vec<u8>, String> {
    use std::io::Read;
    let file = std::fs::File::open(path).map_err(|e| format!("network.ca_file {path:?}: {e}"))?;
    let mut buf = Vec::new();
    file.take(MAX_CA_FILE_BYTES + 1)
        .read_to_end(&mut buf)
        .map_err(|e| format!("network.ca_file {path:?}: {e}"))?;
    if buf.len() as u64 > MAX_CA_FILE_BYTES {
        return Err(format!("network.ca_file {path:?} is larger than 1 MiB"));
    }
    Ok(buf)
}

/// Loads KEV and EPSS with failover over their mirrors, when there are CVE
/// ids to enrich. Sources that are disabled are simply skipped.
async fn load_enrichment(
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
async fn load_and_map_nvd(
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
async fn load_nvd(
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
