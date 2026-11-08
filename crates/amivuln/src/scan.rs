// SPDX-FileCopyrightText: 2026 amivuln contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Resolving targets, fetching sources and evaluating packages. Shared by
//! `check`, `cve`, `pending` and the other commands that need findings.

use std::io::Write;
use std::path::Path;
use std::time::Duration;

use amivuln_cache::{Cache, Policy as CachePolicy};
use amivuln_core::{
    Ecosystem, ExitCode, PackageRef, SourceId, SourceReport, SourceStatus, TargetReport,
    Unresolved, sort_findings,
};
use amivuln_resolve::{
    PackageResolver, PacmanResolver, ResolveError, RpmResolver, SystemRunner, Target, exe_for_unit,
    from_name_version, from_purl, parse_target,
};
use amivuln_sources::arch::ArchTracker;
use amivuln_sources::epss::EpssScores;
use amivuln_sources::fedora::{Updateinfo, updateinfo_location};
use amivuln_sources::fetch::{FetchError, Fetched, fetch_cached};
use amivuln_sources::http::{HttpClient, HttpConfig};
use amivuln_sources::kev::Kev;

use crate::app::{Env, Settings, cache_path, cpu_arch};
use crate::cli::{Cli, Global};
use crate::config::Config;
use crate::pipeline::{arch_findings, enrich, fedora_findings};

/// Default endpoints.
const ARCH_URL: &str = "https://security.archlinux.org/issues/all.json";
const FEDORA_UPDATES: &str = "https://dl.fedoraproject.org/pub/fedora/linux/updates";
const KEV_URL: &str =
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
const EPSS_URL: &str = "https://api.first.org/data/v1/epss";
/// CVE ids per EPSS request, to keep URLs short.
const EPSS_BATCH: usize = 50;

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
    v
}

fn resolve_one(
    input: &str,
    eco: Ecosystem,
    backend: &Backend<'_>,
    runner: &SystemRunner,
) -> Result<PackageRef, ResolveError> {
    let exists = |p: &str| Path::new(p).exists();
    match parse_target(input, exists) {
        Target::Purl(p) => from_purl(
            &p,
            match eco {
                Ecosystem::Fedora(v) => Some(v),
                Ecosystem::Arch => None,
            },
        ),
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

/// Distro data, loaded once per run.
enum DistroData {
    Arch(ArchTracker),
    Fedora(Updateinfo),
}

impl DistroData {
    fn knows(&self, cve: &str) -> bool {
        match self {
            Self::Arch(t) => t.knows(cve),
            Self::Fedora(i) => i.knows(cve),
        }
    }
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
}

impl Fetcher<'_> {
    async fn get(&self, url: &str) -> Result<Fetched, FetchError> {
        fetch_cached(
            self.http,
            self.cache,
            url,
            url,
            self.now,
            self.policy,
            self.offline,
        )
        .await
    }
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

async fn load_distro(
    f: &Fetcher<'_>,
    eco: Ecosystem,
    cfg: &Config,
) -> (Option<DistroData>, SourceReport) {
    let required = cfg.sources.distro.required;
    let override_url = cfg.sources.distro.url.clone();
    match eco {
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

/// The packages a command works on: the host's installed packages for `--all`,
/// a `--packages-from` inventory, and any explicit targets.
pub(crate) fn resolve_scope(
    cli: &Cli,
    targets: &[String],
    all: bool,
    eco: Ecosystem,
) -> Result<Scope, String> {
    let (mut resolved, unresolved) = resolve_all(targets, all, eco);
    if let Some(path) = &cli.global.packages_from {
        resolved.extend(read_inventory(path, eco)?);
    }
    Ok((resolved, unresolved))
}

pub(crate) fn resolve_all(
    targets: &[String],
    all: bool,
    eco: Ecosystem,
) -> (Vec<(String, PackageRef)>, Vec<Unresolved>) {
    let runner = SystemRunner::default();
    let backend = match eco {
        Ecosystem::Fedora(_) => Backend::Rpm(RpmResolver::new(&runner, eco)),
        Ecosystem::Arch => Backend::Pacman(PacmanResolver::new(&runner)),
    };
    let mut resolved: Vec<(String, PackageRef)> = Vec::new();
    let mut unresolved: Vec<Unresolved> = Vec::new();
    if all {
        match backend.resolver().list_all() {
            Ok(list) => resolved.extend(list.into_iter().map(|p| (p.name.clone(), p))),
            Err(e) => unresolved.push(Unresolved {
                input: "--all".into(),
                reason: e.to_string(),
            }),
        }
    }
    for t in targets {
        match resolve_one(t, eco, &backend, &runner) {
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
async fn gather(
    fetcher: &Fetcher<'_>,
    cfg: &Config,
    eco: Ecosystem,
    resolved: &[(String, PackageRef)],
    probe: &[String],
) -> Evaluated {
    let mut sources = Vec::new();
    if resolved.is_empty() {
        return Evaluated {
            targets: Vec::new(),
            sources,
            known: Vec::new(),
        };
    }
    let (data, rep) = if cfg.sources.distro.enabled {
        load_distro(fetcher, eco, cfg).await
    } else {
        let id = match eco {
            Ecosystem::Arch => SourceId::ArchTracker,
            Ecosystem::Fedora(_) => SourceId::FedoraUpdateinfo,
        };
        (
            None,
            report_of(
                id,
                false,
                SourceStatus::Skipped("disabled".into()),
                Duration::ZERO,
            ),
        )
    };
    sources.push(rep);
    let known: Vec<String> = data
        .as_ref()
        .map(|d| probe.iter().filter(|c| d.knows(c)).cloned().collect())
        .unwrap_or_default();

    let mut reports: Vec<TargetReport> = resolved
        .iter()
        .map(|(input, pkg)| {
            let findings = match &data {
                Some(DistroData::Arch(t)) => arch_findings(pkg, t),
                Some(DistroData::Fedora(i)) => fedora_findings(pkg, i),
                None => Vec::new(),
            };
            TargetReport {
                input: input.clone(),
                package: pkg.clone(),
                findings,
            }
        })
        .collect();

    let mut cves: Vec<String> = reports
        .iter()
        .flat_map(|t| t.findings.iter().map(|f| f.id.clone()))
        .collect();
    cves.sort_unstable();
    cves.dedup();

    let (mut kev, mut epss) = (None, None);
    if !cves.is_empty() {
        if cfg.sources.kev.enabled {
            let (k, rep) = load_kev(fetcher, cfg).await;
            kev = k;
            sources.push(rep);
        }
        if cfg.sources.epss.enabled {
            let (e, rep) = load_epss(fetcher, cfg, &cves).await;
            epss = e;
            sources.push(rep);
        }
    }
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
    let http = HttpClient::new(HttpConfig {
        timeout: s.timeout,
        allow_insecure: s.config.network.allow_insecure_http,
        ..HttpConfig::default()
    })
    .map_err(|e| internal(err, e.to_string()))?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .enable_io()
        .build()
        .map_err(|e| internal(err, format!("cannot start the async runtime: {e}")))?;
    let fetcher = Fetcher {
        http: &http,
        cache: &cache,
        now: env.now,
        policy: CachePolicy {
            ttl: s.cache_ttl,
            stale_max_age: s.stale_max_age,
        },
        offline: s.offline,
    };
    Ok(rt.block_on(gather(&fetcher, &s.config, eco, resolved, probe)))
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
