// SPDX-FileCopyrightText: 2026 amivuln contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Resolving targets, fetching sources and evaluating packages. Shared by
//! `check`, `cve`, `pending` and the other commands that need findings.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use amivuln_cache::{Cache, Policy as CachePolicy};
use amivuln_core::VexStatement;
use amivuln_core::i18n::tr_args;
use amivuln_core::{
    Ecosystem, ExitCode, Finding, PackageRef, Severity, SourceId, SourceReport, SourceStatus,
    TargetReport, Unresolved, Verdict, sort_findings,
};
use amivuln_resolve::{
    ApkResolver, DpkgResolver, PackageResolver, PacmanResolver, PortageResolver, ResolveError,
    RpmResolver, SystemRunner, Target, exe_for_unit, from_name_version, from_purl,
    language_packages, package_from_note, parse_target,
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
use crate::pipeline::{Assessment, arch_assess, enrich, fedora_assess, glsa_assess, osv_assess};

mod inputs;
mod osv;
mod resolve;
mod sources;

pub(crate) use inputs::resolve_scope;
use osv::{MAX_OSV_ADVISORIES, load_osv};
pub(crate) use resolve::{expand_targets, owners, resolve_all, running_services};
use sources::{load_and_map_nvd, load_distro, load_enrichment, load_foreign};

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
    Glsa(amivuln_sources::glsa::GlsaData),
    /// One entry per package, in the order of the resolved list: an advisory
    /// found for package A must never be judged against package B.
    Osv(Vec<OsvData>),
}

impl DistroData {
    fn knows(&self, cve: &str) -> bool {
        match self {
            Self::Arch(t) => t.knows(cve),
            Self::Fedora(i) => i.knows(cve),
            Self::Glsa(g) => g.knows(cve),
            Self::Osv(list) => list.iter().any(|o| o.knows(cve)),
        }
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
    fn ctx(&self) -> FetchCtx<'_> {
        FetchCtx {
            http: self.http,
            cache: self.cache,
            now: self.now,
            policy: self.policy,
            offline: self.offline,
            offline_db: self.offline_db,
        }
    }

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

/// Resolved packages (with the input that named them) and the inputs that failed.
pub(crate) type Scope = (Vec<(String, PackageRef)>, Vec<Unresolved>);

/// Fetches every source and evaluates every resolved package.
/// The source a host ecosystem's distribution data comes from.
fn host_source_id(eco: Ecosystem) -> SourceId {
    match eco {
        Ecosystem::Arch => SourceId::ArchTracker,
        Ecosystem::Gentoo => SourceId::Glsa,
        Ecosystem::Fedora(_) => SourceId::FedoraUpdateinfo,
        Ecosystem::Debian(_)
        | Ecosystem::Ubuntu(_)
        | Ecosystem::Rocky(_)
        | Ecosystem::Alma(_)
        | Ecosystem::Rhel(_)
        | Ecosystem::Go
        | Ecosystem::Crates
        | Ecosystem::Alpine(_)
        | Ecosystem::Opensuse(_) => SourceId::Osv,
    }
}

/// Packages judged by the host's data, packages with their own OSV pass, and
/// whether such a separate pass exists.
type LanguageSplit = (Vec<(String, PackageRef)>, Vec<(String, PackageRef)>, bool);

/// True for a package whose distribution data is not OSV (Fedora, Arch).
fn served_by_other_distro(pkg: &PackageRef) -> bool {
    !pkg.ecosystem.is_language() && host_source_id(pkg.ecosystem) != SourceId::Osv
}

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

/// The data each group of packages is judged by.
struct Judging<'a> {
    /// The host's distribution.
    distro: Option<&'a DistroData>,
    /// OSV, for language packages and OSV distributions under another host.
    language: Option<&'a DistroData>,
    /// Fedora or Arch data for images of those distributions.
    foreign: &'a [(Ecosystem, DistroData)],
}

/// What `data` says about `pkg`. `index` is the package's place among those the
/// same OSV pass was asked about.
fn assess(
    pkg: &PackageRef,
    data: Option<&DistroData>,
    index: usize,
    vex: &[VexStatement],
) -> Assessment {
    match data {
        Some(DistroData::Arch(t)) => arch_assess(pkg, t, vex),
        Some(DistroData::Fedora(i)) => fedora_assess(pkg, i, vex),
        Some(DistroData::Glsa(g)) => glsa_assess(pkg, g, vex),
        Some(DistroData::Osv(list)) => list
            .get(index)
            .map_or_else(Assessment::default, |o| osv_assess(pkg, o, vex)),
        None => Assessment::default(),
    }
}

/// One report per resolved package, each judged by the data that applies to it.
fn build_reports(
    resolved: &[(String, PackageRef)],
    separate_lang: bool,
    host_source: SourceId,
    judging: &Judging<'_>,
    nvd_data: &std::collections::BTreeMap<String, Vec<amivuln_sources::nvd::NvdEntry2>>,
    vex: &[VexStatement],
) -> Vec<TargetReport> {
    let Judging {
        distro: data,
        language: lang_data,
        foreign,
    } = *judging;
    let (mut distro_index, mut lang_index) = (0usize, 0usize);
    let mut foreign_index: std::collections::HashMap<Ecosystem, usize> =
        std::collections::HashMap::new();
    resolved
        .iter()
        .map(|(input, pkg)| {
            // The same rule as `split_language`: language packages and packages
            // whose source is not the host's were fetched in the own pass.
            let own_pass = separate_lang
                && (pkg.ecosystem.is_language() || host_source_id(pkg.ecosystem) != host_source);
            let Assessment {
                mut findings,
                resolved,
            } = if own_pass && served_by_other_distro(pkg) {
                // A Fedora or Arch package under a host of another family: it
                // is judged by the data of its own distribution.
                let slot = foreign_index.entry(pkg.ecosystem).or_default();
                let own_data = foreign
                    .iter()
                    .find(|(e, _)| *e == pkg.ecosystem)
                    .map(|(_, d)| d);
                let a = assess(pkg, own_data, *slot, vex);
                *slot += 1;
                a
            } else if own_pass {
                let a = assess(pkg, lang_data, lang_index, vex);
                lang_index += 1;
                a
            } else {
                let a = assess(pkg, data, distro_index, vex);
                distro_index += 1;
                a
            };
            // NVD fallback: products with no distro data (the string
            // heuristic targets) get their CVEs from the NVD 2.0 API.
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
                resolved,
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
    // Packages of a Fedora or Arch image under a host of another family are
    // judged by their own distribution's data, one pass per distribution.
    let (other_resolved, lang_resolved): (Vec<_>, Vec<_>) = lang_resolved
        .into_iter()
        .partition(|(_, p)| served_by_other_distro(p));
    let foreign = load_foreign(fetcher, cfg, &other_resolved, &mut sources).await;
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
        host_source_id(eco),
        &Judging {
            distro: data.as_ref(),
            language: lang_data.as_ref(),
            foreign: &foreign,
        },
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

/// The HTTP settings every outgoing request shares: timeout, proxy, extra CA,
/// User-Agent suffix, retries and breaker. The webhook uses it too, so it works
/// wherever the scan does.
pub(crate) fn http_config(s: &Settings) -> Result<HttpConfig, String> {
    let ca_pem = match &s.config.network.ca_file {
        Some(path) => Some(read_ca_file(path)?),
        None => None,
    };
    Ok(HttpConfig {
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
        let _ = writeln!(err, "{}", tr_args("error.line", &[("message", &msg)]));
        ExitCode::Internal
    };

    let cache = open_cache(&cli.global, s, env, err)
        .map_err(|e| internal(err, format!("cannot create a cache: {e}")))?;
    let config = http_config(s).map_err(|e| {
        let _ = writeln!(err, "{}", tr_args("error.line", &[("message", &e)]));
        ExitCode::Usage
    })?;
    let http = HttpClient::new(config).map_err(|e| internal(err, e.to_string()))?;
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
                    let _ = writeln!(err, "{}", tr_args("warning.offline_db", &[("error", &e)]));
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
            let _ = writeln!(err, "{}", tr_args("warning.memory_cache", &[("why", &why)]));
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
        Ok(c) => {
            // Offline runs only read; the rest drop what can no longer be
            // served so the file does not grow with every package update.
            // A failed prune costs disk space, not correctness.
            if !s.offline {
                let _ = c.prune(env.now, s.stale_max_age);
            }
            Ok(c)
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn pkg(eco: Ecosystem, name: &str, version: &str, kind: &str) -> PackageRef {
        let version = match kind {
            "rpm" => amivuln_core::Version::Rpm(version.parse().unwrap_or_else(|n| match n {})),
            _ => amivuln_core::Version::Deb(version.parse().unwrap_or_else(|n| match n {})),
        };
        PackageRef {
            ecosystem: eco,
            name: name.to_owned(),
            source_name: None,
            version,
            arch: None,
            slot: None,
            provenance: amivuln_core::Provenance::PackageDb,
        }
    }

    /// A Fedora image scanned from a Debian host used to fall into the OSV
    /// pass and fail with "no OSV data". It is judged by Fedora's own data.
    #[test]
    fn a_fedora_package_under_a_debian_host_uses_fedora_data() {
        let host = Ecosystem::Debian(12);
        let fedora = pkg(
            Ecosystem::Fedora(43),
            "python3-multipart",
            "0:1.3.0-1.fc43",
            "rpm",
        );
        let debian = pkg(host, "curl", "7.88.1-10", "deb");
        let resolved = vec![
            ("c:curl".to_owned(), debian),
            ("c:python3-multipart".to_owned(), fedora.clone()),
        ];
        let (host_group, own_group, separate) = split_language(host, &resolved);
        assert!(separate);
        assert_eq!(host_group.len(), 1);
        assert_eq!(own_group.len(), 1);
        assert!(served_by_other_distro(&fedora));
        assert!(!served_by_other_distro(&host_group[0].1));

        let info = Updateinfo::parse_zst(include_bytes!(
            "../../../../tests/fixtures/http/fedora-updateinfo/2026-11-07/updateinfo.xml.zst"
        ))
        .unwrap();
        let foreign = [(Ecosystem::Fedora(43), DistroData::Fedora(info))];
        let judging = Judging {
            distro: None,
            language: None,
            foreign: &foreign,
        };
        let reports = build_reports(
            &own_group,
            separate,
            host_source_id(host),
            &judging,
            &std::collections::BTreeMap::new(),
            &[],
        );
        assert!(
            reports[0].findings.iter().any(|f| f.id == "CVE-2026-28356"),
            "{:?}",
            reports[0].findings
        );
    }
}
