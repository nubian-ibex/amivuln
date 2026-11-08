// SPDX-FileCopyrightText: 2026 amivuln contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Orchestration: settings, host detection, target resolution, source
//! fetching, policy and output. The only place that touches the outside world.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use amivuln_cache::{Cache, Policy as CachePolicy};
use amivuln_core::{
    Condition, Ecosystem, ExitCode, FailOn, Finding, HostMeta, PackageRef, Policy, RunReport,
    SourceId, SourceReport, SourceStatus, TargetReport, Unresolved, exit_code, is_complete,
    sort_findings,
};
use amivuln_report::{Format, RenderOptions, render};
use amivuln_resolve::{
    PackageResolver, PacmanResolver, ResolveError, RpmResolver, SystemRunner, Target, exe_for_unit,
    from_name_version, from_purl, parse_os_release, parse_target,
};
use amivuln_sources::arch::ArchTracker;
use amivuln_sources::epss::EpssScores;
use amivuln_sources::fedora::{Updateinfo, updateinfo_location};
use amivuln_sources::fetch::{FetchError, Fetched, fetch_cached};
use amivuln_sources::http::{HttpClient, HttpConfig};
use amivuln_sources::kev::Kev;
use clap::{CommandFactory, Parser};

use crate::cli::{CacheAction, Cli, Command, ConfigAction, Global, Shell};
use crate::config::{self, Config, parse_duration};
use crate::pipeline::{arch_findings, enrich, fedora_findings};

/// Default endpoints.
const ARCH_URL: &str = "https://security.archlinux.org/issues/all.json";
const FEDORA_UPDATES: &str = "https://dl.fedoraproject.org/pub/fedora/linux/updates";
const KEV_URL: &str =
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
const EPSS_URL: &str = "https://api.first.org/data/v1/epss";
/// CVE ids per EPSS request, to keep URLs short.
const EPSS_BATCH: usize = 50;

/// Process environment, injectable for tests.
#[derive(Debug, Clone, Default)]
pub struct Env {
    /// Current directory.
    pub cwd: PathBuf,
    /// `HOME`.
    pub home: Option<PathBuf>,
    /// `XDG_CONFIG_HOME`.
    pub xdg_config_home: Option<PathBuf>,
    /// `XDG_CACHE_HOME`.
    pub xdg_cache_home: Option<PathBuf>,
    /// Contents of `/etc/os-release`, when readable.
    pub os_release: Option<String>,
    /// `NO_COLOR` is set and non-empty.
    pub no_color: bool,
    /// Standard output is a terminal.
    pub stdout_is_tty: bool,
    /// Current Unix time.
    pub now: i64,
}

impl Env {
    /// Reads the real process environment.
    #[must_use]
    pub fn from_process() -> Self {
        use std::io::IsTerminal;
        let var = |k: &str| {
            std::env::var_os(k)
                .filter(|v| !v.is_empty())
                .map(PathBuf::from)
        };
        let os_release = std::fs::File::open("/etc/os-release").ok().and_then(|f| {
            use std::io::Read;
            let mut s = String::new();
            f.take(64 * 1024).read_to_string(&mut s).ok().map(|_| s)
        });
        Self {
            cwd: std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/")),
            home: var("HOME"),
            xdg_config_home: var("XDG_CONFIG_HOME"),
            xdg_cache_home: var("XDG_CACHE_HOME"),
            os_release,
            no_color: std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty()),
            stdout_is_tty: std::io::stdout().is_terminal(),
            now: jiff::Timestamp::now().as_second(),
        }
    }
}

/// Resolved settings for one run.
#[derive(Debug)]
struct Settings {
    config: Config,
    format: Format,
    color: bool,
    policy: Policy,
    offline: bool,
    cache_ttl: i64,
    stale_max_age: i64,
    timeout: Duration,
}

fn usage(stderr: &mut dyn Write, msg: &str) -> ExitCode {
    let _ = writeln!(stderr, "error: {msg}");
    ExitCode::Usage
}

fn secs(d: Duration) -> i64 {
    i64::try_from(d.as_secs()).unwrap_or(i64::MAX)
}

fn settings(g: &Global, env: &Env) -> Result<(Settings, Option<PathBuf>), String> {
    let candidates = config::search_path(
        &env.cwd,
        env.xdg_config_home.as_deref(),
        env.home.as_deref(),
    );
    let (cfg, from) = config::load(g.config.as_deref(), &candidates).map_err(|e| e.0)?;

    let format: Format = g.format.as_deref().unwrap_or(&cfg.output.format).parse()?;
    let color_mode = g.color.as_deref().unwrap_or(&cfg.output.color);
    let color = match color_mode {
        "always" => true,
        "never" => false,
        "auto" => env.stdout_is_tty && !env.no_color,
        other => {
            return Err(format!(
                "invalid --color value {other:?}; use auto, always or never"
            ));
        }
    };
    let fail_on: FailOn = g
        .fail_on
        .as_deref()
        .unwrap_or(&cfg.policy.fail_on)
        .parse()?;
    let fail_on_epss = g.fail_on_epss.or(cfg.policy.fail_on_epss);
    if let Some(e) = fail_on_epss
        && !(0.0..=1.0).contains(&e)
    {
        return Err("--fail-on-epss must be between 0.0 and 1.0".into());
    }
    let ttl = parse_duration(&cfg.general.cache_ttl).map_err(|e| e.0)?;
    let stale = parse_duration(&cfg.general.stale_max_age).map_err(|e| e.0)?;
    let timeout = parse_duration(&cfg.general.timeout).map_err(|e| e.0)?;
    Ok((
        Settings {
            format,
            color,
            policy: Policy {
                fail_on,
                fail_on_epss,
                strict: g.flags.strict || cfg.policy.strict,
            },
            offline: g.flags.offline || cfg.general.offline,
            cache_ttl: secs(ttl),
            stale_max_age: secs(stale),
            timeout,
            config: cfg,
        },
        from,
    ))
}

/// Parses `fedora:44` or `arch`.
fn parse_distro(s: &str) -> Result<Ecosystem, String> {
    match s.split_once(':') {
        Some(("fedora", v)) => v
            .parse()
            .map(Ecosystem::Fedora)
            .map_err(|_| format!("invalid Fedora release {v:?} in --distro")),
        None if s == "arch" => Ok(Ecosystem::Arch),
        _ => Err(format!("unsupported --distro {s:?}; use fedora:NN or arch")),
    }
}

fn host_ecosystem(g: &Global, env: &Env) -> Result<Ecosystem, String> {
    if let Some(d) = &g.distro {
        return parse_distro(d);
    }
    env.os_release
        .as_deref()
        .and_then(parse_os_release)
        .map(|h| h.ecosystem)
        .ok_or_else(|| {
            "this distribution is not supported yet (Fedora and Arch Linux are); \
             use --distro fedora:NN or --distro arch to query for one of them"
                .to_owned()
        })
}

fn cpu_arch() -> &'static str {
    match std::env::consts::ARCH {
        "powerpc64" => "ppc64le",
        other => other,
    }
}

/// Runs the program and returns the process exit code.
pub fn run(args: &[String], env: &Env, stdout: &mut dyn Write, stderr: &mut dyn Write) -> ExitCode {
    let cli = match Cli::try_parse_from(args) {
        Ok(c) => c,
        Err(e) => {
            // clap prints help and version to stdout and errors to stderr.
            let code = e.exit_code();
            let text = e.render().to_string();
            if code == 0 {
                let _ = stdout.write_all(text.as_bytes());
                return ExitCode::Success;
            }
            let _ = stderr.write_all(text.as_bytes());
            return ExitCode::Usage;
        }
    };
    match &cli.command {
        Some(Command::Version { json }) => version(*json, stdout),
        Some(Command::Completions { shell }) => completions(*shell, stdout),
        Some(Command::Config { action }) => config_cmd(action, &cli.global, env, stdout, stderr),
        Some(Command::Cache { action }) => cache_cmd(action, &cli.global, env, stdout, stderr),
        Some(Command::Check { targets, all }) => check(&cli, targets, *all, env, stdout, stderr),
        None => check(&cli, &cli.targets, cli.all, env, stdout, stderr),
    }
}

fn version(json: bool, out: &mut dyn Write) -> ExitCode {
    let v = env!("CARGO_PKG_VERSION");
    let _ = if json {
        writeln!(
            out,
            "{{\"name\":\"amivuln\",\"version\":\"{v}\",\"schema_version\":{}}}",
            amivuln_report::SCHEMA_VERSION
        )
    } else {
        writeln!(out, "amivuln {v}")
    };
    ExitCode::Success
}

fn completions(shell: Shell, out: &mut dyn Write) -> ExitCode {
    use clap_complete::{Shell as S, generate};
    let s = match shell {
        Shell::Bash => S::Bash,
        Shell::Zsh => S::Zsh,
        Shell::Fish => S::Fish,
        Shell::Elvish => S::Elvish,
        Shell::Powershell => S::PowerShell,
    };
    generate(s, &mut Cli::command(), "amivuln", out);
    ExitCode::Success
}

fn config_cmd(
    action: &ConfigAction,
    g: &Global,
    env: &Env,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> ExitCode {
    if let ConfigAction::Init { path } = action {
        let target = path.clone().or_else(|| {
            config::user_config_path(env.xdg_config_home.as_deref(), env.home.as_deref())
        });
        let Some(target) = target else {
            return usage(
                err,
                "cannot determine the configuration directory; pass --path",
            );
        };
        if target.exists() {
            return usage(
                err,
                &format!("{} already exists; not overwriting", target.display()),
            );
        }
        if let Some(dir) = target.parent()
            && let Err(e) = std::fs::create_dir_all(dir)
        {
            return usage(err, &format!("{}: {e}", dir.display()));
        }
        return match std::fs::write(&target, config::TEMPLATE) {
            Ok(()) => {
                let _ = writeln!(out, "wrote {}", target.display());
                ExitCode::Success
            }
            Err(e) => usage(err, &format!("{}: {e}", target.display())),
        };
    }
    let (s, from) = match settings(g, env) {
        Ok(v) => v,
        Err(m) => return usage(err, &m),
    };
    let source = from.map_or_else(
        || "built-in defaults".to_owned(),
        |p| p.display().to_string(),
    );
    if matches!(action, ConfigAction::Validate) {
        let _ = writeln!(out, "configuration is valid ({source})");
        return ExitCode::Success;
    }
    let _ = writeln!(out, "# source: {source}");
    match s.config.to_toml() {
        Ok(t) => {
            let _ = out.write_all(t.as_bytes());
            ExitCode::Success
        }
        Err(e) => usage(err, &e.0),
    }
}

fn cache_path(cfg: &Config, env: &Env) -> Option<PathBuf> {
    let dir = cfg
        .general
        .cache_dir
        .as_ref()
        .map(PathBuf::from)
        .or_else(|| {
            config::default_cache_dir(env.xdg_cache_home.as_deref(), env.home.as_deref())
        })?;
    Some(dir.join("cache.sqlite"))
}

fn cache_cmd(
    action: &CacheAction,
    g: &Global,
    env: &Env,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> ExitCode {
    let (s, _) = match settings(g, env) {
        Ok(v) => v,
        Err(m) => return usage(err, &m),
    };
    let Some(path) = cache_path(&s.config, env) else {
        return usage(
            err,
            "cannot determine the cache directory; set general.cache_dir",
        );
    };
    let cache = match Cache::open(&path) {
        Ok(c) => c,
        Err(e) => return usage(err, &format!("{}: {e}", path.display())),
    };
    let result = match action {
        CacheAction::Info => cache.info().map(|i| {
            let _ = writeln!(
                out,
                "path:    {}\nentries: {}\nbytes:   {}",
                path.display(),
                i.entries,
                i.bytes
            );
        }),
        CacheAction::Clear => cache.clear().map(|()| {
            let _ = writeln!(out, "cleared {}", path.display());
        }),
    };
    match result {
        Ok(()) => ExitCode::Success,
        Err(e) => usage(err, &e.to_string()),
    }
}

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

fn expand_targets(cli: &Cli, subcommand_targets: &[String]) -> Vec<String> {
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

fn resolve_all(
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
) -> (Vec<TargetReport>, Vec<SourceReport>) {
    let mut sources = Vec::new();
    if resolved.is_empty() {
        return (Vec::new(), sources);
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
    (reports, sources)
}

/// Sets up the cache, HTTP client and runtime, then runs [`gather`].
fn evaluate(
    cli: &Cli,
    s: &Settings,
    env: &Env,
    eco: Ecosystem,
    resolved: &[(String, PackageRef)],
    err: &mut dyn Write,
) -> Result<(Vec<TargetReport>, Vec<SourceReport>), ExitCode> {
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
    Ok(rt.block_on(gather(&fetcher, &s.config, eco, resolved)))
}

fn check(
    cli: &Cli,
    subcommand_targets: &[String],
    all: bool,
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
    let targets = expand_targets(cli, subcommand_targets);
    if targets.is_empty() && !all {
        return usage(
            err,
            "no target given; pass a package, a file path, name@version, a purl or --all (see --help)",
        );
    }

    let (resolved, unresolved) = resolve_all(&targets, all, eco);
    let (targets_out, sources) = match evaluate(cli, &s, env, eco, &resolved, err) {
        Ok(v) => v,
        Err(code) => return code,
    };
    let report = RunReport {
        tool_version: env!("CARGO_PKG_VERSION").to_owned(),
        generated_at: jiff::Timestamp::from_second(env.now)
            .map_or_else(|_| "1970-01-01T00:00:00Z".to_owned(), |t| t.to_string()),
        host: host_meta(eco),
        complete: is_complete(&sources),
        sources,
        targets: targets_out,
        unresolved,
    };

    if let Err(e) = render(
        &report,
        s.format,
        RenderOptions {
            color: s.color,
            hide_clean: all,
        },
        out,
    ) {
        // A closed pipe (`| head`) is not an error worth a message.
        if e.kind() != std::io::ErrorKind::BrokenPipe {
            let _ = writeln!(err, "error: cannot write the report: {e}");
        }
        return ExitCode::Internal;
    }
    exit_for(&report, &s)
}

fn exit_for(report: &RunReport, s: &Settings) -> ExitCode {
    let mut conditions = Vec::new();
    if !report.complete && s.config.policy.fail_on_incomplete {
        conditions.push(Condition::Incomplete);
    }
    if !report.unresolved.is_empty() {
        conditions.push(Condition::Unresolved);
    }
    let findings: Vec<Finding> = report
        .targets
        .iter()
        .flat_map(|t| t.findings.clone())
        .collect();
    if s.policy.violated_by(&findings) {
        conditions.push(Condition::Violation);
    }
    exit_code(&conditions)
}

fn host_meta(eco: Ecosystem) -> HostMeta {
    let (os_id, os_version) = match eco {
        Ecosystem::Fedora(v) => ("fedora".to_owned(), v.to_string()),
        Ecosystem::Arch => ("arch".to_owned(), "rolling".to_owned()),
    };
    HostMeta {
        os_id,
        os_version,
        arch: cpu_arch().to_owned(),
    }
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
