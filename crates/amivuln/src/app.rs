// SPDX-FileCopyrightText: 2026 amivuln contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Orchestration: settings, host detection, target resolution, source
//! fetching, policy and output. The only place that touches the outside world.

use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;

use amivuln_cache::Cache;
use amivuln_core::{
    Condition, Ecosystem, ExitCode, FailOn, Finding, HostMeta, Policy, RunReport, exit_code,
    is_complete,
};
use amivuln_report::{Format, RenderOptions, render};
use amivuln_resolve::parse_os_release;
use clap::{CommandFactory, Parser};

use crate::cli::{CacheAction, Cli, Command, ConfigAction, Global, Shell};
use crate::config::{self, Config, parse_duration};
use crate::scan::{evaluate, expand_targets, resolve_scope};

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
pub(crate) struct Settings {
    pub(crate) config: Config,
    pub(crate) format: Format,
    pub(crate) color: bool,
    pub(crate) policy: Policy,
    pub(crate) offline: bool,
    pub(crate) cache_ttl: i64,
    pub(crate) stale_max_age: i64,
    pub(crate) timeout: Duration,
    /// Accepted findings from the ignore file (empty when none).
    pub(crate) ignores: Vec<amivuln_core::IgnoreEntry>,
    /// `OpenVEX` statements from the --vex files (empty when none).
    pub(crate) vex: Vec<amivuln_core::VexStatement>,
    /// The parsed `--baseline`, when given.
    pub(crate) baseline: Option<amivuln_core::Baseline>,
}

pub(crate) fn usage(stderr: &mut dyn Write, msg: &str) -> ExitCode {
    let _ = writeln!(stderr, "error: {msg}");
    ExitCode::Usage
}

fn secs(d: Duration) -> i64 {
    i64::try_from(d.as_secs()).unwrap_or(i64::MAX)
}

pub(crate) fn settings(g: &Global, env: &Env) -> Result<(Settings, Option<PathBuf>), String> {
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
    let ignores = config::load_ignore(&cfg, from.as_deref().and_then(|p| p.parent()), &today(env))
        .map_err(|e| format!("ignore file: {e}"))?;
    let baseline = g
        .baseline
        .as_deref()
        .map(|path| {
            let text =
                std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
            amivuln_core::parse_baseline(text.as_bytes())
                .map_err(|e| format!("{}: {e}", path.display()))
        })
        .transpose()
        .map_err(|e| format!("baseline: {e}"))?;
    let mut vex = Vec::new();
    for path in &g.vex {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let parsed = amivuln_core::parse_vex(text.as_bytes())
            .map_err(|e| format!("{}: {e}", path.display()))?;
        vex.extend(parsed);
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
            ignores,
            vex,
            baseline,
            config: cfg,
        },
        from,
    ))
}

/// Parses `fedora:44` or `arch`.
pub(crate) fn parse_distro(s: &str) -> Result<Ecosystem, String> {
    match s.split_once(':') {
        Some(("fedora", v)) => v
            .parse()
            .map(Ecosystem::Fedora)
            .map_err(|_| format!("invalid Fedora release {v:?} in --distro")),
        Some(("rocky", v)) => v
            .parse::<u16>()
            .ok()
            .filter(|n| (8..=9).contains(n))
            .map(Ecosystem::Rocky)
            .ok_or_else(|| format!("invalid Rocky release {v:?} in --distro (use 8 or 9)")),
        Some(("alma" | "almalinux", v)) => v
            .parse::<u16>()
            .ok()
            .filter(|n| (8..=9).contains(n))
            .map(Ecosystem::Alma)
            .ok_or_else(|| format!("invalid AlmaLinux release {v:?} in --distro (use 8 or 9)")),
        Some(("debian", v)) => v
            .parse()
            .map(Ecosystem::Debian)
            .map_err(|_| format!("invalid Debian release {v:?} in --distro")),
        // Ubuntu releases are "24.04" or "24.10"; the OSV ecosystem keeps the
        // decimal form. Only LTS releases have OSV data.
        Some(("ubuntu", v)) => {
            // Ubuntu releases are "NN.04" or "NN.10"; the OSV ecosystem keeps
            // the decimal form and covers interim releases too.
            match v.replace('.', "").parse::<u16>() {
                Ok(n) if (404..=9904).contains(&n) && (n % 100 == 4 || n % 100 == 10) => {
                    Ok(Ecosystem::Ubuntu(n))
                }
                _ => Err(format!(
                    "invalid Ubuntu release {v:?}; use a form like ubuntu:24.04"
                )),
            }
        }
        None if s == "arch" => Ok(Ecosystem::Arch),
        _ => Err(format!(
            "unsupported --distro {s:?}; use fedora:NN, arch, debian:NN, ubuntu:NN.NN, rocky:NN or alma:NN"
        )),
    }
}

pub(crate) fn host_ecosystem(g: &Global, env: &Env) -> Result<Ecosystem, String> {
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

pub(crate) fn cpu_arch() -> &'static str {
    match std::env::consts::ARCH {
        "powerpc64" => "ppc64le",
        other => other,
    }
}

/// Runs the program and returns the process exit code.
pub fn run(args: &[String], env: &Env, stdout: &mut dyn Write, stderr: &mut dyn Write) -> ExitCode {
    let cli = match Cli::try_parse_from(crate::cli::normalize_args(args)) {
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
        Some(Command::Cve { ids }) => crate::commands::cve(&cli, ids, env, stdout, stderr),
        Some(Command::Pending) => crate::commands::pending(&cli, env, stdout, stderr),
        Some(Command::Services) => crate::commands::services(&cli, env, stdout, stderr),
        Some(Command::Restart) => crate::commands::restart(&cli, env, stdout, stderr),
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

pub(crate) fn cache_path(cfg: &Config, env: &Env) -> Option<PathBuf> {
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

/// The UTC date, `YYYY-MM-DD`, for ignore-file expiry checks.
pub(crate) fn today(env: &Env) -> String {
    jiff::Timestamp::from_second(env.now).map_or_else(
        |_| "1970-01-01".to_owned(),
        |t| t.strftime("%Y-%m-%d").to_string(),
    )
}

/// How a scan is presented and judged.
#[derive(Debug, Clone, Copy)]
pub(crate) struct CheckMode {
    /// Whole-scope scan: leave out clean targets and total them.
    pub(crate) hide_clean: bool,
    /// An unresolved target fails the run (exit 3). Off for scans whose
    /// targets are discovered, such as services, where some are not packages.
    pub(crate) unresolved_is_fatal: bool,
}

fn check(
    cli: &Cli,
    subcommand_targets: &[String],
    all: bool,
    env: &Env,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> ExitCode {
    let mode = CheckMode {
        hide_clean: all,
        unresolved_is_fatal: true,
    };
    check_with(cli, subcommand_targets, all, mode, env, out, err)
}

pub(crate) fn check_with(
    cli: &Cli,
    subcommand_targets: &[String],
    all: bool,
    mode: CheckMode,
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
    if targets.is_empty() && !all && cli.global.packages_from.is_none() {
        return usage(
            err,
            "no target given; pass a package, a file path, name@version, a purl, --all or --packages-from (see --help)",
        );
    }

    let (resolved, unresolved) = match resolve_scope(cli, &targets, all, eco) {
        Ok(v) => v,
        Err(m) => return usage(err, &m),
    };
    let ev = match evaluate(cli, &s, env, eco, &resolved, &[], err) {
        Ok(v) => v,
        Err(code) => return code,
    };
    let (targets_out, sources) = (ev.targets, ev.sources);
    let all_findings: Vec<Finding> = targets_out
        .iter()
        .flat_map(|t| t.findings.clone())
        .collect();
    let suppressed = amivuln_core::suppress(&all_findings, &s.ignores, &today(env));
    let report = RunReport {
        tool_version: env!("CARGO_PKG_VERSION").to_owned(),
        generated_at: jiff::Timestamp::from_second(env.now)
            .map_or_else(|_| "1970-01-01T00:00:00Z".to_owned(), |t| t.to_string()),
        host: host_meta(eco),
        complete: is_complete(&sources),
        suppressed,
        sources,
        targets: targets_out,
        unresolved,
    };

    if let Err(e) = render(
        &report,
        s.format,
        RenderOptions {
            color: s.color,
            hide_clean: mode.hide_clean,
        },
        out,
    ) {
        // A closed pipe (`| head`) is not an error worth a message.
        if e.kind() != std::io::ErrorKind::BrokenPipe {
            let _ = writeln!(err, "error: cannot write the report: {e}");
        }
        return ExitCode::Internal;
    }
    exit_for(&report, &s, mode)
}

fn exit_for(report: &RunReport, s: &Settings, mode: CheckMode) -> ExitCode {
    let mut conditions = Vec::new();
    if !report.complete && s.config.policy.fail_on_incomplete {
        conditions.push(Condition::Incomplete);
    }
    if mode.unresolved_is_fatal && !report.unresolved.is_empty() {
        conditions.push(Condition::Unresolved);
    }
    let findings: Vec<Finding> = report
        .targets
        .iter()
        .flat_map(|t| t.findings.clone())
        .filter(|f| !report.suppressed.contains_key(&f.id))
        .collect();
    // With a baseline only new findings violate the policy.
    let findings = match &s.baseline {
        Some(b) => {
            let new: std::collections::BTreeSet<String> = b
                .new_findings(&report.targets)
                .into_values()
                .flatten()
                .collect();
            findings
                .into_iter()
                .filter(|f| new.contains(&f.id))
                .collect()
        }
        None => findings,
    };
    if s.policy.violated_by(&findings) {
        conditions.push(Condition::Violation);
    }
    exit_code(&conditions)
}

pub(crate) fn host_meta(eco: Ecosystem) -> HostMeta {
    let (os_id, os_version) = match eco {
        Ecosystem::Fedora(v) => ("fedora".to_owned(), v.to_string()),
        Ecosystem::Arch => ("arch".to_owned(), "rolling".to_owned()),
        Ecosystem::Debian(v) => ("debian".to_owned(), v.to_string()),
        Ecosystem::Ubuntu(v) => ("ubuntu".to_owned(), format!("{}.{}", v / 100, v % 100)),
        Ecosystem::Rocky(v) => ("rocky".to_owned(), v.to_string()),
        Ecosystem::Alma(v) => ("almalinux".to_owned(), v.to_string()),
    };
    HostMeta {
        os_id,
        os_version,
        arch: cpu_arch().to_owned(),
    }
}
