// SPDX-FileCopyrightText: 2026 amivuln contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Configuration: file format, search path, environment and validation.
//!
//! Precedence, highest first: command-line flags, `AMIVULN_*` environment
//! variables (both handled by clap), the first configuration file found
//! (`./.amivuln.toml`, `$XDG_CONFIG_HOME/amivuln/config.toml`,
//! `/etc/amivuln/config.toml`), then built-in defaults. Files are not merged:
//! the first one found wins, which keeps the effective value easy to predict.

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// Largest configuration file accepted.
const MAX_CONFIG_BYTES: u64 = 256 * 1024;

/// A configuration problem, written for the user.
#[derive(Debug)]
pub struct ConfigError(pub String);

impl std::error::Error for ConfigError {}

impl core::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

fn err<T>(msg: impl Into<String>) -> Result<T, ConfigError> {
    Err(ConfigError(msg.into()))
}

/// The file format. Unknown keys are rejected so typos do not pass silently.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Config {
    /// Format version of this file.
    pub schema_version: u32,
    /// Accepted findings (ignore file), path relative to the config file.
    pub ignore_file: Option<String>,
    /// General behavior.
    pub general: General,
    /// Output defaults.
    pub output: Output,
    /// Failure policy.
    pub policy: PolicySection,
    /// Network options.
    pub network: Network,
    /// Webhook notifications (`[notify]`).
    pub notify: Notify,
    /// Per-source settings.
    pub sources: Sources,
}

/// `[general]`
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct General {
    /// Never use the network.
    pub offline: bool,
    /// Cache directory; defaults to `$XDG_CACHE_HOME/amivuln`.
    pub cache_dir: Option<String>,
    /// How long a cached response is fresh, for example `6h`.
    pub cache_ttl: String,
    /// How old a cached response may be when the network fails, for example `72h`.
    pub stale_max_age: String,
    /// Per-request timeout, for example `10s`.
    pub timeout: String,
}

/// `[output]`
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Output {
    /// `summary`, `detail` or `json`.
    pub format: String,
    /// `auto`, `always` or `never`.
    pub color: String,
}

/// `[notify]`
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Notify {
    /// POST a compact summary to this URL when the run trips the condition.
    pub webhook: Option<String>,
    /// File with a bearer token sent as `Authorization: Bearer ...`.
    pub bearer_file: Option<String>,
    /// `violation` (default), `incomplete` or `always`.
    pub on: String,
}

impl Default for Notify {
    fn default() -> Self {
        Self {
            webhook: None,
            bearer_file: None,
            on: "violation".to_owned(),
        }
    }
}

/// `[policy]`
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct PolicySection {
    /// `none`, `low`, `medium`, `high`, `critical` or `kev`.
    pub fail_on: String,
    /// Fail when an affected finding reaches this EPSS score.
    pub fail_on_epss: Option<f64>,
    /// Exit 2 when a required source failed.
    pub fail_on_incomplete: bool,
    /// Count unverified findings as violations.
    pub strict: bool,
}

/// `[network]`
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Network {
    /// Allow plain `http://` source URLs (only for a trusted internal mirror).
    pub allow_insecure_http: bool,
    /// Explicit proxy URL (`http://` or `https://`). Credentials in the URL
    /// are never printed. Without it `HTTPS_PROXY` and `NO_PROXY` apply.
    pub proxy: Option<String>,
    /// PEM file with extra trusted root certificates (a corporate CA).
    pub ca_file: Option<String>,
    /// Text appended to the `User-Agent` (printable ASCII, at most 64 bytes).
    pub user_agent_suffix: Option<String>,
    /// Retry attempts per failing call (timeouts, 5xx and 429).
    pub retries: u32,
    /// How long a failing endpoint is skipped before a trial (circuit
    /// breaker cooldown).
    pub cooldown: String,
    /// Minimum spacing between requests to one host, for example `"100ms"`.
    /// None by default.
    pub min_interval: Option<String>,
}

/// `[sources]`
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Sources {
    /// Distribution data (Arch Security Tracker, Fedora updateinfo).
    pub distro: DistroCfg,
    /// CISA Known Exploited Vulnerabilities.
    pub kev: SourceCfg,
    /// FIRST EPSS.
    pub epss: SourceCfg,
    /// OSV, for Go modules and Rust crates found inside files. Distro hosts
    /// that already use OSV (Debian, Ubuntu, Rocky, `AlmaLinux`) take their
    /// endpoint from `sources.distro` instead.
    pub osv: SourceCfg,
}

/// The distribution source. It is required by default: without it a result
/// would be a guess, so a failure must not look like a clean scan.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct DistroCfg {
    /// Query this source.
    pub enabled: bool,
    /// A failure makes the result incomplete (exit 2).
    pub required: bool,
    /// Override the endpoint (internal mirror). On Fedora this is the
    /// `updates` directory; on Arch it is the `issues/all.json` URL.
    pub url: Option<String>,
    /// Ordered mirrors tried after the primary endpoint fails.
    pub fallback: Vec<String>,
}

impl Default for DistroCfg {
    fn default() -> Self {
        Self {
            enabled: true,
            required: true,
            url: None,
            fallback: Vec::new(),
        }
    }
}

/// One source.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct SourceCfg {
    /// Query this source.
    pub enabled: bool,
    /// A failure makes the result incomplete (exit 2).
    pub required: bool,
    /// Override the endpoint (internal mirror).
    pub url: Option<String>,
    /// Ordered mirrors tried after the primary endpoint fails.
    pub fallback: Vec<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            schema_version: 1,
            general: General {
                offline: false,
                cache_dir: None,
                cache_ttl: "6h".into(),
                stale_max_age: "72h".into(),
                timeout: "10s".into(),
            },
            output: Output {
                format: "summary".into(),
                color: "auto".into(),
            },
            policy: PolicySection {
                fail_on: "none".into(),
                fail_on_epss: None,
                fail_on_incomplete: true,
                strict: false,
            },
            ignore_file: None,
            network: Network {
                allow_insecure_http: false,
                proxy: None,
                ca_file: None,
                user_agent_suffix: None,
                retries: 2,
                cooldown: "30s".into(),
                min_interval: None,
            },
            notify: Notify::default(),
            sources: Sources {
                distro: DistroCfg::default(),
                kev: SourceCfg {
                    enabled: true,
                    required: false,
                    url: None,
                    fallback: Vec::new(),
                },
                epss: SourceCfg {
                    enabled: true,
                    required: false,
                    url: None,
                    fallback: Vec::new(),
                },
                // Required: a language pass that fails leaves those packages
                // unjudged, which must not read as a clean scan.
                osv: SourceCfg {
                    enabled: true,
                    required: true,
                    url: None,
                    fallback: Vec::new(),
                },
            },
        }
    }
}

impl Default for General {
    fn default() -> Self {
        Config::default().general
    }
}
impl Default for Output {
    fn default() -> Self {
        Config::default().output
    }
}
impl Default for PolicySection {
    fn default() -> Self {
        Config::default().policy
    }
}
impl Default for Network {
    fn default() -> Self {
        Config::default().network
    }
}
impl Default for Sources {
    fn default() -> Self {
        Config::default().sources
    }
}
impl Default for SourceCfg {
    fn default() -> Self {
        Self {
            enabled: true,
            required: false,
            url: None,
            fallback: Vec::new(),
        }
    }
}

/// Parses `10s`, `5m`, `6h` or `3d`.
///
/// # Errors
///
/// Fails on any other shape or a zero value.
pub fn parse_duration(s: &str) -> Result<Duration, ConfigError> {
    let (num, unit) = s.split_at(s.len().saturating_sub(1));
    let n: u64 = num.parse().map_err(|_| {
        ConfigError(format!(
            "invalid duration {s:?}; use forms like 10s, 5m, 6h or 3d"
        ))
    })?;
    let secs = match unit {
        "s" => n,
        "m" => n.saturating_mul(60),
        "h" => n.saturating_mul(3600),
        "d" => n.saturating_mul(86_400),
        _ => {
            return err(format!(
                "invalid duration {s:?}; use forms like 10s, 5m, 6h or 3d"
            ));
        }
    };
    if secs == 0 {
        return err(format!("duration {s:?} must be greater than zero"));
    }
    Ok(Duration::from_secs(secs))
}

impl Config {
    /// Parses and validates a TOML document.
    ///
    /// # Errors
    ///
    /// Fails on syntax errors, unknown keys and invalid values.
    pub fn from_toml(text: &str) -> Result<Self, ConfigError> {
        let cfg: Self =
            toml::from_str(text).map_err(|e| ConfigError(e.to_string().trim().to_owned()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Checks values that serde cannot.
    ///
    /// # Errors
    ///
    /// Describes the first invalid value.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.schema_version != 1 {
            return err(format!(
                "unsupported schema_version {}; this amivuln reads 1",
                self.schema_version
            ));
        }
        let ttl = parse_duration(&self.general.cache_ttl)?;
        let stale = parse_duration(&self.general.stale_max_age)?;
        if stale < ttl {
            return err("general.stale_max_age must not be shorter than general.cache_ttl");
        }
        parse_duration(&self.general.timeout)?;
        check_network(&self.network)?;
        if let Some(p) = &self.network.proxy
            && !(p.starts_with("http://") || p.starts_with("https://"))
        {
            return err("network.proxy must be an http:// or https:// URL");
        }
        if let Some(w) = &self.notify.webhook
            && !(w.starts_with("https://")
                || (self.network.allow_insecure_http && w.starts_with("http://")))
        {
            return err(
                "notify.webhook must be an https:// URL (or http:// with network.allow_insecure_http)",
            );
        }
        if !matches!(
            self.notify.on.as_str(),
            "violation" | "incomplete" | "always"
        ) {
            return err("notify.on must be violation, incomplete or always");
        }
        if let Some(ua) = &self.network.user_agent_suffix
            && (ua.is_empty()
                || ua.len() > 64
                || !ua.bytes().all(|b| b == b' ' || b.is_ascii_graphic()))
        {
            return err("network.user_agent_suffix must be 1 to 64 printable ASCII characters");
        }
        self.output
            .format
            .parse::<amivuln_report::Format>()
            .map_err(ConfigError)?;
        if !matches!(self.output.color.as_str(), "auto" | "always" | "never") {
            return err(format!(
                "output.color {:?} is invalid; use auto, always or never",
                self.output.color
            ));
        }
        self.policy
            .fail_on
            .parse::<amivuln_core::FailOn>()
            .map_err(ConfigError)?;
        if let Some(e) = self.policy.fail_on_epss
            && !(0.0..=1.0).contains(&e)
        {
            return err("policy.fail_on_epss must be between 0.0 and 1.0");
        }
        check_sources(self)?;
        Ok(())
    }

    /// Serialises to TOML for `config show`.
    ///
    /// # Errors
    ///
    /// Fails only on an internal serialisation problem.
    pub fn to_toml(&self) -> Result<String, ConfigError> {
        toml::to_string(self).map_err(|e| ConfigError(e.to_string()))
    }
}

/// Where configuration files are searched, in order.
#[must_use]
pub fn search_path(
    cwd: &Path,
    xdg_config_home: Option<&Path>,
    home: Option<&Path>,
) -> Vec<PathBuf> {
    let mut v = vec![cwd.join(".amivuln.toml")];
    if let Some(x) = xdg_config_home.filter(|p| p.is_absolute()) {
        v.push(x.join("amivuln/config.toml"));
    } else if let Some(h) = home {
        v.push(h.join(".config/amivuln/config.toml"));
    }
    v.push(PathBuf::from("/etc/amivuln/config.toml"));
    v
}

/// The user configuration path used by `config init`.
#[must_use]
pub fn user_config_path(xdg_config_home: Option<&Path>, home: Option<&Path>) -> Option<PathBuf> {
    if let Some(x) = xdg_config_home.filter(|p| p.is_absolute()) {
        return Some(x.join("amivuln/config.toml"));
    }
    home.map(|h| h.join(".config/amivuln/config.toml"))
}

/// Default cache directory.
#[must_use]
pub fn default_cache_dir(xdg_cache_home: Option<&Path>, home: Option<&Path>) -> Option<PathBuf> {
    if let Some(x) = xdg_cache_home.filter(|p| p.is_absolute()) {
        return Some(x.join("amivuln"));
    }
    home.map(|h| h.join(".cache/amivuln"))
}

/// Loads the first configuration file found, or the defaults.
///
/// Returns the configuration and the file it came from.
///
/// # Errors
///
/// Fails when an explicit path is unreadable, or a found file is invalid,
/// unreadable or too large.
pub fn load(
    explicit: Option<&Path>,
    candidates: &[PathBuf],
) -> Result<(Config, Option<PathBuf>), ConfigError> {
    let try_read = |path: &Path| -> Result<Config, ConfigError> {
        let meta =
            std::fs::metadata(path).map_err(|e| ConfigError(format!("{}: {e}", path.display())))?;
        if meta.len() > MAX_CONFIG_BYTES {
            return err(format!(
                "{} is larger than {MAX_CONFIG_BYTES} bytes",
                path.display()
            ));
        }
        let text = std::fs::read_to_string(path)
            .map_err(|e| ConfigError(format!("{}: {e}", path.display())))?;
        Config::from_toml(&text).map_err(|e| ConfigError(format!("{}: {}", path.display(), e.0)))
    };
    if let Some(path) = explicit {
        return Ok((try_read(path)?, Some(path.to_path_buf())));
    }
    for path in candidates {
        if path.is_file() {
            return Ok((try_read(path)?, Some(path.clone())));
        }
    }
    Ok((Config::default(), None))
}

/// Loads and validates the ignore file.
///
/// `base` is the directory of the configuration file (or the working directory
/// when no file was read), so a relative `ignore_file` sits next to it.
///
/// # Errors
///
/// An error when the file exists but is invalid or has an expired entry.
/// A missing file is not an error (empty list).
pub fn load_ignore(
    cfg: &Config,
    config_dir: Option<&Path>,
    today: &str,
) -> Result<Vec<amivuln_core::IgnoreEntry>, String> {
    let Some(rel) = &cfg.ignore_file else {
        return Ok(Vec::new());
    };
    let path: PathBuf = if Path::new(rel).is_absolute() {
        PathBuf::from(rel)
    } else {
        config_dir.unwrap_or(Path::new(".")).join(rel)
    };
    let meta = std::fs::metadata(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    if meta.len() > MAX_CONFIG_BYTES {
        return Err(format!(
            "{} is larger than {MAX_CONFIG_BYTES} bytes",
            path.display()
        ));
    }
    let text = std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    let entries =
        amivuln_core::parse_ignore(&text).map_err(|e| format!("{}: {e}", path.display()))?;
    for e in &entries {
        if !e.active_on(today) {
            return Err(format!(
                "{}: entry {} expired on {}; remove it or extend the expiry",
                path.display(),
                e.id,
                e.expires
            ));
        }
    }
    Ok(entries)
}

/// The commented template written by `config init`.
pub const TEMPLATE: &str = "\
# amivuln configuration. Every key is optional; these are the defaults.
schema_version = 1

[general]
offline = false
# cache_dir = \"~/.cache/amivuln\"
cache_ttl = \"6h\"        # a cached response younger than this is used without asking the network
stale_max_age = \"72h\"   # when the network fails, a response up to this old is still used (reported as stale)
timeout = \"10s\"

[output]
format = \"summary\"      # summary, detail, json, sarif, markdown, csv or prometheus
color = \"auto\"          # auto, always or never (NO_COLOR is honored)

[policy]
fail_on = \"none\"        # none, low, medium, high, critical or kev
# fail_on_epss = 0.5
fail_on_incomplete = true
strict = false          # count findings without a distro statement
# ignore_file = \".amivuln-ignore.toml\"

[notify]
# webhook = \"https://ntfy.sh/example-topic\"    # POSTed a compact summary
# bearer_file = \"/etc/amivuln/notify-token\"   # sent as Authorization: Bearer
on = \"violation\"                              # violation | incomplete | always

[network]
allow_insecure_http = false
retries = 2
# cooldown = \"30s\"   # breaker cooldown for a dead endpoint
# min_interval = \"100ms\"
# proxy = \"http://proxy.corp.example:3128\"   # default: HTTPS_PROXY / NO_PROXY
# ca_file = \"/etc/pki/ca-trust/source/anchors/corp.pem\"
# user_agent_suffix = \"team-sre\"

# A required source that fails makes the result incomplete (exit code 2).
[sources.distro]
enabled = true
required = true
# url = \"https://mirror.example/fedora/linux/updates\"
# fallback = [\"https://mirror2.example/fedora/linux/updates\"]

[sources.kev]
enabled = true
required = false

[sources.epss]
enabled = true
required = false

# Go modules and Rust crates found inside files are judged by OSV.
[sources.osv]
enabled = true
required = true
# url = \"https://osv-mirror.example\"
";

/// The `[network]` retry, cooldown and rate rules serde cannot express.
fn check_network(net: &Network) -> Result<(), ConfigError> {
    if net.retries > 10 {
        return err("network.retries must be at most 10");
    }
    if parse_duration(&net.cooldown).is_ok_and(|d| d.is_zero()) {
        return err("network.cooldown must not be zero");
    }
    if let Some(rate) = &net.min_interval
        && parse_duration(rate).is_ok_and(|d| d.is_zero())
    {
        return err("network.min_interval must not be zero");
    }
    Ok(())
}

/// The `[sources]` rules: mirrors follow the endpoint rules, and `required`
/// needs `enabled` (a required source that is disabled fails every scan).
fn check_sources(cfg: &Config) -> Result<(), ConfigError> {
    let https = |u: &str, what: &str, name: &str| -> Result<(), ConfigError> {
        if !(u.starts_with("https://")
            || (cfg.network.allow_insecure_http && u.starts_with("http://")))
        {
            return err(format!(
                "sources.{name}.{what} {u:?} must be an https:// URL (or http:// with network.allow_insecure_http)"
            ));
        }
        Ok(())
    };
    if !cfg.sources.distro.enabled && cfg.sources.distro.required {
        return err("sources.distro is required but disabled");
    }
    if let Some(u) = &cfg.sources.distro.url {
        https(u, "url", "distro")?;
    }
    for mirror in &cfg.sources.distro.fallback {
        https(mirror, "fallback", "distro")?;
    }
    for (name, source) in [
        (&"kev", &cfg.sources.kev),
        (&"epss", &cfg.sources.epss),
        (&"osv", &cfg.sources.osv),
    ] {
        let (name, source): (&str, &SourceCfg) = (*name, source);
        if !source.enabled && source.required {
            return err(format!(
                "sources.{name}: required requires enabled (a required source that is disabled would fail every scan)"
            ));
        }
        if let Some(u) = &source.url {
            https(u, "url", name)?;
        }
        for mirror in &source.fallback {
            https(mirror, "fallback", name)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_valid_and_roundtrip() {
        let d = Config::default();
        d.validate().unwrap();
        let back = Config::from_toml(&d.to_toml().unwrap()).unwrap();
        assert_eq!(back, d);
    }

    #[test]
    fn template_is_valid_and_equals_defaults() {
        assert_eq!(Config::from_toml(TEMPLATE).unwrap(), Config::default());
    }

    #[test]
    fn partial_files_fill_in_defaults() {
        let c = Config::from_toml("[policy]\nfail_on = \"high\"\n").unwrap();
        assert_eq!(c.policy.fail_on, "high");
        assert_eq!(c.general.cache_ttl, "6h");
    }

    #[test]
    fn unknown_keys_and_bad_values_are_rejected() {
        assert!(Config::from_toml("bogus = 1").is_err());
        assert!(Config::from_toml("[general]\ncache_tll = \"1h\"").is_err());
        assert!(Config::from_toml("[output]\nformat = \"xml\"").is_err());
        assert!(Config::from_toml("[policy]\nfail_on = \"urgent\"").is_err());
        assert!(Config::from_toml("[policy]\nfail_on_epss = 2.0").is_err());
        assert!(Config::from_toml("schema_version = 2").is_err());
        assert!(Config::from_toml("[general]\ncache_ttl = \"5y\"").is_err());
        assert!(
            Config::from_toml("[general]\ncache_ttl = \"2h\"\nstale_max_age = \"1h\"").is_err()
        );
        assert!(Config::from_toml("[sources.kev]\nurl = \"http://x\"").is_err());
        assert!(Config::from_toml("[sources.distro]\nenabled = false").is_err());
    }

    #[test]
    fn insecure_mirror_needs_an_explicit_opt_in() {
        let ok = "[network]\nallow_insecure_http = true\n[sources.kev]\nurl = \"http://mirror.internal/kev.json\"\n";
        assert!(Config::from_toml(ok).is_ok());
    }

    #[test]
    fn network_options_are_validated() {
        let ok = "[network]\nproxy = \"http://proxy.corp:3128\"\nca_file = \"/etc/corp.pem\"\nuser_agent_suffix = \"team-sre\"\n";
        assert!(Config::from_toml(ok).is_ok());
        for bad in [
            "[network]\nproxy = \"socks5://p:1080\"\n",
            "[network]\nproxy = \"proxy.corp:3128\"\n",
            "[network]\nuser_agent_suffix = \"\"\n",
            "[network]\nuser_agent_suffix = \"line\\nbreak\"\n",
            "[network]\nuser_agent_suffix = \"x\u{e9}\"\n",
        ] {
            assert!(Config::from_toml(bad).is_err(), "{bad:?}");
        }
        let long = format!("[network]\nuser_agent_suffix = \"{}\"\n", "a".repeat(65));
        assert!(Config::from_toml(&long).is_err());
    }

    #[test]
    fn durations() {
        assert_eq!(parse_duration("10s").unwrap(), Duration::from_secs(10));
        assert_eq!(parse_duration("6h").unwrap(), Duration::from_hours(6));
        assert_eq!(parse_duration("3d").unwrap(), Duration::from_hours(72));
        for bad in ["", "s", "0s", "10", "1w", "-5s", "1.5h"] {
            assert!(parse_duration(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn search_path_order_and_xdg() {
        let v = search_path(
            Path::new("/work"),
            Some(Path::new("/xdg")),
            Some(Path::new("/home/u")),
        );
        assert_eq!(
            v,
            [
                PathBuf::from("/work/.amivuln.toml"),
                "/xdg/amivuln/config.toml".into(),
                "/etc/amivuln/config.toml".into()
            ]
        );
        let v = search_path(Path::new("/work"), None, Some(Path::new("/home/u")));
        assert_eq!(v[1], PathBuf::from("/home/u/.config/amivuln/config.toml"));
        // A relative XDG value is ignored, as the spec requires.
        let v = search_path(
            Path::new("/work"),
            Some(Path::new("rel")),
            Some(Path::new("/home/u")),
        );
        assert_eq!(v[1], PathBuf::from("/home/u/.config/amivuln/config.toml"));
    }

    #[test]
    fn cache_dir_default() {
        assert_eq!(
            default_cache_dir(Some(Path::new("/c")), Some(Path::new("/h"))),
            Some("/c/amivuln".into())
        );
        assert_eq!(
            default_cache_dir(None, Some(Path::new("/h"))),
            Some("/h/.cache/amivuln".into())
        );
        assert_eq!(default_cache_dir(None, None), None);
    }

    #[test]
    fn load_prefers_explicit_then_first_found() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a.toml");
        let b = dir.path().join("b.toml");
        std::fs::write(&a, "[policy]\nfail_on = \"low\"\n").unwrap();
        std::fs::write(&b, "[policy]\nfail_on = \"high\"\n").unwrap();
        let (c, from) = load(
            None,
            &[dir.path().join("missing.toml"), a.clone(), b.clone()],
        )
        .unwrap();
        assert_eq!((c.policy.fail_on.as_str(), from), ("low", Some(a.clone())));
        let (c, _) = load(Some(&b), &[a]).unwrap();
        assert_eq!(c.policy.fail_on, "high");
        let (c, from) = load(None, &[]).unwrap();
        assert_eq!((c, from), (Config::default(), None));
        let e = load(Some(&dir.path().join("nope.toml")), &[]).unwrap_err();
        assert!(e.0.contains("nope.toml"));
    }

    #[test]
    fn oversized_and_invalid_files_name_the_path() {
        let dir = tempfile::tempdir().unwrap();
        let big = dir.path().join("big.toml");
        std::fs::write(&big, vec![b'#'; 300 * 1024]).unwrap();
        assert!(load(Some(&big), &[]).unwrap_err().0.contains("larger than"));
        let bad = dir.path().join("bad.toml");
        std::fs::write(&bad, "[output]\nformat = \"xml\"\n").unwrap();
        assert!(load(Some(&bad), &[]).unwrap_err().0.contains("bad.toml"));
    }
}
