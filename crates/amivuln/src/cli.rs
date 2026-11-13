// SPDX-FileCopyrightText: 2026 amivuln contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Command-line definition (clap derive).

use clap::{Args, Parser, Subcommand, ValueEnum};

const AFTER_HELP: &str = "\
EXAMPLES:
  amivuln nginx                      installed package by name
  amivuln /usr/sbin/nginx            package that owns a file
  amivuln openssl@3.2.2-1.fc44       a specific version, without reading the host
  amivuln --all --fail-on high       every installed package, fail the build on HIGH or worse
  amivuln check openssl@3.5.1-1 --distro arch -f json
                                     query for another distro (useful in CI containers)

EXIT CODES:
  0   no finding at or above --fail-on
  1   findings at or above --fail-on
  2   result incomplete: a required source was unavailable
  3   a target could not be resolved
  64  usage or configuration error
  65  invalid offline database data (tampered or regressive)
  70  internal error

Only the ecosystem, package name and version ever leave the host.";

/// Top level arguments. A bare list of targets is a shortcut for `check`.
#[derive(Debug, Parser)]
#[command(
    name = "amivuln",
    version,
    about = "Am I vulnerable? Backport-aware CVE check for packages on this host",
    long_about = "Reports which CVEs apply to an installed package, binary or version, \
taking the patches your distribution already shipped into account. Fedora and Arch Linux \
are supported.",
    after_help = AFTER_HELP,
    args_conflicts_with_subcommands = true
)]
pub struct Cli {
    /// Options shared by all commands.
    #[command(flatten)]
    pub global: Global,
    /// Command to run; without one, the positional targets are checked.
    #[command(subcommand)]
    pub command: Option<Command>,
    /// Targets to check: package name, file path, `name@version` or purl.
    #[arg(value_name = "TARGET")]
    pub targets: Vec<String>,
    /// Check every installed package.
    #[arg(long)]
    pub all: bool,
}

/// Options available everywhere.
#[derive(Debug, Args, Clone)]
pub struct Global {
    /// Output format: summary, detail, json, sarif, markdown, csv, prometheus, cyclonedx or openvex.
    #[arg(
        short,
        long,
        global = true,
        value_name = "FORMAT",
        env = "AMIVULN_FORMAT"
    )]
    pub format: Option<String>,
    /// Write the result to FILE instead of stdout, replacing it atomically.
    #[arg(long, global = true, value_name = "FILE")]
    pub output: Option<std::path::PathBuf>,
    /// Exit 1 when a finding reaches this level: none, low, medium, high, critical or kev.
    #[arg(long, global = true, value_name = "LEVEL", env = "AMIVULN_FAIL_ON")]
    pub fail_on: Option<String>,
    /// Exit 1 when an affected finding has at least this EPSS score (0.0 to 1.0).
    #[arg(long, global = true, value_name = "SCORE")]
    pub fail_on_epss: Option<f64>,
    /// Behavior switches.
    #[command(flatten)]
    pub flags: Flags,
    /// Configuration file (skips the default search path).
    #[arg(long, global = true, value_name = "FILE", env = "AMIVULN_CONFIG")]
    pub config: Option<std::path::PathBuf>,
    /// Colors: auto, always or never (`NO_COLOR` is honored).
    #[arg(long, global = true, value_name = "WHEN", env = "AMIVULN_COLOR")]
    pub color: Option<String>,
    /// Treat the host as another distro: `fedora:44` or `arch`.
    #[arg(long, global = true, value_name = "DISTRO")]
    pub distro: Option<String>,
    /// Treat this path as a target (repeatable).
    #[arg(long, global = true, value_name = "PATH")]
    pub file: Vec<String>,
    /// Treat this value as an installed package name or `name@version` (repeatable).
    #[arg(long, global = true, value_name = "NAME[@VERSION]")]
    pub package: Vec<String>,
    /// Check the executable of this running process (repeatable).
    #[arg(long, global = true, value_name = "PID")]
    pub pid: Vec<u32>,
    /// Treat this value as a package URL (repeatable).
    #[arg(long, global = true, value_name = "PURL")]
    pub purl: Vec<String>,
    /// A previous `-f json` report; only new findings violate --fail-on.
    #[arg(long, global = true, value_name = "FILE")]
    pub baseline: Option<std::path::PathBuf>,
    /// `OpenVEX` documents stating that a product is not affected (repeatable).
    #[arg(long, global = true, value_name = "FILE")]
    pub vex: Vec<std::path::PathBuf>,
    /// Check the packages listed in FILE (one `name@version` per line) instead of
    /// the installed ones; for example a list exported from another host.
    #[arg(long, global = true, value_name = "FILE")]
    pub packages_from: Option<std::path::PathBuf>,
    /// Check the OS packages listed in a `CycloneDX` JSON SBOM (rpm, deb and alpm
    /// purls). Other components are listed as unresolved, grouped by type.
    #[arg(long, global = true, value_name = "FILE")]
    pub sbom: Option<std::path::PathBuf>,
    /// Scan a container's installed packages (repeatable): the rootfs is
    /// exported with podman or docker, nothing inside the container runs.
    /// The container's own `os-release` decides the ecosystem.
    #[arg(long, global = true, value_name = "ID")]
    pub container: Vec<String>,
    /// Only print errors.
    #[arg(short, long, global = true)]
    pub quiet: bool,
}

/// Moves a subcommand written after global options to the front, so
/// `amivuln --color never pending` and `amivuln pending --color never` mean the
/// same. clap would otherwise read `pending` as a target once an option has
/// been seen. A bare word that equals a subcommand name is always the
/// subcommand; use `--package NAME` for a package that shares a name with one.
#[must_use]
pub fn normalize_args(args: &[String]) -> Vec<String> {
    use clap::CommandFactory;
    let cmd = Cli::command();
    let takes_value = |arg: &str| -> bool {
        if let Some(long) = arg.strip_prefix("--") {
            return cmd
                .get_arguments()
                .any(|a| a.get_long() == Some(long) && a.get_action().takes_values());
        }
        arg.len() == 2
            && arg.chars().nth(1).is_some_and(|c| {
                cmd.get_arguments()
                    .any(|a| a.get_short() == Some(c) && a.get_action().takes_values())
            })
    };
    let mut i = 1;
    while let Some(tok) = args.get(i) {
        if tok.starts_with('-') {
            i += if tok.contains('=') || !takes_value(tok) {
                1
            } else {
                2
            };
            continue;
        }
        if i > 1 && cmd.get_subcommands().any(|s| s.get_name() == tok) {
            let mut out = Vec::with_capacity(args.len());
            out.push(args.first().cloned().unwrap_or_default());
            out.push(tok.clone());
            out.extend(
                args.iter()
                    .enumerate()
                    .filter(|(j, _)| *j != 0 && *j != i)
                    .map(|(_, a)| a.clone()),
            );
            return out;
        }
        break;
    }
    args.to_vec()
}

/// On/off switches.
#[derive(Debug, Args, Clone, Copy)]
pub struct Flags {
    /// Count findings without a distro statement as violations of --fail-on.
    #[arg(long, global = true)]
    pub strict: bool,
    /// Never use the network; answer from the cache only.
    #[arg(long, global = true, env = "AMIVULN_OFFLINE")]
    pub offline: bool,
    /// Do not keep a cache on disk for this run.
    #[arg(long, global = true)]
    pub no_cache: bool,
}

/// Subcommands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Check packages, files, versions or purls.
    Check {
        /// Targets to check.
        #[arg(value_name = "TARGET")]
        targets: Vec<String>,
        /// Check every installed package.
        #[arg(long)]
        all: bool,
    },
    /// Is this host affected by a CVE? Scans every installed package.
    Cve {
        /// CVE ids, for example CVE-2024-6387.
        #[arg(value_name = "CVE-ID", required = true)]
        ids: Vec<String>,
    },
    /// Which updates close the most risk? Ranks the updates that fix affected findings.
    Pending,
    /// Check every running systemd service. Services that are not packaged are listed, not fatal.
    Services,
    /// Which running processes still use files an update replaced? Exit 1 when a restart is needed.
    Restart,
    /// Serve read-only tools to AI agents over the Model Context Protocol on stdio.
    Mcp,
    /// Interactive terminal UI (feature `tui`). Without the feature, exits 64.
    Tui,
    /// Build, fetch, verify or inspect the offline advisory database.
    Db {
        /// What to do.
        #[command(subcommand)]
        action: DbAction,
    },
    /// Show, create or validate the configuration.
    Config {
        /// What to do.
        #[command(subcommand)]
        action: ConfigAction,
    },
    /// Inspect or clear the on-disk cache.
    Cache {
        /// What to do.
        #[command(subcommand)]
        action: CacheAction,
    },
    /// Print shell completions.
    Completions {
        /// Target shell.
        #[arg(value_enum)]
        shell: Shell,
    },
    /// Print version and build information.
    Version {
        /// Machine-readable output.
        #[arg(long)]
        json: bool,
    },
}

/// `amivuln db ...`
#[derive(Debug, Subcommand)]
pub enum DbAction {
    /// Snapshot the local cache into a signed-ready `tar.zst` archive.
    Build {
        /// Where to write the archive.
        #[arg(long, value_name = "FILE")]
        archive: std::path::PathBuf,
    },
    /// Verify an archive and install it as the offline database.
    Pull {
        /// Archive path or `https://` URL.
        #[arg(value_name = "SOURCE")]
        source: String,
        /// Install even when the archive is older than the installed database.
        #[arg(long)]
        force: bool,
        /// Minisign public key; the signature over the manifest is checked.
        #[arg(long, value_name = "FILE")]
        key: Option<std::path::PathBuf>,
        /// Minisign signature over `manifest.json`.
        #[arg(long, value_name = "FILE")]
        sig: Option<std::path::PathBuf>,
    },
    /// Check an archive: manifest, database checksum and, with `--key`/`--sig`, the signature.
    Verify {
        /// Archive path.
        #[arg(value_name = "FILE")]
        archive: std::path::PathBuf,
        /// Minisign public key.
        #[arg(long, value_name = "FILE")]
        key: Option<std::path::PathBuf>,
        /// Minisign signature over `manifest.json`.
        #[arg(long, value_name = "FILE")]
        sig: Option<std::path::PathBuf>,
    },
    /// Print the manifest of an archive (after checking its integrity).
    Info {
        /// Archive path.
        #[arg(value_name = "FILE")]
        archive: std::path::PathBuf,
    },
}

/// `amivuln config ...`
#[derive(Debug, Subcommand)]
pub enum ConfigAction {
    /// Print the effective configuration.
    Show,
    /// Write a commented default configuration file.
    Init {
        /// Where to write; defaults to the user configuration path.
        #[arg(long, value_name = "FILE")]
        path: Option<std::path::PathBuf>,
    },
    /// Load the configuration and report problems.
    Validate,
}

/// `amivuln cache ...`
#[derive(Debug, Subcommand)]
pub enum CacheAction {
    /// Show where the cache lives and how big it is.
    Info,
    /// Delete every cached response.
    Clear,
}

/// Shells with completion support.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum Shell {
    /// Bash.
    Bash,
    /// Zsh.
    Zsh,
    /// Fish.
    Fish,
    /// Elvish.
    Elvish,
    /// PowerShell.
    Powershell,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn bare_targets_are_the_check_shortcut() {
        let cli = Cli::try_parse_from(["amivuln", "nginx", "openssl@3.0-1"]).unwrap();
        assert!(cli.command.is_none());
        assert_eq!(cli.targets, ["nginx", "openssl@3.0-1"]);
    }

    #[test]
    fn subcommands_and_global_options_after_them() {
        let cli = Cli::try_parse_from([
            "amivuln",
            "check",
            "nginx",
            "-f",
            "json",
            "--fail-on",
            "high",
        ])
        .unwrap();
        assert!(matches!(cli.command, Some(Command::Check { .. })));
        assert_eq!(cli.global.format.as_deref(), Some("json"));
        assert_eq!(cli.global.fail_on.as_deref(), Some("high"));
        let cli = Cli::try_parse_from(["amivuln", "config", "show", "--color", "never"]).unwrap();
        assert_eq!(cli.global.color.as_deref(), Some("never"));
    }

    fn parse(args: &[&str]) -> Cli {
        let args: Vec<String> = args.iter().map(|a| (*a).to_owned()).collect();
        Cli::try_parse_from(normalize_args(&args)).unwrap()
    }

    #[test]
    fn subcommands_win_after_global_options() {
        for args in [
            vec!["amivuln", "--color", "never", "pending"],
            vec!["amivuln", "-f", "json", "--config", "/x", "pending"],
            vec!["amivuln", "--strict", "--fail-on=high", "pending"],
            vec!["amivuln", "--fail-on", "high", "cve", "CVE-2024-6387"],
            vec!["amivuln", "-q", "check", "nginx"],
            vec!["amivuln", "pending", "--color", "never"],
        ] {
            let cli = parse(&args);
            assert!(
                cli.command.is_some(),
                "{args:?} parsed as targets {:?}",
                cli.targets
            );
            assert!(cli.targets.is_empty());
        }
        let cli = parse(&[
            "amivuln",
            "--color",
            "never",
            "cve",
            "CVE-2024-6387",
            "--offline",
        ]);
        assert_eq!(cli.global.color.as_deref(), Some("never"));
        assert!(cli.global.flags.offline);
        assert!(matches!(cli.command, Some(Command::Cve { ref ids }) if ids == &["CVE-2024-6387"]));
        // A package that happens to share a subcommand name stays reachable.
        let cli = parse(&["amivuln", "--package", "pending"]);
        assert_eq!(cli.global.package, ["pending"]);
    }

    #[test]
    fn selectors_repeat() {
        let cli = Cli::try_parse_from([
            "amivuln",
            "--package",
            "a",
            "--package",
            "b@1",
            "--file",
            "/x",
        ])
        .unwrap();
        assert_eq!(cli.global.package, ["a", "b@1"]);
        assert_eq!(cli.global.file, ["/x"]);
    }

    #[test]
    fn help_and_version_exit_cleanly() {
        for arg in ["--help", "--version"] {
            let e = Cli::try_parse_from(["amivuln", arg]).unwrap_err();
            assert_eq!(e.exit_code(), 0);
        }
    }
}
