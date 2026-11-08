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
    /// Output format: summary, detail or json.
    #[arg(
        short,
        long,
        global = true,
        value_name = "FORMAT",
        env = "AMIVULN_FORMAT"
    )]
    pub format: Option<String>,
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
    /// Treat this value as a package URL (repeatable).
    #[arg(long, global = true, value_name = "PURL")]
    pub purl: Vec<String>,
    /// Only print errors.
    #[arg(short, long, global = true)]
    pub quiet: bool,
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
