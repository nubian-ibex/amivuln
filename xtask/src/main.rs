// SPDX-FileCopyrightText: 2026 amivuln contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Project automation: man pages and shell completions.
//!
//! `cargo xtask assets` writes the generated files under `contrib/`;
//! `cargo xtask assets --check` fails when they are out of date, which CI
//! uses to keep the committed copies honest.

#![forbid(unsafe_code)]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::CommandFactory;
use clap_complete::{Shell, generate};

/// Sections `clap_mangen` cannot derive from the argument definitions.
const EXTRA_SECTIONS: &str = r".SH EXIT STATUS
.TP
0
Finished; no finding at or above \fB\-\-fail\-on\fR.
.TP
1
Finished; findings at or above \fB\-\-fail\-on\fR.
.TP
2
The result is incomplete: a required source was unavailable and no usable cached copy existed. Never treat this as a clean result.
.TP
3
A target could not be resolved (not found, ambiguous, or no detectable version).
.TP
64
Usage or configuration error.
.TP
70
Internal error.
.SH EXAMPLES
Check an installed package:
.PP
.RS
amivuln nginx
.RE
.PP
Check the package that owns a file:
.PP
.RS
amivuln /usr/sbin/nginx
.RE
.PP
Check every installed package and fail a build on HIGH or worse:
.PP
.RS
amivuln \-\-all \-\-fail\-on high
.RE
.PP
Check a version for another distribution, for example in a CI container:
.PP
.RS
amivuln openssl@3.5.1\-1 \-\-distro arch \-f json
.RE
.SH FILES
.TP
\fI./.amivuln.toml\fR, \fI$XDG_CONFIG_HOME/amivuln/config.toml\fR, \fI/etc/amivuln/config.toml\fR
Configuration, first one found wins. See \fBamivuln config init\fR.
.TP
\fI$XDG_CACHE_HOME/amivuln/cache.sqlite\fR
HTTP cache.
.SH ENVIRONMENT
.TP
\fBAMIVULN_FORMAT\fR, \fBAMIVULN_FAIL_ON\fR, \fBAMIVULN_OFFLINE\fR, \fBAMIVULN_CONFIG\fR, \fBAMIVULN_COLOR\fR
Same as the corresponding options.
.TP
\fBNO_COLOR\fR
Disables colors when set to a non\-empty value.
.SH PRIVACY
Only the ecosystem, the package name and the version leave the host. There is no telemetry.
";

/// Every generated file as `(relative path, contents)`.
fn assets() -> Result<Vec<(PathBuf, Vec<u8>)>, String> {
    let cmd = amivuln::cli::Cli::command();
    let mut out: Vec<(PathBuf, Vec<u8>)> = Vec::new();

    let mut pages = vec![(cmd.get_name().to_owned(), cmd.clone())];
    for sub in cmd
        .get_subcommands()
        .filter(|s| !s.is_hide_set() && s.get_name() != "help")
    {
        pages.push((
            format!("{}-{}", cmd.get_name(), sub.get_name()),
            sub.clone(),
        ));
    }
    for (name, page) in pages {
        let mut buf = Vec::new();
        // The title is what `man` shows in the header; the file name carries
        // the section, so the page is found as `man amivuln-check`.
        clap_mangen::Man::new(page)
            .title(name.to_uppercase())
            .render(&mut buf)
            .map_err(|e| e.to_string())?;
        if name == "amivuln" {
            buf.extend_from_slice(EXTRA_SECTIONS.as_bytes());
        }
        out.push((PathBuf::from(format!("contrib/man/{name}.1")), buf));
    }

    for (shell, file) in [
        (Shell::Bash, "contrib/completions/amivuln.bash"),
        (Shell::Zsh, "contrib/completions/_amivuln"),
        (Shell::Fish, "contrib/completions/amivuln.fish"),
    ] {
        let mut buf = Vec::new();
        generate(
            shell,
            &mut amivuln::cli::Cli::command(),
            "amivuln",
            &mut buf,
        );
        out.push((PathBuf::from(file), buf));
    }
    Ok(out)
}

fn run(root: &Path, check: bool, err: &mut dyn Write) -> Result<(), String> {
    let mut stale = Vec::new();
    for (rel, bytes) in assets()? {
        let path = root.join(&rel);
        if check {
            if std::fs::read(&path).ok().as_deref() != Some(bytes.as_slice()) {
                stale.push(rel.display().to_string());
            }
        } else {
            if let Some(dir) = path.parent() {
                std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
            }
            std::fs::write(&path, &bytes).map_err(|e| format!("{}: {e}", path.display()))?;
            let _ = writeln!(err, "wrote {}", rel.display());
        }
    }
    if stale.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "out of date, run `cargo xtask assets`: {}",
            stale.join(", ")
        ))
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut err = std::io::stderr();
    let check = args.iter().any(|a| a == "--check");
    if args.first().map(String::as_str) != Some("assets") {
        let _ = writeln!(err, "usage: cargo xtask assets [--check]");
        return ExitCode::from(2);
    }
    // xtask lives in <root>/xtask, so the repository root is its parent.
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    match run(&root, check, &mut err) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            let _ = writeln!(err, "error: {e}");
            ExitCode::FAILURE
        }
    }
}
