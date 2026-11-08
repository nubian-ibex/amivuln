// SPDX-FileCopyrightText: 2026 amivuln contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! From a systemd unit to the executable it runs.
//!
//! The chain is `systemctl show` (read-only), then the running process'
//! `/proc/<pid>/exe`, falling back to the unit's `ExecStart` path when the
//! unit is not running or the process is not readable by this user. The unit
//! is never started, stopped or otherwise touched, and the executable is
//! never run.

use amivuln_core::{ProcessRunner, Program};

use crate::ResolveError;

/// The executable behind a unit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnitExe {
    /// Absolute path of the executable.
    pub path: String,
    /// Main process id when the unit is running.
    pub pid: Option<u32>,
    /// The running process executes a file that was replaced on disk, so the
    /// unit needs a restart to use the installed version.
    pub deleted: bool,
}

fn valid_unit(unit: &str) -> bool {
    unit.len() <= 256
        && unit.ends_with(".service")
        && unit.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b':' | b'_' | b'.' | b'@' | b'\\' | b'-')
        })
}

/// The first `path=` of an `ExecStart={ path=/x ; argv[]=... }` value.
fn exec_start_path(value: &str) -> Option<String> {
    let after = value.split_once("path=")?.1;
    let path = after.split(" ;").next()?.trim();
    path.starts_with('/').then(|| path.to_owned())
}

/// Resolves a `.service` unit to its executable.
///
/// `read_link` reads a symbolic link (injected so tests need no `/proc`).
///
/// # Errors
///
/// [`ResolveError::NotFound`] for unknown units, non-service units and units
/// with neither a readable process nor an `ExecStart` path.
pub fn exe_for_unit(
    runner: &dyn ProcessRunner,
    read_link: &dyn Fn(&str) -> Option<String>,
    unit: &str,
) -> Result<UnitExe, ResolveError> {
    if !valid_unit(unit) {
        return Err(ResolveError::NotFound(format!(
            "{unit:?} (only .service units are supported; socket and timer units activate a service, check that service)"
        )));
    }
    let out = runner.run(
        Program::Systemctl,
        &[
            "show",
            "--no-pager",
            "-p",
            "LoadState",
            "-p",
            "MainPID",
            "-p",
            "ExecStart",
            "--",
            unit,
        ],
    )?;
    if !out.success {
        return Err(ResolveError::NotFound(format!(
            "{unit} (systemctl could not describe it)"
        )));
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let field = |key: &str| {
        text.lines()
            .find_map(|l| l.strip_prefix(key).and_then(|r| r.strip_prefix('=')))
            .map(str::trim)
    };
    if field("LoadState") != Some("loaded") {
        return Err(ResolveError::NotFound(format!(
            "{unit} (the unit is not loaded)"
        )));
    }
    let pid: Option<u32> = field("MainPID")
        .and_then(|p| p.parse().ok())
        .filter(|p| *p > 0);

    if let Some(pid) = pid
        && let Some(link) = read_link(&format!("/proc/{pid}/exe"))
    {
        let (path, deleted) = link
            .strip_suffix(" (deleted)")
            .map_or((link.as_str(), false), |p| (p, true));
        if path.starts_with('/') {
            return Ok(UnitExe {
                path: path.to_owned(),
                pid: Some(pid),
                deleted,
            });
        }
    }
    let path = field("ExecStart")
        .and_then(exec_start_path)
        .ok_or_else(|| {
            ResolveError::NotFound(format!("{unit} (no running process and no ExecStart path)"))
        })?;
    Ok(UnitExe {
        path,
        pid,
        deleted: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests_support::FakeRunner;

    const RUNNING: &str = "LoadState=loaded\nMainPID=1330\nExecStart={ path=/usr/lib/systemd/systemd-journald ; argv[]=/usr/lib/systemd/systemd-journald ; ignore_errors=no ; start_time=[n/a] ; pid=1330 ; code=(null) ; status=0/0 }\n";
    const STOPPED: &str = "LoadState=loaded\nMainPID=0\nExecStart={ path=/usr/sbin/nginx ; argv[]=/usr/sbin/nginx -g daemon on; ; ignore_errors=no }\n";

    fn no_link(_: &str) -> Option<String> {
        None
    }

    #[test]
    fn running_unit_uses_the_process_executable() {
        let r = FakeRunner::ok(RUNNING);
        let link = |p: &str| (p == "/proc/1330/exe").then(|| "/usr/sbin/real".to_owned());
        let exe = exe_for_unit(&r, &link, "x.service").unwrap();
        assert_eq!(
            exe,
            UnitExe {
                path: "/usr/sbin/real".into(),
                pid: Some(1330),
                deleted: false
            }
        );
        assert_eq!(
            r.calls.borrow()[0],
            [
                "show",
                "--no-pager",
                "-p",
                "LoadState",
                "-p",
                "MainPID",
                "-p",
                "ExecStart",
                "--",
                "x.service"
            ]
        );
    }

    #[test]
    fn replaced_binary_is_flagged_for_restart() {
        let r = FakeRunner::ok(RUNNING);
        let link = |_: &str| Some("/usr/sbin/nginx (deleted)".to_owned());
        let exe = exe_for_unit(&r, &link, "nginx.service").unwrap();
        assert_eq!(exe.path, "/usr/sbin/nginx");
        assert!(exe.deleted);
    }

    #[test]
    fn unreadable_process_falls_back_to_exec_start() {
        let r = FakeRunner::ok(RUNNING);
        let exe = exe_for_unit(&r, &no_link, "x.service").unwrap();
        assert_eq!(exe.path, "/usr/lib/systemd/systemd-journald");
        assert_eq!(exe.pid, Some(1330));
    }

    #[test]
    fn stopped_unit_uses_exec_start() {
        let r = FakeRunner::ok(STOPPED);
        let exe = exe_for_unit(&r, &no_link, "nginx.service").unwrap();
        assert_eq!((exe.path.as_str(), exe.pid), ("/usr/sbin/nginx", None));
    }

    #[test]
    fn unknown_unsupported_and_hostile_units() {
        let r = FakeRunner::ok("LoadState=not-found\nMainPID=0\nExecStart=\n");
        assert!(exe_for_unit(&r, &no_link, "ghost.service").is_err());
        let r = FakeRunner::ok(STOPPED);
        for bad in [
            "nginx.socket",
            "a.timer",
            "nginx",
            "x y.service",
            "a;b.service",
            "../x.service",
            "-x.service ",
            "",
        ] {
            assert!(exe_for_unit(&r, &no_link, bad).is_err(), "{bad:?}");
        }
        assert!(
            r.calls.borrow().is_empty(),
            "invalid units must not reach systemctl"
        );
        let r = FakeRunner::failing();
        assert!(exe_for_unit(&r, &no_link, "x.service").is_err());
        let r = FakeRunner::ok("LoadState=loaded\nMainPID=0\nExecStart=\n");
        assert!(exe_for_unit(&r, &no_link, "x.service").is_err());
    }

    #[test]
    fn exec_start_parsing() {
        assert_eq!(
            exec_start_path("{ path=/a/b ; argv[]=/a/b -x }").as_deref(),
            Some("/a/b")
        );
        assert_eq!(exec_start_path("{ path=relative ; }"), None);
        assert_eq!(exec_start_path(""), None);
    }

    #[test]
    fn real_systemd_resolves_a_known_unit_when_present() {
        use crate::SystemRunner;
        let runner = SystemRunner::default();
        let link = |p: &str| std::fs::read_link(p).ok().map(|l| l.display().to_string());
        // Hosts without systemd return an error, which is fine here.
        if let Ok(exe) = exe_for_unit(&runner, &link, "systemd-journald.service") {
            assert!(exe.path.starts_with('/'));
        }
    }
}
