// SPDX-FileCopyrightText: 2026 amivuln contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Processes that still run files an update has replaced.
//!
//! Linux marks a mapped or executed file whose directory entry was replaced
//! with ` (deleted)` in `/proc/<pid>/exe` and `/proc/<pid>/maps`. A process in
//! that state is running the old code and needs a restart for an update to
//! take effect. The scan only reads `/proc`; it never signals or touches a
//! process.

use std::io::Read;
use std::path::Path;

/// Most process directories examined.
const MAX_PROCESSES: usize = 200_000;
/// Largest `maps` file read per process.
const MAX_MAPS_BYTES: u64 = 8 * 1024 * 1024;

/// A running process that uses replaced files.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaleProcess {
    /// Process id.
    pub pid: u32,
    /// Command name (`comm`).
    pub comm: String,
    /// The systemd service the process belongs to, when it can be told.
    pub unit: Option<String>,
    /// The executable, when it was replaced.
    pub exe: Option<String>,
    /// Replaced shared libraries and other mapped files, sorted.
    pub libs: Vec<String>,
}

/// The result of a scan, including what it could not see.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StaleScan {
    /// Processes using replaced files, sorted by unit then pid.
    pub stale: Vec<StaleProcess>,
    /// Processes inspected.
    pub inspected: usize,
    /// Processes that could not be inspected (permissions). Run as root, or
    /// with `CAP_SYS_PTRACE`, to see all of them.
    pub unreadable: usize,
}

/// Paths worth reporting: files an update could have replaced. Temporary and
/// anonymous mappings (`/tmp`, `memfd:`, `/dev/shm`) are not.
fn is_system_path(path: &str) -> bool {
    ["/usr/", "/lib/", "/lib64/", "/bin/", "/sbin/", "/opt/"]
        .iter()
        .any(|p| path.starts_with(p))
}

/// The service a cgroup path belongs to: its last `*.service` component.
fn unit_from_cgroup(cgroup: &str) -> Option<String> {
    cgroup
        .lines()
        .filter_map(|l| l.rsplit(':').next())
        .flat_map(|p| p.split('/'))
        .rfind(|c| c.ends_with(".service") && !c.contains(['\n', ' ']))
        .map(str::to_owned)
}

/// The replaced path in a `maps` line (`... /usr/lib64/libfoo.so.1 (deleted)`).
fn deleted_path(line: &str) -> Option<&str> {
    let path = line.strip_suffix(" (deleted)")?;
    // address perms offset dev inode path: the path starts at the 6th field.
    let mut rest = path;
    for _ in 0..5 {
        rest = rest.trim_start().split_once(char::is_whitespace)?.1;
    }
    let rest = rest.trim_start();
    (rest.starts_with('/') && is_system_path(rest)).then_some(rest)
}

fn read_limited(path: &Path, limit: u64) -> Option<String> {
    let file = std::fs::File::open(path).ok()?;
    let mut text = String::new();
    file.take(limit).read_to_string(&mut text).ok()?;
    Some(text)
}

fn inspect(root: &Path, pid: u32) -> Result<Option<StaleProcess>, ()> {
    let dir = root.join(pid.to_string());
    let exe = match std::fs::read_link(dir.join("exe")) {
        Ok(p) => Some(p.display().to_string()),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => return Err(()),
        // Kernel threads have no exe and a process may exit while we look.
        Err(_) => None,
    };
    let exe_deleted = exe
        .as_deref()
        .and_then(|e| e.strip_suffix(" (deleted)"))
        .filter(|p| is_system_path(p))
        .map(str::to_owned);
    let mut libs: Vec<String> = Vec::new();
    match read_limited(&dir.join("maps"), MAX_MAPS_BYTES) {
        Some(maps) => {
            libs.extend(maps.lines().filter_map(deleted_path).map(str::to_owned));
        }
        None if dir.join("maps").exists() => return Err(()),
        None => {}
    }
    libs.sort();
    libs.dedup();
    if let Some(e) = &exe_deleted {
        libs.retain(|l| l != e);
    }
    if exe_deleted.is_none() && libs.is_empty() {
        return Ok(None);
    }
    let comm =
        read_limited(&dir.join("comm"), 256).map_or_else(String::new, |c| c.trim().to_owned());
    let unit = read_limited(&dir.join("cgroup"), 8192).and_then(|c| unit_from_cgroup(&c));
    Ok(Some(StaleProcess {
        pid,
        comm,
        unit,
        exe: exe_deleted,
        libs,
    }))
}

/// Scans a `/proc`-shaped directory.
#[must_use]
pub fn scan_stale(root: &Path) -> StaleScan {
    let mut scan = StaleScan::default();
    let Ok(entries) = std::fs::read_dir(root) else {
        return scan;
    };
    for entry in entries.flatten().take(MAX_PROCESSES) {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|n| n.parse::<u32>().ok())
        else {
            continue;
        };
        match inspect(root, pid) {
            Ok(Some(p)) => {
                scan.inspected += 1;
                scan.stale.push(p);
            }
            Ok(None) => scan.inspected += 1,
            Err(()) => scan.unreadable += 1,
        }
    }
    scan.stale
        .sort_by(|a, b| a.unit.cmp(&b.unit).then_with(|| a.pid.cmp(&b.pid)));
    scan
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    fn fake_proc() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    fn add(root: &Path, pid: u32, exe: &str, maps: &str, comm: &str, cgroup: &str) {
        let d = root.join(pid.to_string());
        std::fs::create_dir_all(&d).unwrap();
        symlink(exe, d.join("exe")).unwrap();
        std::fs::write(d.join("maps"), maps).unwrap();
        std::fs::write(d.join("comm"), format!("{comm}\n")).unwrap();
        std::fs::write(d.join("cgroup"), cgroup).unwrap();
    }

    const MAPS_OLD_LIB: &str = "7f00-7f10 r-xp 00000000 fd:01 1234  /usr/lib64/libssl.so.3 (deleted)\n\
        7f10-7f20 r-xp 00000000 fd:01 99  /usr/lib64/libc.so.6\n\
        7f20-7f30 rw-s 00000000 00:01 5  /dev/shm/x (deleted)\n\
        7f30-7f40 rw-p 00000000 00:00 0  /tmp/scratch (deleted)\n\
        7f40-7f50 rw-p 00000000 00:00 0  \n";

    #[test]
    fn replaced_executable_and_library_are_found() {
        let root = fake_proc();
        add(
            root.path(),
            100,
            "/usr/sbin/nginx (deleted)",
            MAPS_OLD_LIB,
            "nginx",
            "0::/system.slice/nginx.service\n",
        );
        let scan = scan_stale(root.path());
        assert_eq!(scan.inspected, 1);
        assert_eq!(scan.unreadable, 0);
        let p = &scan.stale[0];
        assert_eq!((p.pid, p.comm.as_str()), (100, "nginx"));
        assert_eq!(p.unit.as_deref(), Some("nginx.service"));
        assert_eq!(p.exe.as_deref(), Some("/usr/sbin/nginx"));
        // Only the system library: shm and tmp mappings are not updates.
        assert_eq!(p.libs, ["/usr/lib64/libssl.so.3"]);
    }

    #[test]
    fn up_to_date_and_kernel_threads_are_clean() {
        let root = fake_proc();
        add(
            root.path(),
            1,
            "/usr/lib/systemd/systemd",
            "7f00-7f10 r-xp 0 fd:01 1  /usr/lib64/libc.so.6\n",
            "systemd",
            "0::/init.scope\n",
        );
        let kthread = root.path().join("2");
        std::fs::create_dir_all(&kthread).unwrap();
        std::fs::write(kthread.join("comm"), "kthreadd\n").unwrap();
        let scan = scan_stale(root.path());
        assert!(scan.stale.is_empty());
        assert_eq!(scan.inspected, 2);
    }

    #[test]
    fn processes_without_a_service_have_no_unit_and_sort_stably() {
        let root = fake_proc();
        add(
            root.path(),
            300,
            "/usr/bin/foo (deleted)",
            "",
            "foo",
            "0::/user.slice/session-2.scope\n",
        );
        add(
            root.path(),
            200,
            "/usr/bin/bar (deleted)",
            "",
            "bar",
            "0::/system.slice/bar.service\n",
        );
        add(
            root.path(),
            150,
            "/usr/bin/baz (deleted)",
            "",
            "baz",
            "0::/system.slice/bar.service\n",
        );
        let scan = scan_stale(root.path());
        let order: Vec<(Option<&str>, u32)> = scan
            .stale
            .iter()
            .map(|p| (p.unit.as_deref(), p.pid))
            .collect();
        assert_eq!(
            order,
            [
                (None, 300),
                (Some("bar.service"), 150),
                (Some("bar.service"), 200)
            ]
        );
    }

    #[test]
    fn cgroup_parsing() {
        assert_eq!(
            unit_from_cgroup(
                "0::/user.slice/user-1000.slice/user@1000.service/app.slice/app-x.service\n"
            )
            .as_deref(),
            Some("app-x.service")
        );
        assert_eq!(
            unit_from_cgroup("12:cpu:/system.slice/a.service\n0::/system.slice/a.service\n")
                .as_deref(),
            Some("a.service")
        );
        assert_eq!(unit_from_cgroup("0::/init.scope\n"), None);
        assert_eq!(unit_from_cgroup(""), None);
    }

    #[test]
    fn maps_line_parsing() {
        assert_eq!(
            deleted_path("7f00-7f10 r-xp 0 fd:01 1  /usr/lib/x.so (deleted)"),
            Some("/usr/lib/x.so")
        );
        assert_eq!(
            deleted_path("7f00-7f10 r-xp 0 fd:01 1  /usr/lib/x.so"),
            None
        );
        assert_eq!(
            deleted_path("7f00-7f10 rw-p 0 00:00 0  /tmp/x (deleted)"),
            None
        );
        assert_eq!(deleted_path("garbage (deleted)"), None);
        assert_eq!(deleted_path(""), None);
    }

    #[test]
    fn a_missing_root_is_an_empty_scan() {
        assert_eq!(
            scan_stale(Path::new("/nonexistent/proc")),
            StaleScan::default()
        );
    }

    #[test]
    fn the_real_proc_can_be_scanned() {
        let scan = scan_stale(Path::new("/proc"));
        // At least this test process is visible on Linux.
        if Path::new("/proc/self").exists() {
            assert!(scan.inspected >= 1);
        }
    }
}
