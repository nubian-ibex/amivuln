// SPDX-FileCopyrightText: 2026 amivuln contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! The only `unsafe` code in the workspace: raw Landlock, seccomp and
//! `prctl` calls applied in the child between `fork` and `exec`.
//!
//! Everything that allocates (opening directories, building the BPF program)
//! happens in the parent. The `pre_exec` closure only issues system calls,
//! which keeps it async-signal-safe.

#![allow(unsafe_code)]
// The RLIMIT_* constants are unsigned on glibc and signed on musl; the `as _`
// casts bridge that and the values are tiny.
#![allow(clippy::cast_possible_wrap, clippy::cast_sign_loss)]

use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;

use crate::SandboxError;

const SYS_LANDLOCK_CREATE_RULESET: libc::c_long = 444;
const SYS_LANDLOCK_ADD_RULE: libc::c_long = 445;
const SYS_LANDLOCK_RESTRICT_SELF: libc::c_long = 446;
const LANDLOCK_CREATE_RULESET_VERSION: libc::c_uint = 1;
const LANDLOCK_RULE_PATH_BENEATH: libc::c_int = 1;

const ACCESS_EXECUTE: u64 = 1 << 0;
const ACCESS_READ_FILE: u64 = 1 << 2;
const ACCESS_READ_DIR: u64 = 1 << 3;
/// Every filesystem right of Landlock ABI 1: handling them all denies them all.
const HANDLED_FS: u64 = (1 << 13) - 1;

/// Unprivileged account the probe drops to when started as root.
const NOBODY: libc::c_uint = 65_534;

/// Directories a dynamically linked binary needs to start.
const SYSTEM_READ: &[&str] = &[
    "/usr",
    "/lib",
    "/lib64",
    "/bin",
    "/sbin",
    "/etc/ld.so.cache",
];

#[repr(C)]
struct RulesetAttr {
    handled_access_fs: u64,
}

#[repr(C, packed)]
struct PathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
}

/// Prepared confinement; keeps the Landlock ruleset descriptor alive until
/// the child has been spawned.
pub(crate) struct Guard {
    _ruleset: OwnedFd,
}

fn last_error(what: &str) -> SandboxError {
    SandboxError::Io(format!("{what}: {}", io::Error::last_os_error()))
}

fn landlock_abi() -> Option<libc::c_long> {
    // SAFETY: a null attribute with size 0 and the VERSION flag only queries
    // the ABI number; no memory is read or written.
    let abi = unsafe {
        libc::syscall(
            SYS_LANDLOCK_CREATE_RULESET,
            std::ptr::null::<RulesetAttr>(),
            0_usize,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };
    (abi >= 1).then_some(abi)
}

/// True when the running kernel can enforce the sandbox.
pub(crate) fn supported() -> bool {
    audit_arch().is_some() && landlock_abi().is_some()
}

fn new_ruleset() -> Result<OwnedFd, SandboxError> {
    if landlock_abi().is_none() {
        return Err(SandboxError::Unsupported(
            "the kernel has no Landlock support".to_owned(),
        ));
    }
    let attr = RulesetAttr {
        handled_access_fs: HANDLED_FS,
    };
    // SAFETY: `attr` is a valid, initialised `RulesetAttr` and the size
    // passed matches it.
    let fd = unsafe {
        libc::syscall(
            SYS_LANDLOCK_CREATE_RULESET,
            &raw const attr,
            size_of::<RulesetAttr>(),
            0_u32,
        )
    };
    if fd < 0 {
        return Err(last_error("landlock_create_ruleset"));
    }
    let fd = RawFd::try_from(fd).map_err(|e| SandboxError::Io(e.to_string()))?;
    // SAFETY: the kernel just returned `fd`, so this process owns it and
    // nothing else wraps it.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn allow_read(ruleset: &OwnedFd, path: &Path) -> Result<(), SandboxError> {
    let Ok(meta) = std::fs::metadata(path) else {
        // A directory this distribution does not have is not an error.
        return Ok(());
    };
    let c = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| SandboxError::Io("path contains a NUL byte".to_owned()))?;
    // SAFETY: `c` is a valid NUL-terminated string that outlives the call.
    let raw = unsafe { libc::open(c.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
    if raw < 0 {
        return Err(last_error("open"));
    }
    // SAFETY: `open` just returned `raw`; this process owns it.
    let parent = unsafe { OwnedFd::from_raw_fd(raw) };
    // Directory-only rights on a plain file make Landlock reject the rule.
    let allowed_access = if meta.is_dir() {
        ACCESS_EXECUTE | ACCESS_READ_FILE | ACCESS_READ_DIR
    } else {
        ACCESS_EXECUTE | ACCESS_READ_FILE
    };
    let rule = PathBeneathAttr {
        allowed_access,
        parent_fd: parent.as_raw_fd(),
    };
    // SAFETY: `rule` is a valid `PathBeneathAttr` and both descriptors are
    // open for the duration of the call.
    let rc = unsafe {
        libc::syscall(
            SYS_LANDLOCK_ADD_RULE,
            ruleset.as_raw_fd(),
            LANDLOCK_RULE_PATH_BENEATH,
            &raw const rule,
            0_u32,
        )
    };
    if rc < 0 {
        return Err(last_error("landlock_add_rule"));
    }
    Ok(())
}

// `Option` because other architectures have no filter; see the last variant.
#[allow(clippy::unnecessary_wraps)]
#[cfg(target_arch = "x86_64")]
fn audit_arch() -> Option<u32> {
    Some(0xC000_003E)
}

#[allow(clippy::unnecessary_wraps)]
#[cfg(target_arch = "aarch64")]
fn audit_arch() -> Option<u32> {
    Some(0xC000_00B7)
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
fn audit_arch() -> Option<u32> {
    None
}

/// Syscalls the probe may never make: network, tracing of other processes,
/// namespace and mount changes, kernel extension points and `io_uring`
/// (which could reach the network around the filter).
fn denied_syscalls() -> Vec<libc::c_long> {
    vec![
        libc::SYS_socket,
        libc::SYS_socketpair,
        libc::SYS_connect,
        libc::SYS_bind,
        libc::SYS_ptrace,
        libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev,
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_pivot_root,
        libc::SYS_chroot,
        libc::SYS_reboot,
        libc::SYS_kexec_load,
        libc::SYS_init_module,
        libc::SYS_finit_module,
        libc::SYS_delete_module,
        libc::SYS_bpf,
        libc::SYS_perf_event_open,
        libc::SYS_keyctl,
        libc::SYS_add_key,
        libc::SYS_request_key,
        libc::SYS_unshare,
        libc::SYS_setns,
        libc::SYS_io_uring_setup,
        libc::SYS_io_uring_enter,
        libc::SYS_io_uring_register,
    ]
}

fn stmt(code: u32, k: u32) -> libc::sock_filter {
    libc::sock_filter {
        code: u16::try_from(code).unwrap_or(0),
        jt: 0,
        jf: 0,
        k,
    }
}

fn jump_eq(k: u32, jt: u8) -> libc::sock_filter {
    libc::sock_filter {
        code: u16::try_from(libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K).unwrap_or(0),
        jt,
        jf: 0,
        k,
    }
}

/// Builds the BPF program: wrong architecture is killed, denied syscalls
/// fail with `EPERM`, everything else is allowed.
fn build_filter() -> Result<Vec<libc::sock_filter>, SandboxError> {
    let arch = audit_arch().ok_or_else(|| {
        SandboxError::Unsupported("seccomp filter is not defined for this architecture".to_owned())
    })?;
    let denied = denied_syscalls();
    let load = libc::BPF_LD | libc::BPF_W | libc::BPF_ABS;
    let ret = libc::BPF_RET | libc::BPF_K;
    let mut prog = vec![
        stmt(load, 4),
        jump_eq(arch, 1),
        stmt(ret, libc::SECCOMP_RET_KILL_PROCESS),
        stmt(load, 0),
    ];
    let n = denied.len();
    for (i, nr) in denied.iter().enumerate() {
        let nr = u32::try_from(*nr).map_err(|e| SandboxError::Io(e.to_string()))?;
        let jt = u8::try_from(n - i).map_err(|e| SandboxError::Io(e.to_string()))?;
        prog.push(jump_eq(nr, jt));
    }
    prog.push(stmt(ret, libc::SECCOMP_RET_ALLOW));
    let errno = u32::try_from(libc::EPERM).unwrap_or(1);
    prog.push(stmt(ret, libc::SECCOMP_RET_ERRNO | errno));
    Ok(prog)
}

/// Prepares the confinement for `exe` and arranges for `cmd` to apply it
/// in the child just before `exec`.
pub(crate) fn confine(cmd: &mut Command, exe: &Path) -> Result<Guard, SandboxError> {
    let ruleset = new_ruleset()?;
    for dir in SYSTEM_READ {
        allow_read(&ruleset, Path::new(dir))?;
    }
    if let Some(parent) = exe.parent() {
        allow_read(&ruleset, parent)?;
    }
    let filter = build_filter()?;
    let ruleset_fd = ruleset.as_raw_fd();
    let drop_privileges = {
        // SAFETY: `geteuid` has no preconditions and cannot fail.
        unsafe { libc::geteuid() == 0 }
    };

    // SAFETY: the closure only issues system calls on data prepared above
    // (no allocation, no locks), which is allowed between fork and exec.
    unsafe {
        cmd.pre_exec(move || apply(ruleset_fd, &filter, drop_privileges));
    }
    Ok(Guard { _ruleset: ruleset })
}

/// Runs in the child: lowers privileges and resources, then installs
/// Landlock and seccomp. Order matters: seccomp comes last because the
/// earlier steps need syscalls it would not forbid but keeps the window short.
fn apply(ruleset_fd: RawFd, filter: &[libc::sock_filter], drop_privileges: bool) -> io::Result<()> {
    // SAFETY: plain system calls with valid arguments; `filter` outlives them.
    unsafe {
        check(libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))?;
        limit(libc::RLIMIT_CPU as _, 2)?;
        limit(libc::RLIMIT_FSIZE as _, 0)?;
        limit(libc::RLIMIT_CORE as _, 0)?;
        limit(libc::RLIMIT_NOFILE as _, 64)?;
        if drop_privileges {
            check(libc::setgroups(0, std::ptr::null()))?;
            check(libc::setgid(NOBODY))?;
            check(libc::setuid(NOBODY))?;
        }
        let rc = libc::syscall(SYS_LANDLOCK_RESTRICT_SELF, ruleset_fd, 0_u32);
        check(i32::try_from(rc).unwrap_or(-1))?;
        let prog = libc::sock_fprog {
            len: u16::try_from(filter.len()).unwrap_or(u16::MAX),
            filter: filter.as_ptr().cast_mut(),
        };
        check(libc::prctl(
            libc::PR_SET_SECCOMP,
            libc::SECCOMP_MODE_FILTER,
            &raw const prog,
            0,
            0,
        ))?;
    }
    Ok(())
}

fn check(rc: libc::c_int) -> io::Result<()> {
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Sets a hard and soft resource limit.
///
/// # Safety
///
/// Must only be called with a valid `resource`; it issues one system call.
unsafe fn limit(resource: libc::c_int, value: libc::rlim_t) -> io::Result<()> {
    let lim = libc::rlimit {
        rlim_cur: value,
        rlim_max: value,
    };
    // SAFETY: `lim` is a valid `rlimit` for the duration of the call.
    check(unsafe { libc::setrlimit(resource as _, &raw const lim) })
}
