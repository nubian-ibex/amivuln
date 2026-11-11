// SPDX-FileCopyrightText: 2026 amivuln contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Confined execution of the version probe (roadmap phase 6).
//!
//! [`probe`] runs a target with fixed arguments in a child that cannot write
//! to the file system, open sockets or gain privileges, and that is bounded
//! in CPU time, wall-clock time and output. When the kernel cannot enforce
//! that, the call fails with [`SandboxError::Unsupported`]; it never falls
//! back to running unconfined.
//!
//! The seccomp filter is a deny list rather than an allow list: the targets
//! are arbitrary binaries (Go, Rust, C) whose startup syscalls cannot be
//! enumerated, and Landlock already removes file-system writes. The deny
//! list covers the network and the other ways out.

#![deny(unsafe_code)]

mod sys;

use std::io::Read;
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

/// Output limit per stream.
const MAX_OUTPUT: usize = 64 * 1024;

/// How long to wait for a reader thread once the child is gone; a
/// grandchild holding the pipe open must not hang the probe.
const DRAIN_WAIT: Duration = Duration::from_millis(200);

/// What a confined run produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeOutput {
    /// True when the program exited with status 0.
    pub success: bool,
    /// Standard output, then standard error, each capped at 64 KiB.
    pub output: Vec<u8>,
}

/// Why the probe could not run or finish.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SandboxError {
    /// The kernel or architecture cannot enforce the confinement.
    #[error("sandbox unavailable: {0}")]
    Unsupported(String),
    /// The target path is not usable.
    #[error("invalid probe target: {0}")]
    InvalidTarget(String),
    /// The program did not finish before the timeout.
    #[error("the probe timed out")]
    TimedOut,
    /// Setting up or spawning the child failed.
    #[error("sandbox error: {0}")]
    Io(String),
}

/// True when this kernel and architecture can enforce the sandbox.
#[must_use]
pub fn supported() -> bool {
    sys::supported()
}

fn drain<R: Read + Send + 'static>(stream: Option<R>) -> mpsc::Receiver<Vec<u8>> {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(s) = stream {
            let _ = s.take(MAX_OUTPUT as u64).read_to_end(&mut buf);
        }
        let _ = tx.send(buf);
    });
    rx
}

/// Runs the absolute path `exe` with `args` in the sandbox and returns what
/// it printed.
///
/// # Errors
///
/// Fails when `exe` is not an absolute path to an existing file, when the
/// sandbox cannot be enforced, when the child cannot be spawned, or when it
/// does not finish within `timeout`.
pub fn probe(exe: &Path, args: &[&str], timeout: Duration) -> Result<ProbeOutput, SandboxError> {
    if !exe.is_absolute() || !exe.is_file() {
        return Err(SandboxError::InvalidTarget(exe.display().to_string()));
    }
    let mut cmd = Command::new(exe);
    cmd.args(args)
        .env_clear()
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let _guard = sys::confine(&mut cmd, exe)?;
    let mut child = cmd.spawn().map_err(|e| SandboxError::Io(e.to_string()))?;
    let out = drain(child.stdout.take());
    let err = drain(child.stderr.take());

    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {}
            Err(e) => return Err(SandboxError::Io(e.to_string())),
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(SandboxError::TimedOut);
        }
        thread::sleep(Duration::from_millis(5));
    };
    let mut output = out.recv_timeout(DRAIN_WAIT).unwrap_or_default();
    output.extend(err.recv_timeout(DRAIN_WAIT).unwrap_or_default());
    // A signal (for example the CPU limit's SIGXCPU) is a failure, not a pass.
    Ok(ProbeOutput {
        success: status.success() && status.signal().is_none(),
        output,
    })
}
