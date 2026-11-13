// SPDX-FileCopyrightText: 2026 amivuln contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! The real [`ProcessRunner`]: allowlisted programs, no shell, bounded.

use std::io::Read;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use amivuln_core::{ProcessError, ProcessOutput, ProcessRunner, ProcessStream, Program};

/// Output limit per run.
const MAX_OUTPUT: usize = 4 * 1024 * 1024;

/// Runs system package managers from fixed absolute paths.
#[derive(Debug, Clone, Copy)]
pub struct SystemRunner {
    timeout: Duration,
}

impl SystemRunner {
    /// Creates a runner that kills programs after `timeout`.
    #[must_use]
    pub fn new(timeout: Duration) -> Self {
        Self { timeout }
    }
}

impl Default for SystemRunner {
    fn default() -> Self {
        Self::new(Duration::from_secs(10))
    }
}

fn locate(program: Program) -> Option<&'static str> {
    let candidates: &[&str] = match program {
        Program::Rpm => &["/usr/bin/rpm", "/bin/rpm"],
        Program::Pacman => &["/usr/bin/pacman", "/bin/pacman"],
        Program::Systemctl => &["/usr/bin/systemctl", "/bin/systemctl"],
        Program::Podman => &["/usr/bin/podman", "/bin/podman"],
        Program::Docker => &["/usr/bin/docker", "/bin/docker"],
    };
    candidates
        .iter()
        .copied()
        .find(|p| std::path::Path::new(p).is_file())
}

impl ProcessRunner for SystemRunner {
    fn stream(
        &self,
        program: Program,
        args: &[&str],
    ) -> Result<Box<dyn ProcessStream>, ProcessError> {
        let path = locate(program).ok_or(ProcessError::NotInstalled(program))?;
        let io = |e: std::io::Error| ProcessError::Io(program, e.to_string());
        let mut child = Command::new(path)
            .args(args)
            .env_clear()
            .env("LC_ALL", "C")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(io)?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| ProcessError::Io(program, "no standard output".to_owned()))?;
        let child = std::sync::Arc::new(std::sync::Mutex::new(child));
        let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (watched, finished) = (std::sync::Arc::clone(&child), std::sync::Arc::clone(&done));
        let deadline = Instant::now() + STREAM_TIMEOUT;
        thread::spawn(move || {
            while !finished.load(std::sync::atomic::Ordering::SeqCst) {
                if Instant::now() >= deadline {
                    let _ = watched
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .kill();
                    return;
                }
                thread::sleep(Duration::from_millis(100));
            }
        });
        Ok(Box::new(ChildStream {
            child,
            stdout,
            done,
        }))
    }

    fn run(&self, program: Program, args: &[&str]) -> Result<ProcessOutput, ProcessError> {
        let path = locate(program).ok_or(ProcessError::NotInstalled(program))?;
        self.run_at(program, path, args)
    }
}

/// How long a streamed program may run: an export of a large image takes
/// minutes, unlike the package queries.
const STREAM_TIMEOUT: Duration = Duration::from_secs(600);

/// A child whose standard output is read by the caller. A watchdog thread
/// kills it at the deadline, which ends the read with end-of-file.
struct ChildStream {
    child: std::sync::Arc<std::sync::Mutex<std::process::Child>>,
    stdout: std::process::ChildStdout,
    done: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl ChildStream {
    fn stop(&self) {
        self.done.store(true, std::sync::atomic::Ordering::SeqCst);
        let mut child = self
            .child
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _ = child.kill();
        let _ = child.wait();
    }
}

impl Read for ChildStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.stdout.read(buf)
    }
}

impl ProcessStream for ChildStream {
    fn finish(self: Box<Self>) -> Result<bool, ProcessError> {
        self.done.store(true, std::sync::atomic::Ordering::SeqCst);
        let status = self
            .child
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .wait()
            .map_err(|e| ProcessError::Io(Program::Podman, e.to_string()))?;
        Ok(status.success())
    }
}

impl Drop for ChildStream {
    fn drop(&mut self) {
        // Stopping a finished child is harmless; stopping a running one is the
        // point (the reader gave up, for example at the size limit).
        self.stop();
    }
}

impl SystemRunner {
    /// Runs the program at `path`, bounded in time and output size.
    fn run_at(
        &self,
        program: Program,
        path: &str,
        args: &[&str],
    ) -> Result<ProcessOutput, ProcessError> {
        let io = |e: std::io::Error| ProcessError::Io(program, e.to_string());
        let mut child = Command::new(path)
            .args(args)
            .env_clear()
            .env("LC_ALL", "C")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(io)?;
        let stdout = child.stdout.take();
        let overflow = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = std::sync::Arc::clone(&overflow);
        let reader = thread::spawn(move || {
            let mut buf = Vec::new();
            if let Some(out) = stdout {
                // One byte past the limit tells "exactly full" from "too much".
                let _ = out.take(MAX_OUTPUT as u64 + 1).read_to_end(&mut buf);
            }
            flag.store(buf.len() > MAX_OUTPUT, std::sync::atomic::Ordering::SeqCst);
            buf
        });

        let deadline = Instant::now() + self.timeout;
        let status = loop {
            if let Some(status) = child.try_wait().map_err(io)? {
                break status;
            }
            // The reader also finishes at end-of-file, which comes a moment
            // before the child can be reaped: only an overflow stops the
            // program early, otherwise it is waited for until the deadline.
            let too_much = overflow.load(std::sync::atomic::Ordering::SeqCst);
            if too_much || Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                let _ = reader.join();
                return Err(if too_much {
                    ProcessError::TooMuchOutput(program, MAX_OUTPUT)
                } else {
                    ProcessError::TimedOut(program)
                });
            }
            thread::sleep(Duration::from_millis(5));
        };
        let stdout = reader.join().unwrap_or_default();
        if stdout.len() > MAX_OUTPUT {
            return Err(ProcessError::TooMuchOutput(program, MAX_OUTPUT));
        }
        Ok(ProcessOutput {
            success: status.success(),
            stdout,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_program_is_reported() {
        // pacman is not installed on Fedora/Debian; on Arch the call succeeds.
        let r = SystemRunner::default();
        match r.run(Program::Pacman, &["--version"]) {
            Ok(out) => assert!(out.success),
            Err(e) => assert_eq!(e, ProcessError::NotInstalled(Program::Pacman)),
        }
    }

    #[test]
    fn runs_rpm_when_present() {
        let r = SystemRunner::default();
        if let Ok(out) = r.run(Program::Rpm, &["--version"]) {
            assert!(out.success);
            assert!(String::from_utf8_lossy(&out.stdout).starts_with("RPM version"));
        }
    }

    #[test]
    fn rpm_unknown_package_fails_cleanly() {
        let r = SystemRunner::default();
        if let Ok(out) = r.run(Program::Rpm, &["-q", "--", "amivuln-surely-not-installed"]) {
            assert!(!out.success);
        }
    }

    /// Regression: the reader sees end-of-file a moment before the child can
    /// be reaped, and that was taken for "too much output", so fast programs
    /// sometimes failed and a package looked unresolved.
    #[test]
    fn a_fast_program_never_fails_spuriously() {
        // A program that closes its output and keeps running a moment is the
        // case that used to be killed as "too much output".
        let r = SystemRunner::default();
        let out = r.run_at(
            Program::Rpm,
            "/bin/sh",
            &["-c", "exec >&-; sleep 0.3; exit 0"],
        );
        assert!(out.is_ok_and(|o| o.success));
    }

    #[test]
    fn output_over_the_limit_is_still_refused() {
        let r = SystemRunner::default();
        let out = r.run_at(
            Program::Rpm,
            "/bin/sh",
            &["-c", "head -c 5000000 /dev/zero; sleep 5"],
        );
        assert_eq!(
            out,
            Err(ProcessError::TooMuchOutput(Program::Rpm, MAX_OUTPUT))
        );
    }

    #[test]
    fn zero_timeout_kills_the_program() {
        let r = SystemRunner::new(Duration::ZERO);
        if locate(Program::Rpm).is_some() {
            assert_eq!(
                r.run(Program::Rpm, &["-qa"]),
                Err(ProcessError::TimedOut(Program::Rpm))
            );
        }
    }

    #[test]
    fn resolves_bash_through_the_real_rpm() {
        use crate::{PackageResolver, RpmResolver};
        use amivuln_core::Ecosystem;
        let r = SystemRunner::default();
        if locate(Program::Rpm).is_some() && std::path::Path::new("/usr/bin/bash").is_file() {
            // Owned on rpm-based hosts; on others rpm reports no owner.
            if let Ok(p) = RpmResolver::new(&r, Ecosystem::Fedora(0)).owner_of("/usr/bin/bash") {
                assert_eq!(p.name, "bash");
            }
        }
    }
}
