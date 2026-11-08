// SPDX-FileCopyrightText: 2026 amivuln contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! The real [`ProcessRunner`]: allowlisted programs, no shell, bounded.

use std::io::Read;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use amivuln_core::{ProcessError, ProcessOutput, ProcessRunner, Program};

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
    };
    candidates
        .iter()
        .copied()
        .find(|p| std::path::Path::new(p).is_file())
}

impl ProcessRunner for SystemRunner {
    fn run(&self, program: Program, args: &[&str]) -> Result<ProcessOutput, ProcessError> {
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
        let stdout = child.stdout.take();
        let reader = thread::spawn(move || {
            let mut buf = Vec::new();
            if let Some(out) = stdout {
                // One byte past the limit tells "exactly full" from "too much".
                let _ = out.take(MAX_OUTPUT as u64 + 1).read_to_end(&mut buf);
            }
            buf
        });

        let deadline = Instant::now() + self.timeout;
        let status = loop {
            if let Some(status) = child.try_wait().map_err(io)? {
                break status;
            }
            if Instant::now() >= deadline || reader.is_finished() {
                let _ = child.kill();
                let _ = child.wait();
                let buf = reader.join().unwrap_or_default();
                return Err(if buf.len() > MAX_OUTPUT {
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
