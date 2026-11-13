// SPDX-FileCopyrightText: 2026 amivuln contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Port for running allowlisted system programs.

/// System programs amivuln may run. Anything else cannot be expressed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Program {
    /// The RPM package manager.
    Rpm,
    /// The pacman package manager.
    Pacman,
    /// systemd's control tool, for read-only `show` queries.
    Systemctl,
    /// The podman container runtime, for read-only `export` of a rootfs.
    Podman,
    /// The docker container runtime, for read-only `export` of a rootfs.
    Docker,
}

/// Result of a finished program.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessOutput {
    /// True when the program exited with status 0.
    pub success: bool,
    /// Captured standard output (bounded by the runner).
    pub stdout: Vec<u8>,
}

/// Why a program could not be run to completion.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ProcessError {
    /// The program is not installed in a trusted location.
    #[error("{0:?} is not installed in a trusted system path")]
    NotInstalled(Program),
    /// The program did not finish before the timeout.
    #[error("{0:?} timed out")]
    TimedOut(Program),
    /// The program wrote more output than the limit.
    #[error("{0:?} produced more output than the {1} byte limit")]
    TooMuchOutput(Program, usize),
    /// Spawning or reading failed.
    #[error("could not run {0:?}: {1}")]
    Io(Program, String),
}

/// A running program whose standard output is read while it is produced, for
/// output too large to hold in memory (a container export). Dropping it before
/// the end stops the program.
pub trait ProcessStream: std::io::Read {
    /// Waits for the program and tells whether it exited with status 0.
    ///
    /// # Errors
    ///
    /// Fails when the program cannot be waited for.
    fn finish(self: Box<Self>) -> Result<bool, ProcessError>;
}

/// Runs a program with fixed arguments: no shell, clean environment,
/// `LC_ALL=C`, bounded output and a timeout.
pub trait ProcessRunner {
    /// Runs `program` with `args` and returns its output.
    ///
    /// # Errors
    ///
    /// Fails when the program is missing, times out, exceeds the output
    /// limit or cannot be spawned.
    fn run(&self, program: Program, args: &[&str]) -> Result<ProcessOutput, ProcessError>;

    /// Starts `program` and returns its standard output as a stream. Only the
    /// real runner implements it; the default refuses.
    ///
    /// # Errors
    ///
    /// Fails when the program is missing, cannot be spawned, or the runner
    /// does not stream.
    fn stream(
        &self,
        program: Program,
        args: &[&str],
    ) -> Result<Box<dyn ProcessStream>, ProcessError> {
        let _ = args;
        Err(ProcessError::Io(
            program,
            "this runner does not stream output".to_owned(),
        ))
    }
}
