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
}
