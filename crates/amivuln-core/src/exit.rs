// SPDX-FileCopyrightText: 2026 amivuln contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Process exit codes and their precedence.

/// Exit codes of the CLI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitCode {
    /// Finished, nothing above the `--fail-on` threshold.
    Success = 0,
    /// Finished, findings above the threshold.
    PolicyViolation = 1,
    /// Result incomplete: a required source was unavailable.
    Incomplete = 2,
    /// Target not resolved (not found, ambiguous or no detectable version).
    TargetNotResolved = 3,
    /// Usage or configuration error (`EX_USAGE`).
    Usage = 64,
    /// Internal error (`EX_SOFTWARE`).
    Internal = 70,
}

/// A fact observed during a run that influences the exit code.
///
/// Variants are declared from lowest to highest precedence, so the derived
/// ordering is the precedence order 70 > 64 > 2 > 3 > 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Condition {
    /// A finding crossed the `--fail-on` threshold.
    Violation,
    /// Some target could not be resolved.
    Unresolved,
    /// A required source failed.
    Incomplete,
    /// Invalid arguments or configuration.
    Usage,
    /// Internal error occurred.
    Internal,
}

/// Picks the exit code for the observed conditions (precedence 70 > 64 > 2 > 3 > 1 > 0).
///
/// Incomplete wins over findings so CI never treats a false negative as
/// success.
#[must_use]
pub fn exit_code(conditions: &[Condition]) -> ExitCode {
    match conditions.iter().max() {
        None => ExitCode::Success,
        Some(Condition::Violation) => ExitCode::PolicyViolation,
        Some(Condition::Unresolved) => ExitCode::TargetNotResolved,
        Some(Condition::Incomplete) => ExitCode::Incomplete,
        Some(Condition::Usage) => ExitCode::Usage,
        Some(Condition::Internal) => ExitCode::Internal,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use Condition::{Incomplete, Internal, Unresolved, Usage, Violation};

    #[test]
    fn precedence_order() {
        assert_eq!(exit_code(&[]), ExitCode::Success);
        assert_eq!(exit_code(&[Violation]), ExitCode::PolicyViolation);
        assert_eq!(
            exit_code(&[Violation, Unresolved]),
            ExitCode::TargetNotResolved
        );
        assert_eq!(
            exit_code(&[Unresolved, Violation, Incomplete]),
            ExitCode::Incomplete
        );
        assert_eq!(exit_code(&[Incomplete, Usage, Violation]), ExitCode::Usage);
        assert_eq!(
            exit_code(&[Usage, Internal, Incomplete]),
            ExitCode::Internal
        );
    }

    #[test]
    fn numeric_values_match_contract() {
        assert_eq!(ExitCode::Success as i32, 0);
        assert_eq!(ExitCode::PolicyViolation as i32, 1);
        assert_eq!(ExitCode::Incomplete as i32, 2);
        assert_eq!(ExitCode::TargetNotResolved as i32, 3);
        assert_eq!(ExitCode::Usage as i32, 64);
        assert_eq!(ExitCode::Internal as i32, 70);
    }
}
