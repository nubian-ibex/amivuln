// SPDX-FileCopyrightText: 2026 amivuln contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Domain types and pure decision logic for amivuln.
//!
//! This crate performs no I/O. Edge crates implement the data sources and
//! resolvers; the rules that must never regress (distro status beats upstream
//! comparison, unknown is kept apart, incomplete beats findings) live here.

#![forbid(unsafe_code)]

mod baseline;
mod exit;
pub mod i18n;
mod ignore;
mod matching;
mod package;
mod pending;
mod process;
mod report;
mod score;
mod source;
mod vex;

pub use baseline::{Baseline, BaselineError, parse_baseline};
pub use exit::{Condition, ExitCode, exit_code};
pub use ignore::{IgnoreEntry, IgnoreError, parse_ignore, suppress};
pub use matching::{
    DistroStatus, EpssInfo, Finding, KevInfo, Severity, Verdict, classify, sort_findings,
};
pub use package::{Ecosystem, PackageRef, Provenance, Version};
pub use pending::{CveAnswer, CveHit, CveState, PendingUpdate, cve_answers, pending_updates};
pub use process::{ProcessError, ProcessOutput, ProcessRunner, ProcessStream, Program};
pub use report::{
    CveReport, FailOn, HostMeta, PendingReport, Policy, RestartItem, RestartReport, RunReport,
    Summary, TargetReport, Unresolved,
};
pub use score::{Grade, Score, score};
pub use source::{SourceId, SourceReport, SourceStatus, is_complete};
pub use vex::{VexStatement, apply_vex, parse_vex};

/// Makes `cargo test` run the code examples in the README.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;
