// SPDX-FileCopyrightText: 2026 amivuln contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Domain types and pure decision logic for amivuln.
//!
//! This crate performs no I/O. Edge crates implement the data sources and
//! resolvers; the rules that must never regress (distro status beats upstream
//! comparison, unknown is kept apart, incomplete beats findings) live here.

#![forbid(unsafe_code)]

mod exit;
mod matching;
mod package;
mod source;

pub use exit::{Condition, ExitCode, exit_code};
pub use matching::{DistroStatus, Finding, Severity, Verdict, classify, sort_findings};
pub use package::{Ecosystem, PackageRef, Provenance, Version};
pub use source::{SourceId, SourceReport, SourceStatus, is_complete};
