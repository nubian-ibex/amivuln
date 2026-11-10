// SPDX-FileCopyrightText: 2026 amivuln contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Target resolution: user input and installed packages to package references.
//!
//! I/O goes through [`amivuln_core::ProcessRunner`], so the logic here is
//! tested with a fake runner. [`SystemRunner`] is the real implementation.

#![forbid(unsafe_code)]

mod build;
pub mod container;
pub mod embedded;
mod host;
mod pacman;
mod restart;
mod rpm;
mod system;
mod target;
mod unit;

pub use build::{from_name_version, from_purl};
pub use container::{
    ContainerError, available_runtime, export as export_container, packages as container_packages,
};
pub use embedded::{Detected, Origin, detect, detect_bytes, language_packages, package_from_note};
pub use host::{HostInfo, parse_os_release};
pub use pacman::PacmanResolver;
pub use restart::{StaleProcess, StaleScan, scan_stale};
pub use rpm::RpmResolver;
pub use system::SystemRunner;
pub use target::{Target, parse_target};
pub use unit::{UnitExe, exe_for_unit, list_running_services};

use amivuln_core::{PackageRef, ProcessError};

/// Resolution failures, each with an actionable message.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ResolveError {
    /// No installed package matches.
    #[error("no installed package matches {0:?}")]
    NotFound(String),
    /// More than one package matches; the caller must pick one.
    #[error("{0:?} is ambiguous: matches {1}; use --package NAME to choose")]
    Ambiguous(String, String),
    /// The package manager failed.
    #[error(transparent)]
    Process(#[from] ProcessError),
    /// The package manager printed something unexpected.
    #[error("unexpected output from the package manager: {0}")]
    Parse(String),
}

/// Looks up installed packages.
pub trait PackageResolver {
    /// The package that owns a file.
    ///
    /// # Errors
    ///
    /// [`ResolveError::NotFound`] when no package owns the path,
    /// [`ResolveError::Ambiguous`] for several owners.
    fn owner_of(&self, path: &str) -> Result<PackageRef, ResolveError>;

    /// The installed package with this name.
    ///
    /// # Errors
    ///
    /// [`ResolveError::NotFound`] when it is not installed,
    /// [`ResolveError::Ambiguous`] when several versions are installed.
    fn by_name(&self, name: &str) -> Result<PackageRef, ResolveError>;

    /// Every installed package, sorted by name then version.
    ///
    /// # Errors
    ///
    /// Fails when the package manager cannot be run or prints garbage.
    fn list_all(&self) -> Result<Vec<PackageRef>, ResolveError>;
}

#[cfg(test)]
mod tests_support {
    use std::cell::RefCell;

    use amivuln_core::{ProcessError, ProcessOutput, ProcessRunner, Program};

    /// Scripted runner that records the arguments it receives.
    pub(crate) struct FakeRunner {
        replies: RefCell<Vec<ProcessOutput>>,
        pub(crate) calls: RefCell<Vec<Vec<String>>>,
    }

    impl FakeRunner {
        pub(crate) fn ok(stdout: &str) -> Self {
            Self::sequence(&[stdout])
        }

        pub(crate) fn sequence(replies: &[&str]) -> Self {
            Self {
                replies: RefCell::new(
                    replies
                        .iter()
                        .rev()
                        .map(|s| ProcessOutput {
                            success: true,
                            stdout: s.as_bytes().to_vec(),
                        })
                        .collect(),
                ),
                calls: RefCell::default(),
            }
        }

        pub(crate) fn failing() -> Self {
            Self {
                replies: RefCell::new(vec![ProcessOutput {
                    success: false,
                    stdout: Vec::new(),
                }]),
                calls: RefCell::default(),
            }
        }
    }

    impl ProcessRunner for FakeRunner {
        fn run(&self, _: Program, args: &[&str]) -> Result<ProcessOutput, ProcessError> {
            self.calls
                .borrow_mut()
                .push(args.iter().map(|a| (*a).to_owned()).collect());
            self.replies
                .borrow_mut()
                .pop()
                .ok_or(ProcessError::Io(Program::Rpm, "no scripted reply".into()))
        }
    }
}
