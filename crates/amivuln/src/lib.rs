// SPDX-FileCopyrightText: 2026 amivuln contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! amivuln command line: argument parsing, configuration and orchestration.
//!
//! The binary is a thin wrapper around [`app::run`]. Everything is exposed as
//! a library so the man page and completion generators in `xtask` can reuse
//! the exact argument definitions.

#![forbid(unsafe_code)]

pub mod app;
pub mod cli;
pub mod commands;
pub mod config;
pub mod mcp;
pub mod pipeline;
pub mod scan;
