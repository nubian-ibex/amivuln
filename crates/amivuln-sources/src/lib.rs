// SPDX-FileCopyrightText: 2026 amivuln contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Parsers and models for vulnerability data sources.
//!
//! Network access is not part of this crate yet; parsers take bytes so they
//! can be tested with recorded fixtures and fuzzed.

#![forbid(unsafe_code)]

pub mod arch;
