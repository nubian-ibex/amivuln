// SPDX-FileCopyrightText: 2026 amivuln contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Data sources: parsers, an HTTP client and cache-aware fetching.
//!
//! Parsers take bytes so they can be tested with recorded fixtures and
//! fuzzed. [`http`] performs bounded, conditional requests and [`fetch`]
//! combines it with the cache so every answer carries a source status.

#![forbid(unsafe_code)]

pub mod arch;
pub mod fedora;
pub mod fetch;
pub mod http;
