// SPDX-FileCopyrightText: 2026 amivuln contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! OSV responses are untrusted network input and never panic the parser.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = amivuln_sources::osv::parse_batch(data);
    let _ = amivuln_sources::osv::OsvData::parse_advisory(data, "Debian:12");
});
