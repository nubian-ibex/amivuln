// SPDX-FileCopyrightText: 2026 amivuln contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! The KEV, EPSS, Arch, Fedora and NVD feeds never panic the parsers.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = amivuln_sources::kev::Kev::parse(data);
    let _ = amivuln_sources::epss::EpssScores::parse(data);
    let _ = amivuln_sources::arch::ArchTracker::parse(data);
    let _ = amivuln_sources::fedora::Updateinfo::parse(data);
    let _ = amivuln_sources::nvd::parse_response(data, "nginx");
});
