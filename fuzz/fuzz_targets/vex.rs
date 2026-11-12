// SPDX-FileCopyrightText: 2026 amivuln contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! The OpenVEX, ignore-file and baseline parsers reject bad input without panicking.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = amivuln_core::parse_vex(data);
    let _ = amivuln_core::parse_baseline(data);
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = amivuln_core::parse_ignore(text);
    }
});
