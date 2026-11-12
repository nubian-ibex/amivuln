// SPDX-FileCopyrightText: 2026 amivuln contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! The version comparators never panic and stay antisymmetric.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else { return };
    let (a, b) = text.split_once('\n').unwrap_or((text, text));
    for cmp in [
        amivuln_version::rpmvercmp,
        amivuln_version::debvercmp,
        amivuln_version::alpm_vercmp,
    ] {
        assert_eq!(cmp(a, b), cmp(b, a).reverse());
    }
    let _ = amivuln_version::SemverVersion::parse(a);
});
