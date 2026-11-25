// SPDX-FileCopyrightText: 2026 amivuln contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! The qualitative rating of a CVSS 3.0 or 3.1 vector, for advisories that
//! state a vector and no rating of their own. CVSS 4 is not read: its score
//! comes from a lookup table and no distribution relies on it alone.

/// `CRITICAL`, `HIGH`, `MEDIUM` or `LOW` for `vector`. `None` when it is not
/// a complete CVSS 3 base vector, or when it scores 0.0 (no impact), so that
/// nothing is claimed that the vector does not say.
pub(crate) fn rating(vector: &str) -> Option<&'static str> {
    let score = base_score(vector)?;
    Some(match score {
        s if s >= 9.0 => "CRITICAL",
        s if s >= 7.0 => "HIGH",
        s if s >= 4.0 => "MEDIUM",
        s if s > 0.0 => "LOW",
        _ => return None,
    })
}

/// The base score as the specification computes it (CVSS 3.1, section 7.1).
fn base_score(vector: &str) -> Option<f64> {
    let mut parts = vector.split('/');
    if !matches!(parts.next()?, "CVSS:3.0" | "CVSS:3.1") {
        return None;
    }
    let metrics: std::collections::BTreeMap<&str, &str> =
        parts.filter_map(|p| p.split_once(':')).collect();
    let get = |name: &str| metrics.get(name).copied();
    let changed = match get("S")? {
        "U" => false,
        "C" => true,
        _ => return None,
    };
    let attack_vector = match get("AV")? {
        "N" => 0.85,
        "A" => 0.62,
        "L" => 0.55,
        "P" => 0.2,
        _ => return None,
    };
    let complexity = match get("AC")? {
        "L" => 0.77,
        "H" => 0.44,
        _ => return None,
    };
    let privileges = match (get("PR")?, changed) {
        ("N", _) => 0.85,
        ("L", false) => 0.62,
        ("L", true) => 0.68,
        ("H", false) => 0.27,
        ("H", true) => 0.5,
        _ => return None,
    };
    let interaction = match get("UI")? {
        "N" => 0.85,
        "R" => 0.62,
        _ => return None,
    };
    let impact_of = |name: &str| match get(name)? {
        "H" => Some(0.56),
        "L" => Some(0.22),
        "N" => Some(0.0),
        _ => None,
    };
    let (c, i, a): (f64, f64, f64) = (impact_of("C")?, impact_of("I")?, impact_of("A")?);
    let loss = 1.0 - (1.0 - c) * (1.0 - i) * (1.0 - a);
    let impact = if changed {
        7.52 * (loss - 0.029) - 3.25 * (loss - 0.02).powi(15)
    } else {
        6.42 * loss
    };
    if impact <= 0.0 {
        return Some(0.0);
    }
    let exploitability = 8.22 * attack_vector * complexity * privileges * interaction;
    let scope = if changed { 1.08 } else { 1.0 };
    Some(round_up((scope * (impact + exploitability)).min(10.0)))
}

/// The specification's rounding: up to one decimal, ignoring float noise.
fn round_up(score: f64) -> f64 {
    let scaled = (score * 100_000.0).round();
    if scaled % 10_000.0 == 0.0 {
        scaled / 100_000.0
    } else {
        ((scaled / 10_000.0).floor() + 1.0) / 10.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scores_match_the_published_ones() {
        // Scores as NVD publishes them for these vectors.
        for (vector, score) in [
            ("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
            ("AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
            ("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5),
            ("AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8),
            ("AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
            ("AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L", 5.3),
            ("AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.6),
            ("AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
        ] {
            let got = base_score(&format!("CVSS:3.1/{vector}")).unwrap();
            assert!((got - score).abs() < 1e-9, "{vector}: {got} != {score}");
        }
    }

    #[test]
    fn an_incomplete_or_foreign_vector_has_no_rating() {
        for vector in [
            "",
            "CVSS:3.1/AV:N/AC:L",
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        ] {
            assert_eq!(rating(vector), None, "{vector}");
        }
    }
}
