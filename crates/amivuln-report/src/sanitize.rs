// SPDX-FileCopyrightText: 2026 amivuln contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Neutralising text that came from outside the process.

/// Replaces control characters (including ESC, so ANSI and OSC sequences
/// cannot act) with U+FFFD. Newlines and tabs become spaces so one value stays
/// on one line.
#[must_use]
pub fn sanitize_terminal(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '\n' | '\r' | '\t' => ' ',
            c if c.is_control() => '\u{FFFD}',
            c => c,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_and_controls_are_neutralised() {
        assert_eq!(
            sanitize_terminal("a\u{1b}[31mred\u{1b}[0m"),
            "a\u{FFFD}[31mred\u{FFFD}[0m"
        );
        assert_eq!(
            sanitize_terminal("x\u{1b}]8;;http://evil\u{7}y"),
            "x\u{FFFD}]8;;http://evil\u{FFFD}y"
        );
        assert_eq!(sanitize_terminal("line1\nline2\tend\r"), "line1 line2 end ");
        assert_eq!(sanitize_terminal("\u{85}\u{9b}"), "\u{FFFD}\u{FFFD}");
    }

    #[test]
    fn ordinary_text_is_untouched() {
        assert_eq!(
            sanitize_terminal("nginx-1:1.26.2-1.fc41 ✓ ação"),
            "nginx-1:1.26.2-1.fc41 ✓ ação"
        );
    }
}
