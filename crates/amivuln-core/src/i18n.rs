// SPDX-FileCopyrightText: 2026 amivuln contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Message catalogs: the text a person reads is kept apart from the code.
//!
//! A catalog is a `locales/<code>.txt` file of `key = text` lines. `#` starts a
//! comment, `{name}` is a placeholder and `\n` a line break. English is the
//! source: a key missing from another language falls back to it, and a key
//! missing everywhere shows as the key itself, so a gap is visible and never
//! empty. Only text meant for people goes through here; the JSON, SARIF, CSV,
//! `CycloneDX`, `OpenVEX` and Prometheus output stays English because it is a
//! contract with other programs.

use std::collections::HashMap;
use std::fmt::Display;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU8, Ordering};

/// A language the messages exist in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Language {
    /// English, the source of every message.
    English,
    /// Brazilian Portuguese.
    Portuguese,
}

impl Language {
    /// Every language, English first.
    pub const ALL: [Self; 2] = [Self::English, Self::Portuguese];

    /// The language code of the catalog file.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Self::English => "en",
            Self::Portuguese => "pt",
        }
    }

    fn source(self) -> &'static str {
        match self {
            Self::English => include_str!("../locales/en.txt"),
            Self::Portuguese => include_str!("../locales/pt.txt"),
        }
    }

    /// The language a locale name such as `pt_BR.UTF-8` asks for. `C`,
    /// `POSIX` and anything unknown are English.
    #[must_use]
    pub fn from_locale(name: &str) -> Self {
        let code: String = name
            .chars()
            .take_while(char::is_ascii_alphabetic)
            .collect::<String>()
            .to_ascii_lowercase();
        Self::ALL
            .into_iter()
            .find(|l| l.code() == code)
            .unwrap_or(Self::English)
    }

    /// The language of the environment: the first of `LC_ALL`, `LC_MESSAGES`
    /// and `LANG` that is set and not empty, as the C library does.
    #[must_use]
    pub fn from_env(var: impl Fn(&str) -> Option<String>) -> Self {
        ["LC_ALL", "LC_MESSAGES", "LANG"]
            .into_iter()
            .find_map(|name| var(name).filter(|v| !v.is_empty()))
            .map_or(Self::English, |v| Self::from_locale(v.as_str()))
    }

    fn index(self) -> u8 {
        match self {
            Self::English => 0,
            Self::Portuguese => 1,
        }
    }
}

static CURRENT: AtomicU8 = AtomicU8::new(0);

/// Chooses the language of every message from now on.
pub fn set_language(language: Language) {
    CURRENT.store(language.index(), Ordering::Relaxed);
}

/// The language messages are produced in.
#[must_use]
pub fn language() -> Language {
    Language::ALL
        .into_iter()
        .find(|l| l.index() == CURRENT.load(Ordering::Relaxed))
        .unwrap_or(Language::English)
}

/// The lines of a catalog as `(key, text)`, escapes resolved.
#[must_use]
pub fn parse_catalog(source: &str) -> Vec<(String, String)> {
    source
        .lines()
        .filter_map(|line| {
            let line = line.trim_end();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            let (key, text) = line.split_once(" = ")?;
            Some((key.trim().to_owned(), text.replace("\\n", "\n")))
        })
        .collect()
}

fn catalog(language: Language) -> &'static HashMap<String, String> {
    static ENGLISH: OnceLock<HashMap<String, String>> = OnceLock::new();
    static PORTUGUESE: OnceLock<HashMap<String, String>> = OnceLock::new();
    let cell = match language {
        Language::English => &ENGLISH,
        Language::Portuguese => &PORTUGUESE,
    };
    cell.get_or_init(|| parse_catalog(language.source()).into_iter().collect())
}

/// The message for `key` in the current language, English when it is missing
/// there, and `key` itself when it is missing everywhere.
#[must_use]
pub fn tr(key: &str) -> String {
    catalog(language())
        .get(key)
        .or_else(|| catalog(Language::English).get(key))
        .cloned()
        .unwrap_or_else(|| key.to_owned())
}

/// Like [`tr`], with each `{name}` replaced by its value.
#[must_use]
pub fn tr_args(key: &str, args: &[(&str, &dyn Display)]) -> String {
    let mut text = tr(key);
    for (name, value) in args {
        text = text.replace(&format!("{{{name}}}"), &value.to_string());
    }
    text
}

/// The `{placeholders}` of a message, sorted.
#[must_use]
pub fn placeholders(text: &str) -> Vec<String> {
    let mut found: Vec<String> = text
        .split('{')
        .skip(1)
        .filter_map(|rest| rest.split_once('}').map(|(name, _)| name.to_owned()))
        .collect();
    found.sort();
    found.dedup();
    found
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::{Path, PathBuf};

    use super::*;

    fn map(language: Language) -> BTreeMap<String, String> {
        parse_catalog(language.source()).into_iter().collect()
    }

    /// Every `*.rs` file of the workspace crates, tests included.
    fn sources(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                sources(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }

    /// The keys the code asks for: the first string literal after `tr(` or
    /// `tr_args(`.
    fn used_keys() -> BTreeMap<String, PathBuf> {
        let crates = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let mut files = Vec::new();
        sources(&crates, &mut files);
        let mut keys = BTreeMap::new();
        for file in files {
            if file.ends_with("i18n.rs") {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(&file) else {
                continue;
            };
            for marker in ["tr(\"", "tr_args(\"", "tr_args(\n"] {
                for part in text.split(marker).skip(1) {
                    let key = if marker.ends_with('\n') {
                        part.trim_start().strip_prefix('"').unwrap_or("")
                    } else {
                        part
                    };
                    if let Some((key, _)) = key.split_once('"')
                        && key.contains('.')
                        && !key.contains(' ')
                    {
                        keys.insert(key.to_owned(), file.clone());
                    }
                }
            }
        }
        keys
    }

    #[test]
    fn every_key_the_code_asks_for_has_an_english_message() {
        let english = map(Language::English);
        let used = used_keys();
        assert!(used.len() > 30, "the scan found only {} keys", used.len());
        for (key, file) in &used {
            assert!(
                english.contains_key(key),
                "{key} (in {}) has no message",
                file.display()
            );
        }
    }

    #[test]
    fn no_english_message_is_unused() {
        let used = used_keys();
        for key in map(Language::English).keys() {
            assert!(
                used.contains_key(key),
                "{key} is in en.txt and used nowhere"
            );
        }
    }

    #[test]
    fn a_translation_adds_no_key_and_keeps_every_placeholder() {
        let english = map(Language::English);
        for language in Language::ALL {
            for (key, text) in map(language) {
                let source = english.get(&key);
                assert!(
                    source.is_some(),
                    "{} has {key}, English does not",
                    language.code()
                );
                assert_eq!(
                    placeholders(&text),
                    source.map(|s| placeholders(s)).unwrap_or_default(),
                    "{} {key}",
                    language.code()
                );
            }
        }
    }

    #[test]
    fn locale_names_pick_a_language() {
        for (name, want) in [
            ("pt_BR.UTF-8", Language::Portuguese),
            ("pt", Language::Portuguese),
            ("PT_br", Language::Portuguese),
            ("en_US.UTF-8", Language::English),
            ("C", Language::English),
            ("POSIX", Language::English),
            ("tlh", Language::English),
            ("", Language::English),
        ] {
            assert_eq!(Language::from_locale(name), want, "{name:?}");
        }
        let env = |pairs: &'static [(&'static str, &'static str)]| {
            Language::from_env(|n| {
                pairs
                    .iter()
                    .find(|(k, _)| *k == n)
                    .map(|(_, v)| (*v).to_owned())
            })
        };
        // LC_ALL wins, and an empty value does not count as set.
        assert_eq!(
            env(&[("LANG", "pt_BR"), ("LC_ALL", "C")]),
            Language::English
        );
        assert_eq!(
            env(&[("LANG", "pt_BR"), ("LC_ALL", "")]),
            Language::Portuguese
        );
        assert_eq!(env(&[]), Language::English);
    }

    #[test]
    fn a_missing_key_shows_as_itself_and_arguments_are_filled() {
        assert_eq!(tr("no.such.key"), "no.such.key");
        assert_eq!(
            tr_args("restart.inspected", &[("n", &3)]),
            "inspected 3 processes"
        );
        assert_eq!(
            parse_catalog("# c\n\na.b = x\\ny\n")[0],
            ("a.b".to_owned(), "x\ny".to_owned())
        );
    }
}
