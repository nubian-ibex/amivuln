// SPDX-FileCopyrightText: 2026 amivuln contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! The `--help` text in the language of the locale.
//!
//! English is the source and stays in the doc comments of [`crate::cli`]: a
//! catalog only replaces a text. A catalog is a `locales/help.<code>.txt` file
//! of `key = text` lines; the key is the command path and what the text
//! belongs to, `amivuln.db.pull/force` for the `--force` option of
//! `amivuln db pull`, and `amivuln/about` for the description of a command.
//! A key missing from a catalog leaves the English text, so a gap is visible
//! and never empty. clap's own error messages are not translated.

use std::collections::HashMap;

use amivuln_core::i18n::{Language, language, parse_catalog};
use clap::{Arg, Command};

/// The catalog of `language`, `None` for English, which needs none.
fn source(language: Language) -> Option<&'static str> {
    match language {
        Language::English => None,
        Language::Portuguese => Some(include_str!("../locales/help.pt.txt")),
    }
}

/// What the current language says, by key.
fn table() -> HashMap<String, String> {
    source(language())
        .map(|text| parse_catalog(text).into_iter().collect())
        .unwrap_or_default()
}

/// The text of `command` and of its options, each under its key.
fn entries(command: &Command, path: &str, out: &mut Vec<(String, String)>) {
    let mut add = |what: &str, text: Option<String>| {
        if let Some(text) = text {
            out.push((format!("{path}/{what}"), text));
        }
    };
    add("about", command.get_about().map(ToString::to_string));
    add(
        "long_about",
        command.get_long_about().map(ToString::to_string),
    );
    add(
        "after_help",
        command.get_after_help().map(ToString::to_string),
    );
    for arg in command.get_arguments() {
        add(
            arg.get_id().as_str(),
            arg.get_help().map(ToString::to_string),
        );
    }
    for sub in command.get_subcommands() {
        entries(sub, &format!("{path}.{}", sub.get_name()), out);
    }
}

/// Every key of the help of `command`, with its English text.
#[must_use]
pub fn english_entries(command: &Command) -> Vec<(String, String)> {
    let mut out = Vec::new();
    entries(command, command.get_name(), &mut out);
    out
}

/// The headings clap prints around the lists of arguments, options and
/// commands, and the word before the usage line.
fn headings(command: Command, table: &HashMap<String, String>) -> Command {
    let word = |key: &str, english: &str| {
        table
            .get(&format!("builtin/{key}"))
            .cloned()
            .unwrap_or_else(|| english.to_owned())
    };
    let (arguments, options) = (word("arguments", "Arguments"), word("options", "Options"));
    let usage = word("usage", "Usage:");
    let mut command = command
        .subcommand_help_heading(word("commands", "Commands"))
        .help_template(format!(
            "{{before-help}}{{about-with-newline}}\n{usage} {{usage}}\n\n{{all-args}}{{after-help}}"
        ));
    let ids: Vec<(String, bool)> = command
        .get_arguments()
        .map(|a| (a.get_id().to_string(), a.is_positional()))
        .collect();
    for (id, positional) in ids {
        let heading = if positional { &arguments } else { &options };
        command = command.mut_arg(id, |a: Arg| a.help_heading(heading.clone()));
    }
    command
}

/// `command` with its text replaced by what `table` says.
fn apply(command: Command, path: &str, table: &HashMap<String, String>) -> Command {
    let say = |what: &str| table.get(&format!("{path}/{what}")).cloned();
    let mut command = command;
    if let Some(text) = say("about") {
        command = command.about(text);
    }
    if let Some(text) = say("long_about") {
        command = command.long_about(text);
    }
    if let Some(text) = say("after_help") {
        command = command.after_help(text);
    }
    command = headings(command, table);
    let ids: Vec<String> = command
        .get_arguments()
        .map(|a| a.get_id().to_string())
        .collect();
    for id in ids {
        if let Some(text) = say(&id) {
            command = command.mut_arg(id, |a: Arg| a.help(text));
        }
    }
    let names: Vec<String> = command
        .get_subcommands()
        .map(|c| c.get_name().to_owned())
        .collect();
    for name in names {
        let sub_path = format!("{path}.{name}");
        command = command.mut_subcommand(name, |c| apply(c, &sub_path, table));
    }
    command
}

/// The built-in `-h`, `-V` and `help` entries clap adds when it builds a
/// command, translated in `command` and in every subcommand.
fn builtins(command: Command, table: &HashMap<String, String>) -> Command {
    let mut command = command;
    for (id, key) in [("help", "builtin/help"), ("version", "builtin/version")] {
        if let Some(text) = table.get(key)
            && command.get_arguments().any(|a| a.get_id() == id)
        {
            let heading = table.get("builtin/options").cloned();
            command = command.mut_arg(id, |a: Arg| {
                let a = a.help(text.clone());
                heading.map_or(a.clone(), |h| a.help_heading(h))
            });
        }
    }
    if let Some(text) = table.get("builtin/help_command")
        && command.get_subcommands().any(|c| c.get_name() == "help")
    {
        command = command.mut_subcommand("help", |c| c.about(text.clone()));
    }
    let names: Vec<String> = command
        .get_subcommands()
        .map(|c| c.get_name().to_owned())
        .collect();
    for name in names.into_iter().filter(|n| n != "help") {
        command = command.mut_subcommand(name, |c| builtins(c, table));
    }
    command
}

/// `command` with its help in the current language. English changes nothing.
#[must_use]
pub fn localize(command: Command) -> Command {
    let table = table();
    if table.is_empty() {
        return command;
    }
    let name = command.get_name().to_owned();
    let mut command = apply(command, &name, &table);
    command.build();
    builtins(command, &table)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use clap::CommandFactory;

    use super::*;
    use crate::cli::Cli;

    fn catalog(language: Language) -> Vec<(String, String)> {
        source(language).map(parse_catalog).unwrap_or_default()
    }

    #[test]
    fn a_catalog_has_no_key_the_help_does_not_have() {
        let known: BTreeSet<String> = english_entries(&Cli::command())
            .into_iter()
            .map(|(k, _)| k)
            .chain(
                [
                    "help",
                    "version",
                    "help_command",
                    "usage",
                    "commands",
                    "options",
                    "arguments",
                ]
                .into_iter()
                .map(|k| format!("builtin/{k}")),
            )
            .collect();
        for language in Language::ALL {
            for (key, _) in catalog(language) {
                assert!(known.contains(&key), "{} has {key}", language.code());
            }
        }
    }

    #[test]
    fn every_help_text_is_translated() {
        for language in Language::ALL {
            let translated: BTreeSet<String> =
                catalog(language).into_iter().map(|(k, _)| k).collect();
            if translated.is_empty() {
                continue;
            }
            for (key, _) in english_entries(&Cli::command()) {
                assert!(translated.contains(&key), "{} lacks {key}", language.code());
            }
        }
    }

    #[test]
    fn a_translation_keeps_every_option_name() {
        let english: HashMap<String, String> =
            english_entries(&Cli::command()).into_iter().collect();
        for (key, text) in catalog(Language::Portuguese) {
            if let Some(source) = english.get(&key) {
                assert!(!text.trim().is_empty(), "{key} is empty");
                // Examples and exit codes keep their commands: every word that
                // starts with `--` or `amivuln` in English is still there.
                for word in source.split_whitespace().filter(|w| w.starts_with("--")) {
                    let word = word.trim_matches(|c: char| !c.is_alphanumeric() && c != '-');
                    assert!(text.contains(word), "{key} lost {word}");
                }
            }
        }
    }
}
