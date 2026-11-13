// SPDX-FileCopyrightText: 2026 amivuln contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! `amivuln tui`: interactive terminal UI (feature `tui`).
//!
//! Without the `tui` feature the command exits 64 with a message that names
//! the feature, so the binary stays small with the default feature set.

#[cfg(not(feature = "tui"))]
/// Reports that the `tui` feature is not compiled in.
pub fn run(_env: &crate::app::Env, err: &mut dyn std::io::Write) -> amivuln_core::ExitCode {
    let _ = writeln!(
        err,
        "error: the tui command needs the `tui` feature: cargo install amivuln --features tui"
    );
    amivuln_core::ExitCode::Usage
}

/// Runs the TUI: scans the host, renders the report, handles keys.
#[cfg(feature = "tui")]
pub fn run(env: &crate::app::Env, err: &mut dyn std::io::Write) -> amivuln_core::ExitCode {
    let Ok(cli) = <crate::cli::Cli as clap::Parser>::try_parse_from(vec!["amivuln", "--all"])
    else {
        return amivuln_core::ExitCode::Usage;
    };
    let (s, _) = match crate::app::settings(&cli.global, env) {
        Ok(v) => v,
        Err(m) => {
            let _ = writeln!(err, "error: {m}");
            return amivuln_core::ExitCode::Usage;
        }
    };
    let Ok(eco) = crate::app::host_ecosystem(&cli.global, env) else {
        return amivuln_core::ExitCode::Usage;
    };
    let targets = crate::scan::expand_targets(&cli, &[]);
    let Ok((resolved, unresolved)) = crate::scan::resolve_scope(
        &cli,
        &targets,
        true,
        eco,
        s.config.general.exec_version_probe,
    ) else {
        return amivuln_core::ExitCode::Usage;
    };
    let ev = match crate::scan::evaluate(&cli, &s, env, eco, &resolved, &[], err) {
        Ok(v) => v,
        Err(code) => return code,
    };
    let all_findings: Vec<amivuln_core::Finding> =
        ev.targets.iter().flat_map(|t| t.findings.clone()).collect();
    let suppressed = amivuln_core::suppress(&all_findings, &s.ignores, &crate::app::today(env));
    let report = amivuln_core::RunReport {
        tool_version: env!("CARGO_PKG_VERSION").to_owned(),
        generated_at: jiff::Timestamp::from_second(env.now)
            .map_or_else(|_| "1970-01-01T00:00:00Z".to_owned(), |t| t.to_string()),
        host: crate::app::host_meta(eco),
        complete: amivuln_core::is_complete(&ev.sources),
        suppressed,
        sources: ev.sources,
        targets: ev.targets,
        unresolved,
    };
    terminal::run(report, err)
}

#[cfg(feature = "tui")]
mod terminal {
    use amivuln_core::{ExitCode, RunReport, Severity, Verdict};
    use crossterm::event::{self, Event, KeyCode, KeyEventKind};
    use ratatui::prelude::*;
    use ratatui::widgets::{Block, Borders, Paragraph, Row, Table, Wrap};

    struct App {
        report: RunReport,
        selected: usize,
        kev_only: bool,
        high_only: bool,
    }

    impl App {
        fn visible(&self) -> Vec<&amivuln_core::TargetReport> {
            self.report
                .targets
                .iter()
                .filter(|t| {
                    let has_kev = t.findings.iter().any(|f| f.kev.is_some());
                    let has_high = t.findings.iter().any(|f| f.severity >= Severity::High);
                    (!self.kev_only || has_kev) && (!self.high_only || has_high)
                })
                .collect()
        }

        fn findings_of(&self) -> Vec<&amivuln_core::Finding> {
            self.visible()
                .get(self.selected)
                .map(|t| t.findings.iter().collect())
                .unwrap_or_default()
        }

        fn total(&self) -> usize {
            self.visible().len()
        }

        /// Keeps the selection inside the list after a filter shrank it.
        fn clamp(&mut self) {
            self.selected = self.selected.min(self.total().saturating_sub(1));
        }

        /// Applies one key press; true means quit.
        fn handle_key(&mut self, code: KeyCode) -> bool {
            match code {
                KeyCode::Char('q') | KeyCode::Esc => return true,
                KeyCode::Down | KeyCode::Char('j') => {
                    self.selected = self.selected.saturating_add(1);
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    self.selected = self.selected.saturating_sub(1);
                }
                KeyCode::Char('K') => self.kev_only = !self.kev_only,
                KeyCode::Char('H') => self.high_only = !self.high_only,
                _ => {}
            }
            self.clamp();
            false
        }
    }

    /// Runs the TUI loop: renders, polls keys, quits on `q` or `Esc`.
    pub(super) fn run(report: RunReport, err: &mut dyn std::io::Write) -> ExitCode {
        let mut stdout = std::io::stdout();
        let backend = ratatui::backend::CrosstermBackend::new(&mut stdout);
        let Ok(mut terminal) = ratatui::Terminal::new(backend) else {
            let _ = writeln!(err, "error: cannot initialise the terminal");
            return ExitCode::Internal;
        };
        let _ = crossterm::terminal::enable_raw_mode();
        let _ = crossterm::execute!(std::io::stdout(), crossterm::terminal::EnterAlternateScreen);

        let mut app = App {
            report,
            selected: 0,
            kev_only: false,
            high_only: false,
        };

        loop {
            let _ = terminal.draw(|f| draw(f, &app));
            if !event::poll(std::time::Duration::from_millis(200)).unwrap_or(false) {
                continue;
            }
            let Ok(Event::Key(key)) = event::read() else {
                continue;
            };
            if key.kind != KeyEventKind::Press {
                continue;
            }
            if app.handle_key(key.code) {
                break;
            }
        }

        let _ = crossterm::execute!(std::io::stdout(), crossterm::terminal::LeaveAlternateScreen);
        let _ = crossterm::terminal::disable_raw_mode();
        ExitCode::Success
    }

    fn draw(f: &mut Frame<'_>, app: &App) {
        let targets = app.visible();

        let chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Percentage(30),
                Constraint::Percentage(35),
                Constraint::Percentage(35),
            ])
            .split(f.area());

        let filter = match (app.kev_only, app.high_only) {
            (true, false) => " KEV only",
            (false, true) => " HIGH only",
            (true, true) => " KEV+HIGH",
            _ => "",
        };

        let rows: Vec<Row<'_>> = targets
            .iter()
            .enumerate()
            .map(|(i, t)| {
                let max_sev = t
                    .findings
                    .iter()
                    .map(|f| f.severity)
                    .max()
                    .unwrap_or(Severity::Unknown);
                Row::new(vec![
                    Span::styled(
                        t.input.clone(),
                        if i == app.selected {
                            Style::default().bold()
                        } else {
                            Style::default()
                        },
                    ),
                    Span::raw(t.findings.len().to_string()),
                    Span::styled(
                        format!("{max_sev:?}"),
                        Style::default().fg(severity_color(max_sev)),
                    ),
                ])
            })
            .collect();

        let mut table_state =
            ratatui::widgets::TableState::default().with_selected(if app.total() > 0 {
                Some(app.selected)
            } else {
                None
            });
        let target_table = Table::new(
            rows,
            [
                Constraint::Percentage(55),
                Constraint::Percentage(20),
                Constraint::Percentage(25),
            ],
        )
        .header(Row::new(["Target", "Findings", "Max severity"]).bold())
        .block(Block::default().borders(Borders::ALL).title(format!(
            "Targets{filter} (up/down or j/k, K: KEV, H: HIGH, q: quit)"
        )))
        .highlight_symbol("> ");
        f.render_stateful_widget(
            target_table,
            chunks.first().copied().unwrap_or_default(),
            &mut table_state,
        );

        f.render_widget(
            finding_table(app),
            chunks.get(1).copied().unwrap_or_default(),
        );
        f.render_widget(
            detail_paragraph(app),
            chunks.get(2).copied().unwrap_or_default(),
        );
    }

    fn finding_table(app: &App) -> Table<'_> {
        let rows: Vec<Row<'_>> = app
            .findings_of()
            .iter()
            .map(|fd| {
                let (state, fix) = match &fd.verdict {
                    Verdict::Affected { fixed_in } => (
                        "affected",
                        fixed_in
                            .as_ref()
                            .map_or_else(String::new, ToString::to_string),
                    ),
                    Verdict::Patched => ("patched", String::new()),
                    Verdict::Unverified => ("unverified", String::new()),
                    Verdict::NotAffected(_) => ("not affected", String::new()),
                };
                Row::new(vec![
                    Span::raw(fd.id.clone()),
                    Span::styled(
                        format!("{:?}", fd.severity),
                        Style::default().fg(severity_color(fd.severity)),
                    ),
                    Span::raw(state),
                    Span::raw(fix),
                ])
            })
            .collect();
        Table::new(
            rows,
            [
                Constraint::Percentage(35),
                Constraint::Percentage(20),
                Constraint::Percentage(20),
                Constraint::Percentage(25),
            ],
        )
        .header(Row::new(["CVE", "Severity", "State", "Fix"]).bold())
        .block(Block::default().borders(Borders::ALL).title("Findings"))
    }

    fn detail_paragraph(app: &App) -> Paragraph<'_> {
        let lines: Vec<Line<'_>> = app
            .findings_of()
            .iter()
            .flat_map(|fd| {
                let mut lines = vec![
                    Line::styled(fd.id.clone(), Style::default().bold()),
                    Line::raw(format!("severity: {:?}", fd.severity)),
                ];
                if let Some(kev) = &fd.kev {
                    lines.push(Line::raw(format!(
                        "KEV: added {}, ransomware: {}",
                        kev.added, kev.ransomware
                    )));
                }
                if let Some(epss) = &fd.epss {
                    lines.push(Line::raw(format!("EPSS: {:.3}", epss.score)));
                }
                if let Verdict::Affected { fixed_in } = &fd.verdict {
                    lines.push(Line::raw(format!(
                        "fixed in: {}",
                        fixed_in
                            .as_ref()
                            .map_or_else(|| "no fix published".to_owned(), ToString::to_string)
                    )));
                }
                lines.push(Line::raw(""));
                lines
            })
            .collect();
        Paragraph::new(lines)
            .block(Block::default().borders(Borders::ALL).title("Detail"))
            .wrap(Wrap { trim: true })
    }

    fn severity_color(sev: Severity) -> Color {
        match sev {
            Severity::Critical => Color::Red,
            Severity::High => Color::LightRed,
            Severity::Medium => Color::Yellow,
            Severity::Low => Color::Blue,
            Severity::Unknown => Color::DarkGray,
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use amivuln_core::{
            Ecosystem, EpssInfo, Finding, HostMeta, KevInfo, TargetReport, Verdict,
        };
        use ratatui::backend::TestBackend;

        fn target(name: &str, findings: Vec<Finding>) -> TargetReport {
            let package =
                amivuln_resolve::from_name_version(Ecosystem::Fedora(44), name, "1.0-1.fc44")
                    .unwrap();
            TargetReport {
                input: name.to_owned(),
                package,
                findings,
                resolved: Vec::new(),
            }
        }

        fn affected(id: &str, severity: Severity) -> Finding {
            Finding::new(id, severity, Verdict::Affected { fixed_in: None })
        }

        fn app() -> App {
            let mut kev = affected("CVE-2024-0002", Severity::Medium);
            kev.kev = Some(KevInfo {
                added: "2024-05-01".to_owned(),
                ransomware: false,
            });
            kev.epss = Some(EpssInfo {
                score: 0.5,
                percentile: 0.9,
                date: "2024-05-02".to_owned(),
            });
            App {
                report: RunReport {
                    tool_version: "0".to_owned(),
                    generated_at: "1970-01-01T00:00:00Z".to_owned(),
                    host: HostMeta {
                        os_id: "fedora".to_owned(),
                        os_version: "44".to_owned(),
                        arch: "x86_64".to_owned(),
                    },
                    complete: true,
                    sources: Vec::new(),
                    targets: vec![
                        target("alpha", vec![affected("CVE-2024-0001", Severity::High)]),
                        target("bravo", vec![kev]),
                        target("charlie", vec![affected("CVE-2024-0003", Severity::Low)]),
                    ],
                    suppressed: std::collections::BTreeMap::new(),
                    unresolved: Vec::new(),
                },
                selected: 0,
                kev_only: false,
                high_only: false,
            }
        }

        fn screen(app: &App) -> String {
            let mut terminal = Terminal::new(TestBackend::new(140, 12)).unwrap();
            terminal.draw(|f| draw(f, app)).unwrap();
            let buf = terminal.backend().buffer().clone();
            buf.content()
                .iter()
                .map(ratatui::buffer::Cell::symbol)
                .collect::<String>()
        }

        #[test]
        fn selection_stays_inside_the_list() {
            let mut a = app();
            for _ in 0..10 {
                a.handle_key(KeyCode::Down);
            }
            assert_eq!(a.selected, 2);
            for _ in 0..10 {
                a.handle_key(KeyCode::Char('k'));
            }
            assert_eq!(a.selected, 0);
        }

        #[test]
        fn quit_keys_end_the_loop() {
            assert!(app().handle_key(KeyCode::Char('q')));
            assert!(app().handle_key(KeyCode::Esc));
            assert!(!app().handle_key(KeyCode::Char('x')));
        }

        #[test]
        fn filters_narrow_the_targets_and_clamp_the_selection() {
            let mut a = app();
            a.selected = 2;
            a.handle_key(KeyCode::Char('K'));
            assert_eq!(a.total(), 1);
            assert_eq!(a.selected, 0, "selection must follow the shrunken list");
            a.handle_key(KeyCode::Char('K'));
            a.handle_key(KeyCode::Char('H'));
            assert_eq!(a.total(), 1);
            a.handle_key(KeyCode::Char('K'));
            assert_eq!(a.total(), 0);
            assert_eq!(a.selected, 0);
            // An empty list must not panic when drawn.
            let _ = screen(&a);
        }

        #[test]
        fn the_screen_shows_targets_findings_and_detail() {
            let mut a = app();
            let text = screen(&a);
            assert!(text.contains("alpha") && text.contains("charlie"));
            assert!(text.contains("CVE-2024-0001"));
            assert!(!text.contains("CVE-2024-0003"), "only the selected target");
            a.handle_key(KeyCode::Down);
            let text = screen(&a);
            assert!(text.contains("CVE-2024-0002"));
            assert!(text.contains("KEV: added 2024-05-01"));
            assert!(text.contains("EPSS: 0.500"));
        }
    }
}
