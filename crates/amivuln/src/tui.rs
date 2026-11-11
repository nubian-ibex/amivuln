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
            match key.code {
                KeyCode::Char('q') | KeyCode::Esc => break,
                KeyCode::Down | KeyCode::Char('j') => {
                    if app.total() > 0 {
                        app.selected = (app.selected + 1).min(app.total() - 1);
                    }
                }
                KeyCode::Up => {
                    app.selected = app.selected.saturating_sub(1);
                }
                KeyCode::Char('K') => app.kev_only = !app.kev_only,
                KeyCode::Char('H') => app.high_only = !app.high_only,
                _ => {}
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
            "Targets{filter} (up/down, K: KEV, H: HIGH, q: quit)"
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
}
