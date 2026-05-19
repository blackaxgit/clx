use ratatui::prelude::*;
use ratatui::widgets::{
    Block, Cell, Paragraph, Row, Scrollbar, ScrollbarOrientation, ScrollbarState, Table, Wrap,
};

use crate::dashboard::app::App;
use crate::dashboard::data::AuditRow;

const AUDIT_COLUMNS: [&str; 6] = ["Time", "Decision", "Risk", "Layer", "Command", "Session"];

pub fn render(frame: &mut Frame, app: &mut App, area: Rect) {
    let filter = app.filter_text.to_lowercase();
    let mut filtered: Vec<_> = app
        .data
        .audit_entries
        .iter()
        .filter(|e| {
            filter.is_empty()
                || e.command.to_lowercase().contains(&filter)
                || e.decision.to_lowercase().contains(&filter)
                || e.layer.to_lowercase().contains(&filter)
                || e.session_short_id.to_lowercase().contains(&filter)
                || e.time.to_lowercase().contains(&filter)
        })
        .collect();

    filtered.sort_by(|a, b| {
        let ordering = match app.audit_sort_column {
            0 => a.time.cmp(&b.time),
            1 => a.decision.cmp(&b.decision),
            2 => {
                let a_risk = a.risk_score.unwrap_or(-1);
                let b_risk = b.risk_score.unwrap_or(-1);
                a_risk.cmp(&b_risk)
            }
            3 => a.layer.cmp(&b.layer),
            4 => a.command.cmp(&b.command),
            5 => a.session_short_id.cmp(&b.session_short_id),
            _ => std::cmp::Ordering::Equal,
        };
        if app.audit_sort_ascending {
            ordering
        } else {
            ordering.reverse()
        }
    });

    let count = filtered.len();

    // Split into table area (top) and detail pane (bottom)
    let chunks = Layout::vertical([Constraint::Min(10), Constraint::Percentage(30)]).split(area);

    let header_cells: Vec<Cell> = AUDIT_COLUMNS
        .iter()
        .enumerate()
        .map(|(i, name)| {
            if i == app.audit_sort_column {
                let arrow = if app.audit_sort_ascending {
                    " \u{25b2}"
                } else {
                    " \u{25bc}"
                };
                Cell::from(format!("{name}{arrow}"))
            } else {
                Cell::from(*name)
            }
        })
        .collect();
    let header = Row::new(header_cells)
        .style(Style::default().bold())
        .bottom_margin(1);

    let rows: Vec<Row> = if filtered.is_empty() {
        vec![Row::new(vec![Cell::from(Span::styled(
            "No audit entries found",
            Style::default().fg(Color::DarkGray).italic(),
        ))])]
    } else {
        filtered
            .iter()
            .map(|e| {
                let decision_style = match e.decision.as_str() {
                    "allowed" => Style::default().fg(Color::Green),
                    "blocked" => Style::default().fg(Color::Red),
                    "prompted" => Style::default().fg(Color::Yellow),
                    _ => Style::default().fg(Color::White),
                };

                let risk_display = match e.risk_score {
                    Some(score) => score.to_string(),
                    None => "-".to_string(),
                };

                Row::new(vec![
                    Cell::from(e.time.as_str()),
                    Cell::from(e.decision.as_str()).style(decision_style),
                    Cell::from(risk_display),
                    Cell::from(e.layer.as_str()),
                    Cell::from(e.command_short.as_str()),
                    Cell::from(e.session_short_id.as_str()),
                ])
            })
            .collect()
    };

    let widths = [
        Constraint::Length(11),
        Constraint::Length(12),
        Constraint::Length(8),
        Constraint::Length(10),
        Constraint::Fill(1),
        Constraint::Length(12),
    ];

    let title = if app.filter_text.is_empty() {
        format!(" Audit Log ({count}) ")
    } else {
        format!(" Audit Log ({}) [filter: {}] ", count, app.filter_text)
    };
    let table = Table::new(rows, widths)
        .header(header)
        .block(Block::bordered().title(title))
        .row_highlight_style(Style::default().bg(Color::DarkGray));

    frame.render_stateful_widget(table, chunks[0], &mut app.audit_table_state);

    // Scrollbar
    let total_rows = filtered.len();
    let selected = app.audit_table_state.selected().unwrap_or(0);
    let mut scrollbar_state = ScrollbarState::new(total_rows).position(selected);
    let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
        .begin_symbol(Some("\u{2191}"))
        .end_symbol(Some("\u{2193}"));
    frame.render_stateful_widget(scrollbar, chunks[0], &mut scrollbar_state);

    // Always-visible detail pane at bottom
    render_detail_pane(frame, &filtered, app, chunks[1]);
}

fn render_detail_pane(frame: &mut Frame, filtered: &[&AuditRow], app: &App, area: Rect) {
    let selected = app.audit_table_state.selected();

    let text = match selected.and_then(|i| filtered.get(i)) {
        Some(entry) => {
            let decision_style = match entry.decision.as_str() {
                "allowed" => Style::default().fg(Color::Green),
                "blocked" => Style::default().fg(Color::Red),
                "prompted" => Style::default().fg(Color::Yellow),
                _ => Style::default().fg(Color::White),
            };

            let risk_display: String = entry
                .risk_score
                .map_or_else(|| "-".into(), |r| r.to_string());

            let header_line = Line::from(vec![
                Span::styled("Time: ", Style::default().fg(Color::DarkGray)),
                Span::from(entry.time.clone()),
                Span::raw("  "),
                Span::styled("Decision: ", Style::default().fg(Color::DarkGray)),
                Span::styled(entry.decision.clone(), decision_style),
                Span::raw("  "),
                Span::styled("Risk: ", Style::default().fg(Color::DarkGray)),
                Span::from(risk_display),
            ]);
            let meta_line = Line::from(vec![
                Span::styled("Layer: ", Style::default().fg(Color::DarkGray)),
                Span::from(entry.layer.clone()),
                Span::raw("  "),
                Span::styled("Session: ", Style::default().fg(Color::DarkGray)),
                Span::from(entry.session_short_id.clone()),
            ]);

            vec![
                header_line,
                meta_line,
                Line::from(""),
                Line::from(vec![Span::styled(
                    "Command: ",
                    Style::default().fg(Color::Cyan).bold(),
                )]),
                Line::from(Span::from(entry.command.clone())),
            ]
        }
        None => {
            vec![Line::from(Span::styled(
                "Select a row to view details",
                Style::default().fg(Color::DarkGray).italic(),
            ))]
        }
    };

    let block = Block::bordered().title(" Detail ");
    let paragraph = Paragraph::new(text).block(block).wrap(Wrap { trim: false });
    frame.render_widget(paragraph, area);
}

// ── H2: TestBackend + insta snapshots for the Audit tab ─────────────────────
//
// These pin the rendered output of `audit::render` (and its private
// `render_detail_pane`) against deterministic AppState fixtures. They cover
// the previously-unrendered branches: every sort column / direction, the
// case-insensitive filter closure, the decision-color match arms
// (blocked/prompted/other), the missing-risk "-" arm, and the populated
// detail pane reached by selecting a row.
//
// Hermetic: TestBackend only — no terminal, no DB, no network, no clock.
// The audit table never embeds the config path or HOME, so no redaction is
// required (every row value is supplied by the fixture).
#[cfg(test)]
mod render_snapshots {
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    use crate::dashboard::app::{App, DashboardTab};
    use crate::dashboard::data::AuditRow;

    const COLS: u16 = 100;
    const ROWS: u16 = 30;

    fn render_audit_to_string(app: &mut App) -> String {
        let backend = TestBackend::new(COLS, ROWS);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| {
                let area = frame.area();
                super::render(frame, app, area);
            })
            .unwrap();
        let buffer = terminal.backend().buffer().clone();
        (0..ROWS)
            .map(|y| {
                let row: String = (0..COLS)
                    .map(|x| buffer.cell((x, y)).unwrap().symbol().to_string())
                    .collect();
                row.trim_end().to_string()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn row(time: &str, decision: &str, layer: &str, cmd: &str, risk: Option<i32>) -> AuditRow {
        AuditRow {
            time: time.to_string(),
            decision: decision.to_string(),
            layer: layer.to_string(),
            command: cmd.to_string(),
            command_short: cmd.to_string(),
            risk_score: risk,
            session_short_id: "sess0001".to_string(),
        }
    }

    fn app_with_mixed_rows() -> App {
        let mut app = App::new(7, 5);
        app.current_tab = DashboardTab::AuditLog;
        // Distinct decisions to exercise every color arm; one missing risk
        // to exercise the "-" arm; deliberately unsorted to make the
        // comparator output observable.
        app.data.audit_entries = vec![
            row("09:00:03", "blocked", "layer1", "rm -rf /tmp/x", Some(95)),
            row("09:00:01", "allowed", "builtin", "ls -la", Some(5)),
            row("09:00:02", "prompted", "layer2", "git push --force", None),
            row(
                "09:00:04",
                "deferred",
                "builtin",
                "cat /etc/hosts",
                Some(20),
            ),
        ];
        app.data.total_commands = 4;
        app
    }

    /// Default sort (column 0 = Time, *descending* — `App::new` defaults
    /// `audit_sort_ascending = false`): rows ordered 04→01, all decision
    /// colors present, the `None` risk renders as "-", header arrow ▼.
    #[test]
    fn snapshot_audit_time_desc_all_decisions() {
        let mut app = app_with_mixed_rows();
        assert!(!app.audit_sort_ascending, "default is descending");
        let rendered = render_audit_to_string(&mut app);
        insta::assert_snapshot!("dashboard_ui_audit_time_desc_all_decisions", rendered);
    }

    /// Time ascending: rows ordered 01→04 and the header arrow flips to ▲.
    /// Exercises the `app.audit_sort_ascending { ordering }` (non-reversed)
    /// branch and the ascending header-arrow branch.
    #[test]
    fn snapshot_audit_time_asc() {
        let mut app = app_with_mixed_rows();
        app.audit_sort_column = 0;
        app.audit_sort_ascending = true;
        let rendered = render_audit_to_string(&mut app);
        insta::assert_snapshot!("dashboard_ui_audit_time_asc", rendered);
    }

    /// Sort by Risk (column 2) descending: highest risk first, `None` risk
    /// (mapped to -1) sinks to the bottom. Exercises the risk comparator and
    /// the descending `ordering.reverse()` branch + header arrow ▼.
    #[test]
    fn snapshot_audit_risk_desc() {
        let mut app = app_with_mixed_rows();
        app.audit_sort_column = 2;
        app.audit_sort_ascending = false;
        let rendered = render_audit_to_string(&mut app);
        insta::assert_snapshot!("dashboard_ui_audit_risk_desc", rendered);
    }

    /// Sort by Command (column 4) ascending: lexicographic order, header
    /// arrow ▲ on the Command column.
    #[test]
    fn snapshot_audit_command_asc() {
        let mut app = app_with_mixed_rows();
        app.audit_sort_column = 4;
        app.audit_sort_ascending = true;
        let rendered = render_audit_to_string(&mut app);
        insta::assert_snapshot!("dashboard_ui_audit_command_asc", rendered);
    }

    /// Sort by Decision (col 1), Layer (col 3) and Session (col 5) — covers
    /// the remaining string comparator arms in one snapshot via decision.
    #[test]
    fn snapshot_audit_decision_layer_session_sorts() {
        let mut app = app_with_mixed_rows();
        app.audit_sort_column = 1;
        let rendered = render_audit_to_string(&mut app);
        insta::assert_snapshot!("dashboard_ui_audit_decision_asc", rendered);

        app.audit_sort_column = 3;
        let rendered = render_audit_to_string(&mut app);
        insta::assert_snapshot!("dashboard_ui_audit_layer_asc", rendered);

        app.audit_sort_column = 5;
        let rendered = render_audit_to_string(&mut app);
        insta::assert_snapshot!("dashboard_ui_audit_session_asc", rendered);
    }

    /// Active filter: case-insensitive match on the command. Only the
    /// matching row survives; the title shows `[filter: ...]` and the count.
    #[test]
    fn snapshot_audit_filtered_by_command() {
        let mut app = app_with_mixed_rows();
        app.filter_text = "GIT".to_string(); // uppercase: proves to_lowercase()
        let rendered = render_audit_to_string(&mut app);
        insta::assert_snapshot!("dashboard_ui_audit_filtered_git", rendered);
    }

    /// Filter that matches nothing: the empty-state placeholder renders and
    /// the title count is (0).
    #[test]
    fn snapshot_audit_filter_no_match_placeholder() {
        let mut app = app_with_mixed_rows();
        app.filter_text = "no-such-command-xyz".to_string();
        let rendered = render_audit_to_string(&mut app);
        insta::assert_snapshot!("dashboard_ui_audit_filter_no_match", rendered);
    }

    /// A row is selected → the detail pane renders the full command, the
    /// decision color, the risk, layer and session. Exercises the
    /// `render_detail_pane` Some(entry) branch (with a present risk score).
    #[test]
    fn snapshot_audit_detail_pane_selected_with_risk() {
        let mut app = app_with_mixed_rows();
        // Default sort is Time-descending → visible index 0 is 09:00:04.
        app.audit_table_state.select(Some(0));
        let rendered = render_audit_to_string(&mut app);
        assert!(
            rendered.contains("Time: 09:00:04") && rendered.contains("Risk: 20"),
            "detail pane renders the selected row with its present risk score"
        );
        insta::assert_snapshot!("dashboard_ui_audit_detail_selected", rendered);
    }

    /// Selected row whose risk is `None` → detail pane renders risk as "-"
    /// and the prompted decision color (Yellow) path in the detail pane.
    /// Force Time-ascending so the visible order is 01,02,03,04 and index 1
    /// is deterministically the `09:00:02 prompted` row with `risk_score:
    /// None`, exercising the detail-pane `map_or_else(|| "-", ...)` arm.
    #[test]
    fn snapshot_audit_detail_pane_selected_no_risk_prompted() {
        let mut app = app_with_mixed_rows();
        app.audit_sort_column = 0;
        app.audit_sort_ascending = true;
        app.audit_table_state.select(Some(1));
        let rendered = render_audit_to_string(&mut app);
        assert!(
            rendered.contains("Decision: prompted") && rendered.contains("Risk: -"),
            "detail pane must show the None-risk prompted row"
        );
        insta::assert_snapshot!("dashboard_ui_audit_detail_no_risk", rendered);
    }
}
