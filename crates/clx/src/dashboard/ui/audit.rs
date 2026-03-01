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
