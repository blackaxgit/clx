use ratatui::prelude::*;
use ratatui::widgets::{Block, Cell, Row, Scrollbar, ScrollbarOrientation, ScrollbarState, Table};

use super::overview;
use crate::dashboard::app::App;

const SESSION_COLUMNS: [&str; 8] = [
    "Status", "ID", "Started", "Duration", "Msgs", "Cmds", "Tokens", "Project",
];

pub fn render(frame: &mut Frame, app: &mut App, area: Rect) {
    // Split area: compact overview header + sessions table
    let chunks = Layout::vertical([
        Constraint::Length(overview::HEADER_HEIGHT),
        Constraint::Min(5),
    ])
    .split(area);

    // Render overview stats as compact header
    overview::render_header(frame, app, chunks[0]);

    // Render sessions table below
    render_table(frame, app, chunks[1]);
}

fn render_table(frame: &mut Frame, app: &mut App, area: Rect) {
    let filter = app.filter_text.to_lowercase();
    let mut filtered: Vec<_> = app
        .data
        .sessions
        .iter()
        .filter(|s| {
            filter.is_empty()
                || s.project.to_lowercase().contains(&filter)
                || s.short_id.to_lowercase().contains(&filter)
                || s.status.to_lowercase().contains(&filter)
                || s.started.to_lowercase().contains(&filter)
                || s.tokens.to_lowercase().contains(&filter)
        })
        .collect();

    filtered.sort_by(|a, b| {
        let ordering = match app.sessions_sort_column {
            0 => a.status.cmp(&b.status),
            1 => a.short_id.cmp(&b.short_id),
            2 => a.started.cmp(&b.started),
            3 => a.duration_secs.cmp(&b.duration_secs),
            4 => a.messages.cmp(&b.messages),
            5 => a.commands.cmp(&b.commands),
            6 => a.tokens_raw.cmp(&b.tokens_raw),
            7 => a.project.cmp(&b.project),
            _ => std::cmp::Ordering::Equal,
        };
        if app.sessions_sort_ascending {
            ordering
        } else {
            ordering.reverse()
        }
    });

    let count = filtered.len();

    let header_cells: Vec<Cell> = SESSION_COLUMNS
        .iter()
        .enumerate()
        .map(|(i, name)| {
            if i == app.sessions_sort_column {
                let arrow = if app.sessions_sort_ascending {
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
            "No sessions found",
            Style::default().fg(Color::DarkGray).italic(),
        ))])]
    } else {
        filtered
            .iter()
            .map(|s| {
                let status_style = match s.status.as_str() {
                    "active" => Style::default().fg(Color::Green),
                    "ended" => Style::default().fg(Color::DarkGray),
                    "abandoned" => Style::default().fg(Color::Red),
                    _ => Style::default(),
                };

                Row::new(vec![
                    Cell::from(s.status.as_str()).style(status_style),
                    Cell::from(s.short_id.as_str()),
                    Cell::from(s.started.as_str()),
                    Cell::from(s.duration.as_str()),
                    Cell::from(s.messages.to_string()),
                    Cell::from(s.commands.to_string()),
                    Cell::from(s.tokens.as_str()),
                    Cell::from(s.project.as_str()),
                ])
            })
            .collect()
    };

    let widths = [
        Constraint::Length(10),
        Constraint::Length(10),
        Constraint::Length(14),
        Constraint::Length(12),
        Constraint::Length(7),
        Constraint::Length(7),
        Constraint::Length(10),
        Constraint::Fill(1),
    ];

    let title = if app.filter_text.is_empty() {
        format!(" Sessions ({count}) ")
    } else {
        format!(" Sessions ({}) [filter: {}] ", count, app.filter_text)
    };
    let table = Table::new(rows, widths)
        .header(header)
        .block(Block::bordered().title(title))
        .row_highlight_style(Style::default().bg(Color::DarkGray));

    frame.render_stateful_widget(table, area, &mut app.sessions_table_state);

    // Scrollbar
    let total_rows = filtered.len();
    let selected = app.sessions_table_state.selected().unwrap_or(0);
    let mut scrollbar_state = ScrollbarState::new(total_rows).position(selected);
    let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
        .begin_symbol(Some("\u{2191}"))
        .end_symbol(Some("\u{2193}"));
    frame.render_stateful_widget(scrollbar, area, &mut scrollbar_state);
}
