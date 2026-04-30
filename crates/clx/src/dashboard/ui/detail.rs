use ratatui::prelude::*;
use ratatui::widgets::{
    Block, Cell, Paragraph, Row, Scrollbar, ScrollbarOrientation, ScrollbarState, Table,
    TableState, Tabs, Wrap,
};

use crate::dashboard::app::{App, DetailTab};
use crate::dashboard::data::SessionDetailData;

/// Format a token count with K/M suffixes matching existing `format_tokens` in overview.
fn format_tokens(tokens: i64) -> String {
    if tokens >= 1_000_000 {
        format!("{:.1}M", tokens as f64 / 1_000_000.0)
    } else if tokens >= 1_000 {
        format!("{:.1}K", tokens as f64 / 1_000.0)
    } else {
        tokens.to_string()
    }
}

/// Truncate a string to `max_len` characters, appending "..." if truncated.
fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        let mut end = max_len.saturating_sub(3);
        while !s.is_char_boundary(end) && end > 0 {
            end -= 1;
        }
        format!("{}...", &s[..end])
    }
}

pub fn render(frame: &mut Frame, app: &mut App) {
    let [header_area, content_area, status_area] = Layout::vertical([
        Constraint::Length(3),
        Constraint::Fill(1),
        Constraint::Length(1),
    ])
    .areas(frame.area());

    render_detail_tab_bar(frame, app, header_area);

    if let Some(ref data) = app.detail_data {
        // Clone the pieces we need to avoid borrow conflicts with `app`
        // for stateful widget rendering.
        match app.detail_tab {
            DetailTab::Info => render_info(
                frame,
                data,
                app.detail_scroll_offset,
                &mut app.detail_commands_state,
                content_area,
            ),
            DetailTab::Commands => {
                render_commands(frame, data, &mut app.detail_commands_state, content_area);
            }
            DetailTab::Audit => {
                render_audit(frame, data, &mut app.detail_events_state, content_area);
            }
            DetailTab::Snapshots => {
                render_snapshots(frame, data, &mut app.detail_snapshots_state, content_area);
            }
        }
    } else {
        let msg = Paragraph::new("Loading session data...")
            .style(Style::default().fg(Color::DarkGray).italic())
            .block(Block::bordered().title(" Session Detail "));
        frame.render_widget(msg, content_area);
    }

    render_detail_status_bar(frame, app, status_area);
}

fn render_detail_tab_bar(frame: &mut Frame, app: &App, area: Rect) {
    let short_id = match app.screen_state {
        super::super::app::ScreenState::SessionDetail(ref sid) => {
            if sid.len() > 8 {
                &sid[sid.len() - 8..]
            } else {
                sid.as_str()
            }
        }
        super::super::app::ScreenState::List => "",
    };

    let titles: Vec<&str> = DetailTab::ALL.iter().map(|t| t.title()).collect();
    let tabs = Tabs::new(titles)
        .block(Block::bordered().title(format!(" Session Detail: {short_id} ")))
        .select(app.detail_tab.index())
        .highlight_style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
        )
        .divider(ratatui::symbols::DOT);
    frame.render_widget(tabs, area);
}

fn render_detail_status_bar(frame: &mut Frame, app: &App, area: Rect) {
    let hints = match app.detail_tab {
        DetailTab::Info => "Tab:switch  j/k:scroll  r:refresh  Esc:back  1-4:tab",
        DetailTab::Commands | DetailTab::Audit | DetailTab::Snapshots => {
            "Tab:switch  j/k:select  PgUp/Dn  g/G:top/bottom  r:refresh  Esc:back  1-4:tab"
        }
    };

    let bar = Paragraph::new(format!(" {hints}"))
        .style(Style::default().bg(Color::DarkGray).fg(Color::White));
    frame.render_widget(bar, area);
}

// ── Info Tab ─────────────────────────────────────────────────────────────────

#[allow(clippy::vec_init_then_push)]
fn render_info(
    frame: &mut Frame,
    data: &SessionDetailData,
    scroll_offset: u16,
    commands_state: &mut TableState,
    area: Rect,
) {
    let session = &data.session;

    let status_style = match session.status {
        clx_core::types::SessionStatus::Active => Style::default().fg(Color::Green),
        clx_core::types::SessionStatus::Ended => Style::default().fg(Color::DarkGray),
        clx_core::types::SessionStatus::Abandoned => Style::default().fg(Color::Red),
    };

    let duration = match session.ended_at {
        Some(end) => {
            let dur = end - session.started_at;
            let mins = dur.num_minutes();
            if mins >= 60 {
                format!("{}h {}m", mins / 60, mins % 60)
            } else {
                format!("{mins}m")
            }
        }
        None => "-".to_string(),
    };

    let ended_str = session.ended_at.map_or_else(
        || "-".to_string(),
        |e| e.format("%Y-%m-%d %H:%M:%S").to_string(),
    );

    let cost = clx_core::types::estimate_cost(session.input_tokens, session.output_tokens);
    let total_tokens = session.input_tokens + session.output_tokens;

    let label_style = Style::default().fg(Color::DarkGray);
    let value_style = Style::default().bold();

    let mut lines: Vec<Line> = Vec::new();

    // Session metadata
    lines.push(Line::from(vec![
        Span::styled("  Session:  ", label_style),
        Span::styled(session.id.as_str(), value_style),
    ]));
    lines.push(Line::from(vec![
        Span::styled("  Project:  ", label_style),
        Span::styled(session.project_path.as_str(), value_style),
    ]));
    lines.push(Line::from(vec![
        Span::styled("  Status:   ", label_style),
        Span::styled(session.status.as_str(), status_style.bold()),
        Span::raw("                    "),
        Span::styled("Started: ", label_style),
        Span::styled(
            session.started_at.format("%Y-%m-%d %H:%M:%S").to_string(),
            value_style,
        ),
    ]));
    lines.push(Line::from(vec![
        Span::styled("  Source:   ", label_style),
        Span::styled(session.source.as_str(), value_style),
        Span::raw("                  "),
        Span::styled("Ended:   ", label_style),
        Span::styled(ended_str, value_style),
    ]));
    lines.push(Line::from(vec![
        Span::styled("  Duration: ", label_style),
        Span::styled(&duration, value_style),
    ]));
    lines.push(Line::from(""));

    // Metric boxes (text-based)
    let cs = &data.command_stats;
    let rs = &data.risk_stats;

    let pct = |n: usize, total: usize| -> String {
        (n * 100)
            .checked_div(total)
            .map_or_else(|| "0%".to_string(), |v| format!("{v}%"))
    };

    let cyan_style = Style::default().fg(Color::Cyan).bold();

    lines.push(Line::from(vec![
        Span::raw("  "),
        Span::styled("Tokens", cyan_style),
        Span::raw("                  "),
        Span::styled("Commands", cyan_style),
        Span::raw("                 "),
        Span::styled("Risk", cyan_style),
    ]));
    lines.push(Line::from(vec![
        Span::styled("  Input:  ", label_style),
        Span::styled(
            format!("{:<12}", format_tokens(session.input_tokens)),
            value_style,
        ),
        Span::raw("      "),
        Span::styled("Total:    ", label_style),
        Span::styled(format!("{:<12}", cs.total), value_style),
        Span::raw("     "),
        Span::styled("Low (1-3):  ", label_style),
        Span::styled(rs.low.to_string(), Style::default().fg(Color::Green).bold()),
    ]));
    lines.push(Line::from(vec![
        Span::styled("  Output: ", label_style),
        Span::styled(
            format!("{:<12}", format_tokens(session.output_tokens)),
            value_style,
        ),
        Span::raw("      "),
        Span::styled("Allowed:  ", label_style),
        Span::styled(
            format!("{:<5}({})", cs.allowed, pct(cs.allowed, cs.total)),
            Style::default().fg(Color::Green).bold(),
        ),
        Span::raw("    "),
        Span::styled("Med (4-7):  ", label_style),
        Span::styled(
            rs.medium.to_string(),
            Style::default().fg(Color::Yellow).bold(),
        ),
    ]));
    lines.push(Line::from(vec![
        Span::styled("  Total:  ", label_style),
        Span::styled(format!("{:<12}", format_tokens(total_tokens)), value_style),
        Span::raw("      "),
        Span::styled("Blocked:  ", label_style),
        Span::styled(
            format!("{:<5}({})", cs.blocked, pct(cs.blocked, cs.total)),
            Style::default().fg(Color::Red).bold(),
        ),
        Span::raw("    "),
        Span::styled("High (8-10):", label_style),
        Span::raw(" "),
        Span::styled(rs.high.to_string(), Style::default().fg(Color::Red).bold()),
    ]));
    lines.push(Line::from(vec![
        Span::styled("  Cost:   ", label_style),
        Span::styled(
            format!("${cost:.2}"),
            Style::default().fg(Color::Yellow).bold(),
        ),
        Span::raw("              "),
        Span::styled("Prompted: ", label_style),
        Span::styled(
            format!("{:<5}({})", cs.prompted, pct(cs.prompted, cs.total)),
            Style::default().fg(Color::Yellow).bold(),
        ),
    ]));
    lines.push(Line::from(""));

    // Messages and snapshots count
    lines.push(Line::from(vec![
        Span::styled("  Messages:  ", label_style),
        Span::styled(session.message_count.to_string(), value_style),
        Span::raw("    "),
        Span::styled("Snapshots: ", label_style),
        Span::styled(data.snapshots.len().to_string(), value_style),
        Span::raw("    "),
        Span::styled("Events: ", label_style),
        Span::styled(data.events.len().to_string(), value_style),
    ]));
    lines.push(Line::from(""));

    // Latest snapshot preview
    if let Some(snap) = data.snapshots.first() {
        lines.push(Line::from(Span::styled("  Latest Snapshot:", cyan_style)));
        if let Some(ref summary) = snap.summary {
            lines.push(Line::from(vec![
                Span::styled("    Summary: ", label_style),
                Span::from(truncate(summary, 120)),
            ]));
        }
        if let Some(ref facts) = snap.key_facts {
            lines.push(Line::from(vec![
                Span::styled("    Key Facts: ", label_style),
                Span::from(truncate(facts, 120)),
            ]));
        }
        if let Some(ref todos) = snap.todos {
            lines.push(Line::from(vec![
                Span::styled("    TODOs: ", label_style),
                Span::from(truncate(todos, 120)),
            ]));
        }
    }

    // Split area: stats overview (top, max 40%) + command list (bottom, min 60%)
    let stats_height = u16::try_from(lines.len()).unwrap_or(20) + 2; // +2 for border
    let max_stats = area.height * 40 / 100;
    let clamped = stats_height.min(max_stats).max(10);
    let [stats_area, commands_area] =
        Layout::vertical([Constraint::Length(clamped), Constraint::Fill(1)]).areas(area);

    let paragraph = Paragraph::new(lines)
        .block(Block::bordered().title(" Info "))
        .wrap(Wrap { trim: false })
        .scroll((scroll_offset, 0));
    frame.render_widget(paragraph, stats_area);

    // Embedded command table (same as Commands tab but inline)
    render_info_commands(frame, data, commands_state, commands_area);
}

/// Render the embedded command table in the Info tab.
fn render_info_commands(
    frame: &mut Frame,
    data: &SessionDetailData,
    table_state: &mut TableState,
    area: Rect,
) {
    let entries = &data.audit_entries;
    let count = entries.len();

    let header = Row::new(vec![
        Cell::from("Time"),
        Cell::from("Decision"),
        Cell::from("Risk"),
        Cell::from("Layer"),
        Cell::from("Command"),
    ])
    .style(Style::default().bold())
    .bottom_margin(1);

    let rows: Vec<Row> = if entries.is_empty() {
        vec![Row::new(vec![Cell::from(Span::styled(
            "No commands recorded for this session",
            Style::default().fg(Color::DarkGray).italic(),
        ))])]
    } else {
        entries
            .iter()
            .map(|e| {
                let ds = decision_style(e.decision.as_str());
                let risk = e
                    .risk_score
                    .map_or_else(|| "-".to_string(), |r: i32| r.to_string());
                Row::new(vec![
                    Cell::from(e.timestamp.format("%H:%M:%S").to_string()),
                    Cell::from(e.decision.as_str()).style(ds),
                    Cell::from(risk),
                    Cell::from(e.layer.as_str()),
                    Cell::from(e.command.as_str()),
                ])
            })
            .collect()
    };

    let widths = [
        Constraint::Length(10),
        Constraint::Length(10),
        Constraint::Length(6),
        Constraint::Length(12),
        Constraint::Fill(1),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(Block::bordered().title(format!(" Commands ({count}) ")))
        .row_highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("\u{2192} ");
    frame.render_stateful_widget(table, area, table_state);

    // Scrollbar
    if count > 0 {
        let selected = table_state.selected().unwrap_or(0);
        let mut scrollbar_state = ScrollbarState::new(count).position(selected);
        let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
            .begin_symbol(Some("\u{2191}"))
            .end_symbol(Some("\u{2193}"));
        frame.render_stateful_widget(scrollbar, area, &mut scrollbar_state);
    }
}

// ── Commands Tab ─────────────────────────────────────────────────────────────

fn render_commands(
    frame: &mut Frame,
    data: &SessionDetailData,
    table_state: &mut TableState,
    area: Rect,
) {
    let [table_area, detail_area] =
        Layout::vertical([Constraint::Min(8), Constraint::Percentage(30)]).areas(area);

    let entries = &data.audit_entries;
    let count = entries.len();

    let header = Row::new(vec![
        Cell::from("Time"),
        Cell::from("Decision"),
        Cell::from("Risk"),
        Cell::from("Layer"),
        Cell::from("Command"),
    ])
    .style(Style::default().bold())
    .bottom_margin(1);

    let rows: Vec<Row> = if entries.is_empty() {
        vec![Row::new(vec![Cell::from(Span::styled(
            "No commands found",
            Style::default().fg(Color::DarkGray).italic(),
        ))])]
    } else {
        entries
            .iter()
            .map(|e| {
                let decision_style = decision_style(e.decision.as_str());
                let risk_display = e
                    .risk_score
                    .map_or_else(|| "-".to_string(), |r: i32| r.to_string());

                Row::new(vec![
                    Cell::from(e.timestamp.format("%H:%M:%S").to_string()),
                    Cell::from(e.decision.as_str()).style(decision_style),
                    Cell::from(risk_display),
                    Cell::from(e.layer.as_str()),
                    Cell::from(truncate(&e.command, 60)),
                ])
            })
            .collect()
    };

    let widths = [
        Constraint::Length(10),
        Constraint::Length(10),
        Constraint::Length(6),
        Constraint::Length(12),
        Constraint::Fill(1),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(Block::bordered().title(format!(" Commands ({count}) ")))
        .row_highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("\u{2192} ");
    frame.render_stateful_widget(table, table_area, table_state);

    // Scrollbar
    let selected = table_state.selected().unwrap_or(0);
    let mut scrollbar_state = ScrollbarState::new(count).position(selected);
    let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
        .begin_symbol(Some("\u{2191}"))
        .end_symbol(Some("\u{2193}"));
    frame.render_stateful_widget(scrollbar, table_area, &mut scrollbar_state);

    // Detail pane
    render_command_detail(frame, entries, table_state, detail_area);
}

fn render_command_detail(
    frame: &mut Frame,
    entries: &[clx_core::types::AuditLogEntry],
    table_state: &TableState,
    area: Rect,
) {
    let selected = table_state.selected();
    let label_style = Style::default().fg(Color::DarkGray);

    let text = match selected.and_then(|i| entries.get(i)) {
        Some(entry) => {
            let ds = decision_style(entry.decision.as_str());
            let risk_display = entry
                .risk_score
                .map_or_else(|| "-".to_string(), |r: i32| r.to_string());

            let mut lines = vec![
                Line::from(vec![
                    Span::styled("Command: ", Style::default().fg(Color::Cyan).bold()),
                    Span::from(entry.command.clone()),
                ]),
                Line::from(vec![
                    Span::styled("Decision: ", label_style),
                    Span::styled(entry.decision.as_str(), ds),
                    Span::raw("  "),
                    Span::styled("Risk: ", label_style),
                    Span::from(risk_display),
                    Span::raw("  "),
                    Span::styled("Layer: ", label_style),
                    Span::from(entry.layer.clone()),
                ]),
            ];

            if let Some(ref reason) = entry.reasoning {
                lines.push(Line::from(vec![
                    Span::styled("Reason: ", label_style),
                    Span::from(reason.clone()),
                ]));
            }
            if let Some(ref wd) = entry.working_dir {
                lines.push(Line::from(vec![
                    Span::styled("Working Dir: ", label_style),
                    Span::from(wd.clone()),
                ]));
            }

            lines
        }
        None => vec![Line::from(Span::styled(
            "Select a row to view details",
            Style::default().fg(Color::DarkGray).italic(),
        ))],
    };

    let paragraph = Paragraph::new(text)
        .block(Block::bordered().title(" Detail "))
        .wrap(Wrap { trim: false });
    frame.render_widget(paragraph, area);
}

// ── Audit (Events) Tab ───────────────────────────────────────────────────────

fn render_audit(
    frame: &mut Frame,
    data: &SessionDetailData,
    table_state: &mut TableState,
    area: Rect,
) {
    let [table_area, detail_area] =
        Layout::vertical([Constraint::Min(8), Constraint::Percentage(30)]).areas(area);

    let events = &data.events;
    let count = events.len();

    let header = Row::new(vec![
        Cell::from("Time"),
        Cell::from("Type"),
        Cell::from("Tool"),
        Cell::from("Details"),
    ])
    .style(Style::default().bold())
    .bottom_margin(1);

    let rows: Vec<Row> = if events.is_empty() {
        vec![Row::new(vec![Cell::from(Span::styled(
            "No events found",
            Style::default().fg(Color::DarkGray).italic(),
        ))])]
    } else {
        events
            .iter()
            .map(|e| {
                let tool = e.tool_name.as_deref().unwrap_or("-");
                let details = e
                    .tool_input
                    .as_deref()
                    .or(e.tool_output.as_deref())
                    .unwrap_or("-");

                Row::new(vec![
                    Cell::from(e.timestamp.format("%H:%M:%S").to_string()),
                    Cell::from(e.event_type.as_str()),
                    Cell::from(tool.to_string()),
                    Cell::from(truncate(details, 60)),
                ])
            })
            .collect()
    };

    let widths = [
        Constraint::Length(10),
        Constraint::Length(14),
        Constraint::Length(14),
        Constraint::Fill(1),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(Block::bordered().title(format!(" Events ({count}) ")))
        .row_highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("\u{2192} ");
    frame.render_stateful_widget(table, table_area, table_state);

    // Scrollbar
    let selected = table_state.selected().unwrap_or(0);
    let mut scrollbar_state = ScrollbarState::new(count).position(selected);
    let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
        .begin_symbol(Some("\u{2191}"))
        .end_symbol(Some("\u{2193}"));
    frame.render_stateful_widget(scrollbar, table_area, &mut scrollbar_state);

    // Detail pane
    render_event_detail(frame, events, table_state, detail_area);
}

fn render_event_detail(
    frame: &mut Frame,
    events: &[clx_core::types::Event],
    table_state: &TableState,
    area: Rect,
) {
    let selected = table_state.selected();
    let label_style = Style::default().fg(Color::DarkGray);

    let text = match selected.and_then(|i| events.get(i)) {
        Some(event) => {
            let mut lines = vec![Line::from(vec![
                Span::styled("Event: ", Style::default().fg(Color::Cyan).bold()),
                Span::from(event.event_type.as_str()),
                Span::raw(" "),
                Span::styled(
                    format!("({})", event.tool_name.as_deref().unwrap_or("-")),
                    label_style,
                ),
            ])];

            if let Some(ref tuid) = event.tool_use_id {
                lines.push(Line::from(vec![
                    Span::styled("Tool Use ID: ", label_style),
                    Span::from(tuid.clone()),
                ]));
            }

            lines.push(Line::from(vec![
                Span::styled("Time: ", label_style),
                Span::from(event.timestamp.format("%Y-%m-%dT%H:%M:%SZ").to_string()),
            ]));

            if let Some(ref input) = event.tool_input {
                lines.push(Line::from(""));
                lines.push(Line::from(Span::styled(
                    "Input:",
                    Style::default().fg(Color::Cyan).bold(),
                )));
                lines.push(Line::from(truncate(input, 200)));
            }
            if let Some(ref output) = event.tool_output {
                lines.push(Line::from(""));
                lines.push(Line::from(Span::styled(
                    "Output:",
                    Style::default().fg(Color::Cyan).bold(),
                )));
                lines.push(Line::from(truncate(output, 200)));
            }

            lines
        }
        None => vec![Line::from(Span::styled(
            "Select a row to view details",
            Style::default().fg(Color::DarkGray).italic(),
        ))],
    };

    let paragraph = Paragraph::new(text)
        .block(Block::bordered().title(" Detail "))
        .wrap(Wrap { trim: false });
    frame.render_widget(paragraph, area);
}

// ── Snapshots Tab ────────────────────────────────────────────────────────────

fn render_snapshots(
    frame: &mut Frame,
    data: &SessionDetailData,
    table_state: &mut TableState,
    area: Rect,
) {
    let [table_area, detail_area] =
        Layout::vertical([Constraint::Min(6), Constraint::Percentage(50)]).areas(area);

    let snapshots = &data.snapshots;
    let count = snapshots.len();

    let header = Row::new(vec![
        Cell::from("#"),
        Cell::from("Created"),
        Cell::from("Trigger"),
        Cell::from("Tokens (in/out)"),
        Cell::from("Messages"),
    ])
    .style(Style::default().bold())
    .bottom_margin(1);

    let rows: Vec<Row> = if snapshots.is_empty() {
        vec![Row::new(vec![Cell::from(Span::styled(
            "No snapshots found",
            Style::default().fg(Color::DarkGray).italic(),
        ))])]
    } else {
        snapshots
            .iter()
            .enumerate()
            .map(|(i, s)| {
                let tokens = format!(
                    "{}/{}",
                    format_tokens(s.input_tokens.unwrap_or(0)),
                    format_tokens(s.output_tokens.unwrap_or(0)),
                );
                let msgs = s
                    .message_count
                    .map_or_else(|| "-".to_string(), |m| m.to_string());

                Row::new(vec![
                    Cell::from((i + 1).to_string()),
                    Cell::from(s.created_at.format("%m-%d %H:%M").to_string()),
                    Cell::from(s.trigger.as_str()),
                    Cell::from(tokens),
                    Cell::from(msgs),
                ])
            })
            .collect()
    };

    let widths = [
        Constraint::Length(4),
        Constraint::Length(14),
        Constraint::Length(18),
        Constraint::Length(18),
        Constraint::Length(10),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(Block::bordered().title(format!(" Snapshots ({count}) ")))
        .row_highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("\u{2192} ");
    frame.render_stateful_widget(table, table_area, table_state);

    // Scrollbar
    let selected = table_state.selected().unwrap_or(0);
    let mut scrollbar_state = ScrollbarState::new(count).position(selected);
    let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
        .begin_symbol(Some("\u{2191}"))
        .end_symbol(Some("\u{2193}"));
    frame.render_stateful_widget(scrollbar, table_area, &mut scrollbar_state);

    // Detail pane
    render_snapshot_detail(frame, snapshots, table_state, detail_area);
}

fn render_snapshot_detail(
    frame: &mut Frame,
    snapshots: &[clx_core::types::Snapshot],
    table_state: &TableState,
    area: Rect,
) {
    let selected = table_state.selected();
    let label_style = Style::default().fg(Color::DarkGray);
    let heading_style = Style::default().fg(Color::Cyan).bold();

    let text = match selected.and_then(|i| snapshots.get(i)) {
        Some(snap) => {
            let idx = selected.unwrap_or(0) + 1;
            let mut lines = vec![Line::from(vec![Span::styled(
                format!(
                    "Snapshot #{idx} \u{2014} {} ({})",
                    snap.trigger.as_str(),
                    snap.created_at.format("%Y-%m-%d %H:%M")
                ),
                heading_style,
            )])];

            lines.push(Line::from(""));

            if let Some(ref summary) = snap.summary {
                lines.push(Line::from(Span::styled("Summary:", heading_style)));
                for line in summary.lines() {
                    lines.push(Line::from(format!("  {line}")));
                }
                lines.push(Line::from(""));
            }
            if let Some(ref facts) = snap.key_facts {
                lines.push(Line::from(Span::styled("Key Facts:", heading_style)));
                for line in facts.lines() {
                    lines.push(Line::from(format!("  {line}")));
                }
                lines.push(Line::from(""));
            }
            if let Some(ref todos) = snap.todos {
                lines.push(Line::from(Span::styled("TODOs:", heading_style)));
                for line in todos.lines() {
                    lines.push(Line::from(format!("  {line}")));
                }
            }

            if snap.summary.is_none() && snap.key_facts.is_none() && snap.todos.is_none() {
                lines.push(Line::from(Span::styled(
                    "No content in this snapshot",
                    label_style.italic(),
                )));
            }

            lines
        }
        None => vec![Line::from(Span::styled(
            "Select a snapshot to view details",
            Style::default().fg(Color::DarkGray).italic(),
        ))],
    };

    let paragraph = Paragraph::new(text)
        .block(Block::bordered().title(" Snapshot Detail "))
        .wrap(Wrap { trim: false });
    frame.render_widget(paragraph, area);
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn decision_style(decision: &str) -> Style {
    match decision {
        "allowed" => Style::default().fg(Color::Green),
        "blocked" => Style::default().fg(Color::Red),
        "prompted" => Style::default().fg(Color::Yellow),
        _ => Style::default().fg(Color::White),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_tokens_units() {
        assert_eq!(format_tokens(0), "0");
        assert_eq!(format_tokens(500), "500");
        assert_eq!(format_tokens(999), "999");
        assert_eq!(format_tokens(1_000), "1.0K");
        assert_eq!(format_tokens(1_500), "1.5K");
        assert_eq!(format_tokens(999_999), "1000.0K");
        assert_eq!(format_tokens(1_000_000), "1.0M");
        assert_eq!(format_tokens(5_300_000), "5.3M");
    }

    #[test]
    fn truncate_short_string_unchanged() {
        assert_eq!(truncate("hello", 10), "hello");
    }

    #[test]
    fn truncate_exact_length_unchanged() {
        assert_eq!(truncate("hello", 5), "hello");
    }

    #[test]
    fn truncate_long_string_adds_ellipsis() {
        assert_eq!(truncate("hello world", 8), "hello...");
    }

    #[test]
    fn truncate_empty_string() {
        assert_eq!(truncate("", 5), "");
    }

    #[test]
    fn truncate_handles_unicode() {
        // Multi-byte chars should not panic
        let s = "hello 🌍 world";
        let result = truncate(s, 10);
        assert!(result.ends_with("..."));
        assert!(result.len() <= 13); // 10 + "..." worst case
    }

    #[test]
    fn decision_style_colors() {
        assert_eq!(decision_style("allowed").fg, Some(Color::Green));
        assert_eq!(decision_style("blocked").fg, Some(Color::Red));
        assert_eq!(decision_style("prompted").fg, Some(Color::Yellow));
        assert_eq!(decision_style("unknown").fg, Some(Color::White));
    }
}
