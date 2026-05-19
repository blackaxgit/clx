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

// ── H2: TestBackend + insta snapshots for the Sessions tab table ────────────
//
// Pins `sessions::render_table` (driven through `sessions::render`) for the
// previously-unrendered branches: every sort column / direction, the
// case-insensitive filter closure, the status-color match arms
// (active/ended/abandoned/other), and the filtered title with `[filter: ]`.
//
// Hermetic: TestBackend only. The session table embeds the per-row
// `project` path supplied by the fixture (a fixed `/work/...` literal, not
// the real HOME), so no redaction is required.
#[cfg(test)]
mod render_snapshots {
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    use crate::dashboard::app::{App, DashboardTab};
    use crate::dashboard::data::SessionRow;

    const COLS: u16 = 100;
    const ROWS: u16 = 30;

    fn render_sessions_to_string(app: &mut App) -> String {
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

    #[allow(clippy::too_many_arguments)]
    fn srow(
        short: &str,
        project: &str,
        started: &str,
        status: &str,
        msgs: i64,
        cmds: i64,
        tokens: &str,
        dur_secs: i64,
        tokens_raw: i64,
    ) -> SessionRow {
        SessionRow {
            session_id: format!("full-{short}"),
            short_id: short.to_string(),
            project: project.to_string(),
            started: started.to_string(),
            duration: format!("{}m", dur_secs / 60),
            messages: msgs,
            commands: cmds,
            tokens: tokens.to_string(),
            status: status.to_string(),
            duration_secs: dur_secs,
            tokens_raw,
        }
    }

    fn app_with_mixed_sessions() -> App {
        let mut app = App::new(7, 5);
        app.current_tab = DashboardTab::Sessions;
        // One of each status to hit every status-color arm (including the
        // catch-all via "queued"); unsorted to make the comparator visible.
        app.data.sessions = vec![
            srow(
                "zzz1",
                "/work/beta",
                "03-13 09:02",
                "active",
                4,
                1,
                "900",
                120,
                900,
            ),
            srow(
                "aaa2",
                "/work/alpha",
                "03-13 09:01",
                "ended",
                20,
                6,
                "3.1K",
                600,
                3100,
            ),
            srow(
                "mmm3",
                "/work/gamma",
                "03-13 09:03",
                "abandoned",
                2,
                0,
                "100",
                30,
                100,
            ),
            srow(
                "kkk4",
                "/work/delta",
                "03-13 09:00",
                "queued",
                9,
                3,
                "1.2K",
                300,
                1200,
            ),
        ];
        app.data.total_sessions = 4;
        app
    }

    /// Default sort (column 0 = Status, ascending). Exercises the status
    /// comparator and every status-color arm in the rendered rows.
    #[test]
    fn snapshot_sessions_status_asc_all_statuses() {
        let mut app = app_with_mixed_sessions();
        let rendered = render_sessions_to_string(&mut app);
        insta::assert_snapshot!("dashboard_ui_sessions_status_asc", rendered);
    }

    /// Sort by Duration (col 3) descending: longest first. Covers the
    /// numeric duration comparator + descending reverse + header arrow ▼.
    #[test]
    fn snapshot_sessions_duration_desc() {
        let mut app = app_with_mixed_sessions();
        app.sessions_sort_column = 3;
        app.sessions_sort_ascending = false;
        let rendered = render_sessions_to_string(&mut app);
        insta::assert_snapshot!("dashboard_ui_sessions_duration_desc", rendered);
    }

    /// Sort by Tokens (col 6) ascending: numeric token comparator.
    #[test]
    fn snapshot_sessions_tokens_asc() {
        let mut app = app_with_mixed_sessions();
        app.sessions_sort_column = 6;
        let rendered = render_sessions_to_string(&mut app);
        insta::assert_snapshot!("dashboard_ui_sessions_tokens_asc", rendered);
    }

    /// Remaining comparator columns: ID(1), Started(2), Msgs(4), Cmds(5),
    /// Project(7) — one snapshot per column proves each match arm executes.
    #[test]
    fn snapshot_sessions_remaining_sort_columns() {
        for (col, name) in [
            (1usize, "id"),
            (2, "started"),
            (4, "msgs"),
            (5, "cmds"),
            (7, "project"),
        ] {
            let mut app = app_with_mixed_sessions();
            app.sessions_sort_column = col;
            let rendered = render_sessions_to_string(&mut app);
            insta::assert_snapshot!(format!("dashboard_ui_sessions_sort_{name}_asc"), rendered);
        }
    }

    /// Case-insensitive filter on the project path. Only the matching row
    /// survives; title shows `[filter: ...]` and the filtered count.
    #[test]
    fn snapshot_sessions_filtered_by_project() {
        let mut app = app_with_mixed_sessions();
        app.filter_text = "ALPHA".to_string(); // uppercase proves to_lowercase()
        let rendered = render_sessions_to_string(&mut app);
        insta::assert_snapshot!("dashboard_ui_sessions_filtered_alpha", rendered);
    }

    /// Filter matching nothing → empty placeholder row, title count (0).
    #[test]
    fn snapshot_sessions_filter_no_match() {
        let mut app = app_with_mixed_sessions();
        app.filter_text = "zzz-no-match".to_string();
        let rendered = render_sessions_to_string(&mut app);
        insta::assert_snapshot!("dashboard_ui_sessions_filter_no_match", rendered);
    }
}
