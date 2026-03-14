mod audit;
pub(super) mod overview;
mod rules;
mod sessions;
mod settings;

use chrono::Utc;
use ratatui::prelude::*;
use ratatui::symbols;
use ratatui::widgets::{Block, Paragraph, Tabs};

use super::app::{App, DashboardTab, InputMode};

pub fn render(frame: &mut Frame, app: &mut App) {
    let chunks = Layout::vertical([
        Constraint::Length(3),
        Constraint::Min(10),
        Constraint::Length(1),
    ])
    .split(frame.area());

    render_tab_bar(frame, app, chunks[0]);

    match app.current_tab {
        DashboardTab::Sessions => sessions::render(frame, app, chunks[1]),
        DashboardTab::AuditLog => audit::render(frame, app, chunks[1]),
        DashboardTab::Rules => rules::render(frame, app, chunks[1]),
        DashboardTab::Settings => settings::render(frame, app, chunks[1]),
    }

    render_status_bar(frame, app, chunks[2]);
}

fn render_tab_bar(frame: &mut Frame, app: &App, area: Rect) {
    let titles: Vec<String> = DashboardTab::ALL
        .iter()
        .enumerate()
        .map(|(i, t)| {
            let base = if *t == DashboardTab::Settings && app.settings_is_dirty {
                format!("{} *", t.title())
            } else {
                t.title().to_string()
            };
            if i == app.current_tab.index() && !app.filter_text.is_empty() {
                format!("{base} [filter: {}]", app.filter_text)
            } else {
                base
            }
        })
        .collect();
    let tabs = Tabs::new(titles)
        .block(Block::bordered().title(" CLX Dashboard "))
        .select(app.current_tab.index())
        .highlight_style(Style::default().bold().fg(Color::Cyan))
        .divider(symbols::DOT);
    frame.render_widget(tabs, area);
}

pub(super) fn render_status_bar(frame: &mut Frame, app: &App, area: Rect) {
    let now = Utc::now().format("%H:%M:%S");
    let refresh_secs = app
        .refresh_interval
        .checked_sub(app.last_refresh.elapsed())
        .map_or(0, |d| d.as_secs());

    let filter_info = match app.input_mode {
        InputMode::Filter => format!(" | Filter: {}_", app.filter_text),
        InputMode::Normal if !app.filter_text.is_empty() => {
            format!(" | Filter: {}", app.filter_text)
        }
        InputMode::Normal => String::new(),
        InputMode::SettingsNav | InputMode::SettingsEdit => String::new(),
    };

    let error_info = match &app.data.load_error {
        Some(e) => format!(" | ERROR: {e}"),
        None => String::new(),
    };

    let key_hints = match app.input_mode {
        InputMode::SettingsEdit => {
            "Type to edit | [Enter] Confirm | [Esc] Cancel | [Ctrl+U] Clear".to_owned()
        }
        InputMode::SettingsNav if app.settings_exit_pending.is_some() => {
            "[s] Save  [x] Discard  [Esc] Stay".to_owned()
        }
        InputMode::SettingsNav if app.settings_reload_confirm => {
            "Reload from disk? [y] Yes  [n/Esc] No".to_owned()
        }
        InputMode::SettingsNav if app.settings_confirm_reset => {
            "Reset all changes? [y] Yes  [n/Esc] No".to_owned()
        }
        InputMode::SettingsNav => {
            let save_hint = if app.settings_is_dirty {
                " [s]Save [R]Reset"
            } else {
                ""
            };
            format!(
                "h/l:section j/k:field Space/Enter:edit [d]Default [r]Reload{save_hint} q:quit Tab:switch"
            )
        }
        _ => "q:quit Tab:switch /:filter s:sort S:reverse PgUp/Dn g/G:top/bottom r:refresh"
            .to_owned(),
    };

    let settings_error = match &app.settings_edit_error {
        Some(e) => format!(" | {e}"),
        None => String::new(),
    };

    let save_result = match &app.settings_save_result {
        Some(msg) => format!(" | {msg}"),
        None => String::new(),
    };

    let status = format!(
        " {} | Refresh {}s | Sessions: {} | Commands: {}{}{}{}{} | {}",
        now,
        refresh_secs,
        app.data.total_sessions,
        app.data.total_commands,
        filter_info,
        error_info,
        settings_error,
        save_result,
        key_hints,
    );

    let style = if app.data.load_error.is_some() || app.settings_edit_error.is_some() {
        Style::default().bg(Color::Red).fg(Color::White)
    } else if app.settings_is_dirty && app.current_tab == DashboardTab::Settings {
        Style::default().bg(Color::Yellow).fg(Color::Black)
    } else {
        Style::default().bg(Color::DarkGray).fg(Color::White)
    };

    let bar = Paragraph::new(status).style(style);
    frame.render_widget(bar, area);
}

#[cfg(test)]
mod tests {
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    use super::super::app::{App, DashboardTab};
    use super::super::data::{AuditRow, SessionRow};
    use super::render;

    // ─── helpers ────────────────────────────────────────────────────────────

    /// Render `app` into an 80×24 headless terminal and return the buffer
    /// contents as a single string (rows joined by newlines, trailing spaces
    /// stripped per row for snapshot stability).
    fn render_to_string(app: &mut App) -> String {
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| {
                render(frame, app);
            })
            .unwrap();
        let buffer = terminal.backend().buffer().clone();
        (0..24)
            .map(|y| {
                let row: String = (0..80_u16)
                    .map(|x| buffer.cell((x, y)).unwrap().symbol().to_string())
                    .collect();
                row.trim_end().to_string()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Replace volatile parts of a rendered string so snapshots are stable
    /// across runs:
    /// - `HH:MM:SS` clock in the status bar → `<TIME>`
    /// - `Refresh Ns` countdown → `Refresh <N>s`
    fn redact_volatile(s: &str) -> String {
        // Walk through the string replacing HH:MM:SS patterns (all digits with
        // two colons in the right positions) and "Refresh <digits>s" spans.
        let bytes = s.as_bytes();
        let len = bytes.len();
        let mut out = String::with_capacity(len);
        let mut i = 0;
        while i < len {
            // Match HH:MM:SS  (8 chars: D D : D D : D D)
            if i + 7 < len
                && bytes[i].is_ascii_digit()
                && bytes[i + 1].is_ascii_digit()
                && bytes[i + 2] == b':'
                && bytes[i + 3].is_ascii_digit()
                && bytes[i + 4].is_ascii_digit()
                && bytes[i + 5] == b':'
                && bytes[i + 6].is_ascii_digit()
                && bytes[i + 7].is_ascii_digit()
            {
                out.push_str("<TIME>");
                i += 8;
                continue;
            }
            // Match "Refresh " followed by one-or-more digits then 's'
            let refresh_prefix = b"Refresh ";
            if i + refresh_prefix.len() < len
                && bytes[i..i + refresh_prefix.len()] == *refresh_prefix
            {
                let after = i + refresh_prefix.len();
                let mut j = after;
                while j < len && bytes[j].is_ascii_digit() {
                    j += 1;
                }
                if j > after && j < len && bytes[j] == b's' {
                    out.push_str("Refresh <N>s");
                    i = j + 1;
                    continue;
                }
            }
            out.push(s[i..].chars().next().unwrap());
            // Advance by the byte length of the character we just pushed.
            i += s[i..].chars().next().unwrap().len_utf8();
        }
        out
    }

    fn make_app() -> App {
        App::new(7, 5)
    }

    fn session_row(id: &str) -> SessionRow {
        SessionRow {
            short_id: id.to_string(),
            project: "/home/user/project".to_string(),
            started: "03-13 09:00".to_string(),
            duration: "5m".to_string(),
            messages: 10,
            commands: 3,
            tokens: "1.2K".to_string(),
            status: "ended".to_string(),
            duration_secs: 300,
            tokens_raw: 1200,
        }
    }

    fn audit_row(cmd: &str) -> AuditRow {
        AuditRow {
            time: "09:00:01".to_string(),
            decision: "allowed".to_string(),
            layer: "builtin".to_string(),
            command: cmd.to_string(),
            command_short: cmd.to_string(),
            risk_score: Some(10),
            session_short_id: "abcd1234".to_string(),
        }
    }

    // ─── T34: snapshot tests ─────────────────────────────────────────────────

    /// Sessions tab with no data — should show "No sessions found" placeholder.
    #[test]
    fn test_snapshot_sessions_tab_empty() {
        let mut app = make_app();
        app.current_tab = DashboardTab::Sessions;
        let rendered = redact_volatile(&render_to_string(&mut app));
        insta::assert_snapshot!("sessions_tab_empty", rendered);
    }

    /// Sessions tab with one session row — verifies table headers and data row.
    #[test]
    fn test_snapshot_sessions_tab_one_row() {
        let mut app = make_app();
        app.current_tab = DashboardTab::Sessions;
        app.data.sessions.push(session_row("abcd1234"));
        app.data.total_sessions = 1;
        let rendered = redact_volatile(&render_to_string(&mut app));
        insta::assert_snapshot!("sessions_tab_one_row", rendered);
    }

    /// Audit tab with no data — should show "No audit entries found" placeholder.
    #[test]
    fn test_snapshot_audit_tab_empty() {
        let mut app = make_app();
        app.current_tab = DashboardTab::AuditLog;
        let rendered = redact_volatile(&render_to_string(&mut app));
        insta::assert_snapshot!("audit_tab_empty", rendered);
    }

    /// Audit tab with one entry — verifies the entry appears in the table.
    #[test]
    fn test_snapshot_audit_tab_one_entry() {
        let mut app = make_app();
        app.current_tab = DashboardTab::AuditLog;
        app.data.audit_entries.push(audit_row("ls -la /tmp"));
        app.data.total_commands = 1;
        app.data.allowed_commands = 1;
        let rendered = redact_volatile(&render_to_string(&mut app));
        insta::assert_snapshot!("audit_tab_one_entry", rendered);
    }

    /// Rules tab with no data — all sections empty, "No learned rules" shown.
    #[test]
    fn test_snapshot_rules_tab_empty() {
        let mut app = make_app();
        app.current_tab = DashboardTab::Rules;
        let rendered = redact_volatile(&render_to_string(&mut app));
        insta::assert_snapshot!("rules_tab_empty", rendered);
    }

    /// Settings tab with a load error — verifies the error message renders.
    #[test]
    fn test_snapshot_settings_tab_load_error() {
        let mut app = make_app();
        app.current_tab = DashboardTab::Settings;
        app.settings_load_error = Some("Cannot open config file".to_string());
        // input_mode stays Normal so SettingsNav key hints are not shown
        let rendered = redact_volatile(&render_to_string(&mut app));
        insta::assert_snapshot!("settings_tab_load_error", rendered);
    }

    /// Settings tab with no config loaded and no error (`settings_editing_config`
    /// is None by default) — renders the empty field placeholder.
    #[test]
    fn test_snapshot_settings_tab_no_config() {
        let mut app = make_app();
        app.current_tab = DashboardTab::Settings;
        // Leave settings_editing_config as None (default) and no load error,
        // so render_field_table shows the bordered " Fields " block.
        let rendered = redact_volatile(&render_to_string(&mut app));
        insta::assert_snapshot!("settings_tab_no_config", rendered);
    }
}
