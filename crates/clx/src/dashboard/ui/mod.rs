mod audit;
mod detail;
pub(super) mod overview;
mod rules;
mod sessions;
mod settings;

use chrono::Utc;
use ratatui::prelude::*;
use ratatui::symbols;
use ratatui::widgets::{Block, Paragraph, Tabs};

use super::app::{App, DashboardTab, InputMode, ScreenState};

pub fn render(frame: &mut Frame, app: &mut App) {
    match app.screen_state {
        ScreenState::List => render_list_view(frame, app),
        ScreenState::SessionDetail(_) => detail::render(frame, app),
    }
}

fn render_list_view(frame: &mut Frame, app: &mut App) {
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
        // Replace the home directory path so snapshots are portable across
        // machines (e.g. /Users/blackax vs /home/runner). Because the path
        // length affects ratatui box-drawing padding, we also normalize each
        // line to exactly 80 visible characters so border widths are stable.
        let home = dirs::home_dir()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();
        // The Settings-tab panel title embeds the absolute config-file path,
        // which ratatui clips to the panel width (only a prefix survives in
        // the buffer). Redact the longest known prefix and canonicalize the
        // volatile tail to 80 cols. Non-title lines never contain this
        // prefix, so every other snapshot stays byte-identical.
        let config_path = clx_core::config::Config::config_file_path()
            .map(|p| p.display().to_string())
            .unwrap_or_default();
        let s = {
            let mut lines: Vec<String> = Vec::new();
            for line in s.lines() {
                if let Some(title) = redact_title_config_path(line, &config_path, 80) {
                    lines.push(title);
                } else if !home.is_empty() && line.contains(&home) {
                    // Re-pad lines that changed so the total visible width
                    // stays at 80 columns (the <HOME> token may differ in
                    // length from the real path).
                    let replaced = line.replace(&home, "<HOME>");
                    let vis_len: usize = replaced.chars().count();
                    if vis_len >= 80 {
                        lines.push(replaced.chars().take(80).collect());
                    } else if replaced.contains('─') && replaced.trim_end().ends_with('┐') {
                        // Insert ─ before the trailing ┐ to fill to 80 cols.
                        let trimmed = replaced.trim_end_matches('┐');
                        let mut padded = trimmed.to_string();
                        for _ in 0..(80 - vis_len) {
                            padded.push('─');
                        }
                        padded.push('┐');
                        lines.push(padded);
                    } else {
                        let mut padded = replaced;
                        for _ in 0..(80 - vis_len) {
                            padded.push(' ');
                        }
                        lines.push(padded);
                    }
                } else {
                    lines.push(line.to_string());
                }
            }
            lines.join("\n")
        };
        let s = &s;
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

    /// If `line` contains a (possibly ratatui-truncated) prefix of the
    /// absolute `config_path`, return the line with that path region replaced
    /// by the stable `<CONFIG_PATH>` token and the volatile tail truncated
    /// then space-padded to exactly `width` columns. Returns `None` when the
    /// line does not contain the path, so callers leave non-title lines
    /// byte-identical (zero collateral on sessions/audit/rules snapshots).
    fn redact_title_config_path(line: &str, config_path: &str, width: usize) -> Option<String> {
        const MIN: usize = 12;
        if config_path.len() < MIN {
            return None;
        }
        let mut end = config_path.len();
        loop {
            if config_path.is_char_boundary(end)
                && let Some(pos) = line.find(&config_path[..end])
            {
                let mut head = String::with_capacity(width);
                head.push_str(&line[..pos]);
                head.push_str("<CONFIG_PATH>");
                let mut canon: String = head.chars().take(width).collect();
                while canon.chars().count() < width {
                    canon.push(' ');
                }
                return Some(canon);
            }
            if end <= MIN {
                return None;
            }
            end -= 1;
        }
    }

    fn make_app() -> App {
        App::new(7, 5)
    }

    fn session_row(id: &str) -> SessionRow {
        SessionRow {
            session_id: format!("full-{id}"),
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

    // =====================================================================
    // Wave 1 E: dashboard TUI "pixel" snapshots + pure reducer transitions.
    //
    // Lives here (not in `crates/clx/tests/dashboard_pixel.rs`) because
    // `clx` is a binary-only crate (no lib target): the dashboard render
    // path and the pure `state::update` reducer are unreachable from a
    // separate integration test file. Per the Wave 1 E brief, the pixel
    // snapshots + reducer transitions are placed in this clearly-marked
    // in-crate module instead. Anchored to
    // `specs/_prerelease/04-integration.md` section 3.9 and the
    // edge/failure matrix row "Dashboard with empty DB".
    //
    // TestBackend + insta only; no terminal, no DB, no network.
    // =====================================================================
    mod wave1_pixel {
        use super::super::super::app::{DashboardTab, InputMode};
        use super::super::super::data::{BuiltinRuleRow, LearnedRuleRow};
        use super::super::super::state::{AppState, DashboardCmd, DashboardEvent, update};
        use super::{audit_row, make_app, redact_volatile, render_to_string};
        use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

        // ---- Pixel snapshots for states not yet covered upstream --------

        /// `AuditLog` tab with several rows (multi-row table render).
        #[test]
        fn pixel_audit_tab_multi_row() {
            let mut app = make_app();
            app.current_tab = DashboardTab::AuditLog;
            app.data.audit_entries.push(audit_row("ls -la /tmp"));
            app.data.audit_entries.push(audit_row("cat /etc/hosts"));
            app.data.audit_entries.push(audit_row("git status"));
            app.data.total_commands = 3;
            app.data.allowed_commands = 3;
            let rendered = redact_volatile(&render_to_string(&mut app));
            insta::assert_snapshot!("wave1_audit_tab_multi_row", rendered);
        }

        /// Rules tab populated with a learned rule and builtin lists.
        #[test]
        fn pixel_rules_tab_populated() {
            let mut app = make_app();
            app.current_tab = DashboardTab::Rules;
            app.data.learned_rules.push(LearnedRuleRow {
                pattern: "cargo build".to_string(),
                rule_type: "whitelist".to_string(),
                scope: "global".to_string(),
                confirmations: 4,
                denials: 0,
            });
            app.data.builtin_whitelist.push(BuiltinRuleRow {
                pattern: "ls *".to_string(),
                description: Some("list directory".to_string()),
            });
            app.data.builtin_blacklist.push(BuiltinRuleRow {
                pattern: "rm -rf /".to_string(),
                description: Some("destructive".to_string()),
            });
            let rendered = redact_volatile(&render_to_string(&mut app));
            insta::assert_snapshot!("wave1_rules_tab_populated", rendered);
        }

        /// Settings tab with a populated editing config (default Config).
        #[test]
        fn pixel_settings_tab_populated() {
            let mut app = make_app();
            app.current_tab = DashboardTab::Settings;
            let cfg = clx_core::config::Config::default();
            app.settings_editing_config = Some(cfg.clone());
            app.settings_original_config = Some(cfg);
            app.input_mode = InputMode::SettingsNav;
            let rendered = redact_volatile(&render_to_string(&mut app));
            insta::assert_snapshot!("wave1_settings_tab_populated", rendered);
        }

        // ---- Pure reducer transitions for every DashboardEvent ----------

        fn key(code: KeyCode) -> DashboardEvent {
            DashboardEvent::Key(KeyEvent::new(code, KeyModifiers::NONE))
        }

        #[test]
        fn reducer_quit_event_sets_should_quit_and_emits_quit() {
            let (st, cmds) = update(AppState::new(), DashboardEvent::Quit);
            assert!(st.should_quit);
            assert_eq!(cmds, vec![DashboardCmd::Quit]);
        }

        #[test]
        fn reducer_tick_is_a_no_op_pure_transition() {
            let before = AppState::new();
            let (after, cmds) = update(before.clone(), DashboardEvent::Tick);
            assert_eq!(before, after, "Tick must not mutate state");
            assert!(cmds.is_empty());
        }

        #[test]
        fn reducer_resize_is_a_no_op_pure_transition() {
            let before = AppState::new();
            let (after, cmds) = update(before.clone(), DashboardEvent::Resize(120, 40));
            assert_eq!(before, after, "Resize must not mutate state");
            assert!(cmds.is_empty());
        }

        #[test]
        fn reducer_q_key_quits() {
            let (st, cmds) = update(AppState::new(), key(KeyCode::Char('q')));
            assert!(st.should_quit);
            assert_eq!(cmds, vec![DashboardCmd::Quit]);
        }

        #[test]
        fn reducer_esc_key_quits_from_normal_mode() {
            let (st, cmds) = update(AppState::new(), key(KeyCode::Esc));
            assert!(st.should_quit);
            assert_eq!(cmds, vec![DashboardCmd::Quit]);
        }

        #[test]
        fn reducer_tab_cycles_forward_then_back() {
            let s0 = AppState::new();
            assert_eq!(s0.current_tab, DashboardTab::Sessions);
            let (s1, _) = update(s0, key(KeyCode::Tab));
            assert_eq!(s1.current_tab, DashboardTab::AuditLog);
            let (s2, _) = update(s1, key(KeyCode::BackTab));
            assert_eq!(s2.current_tab, DashboardTab::Sessions);
        }

        #[test]
        fn reducer_number_keys_jump_tabs_and_settings_emits_enter_settings() {
            let (s, cmds) = update(AppState::new(), key(KeyCode::Char('4')));
            assert_eq!(s.current_tab, DashboardTab::Settings);
            assert!(cmds.contains(&DashboardCmd::EnterSettings));
        }

        #[test]
        fn reducer_enter_on_empty_sessions_is_a_no_op_no_panic() {
            // Edge matrix: Enter on empty Sessions is a no-op (count guard).
            let mut s = AppState::new();
            s.sessions_count = 0;
            let (st, cmds) = update(s, key(KeyCode::Enter));
            assert!(
                !cmds.contains(&DashboardCmd::EnterSessionDetail),
                "no detail entry when sessions empty"
            );
            assert!(!st.should_quit);
        }

        #[test]
        fn reducer_enter_on_nonempty_sessions_enters_detail() {
            let mut s = AppState::new();
            s.sessions_count = 3;
            let (_st, cmds) = update(s, key(KeyCode::Enter));
            assert!(cmds.contains(&DashboardCmd::EnterSessionDetail));
        }

        #[test]
        fn reducer_scroll_guards_on_empty_db_never_panic() {
            // Edge matrix: empty-DB reducer count guards prevent panic.
            let s = AppState::new(); // all *_count == 0
            for code in [
                KeyCode::Char('j'),
                KeyCode::Char('k'),
                KeyCode::Down,
                KeyCode::Up,
                KeyCode::PageDown,
                KeyCode::PageUp,
                KeyCode::Char('g'),
                KeyCode::Char('G'),
                KeyCode::Home,
                KeyCode::End,
            ] {
                let (st, _) = update(s.clone(), key(code));
                // Selection stays None or Some(0); no overflow/panic.
                assert!(matches!(st.sessions_selected, None | Some(0)));
            }
        }

        #[test]
        fn reducer_r_key_requests_refresh() {
            let (_s, cmds) = update(AppState::new(), key(KeyCode::Char('r')));
            assert_eq!(cmds, vec![DashboardCmd::RefreshData]);
        }

        #[test]
        fn reducer_slash_enters_filter_mode_and_typing_accumulates() {
            let (s1, _) = update(AppState::new(), key(KeyCode::Char('/')));
            assert_eq!(s1.input_mode, InputMode::Filter);
            let (s2, _) = update(s1, key(KeyCode::Char('a')));
            let (s3, _) = update(s2, key(KeyCode::Char('b')));
            assert_eq!(s3.filter_text, "ab");
            let (s4, _) = update(s3, key(KeyCode::Backspace));
            assert_eq!(s4.filter_text, "a");
            let (s5, _) = update(s4, key(KeyCode::Esc));
            assert_eq!(s5.input_mode, InputMode::Normal);
            assert!(s5.filter_text.is_empty());
        }

        #[test]
        fn reducer_sort_column_cycle_and_direction_toggle() {
            let mut s = AppState::new();
            s.current_tab = DashboardTab::Sessions;
            let start = s.sessions_sort_column;
            let (s1, _) = update(s, key(KeyCode::Char('s')));
            assert_ne!(s1.sessions_sort_column, start);
            let asc = s1.sessions_sort_ascending;
            let (s2, _) = update(s1, key(KeyCode::Char('S')));
            assert_eq!(s2.sessions_sort_ascending, !asc);
        }
    }
}
