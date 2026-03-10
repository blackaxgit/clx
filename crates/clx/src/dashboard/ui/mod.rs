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

fn render_status_bar(frame: &mut Frame, app: &App, area: Rect) {
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
        InputMode::SettingsNav => {
            let save_hint = if app.settings_is_dirty {
                " [s]Save [R]Reset"
            } else {
                ""
            };
            format!(
                "h/l:section j/k:field Space/Enter:edit [d]Default{save_hint} q:quit Tab:switch"
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
