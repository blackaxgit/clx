use std::io;
use std::time::Duration;

use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyModifiers};
use ratatui::DefaultTerminal;

use super::app::{App, DashboardTab, DetailTab, ExitTarget, InputMode, ScreenState};
use super::settings::config_bridge;
use super::settings::fields::{self, FieldWidget};
use super::ui;

pub fn run_event_loop(terminal: &mut DefaultTerminal, app: &mut App) -> io::Result<()> {
    loop {
        // Auto-clear timed messages before each render
        app.settings_clear_timed_messages();

        terminal.draw(|frame| ui::render(frame, app))?;

        let timeout = app
            .refresh_interval
            .checked_sub(app.last_refresh.elapsed())
            .unwrap_or(Duration::ZERO);

        if event::poll(timeout)?
            && let Event::Key(key) = event::read()?
        {
            handle_key_event(app, key);
        }

        if app.last_refresh.elapsed() >= app.refresh_interval {
            app.refresh_data();
        }

        if app.should_quit {
            return Ok(());
        }
    }
}

fn handle_key_event(app: &mut App, key: KeyEvent) {
    // If we are in the session detail view, handle those keys first.
    if matches!(app.screen_state, ScreenState::SessionDetail(_)) {
        handle_detail_mode(app, key);
        return;
    }

    match app.input_mode {
        InputMode::Normal => handle_normal_mode(app, key),
        InputMode::Filter => handle_filter_mode(app, key),
        InputMode::SettingsNav => handle_settings_nav(app, key),
        InputMode::SettingsEdit => handle_settings_edit(app, key),
    }
}

fn handle_normal_mode(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Char('q') => app.should_quit = true,
        KeyCode::Esc => app.should_quit = true,
        KeyCode::Enter
            // Drill into session detail when on Sessions tab
            if app.current_tab == DashboardTab::Sessions && !app.data.sessions.is_empty() => {
                app.enter_session_detail();
            }
        KeyCode::Tab => {
            app.next_tab();
            on_tab_switch(app);
        }
        KeyCode::BackTab => {
            app.prev_tab();
            on_tab_switch(app);
        }
        KeyCode::Char('j') | KeyCode::Down => app.scroll_down(),
        KeyCode::Char('k') | KeyCode::Up => app.scroll_up(),
        KeyCode::PageDown => app.page_down(),
        KeyCode::PageUp => app.page_up(),
        KeyCode::Char('g') | KeyCode::Home => app.scroll_to_top(),
        KeyCode::Char('G') | KeyCode::End => app.scroll_to_bottom(),
        KeyCode::Char('r') => app.refresh_data(),
        KeyCode::Char('s') => app.cycle_sort_column(),
        KeyCode::Char('S') => app.toggle_sort_direction(),
        KeyCode::Char('/') => {
            app.input_mode = InputMode::Filter;
            app.filter_text.clear();
        }
        KeyCode::Char('1') => switch_to_tab(app, DashboardTab::Sessions),
        KeyCode::Char('2') => switch_to_tab(app, DashboardTab::AuditLog),
        KeyCode::Char('3') => switch_to_tab(app, DashboardTab::Rules),
        KeyCode::Char('4') => switch_to_tab(app, DashboardTab::Settings),
        _ => {}
    }
}

fn handle_detail_mode(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Esc | KeyCode::Char('q') => app.leave_session_detail(),
        KeyCode::Tab => app.detail_next_tab(),
        KeyCode::BackTab => app.detail_prev_tab(),
        KeyCode::Char('1') => app.detail_tab = DetailTab::Info,
        KeyCode::Char('2') => app.detail_tab = DetailTab::Commands,
        KeyCode::Char('3') => app.detail_tab = DetailTab::Audit,
        KeyCode::Char('4') => app.detail_tab = DetailTab::Snapshots,
        KeyCode::Char('j') | KeyCode::Down => app.detail_scroll_down(),
        KeyCode::Char('k') | KeyCode::Up => app.detail_scroll_up(),
        KeyCode::PageDown => app.detail_page_down(),
        KeyCode::PageUp => app.detail_page_up(),
        KeyCode::Char('g') | KeyCode::Home => app.detail_scroll_to_top(),
        KeyCode::Char('G') | KeyCode::End => app.detail_scroll_to_bottom(),
        KeyCode::Char('r') => app.refresh_data(),
        _ => {}
    }
}

fn handle_filter_mode(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Esc => {
            app.input_mode = InputMode::Normal;
            app.filter_text.clear();
        }
        KeyCode::Enter => app.input_mode = InputMode::Normal,
        KeyCode::Backspace => {
            app.filter_text.pop();
        }
        KeyCode::Char(c) => app.filter_text.push(c),
        _ => {}
    }
}

fn handle_settings_nav(app: &mut App, key: KeyEvent) {
    // Handle dirty-exit guard prompt first
    if let Some(target) = app.settings_exit_pending {
        match key.code {
            KeyCode::Char('s') => {
                app.settings_save();
                app.settings_exit_pending = None;
                app.execute_exit_target(target);
            }
            KeyCode::Char('x') => {
                app.settings_discard_changes();
                app.settings_exit_pending = None;
                app.execute_exit_target(target);
            }
            KeyCode::Esc => {
                app.settings_exit_pending = None;
            }
            _ => {}
        }
        return;
    }

    // Handle reload confirmation when dirty
    if app.settings_reload_confirm {
        match key.code {
            KeyCode::Char('y') => {
                app.settings_reload_confirm = false;
                app.settings_reload();
            }
            KeyCode::Char('n') | KeyCode::Esc => {
                app.settings_reload_confirm = false;
            }
            _ => {}
        }
        return;
    }

    // Handle confirm-reset dialog
    if app.settings_confirm_reset {
        match key.code {
            KeyCode::Char('y') => {
                app.settings_discard_changes();
                app.settings_confirm_reset = false;
                app.settings_edit_error = None;
                app.settings_edit_error_time = None;
            }
            KeyCode::Char('n') | KeyCode::Esc => {
                app.settings_confirm_reset = false;
            }
            _ => {}
        }
        return;
    }

    match key.code {
        KeyCode::Char('q') | KeyCode::Esc => {
            if app.settings_is_dirty {
                app.settings_exit_pending = Some(ExitTarget::Quit);
            } else {
                app.input_mode = InputMode::Normal;
                app.current_tab = DashboardTab::Sessions;
            }
        }
        KeyCode::Tab => {
            if app.settings_is_dirty {
                // Compute next tab
                let idx = app.current_tab.index();
                let next = (idx + 1) % DashboardTab::ALL.len();
                app.settings_exit_pending = Some(ExitTarget::Tab(DashboardTab::ALL[next]));
            } else {
                app.next_tab();
                on_tab_switch(app);
            }
        }
        KeyCode::BackTab => {
            if app.settings_is_dirty {
                let idx = app.current_tab.index();
                let prev = if idx == 0 {
                    DashboardTab::ALL.len() - 1
                } else {
                    idx - 1
                };
                app.settings_exit_pending = Some(ExitTarget::Tab(DashboardTab::ALL[prev]));
            } else {
                app.prev_tab();
                on_tab_switch(app);
            }
        }
        KeyCode::Char('j') | KeyCode::Down => app.scroll_down(),
        KeyCode::Char('k') | KeyCode::Up => app.scroll_up(),
        KeyCode::PageDown => app.page_down(),
        KeyCode::PageUp => app.page_up(),
        KeyCode::Char('g') | KeyCode::Home => app.scroll_to_top(),
        KeyCode::Char('G') | KeyCode::End => app.scroll_to_bottom(),
        KeyCode::Char('h' | '[') | KeyCode::Left => {
            app.settings_prev_section();
        }
        KeyCode::Char('l' | ']') | KeyCode::Right => {
            app.settings_next_section();
        }
        KeyCode::Char(' ') | KeyCode::Enter
            // Don't allow editing if config failed to load
            if app.settings_load_error.is_none() => {
                handle_settings_edit_field(app);
            }
        KeyCode::Char('s') => {
            app.settings_save();
        }
        KeyCode::Char('d')
            if app.settings_load_error.is_none() => {
                handle_settings_reset_field(app);
            }
        KeyCode::Char('R')
            if app.settings_is_dirty => {
                app.settings_confirm_reset = true;
            }
        KeyCode::Char('r') => {
            if app.settings_is_dirty {
                app.settings_reload_confirm = true;
            } else {
                app.settings_reload();
            }
        }
        KeyCode::Char('1') => {
            if app.settings_is_dirty {
                app.settings_exit_pending = Some(ExitTarget::Tab(DashboardTab::Sessions));
            } else {
                switch_to_tab(app, DashboardTab::Sessions);
            }
        }
        KeyCode::Char('2') => {
            if app.settings_is_dirty {
                app.settings_exit_pending = Some(ExitTarget::Tab(DashboardTab::AuditLog));
            } else {
                switch_to_tab(app, DashboardTab::AuditLog);
            }
        }
        KeyCode::Char('3') => {
            if app.settings_is_dirty {
                app.settings_exit_pending = Some(ExitTarget::Tab(DashboardTab::Rules));
            } else {
                switch_to_tab(app, DashboardTab::Rules);
            }
        }
        KeyCode::Char('4') => {} // Already on Settings
        _ => {}
    }
}

/// Handle Space/Enter on the currently selected settings field.
///
/// For `Toggle` fields: flip the bool in-place.
/// For `CycleSelect` fields: rotate to the next option.
/// For `TextInput`/Number fields: no-op (Phase 3 will open a popup).
fn handle_settings_edit_field(app: &mut App) {
    let section = app.settings_section_idx;
    let field = app.settings_field_idx;

    let field_defs = fields::fields_for_section(section);
    let Some(field_def) = field_defs.get(field) else {
        return;
    };

    if app.settings_editing_config.is_none() {
        return;
    }

    // Clear any timed edit error when starting a new edit
    app.settings_edit_error = None;
    app.settings_edit_error_time = None;

    match &field_def.widget {
        FieldWidget::Toggle => {
            // Check for trust_mode warning before toggling
            let config = app.settings_editing_config.as_ref().unwrap();
            if config_bridge::is_trust_mode_enabling(config, section, field) {
                app.settings_edit_error =
                    Some("WARNING: Trust mode auto-allows ALL commands!".to_owned());
                app.settings_edit_error_time = Some(std::time::Instant::now());
            }
            config_bridge::toggle_field(
                app.settings_editing_config.as_mut().unwrap(),
                section,
                field,
            );
            config_bridge::recompute_dirty(app);
        }
        FieldWidget::CycleSelect { .. } => {
            config_bridge::cycle_field(
                app.settings_editing_config.as_mut().unwrap(),
                section,
                field,
            );
            config_bridge::recompute_dirty(app);
        }
        // Text/Number fields: open popup editor
        FieldWidget::TextInput { .. }
        | FieldWidget::NumberU64 { .. }
        | FieldWidget::NumberU32 { .. }
        | FieldWidget::NumberI64 { .. }
        | FieldWidget::NumberF64 { .. }
        | FieldWidget::NumberF32 { .. }
        | FieldWidget::NumberUsize { .. } => {
            // Copy current value into edit buffer
            let config = app.settings_editing_config.as_ref().unwrap();
            app.settings_edit_buffer = config_bridge::get_field_value(config, section, field);
            app.settings_edit_error = None;
            app.settings_edit_error_time = None;
            app.input_mode = InputMode::SettingsEdit;
        }
        FieldWidget::ReadOnlyList => {}
    }
}

/// Handle `SettingsEdit` mode key events (popup is open).
fn handle_settings_edit(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Esc => {
            app.settings_edit_buffer.clear();
            app.settings_edit_error = None;
            app.input_mode = InputMode::SettingsNav;
        }
        KeyCode::Enter => {
            let section = app.settings_section_idx;
            let field = app.settings_field_idx;
            let raw = app.settings_edit_buffer.clone();

            if let Some(config) = app.settings_editing_config.as_mut() {
                match config_bridge::set_field_value(config, section, field, &raw) {
                    Ok(()) => {
                        config_bridge::recompute_dirty(app);
                        app.settings_edit_buffer.clear();
                        app.settings_edit_error = None;
                        app.input_mode = InputMode::SettingsNav;
                    }
                    Err(e) => {
                        app.settings_edit_error = Some(e);
                        app.settings_edit_error_time = Some(std::time::Instant::now());
                    }
                }
            }
        }
        KeyCode::Backspace => {
            app.settings_edit_buffer.pop();
        }
        KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            app.settings_edit_buffer.clear();
        }
        KeyCode::Char(c) => {
            app.settings_edit_buffer.push(c);
        }
        _ => {}
    }
}

/// Reset the currently selected field to its default value.
fn handle_settings_reset_field(app: &mut App) {
    let section = app.settings_section_idx;
    let field = app.settings_field_idx;

    if let Some(config) = app.settings_editing_config.as_mut() {
        config_bridge::reset_field_to_default(config, section, field);
        config_bridge::recompute_dirty(app);
    }
}

/// Switch to a specific tab and trigger entry logic.
fn switch_to_tab(app: &mut App, tab: DashboardTab) {
    app.current_tab = tab;
    on_tab_switch(app);
}

/// Called after any tab switch to handle entry/exit logic.
fn on_tab_switch(app: &mut App) {
    if app.current_tab == DashboardTab::Settings {
        app.on_enter_settings_tab();
    } else {
        // Leaving settings — reset to Normal mode
        if app.input_mode == InputMode::SettingsNav || app.input_mode == InputMode::SettingsEdit {
            app.input_mode = InputMode::Normal;
        }
    }
}
