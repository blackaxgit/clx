use std::io;
use std::time::Duration;

use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyModifiers};
use ratatui::DefaultTerminal;

use super::app::{App, DashboardTab, InputMode};
use super::settings::config_bridge;
use super::settings::fields::{self, FieldWidget};
use super::ui;

pub fn run_event_loop(terminal: &mut DefaultTerminal, app: &mut App) -> io::Result<()> {
    loop {
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
    // Handle confirm-reset dialog first
    if app.settings_confirm_reset {
        match key.code {
            KeyCode::Char('y') => {
                // Revert editing to original
                if let Some(orig) = &app.settings_original_config {
                    app.settings_editing_config = Some(orig.clone());
                }
                app.settings_is_dirty = false;
                app.settings_confirm_reset = false;
                app.settings_edit_error = None;
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
            app.input_mode = InputMode::Normal;
            app.current_tab = DashboardTab::Sessions;
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
        KeyCode::Char('h' | '[') | KeyCode::Left => {
            app.settings_prev_section();
        }
        KeyCode::Char('l' | ']') | KeyCode::Right => {
            app.settings_next_section();
        }
        KeyCode::Char(' ') | KeyCode::Enter => {
            handle_settings_edit_field(app);
        }
        KeyCode::Char('s') => {
            app.settings_save();
        }
        KeyCode::Char('d') => {
            handle_settings_reset_field(app);
        }
        KeyCode::Char('R') => {
            if app.settings_is_dirty {
                app.settings_confirm_reset = true;
            }
        }
        KeyCode::Char('1') => switch_to_tab(app, DashboardTab::Sessions),
        KeyCode::Char('2') => switch_to_tab(app, DashboardTab::AuditLog),
        KeyCode::Char('3') => switch_to_tab(app, DashboardTab::Rules),
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

    match &field_def.widget {
        FieldWidget::Toggle => {
            // Check for trust_mode warning before toggling
            let config = app.settings_editing_config.as_ref().unwrap();
            if config_bridge::is_trust_mode_enabling(config, section, field) {
                app.settings_edit_error =
                    Some("WARNING: Trust mode auto-allows ALL commands!".to_owned());
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
            app.settings_edit_buffer =
                config_bridge::get_field_value(config, section, field);
            app.settings_edit_error = None;
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
