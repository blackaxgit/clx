//! Dashboard event loop and key dispatch.
//!
//! Thin glue between the terminal (`crossterm` + `ratatui`) and the pure
//! reducer in [`super::state`]. Each iteration of [`run_event_loop`]:
//!
//! 1. Renders the current `App` to the terminal.
//! 2. Polls `crossterm` for a key event, with a timeout tied to the
//!    refresh interval.
//! 3. Builds an [`AppState`] snapshot from `App`, runs [`update`], and
//!    applies the resulting state diff back to `App`.
//! 4. Executes any returned [`DashboardCmd`] intents against `App`
//!    (data fetch, settings save, etc.). These are the only places that
//!    touch I/O or wall-clock state.
//! 5. Quits the loop when `App::should_quit` is set.

use std::io;
use std::time::Duration;

use crossterm::event::{self, Event, KeyCode, KeyModifiers};
use ratatui::DefaultTerminal;

use super::app::{App, DashboardTab, DetailTab, ExitTarget, InputMode, ScreenState};
use super::settings::config_bridge;
use super::settings::fields::{self, FieldWidget};
use super::state::{AppState, DashboardCmd, DashboardEvent, update};
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

        if event::poll(timeout)? {
            match event::read()? {
                // Ctrl-C is mapped to the reducer's explicit Quit event so
                // the runtime treats it identically to pressing `q`. This is
                // safer than relying on every input-mode branch to handle
                // the chord.
                Event::Key(key)
                    if key.code == KeyCode::Char('c')
                        && key.modifiers.contains(KeyModifiers::CONTROL) =>
                {
                    handle_dashboard_event(app, DashboardEvent::Quit);
                }
                Event::Key(key) => {
                    handle_dashboard_event(app, DashboardEvent::Key(key));
                }
                Event::Resize(cols, rows) => {
                    // Resize is currently a reducer no-op (layout is derived
                    // per frame), but routing it through the reducer keeps
                    // the runtime free of branching logic and exercises the
                    // variant so it stays alive for future use.
                    handle_dashboard_event(app, DashboardEvent::Resize(cols, rows));
                }
                _ => {}
            }
        }

        if app.last_refresh.elapsed() >= app.refresh_interval {
            // Tick is a reducer hint that wall time elapsed; the actual data
            // fetch is still owned by the runtime since it depends on App.
            handle_dashboard_event(app, DashboardEvent::Tick);
            app.refresh_data();
        }

        if app.should_quit {
            return Ok(());
        }
    }
}

/// Push a `DashboardEvent` through the pure reducer and execute the resulting
/// commands. This is the single chokepoint that adapts the terminal-driven
/// runtime to the pure [`update`] function.
fn handle_dashboard_event(app: &mut App, ev: DashboardEvent) {
    let state = snapshot_state(app);
    let (next_state, cmds) = update(state, ev);
    apply_state_to_app(app, &next_state);
    for cmd in cmds {
        execute_cmd(app, cmd);
    }
}

// ---------------------------------------------------------------------------
// Snapshot: App -> AppState
// ---------------------------------------------------------------------------

fn snapshot_state(app: &App) -> AppState {
    let settings_field_count = super::settings::fields::fields_for_section(app.settings_section_idx).len();
    AppState {
        current_tab: app.current_tab,
        should_quit: app.should_quit,
        input_mode: app.input_mode,
        sessions_selected: app.sessions_table_state.selected(),
        audit_selected: app.audit_table_state.selected(),
        rules_scroll_offset: app.rules_scroll_offset,
        filter_text: app.filter_text.clone(),
        sessions_sort_column: app.sessions_sort_column,
        sessions_sort_ascending: app.sessions_sort_ascending,
        audit_sort_column: app.audit_sort_column,
        audit_sort_ascending: app.audit_sort_ascending,
        screen_state: app.screen_state.clone(),
        detail_tab: app.detail_tab,
        detail_commands_selected: app.detail_commands_state.selected(),
        detail_events_selected: app.detail_events_state.selected(),
        detail_snapshots_selected: app.detail_snapshots_state.selected(),
        detail_scroll_offset: app.detail_scroll_offset,
        settings_section_idx: app.settings_section_idx,
        settings_field_idx: app.settings_field_idx,
        settings_is_dirty: app.settings_is_dirty,
        settings_edit_buffer: app.settings_edit_buffer.clone(),
        settings_edit_error: app.settings_edit_error.clone(),
        settings_save_result: app.settings_save_result.clone(),
        settings_confirm_reset: app.settings_confirm_reset,
        settings_exit_pending: app.settings_exit_pending,
        settings_reload_confirm: app.settings_reload_confirm,
        settings_load_error: app.settings_load_error.clone(),
        sessions_count: app.data.sessions.len(),
        audit_count: app.data.audit_entries.len(),
        settings_field_count,
    }
}

fn apply_state_to_app(app: &mut App, s: &AppState) {
    app.current_tab = s.current_tab;
    app.should_quit = s.should_quit;
    app.input_mode = s.input_mode;
    if app.sessions_table_state.selected() != s.sessions_selected {
        app.sessions_table_state.select(s.sessions_selected);
    }
    if app.audit_table_state.selected() != s.audit_selected {
        app.audit_table_state.select(s.audit_selected);
    }
    app.rules_scroll_offset = s.rules_scroll_offset;
    app.filter_text.clone_from(&s.filter_text);
    app.sessions_sort_column = s.sessions_sort_column;
    app.sessions_sort_ascending = s.sessions_sort_ascending;
    app.audit_sort_column = s.audit_sort_column;
    app.audit_sort_ascending = s.audit_sort_ascending;
    app.screen_state = s.screen_state.clone();
    app.detail_tab = s.detail_tab;
    if app.detail_commands_state.selected() != s.detail_commands_selected {
        app.detail_commands_state.select(s.detail_commands_selected);
    }
    if app.detail_events_state.selected() != s.detail_events_selected {
        app.detail_events_state.select(s.detail_events_selected);
    }
    if app.detail_snapshots_state.selected() != s.detail_snapshots_selected {
        app.detail_snapshots_state.select(s.detail_snapshots_selected);
    }
    app.detail_scroll_offset = s.detail_scroll_offset;
    if app.settings_section_idx != s.settings_section_idx {
        app.settings_section_idx = s.settings_section_idx;
    }
    if app.settings_field_idx != s.settings_field_idx {
        app.settings_field_idx = s.settings_field_idx;
        app.settings_field_table_state.select(Some(s.settings_field_idx));
    }
    app.settings_is_dirty = s.settings_is_dirty;
    app.settings_edit_buffer.clone_from(&s.settings_edit_buffer);
    app.settings_edit_error.clone_from(&s.settings_edit_error);
    app.settings_save_result.clone_from(&s.settings_save_result);
    app.settings_confirm_reset = s.settings_confirm_reset;
    app.settings_exit_pending = s.settings_exit_pending;
    app.settings_reload_confirm = s.settings_reload_confirm;
    app.settings_load_error.clone_from(&s.settings_load_error);
}

// ---------------------------------------------------------------------------
// Command executor: DashboardCmd -> side effect on App
// ---------------------------------------------------------------------------

#[allow(clippy::needless_pass_by_value)]
fn execute_cmd(app: &mut App, cmd: DashboardCmd) {
    match cmd {
        DashboardCmd::Quit => {
            app.should_quit = true;
        }
        DashboardCmd::RefreshData => {
            // In detail mode, refresh_data also refreshes detail.
            app.refresh_data();
        }
        DashboardCmd::EnterSessionDetail => {
            if app.current_tab == DashboardTab::Sessions && !app.data.sessions.is_empty() {
                app.enter_session_detail();
            }
        }
        DashboardCmd::LeaveSessionDetail => {
            app.leave_session_detail();
        }
        DashboardCmd::EnterSettings => {
            app.on_enter_settings_tab();
        }
        DashboardCmd::SettingsSave => {
            app.settings_save();
        }
        DashboardCmd::SettingsReload => {
            app.settings_reload();
        }
        DashboardCmd::SettingsDiscardChanges => {
            app.settings_discard_changes();
        }
        DashboardCmd::SettingsResetConfirmed => {
            app.settings_discard_changes();
            app.settings_edit_error = None;
            app.settings_edit_error_time = None;
        }
        DashboardCmd::ExecuteExitTarget(target) => {
            app.execute_exit_target(target);
        }
        DashboardCmd::SettingsEditField => {
            handle_settings_edit_field(app);
        }
        DashboardCmd::SettingsCommitEdit => {
            commit_settings_edit(app);
        }
        DashboardCmd::SettingsResetField => {
            handle_settings_reset_field(app);
        }
    }
}

/// Handle Space/Enter on the currently selected settings field.
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
        FieldWidget::TextInput { .. }
        | FieldWidget::NumberU64 { .. }
        | FieldWidget::NumberU32 { .. }
        | FieldWidget::NumberI64 { .. }
        | FieldWidget::NumberF64 { .. }
        | FieldWidget::NumberF32 { .. }
        | FieldWidget::NumberUsize { .. } => {
            let config = app.settings_editing_config.as_ref().unwrap();
            app.settings_edit_buffer = config_bridge::get_field_value(config, section, field);
            app.settings_edit_error = None;
            app.settings_edit_error_time = None;
            app.input_mode = InputMode::SettingsEdit;
        }
        FieldWidget::ReadOnlyList => {}
    }
}

/// Commit the current `settings_edit_buffer` to the selected field.
fn commit_settings_edit(app: &mut App) {
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

/// Reset the currently selected field to its default value.
fn handle_settings_reset_field(app: &mut App) {
    let section = app.settings_section_idx;
    let field = app.settings_field_idx;

    if let Some(config) = app.settings_editing_config.as_mut() {
        config_bridge::reset_field_to_default(config, section, field);
        config_bridge::recompute_dirty(app);
    }
}

// Suppress unused-import warnings if any feature combination strips a branch.
#[allow(dead_code)]
fn _exhaustive_match(_: DetailTab, _: ExitTarget, _: ScreenState) {}
