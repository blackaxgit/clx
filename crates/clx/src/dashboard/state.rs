//! Dashboard reducer (B2 testability refactor).
//!
//! This module hosts the pure-data half of the dashboard split:
//!
//! - [`AppState`] is a `Clone`-able projection of the parts of [`super::app::App`] that
//!   form the deterministic UI state. It contains no `Instant`, no `Arc<Mutex<...>>`,
//!   and no `TableState` (table state is rebuilt from `*_selected: Option<usize>` and
//!   `*_offset` per frame in `ui::*`).
//! - [`DashboardEvent`] is the input alphabet for the reducer (keyboard, resize, tick).
//! - [`DashboardCmd`] is the output alphabet of side-effect intents emitted by the
//!   reducer for the runtime layer to execute (data refresh, settings save, quit).
//! - [`update`] is a pure function `(AppState, DashboardEvent) -> (AppState, Vec<DashboardCmd>)`.
//!
//! `App` still owns the authoritative runtime state. The reducer is invoked by
//! `event::handle_key_event` after deriving an [`AppState`] snapshot via
//! [`AppState::from_app`]; any pure transitions are applied back to `App` via
//! [`AppState::apply_to_app`] and emitted commands are executed by the runtime.
//!
//! Side-effecting branches (`refresh_data`, settings save/reload, popup-opening edits)
//! are emitted as [`DashboardCmd`] variants. Pure transitions (tab nav, scrolling,
//! sort cycling, filter mode, settings nav) are applied directly to `AppState`.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use super::app::{DashboardTab, DetailTab, ExitTarget, InputMode, ScreenState};

// ---------------------------------------------------------------------------
// AppState: pure data view of the dashboard.
// ---------------------------------------------------------------------------

/// Pure-data projection of the dashboard state.
///
/// `AppState` is `Clone` and intentionally free of `Instant`, `Arc<Mutex<...>>`,
/// and `ratatui::widgets::TableState`. Tests build instances directly and run
/// the reducer against them without a terminal.
///
/// Selection is tracked as `Option<usize>` to mirror `TableState::selected`,
/// and an `_offset` companion mirrors `TableState`'s scroll offset so the UI
/// can rebuild a `TableState` per frame without losing scroll position.
#[derive(Debug, Clone, PartialEq)]
pub struct AppState {
    pub current_tab: DashboardTab,
    pub should_quit: bool,
    pub input_mode: InputMode,

    // Sessions / Audit list state
    pub sessions_selected: Option<usize>,
    pub audit_selected: Option<usize>,
    pub rules_scroll_offset: u16,

    pub filter_text: String,
    pub sessions_sort_column: usize,
    pub sessions_sort_ascending: bool,
    pub audit_sort_column: usize,
    pub audit_sort_ascending: bool,

    // Session detail
    pub screen_state: ScreenState,
    pub detail_tab: DetailTab,
    pub detail_commands_selected: Option<usize>,
    pub detail_events_selected: Option<usize>,
    pub detail_snapshots_selected: Option<usize>,
    pub detail_scroll_offset: u16,

    // Settings nav
    pub settings_section_idx: usize,
    pub settings_field_idx: usize,
    pub settings_is_dirty: bool,
    pub settings_edit_buffer: String,
    pub settings_edit_error: Option<String>,
    pub settings_save_result: Option<String>,
    pub settings_confirm_reset: bool,
    pub settings_exit_pending: Option<ExitTarget>,
    pub settings_reload_confirm: bool,
    pub settings_load_error: Option<String>,

    // Counts kept in state so reducer decisions that depend on data sizes
    // (e.g. Enter on Sessions tab when sessions are empty) are pure.
    pub sessions_count: usize,
    pub audit_count: usize,
    pub settings_field_count: usize,
}

impl AppState {
    /// Build a fresh state mirroring [`super::app::App::new`] defaults.
    #[must_use]
    pub fn new() -> Self {
        Self {
            current_tab: DashboardTab::Sessions,
            should_quit: false,
            input_mode: InputMode::Normal,
            sessions_selected: None,
            audit_selected: None,
            rules_scroll_offset: 0,
            filter_text: String::new(),
            sessions_sort_column: 2,
            sessions_sort_ascending: false,
            audit_sort_column: 0,
            audit_sort_ascending: false,
            screen_state: ScreenState::List,
            detail_tab: DetailTab::Info,
            detail_commands_selected: None,
            detail_events_selected: None,
            detail_snapshots_selected: None,
            detail_scroll_offset: 0,
            settings_section_idx: 0,
            settings_field_idx: 0,
            settings_is_dirty: false,
            settings_edit_buffer: String::new(),
            settings_edit_error: None,
            settings_save_result: None,
            settings_confirm_reset: false,
            settings_exit_pending: None,
            settings_reload_confirm: false,
            settings_load_error: None,
            sessions_count: 0,
            audit_count: 0,
            settings_field_count: 0,
        }
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// DashboardEvent: input alphabet for the reducer.
// ---------------------------------------------------------------------------

/// Input event delivered to the reducer.
#[derive(Debug, Clone)]
pub enum DashboardEvent {
    /// A keystroke arrived from the terminal.
    Key(KeyEvent),
    /// The terminal was resized to `(cols, rows)`.
    Resize(u16, u16),
    /// Wall-clock refresh tick from the runtime.
    Tick,
    /// User-requested quit (e.g. Ctrl-C). Equivalent to pressing `q`.
    Quit,
}

// ---------------------------------------------------------------------------
// DashboardCmd: side-effect intents the runtime must execute.
// ---------------------------------------------------------------------------

/// Side-effect intent emitted by the reducer.
///
/// The runtime is responsible for translating these to actual I/O against the
/// [`super::app::App`] runtime container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DashboardCmd {
    /// Re-fetch dashboard data (and detail data if in detail view).
    RefreshData,
    /// Enter the session-detail view for the currently selected session.
    EnterSessionDetail,
    /// Leave the session-detail view.
    LeaveSessionDetail,
    /// Load settings config from disk on tab entry.
    EnterSettings,
    /// Save the editing config to disk.
    SettingsSave,
    /// Reload the editing config from disk.
    SettingsReload,
    /// Reset all in-memory edits to the original config.
    SettingsDiscardChanges,
    /// Clear edit error and dirty flag after a confirmed reset.
    SettingsResetConfirmed,
    /// Execute a pending exit target after save/discard.
    ExecuteExitTarget(ExitTarget),
    /// Toggle (or cycle) the currently selected settings field.
    SettingsEditField,
    /// Commit the current edit buffer to the selected settings field.
    SettingsCommitEdit,
    /// Reset the currently selected settings field to its default value.
    SettingsResetField,
    /// Quit the dashboard event loop.
    Quit,
}

// ---------------------------------------------------------------------------
// Reducer: (state, event) -> (state', cmds)
// ---------------------------------------------------------------------------

const PAGE_SIZE: usize = 10;

/// Pure dashboard reducer.
///
/// Applies `event` to `state`, returning the new state and a list of
/// side-effect commands the runtime should execute (in order).
#[must_use]
pub fn update(mut state: AppState, event: DashboardEvent) -> (AppState, Vec<DashboardCmd>) {
    let mut cmds: Vec<DashboardCmd> = Vec::new();

    match event {
        DashboardEvent::Quit => {
            state.should_quit = true;
            cmds.push(DashboardCmd::Quit);
        }
        DashboardEvent::Tick => {
            // The runtime owns the wall-clock decision of whether to refresh.
            // The reducer treats Tick as a hint; no state change here.
        }
        DashboardEvent::Resize(_, _) => {
            // Layout is derived in the renderer from frame area; no state change.
        }
        DashboardEvent::Key(key) => {
            // Session detail view takes precedence.
            if matches!(state.screen_state, ScreenState::SessionDetail(_)) {
                handle_detail_key(&mut state, &mut cmds, key);
            } else {
                match state.input_mode {
                    InputMode::Normal => handle_normal_key(&mut state, &mut cmds, key),
                    InputMode::Filter => handle_filter_key(&mut state, key),
                    InputMode::SettingsNav => handle_settings_nav_key(&mut state, &mut cmds, key),
                    InputMode::SettingsEdit => handle_settings_edit_key(&mut state, &mut cmds, key),
                }
            }
        }
    }

    (state, cmds)
}

// ---------------------------------------------------------------------------
// Normal mode
// ---------------------------------------------------------------------------

fn handle_normal_key(state: &mut AppState, cmds: &mut Vec<DashboardCmd>, key: KeyEvent) {
    match key.code {
        KeyCode::Char('q') | KeyCode::Esc => {
            state.should_quit = true;
            cmds.push(DashboardCmd::Quit);
        }
        KeyCode::Enter
            if state.current_tab == DashboardTab::Sessions && state.sessions_count > 0 =>
        {
            cmds.push(DashboardCmd::EnterSessionDetail);
        }
        KeyCode::Tab => {
            next_tab(state);
            on_tab_switch(state, cmds);
        }
        KeyCode::BackTab => {
            prev_tab(state);
            on_tab_switch(state, cmds);
        }
        KeyCode::Char('j') | KeyCode::Down => scroll_down(state),
        KeyCode::Char('k') | KeyCode::Up => scroll_up(state),
        KeyCode::PageDown => page_down(state),
        KeyCode::PageUp => page_up(state),
        KeyCode::Char('g') | KeyCode::Home => scroll_to_top(state),
        KeyCode::Char('G') | KeyCode::End => scroll_to_bottom(state),
        KeyCode::Char('r') => cmds.push(DashboardCmd::RefreshData),
        KeyCode::Char('s') => cycle_sort_column(state),
        KeyCode::Char('S') => toggle_sort_direction(state),
        KeyCode::Char('/') => {
            state.input_mode = InputMode::Filter;
            state.filter_text.clear();
        }
        KeyCode::Char('1') => switch_to_tab(state, cmds, DashboardTab::Sessions),
        KeyCode::Char('2') => switch_to_tab(state, cmds, DashboardTab::AuditLog),
        KeyCode::Char('3') => switch_to_tab(state, cmds, DashboardTab::Rules),
        KeyCode::Char('4') => switch_to_tab(state, cmds, DashboardTab::Settings),
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Detail mode
// ---------------------------------------------------------------------------

fn handle_detail_key(state: &mut AppState, cmds: &mut Vec<DashboardCmd>, key: KeyEvent) {
    match key.code {
        KeyCode::Esc | KeyCode::Char('q') => {
            cmds.push(DashboardCmd::LeaveSessionDetail);
        }
        KeyCode::Tab => detail_next_tab(state),
        KeyCode::BackTab => detail_prev_tab(state),
        KeyCode::Char('1') => state.detail_tab = DetailTab::Info,
        KeyCode::Char('2') => state.detail_tab = DetailTab::Commands,
        KeyCode::Char('3') => state.detail_tab = DetailTab::Audit,
        KeyCode::Char('4') => state.detail_tab = DetailTab::Snapshots,
        KeyCode::Char('j') | KeyCode::Down
        | KeyCode::Char('k') | KeyCode::Up
        | KeyCode::PageDown | KeyCode::PageUp
        | KeyCode::Char('g') | KeyCode::Home
        | KeyCode::Char('G') | KeyCode::End => {
            // Detail scrolling depends on detail_data which lives on the runtime;
            // the runtime executes the scroll directly. Reducer is a no-op for
            // these so we still consume the key.
        }
        KeyCode::Char('r') => cmds.push(DashboardCmd::RefreshData),
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Filter mode
// ---------------------------------------------------------------------------

fn handle_filter_key(state: &mut AppState, key: KeyEvent) {
    match key.code {
        KeyCode::Esc => {
            state.input_mode = InputMode::Normal;
            state.filter_text.clear();
        }
        KeyCode::Enter => state.input_mode = InputMode::Normal,
        KeyCode::Backspace => {
            state.filter_text.pop();
        }
        KeyCode::Char(c) => state.filter_text.push(c),
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Settings nav mode (Settings tab, no popup)
// ---------------------------------------------------------------------------

fn handle_settings_nav_key(state: &mut AppState, cmds: &mut Vec<DashboardCmd>, key: KeyEvent) {
    // Dirty-exit guard prompt has highest priority.
    if let Some(target) = state.settings_exit_pending {
        match key.code {
            KeyCode::Char('s') => {
                cmds.push(DashboardCmd::SettingsSave);
                state.settings_exit_pending = None;
                cmds.push(DashboardCmd::ExecuteExitTarget(target));
            }
            KeyCode::Char('x') => {
                cmds.push(DashboardCmd::SettingsDiscardChanges);
                state.settings_exit_pending = None;
                cmds.push(DashboardCmd::ExecuteExitTarget(target));
            }
            KeyCode::Esc => {
                state.settings_exit_pending = None;
            }
            _ => {}
        }
        return;
    }

    // Reload confirm dialog.
    if state.settings_reload_confirm {
        match key.code {
            KeyCode::Char('y') => {
                state.settings_reload_confirm = false;
                cmds.push(DashboardCmd::SettingsReload);
            }
            KeyCode::Char('n') | KeyCode::Esc => {
                state.settings_reload_confirm = false;
            }
            _ => {}
        }
        return;
    }

    // Reset-all confirm dialog.
    if state.settings_confirm_reset {
        match key.code {
            KeyCode::Char('y') => {
                cmds.push(DashboardCmd::SettingsResetConfirmed);
                state.settings_confirm_reset = false;
                state.settings_edit_error = None;
            }
            KeyCode::Char('n') | KeyCode::Esc => {
                state.settings_confirm_reset = false;
            }
            _ => {}
        }
        return;
    }

    match key.code {
        KeyCode::Char('q') | KeyCode::Esc => {
            if state.settings_is_dirty {
                state.settings_exit_pending = Some(ExitTarget::Quit);
            } else {
                state.input_mode = InputMode::Normal;
                state.current_tab = DashboardTab::Sessions;
            }
        }
        KeyCode::Tab => {
            if state.settings_is_dirty {
                let idx = state.current_tab.index();
                let next = (idx + 1) % DashboardTab::ALL.len();
                state.settings_exit_pending = Some(ExitTarget::Tab(DashboardTab::ALL[next]));
            } else {
                next_tab(state);
                on_tab_switch(state, cmds);
            }
        }
        KeyCode::BackTab => {
            if state.settings_is_dirty {
                let idx = state.current_tab.index();
                let prev = if idx == 0 {
                    DashboardTab::ALL.len() - 1
                } else {
                    idx - 1
                };
                state.settings_exit_pending = Some(ExitTarget::Tab(DashboardTab::ALL[prev]));
            } else {
                prev_tab(state);
                on_tab_switch(state, cmds);
            }
        }
        KeyCode::Char('j') | KeyCode::Down => scroll_down(state),
        KeyCode::Char('k') | KeyCode::Up => scroll_up(state),
        KeyCode::PageDown => page_down(state),
        KeyCode::PageUp => page_up(state),
        KeyCode::Char('g') | KeyCode::Home => scroll_to_top(state),
        KeyCode::Char('G') | KeyCode::End => scroll_to_bottom(state),
        KeyCode::Char('h' | '[') | KeyCode::Left => {
            // Section navigation is delegated to the runtime (depends on
            // SECTIONS const which the reducer doesn't import).
            cmds.push(DashboardCmd::SettingsEditField);
            // Push a marker via state flag? Instead model as RefreshData? No.
            // Cleaner: handle section nav purely. We need section count.
            // Approach: keep section navigation here using bounded-modular math
            // but the runtime applies field_count reset.
            // To stay pure, we emit a SettingsPrevSection cmd. But we don't
            // have one. For B2a we use the simplest path: pop the placeholder.
            cmds.pop();
            settings_prev_section(state);
        }
        KeyCode::Char('l' | ']') | KeyCode::Right => {
            settings_next_section(state);
        }
        KeyCode::Char(' ') | KeyCode::Enter if state.settings_load_error.is_none() => {
            cmds.push(DashboardCmd::SettingsEditField);
        }
        KeyCode::Char('s') => cmds.push(DashboardCmd::SettingsSave),
        KeyCode::Char('d') if state.settings_load_error.is_none() => {
            cmds.push(DashboardCmd::SettingsResetField);
        }
        KeyCode::Char('R') if state.settings_is_dirty => {
            state.settings_confirm_reset = true;
        }
        KeyCode::Char('r') => {
            if state.settings_is_dirty {
                state.settings_reload_confirm = true;
            } else {
                cmds.push(DashboardCmd::SettingsReload);
            }
        }
        KeyCode::Char('1') => {
            if state.settings_is_dirty {
                state.settings_exit_pending = Some(ExitTarget::Tab(DashboardTab::Sessions));
            } else {
                switch_to_tab(state, cmds, DashboardTab::Sessions);
            }
        }
        KeyCode::Char('2') => {
            if state.settings_is_dirty {
                state.settings_exit_pending = Some(ExitTarget::Tab(DashboardTab::AuditLog));
            } else {
                switch_to_tab(state, cmds, DashboardTab::AuditLog);
            }
        }
        KeyCode::Char('3') => {
            if state.settings_is_dirty {
                state.settings_exit_pending = Some(ExitTarget::Tab(DashboardTab::Rules));
            } else {
                switch_to_tab(state, cmds, DashboardTab::Rules);
            }
        }
        KeyCode::Char('4') => {} // Already on Settings
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Settings edit mode (popup is open)
// ---------------------------------------------------------------------------

fn handle_settings_edit_key(state: &mut AppState, cmds: &mut Vec<DashboardCmd>, key: KeyEvent) {
    match key.code {
        KeyCode::Esc => {
            state.settings_edit_buffer.clear();
            state.settings_edit_error = None;
            state.input_mode = InputMode::SettingsNav;
        }
        KeyCode::Enter => {
            // Runtime owns Config and applies set_field_value with validation.
            cmds.push(DashboardCmd::SettingsCommitEdit);
        }
        KeyCode::Backspace => {
            state.settings_edit_buffer.pop();
        }
        KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            state.settings_edit_buffer.clear();
        }
        KeyCode::Char(c) => state.settings_edit_buffer.push(c),
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Pure AppState helpers (mirrors of App's pure methods)
// ---------------------------------------------------------------------------

fn next_tab(state: &mut AppState) {
    let idx = state.current_tab.index();
    let next = (idx + 1) % DashboardTab::ALL.len();
    state.current_tab = DashboardTab::ALL[next];
}

fn prev_tab(state: &mut AppState) {
    let idx = state.current_tab.index();
    let prev = if idx == 0 {
        DashboardTab::ALL.len() - 1
    } else {
        idx - 1
    };
    state.current_tab = DashboardTab::ALL[prev];
}

fn switch_to_tab(state: &mut AppState, cmds: &mut Vec<DashboardCmd>, tab: DashboardTab) {
    state.current_tab = tab;
    on_tab_switch(state, cmds);
}

fn on_tab_switch(state: &mut AppState, cmds: &mut Vec<DashboardCmd>) {
    if state.current_tab == DashboardTab::Settings {
        cmds.push(DashboardCmd::EnterSettings);
    } else if matches!(
        state.input_mode,
        InputMode::SettingsNav | InputMode::SettingsEdit
    ) {
        state.input_mode = InputMode::Normal;
    }
}

fn scroll_down(state: &mut AppState) {
    match state.current_tab {
        DashboardTab::Sessions => {
            if state.sessions_count > 0 {
                let i = state.sessions_selected.unwrap_or(0);
                let max = state.sessions_count - 1;
                state.sessions_selected = Some(i.saturating_add(1).min(max));
            }
        }
        DashboardTab::AuditLog => {
            if state.audit_count > 0 {
                let i = state.audit_selected.unwrap_or(0);
                let max = state.audit_count - 1;
                state.audit_selected = Some(i.saturating_add(1).min(max));
            }
        }
        DashboardTab::Rules => {
            state.rules_scroll_offset = state.rules_scroll_offset.saturating_add(1);
        }
        DashboardTab::Settings => settings_scroll_field_down(state),
    }
}

fn scroll_up(state: &mut AppState) {
    match state.current_tab {
        DashboardTab::Sessions => {
            let i = state.sessions_selected.unwrap_or(0);
            state.sessions_selected = Some(i.saturating_sub(1));
        }
        DashboardTab::AuditLog => {
            let i = state.audit_selected.unwrap_or(0);
            state.audit_selected = Some(i.saturating_sub(1));
        }
        DashboardTab::Rules => {
            state.rules_scroll_offset = state.rules_scroll_offset.saturating_sub(1);
        }
        DashboardTab::Settings => settings_scroll_field_up(state),
    }
}

fn page_down(state: &mut AppState) {
    match state.current_tab {
        DashboardTab::Sessions => {
            if state.sessions_count > 0 {
                let i = state.sessions_selected.unwrap_or(0);
                let max = state.sessions_count - 1;
                state.sessions_selected = Some((i + PAGE_SIZE).min(max));
            }
        }
        DashboardTab::AuditLog => {
            if state.audit_count > 0 {
                let i = state.audit_selected.unwrap_or(0);
                let max = state.audit_count - 1;
                state.audit_selected = Some((i + PAGE_SIZE).min(max));
            }
        }
        DashboardTab::Rules => {
            state.rules_scroll_offset = state.rules_scroll_offset.saturating_add(PAGE_SIZE as u16);
        }
        DashboardTab::Settings => {
            for _ in 0..PAGE_SIZE {
                settings_scroll_field_down(state);
            }
        }
    }
}

fn page_up(state: &mut AppState) {
    match state.current_tab {
        DashboardTab::Sessions => {
            if state.sessions_count > 0 {
                let i = state.sessions_selected.unwrap_or(0);
                state.sessions_selected = Some(i.saturating_sub(PAGE_SIZE));
            }
        }
        DashboardTab::AuditLog => {
            if state.audit_count > 0 {
                let i = state.audit_selected.unwrap_or(0);
                state.audit_selected = Some(i.saturating_sub(PAGE_SIZE));
            }
        }
        DashboardTab::Rules => {
            state.rules_scroll_offset = state.rules_scroll_offset.saturating_sub(PAGE_SIZE as u16);
        }
        DashboardTab::Settings => {
            for _ in 0..PAGE_SIZE {
                settings_scroll_field_up(state);
            }
        }
    }
}

fn scroll_to_top(state: &mut AppState) {
    match state.current_tab {
        DashboardTab::Sessions => state.sessions_selected = Some(0),
        DashboardTab::AuditLog => state.audit_selected = Some(0),
        DashboardTab::Rules => state.rules_scroll_offset = 0,
        DashboardTab::Settings => state.settings_field_idx = 0,
    }
}

fn scroll_to_bottom(state: &mut AppState) {
    match state.current_tab {
        DashboardTab::Sessions => {
            if state.sessions_count > 0 {
                state.sessions_selected = Some(state.sessions_count - 1);
            }
        }
        DashboardTab::AuditLog => {
            if state.audit_count > 0 {
                state.audit_selected = Some(state.audit_count - 1);
            }
        }
        DashboardTab::Rules => state.rules_scroll_offset = u16::MAX / 2,
        DashboardTab::Settings => {
            let max = state.settings_field_count.saturating_sub(1);
            state.settings_field_idx = max;
        }
    }
}

fn cycle_sort_column(state: &mut AppState) {
    match state.current_tab {
        DashboardTab::Sessions => {
            state.sessions_sort_column = (state.sessions_sort_column + 1) % 8;
            state.sessions_sort_ascending = true;
        }
        DashboardTab::AuditLog => {
            state.audit_sort_column = (state.audit_sort_column + 1) % 6;
            state.audit_sort_ascending = true;
        }
        DashboardTab::Rules | DashboardTab::Settings => {}
    }
}

fn toggle_sort_direction(state: &mut AppState) {
    match state.current_tab {
        DashboardTab::Sessions => {
            state.sessions_sort_ascending = !state.sessions_sort_ascending;
        }
        DashboardTab::AuditLog => {
            state.audit_sort_ascending = !state.audit_sort_ascending;
        }
        DashboardTab::Rules | DashboardTab::Settings => {}
    }
}

fn detail_next_tab(state: &mut AppState) {
    let idx = state.detail_tab.index();
    let next = (idx + 1) % DetailTab::ALL.len();
    state.detail_tab = DetailTab::ALL[next];
}

fn detail_prev_tab(state: &mut AppState) {
    let idx = state.detail_tab.index();
    let prev = if idx == 0 {
        DetailTab::ALL.len() - 1
    } else {
        idx - 1
    };
    state.detail_tab = DetailTab::ALL[prev];
}

fn settings_scroll_field_down(state: &mut AppState) {
    let max = state.settings_field_count.saturating_sub(1);
    if max > 0 || state.settings_field_idx == 0 {
        state.settings_field_idx = state.settings_field_idx.saturating_add(1).min(max);
    }
}

fn settings_scroll_field_up(state: &mut AppState) {
    state.settings_field_idx = state.settings_field_idx.saturating_sub(1);
}

fn settings_next_section(state: &mut AppState) {
    let count = super::settings::sections::SECTIONS.len();
    state.settings_section_idx = (state.settings_section_idx + 1) % count;
    state.settings_field_idx = 0;
}

fn settings_prev_section(state: &mut AppState) {
    let count = super::settings::sections::SECTIONS.len();
    state.settings_section_idx = if state.settings_section_idx == 0 {
        count - 1
    } else {
        state.settings_section_idx - 1
    };
    state.settings_field_idx = 0;
}

#[cfg(test)]
mod tests;
