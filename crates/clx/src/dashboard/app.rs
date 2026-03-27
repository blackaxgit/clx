use std::time::{Duration, Instant};

use clx_core::config::Config;
use ratatui::widgets::TableState;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DashboardTab {
    Sessions,
    AuditLog,
    Rules,
    Settings,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScreenState {
    /// Normal list view (Sessions, Audit, Rules, Settings tabs).
    List,
    /// Drill-down into a specific session.
    SessionDetail(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetailTab {
    Info,
    Commands,
    Audit,
    Snapshots,
}

impl DetailTab {
    pub const ALL: [DetailTab; 4] = [Self::Info, Self::Commands, Self::Audit, Self::Snapshots];

    pub fn title(self) -> &'static str {
        match self {
            Self::Info => "Info",
            Self::Commands => "Commands",
            Self::Audit => "Audit",
            Self::Snapshots => "Snapshots",
        }
    }

    pub fn index(self) -> usize {
        Self::ALL.iter().position(|t| *t == self).unwrap_or(0)
    }
}

/// Where the user intended to go when leaving the Settings tab with unsaved changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitTarget {
    Tab(DashboardTab),
    Quit,
}

impl DashboardTab {
    pub const ALL: [DashboardTab; 4] =
        [Self::Sessions, Self::AuditLog, Self::Rules, Self::Settings];

    pub fn title(self) -> &'static str {
        match self {
            Self::Sessions => "Sessions",
            Self::AuditLog => "Audit Log",
            Self::Rules => "Rules",
            Self::Settings => "Settings",
        }
    }

    pub fn index(self) -> usize {
        Self::ALL.iter().position(|t| *t == self).unwrap_or(0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputMode {
    Normal,
    Filter,
    SettingsNav,
    SettingsEdit,
}

pub struct App {
    pub current_tab: DashboardTab,
    pub should_quit: bool,
    pub input_mode: InputMode,
    pub sessions_table_state: TableState,
    pub audit_table_state: TableState,
    pub rules_scroll_offset: u16,
    pub filter_text: String,
    pub sessions_sort_column: usize,
    pub sessions_sort_ascending: bool,
    pub audit_sort_column: usize,
    pub audit_sort_ascending: bool,
    pub data: super::data::DashboardData,
    pub last_refresh: Instant,
    pub refresh_interval: Duration,
    pub days_filter: u32,

    // Session detail view state
    pub screen_state: ScreenState,
    pub detail_tab: DetailTab,
    pub detail_commands_state: TableState,
    pub detail_events_state: TableState,
    pub detail_snapshots_state: TableState,
    pub detail_scroll_offset: u16,
    pub detail_data: Option<super::data::SessionDetailData>,

    // Settings tab state
    pub settings_section_idx: usize,
    pub settings_field_idx: usize,
    pub settings_field_table_state: TableState,
    pub settings_original_config: Option<Config>,
    pub settings_editing_config: Option<Config>,
    // Settings editing state
    pub settings_is_dirty: bool,
    pub settings_edit_buffer: String,
    pub settings_edit_error: Option<String>,
    pub settings_edit_error_time: Option<Instant>,
    pub settings_save_result: Option<String>,
    pub settings_save_result_time: Option<Instant>,
    pub settings_confirm_reset: bool,
    pub settings_exit_pending: Option<ExitTarget>,
    pub settings_reload_confirm: bool,
    pub settings_load_error: Option<String>,
}

impl App {
    pub fn new(days: u32, refresh_secs: u64) -> Self {
        Self {
            current_tab: DashboardTab::Sessions,
            should_quit: false,
            input_mode: InputMode::Normal,
            sessions_table_state: TableState::default(),
            audit_table_state: TableState::default(),
            rules_scroll_offset: 0,
            filter_text: String::new(),
            sessions_sort_column: 2,
            sessions_sort_ascending: false,
            audit_sort_column: 0,
            audit_sort_ascending: false,
            data: super::data::DashboardData::empty(),
            last_refresh: Instant::now(),
            refresh_interval: Duration::from_secs(refresh_secs),
            days_filter: days,
            screen_state: ScreenState::List,
            detail_tab: DetailTab::Info,
            detail_commands_state: TableState::default(),
            detail_events_state: TableState::default(),
            detail_snapshots_state: TableState::default(),
            detail_scroll_offset: 0,
            detail_data: None,
            settings_section_idx: 0,
            settings_field_idx: 0,
            settings_field_table_state: TableState::default(),
            settings_original_config: None,
            settings_editing_config: None,
            settings_is_dirty: false,
            settings_edit_buffer: String::new(),
            settings_edit_error: None,
            settings_edit_error_time: None,
            settings_save_result: None,
            settings_save_result_time: None,
            settings_confirm_reset: false,
            settings_exit_pending: None,
            settings_reload_confirm: false,
            settings_load_error: None,
        }
    }

    pub fn next_tab(&mut self) {
        let idx = self.current_tab.index();
        let next = (idx + 1) % DashboardTab::ALL.len();
        self.current_tab = DashboardTab::ALL[next];
    }

    pub fn prev_tab(&mut self) {
        let idx = self.current_tab.index();
        let prev = if idx == 0 {
            DashboardTab::ALL.len() - 1
        } else {
            idx - 1
        };
        self.current_tab = DashboardTab::ALL[prev];
    }

    pub fn scroll_down(&mut self) {
        match self.current_tab {
            DashboardTab::Sessions => {
                if !self.data.sessions.is_empty() {
                    let i = self.sessions_table_state.selected().unwrap_or(0);
                    let max = self.data.sessions.len() - 1;
                    self.sessions_table_state
                        .select(Some(i.saturating_add(1).min(max)));
                }
            }
            DashboardTab::AuditLog => {
                if !self.data.audit_entries.is_empty() {
                    let i = self.audit_table_state.selected().unwrap_or(0);
                    let max = self.data.audit_entries.len() - 1;
                    self.audit_table_state
                        .select(Some(i.saturating_add(1).min(max)));
                }
            }
            DashboardTab::Rules => {
                self.rules_scroll_offset = self.rules_scroll_offset.saturating_add(1);
            }
            DashboardTab::Settings => {
                self.settings_scroll_field_down();
            }
        }
    }

    pub fn scroll_up(&mut self) {
        match self.current_tab {
            DashboardTab::Sessions => {
                let i = self.sessions_table_state.selected().unwrap_or(0);
                self.sessions_table_state.select(Some(i.saturating_sub(1)));
            }
            DashboardTab::AuditLog => {
                let i = self.audit_table_state.selected().unwrap_or(0);
                self.audit_table_state.select(Some(i.saturating_sub(1)));
            }
            DashboardTab::Rules => {
                self.rules_scroll_offset = self.rules_scroll_offset.saturating_sub(1);
            }
            DashboardTab::Settings => {
                self.settings_scroll_field_up();
            }
        }
    }

    const PAGE_SIZE: usize = 10;

    pub fn page_down(&mut self) {
        match self.current_tab {
            DashboardTab::Sessions => {
                if !self.data.sessions.is_empty() {
                    let i = self.sessions_table_state.selected().unwrap_or(0);
                    let max = self.data.sessions.len() - 1;
                    self.sessions_table_state
                        .select(Some((i + Self::PAGE_SIZE).min(max)));
                }
            }
            DashboardTab::AuditLog => {
                if !self.data.audit_entries.is_empty() {
                    let i = self.audit_table_state.selected().unwrap_or(0);
                    let max = self.data.audit_entries.len() - 1;
                    self.audit_table_state
                        .select(Some((i + Self::PAGE_SIZE).min(max)));
                }
            }
            DashboardTab::Rules => {
                self.rules_scroll_offset = self
                    .rules_scroll_offset
                    .saturating_add(Self::PAGE_SIZE as u16);
            }
            DashboardTab::Settings => {
                for _ in 0..Self::PAGE_SIZE {
                    self.settings_scroll_field_down();
                }
            }
        }
    }

    pub fn page_up(&mut self) {
        match self.current_tab {
            DashboardTab::Sessions => {
                if !self.data.sessions.is_empty() {
                    let i = self.sessions_table_state.selected().unwrap_or(0);
                    self.sessions_table_state
                        .select(Some(i.saturating_sub(Self::PAGE_SIZE)));
                }
            }
            DashboardTab::AuditLog => {
                if !self.data.audit_entries.is_empty() {
                    let i = self.audit_table_state.selected().unwrap_or(0);
                    self.audit_table_state
                        .select(Some(i.saturating_sub(Self::PAGE_SIZE)));
                }
            }
            DashboardTab::Rules => {
                self.rules_scroll_offset = self
                    .rules_scroll_offset
                    .saturating_sub(Self::PAGE_SIZE as u16);
            }
            DashboardTab::Settings => {
                for _ in 0..Self::PAGE_SIZE {
                    self.settings_scroll_field_up();
                }
            }
        }
    }

    pub fn scroll_to_top(&mut self) {
        match self.current_tab {
            DashboardTab::Sessions => {
                self.sessions_table_state.select(Some(0));
            }
            DashboardTab::AuditLog => {
                self.audit_table_state.select(Some(0));
            }
            DashboardTab::Rules => {
                self.rules_scroll_offset = 0;
            }
            DashboardTab::Settings => {
                self.settings_field_idx = 0;
                self.settings_field_table_state.select(Some(0));
            }
        }
    }

    pub fn scroll_to_bottom(&mut self) {
        match self.current_tab {
            DashboardTab::Sessions => {
                if !self.data.sessions.is_empty() {
                    self.sessions_table_state
                        .select(Some(self.data.sessions.len() - 1));
                }
            }
            DashboardTab::AuditLog => {
                if !self.data.audit_entries.is_empty() {
                    self.audit_table_state
                        .select(Some(self.data.audit_entries.len() - 1));
                }
            }
            DashboardTab::Rules => {
                self.rules_scroll_offset = u16::MAX / 2;
            }
            DashboardTab::Settings => {
                let max = self.settings_current_field_count().saturating_sub(1);
                self.settings_field_idx = max;
                self.settings_field_table_state.select(Some(max));
            }
        }
    }

    pub fn refresh_data(&mut self) {
        self.data = super::data::DashboardData::fetch(self.days_filter);
        // Also refresh detail data if we are in detail view
        if let ScreenState::SessionDetail(ref sid) = self.screen_state {
            self.detail_data = super::data::SessionDetailData::fetch(sid);
        }
        self.last_refresh = Instant::now();
    }

    /// Enter session detail view for the currently selected session row.
    pub fn enter_session_detail(&mut self) {
        let selected = self.sessions_table_state.selected().unwrap_or(0);
        if let Some(row) = self.data.sessions.get(selected) {
            let sid = row.session_id.clone();
            self.detail_data = super::data::SessionDetailData::fetch(&sid);
            self.screen_state = ScreenState::SessionDetail(sid);
            self.detail_tab = DetailTab::Info;
            self.detail_commands_state = TableState::default();
            self.detail_events_state = TableState::default();
            self.detail_snapshots_state = TableState::default();
            self.detail_scroll_offset = 0;
        }
    }

    /// Leave session detail view and return to the list.
    pub fn leave_session_detail(&mut self) {
        self.screen_state = ScreenState::List;
        self.detail_data = None;
    }

    pub fn detail_next_tab(&mut self) {
        let idx = self.detail_tab.index();
        let next = (idx + 1) % DetailTab::ALL.len();
        self.detail_tab = DetailTab::ALL[next];
    }

    pub fn detail_prev_tab(&mut self) {
        let idx = self.detail_tab.index();
        let prev = if idx == 0 {
            DetailTab::ALL.len() - 1
        } else {
            idx - 1
        };
        self.detail_tab = DetailTab::ALL[prev];
    }

    pub fn detail_scroll_down(&mut self) {
        match self.detail_tab {
            DetailTab::Info => {
                self.detail_scroll_offset = self.detail_scroll_offset.saturating_add(1);
            }
            DetailTab::Commands => {
                if let Some(ref data) = self.detail_data
                    && !data.audit_entries.is_empty()
                {
                    let i = self.detail_commands_state.selected().unwrap_or(0);
                    let max = data.audit_entries.len() - 1;
                    self.detail_commands_state
                        .select(Some(i.saturating_add(1).min(max)));
                }
            }
            DetailTab::Audit => {
                if let Some(ref data) = self.detail_data
                    && !data.events.is_empty()
                {
                    let i = self.detail_events_state.selected().unwrap_or(0);
                    let max = data.events.len() - 1;
                    self.detail_events_state
                        .select(Some(i.saturating_add(1).min(max)));
                }
            }
            DetailTab::Snapshots => {
                if let Some(ref data) = self.detail_data
                    && !data.snapshots.is_empty()
                {
                    let i = self.detail_snapshots_state.selected().unwrap_or(0);
                    let max = data.snapshots.len() - 1;
                    self.detail_snapshots_state
                        .select(Some(i.saturating_add(1).min(max)));
                }
            }
        }
    }

    pub fn detail_scroll_up(&mut self) {
        match self.detail_tab {
            DetailTab::Info => {
                self.detail_scroll_offset = self.detail_scroll_offset.saturating_sub(1);
            }
            DetailTab::Commands => {
                let i = self.detail_commands_state.selected().unwrap_or(0);
                self.detail_commands_state.select(Some(i.saturating_sub(1)));
            }
            DetailTab::Audit => {
                let i = self.detail_events_state.selected().unwrap_or(0);
                self.detail_events_state.select(Some(i.saturating_sub(1)));
            }
            DetailTab::Snapshots => {
                let i = self.detail_snapshots_state.selected().unwrap_or(0);
                self.detail_snapshots_state
                    .select(Some(i.saturating_sub(1)));
            }
        }
    }

    pub fn detail_scroll_to_top(&mut self) {
        match self.detail_tab {
            DetailTab::Info => self.detail_scroll_offset = 0,
            DetailTab::Commands => self.detail_commands_state.select(Some(0)),
            DetailTab::Audit => self.detail_events_state.select(Some(0)),
            DetailTab::Snapshots => self.detail_snapshots_state.select(Some(0)),
        }
    }

    pub fn detail_scroll_to_bottom(&mut self) {
        if let Some(ref data) = self.detail_data {
            match self.detail_tab {
                DetailTab::Info => self.detail_scroll_offset = u16::MAX / 2,
                DetailTab::Commands => {
                    if !data.audit_entries.is_empty() {
                        self.detail_commands_state
                            .select(Some(data.audit_entries.len() - 1));
                    }
                }
                DetailTab::Audit => {
                    if !data.events.is_empty() {
                        self.detail_events_state.select(Some(data.events.len() - 1));
                    }
                }
                DetailTab::Snapshots => {
                    if !data.snapshots.is_empty() {
                        self.detail_snapshots_state
                            .select(Some(data.snapshots.len() - 1));
                    }
                }
            }
        }
    }

    pub fn detail_page_down(&mut self) {
        for _ in 0..Self::PAGE_SIZE {
            self.detail_scroll_down();
        }
    }

    pub fn detail_page_up(&mut self) {
        for _ in 0..Self::PAGE_SIZE {
            self.detail_scroll_up();
        }
    }

    pub fn cycle_sort_column(&mut self) {
        match self.current_tab {
            DashboardTab::Sessions => {
                self.sessions_sort_column = (self.sessions_sort_column + 1) % 8;
                self.sessions_sort_ascending = true;
            }
            DashboardTab::AuditLog => {
                self.audit_sort_column = (self.audit_sort_column + 1) % 6;
                self.audit_sort_ascending = true;
            }
            DashboardTab::Rules | DashboardTab::Settings => {}
        }
    }

    pub fn toggle_sort_direction(&mut self) {
        match self.current_tab {
            DashboardTab::Sessions => {
                self.sessions_sort_ascending = !self.sessions_sort_ascending;
            }
            DashboardTab::AuditLog => {
                self.audit_sort_ascending = !self.audit_sort_ascending;
            }
            DashboardTab::Rules | DashboardTab::Settings => {}
        }
    }

    // --- Settings helpers ---

    /// Number of fields in the currently selected section.
    fn settings_current_field_count(&self) -> usize {
        super::settings::fields::fields_for_section(self.settings_section_idx).len()
    }

    /// Move the field selection down by one row.
    fn settings_scroll_field_down(&mut self) {
        let max = self.settings_current_field_count().saturating_sub(1);
        if max > 0 || self.settings_field_idx == 0 {
            self.settings_field_idx = self.settings_field_idx.saturating_add(1).min(max);
            self.settings_field_table_state
                .select(Some(self.settings_field_idx));
        }
    }

    /// Move the field selection up by one row.
    fn settings_scroll_field_up(&mut self) {
        self.settings_field_idx = self.settings_field_idx.saturating_sub(1);
        self.settings_field_table_state
            .select(Some(self.settings_field_idx));
    }

    /// Switch to the next section (wrapping).
    pub fn settings_next_section(&mut self) {
        let count = super::settings::sections::SECTIONS.len();
        self.settings_section_idx = (self.settings_section_idx + 1) % count;
        self.settings_field_idx = 0;
        self.settings_field_table_state.select(Some(0));
    }

    /// Switch to the previous section (wrapping).
    pub fn settings_prev_section(&mut self) {
        let count = super::settings::sections::SECTIONS.len();
        self.settings_section_idx = if self.settings_section_idx == 0 {
            count - 1
        } else {
            self.settings_section_idx - 1
        };
        self.settings_field_idx = 0;
        self.settings_field_table_state.select(Some(0));
    }

    /// Called when entering the Settings tab. Loads config from disk.
    pub fn on_enter_settings_tab(&mut self) {
        // Only load if not already loaded (avoids overwriting edits on re-entry)
        if self.settings_original_config.is_none() {
            match Config::load_from_file_only() {
                Ok(config) => {
                    self.settings_editing_config = Some(config.clone());
                    self.settings_original_config = Some(config);
                    self.settings_load_error = None;
                }
                Err(e) => {
                    self.settings_load_error = Some(format!("Failed to load config: {e}"));
                    // Still provide defaults so the UI renders, but mark as non-editable
                    self.settings_editing_config = None;
                    self.settings_original_config = None;
                }
            }
        }
        self.settings_field_table_state
            .select(Some(self.settings_field_idx));
        self.input_mode = InputMode::SettingsNav;
    }

    /// Reload settings from disk, replacing any in-memory state.
    pub fn settings_reload(&mut self) {
        match Config::load_from_file_only() {
            Ok(config) => {
                self.settings_editing_config = Some(config.clone());
                self.settings_original_config = Some(config);
                self.settings_is_dirty = false;
                self.settings_load_error = None;
                self.settings_save_result = Some("Reloaded from disk".to_owned());
                self.settings_save_result_time = Some(Instant::now());
            }
            Err(e) => {
                self.settings_save_result = Some(format!("Reload error: {e}"));
                self.settings_save_result_time = Some(Instant::now());
            }
        }
    }

    /// Auto-clear timed messages (save result after 3s, edit error after 5s).
    pub fn settings_clear_timed_messages(&mut self) {
        if let Some(t) = self.settings_save_result_time
            && t.elapsed() >= Duration::from_secs(3)
        {
            self.settings_save_result = None;
            self.settings_save_result_time = None;
        }
        if let Some(t) = self.settings_edit_error_time
            && t.elapsed() >= Duration::from_secs(5)
        {
            self.settings_edit_error = None;
            self.settings_edit_error_time = None;
        }
    }

    /// Execute a pending exit after save or discard.
    pub fn execute_exit_target(&mut self, target: ExitTarget) {
        match target {
            ExitTarget::Quit => {
                self.input_mode = InputMode::Normal;
                self.should_quit = true;
            }
            ExitTarget::Tab(tab) => {
                self.current_tab = tab;
                if tab == DashboardTab::Settings {
                    self.input_mode = InputMode::SettingsNav;
                } else {
                    self.input_mode = InputMode::Normal;
                }
            }
        }
    }

    /// Discard unsaved changes by reverting editing config to original.
    pub fn settings_discard_changes(&mut self) {
        if let Some(orig) = &self.settings_original_config {
            self.settings_editing_config = Some(orig.clone());
        }
        self.settings_is_dirty = false;
    }

    /// Save the editing config to disk atomically.
    ///
    /// Writes to a temp file first, then renames to `config.yaml`.
    /// On success, updates original config and clears dirty flag.
    pub fn settings_save(&mut self) {
        if !self.settings_is_dirty {
            return;
        }

        let Some(editing) = &self.settings_editing_config else {
            return;
        };

        let config_dir = match Config::config_dir() {
            Ok(d) => d,
            Err(e) => {
                self.settings_save_result = Some(format!("Error: {e}"));
                self.settings_save_result_time = Some(Instant::now());
                return;
            }
        };

        let config_path = config_dir.join("config.yaml");
        let tmp_path = config_dir.join("config.yaml.tmp");

        let yaml = match serde_yml::to_string(editing) {
            Ok(y) => y,
            Err(e) => {
                self.settings_save_result = Some(format!("Serialize error: {e}"));
                self.settings_save_result_time = Some(Instant::now());
                return;
            }
        };

        if let Err(e) = std::fs::write(&tmp_path, &yaml) {
            self.settings_save_result = Some(format!("Write error: {e}"));
            self.settings_save_result_time = Some(Instant::now());
            let _ = std::fs::remove_file(&tmp_path);
            return;
        }

        if let Err(e) = std::fs::rename(&tmp_path, &config_path) {
            self.settings_save_result = Some(format!("Rename error: {e}"));
            self.settings_save_result_time = Some(Instant::now());
            let _ = std::fs::remove_file(&tmp_path);
            return;
        }

        self.settings_original_config = Some(editing.clone());
        self.settings_is_dirty = false;
        self.settings_save_result = Some("Saved".to_owned());
        self.settings_save_result_time = Some(Instant::now());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_app() -> App {
        App::new(7, 5)
    }

    fn make_app_with_sessions(n: usize) -> App {
        let mut app = make_app();
        for _ in 0..n {
            app.data.sessions.push(super::super::data::SessionRow {
                session_id: "full-session-id".into(),
                short_id: "abc".into(),
                project: "/tmp".into(),
                started: "01-01 00:00".into(),
                duration: "5m".into(),
                messages: 0,
                commands: 0,
                tokens: "0".into(),
                status: "active".into(),
                duration_secs: 300,
                tokens_raw: 0,
            });
        }
        app
    }

    fn make_app_with_audit(n: usize) -> App {
        let mut app = make_app();
        for _ in 0..n {
            app.data.audit_entries.push(super::super::data::AuditRow {
                time: "00:00:00".into(),
                decision: "allowed".into(),
                layer: "builtin".into(),
                command: "ls".into(),
                command_short: "ls".into(),
                risk_score: Some(0),
                session_short_id: "abc".into(),
            });
        }
        app
    }

    // ---- Tab navigation ----

    // ---- T32: App::new initial state ----

    #[test]
    fn test_new_initial_tab_is_sessions() {
        // Arrange / Act
        let app = make_app();
        // Assert: default tab is Sessions (index 0)
        assert_eq!(app.current_tab, DashboardTab::Sessions);
        assert_eq!(app.current_tab.index(), 0);
    }

    #[test]
    fn test_new_data_fields_empty() {
        // Arrange / Act
        let app = make_app();
        // Assert: all data collections start empty
        assert_eq!(app.data.total_sessions, 0);
        assert_eq!(app.data.active_sessions, 0);
        assert!(app.data.sessions.is_empty());
        assert!(app.data.audit_entries.is_empty());
        assert!(app.data.learned_rules.is_empty());
    }

    #[test]
    fn test_new_should_quit_is_false() {
        // Arrange / Act
        let app = make_app();
        // Assert: quit flag is not set on construction
        assert!(!app.should_quit);
    }

    #[test]
    fn test_quit_flag_set_directly() {
        // Arrange
        let mut app = make_app();
        // Act: simulate the 'q' key handler setting the flag
        app.should_quit = true;
        // Assert
        assert!(app.should_quit);
    }

    #[test]
    fn test_refresh_data_updates_last_refresh() {
        // Arrange
        let mut app = make_app();
        let before = app.last_refresh;
        // Act: call refresh_data — it calls DashboardData::fetch which opens the
        // default DB, but regardless the timestamp must be updated.
        // We allow failure from the DB open and just test timing behaviour.
        app.refresh_data();
        // Assert: last_refresh has been bumped (elapsed since `before` should
        // be zero or near-zero, but last_refresh is a fresh Instant::now()).
        assert!(app.last_refresh >= before);
    }

    #[test]
    fn test_days_filter_stored_on_construction() {
        // Arrange / Act
        let app = App::new(30, 10);
        // Assert: constructor parameters are preserved
        assert_eq!(app.days_filter, 30);
    }

    // ---- T32: Tab navigation ----

    #[test]
    fn test_next_tab_wraparound() {
        let mut app = make_app();
        app.current_tab = DashboardTab::Settings;
        app.next_tab();
        assert_eq!(app.current_tab, DashboardTab::Sessions);
    }

    #[test]
    fn test_prev_tab_wraparound() {
        let mut app = make_app();
        app.current_tab = DashboardTab::Sessions;
        app.prev_tab();
        assert_eq!(app.current_tab, DashboardTab::Settings);
    }

    #[test]
    fn test_next_tab_sequential() {
        let mut app = make_app();
        app.current_tab = DashboardTab::Sessions;
        app.next_tab();
        assert_eq!(app.current_tab, DashboardTab::AuditLog);
        app.next_tab();
        assert_eq!(app.current_tab, DashboardTab::Rules);
    }

    // ---- Scroll down ----

    #[test]
    fn test_scroll_down_empty_sessions() {
        let mut app = make_app();
        app.current_tab = DashboardTab::Sessions;
        // Must not panic
        app.scroll_down();
        assert_eq!(app.sessions_table_state.selected(), None);
    }

    #[test]
    fn test_scroll_down_empty_audit() {
        let mut app = make_app();
        app.current_tab = DashboardTab::AuditLog;
        // Must not panic
        app.scroll_down();
        assert_eq!(app.audit_table_state.selected(), None);
    }

    #[test]
    fn test_scroll_down_bounds() {
        let mut app = make_app_with_sessions(3);
        app.current_tab = DashboardTab::Sessions;
        // Scroll to the end and beyond
        app.scroll_down(); // 0 -> 1
        app.scroll_down(); // 1 -> 2
        app.scroll_down(); // 2 -> 2 (saturated)
        app.scroll_down(); // still 2
        assert_eq!(app.sessions_table_state.selected(), Some(2));
    }

    #[test]
    fn test_scroll_down_audit_bounds() {
        let mut app = make_app_with_audit(2);
        app.current_tab = DashboardTab::AuditLog;
        app.scroll_down(); // 0 -> 1
        app.scroll_down(); // 1 -> 1 (saturated)
        app.scroll_down(); // still 1
        assert_eq!(app.audit_table_state.selected(), Some(1));
    }

    // ---- Scroll up ----

    #[test]
    fn test_scroll_up_at_zero_sessions() {
        let mut app = make_app_with_sessions(3);
        app.current_tab = DashboardTab::Sessions;
        app.sessions_table_state.select(Some(0));
        app.scroll_up();
        assert_eq!(app.sessions_table_state.selected(), Some(0));
    }

    #[test]
    fn test_scroll_up_at_zero_audit() {
        let mut app = make_app_with_audit(3);
        app.current_tab = DashboardTab::AuditLog;
        app.audit_table_state.select(Some(0));
        app.scroll_up();
        assert_eq!(app.audit_table_state.selected(), Some(0));
    }

    #[test]
    fn test_scroll_up_decrements() {
        let mut app = make_app_with_sessions(5);
        app.current_tab = DashboardTab::Sessions;
        app.sessions_table_state.select(Some(3));
        app.scroll_up();
        assert_eq!(app.sessions_table_state.selected(), Some(2));
    }

    // ---- Sort ----

    #[test]
    fn test_cycle_sort_column_sessions() {
        let mut app = make_app();
        app.current_tab = DashboardTab::Sessions;
        app.sessions_sort_column = 0;
        app.cycle_sort_column();
        assert_eq!(app.sessions_sort_column, 1);
        assert!(app.sessions_sort_ascending);
    }

    #[test]
    fn test_cycle_sort_column_wraps() {
        let mut app = make_app();
        app.current_tab = DashboardTab::Sessions;
        app.sessions_sort_column = 7;
        app.cycle_sort_column();
        assert_eq!(app.sessions_sort_column, 0);
    }

    #[test]
    fn test_toggle_sort_direction() {
        let mut app = make_app();
        app.current_tab = DashboardTab::Sessions;
        app.sessions_sort_ascending = true;
        app.toggle_sort_direction();
        assert!(!app.sessions_sort_ascending);
    }

    #[test]
    fn test_sort_noop_on_rules() {
        let mut app = make_app();
        app.current_tab = DashboardTab::Rules;
        let before = app.sessions_sort_column;
        app.cycle_sort_column();
        assert_eq!(app.sessions_sort_column, before);
    }

    // ---- Page navigation ----

    #[test]
    fn test_page_down_sessions() {
        let mut app = make_app_with_sessions(30);
        app.current_tab = DashboardTab::Sessions;
        app.sessions_table_state.select(Some(0));
        app.page_down();
        assert_eq!(app.sessions_table_state.selected(), Some(10));
    }

    #[test]
    fn test_page_down_bounds() {
        let mut app = make_app_with_sessions(5);
        app.current_tab = DashboardTab::Sessions;
        app.sessions_table_state.select(Some(2));
        app.page_down(); // 2 + 10 = 12, but max is 4
        assert_eq!(app.sessions_table_state.selected(), Some(4));
    }

    #[test]
    fn test_page_down_audit() {
        let mut app = make_app_with_audit(30);
        app.current_tab = DashboardTab::AuditLog;
        app.audit_table_state.select(Some(5));
        app.page_down();
        assert_eq!(app.audit_table_state.selected(), Some(15));
    }

    #[test]
    fn test_page_down_empty() {
        let mut app = make_app();
        app.current_tab = DashboardTab::Sessions;
        // Must not panic on empty data
        app.page_down();
        assert_eq!(app.sessions_table_state.selected(), None);
    }

    #[test]
    fn test_page_up_sessions() {
        let mut app = make_app_with_sessions(30);
        app.current_tab = DashboardTab::Sessions;
        app.sessions_table_state.select(Some(15));
        app.page_up();
        assert_eq!(app.sessions_table_state.selected(), Some(5));
    }

    #[test]
    fn test_page_up_at_zero() {
        let mut app = make_app_with_sessions(10);
        app.current_tab = DashboardTab::Sessions;
        app.sessions_table_state.select(Some(3));
        app.page_up(); // 3 - 10 saturates to 0
        assert_eq!(app.sessions_table_state.selected(), Some(0));
    }

    #[test]
    fn test_page_up_audit() {
        let mut app = make_app_with_audit(30);
        app.current_tab = DashboardTab::AuditLog;
        app.audit_table_state.select(Some(20));
        app.page_up();
        assert_eq!(app.audit_table_state.selected(), Some(10));
    }

    #[test]
    fn test_scroll_to_top() {
        let mut app = make_app_with_sessions(10);
        app.current_tab = DashboardTab::Sessions;
        app.sessions_table_state.select(Some(7));
        app.scroll_to_top();
        assert_eq!(app.sessions_table_state.selected(), Some(0));
    }

    #[test]
    fn test_scroll_to_top_audit() {
        let mut app = make_app_with_audit(10);
        app.current_tab = DashboardTab::AuditLog;
        app.audit_table_state.select(Some(5));
        app.scroll_to_top();
        assert_eq!(app.audit_table_state.selected(), Some(0));
    }

    #[test]
    fn test_scroll_to_top_rules() {
        let mut app = make_app();
        app.current_tab = DashboardTab::Rules;
        app.rules_scroll_offset = 42;
        app.scroll_to_top();
        assert_eq!(app.rules_scroll_offset, 0);
    }

    #[test]
    fn test_scroll_to_bottom_sessions() {
        let mut app = make_app_with_sessions(20);
        app.current_tab = DashboardTab::Sessions;
        app.sessions_table_state.select(Some(0));
        app.scroll_to_bottom();
        assert_eq!(app.sessions_table_state.selected(), Some(19));
    }

    #[test]
    fn test_scroll_to_bottom_audit() {
        let mut app = make_app_with_audit(15);
        app.current_tab = DashboardTab::AuditLog;
        app.audit_table_state.select(Some(0));
        app.scroll_to_bottom();
        assert_eq!(app.audit_table_state.selected(), Some(14));
    }

    #[test]
    fn test_scroll_to_bottom_empty() {
        let mut app = make_app();
        app.current_tab = DashboardTab::Sessions;
        // Must not panic on empty sessions
        app.scroll_to_bottom();
        assert_eq!(app.sessions_table_state.selected(), None);
    }

    #[test]
    fn test_scroll_to_bottom_empty_audit() {
        let mut app = make_app();
        app.current_tab = DashboardTab::AuditLog;
        // Must not panic on empty audit
        app.scroll_to_bottom();
        assert_eq!(app.audit_table_state.selected(), None);
    }

    #[test]
    fn test_page_down_rules() {
        let mut app = make_app();
        app.current_tab = DashboardTab::Rules;
        app.rules_scroll_offset = 5;
        app.page_down();
        assert_eq!(app.rules_scroll_offset, 15);
    }

    #[test]
    fn test_page_up_rules() {
        let mut app = make_app();
        app.current_tab = DashboardTab::Rules;
        app.rules_scroll_offset = 3;
        app.page_up(); // 3 - 10 saturates to 0
        assert_eq!(app.rules_scroll_offset, 0);
    }
}
