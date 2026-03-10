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

impl DashboardTab {
    pub const ALL: [DashboardTab; 4] = [Self::Sessions, Self::AuditLog, Self::Rules, Self::Settings];

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

    // Settings tab state
    pub settings_section_idx: usize,
    pub settings_field_idx: usize,
    pub settings_field_table_state: TableState,
    pub settings_original_config: Option<Config>,
    pub settings_editing_config: Option<Config>,
    // Settings editing state
    pub settings_is_dirty: bool,
    #[allow(dead_code)]
    pub settings_edit_buffer: String,
    pub settings_edit_error: Option<String>,
    pub settings_save_result: Option<String>,
    #[allow(dead_code)]
    pub settings_confirm_reset: bool,
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
            settings_section_idx: 0,
            settings_field_idx: 0,
            settings_field_table_state: TableState::default(),
            settings_original_config: None,
            settings_editing_config: None,
            settings_is_dirty: false,
            settings_edit_buffer: String::new(),
            settings_edit_error: None,
            settings_save_result: None,
            settings_confirm_reset: false,
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
        self.last_refresh = Instant::now();
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
            let config: Config = match Config::load() {
                Ok(c) => c,
                Err(e) => {
                    self.settings_save_result = Some(format!("Load error: {e}"));
                    Config::default()
                }
            };
            self.settings_editing_config = Some(config.clone());
            self.settings_original_config = Some(config);
        }
        self.settings_field_table_state
            .select(Some(self.settings_field_idx));
        self.input_mode = InputMode::SettingsNav;
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
