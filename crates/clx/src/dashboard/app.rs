use std::time::{Duration, Instant};

use ratatui::widgets::TableState;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DashboardTab {
    Sessions,
    AuditLog,
    Rules,
}

impl DashboardTab {
    pub const ALL: [DashboardTab; 3] = [Self::Sessions, Self::AuditLog, Self::Rules];

    pub fn title(self) -> &'static str {
        match self {
            Self::Sessions => "Sessions",
            Self::AuditLog => "Audit Log",
            Self::Rules => "Rules",
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
            DashboardTab::Rules => {}
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
            DashboardTab::Rules => {}
        }
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
        app.current_tab = DashboardTab::Rules;
        app.next_tab();
        assert_eq!(app.current_tab, DashboardTab::Sessions);
    }

    #[test]
    fn test_prev_tab_wraparound() {
        let mut app = make_app();
        app.current_tab = DashboardTab::Sessions;
        app.prev_tab();
        assert_eq!(app.current_tab, DashboardTab::Rules);
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
