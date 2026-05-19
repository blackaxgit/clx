//! Pure reducer tests. No terminal, no I/O.
//!
//! Each test builds an `AppState`, drives a `DashboardEvent` through `update`,
//! and asserts on the resulting `(state', cmds)` tuple. Side-effect commands
//! are captured as `DashboardCmd` values; the runtime layer is not exercised.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use super::super::app::{DashboardTab, DetailTab, ExitTarget, InputMode, ScreenState};
use super::{AppState, DashboardCmd, DashboardEvent, update};

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn key(c: char) -> DashboardEvent {
    DashboardEvent::Key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE))
}

fn keycode(code: KeyCode) -> DashboardEvent {
    DashboardEvent::Key(KeyEvent::new(code, KeyModifiers::NONE))
}

fn ctrl_key(c: char) -> DashboardEvent {
    DashboardEvent::Key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::CONTROL))
}

fn state_with_sessions(n: usize) -> AppState {
    let mut s = AppState::new();
    s.sessions_count = n;
    s
}

fn state_with_audit(n: usize) -> AppState {
    let mut s = AppState::new();
    s.audit_count = n;
    s
}

// ---------------------------------------------------------------------------
// Quit / Tick / Resize
// ---------------------------------------------------------------------------

#[test]
fn test_quit_event_sets_quit_and_emits_cmd() {
    let (s, cmds) = update(AppState::new(), DashboardEvent::Quit);
    assert!(s.should_quit);
    assert_eq!(cmds, vec![DashboardCmd::Quit]);
}

#[test]
fn test_tick_is_noop() {
    let s0 = AppState::new();
    let (s1, cmds) = update(s0.clone(), DashboardEvent::Tick);
    assert_eq!(s0, s1);
    assert!(cmds.is_empty());
}

#[test]
fn test_resize_is_noop() {
    let s0 = AppState::new();
    let (s1, cmds) = update(s0.clone(), DashboardEvent::Resize(120, 40));
    assert_eq!(s0, s1);
    assert!(cmds.is_empty());
}

// ---------------------------------------------------------------------------
// Normal mode: quit
// ---------------------------------------------------------------------------

#[test]
fn test_q_key_quits() {
    let (s, cmds) = update(AppState::new(), key('q'));
    assert!(s.should_quit);
    assert_eq!(cmds, vec![DashboardCmd::Quit]);
}

#[test]
fn test_esc_key_quits_in_normal_mode() {
    let (s, cmds) = update(AppState::new(), keycode(KeyCode::Esc));
    assert!(s.should_quit);
    assert_eq!(cmds, vec![DashboardCmd::Quit]);
}

// ---------------------------------------------------------------------------
// Tab navigation
// ---------------------------------------------------------------------------

#[test]
fn test_tab_advances() {
    let (s, _) = update(AppState::new(), keycode(KeyCode::Tab));
    assert_eq!(s.current_tab, DashboardTab::AuditLog);
}

#[test]
fn test_back_tab_wraps_to_last() {
    let (s, _) = update(AppState::new(), keycode(KeyCode::BackTab));
    assert_eq!(s.current_tab, DashboardTab::Settings);
}

#[test]
fn test_tab_wrap_from_settings_to_sessions() {
    let mut s = AppState::new();
    s.current_tab = DashboardTab::Settings;
    let (s, cmds) = update(s, keycode(KeyCode::Tab));
    assert_eq!(s.current_tab, DashboardTab::Sessions);
    // Leaving Settings does not emit EnterSettings.
    assert!(!cmds.contains(&DashboardCmd::EnterSettings));
}

#[test]
fn test_tab_to_settings_emits_enter_settings() {
    let mut s = AppState::new();
    s.current_tab = DashboardTab::Rules;
    let (s, cmds) = update(s, keycode(KeyCode::Tab));
    assert_eq!(s.current_tab, DashboardTab::Settings);
    assert!(cmds.contains(&DashboardCmd::EnterSettings));
}

#[test]
fn test_switch_to_tab_1() {
    let mut s = AppState::new();
    s.current_tab = DashboardTab::Rules;
    let (s, _) = update(s, key('1'));
    assert_eq!(s.current_tab, DashboardTab::Sessions);
}

#[test]
fn test_switch_to_tab_2() {
    let (s, _) = update(AppState::new(), key('2'));
    assert_eq!(s.current_tab, DashboardTab::AuditLog);
}

#[test]
fn test_switch_to_tab_3() {
    let (s, _) = update(AppState::new(), key('3'));
    assert_eq!(s.current_tab, DashboardTab::Rules);
}

#[test]
fn test_switch_to_tab_4_emits_enter_settings() {
    let (s, cmds) = update(AppState::new(), key('4'));
    assert_eq!(s.current_tab, DashboardTab::Settings);
    assert!(cmds.contains(&DashboardCmd::EnterSettings));
}

// ---------------------------------------------------------------------------
// Scrolling: sessions
// ---------------------------------------------------------------------------

#[test]
fn test_scroll_down_empty_sessions_noop() {
    let s = AppState::new();
    let (s, _) = update(s, key('j'));
    assert_eq!(s.sessions_selected, None);
}

#[test]
fn test_scroll_down_sessions_advances() {
    let s = state_with_sessions(5);
    let (s, _) = update(s, key('j'));
    assert_eq!(s.sessions_selected, Some(1));
}

#[test]
fn test_scroll_down_arrow_key_advances() {
    let s = state_with_sessions(5);
    let (s, _) = update(s, keycode(KeyCode::Down));
    assert_eq!(s.sessions_selected, Some(1));
}

#[test]
fn test_scroll_down_saturates_at_max() {
    let mut s = state_with_sessions(3);
    s.sessions_selected = Some(2);
    let (s, _) = update(s, key('j'));
    assert_eq!(s.sessions_selected, Some(2));
}

#[test]
fn test_scroll_up_sessions_decrements() {
    let mut s = state_with_sessions(5);
    s.sessions_selected = Some(3);
    let (s, _) = update(s, key('k'));
    assert_eq!(s.sessions_selected, Some(2));
}

#[test]
fn test_scroll_up_saturates_at_zero() {
    let mut s = state_with_sessions(5);
    s.sessions_selected = Some(0);
    let (s, _) = update(s, key('k'));
    assert_eq!(s.sessions_selected, Some(0));
}

// ---------------------------------------------------------------------------
// Scrolling: audit
// ---------------------------------------------------------------------------

#[test]
fn test_audit_scroll_down() {
    let mut s = state_with_audit(5);
    s.current_tab = DashboardTab::AuditLog;
    let (s, _) = update(s, key('j'));
    assert_eq!(s.audit_selected, Some(1));
}

#[test]
fn test_audit_scroll_up() {
    let mut s = state_with_audit(5);
    s.current_tab = DashboardTab::AuditLog;
    s.audit_selected = Some(3);
    let (s, _) = update(s, key('k'));
    assert_eq!(s.audit_selected, Some(2));
}

// ---------------------------------------------------------------------------
// Page navigation
// ---------------------------------------------------------------------------

#[test]
fn test_page_down_sessions() {
    let mut s = state_with_sessions(30);
    s.sessions_selected = Some(0);
    let (s, _) = update(s, keycode(KeyCode::PageDown));
    assert_eq!(s.sessions_selected, Some(10));
}

#[test]
fn test_page_down_clamps_to_max() {
    let mut s = state_with_sessions(5);
    s.sessions_selected = Some(2);
    let (s, _) = update(s, keycode(KeyCode::PageDown));
    assert_eq!(s.sessions_selected, Some(4));
}

#[test]
fn test_page_up_sessions() {
    let mut s = state_with_sessions(30);
    s.sessions_selected = Some(15);
    let (s, _) = update(s, keycode(KeyCode::PageUp));
    assert_eq!(s.sessions_selected, Some(5));
}

#[test]
fn test_page_up_saturates_at_zero() {
    let mut s = state_with_sessions(20);
    s.sessions_selected = Some(3);
    let (s, _) = update(s, keycode(KeyCode::PageUp));
    assert_eq!(s.sessions_selected, Some(0));
}

#[test]
fn test_page_down_rules_increments_offset() {
    let mut s = AppState::new();
    s.current_tab = DashboardTab::Rules;
    s.rules_scroll_offset = 5;
    let (s, _) = update(s, keycode(KeyCode::PageDown));
    assert_eq!(s.rules_scroll_offset, 15);
}

#[test]
fn test_page_up_rules_decrements_offset() {
    let mut s = AppState::new();
    s.current_tab = DashboardTab::Rules;
    s.rules_scroll_offset = 3;
    let (s, _) = update(s, keycode(KeyCode::PageUp));
    assert_eq!(s.rules_scroll_offset, 0);
}

// ---------------------------------------------------------------------------
// Scroll-to-top / bottom
// ---------------------------------------------------------------------------

#[test]
fn test_g_lower_scrolls_to_top() {
    let mut s = state_with_sessions(10);
    s.sessions_selected = Some(5);
    let (s, _) = update(s, key('g'));
    assert_eq!(s.sessions_selected, Some(0));
}

#[test]
fn test_home_scrolls_to_top() {
    let mut s = state_with_sessions(10);
    s.sessions_selected = Some(5);
    let (s, _) = update(s, keycode(KeyCode::Home));
    assert_eq!(s.sessions_selected, Some(0));
}

#[test]
fn test_g_upper_scrolls_to_bottom() {
    let s = state_with_sessions(7);
    let (s, _) = update(s, key('G'));
    assert_eq!(s.sessions_selected, Some(6));
}

#[test]
fn test_end_scrolls_to_bottom() {
    let s = state_with_sessions(4);
    let (s, _) = update(s, keycode(KeyCode::End));
    assert_eq!(s.sessions_selected, Some(3));
}

#[test]
fn test_scroll_to_bottom_empty_noop() {
    let (s, _) = update(AppState::new(), key('G'));
    assert_eq!(s.sessions_selected, None);
}

// ---------------------------------------------------------------------------
// Sort
// ---------------------------------------------------------------------------

#[test]
fn test_s_lower_cycles_sort_column_sessions() {
    let (s, _) = update(AppState::new(), key('s'));
    assert_eq!(s.sessions_sort_column, 3); // 2 -> 3
    assert!(s.sessions_sort_ascending);
}

#[test]
fn test_s_lower_wraps_sort_column() {
    let mut s = AppState::new();
    s.sessions_sort_column = 7;
    let (s, _) = update(s, key('s'));
    assert_eq!(s.sessions_sort_column, 0);
}

#[test]
fn test_s_upper_toggles_sort_direction() {
    let mut s = AppState::new();
    s.sessions_sort_ascending = true;
    let (s, _) = update(s, key('S'));
    assert!(!s.sessions_sort_ascending);
}

#[test]
fn test_audit_cycle_sort_column() {
    let mut s = AppState::new();
    s.current_tab = DashboardTab::AuditLog;
    let (s, _) = update(s, key('s'));
    assert_eq!(s.audit_sort_column, 1);
    assert!(s.audit_sort_ascending);
}

#[test]
fn test_sort_noop_on_rules() {
    let mut s = AppState::new();
    s.current_tab = DashboardTab::Rules;
    let before = s.sessions_sort_column;
    let (s, _) = update(s, key('s'));
    assert_eq!(s.sessions_sort_column, before);
}

// ---------------------------------------------------------------------------
// Refresh
// ---------------------------------------------------------------------------

#[test]
fn test_r_lower_emits_refresh_in_normal_mode() {
    let (_, cmds) = update(AppState::new(), key('r'));
    assert_eq!(cmds, vec![DashboardCmd::RefreshData]);
}

// ---------------------------------------------------------------------------
// Enter on Sessions tab
// ---------------------------------------------------------------------------

#[test]
fn test_enter_with_no_sessions_does_not_drill_in() {
    let (_, cmds) = update(AppState::new(), keycode(KeyCode::Enter));
    assert!(!cmds.contains(&DashboardCmd::EnterSessionDetail));
}

#[test]
fn test_enter_with_sessions_emits_drill_in() {
    let s = state_with_sessions(2);
    let (_, cmds) = update(s, keycode(KeyCode::Enter));
    assert_eq!(cmds, vec![DashboardCmd::EnterSessionDetail]);
}

#[test]
fn test_enter_on_audit_tab_does_not_drill_in() {
    let mut s = state_with_sessions(2);
    s.current_tab = DashboardTab::AuditLog;
    let (_, cmds) = update(s, keycode(KeyCode::Enter));
    assert!(!cmds.contains(&DashboardCmd::EnterSessionDetail));
}

// ---------------------------------------------------------------------------
// Filter mode
// ---------------------------------------------------------------------------

#[test]
fn test_slash_enters_filter_mode() {
    let (s, _) = update(AppState::new(), key('/'));
    assert_eq!(s.input_mode, InputMode::Filter);
    assert!(s.filter_text.is_empty());
}

#[test]
fn test_filter_char_appends() {
    let mut s = AppState::new();
    s.input_mode = InputMode::Filter;
    let (s, _) = update(s, key('a'));
    let (s, _) = update(s, key('b'));
    assert_eq!(s.filter_text, "ab");
}

#[test]
fn test_filter_backspace_pops() {
    let mut s = AppState::new();
    s.input_mode = InputMode::Filter;
    s.filter_text = "abc".to_owned();
    let (s, _) = update(s, keycode(KeyCode::Backspace));
    assert_eq!(s.filter_text, "ab");
}

#[test]
fn test_filter_enter_commits_and_returns_to_normal() {
    let mut s = AppState::new();
    s.input_mode = InputMode::Filter;
    s.filter_text = "abc".to_owned();
    let (s, _) = update(s, keycode(KeyCode::Enter));
    assert_eq!(s.input_mode, InputMode::Normal);
    assert_eq!(s.filter_text, "abc");
}

#[test]
fn test_filter_esc_clears_and_returns_to_normal() {
    let mut s = AppState::new();
    s.input_mode = InputMode::Filter;
    s.filter_text = "abc".to_owned();
    let (s, _) = update(s, keycode(KeyCode::Esc));
    assert_eq!(s.input_mode, InputMode::Normal);
    assert!(s.filter_text.is_empty());
}

// ---------------------------------------------------------------------------
// Settings nav: dirty-exit guard
// ---------------------------------------------------------------------------

fn settings_nav() -> AppState {
    let mut s = AppState::new();
    s.current_tab = DashboardTab::Settings;
    s.input_mode = InputMode::SettingsNav;
    s
}

#[test]
fn test_settings_q_when_clean_returns_to_sessions() {
    let s = settings_nav();
    let (s, cmds) = update(s, key('q'));
    assert_eq!(s.current_tab, DashboardTab::Sessions);
    assert_eq!(s.input_mode, InputMode::Normal);
    assert!(!cmds.contains(&DashboardCmd::Quit));
}

#[test]
fn test_settings_q_when_dirty_arms_exit_pending_quit() {
    let mut s = settings_nav();
    s.settings_is_dirty = true;
    let (s, _) = update(s, key('q'));
    assert_eq!(s.settings_exit_pending, Some(ExitTarget::Quit));
}

#[test]
fn test_settings_tab_when_dirty_arms_exit_pending_tab() {
    let mut s = settings_nav();
    s.settings_is_dirty = true;
    let (s, _) = update(s, keycode(KeyCode::Tab));
    // Settings index is 3; next is 0 -> Sessions.
    assert_eq!(
        s.settings_exit_pending,
        Some(ExitTarget::Tab(DashboardTab::Sessions))
    );
}

#[test]
fn test_settings_back_tab_when_dirty_arms_exit_pending_tab() {
    let mut s = settings_nav();
    s.settings_is_dirty = true;
    let (s, _) = update(s, keycode(KeyCode::BackTab));
    assert_eq!(
        s.settings_exit_pending,
        Some(ExitTarget::Tab(DashboardTab::Rules))
    );
}

#[test]
fn test_settings_digit_1_when_dirty_arms_exit_pending_tab() {
    let mut s = settings_nav();
    s.settings_is_dirty = true;
    let (s, _) = update(s, key('1'));
    assert_eq!(
        s.settings_exit_pending,
        Some(ExitTarget::Tab(DashboardTab::Sessions))
    );
}

#[test]
fn test_exit_pending_s_saves_and_executes_exit() {
    let mut s = settings_nav();
    s.settings_is_dirty = true;
    s.settings_exit_pending = Some(ExitTarget::Quit);
    let (s, cmds) = update(s, key('s'));
    assert_eq!(s.settings_exit_pending, None);
    assert!(cmds.contains(&DashboardCmd::SettingsSave));
    assert!(cmds.contains(&DashboardCmd::ExecuteExitTarget(ExitTarget::Quit)));
}

#[test]
fn test_exit_pending_x_discards_and_executes_exit() {
    let mut s = settings_nav();
    s.settings_is_dirty = true;
    s.settings_exit_pending = Some(ExitTarget::Tab(DashboardTab::Sessions));
    let (s, cmds) = update(s, key('x'));
    assert_eq!(s.settings_exit_pending, None);
    assert!(cmds.contains(&DashboardCmd::SettingsDiscardChanges));
    assert!(
        cmds.contains(&DashboardCmd::ExecuteExitTarget(ExitTarget::Tab(
            DashboardTab::Sessions
        )))
    );
}

#[test]
fn test_exit_pending_esc_cancels_exit_only() {
    let mut s = settings_nav();
    s.settings_is_dirty = true;
    s.settings_exit_pending = Some(ExitTarget::Quit);
    let (s, cmds) = update(s, keycode(KeyCode::Esc));
    assert_eq!(s.settings_exit_pending, None);
    assert!(cmds.is_empty());
}

// ---------------------------------------------------------------------------
// Settings nav: reload confirm
// ---------------------------------------------------------------------------

#[test]
fn test_settings_r_when_dirty_arms_reload_confirm() {
    let mut s = settings_nav();
    s.settings_is_dirty = true;
    let (s, cmds) = update(s, key('r'));
    assert!(s.settings_reload_confirm);
    assert!(!cmds.contains(&DashboardCmd::SettingsReload));
}

#[test]
fn test_settings_r_when_clean_reloads_directly() {
    let s = settings_nav();
    let (s, cmds) = update(s, key('r'));
    assert!(!s.settings_reload_confirm);
    assert!(cmds.contains(&DashboardCmd::SettingsReload));
}

#[test]
fn test_reload_confirm_y_emits_reload() {
    let mut s = settings_nav();
    s.settings_reload_confirm = true;
    let (s, cmds) = update(s, key('y'));
    assert!(!s.settings_reload_confirm);
    assert!(cmds.contains(&DashboardCmd::SettingsReload));
}

#[test]
fn test_reload_confirm_n_dismisses() {
    let mut s = settings_nav();
    s.settings_reload_confirm = true;
    let (s, cmds) = update(s, key('n'));
    assert!(!s.settings_reload_confirm);
    assert!(cmds.is_empty());
}

#[test]
fn test_reload_confirm_esc_dismisses() {
    let mut s = settings_nav();
    s.settings_reload_confirm = true;
    let (s, cmds) = update(s, keycode(KeyCode::Esc));
    assert!(!s.settings_reload_confirm);
    assert!(cmds.is_empty());
}

// ---------------------------------------------------------------------------
// Settings nav: reset-all confirm
// ---------------------------------------------------------------------------

#[test]
fn test_settings_uppercase_r_when_dirty_arms_reset_confirm() {
    let mut s = settings_nav();
    s.settings_is_dirty = true;
    let (s, _) = update(s, key('R'));
    assert!(s.settings_confirm_reset);
}

#[test]
fn test_settings_uppercase_r_when_clean_does_nothing() {
    let s = settings_nav();
    let (s, _) = update(s, key('R'));
    assert!(!s.settings_confirm_reset);
}

#[test]
fn test_reset_confirm_y_emits_reset_and_clears_flag() {
    let mut s = settings_nav();
    s.settings_confirm_reset = true;
    s.settings_edit_error = Some("err".to_owned());
    let (s, cmds) = update(s, key('y'));
    assert!(!s.settings_confirm_reset);
    assert!(s.settings_edit_error.is_none());
    assert!(cmds.contains(&DashboardCmd::SettingsResetConfirmed));
}

#[test]
fn test_reset_confirm_n_dismisses() {
    let mut s = settings_nav();
    s.settings_confirm_reset = true;
    let (s, cmds) = update(s, key('n'));
    assert!(!s.settings_confirm_reset);
    assert!(cmds.is_empty());
}

#[test]
fn test_reset_confirm_esc_dismisses() {
    let mut s = settings_nav();
    s.settings_confirm_reset = true;
    let (s, _) = update(s, keycode(KeyCode::Esc));
    assert!(!s.settings_confirm_reset);
}

// ---------------------------------------------------------------------------
// Settings nav: section navigation
// ---------------------------------------------------------------------------

#[test]
fn test_settings_l_advances_section() {
    let s = settings_nav();
    let (s, _) = update(s, key('l'));
    assert_eq!(s.settings_section_idx, 1);
    assert_eq!(s.settings_field_idx, 0);
}

#[test]
fn test_settings_h_retreats_section_with_wrap() {
    let s = settings_nav();
    let (s, _) = update(s, key('h'));
    let count = crate::dashboard::settings::sections::SECTIONS.len();
    assert_eq!(s.settings_section_idx, count - 1);
}

#[test]
fn test_settings_right_arrow_advances_section() {
    let s = settings_nav();
    let (s, _) = update(s, keycode(KeyCode::Right));
    assert_eq!(s.settings_section_idx, 1);
}

#[test]
fn test_settings_left_arrow_retreats_section() {
    let mut s = settings_nav();
    s.settings_section_idx = 2;
    let (s, _) = update(s, keycode(KeyCode::Left));
    assert_eq!(s.settings_section_idx, 1);
}

// ---------------------------------------------------------------------------
// Settings nav: space/enter triggers edit (when no load error)
// ---------------------------------------------------------------------------

#[test]
fn test_settings_space_emits_edit_field() {
    let s = settings_nav();
    let (_, cmds) = update(s, key(' '));
    assert!(cmds.contains(&DashboardCmd::SettingsEditField));
}

#[test]
fn test_settings_enter_emits_edit_field() {
    let s = settings_nav();
    let (_, cmds) = update(s, keycode(KeyCode::Enter));
    assert!(cmds.contains(&DashboardCmd::SettingsEditField));
}

#[test]
fn test_settings_space_blocked_by_load_error() {
    let mut s = settings_nav();
    s.settings_load_error = Some("err".to_owned());
    let (_, cmds) = update(s, key(' '));
    assert!(!cmds.contains(&DashboardCmd::SettingsEditField));
}

#[test]
fn test_settings_d_emits_reset_field() {
    let s = settings_nav();
    let (_, cmds) = update(s, key('d'));
    assert!(cmds.contains(&DashboardCmd::SettingsResetField));
}

#[test]
fn test_settings_d_blocked_by_load_error() {
    let mut s = settings_nav();
    s.settings_load_error = Some("err".to_owned());
    let (_, cmds) = update(s, key('d'));
    assert!(!cmds.contains(&DashboardCmd::SettingsResetField));
}

#[test]
fn test_settings_s_emits_save() {
    let s = settings_nav();
    let (_, cmds) = update(s, key('s'));
    assert!(cmds.contains(&DashboardCmd::SettingsSave));
}

// ---------------------------------------------------------------------------
// Settings edit mode (popup)
// ---------------------------------------------------------------------------

fn settings_edit() -> AppState {
    let mut s = AppState::new();
    s.current_tab = DashboardTab::Settings;
    s.input_mode = InputMode::SettingsEdit;
    s
}

#[test]
fn test_settings_edit_char_appends_buffer() {
    let s = settings_edit();
    let (s, _) = update(s, key('5'));
    let (s, _) = update(s, key('0'));
    assert_eq!(s.settings_edit_buffer, "50");
}

#[test]
fn test_settings_edit_backspace_pops_buffer() {
    let mut s = settings_edit();
    s.settings_edit_buffer = "123".to_owned();
    let (s, _) = update(s, keycode(KeyCode::Backspace));
    assert_eq!(s.settings_edit_buffer, "12");
}

#[test]
fn test_settings_edit_ctrl_u_clears_buffer() {
    let mut s = settings_edit();
    s.settings_edit_buffer = "abc".to_owned();
    let (s, _) = update(s, ctrl_key('u'));
    assert!(s.settings_edit_buffer.is_empty());
}

#[test]
fn test_settings_edit_esc_cancels_and_clears() {
    let mut s = settings_edit();
    s.settings_edit_buffer = "abc".to_owned();
    s.settings_edit_error = Some("err".to_owned());
    let (s, _) = update(s, keycode(KeyCode::Esc));
    assert_eq!(s.input_mode, InputMode::SettingsNav);
    assert!(s.settings_edit_buffer.is_empty());
    assert!(s.settings_edit_error.is_none());
}

#[test]
fn test_settings_edit_enter_emits_commit() {
    let mut s = settings_edit();
    s.settings_edit_buffer = "42".to_owned();
    let (_, cmds) = update(s, keycode(KeyCode::Enter));
    assert!(cmds.contains(&DashboardCmd::SettingsCommitEdit));
}

// ---------------------------------------------------------------------------
// Detail mode
// ---------------------------------------------------------------------------

fn detail_state() -> AppState {
    let mut s = AppState::new();
    s.screen_state = ScreenState::SessionDetail("sid".to_owned());
    s
}

#[test]
fn test_detail_q_emits_leave() {
    let (_, cmds) = update(detail_state(), key('q'));
    assert!(cmds.contains(&DashboardCmd::LeaveSessionDetail));
}

#[test]
fn test_detail_esc_emits_leave() {
    let (_, cmds) = update(detail_state(), keycode(KeyCode::Esc));
    assert!(cmds.contains(&DashboardCmd::LeaveSessionDetail));
}

#[test]
fn test_detail_tab_advances() {
    let (s, _) = update(detail_state(), keycode(KeyCode::Tab));
    assert_eq!(s.detail_tab, DetailTab::Commands);
}

#[test]
fn test_detail_back_tab_wraps() {
    let (s, _) = update(detail_state(), keycode(KeyCode::BackTab));
    assert_eq!(s.detail_tab, DetailTab::Snapshots);
}

#[test]
fn test_detail_digit_switches_subtab() {
    let (s, _) = update(detail_state(), key('3'));
    assert_eq!(s.detail_tab, DetailTab::Audit);
}

#[test]
fn test_detail_r_emits_refresh() {
    let (_, cmds) = update(detail_state(), key('r'));
    assert!(cmds.contains(&DashboardCmd::RefreshData));
}

// ---------------------------------------------------------------------------
// Misc
// ---------------------------------------------------------------------------

#[test]
fn test_unknown_key_is_noop() {
    let s0 = AppState::new();
    let (s1, cmds) = update(
        s0.clone(),
        DashboardEvent::Key(KeyEvent::new(KeyCode::F(5), KeyModifiers::NONE)),
    );
    assert_eq!(s0, s1);
    assert!(cmds.is_empty());
}

#[test]
fn test_default_state_is_consistent() {
    let s = AppState::default();
    assert_eq!(s.current_tab, DashboardTab::Sessions);
    assert!(!s.should_quit);
    assert_eq!(s.input_mode, InputMode::Normal);
    assert!(s.filter_text.is_empty());
}

#[test]
fn test_normal_mode_unknown_char_noop() {
    let s0 = AppState::new();
    let (s1, cmds) = update(s0.clone(), key('z'));
    assert_eq!(s0, s1);
    assert!(cmds.is_empty());
}
