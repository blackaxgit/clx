use clx_core::config::{Config, ContextPressureMode, DefaultDecision};

use crate::dashboard::app::App;

/// Extract the current string value of a field for display.
///
/// Returns the value as a human-readable string. For unknown section/field
/// combinations, returns "???".
#[must_use]
pub fn get_field_value(config: &Config, section: usize, field: usize) -> String {
    match (section, field) {
        // Section 0: Validator
        (0, 0) => config.validator.enabled.to_string(),
        (0, 1) => config.validator.layer1_enabled.to_string(),
        (0, 2) => config.validator.layer1_timeout_ms.to_string(),
        (0, 3) => config.validator.default_decision.to_string(),
        (0, 4) => config.validator.trust_mode.to_string(),
        (0, 5) => config.validator.auto_allow_reads.to_string(),

        // Section 1: Context
        (1, 0) => config.context.enabled.to_string(),
        (1, 1) => config.context.auto_snapshot.to_string(),
        (1, 2) => config.context.embedding_model.clone(),

        // Section 2: Ollama
        (2, 0) => config.ollama.host.clone(),
        (2, 1) => config.ollama.model.clone(),
        (2, 2) => config.ollama.embedding_model.clone(),
        (2, 3) => config.ollama.embedding_dim.to_string(),
        (2, 4) => config.ollama.timeout_ms.to_string(),
        (2, 5) => config.ollama.max_retries.to_string(),
        (2, 6) => config.ollama.retry_delay_ms.to_string(),
        (2, 7) => format!("{:.1}", config.ollama.retry_backoff),

        // Section 3: User Learning
        (3, 0) => config.user_learning.enabled.to_string(),
        (3, 1) => config.user_learning.auto_whitelist_threshold.to_string(),
        (3, 2) => config.user_learning.auto_blacklist_threshold.to_string(),

        // Section 4: Logging
        (4, 0) => config.logging.level.clone(),
        (4, 1) => config.logging.file.clone(),
        (4, 2) => config.logging.max_size_mb.to_string(),
        (4, 3) => config.logging.max_files.to_string(),

        // Section 5: Context Pressure
        (5, 0) => config.context_pressure.mode.to_string(),
        (5, 1) => config.context_pressure.context_window_size.to_string(),
        (5, 2) => format!("{:.2}", config.context_pressure.threshold),

        // Section 6: Session Recovery
        (6, 0) => config.session_recovery.enabled.to_string(),
        (6, 1) => config.session_recovery.stale_hours.to_string(),

        // Section 7: MCP Tools
        (7, 0) => config.mcp_tools.enabled.to_string(),
        (7, 1) => config.mcp_tools.default_decision.to_string(),
        (7, 2) => format!("{} tools", config.mcp_tools.command_tools.len()),

        _ => "???".to_string(),
    }
}

/// Get the default value string for a field (from `Config::default()`).
#[must_use]
pub fn get_default_value(section: usize, field: usize) -> String {
    let defaults = Config::default();
    get_field_value(&defaults, section, field)
}

/// Toggle a boolean field in the config.
///
/// Only operates on fields whose widget type is `Toggle`. Non-bool fields
/// are silently ignored.
pub fn toggle_field(config: &mut Config, section: usize, field: usize) {
    match (section, field) {
        // Section 0: Validator
        (0, 0) => config.validator.enabled = !config.validator.enabled,
        (0, 1) => config.validator.layer1_enabled = !config.validator.layer1_enabled,
        (0, 4) => config.validator.trust_mode = !config.validator.trust_mode,
        (0, 5) => config.validator.auto_allow_reads = !config.validator.auto_allow_reads,

        // Section 1: Context
        (1, 0) => config.context.enabled = !config.context.enabled,
        (1, 1) => config.context.auto_snapshot = !config.context.auto_snapshot,

        // Section 3: User Learning
        (3, 0) => config.user_learning.enabled = !config.user_learning.enabled,

        // Section 6: Session Recovery
        (6, 0) => config.session_recovery.enabled = !config.session_recovery.enabled,

        // Section 7: MCP Tools
        (7, 0) => config.mcp_tools.enabled = !config.mcp_tools.enabled,

        _ => {} // Not a toggle field
    }
}

/// Cycle an enum/cycle-select field to its next option.
///
/// Only operates on fields whose widget type is `CycleSelect`. Other fields
/// are silently ignored.
pub fn cycle_field(config: &mut Config, section: usize, field: usize) {
    match (section, field) {
        // Section 0: Validator — default_decision (ask → allow → deny → ask)
        (0, 3) => {
            config.validator.default_decision = match config.validator.default_decision {
                DefaultDecision::Ask => DefaultDecision::Allow,
                DefaultDecision::Allow => DefaultDecision::Deny,
                DefaultDecision::Deny => DefaultDecision::Ask,
            };
        }

        // Section 4: Logging — level (trace → debug → info → warn → error → trace)
        (4, 0) => {
            config.logging.level = match config.logging.level.as_str() {
                "trace" => "debug".to_owned(),
                "debug" => "info".to_owned(),
                "info" => "warn".to_owned(),
                "warn" => "error".to_owned(),
                _ => "trace".to_owned(),
            };
        }

        // Section 5: Context Pressure — mode (auto → notify → disabled → auto)
        (5, 0) => {
            config.context_pressure.mode = match config.context_pressure.mode {
                ContextPressureMode::Auto => ContextPressureMode::Notify,
                ContextPressureMode::Notify => ContextPressureMode::Disabled,
                ContextPressureMode::Disabled => ContextPressureMode::Auto,
            };
        }

        // Section 7: MCP Tools — default_decision (ask → allow → deny → ask)
        (7, 1) => {
            config.mcp_tools.default_decision = match config.mcp_tools.default_decision {
                DefaultDecision::Ask => DefaultDecision::Allow,
                DefaultDecision::Allow => DefaultDecision::Deny,
                DefaultDecision::Deny => DefaultDecision::Ask,
            };
        }

        _ => {} // Not a cycle field
    }
}

/// Recompute the dirty flag by comparing original and editing configs.
pub fn recompute_dirty(app: &mut App) {
    app.settings_is_dirty = match (&app.settings_original_config, &app.settings_editing_config) {
        (Some(orig), Some(edit)) => orig != edit,
        _ => false,
    };
}

/// Returns `true` if `trust_mode` was just toggled from `false` to `true`.
///
/// Call this *before* toggling to detect the dangerous transition.
#[must_use]
pub fn is_trust_mode_enabling(config: &Config, section: usize, field: usize) -> bool {
    section == 0 && field == 4 && !config.validator.trust_mode
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dashboard::settings::fields::ALL_SECTION_FIELDS;
    use crate::dashboard::settings::sections::SECTIONS;

    #[test]
    fn test_get_field_value_all_defaults() {
        let config = Config::default();
        for (s, section) in SECTIONS.iter().enumerate() {
            for f in 0..section.field_count {
                let value = get_field_value(&config, s, f);
                assert_ne!(
                    value, "???",
                    "Missing field mapping for section '{}' field {}",
                    section.key, f
                );
                assert!(
                    !value.is_empty(),
                    "Empty value for section '{}' field {}",
                    section.key, f
                );
            }
        }
    }

    #[test]
    fn test_get_field_value_unknown_returns_question_marks() {
        let config = Config::default();
        assert_eq!(get_field_value(&config, 99, 0), "???");
        assert_eq!(get_field_value(&config, 0, 99), "???");
    }

    #[test]
    fn test_get_default_value_matches_config_default() {
        let config = Config::default();
        for (s, section) in SECTIONS.iter().enumerate() {
            for f in 0..section.field_count {
                assert_eq!(
                    get_field_value(&config, s, f),
                    get_default_value(s, f),
                    "Default mismatch for section '{}' field {}",
                    section.key, f
                );
            }
        }
    }

    #[test]
    fn test_specific_default_values() {
        let config = Config::default();
        // Validator
        assert_eq!(get_field_value(&config, 0, 0), "true");
        assert_eq!(get_field_value(&config, 0, 2), "30000");
        assert_eq!(get_field_value(&config, 0, 3), "ask");
        assert_eq!(get_field_value(&config, 0, 4), "false");

        // Ollama
        assert_eq!(get_field_value(&config, 2, 0), "http://127.0.0.1:11434");
        assert_eq!(get_field_value(&config, 2, 7), "2.0");

        // Context Pressure
        assert_eq!(get_field_value(&config, 5, 0), "auto");
        assert_eq!(get_field_value(&config, 5, 2), "0.80");

        // MCP Tools
        assert_eq!(get_field_value(&config, 7, 2), "4 tools");
    }

    #[test]
    fn test_all_sections_have_field_definitions() {
        assert_eq!(SECTIONS.len(), ALL_SECTION_FIELDS.len());
    }

    // --- toggle_field tests ---

    #[test]
    fn test_toggle_all_bool_fields() {
        let mut config = Config::default();

        // Each (section, field, getter) tuple for all bool fields
        let bool_fields: &[(usize, usize)] = &[
            (0, 0), // validator.enabled
            (0, 1), // validator.layer1_enabled
            (0, 4), // validator.trust_mode
            (0, 5), // validator.auto_allow_reads
            (1, 0), // context.enabled
            (1, 1), // context.auto_snapshot
            (3, 0), // user_learning.enabled
            (6, 0), // session_recovery.enabled
            (7, 0), // mcp_tools.enabled
        ];

        for &(s, f) in bool_fields {
            let before = get_field_value(&config, s, f);
            toggle_field(&mut config, s, f);
            let after = get_field_value(&config, s, f);
            assert_ne!(
                before, after,
                "toggle_field({s}, {f}) did not change value"
            );

            // Toggle back should restore original
            toggle_field(&mut config, s, f);
            let restored = get_field_value(&config, s, f);
            assert_eq!(
                before, restored,
                "double toggle_field({s}, {f}) did not restore value"
            );
        }
    }

    #[test]
    fn test_toggle_nontoggle_field_is_noop() {
        let mut config = Config::default();
        let before = get_field_value(&config, 0, 2); // layer1_timeout_ms (NumberU64)
        toggle_field(&mut config, 0, 2);
        assert_eq!(get_field_value(&config, 0, 2), before);
    }

    // --- cycle_field tests ---

    #[test]
    fn test_cycle_default_decision_validator() {
        let mut config = Config::default();
        assert_eq!(get_field_value(&config, 0, 3), "ask");
        cycle_field(&mut config, 0, 3);
        assert_eq!(get_field_value(&config, 0, 3), "allow");
        cycle_field(&mut config, 0, 3);
        assert_eq!(get_field_value(&config, 0, 3), "deny");
        cycle_field(&mut config, 0, 3);
        assert_eq!(get_field_value(&config, 0, 3), "ask");
    }

    #[test]
    fn test_cycle_logging_level() {
        let mut config = Config::default();
        assert_eq!(get_field_value(&config, 4, 0), "info");
        cycle_field(&mut config, 4, 0);
        assert_eq!(get_field_value(&config, 4, 0), "warn");
        cycle_field(&mut config, 4, 0);
        assert_eq!(get_field_value(&config, 4, 0), "error");
        cycle_field(&mut config, 4, 0);
        assert_eq!(get_field_value(&config, 4, 0), "trace");
        cycle_field(&mut config, 4, 0);
        assert_eq!(get_field_value(&config, 4, 0), "debug");
        cycle_field(&mut config, 4, 0);
        assert_eq!(get_field_value(&config, 4, 0), "info");
    }

    #[test]
    fn test_cycle_context_pressure_mode() {
        let mut config = Config::default();
        assert_eq!(get_field_value(&config, 5, 0), "auto");
        cycle_field(&mut config, 5, 0);
        assert_eq!(get_field_value(&config, 5, 0), "notify");
        cycle_field(&mut config, 5, 0);
        assert_eq!(get_field_value(&config, 5, 0), "disabled");
        cycle_field(&mut config, 5, 0);
        assert_eq!(get_field_value(&config, 5, 0), "auto");
    }

    #[test]
    fn test_cycle_mcp_tools_default_decision() {
        let mut config = Config::default();
        // MCP tools default is "allow"
        assert_eq!(get_field_value(&config, 7, 1), "allow");
        cycle_field(&mut config, 7, 1);
        assert_eq!(get_field_value(&config, 7, 1), "deny");
        cycle_field(&mut config, 7, 1);
        assert_eq!(get_field_value(&config, 7, 1), "ask");
        cycle_field(&mut config, 7, 1);
        assert_eq!(get_field_value(&config, 7, 1), "allow");
    }

    #[test]
    fn test_cycle_noncycle_field_is_noop() {
        let mut config = Config::default();
        let before = get_field_value(&config, 0, 0); // validator.enabled (Toggle)
        cycle_field(&mut config, 0, 0);
        assert_eq!(get_field_value(&config, 0, 0), before);
    }

    // --- recompute_dirty tests ---

    #[test]
    fn test_recompute_dirty_clean() {
        let mut app = App::new(7, 5);
        let config = Config::default();
        app.settings_original_config = Some(config.clone());
        app.settings_editing_config = Some(config);
        recompute_dirty(&mut app);
        assert!(!app.settings_is_dirty);
    }

    #[test]
    fn test_recompute_dirty_after_toggle() {
        let mut app = App::new(7, 5);
        let config = Config::default();
        app.settings_original_config = Some(config.clone());
        app.settings_editing_config = Some(config);

        // Toggle a field in the editing config
        toggle_field(app.settings_editing_config.as_mut().unwrap(), 0, 0);
        recompute_dirty(&mut app);
        assert!(app.settings_is_dirty);

        // Toggle back — should be clean again
        toggle_field(app.settings_editing_config.as_mut().unwrap(), 0, 0);
        recompute_dirty(&mut app);
        assert!(!app.settings_is_dirty);
    }

    #[test]
    fn test_recompute_dirty_no_configs() {
        let mut app = App::new(7, 5);
        recompute_dirty(&mut app);
        assert!(!app.settings_is_dirty);
    }

    // --- is_trust_mode_enabling tests ---

    #[test]
    fn test_is_trust_mode_enabling_when_off() {
        let config = Config::default();
        assert!(is_trust_mode_enabling(&config, 0, 4));
    }

    #[test]
    fn test_is_trust_mode_enabling_when_already_on() {
        let mut config = Config::default();
        config.validator.trust_mode = true;
        assert!(!is_trust_mode_enabling(&config, 0, 4));
    }

    #[test]
    fn test_is_trust_mode_enabling_wrong_field() {
        let config = Config::default();
        assert!(!is_trust_mode_enabling(&config, 0, 0));
        assert!(!is_trust_mode_enabling(&config, 1, 4));
    }
}
