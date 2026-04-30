use clx_core::config::{Config, ContextPressureMode, DefaultDecision, OllamaConfig};

use crate::dashboard::app::App;

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

fn validate_u64(s: &str, min: u64, max: u64) -> Result<u64, String> {
    let v: u64 = s
        .trim()
        .parse()
        .map_err(|_| format!("Not a valid integer: '{s}'"))?;
    if v < min || v > max {
        return Err(format!("Must be between {min} and {max}"));
    }
    Ok(v)
}

fn validate_u32(s: &str, min: u32, max: u32) -> Result<u32, String> {
    let v: u32 = s
        .trim()
        .parse()
        .map_err(|_| format!("Not a valid integer: '{s}'"))?;
    if v < min || v > max {
        return Err(format!("Must be between {min} and {max}"));
    }
    Ok(v)
}

fn validate_i64(s: &str, min: i64, max: i64) -> Result<i64, String> {
    let v: i64 = s
        .trim()
        .parse()
        .map_err(|_| format!("Not a valid integer: '{s}'"))?;
    if v < min || v > max {
        return Err(format!("Must be between {min} and {max}"));
    }
    Ok(v)
}

fn validate_f64(s: &str, min: f64, max: f64) -> Result<f64, String> {
    let v: f64 = s
        .trim()
        .parse()
        .map_err(|_| format!("Not a valid number: '{s}'"))?;
    if v < min || v > max {
        return Err(format!("Must be between {min} and {max}"));
    }
    Ok(v)
}

fn validate_f32(s: &str, min: f32, max: f32) -> Result<f32, String> {
    let v: f32 = s
        .trim()
        .parse()
        .map_err(|_| format!("Not a valid number: '{s}'"))?;
    if v < min || v > max {
        return Err(format!("Must be between {min} and {max}"));
    }
    Ok(v)
}

fn validate_usize(s: &str, min: usize, max: usize) -> Result<usize, String> {
    let v: usize = s
        .trim()
        .parse()
        .map_err(|_| format!("Not a valid integer: '{s}'"))?;
    if v < min || v > max {
        return Err(format!("Must be between {min} and {max}"));
    }
    Ok(v)
}

fn validate_nonempty_string(s: &str) -> Result<(), String> {
    if s.trim().is_empty() {
        return Err("Value cannot be empty".to_owned());
    }
    Ok(())
}

fn validate_url(s: &str) -> Result<(), String> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Err("URL cannot be empty".to_owned());
    }
    if !trimmed.starts_with("http://") && !trimmed.starts_with("https://") {
        return Err("URL must start with http:// or https://".to_owned());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// set_field_value — parse + validate + apply
// ---------------------------------------------------------------------------

/// Apply an edited string value back to config.
///
/// Returns `Ok(())` on success, or `Err(message)` with a human-readable
/// validation error.
pub fn set_field_value(
    config: &mut Config,
    section: usize,
    field: usize,
    raw: &str,
) -> Result<(), String> {
    match (section, field) {
        // Section 0: Validator
        (0, 2) => {
            config.validator.layer1_timeout_ms = validate_u64(raw, 100, 300_000)?;
        }

        // Section 1: Context
        (1, 2) => {
            validate_nonempty_string(raw)?;
            raw.trim().clone_into(&mut config.context.embedding_model);
        }

        // Section 2: Ollama
        (2, 0) => {
            validate_url(raw)?;
            raw.trim()
                .clone_into(&mut config.ollama.get_or_insert_with(OllamaConfig::default).host);
        }
        (2, 1) => {
            validate_nonempty_string(raw)?;
            raw.trim().clone_into(
                &mut config
                    .ollama
                    .get_or_insert_with(OllamaConfig::default)
                    .model,
            );
        }
        (2, 2) => {
            validate_nonempty_string(raw)?;
            raw.trim().clone_into(
                &mut config
                    .ollama
                    .get_or_insert_with(OllamaConfig::default)
                    .embedding_model,
            );
        }
        (2, 3) => {
            config
                .ollama
                .get_or_insert_with(OllamaConfig::default)
                .embedding_dim = validate_usize(raw, 1, 65536)?;
        }
        (2, 4) => {
            config
                .ollama
                .get_or_insert_with(OllamaConfig::default)
                .timeout_ms = validate_u64(raw, 100, 600_000)?;
        }
        (2, 5) => {
            config
                .ollama
                .get_or_insert_with(OllamaConfig::default)
                .max_retries = validate_u32(raw, 0, 10)?;
        }
        (2, 6) => {
            config
                .ollama
                .get_or_insert_with(OllamaConfig::default)
                .retry_delay_ms = validate_u64(raw, 0, 60_000)?;
        }
        (2, 7) => {
            config
                .ollama
                .get_or_insert_with(OllamaConfig::default)
                .retry_backoff = validate_f32(raw, 1.0, 10.0)?;
        }

        // Section 3: User Learning
        (3, 1) => {
            config.user_learning.auto_whitelist_threshold = validate_u32(raw, 1, 100)?;
        }
        (3, 2) => {
            config.user_learning.auto_blacklist_threshold = validate_u32(raw, 1, 100)?;
        }

        // Section 4: Logging
        (4, 1) => {
            validate_nonempty_string(raw)?;
            raw.trim().clone_into(&mut config.logging.file);
        }
        (4, 2) => {
            config.logging.max_size_mb = validate_u32(raw, 1, 1000)?;
        }
        (4, 3) => {
            config.logging.max_files = validate_u32(raw, 1, 100)?;
        }

        // Section 5: Context Pressure
        (5, 1) => {
            config.context_pressure.context_window_size = validate_i64(raw, 1000, 2_000_000)?;
        }
        (5, 2) => {
            config.context_pressure.threshold = validate_f64(raw, 0.1, 1.0)?;
        }

        // Section 6: Session Recovery
        (6, 1) => {
            config.session_recovery.stale_hours = validate_u32(raw, 1, 168)?;
        }

        // Section 8: Auto Recall
        (8, 1) => {
            config.auto_recall.max_results = validate_usize(raw, 1, 10)?;
        }
        (8, 2) => {
            config.auto_recall.similarity_threshold = validate_f32(raw, 0.0, 1.0)?;
        }
        (8, 3) => {
            config.auto_recall.max_context_chars = validate_usize(raw, 100, 5000)?;
        }
        (8, 4) => {
            config.auto_recall.timeout_ms = validate_u64(raw, 100, 10000)?;
        }
        (8, 7) => {
            config.auto_recall.min_prompt_len = validate_usize(raw, 1, 500)?;
        }

        _ => return Err("Field is not editable".to_owned()),
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// reset_field_to_default — reset a single field to its Config::default() value
// ---------------------------------------------------------------------------

/// Reset a single field to its `Config::default()` value.
///
/// Returns `true` if the field was reset, `false` if the field is not resettable.
pub fn reset_field_to_default(config: &mut Config, section: usize, field: usize) -> bool {
    let defaults = Config::default();
    match (section, field) {
        // Section 0: Validator
        (0, 0) => config.validator.enabled = defaults.validator.enabled,
        (0, 1) => config.validator.layer1_enabled = defaults.validator.layer1_enabled,
        (0, 2) => config.validator.layer1_timeout_ms = defaults.validator.layer1_timeout_ms,
        (0, 3) => config.validator.default_decision = defaults.validator.default_decision,
        (0, 4) => config.validator.trust_mode = defaults.validator.trust_mode,
        (0, 5) => config.validator.auto_allow_reads = defaults.validator.auto_allow_reads,

        // Section 1: Context
        (1, 0) => config.context.enabled = defaults.context.enabled,
        (1, 1) => config.context.auto_snapshot = defaults.context.auto_snapshot,
        (1, 2) => config.context.embedding_model = defaults.context.embedding_model,

        // Section 2: Ollama
        (2, 0) => {
            config.ollama.get_or_insert_with(OllamaConfig::default).host =
                OllamaConfig::default().host;
        }
        (2, 1) => {
            config
                .ollama
                .get_or_insert_with(OllamaConfig::default)
                .model = OllamaConfig::default().model;
        }
        (2, 2) => {
            config
                .ollama
                .get_or_insert_with(OllamaConfig::default)
                .embedding_model = OllamaConfig::default().embedding_model;
        }
        (2, 3) => {
            config
                .ollama
                .get_or_insert_with(OllamaConfig::default)
                .embedding_dim = OllamaConfig::default().embedding_dim;
        }
        (2, 4) => {
            config
                .ollama
                .get_or_insert_with(OllamaConfig::default)
                .timeout_ms = OllamaConfig::default().timeout_ms;
        }
        (2, 5) => {
            config
                .ollama
                .get_or_insert_with(OllamaConfig::default)
                .max_retries = OllamaConfig::default().max_retries;
        }
        (2, 6) => {
            config
                .ollama
                .get_or_insert_with(OllamaConfig::default)
                .retry_delay_ms = OllamaConfig::default().retry_delay_ms;
        }
        (2, 7) => {
            config
                .ollama
                .get_or_insert_with(OllamaConfig::default)
                .retry_backoff = OllamaConfig::default().retry_backoff;
        }

        // Section 3: User Learning
        (3, 0) => config.user_learning.enabled = defaults.user_learning.enabled,
        (3, 1) => {
            config.user_learning.auto_whitelist_threshold =
                defaults.user_learning.auto_whitelist_threshold;
        }
        (3, 2) => {
            config.user_learning.auto_blacklist_threshold =
                defaults.user_learning.auto_blacklist_threshold;
        }

        // Section 4: Logging
        (4, 0) => config.logging.level = defaults.logging.level,
        (4, 1) => config.logging.file = defaults.logging.file,
        (4, 2) => config.logging.max_size_mb = defaults.logging.max_size_mb,
        (4, 3) => config.logging.max_files = defaults.logging.max_files,

        // Section 5: Context Pressure
        (5, 0) => config.context_pressure.mode = defaults.context_pressure.mode,
        (5, 1) => {
            config.context_pressure.context_window_size =
                defaults.context_pressure.context_window_size;
        }
        (5, 2) => config.context_pressure.threshold = defaults.context_pressure.threshold,

        // Section 6: Session Recovery
        (6, 0) => config.session_recovery.enabled = defaults.session_recovery.enabled,
        (6, 1) => config.session_recovery.stale_hours = defaults.session_recovery.stale_hours,

        // Section 7: MCP Tools
        (7, 0) => config.mcp_tools.enabled = defaults.mcp_tools.enabled,
        (7, 1) => config.mcp_tools.default_decision = defaults.mcp_tools.default_decision,

        // Section 8: Auto Recall
        (8, 0) => config.auto_recall.enabled = defaults.auto_recall.enabled,
        (8, 1) => config.auto_recall.max_results = defaults.auto_recall.max_results,
        (8, 2) => {
            config.auto_recall.similarity_threshold = defaults.auto_recall.similarity_threshold;
        }
        (8, 3) => {
            config.auto_recall.max_context_chars = defaults.auto_recall.max_context_chars;
        }
        (8, 4) => config.auto_recall.timeout_ms = defaults.auto_recall.timeout_ms,
        (8, 5) => config.auto_recall.fallback_to_fts = defaults.auto_recall.fallback_to_fts,
        (8, 6) => config.auto_recall.include_key_facts = defaults.auto_recall.include_key_facts,
        (8, 7) => config.auto_recall.min_prompt_len = defaults.auto_recall.min_prompt_len,

        _ => return false,
    }
    true
}

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
        (2, 0) => config
            .ollama
            .as_ref()
            .map_or_else(|| OllamaConfig::default().host, |o| o.host.clone()),
        (2, 1) => config
            .ollama
            .as_ref()
            .map_or_else(|| OllamaConfig::default().model, |o| o.model.clone()),
        (2, 2) => config.ollama.as_ref().map_or_else(
            || OllamaConfig::default().embedding_model,
            |o| o.embedding_model.clone(),
        ),
        (2, 3) => config
            .ollama
            .as_ref()
            .map_or_else(
                || OllamaConfig::default().embedding_dim,
                |o| o.embedding_dim,
            )
            .to_string(),
        (2, 4) => config
            .ollama
            .as_ref()
            .map_or_else(|| OllamaConfig::default().timeout_ms, |o| o.timeout_ms)
            .to_string(),
        (2, 5) => config
            .ollama
            .as_ref()
            .map_or_else(|| OllamaConfig::default().max_retries, |o| o.max_retries)
            .to_string(),
        (2, 6) => config
            .ollama
            .as_ref()
            .map_or_else(
                || OllamaConfig::default().retry_delay_ms,
                |o| o.retry_delay_ms,
            )
            .to_string(),
        (2, 7) => format!(
            "{:.1}",
            config.ollama.as_ref().map_or_else(
                || OllamaConfig::default().retry_backoff,
                |o| o.retry_backoff
            )
        ),

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

        // Section 8: Auto Recall
        (8, 0) => config.auto_recall.enabled.to_string(),
        (8, 1) => config.auto_recall.max_results.to_string(),
        (8, 2) => format!("{:.2}", config.auto_recall.similarity_threshold),
        (8, 3) => config.auto_recall.max_context_chars.to_string(),
        (8, 4) => config.auto_recall.timeout_ms.to_string(),
        (8, 5) => config.auto_recall.fallback_to_fts.to_string(),
        (8, 6) => config.auto_recall.include_key_facts.to_string(),
        (8, 7) => config.auto_recall.min_prompt_len.to_string(),

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

        // Section 8: Auto Recall
        (8, 0) => config.auto_recall.enabled = !config.auto_recall.enabled,
        (8, 5) => config.auto_recall.fallback_to_fts = !config.auto_recall.fallback_to_fts,
        (8, 6) => config.auto_recall.include_key_facts = !config.auto_recall.include_key_facts,

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
                    section.key,
                    f
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
                    section.key,
                    f
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

        // Auto Recall
        assert_eq!(get_field_value(&config, 8, 0), "true");
        assert_eq!(get_field_value(&config, 8, 1), "3");
        assert_eq!(get_field_value(&config, 8, 2), "0.35");
        assert_eq!(get_field_value(&config, 8, 3), "1000");
        assert_eq!(get_field_value(&config, 8, 4), "500");
        assert_eq!(get_field_value(&config, 8, 5), "true");
        assert_eq!(get_field_value(&config, 8, 6), "true");
        assert_eq!(get_field_value(&config, 8, 7), "10");
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
            (8, 0), // auto_recall.enabled
            (8, 5), // auto_recall.fallback_to_fts
            (8, 6), // auto_recall.include_key_facts
        ];

        for &(s, f) in bool_fields {
            let before = get_field_value(&config, s, f);
            toggle_field(&mut config, s, f);
            let after = get_field_value(&config, s, f);
            assert_ne!(before, after, "toggle_field({s}, {f}) did not change value");

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

    // --- Phase 3: validator tests ---

    #[test]
    fn test_validate_u64_valid() {
        assert_eq!(validate_u64("100", 100, 300_000).unwrap(), 100);
        assert_eq!(validate_u64("300000", 100, 300_000).unwrap(), 300_000);
        assert_eq!(validate_u64("5000", 100, 300_000).unwrap(), 5000);
    }

    #[test]
    fn test_validate_u64_out_of_range() {
        assert!(validate_u64("99", 100, 300_000).is_err());
        assert!(validate_u64("300001", 100, 300_000).is_err());
    }

    #[test]
    fn test_validate_u64_invalid() {
        assert!(validate_u64("abc", 100, 300_000).is_err());
        assert!(validate_u64("", 100, 300_000).is_err());
        assert!(validate_u64("-1", 100, 300_000).is_err());
    }

    #[test]
    fn test_validate_u32_valid() {
        assert_eq!(validate_u32("1", 1, 100).unwrap(), 1);
        assert_eq!(validate_u32("100", 1, 100).unwrap(), 100);
    }

    #[test]
    fn test_validate_u32_out_of_range() {
        assert!(validate_u32("0", 1, 100).is_err());
        assert!(validate_u32("101", 1, 100).is_err());
    }

    #[test]
    fn test_validate_i64_valid() {
        assert_eq!(validate_i64("1000", 1000, 2_000_000).unwrap(), 1000);
        assert_eq!(validate_i64("2000000", 1000, 2_000_000).unwrap(), 2_000_000);
    }

    #[test]
    fn test_validate_i64_out_of_range() {
        assert!(validate_i64("999", 1000, 2_000_000).is_err());
        assert!(validate_i64("2000001", 1000, 2_000_000).is_err());
    }

    #[test]
    fn test_validate_f64_valid() {
        let v = validate_f64("0.5", 0.1, 1.0).unwrap();
        assert!((v - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_validate_f64_out_of_range() {
        assert!(validate_f64("0.05", 0.1, 1.0).is_err());
        assert!(validate_f64("1.1", 0.1, 1.0).is_err());
    }

    #[test]
    fn test_validate_f32_valid() {
        let v = validate_f32("2.5", 1.0, 10.0).unwrap();
        assert!((v - 2.5).abs() < f32::EPSILON);
    }

    #[test]
    fn test_validate_f32_out_of_range() {
        assert!(validate_f32("0.5", 1.0, 10.0).is_err());
        assert!(validate_f32("10.1", 1.0, 10.0).is_err());
    }

    #[test]
    fn test_validate_usize_valid() {
        assert_eq!(validate_usize("1024", 1, 65536).unwrap(), 1024);
    }

    #[test]
    fn test_validate_usize_out_of_range() {
        assert!(validate_usize("0", 1, 65536).is_err());
        assert!(validate_usize("65537", 1, 65536).is_err());
    }

    #[test]
    fn test_validate_nonempty_string_valid() {
        assert!(validate_nonempty_string("hello").is_ok());
        assert!(validate_nonempty_string("  x  ").is_ok());
    }

    #[test]
    fn test_validate_nonempty_string_empty() {
        assert!(validate_nonempty_string("").is_err());
        assert!(validate_nonempty_string("   ").is_err());
    }

    #[test]
    fn test_validate_url_valid() {
        assert!(validate_url("http://localhost:11434").is_ok());
        assert!(validate_url("https://example.com").is_ok());
    }

    #[test]
    fn test_validate_url_invalid() {
        assert!(validate_url("").is_err());
        assert!(validate_url("ftp://example.com").is_err());
        assert!(validate_url("localhost:11434").is_err());
    }

    // --- Phase 3: set_field_value tests ---

    #[test]
    fn test_set_field_value_u64_roundtrip() {
        let mut config = Config::default();
        set_field_value(&mut config, 0, 2, "5000").unwrap();
        assert_eq!(config.validator.layer1_timeout_ms, 5000);
        assert_eq!(get_field_value(&config, 0, 2), "5000");
    }

    #[test]
    fn test_set_field_value_u64_rejects_out_of_range() {
        let mut config = Config::default();
        assert!(set_field_value(&mut config, 0, 2, "50").is_err());
        // Verify value unchanged
        assert_eq!(config.validator.layer1_timeout_ms, 30000);
    }

    #[test]
    fn test_set_field_value_string_roundtrip() {
        let mut config = Config::default();
        set_field_value(&mut config, 1, 2, "custom-model").unwrap();
        assert_eq!(config.context.embedding_model, "custom-model");
    }

    #[test]
    fn test_set_field_value_string_rejects_empty() {
        let mut config = Config::default();
        assert!(set_field_value(&mut config, 1, 2, "").is_err());
    }

    #[test]
    fn test_set_field_value_url_validation() {
        let mut config = Config::default();
        set_field_value(&mut config, 2, 0, "http://custom:8080").unwrap();
        assert_eq!(config.ollama.as_ref().unwrap().host, "http://custom:8080");

        assert!(set_field_value(&mut config, 2, 0, "ftp://bad").is_err());
    }

    #[test]
    fn test_set_field_value_f32_roundtrip() {
        let mut config = Config::default();
        set_field_value(&mut config, 2, 7, "3.5").unwrap();
        assert!((config.ollama.as_ref().unwrap().retry_backoff - 3.5).abs() < f32::EPSILON);
    }

    #[test]
    fn test_set_field_value_f64_roundtrip() {
        let mut config = Config::default();
        set_field_value(&mut config, 5, 2, "0.90").unwrap();
        assert!((config.context_pressure.threshold - 0.90).abs() < f64::EPSILON);
    }

    #[test]
    fn test_set_field_value_i64_roundtrip() {
        let mut config = Config::default();
        set_field_value(&mut config, 5, 1, "150000").unwrap();
        assert_eq!(config.context_pressure.context_window_size, 150_000);
    }

    #[test]
    fn test_set_field_value_usize_roundtrip() {
        let mut config = Config::default();
        set_field_value(&mut config, 2, 3, "768").unwrap();
        assert_eq!(config.ollama.as_ref().unwrap().embedding_dim, 768);
    }

    #[test]
    fn test_set_field_value_non_editable_returns_error() {
        let mut config = Config::default();
        // Toggle field (0,0) is not handled by set_field_value
        assert!(set_field_value(&mut config, 0, 0, "true").is_err());
        // ReadOnlyList
        assert!(set_field_value(&mut config, 7, 2, "test").is_err());
        // Unknown field
        assert!(set_field_value(&mut config, 99, 0, "x").is_err());
    }

    #[test]
    fn test_set_field_value_all_number_fields() {
        // Verify every number field can be set with its default value (round-trip)
        let defaults = Config::default();
        let number_fields: &[(usize, usize)] = &[
            (0, 2), // layer1_timeout_ms
            (2, 3), // embedding_dim
            (2, 4), // timeout_ms
            (2, 5), // max_retries
            (2, 6), // retry_delay_ms
            (2, 7), // retry_backoff
            (3, 1), // auto_whitelist_threshold
            (3, 2), // auto_blacklist_threshold
            (4, 2), // max_size_mb
            (4, 3), // max_files
            (5, 1), // context_window_size
            (5, 2), // threshold
            (6, 1), // stale_hours
            (8, 1), // auto_recall.max_results
            (8, 2), // auto_recall.similarity_threshold
            (8, 3), // auto_recall.max_context_chars
            (8, 4), // auto_recall.timeout_ms
            (8, 7), // auto_recall.min_prompt_len
        ];

        for &(s, f) in number_fields {
            let mut config = Config::default();
            let default_val = get_field_value(&defaults, s, f);
            let result = set_field_value(&mut config, s, f, &default_val);
            assert!(
                result.is_ok(),
                "set_field_value({s}, {f}, \"{default_val}\") failed: {:?}",
                result.err()
            );
        }
    }

    // --- Phase 3: reset_field_to_default tests ---

    #[test]
    fn test_reset_field_to_default_number() {
        let mut config = Config::default();
        config.validator.layer1_timeout_ms = 999;
        reset_field_to_default(&mut config, 0, 2);
        assert_eq!(config.validator.layer1_timeout_ms, 30000);
    }

    #[test]
    fn test_reset_field_to_default_string() {
        let mut config = Config::default();
        config.ollama.get_or_insert_with(OllamaConfig::default).host =
            "http://custom:9999".to_owned();
        reset_field_to_default(&mut config, 2, 0);
        assert_eq!(
            config.ollama.as_ref().unwrap().host,
            "http://127.0.0.1:11434"
        );
    }

    #[test]
    fn test_reset_field_to_default_bool() {
        let mut config = Config::default();
        config.validator.enabled = false;
        reset_field_to_default(&mut config, 0, 0);
        assert!(config.validator.enabled);
    }

    #[test]
    fn test_reset_field_to_default_unknown_returns_false() {
        let mut config = Config::default();
        assert!(!reset_field_to_default(&mut config, 99, 0));
        assert!(!reset_field_to_default(&mut config, 7, 2)); // ReadOnlyList
    }

    #[test]
    fn test_reset_all_fields_to_default() {
        let mut config = Config::default();
        // Modify several fields
        config.validator.layer1_timeout_ms = 1;
        config.ollama.get_or_insert_with(OllamaConfig::default).host = "changed".to_owned();
        config.context_pressure.threshold = 0.5;

        // Reset them
        reset_field_to_default(&mut config, 0, 2);
        reset_field_to_default(&mut config, 2, 0);
        reset_field_to_default(&mut config, 5, 2);

        assert_eq!(
            config.validator.layer1_timeout_ms,
            Config::default().validator.layer1_timeout_ms
        );
        assert_eq!(
            config.ollama.as_ref().unwrap().host,
            OllamaConfig::default().host
        );
        assert!(
            (config.context_pressure.threshold - Config::default().context_pressure.threshold)
                .abs()
                < f64::EPSILON
        );
    }
}
