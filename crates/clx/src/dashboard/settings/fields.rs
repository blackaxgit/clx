/// Widget type for a configuration field.
///
/// Determines edit behavior: toggles flip in-place, cycle-selects rotate
/// through options, and text/number fields open a popup.
///
/// Variant fields carry validation metadata used by editing popups.
// Variant fields `max_len` and `decimals` are structural metadata reserved
// for future use (e.g. input length limiting, display formatting) but not
// yet read in current code paths.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum FieldWidget {
    Toggle,
    TextInput { max_len: usize },
    NumberU64 { min: u64, max: u64 },
    NumberU32 { min: u32, max: u32 },
    NumberI64 { min: i64, max: i64 },
    NumberF64 { min: f64, max: f64, decimals: u8 },
    NumberF32 { min: f32, max: f32, decimals: u8 },
    NumberUsize { min: usize, max: usize },
    CycleSelect { options: &'static [&'static str] },
    ReadOnlyList,
}

/// Definition of a single configuration field displayed in the right panel.
pub struct FieldDef {
    /// Display label (matches YAML key)
    pub label: &'static str,
    /// Short description shown in the edit popup
    pub description: &'static str,
    /// Widget type determining edit behavior
    pub widget: FieldWidget,
}

// --- Validator fields (section 0) ---

pub const VALIDATOR_FIELDS: &[FieldDef] = &[
    FieldDef {
        label: "enabled",
        description: "Enable command validation",
        widget: FieldWidget::Toggle,
    },
    FieldDef {
        label: "layer1_enabled",
        description: "Enable layer 1 (fast) validation",
        widget: FieldWidget::Toggle,
    },
    FieldDef {
        label: "layer1_timeout_ms",
        description: "Layer 1 timeout in milliseconds",
        widget: FieldWidget::NumberU64 {
            min: 100,
            max: 300_000,
        },
    },
    FieldDef {
        label: "default_decision",
        description: "Default when validation inconclusive",
        widget: FieldWidget::CycleSelect {
            options: &["ask", "allow", "deny"],
        },
    },
    FieldDef {
        label: "trust_mode",
        description: "Auto-allow ALL commands (dangerous!)",
        widget: FieldWidget::Toggle,
    },
    FieldDef {
        label: "auto_allow_reads",
        description: "Auto-allow read-only commands",
        widget: FieldWidget::Toggle,
    },
];

// --- Context fields (section 1) ---

pub const CONTEXT_FIELDS: &[FieldDef] = &[
    FieldDef {
        label: "enabled",
        description: "Enable context persistence",
        widget: FieldWidget::Toggle,
    },
    FieldDef {
        label: "auto_snapshot",
        description: "Automatically snapshot context",
        widget: FieldWidget::Toggle,
    },
    FieldDef {
        label: "embedding_model",
        description: "Embedding model name",
        widget: FieldWidget::TextInput { max_len: 128 },
    },
];

// --- Ollama fields (section 2) ---

pub const OLLAMA_FIELDS: &[FieldDef] = &[
    FieldDef {
        label: "host",
        description: "Ollama host URL",
        widget: FieldWidget::TextInput { max_len: 256 },
    },
    FieldDef {
        label: "model",
        description: "Default model for inference",
        widget: FieldWidget::TextInput { max_len: 128 },
    },
    FieldDef {
        label: "embedding_model",
        description: "Model for embeddings",
        widget: FieldWidget::TextInput { max_len: 128 },
    },
    FieldDef {
        label: "embedding_dim",
        description: "Embedding vector dimension",
        widget: FieldWidget::NumberUsize { min: 1, max: 65536 },
    },
    FieldDef {
        label: "timeout_ms",
        description: "Request timeout in milliseconds",
        widget: FieldWidget::NumberU64 {
            min: 100,
            max: 600_000,
        },
    },
    FieldDef {
        label: "max_retries",
        description: "Maximum retry count",
        widget: FieldWidget::NumberU32 { min: 0, max: 10 },
    },
    FieldDef {
        label: "retry_delay_ms",
        description: "Initial retry delay in ms",
        widget: FieldWidget::NumberU64 {
            min: 0,
            max: 60_000,
        },
    },
    FieldDef {
        label: "retry_backoff",
        description: "Exponential backoff multiplier",
        widget: FieldWidget::NumberF32 {
            min: 1.0,
            max: 10.0,
            decimals: 1,
        },
    },
];

// --- User Learning fields (section 3) ---

pub const USER_LEARNING_FIELDS: &[FieldDef] = &[
    FieldDef {
        label: "enabled",
        description: "Enable user learning features",
        widget: FieldWidget::Toggle,
    },
    FieldDef {
        label: "auto_whitelist_threshold",
        description: "Approvals before auto-whitelist",
        widget: FieldWidget::NumberU32 { min: 1, max: 100 },
    },
    FieldDef {
        label: "auto_blacklist_threshold",
        description: "Rejections before auto-blacklist",
        widget: FieldWidget::NumberU32 { min: 1, max: 100 },
    },
];

// --- Logging fields (section 4) ---

pub const LOGGING_FIELDS: &[FieldDef] = &[
    FieldDef {
        label: "level",
        description: "Log level",
        widget: FieldWidget::CycleSelect {
            options: &["trace", "debug", "info", "warn", "error"],
        },
    },
    FieldDef {
        label: "file",
        description: "Log file path",
        widget: FieldWidget::TextInput { max_len: 256 },
    },
    FieldDef {
        label: "max_size_mb",
        description: "Max log file size in MB",
        widget: FieldWidget::NumberU32 { min: 1, max: 1000 },
    },
    FieldDef {
        label: "max_files",
        description: "Max number of log files",
        widget: FieldWidget::NumberU32 { min: 1, max: 100 },
    },
];

// --- Context Pressure fields (section 5) ---

pub const CONTEXT_PRESSURE_FIELDS: &[FieldDef] = &[
    FieldDef {
        label: "mode",
        description: "Monitoring mode",
        widget: FieldWidget::CycleSelect {
            options: &["auto", "notify", "disabled"],
        },
    },
    FieldDef {
        label: "context_window_size",
        description: "Context window size in tokens",
        widget: FieldWidget::NumberI64 {
            min: 1000,
            max: 2_000_000,
        },
    },
    FieldDef {
        label: "threshold",
        description: "Threshold percentage (0.0-1.0)",
        widget: FieldWidget::NumberF64 {
            min: 0.1,
            max: 1.0,
            decimals: 2,
        },
    },
];

// --- Session Recovery fields (section 6) ---

pub const SESSION_RECOVERY_FIELDS: &[FieldDef] = &[
    FieldDef {
        label: "enabled",
        description: "Enable auto-recovery",
        widget: FieldWidget::Toggle,
    },
    FieldDef {
        label: "stale_hours",
        description: "Hours before session is stale",
        widget: FieldWidget::NumberU32 { min: 1, max: 168 },
    },
];

// --- MCP Tools fields (section 7) ---

pub const MCP_TOOLS_FIELDS: &[FieldDef] = &[
    FieldDef {
        label: "enabled",
        description: "Enable MCP tool validation",
        widget: FieldWidget::Toggle,
    },
    FieldDef {
        label: "default_decision",
        description: "Default decision for MCP tools",
        widget: FieldWidget::CycleSelect {
            options: &["ask", "allow", "deny"],
        },
    },
    FieldDef {
        label: "command_tools",
        description: "Registered command tools",
        widget: FieldWidget::ReadOnlyList,
    },
];

// --- Auto Recall fields (section 8) ---

pub const AUTO_RECALL_FIELDS: &[FieldDef] = &[
    FieldDef {
        label: "enabled",
        description: "Enable auto-recall on prompts",
        widget: FieldWidget::Toggle,
    },
    FieldDef {
        label: "max_results",
        description: "Max results to inject (1-10)",
        widget: FieldWidget::NumberUsize { min: 1, max: 10 },
    },
    FieldDef {
        label: "similarity_threshold",
        description: "Min relevance score (0.0-1.0)",
        widget: FieldWidget::NumberF32 {
            min: 0.0,
            max: 1.0,
            decimals: 2,
        },
    },
    FieldDef {
        label: "max_context_chars",
        description: "Max chars for recall context",
        widget: FieldWidget::NumberUsize {
            min: 100,
            max: 5000,
        },
    },
    FieldDef {
        label: "timeout_ms",
        description: "Recall timeout in milliseconds",
        widget: FieldWidget::NumberU64 {
            min: 100,
            max: 10000,
        },
    },
    FieldDef {
        label: "fallback_to_fts",
        description: "Use FTS5 if semantic fails",
        widget: FieldWidget::Toggle,
    },
    FieldDef {
        label: "include_key_facts",
        description: "Include key facts in context",
        widget: FieldWidget::Toggle,
    },
    FieldDef {
        label: "min_prompt_len",
        description: "Min prompt length for recall",
        widget: FieldWidget::NumberUsize { min: 1, max: 500 },
    },
];

/// All field definition arrays indexed by section index.
pub const ALL_SECTION_FIELDS: &[&[FieldDef]] = &[
    VALIDATOR_FIELDS,
    CONTEXT_FIELDS,
    OLLAMA_FIELDS,
    USER_LEARNING_FIELDS,
    LOGGING_FIELDS,
    CONTEXT_PRESSURE_FIELDS,
    SESSION_RECOVERY_FIELDS,
    MCP_TOOLS_FIELDS,
    AUTO_RECALL_FIELDS,
];

/// Get the field definitions for a given section index.
#[must_use]
pub fn fields_for_section(section: usize) -> &'static [FieldDef] {
    ALL_SECTION_FIELDS.get(section).copied().unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dashboard::settings::sections::SECTIONS;

    #[test]
    fn test_field_counts_match_sections() {
        for (i, section) in SECTIONS.iter().enumerate() {
            let fields = fields_for_section(i);
            assert_eq!(
                fields.len(),
                section.field_count,
                "Section '{}' field count mismatch: expected {}, got {}",
                section.key,
                section.field_count,
                fields.len()
            );
        }
    }

    #[test]
    fn test_fields_for_section_out_of_bounds() {
        assert!(fields_for_section(99).is_empty());
    }
}
