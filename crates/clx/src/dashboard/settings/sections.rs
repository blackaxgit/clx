/// Definition of a configuration section displayed in the left panel.
pub struct SectionDef {
    /// YAML key, e.g. "validator" (used in Phase 3+ for save/load and tests)
    #[cfg_attr(not(test), allow(dead_code))]
    pub key: &'static str,
    /// Display name, e.g. "Validator"
    pub title: &'static str,
    /// Number of fields in this section (used for validation in tests)
    #[cfg_attr(not(test), allow(dead_code))]
    pub field_count: usize,
}

/// All configuration sections in display order.
pub const SECTIONS: &[SectionDef] = &[
    SectionDef {
        key: "validator",
        title: "Validator",
        field_count: 6,
    },
    SectionDef {
        key: "context",
        title: "Context",
        field_count: 3,
    },
    SectionDef {
        key: "ollama",
        title: "Ollama",
        field_count: 8,
    },
    SectionDef {
        key: "user_learning",
        title: "User Learning",
        field_count: 3,
    },
    SectionDef {
        key: "logging",
        title: "Logging",
        field_count: 4,
    },
    SectionDef {
        key: "context_pressure",
        title: "Ctx Pressure",
        field_count: 3,
    },
    SectionDef {
        key: "session_recovery",
        title: "Sess Recovery",
        field_count: 2,
    },
    SectionDef {
        key: "mcp_tools",
        title: "MCP Tools",
        field_count: 3,
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sections_count() {
        assert_eq!(SECTIONS.len(), 8);
    }

    #[test]
    fn test_total_field_count() {
        let total: usize = SECTIONS.iter().map(|s| s.field_count).sum();
        // 6+3+8+3+4+3+2+3 = 32 scalar fields (+ display-only items)
        assert_eq!(total, 32);
    }
}
