//! Built-in validator prompt templates for different sensitivity levels.
//!
//! Each template is embedded at compile time via `include_str!` and contains
//! the `{{command}}` and `{{working_dir}}` placeholders required by the
//! prompt validation logic.

/// Standard sensitivity prompt (balanced, current default behavior).
pub const PROMPT_STANDARD: &str = include_str!("prompts/validator-standard.txt");

/// High sensitivity prompt (stricter, more suspicious scoring).
pub const PROMPT_HIGH: &str = include_str!("prompts/validator-high.txt");

/// Low sensitivity prompt (relaxed, trusts common dev tools).
pub const PROMPT_LOW: &str = include_str!("prompts/validator-low.txt");

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::llm::validate_prompt_template;

    #[test]
    fn test_standard_prompt_is_valid() {
        assert!(
            validate_prompt_template(PROMPT_STANDARD).is_ok(),
            "Standard prompt must pass validation"
        );
    }

    #[test]
    fn test_high_prompt_is_valid() {
        assert!(
            validate_prompt_template(PROMPT_HIGH).is_ok(),
            "High prompt must pass validation"
        );
    }

    #[test]
    fn test_low_prompt_is_valid() {
        assert!(
            validate_prompt_template(PROMPT_LOW).is_ok(),
            "Low prompt must pass validation"
        );
    }

    #[test]
    fn test_all_prompts_contain_required_placeholders() {
        for (name, prompt) in [
            ("standard", PROMPT_STANDARD),
            ("high", PROMPT_HIGH),
            ("low", PROMPT_LOW),
        ] {
            assert!(
                prompt.contains("{{command}}"),
                "{name} prompt missing {{{{command}}}} placeholder"
            );
            assert!(
                prompt.contains("{{working_dir}}"),
                "{name} prompt missing {{{{working_dir}}}} placeholder"
            );
        }
    }

    #[test]
    fn test_all_prompts_contain_json_keyword() {
        for (name, prompt) in [
            ("standard", PROMPT_STANDARD),
            ("high", PROMPT_HIGH),
            ("low", PROMPT_LOW),
        ] {
            assert!(
                prompt.to_lowercase().contains("json"),
                "{name} prompt missing JSON keyword"
            );
        }
    }

    #[test]
    fn test_prompts_are_distinct() {
        assert_ne!(
            PROMPT_STANDARD, PROMPT_HIGH,
            "Standard and High must differ"
        );
        assert_ne!(PROMPT_STANDARD, PROMPT_LOW, "Standard and Low must differ");
        assert_ne!(PROMPT_HIGH, PROMPT_LOW, "High and Low must differ");
    }
}
