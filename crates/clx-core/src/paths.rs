//! Centralized path resolution for CLX
//!
//! All CLX path constants are defined here so that every crate
//! imports from a single source of truth.

use std::path::PathBuf;

/// Base CLX config directory: ~/.clx
#[must_use]
pub fn clx_dir() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".clx")
}

/// Data directory: ~/.clx/data
#[must_use]
pub fn data_dir() -> PathBuf {
    clx_dir().join("data")
}

/// Database path: ~/.clx/data/clx.db
#[must_use]
pub fn database_path() -> PathBuf {
    data_dir().join("clx.db")
}

/// Prompts directory: ~/.clx/prompts
#[must_use]
pub fn prompts_dir() -> PathBuf {
    clx_dir().join("prompts")
}

/// Validator prompt file: ~/.clx/prompts/validator.txt
#[must_use]
pub fn validator_prompt_path() -> PathBuf {
    prompts_dir().join("validator.txt")
}

/// Rules directory: ~/.clx/rules
#[must_use]
pub fn rules_dir() -> PathBuf {
    clx_dir().join("rules")
}

/// Default rules file: ~/.clx/rules/default.yaml
#[must_use]
pub fn default_rules_path() -> PathBuf {
    rules_dir().join("default.yaml")
}

/// Lib directory for native extensions: ~/.clx/lib
#[must_use]
pub fn lib_dir() -> PathBuf {
    clx_dir().join("lib")
}

/// Bin directory for CLX binaries: ~/.clx/bin
#[must_use]
pub fn bin_dir() -> PathBuf {
    clx_dir().join("bin")
}

/// Logs directory: ~/.clx/logs
#[must_use]
pub fn logs_dir() -> PathBuf {
    clx_dir().join("logs")
}

/// Learned patterns directory: ~/.clx/learned
#[must_use]
pub fn learned_dir() -> PathBuf {
    clx_dir().join("learned")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_end_with_expected_components() {
        let db = database_path();
        assert!(db.ends_with(".clx/data/clx.db"));

        let vp = validator_prompt_path();
        assert!(vp.ends_with(".clx/prompts/validator.txt"));

        let rp = default_rules_path();
        assert!(rp.ends_with(".clx/rules/default.yaml"));

        let ld = lib_dir();
        assert!(ld.ends_with(".clx/lib"));
    }
}
