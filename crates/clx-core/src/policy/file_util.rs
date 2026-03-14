//! File utilities for policy rules management.

use std::fs;
use tracing::info;

use super::types::RulesConfig;

/// Create default rules file if it doesn't exist
pub fn ensure_default_rules_file() -> crate::Result<()> {
    let rules_path = crate::paths::default_rules_path();
    if !rules_path.exists() {
        if let Some(parent) = rules_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let default_config = RulesConfig {
            whitelist: vec![
                // Add some common safe patterns
                "Bash(ls:*)".to_string(),
                "Bash(pwd)".to_string(),
                "Bash(git:status*)".to_string(),
                "Bash(git:log*)".to_string(),
                "Bash(git:diff*)".to_string(),
            ],
            blacklist: vec![
                // Add some dangerous patterns
                "Bash(rm:-rf /*)".to_string(),
                "Bash(rm:-rf ~*)".to_string(),
                "Bash(curl:*|bash)".to_string(),
            ],
        };

        let yaml = serde_yml::to_string(&default_config)?;
        let yaml = format!(
            "# Note: CLX includes built-in rules for common commands. These are user-customizable extras.\n\
             # Run 'clx rules list' to see all active rules.\n\
             {yaml}"
        );
        fs::write(&rules_path, yaml)?;
        info!("Created default rules file: {}", rules_path.display());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use serial_test::serial;
    use tempfile::TempDir;

    use super::*;

    /// Redirect `HOME` to `dir` for the duration of the closure, then restore it.
    #[allow(unsafe_code)]
    fn with_home(dir: &TempDir, f: impl FnOnce()) {
        let original = std::env::var("HOME").ok();
        // SAFETY: single-threaded context enforced by #[serial]
        unsafe {
            std::env::set_var("HOME", dir.path());
        }
        f();
        // SAFETY: single-threaded context enforced by #[serial]
        unsafe {
            match original {
                Some(v) => std::env::set_var("HOME", v),
                None => std::env::remove_var("HOME"),
            }
        }
    }

    #[test]
    #[serial]
    fn creates_rules_file_in_fresh_dir() {
        let tmp = TempDir::new().expect("temp dir");
        with_home(&tmp, || {
            let result = ensure_default_rules_file();
            assert!(result.is_ok(), "should succeed: {result:?}");

            let rules_path = crate::paths::default_rules_path();
            assert!(rules_path.exists(), "rules file should be created");

            let contents = std::fs::read_to_string(&rules_path).expect("read file");
            assert!(!contents.is_empty(), "rules file should not be empty");
            // Must contain YAML structure markers
            assert!(
                contents.contains("whitelist") || contents.contains("blacklist"),
                "rules file should contain valid YAML with whitelist/blacklist"
            );
        });
    }

    #[test]
    #[serial]
    fn idempotent_when_called_twice() {
        let tmp = TempDir::new().expect("temp dir");
        with_home(&tmp, || {
            ensure_default_rules_file().expect("first call");
            let rules_path = crate::paths::default_rules_path();
            let content_first = std::fs::read_to_string(&rules_path).expect("read after first");

            ensure_default_rules_file().expect("second call");
            let content_second = std::fs::read_to_string(&rules_path).expect("read after second");

            assert_eq!(
                content_first, content_second,
                "file content must not change on second call"
            );
        });
    }

    #[test]
    #[serial]
    fn created_file_parses_as_valid_yaml() {
        let tmp = TempDir::new().expect("temp dir");
        with_home(&tmp, || {
            ensure_default_rules_file().expect("create file");
            let rules_path = crate::paths::default_rules_path();
            let contents = std::fs::read_to_string(&rules_path).expect("read file");

            let parsed: Result<super::RulesConfig, _> = serde_yml::from_str(&contents);
            assert!(
                parsed.is_ok(),
                "file must parse as RulesConfig YAML: {parsed:?}"
            );
            let config = parsed.unwrap();
            assert!(
                !config.whitelist.is_empty(),
                "parsed whitelist should not be empty"
            );
            assert!(
                !config.blacklist.is_empty(),
                "parsed blacklist should not be empty"
            );
        });
    }
}
