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
