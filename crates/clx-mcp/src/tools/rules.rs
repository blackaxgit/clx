//! `clx_rules` tool — Manage whitelist/blacklist rules and extract CLAUDE.md rules.

use serde_json::{Value, json};
use std::collections::HashMap;
use std::env;

use clx_core::types::{LearnedRule, RuleType};

use crate::protocol::types::{INTERNAL_ERROR, INVALID_PARAMS};
use crate::server::McpServer;
use crate::validation::{MAX_KEY_LEN, validate_optional_string_param, validate_string_param};

impl McpServer {
    /// `clx_rules` - Manage whitelist/blacklist rules
    pub(crate) fn tool_rules(&self, args: &Value) -> Result<Value, (i32, String)> {
        let action = validate_string_param(args, "action", MAX_KEY_LEN)?;

        match action.as_str() {
            "list" => match self.storage.get_rules() {
                Ok(rules) => {
                    let rules_list: Vec<HashMap<String, Value>> = rules
                        .iter()
                        .map(|r| {
                            let mut map = HashMap::new();
                            map.insert("pattern".to_string(), json!(r.pattern));
                            map.insert("type".to_string(), json!(r.rule_type.as_str()));
                            map.insert(
                                "confirmation_count".to_string(),
                                json!(r.confirmation_count),
                            );
                            map.insert("denial_count".to_string(), json!(r.denial_count));
                            map
                        })
                        .collect();

                    Ok(json!({
                        "content": [{
                            "type": "text",
                            "text": if rules_list.is_empty() {
                                "No rules configured".to_string()
                            } else {
                                serde_json::to_string_pretty(&rules_list).unwrap_or_else(|_| "[]".to_string())
                            }
                        }]
                    }))
                }
                Err(e) => Err((INTERNAL_ERROR, format!("Failed to list rules: {e}"))),
            },
            "add" => {
                let pattern = validate_string_param(args, "pattern", MAX_KEY_LEN)?;
                let rule_type_str = validate_string_param(args, "rule_type", MAX_KEY_LEN)?;

                let rule_type = match rule_type_str.as_str() {
                    "whitelist" => RuleType::Allow,
                    "blacklist" => RuleType::Deny,
                    _ => {
                        return Err((
                            INVALID_PARAMS,
                            format!(
                                "Invalid rule_type: {rule_type_str}. Must be 'whitelist' or 'blacklist'"
                            ),
                        ));
                    }
                };

                let rule =
                    LearnedRule::new(pattern.clone(), rule_type.clone(), "mcp_tool".to_string());

                match self.storage.add_rule(&rule) {
                    Ok(_) => Ok(json!({
                        "content": [{
                            "type": "text",
                            "text": format!("Added {} rule for pattern: {}", rule_type.as_str(), pattern)
                        }]
                    })),
                    Err(e) => Err((INTERNAL_ERROR, format!("Failed to add rule: {e}"))),
                }
            }
            "remove" => {
                let pattern = validate_string_param(args, "pattern", MAX_KEY_LEN)?;

                match self.storage.delete_rule(&pattern) {
                    Ok(()) => Ok(json!({
                        "content": [{
                            "type": "text",
                            "text": format!("Removed rule for pattern: {}", pattern)
                        }]
                    })),
                    Err(e) => Err((INTERNAL_ERROR, format!("Failed to remove rule: {e}"))),
                }
            }
            "get_project_rules" => {
                let category = validate_optional_string_param(args, "category", MAX_KEY_LEN)?;
                let cwd = validate_optional_string_param(args, "cwd", MAX_KEY_LEN)?;
                let mut all_rules = Vec::new();

                // Get project path from cwd argument or current directory.
                // Canonicalize to resolve symlinks and ".." (prevents path traversal).
                let project_path = cwd
                    .and_then(|s| {
                        let path = std::path::PathBuf::from(s);
                        path.canonicalize().ok()
                    })
                    .or_else(|| env::current_dir().ok())
                    .unwrap_or_default();

                // Security: validate path is under home directory to prevent arbitrary file reads
                let home = dirs::home_dir().unwrap_or_default();
                if !project_path.starts_with(&home) {
                    return Err((
                        INVALID_PARAMS,
                        "Invalid project path: must be under home directory".to_string(),
                    ));
                }

                // 1. Check project-specific CLAUDE.md
                let project_claude_md = project_path.join("CLAUDE.md");
                if project_claude_md.exists()
                    && let Ok(content) = std::fs::read_to_string(&project_claude_md)
                {
                    let rules = if let Some(ref cat) = category {
                        extract_rules_by_category(&content, cat)
                    } else {
                        extract_all_critical_rules(&content)
                    };
                    if !rules.is_empty() {
                        all_rules.push(format!(
                            "## Project Rules ({})\n{}",
                            project_path.display(),
                            rules
                        ));
                    }
                }

                // 2. Check global CLAUDE.md at ~/.claude/CLAUDE.md
                if let Some(home) = dirs::home_dir() {
                    let global_claude_md = home.join(".claude").join("CLAUDE.md");
                    if global_claude_md.exists()
                        && let Ok(content) = std::fs::read_to_string(&global_claude_md)
                    {
                        let rules = if let Some(ref cat) = category {
                            extract_rules_by_category(&content, cat)
                        } else {
                            extract_all_critical_rules(&content)
                        };
                        if !rules.is_empty() {
                            all_rules
                                .push(format!("## Global Rules (~/.claude/CLAUDE.md)\n{rules}"));
                        }
                    }
                }

                let combined_rules = if all_rules.is_empty() {
                    "No CLAUDE.md rules found (checked project directory and ~/.claude/CLAUDE.md)"
                        .to_string()
                } else {
                    all_rules.join("\n\n")
                };

                Ok(json!({
                    "content": [{
                        "type": "text",
                        "text": combined_rules
                    }]
                }))
            }
            _ => Err((
                INVALID_PARAMS,
                format!(
                    "Invalid action: {action}. Must be 'get_project_rules', 'list', 'add', or 'remove'"
                ),
            )),
        }
    }
}

// =============================================================================
// CLAUDE.md Rule Extraction Helpers
// =============================================================================

/// Extract all critical rules from CLAUDE.md content
/// Looks for sections marked with priority indicators
fn extract_all_critical_rules(content: &str) -> String {
    clx_core::text::extract_critical_sections(content).join("\n---\n")
}

/// Extract rules by category from CLAUDE.md
/// Category is matched case-insensitively in section headers
pub(crate) fn extract_rules_by_category(content: &str, category: &str) -> String {
    let category_lower = category.to_lowercase();
    let mut rules = Vec::new();
    let mut in_matching_section = false;
    let mut current_section = String::new();

    for line in content.lines() {
        let trimmed = line.trim();

        // Check if this is a heading that matches the category
        if trimmed.starts_with('#') {
            // Save previous matching section if any
            if in_matching_section && !current_section.is_empty() {
                rules.push(current_section.clone());
            }

            in_matching_section = trimmed.to_lowercase().contains(&category_lower);
            current_section = if in_matching_section {
                format!("{line}\n")
            } else {
                String::new()
            };
        } else if in_matching_section {
            current_section.push_str(line);
            current_section.push('\n');
        }
    }

    // Don't forget the last section
    if in_matching_section && !current_section.is_empty() {
        rules.push(current_section);
    }

    if rules.is_empty() {
        format!("No rules found for category: {category}")
    } else {
        rules.join("\n---\n")
    }
}
