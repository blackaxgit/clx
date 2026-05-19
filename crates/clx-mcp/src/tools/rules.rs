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
                if !path_is_within_home(&project_path, dirs::home_dir().as_deref()) {
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
// Path Guard
// =============================================================================

/// Security guard: returns `true` only if `project_path` resides within the
/// user's home directory, defending against arbitrary file reads via crafted
/// `cwd` values (e.g. `../../etc`).
///
/// The caller passes an already-canonicalized `project_path` (symlinks and
/// `..` resolved). The home directory must be canonicalized on *this* side as
/// well, otherwise the comparison is asymmetric: on macOS the default temp dir
/// and frequently `$HOME` itself live under a symlink (`/var` ->
/// `/private/var`), so a canonicalized in-home `cwd` would not `starts_with`
/// the raw `$HOME` and every legitimate in-home lookup would be falsely
/// rejected.
///
/// Fallback behavior (never panics, never loosens the boundary):
/// - `home` is `None` (no home directory): deny. There is no valid in-home
///   path to admit, so refusing matches the original security intent.
/// - `home` canonicalization fails (home path does not exist / is not
///   accessible): fall back to the raw home value for the comparison. This is
///   the pre-fix behavior and is no looser than before; it does not admit any
///   path the original check rejected.
fn path_is_within_home(project_path: &std::path::Path, home: Option<&std::path::Path>) -> bool {
    let Some(home) = home else {
        // No home directory: nothing legitimate to admit. Deny (safe).
        return false;
    };

    // Canonicalize the home side to match the already-canonicalized
    // `project_path`. If canonicalize fails (e.g. home does not exist),
    // fall back to the raw value: identical to the original, no looser.
    let canonical_home = home.canonicalize().unwrap_or_else(|_| home.to_path_buf());

    project_path.starts_with(&canonical_home)
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

// =============================================================================
// Path Guard Regression Tests
// =============================================================================

#[cfg(test)]
mod path_guard_tests {
    use super::path_is_within_home;
    use std::os::unix::fs::symlink;

    /// Regression for the CLX 0.8.0 production bug: a legitimate `cwd` under a
    /// SYMLINKED home was falsely rejected because the guard canonicalized
    /// `cwd` but compared it against the raw, non-canonical `dirs::home_dir()`.
    ///
    /// Reproduction (deterministic on Linux AND macOS): create a real
    /// directory `real_home`, expose it through a symlink `linked_home`, and
    /// pass the *symlink* path as the home argument. The caller canonicalizes
    /// `cwd`, so `project_path` resolves to the real (non-symlinked) location;
    /// the guard MUST canonicalize the home side too in order to match. This
    /// mirrors the macOS `$HOME` / `/var -> /private/var` symlink condition
    /// without depending on the host OS.
    #[test]
    fn in_home_under_symlinked_home_is_accepted() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let real_home = tmp.path().join("real_home");
        std::fs::create_dir(&real_home).expect("create real_home");
        let project = real_home.join("project");
        std::fs::create_dir(&project).expect("create project");

        let linked_home = tmp.path().join("linked_home");
        symlink(&real_home, &linked_home).expect("symlink home");

        // `cwd` arrives canonicalized (symlinks resolved) exactly as the
        // production code does at the call site.
        let project_canon = project.canonicalize().expect("canonicalize project");

        // Pre-fix: rejected (canonical project vs raw symlinked home).
        // Post-fix: accepted (both sides canonicalized).
        assert!(
            path_is_within_home(&project_canon, Some(linked_home.as_path())),
            "legitimate in-home path under a symlinked home must be accepted"
        );
    }

    /// The security boundary is preserved: a genuine out-of-home path (the
    /// traversal-escape case) is STILL rejected even with a symlinked home.
    #[test]
    fn out_of_home_is_still_rejected() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let real_home = tmp.path().join("real_home");
        std::fs::create_dir(&real_home).expect("create real_home");
        let linked_home = tmp.path().join("linked_home");
        symlink(&real_home, &linked_home).expect("symlink home");

        // A sibling directory outside home, canonicalized like a real
        // `../../escape` would be after the call-site canonicalize().
        let outside = tmp.path().join("outside");
        std::fs::create_dir(&outside).expect("create outside");
        let outside_canon = outside.canonicalize().expect("canonicalize outside");

        assert!(
            !path_is_within_home(&outside_canon, Some(linked_home.as_path())),
            "path outside home must remain rejected (traversal guard intact)"
        );
        // /etc is the canonical real-world escape target; never under a home.
        assert!(
            !path_is_within_home(std::path::Path::new("/etc"), Some(real_home.as_path())),
            "/etc must never be accepted as in-home"
        );
    }

    /// Exactly-home is admitted (a project rooted at the home dir itself is a
    /// legitimate, in-boundary lookup), including through a symlinked home.
    #[test]
    fn exactly_home_is_accepted() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let real_home = tmp.path().join("real_home");
        std::fs::create_dir(&real_home).expect("create real_home");
        let linked_home = tmp.path().join("linked_home");
        symlink(&real_home, &linked_home).expect("symlink home");
        let home_canon = real_home.canonicalize().expect("canonicalize home");

        assert!(
            path_is_within_home(&home_canon, Some(linked_home.as_path())),
            "a project exactly at home must be accepted"
        );
    }

    /// `home_dir() == None`: deny without panicking. There is no legitimate
    /// in-home path when there is no home, so refusal preserves the original
    /// security intent.
    #[test]
    fn none_home_denies_safely() {
        assert!(
            !path_is_within_home(std::path::Path::new("/etc"), None),
            "absent home directory must deny (no panic)"
        );
        assert!(
            !path_is_within_home(std::path::Path::new("/home/someone/p"), None),
            "absent home directory must deny even for home-looking paths"
        );
    }

    /// Home path that does not exist (canonicalize fails): fall back to the
    /// raw value. Behavior is identical to pre-fix and no looser; a matching
    /// raw prefix is still admitted, a non-matching one still rejected.
    #[test]
    fn nonexistent_home_falls_back_to_raw_value() {
        let raw_home = std::path::Path::new("/nonexistent-clx-home-xyz");
        // Raw prefix match -> admitted (same as original behavior).
        assert!(path_is_within_home(
            std::path::Path::new("/nonexistent-clx-home-xyz/project"),
            Some(raw_home)
        ));
        // Non-matching -> still rejected (boundary not loosened).
        assert!(!path_is_within_home(
            std::path::Path::new("/etc"),
            Some(raw_home)
        ));
    }
}
