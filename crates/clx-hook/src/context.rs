//! Context loading for session start (previous summaries, project rules).

use crate::embedding::truncate_to_char_boundary;
use clx_core::storage::Storage;
use clx_core::types::SessionId;
use tracing::debug;

/// Load previous session summary for context
pub(crate) fn load_previous_session_summary(
    storage: &Storage,
    current_session_id: &SessionId,
    project_path: &str,
) -> Option<String> {
    // Get sessions for this project
    let sessions = storage.list_sessions_by_project(project_path).ok()?;

    // Find the most recent session that's not the current one
    let previous_session = sessions.into_iter().find(|s| &s.id != current_session_id)?;

    // Get the latest snapshot for that session
    let snapshot = storage
        .get_latest_snapshot(previous_session.id.as_str())
        .ok()??;

    snapshot.summary
}

/// Load rules from CLAUDE.md (project-specific and global)
pub(crate) fn load_project_rules(cwd: &str) -> Option<String> {
    use std::path::Path;

    let mut all_rules = Vec::new();

    // 1. Check project-specific CLAUDE.md
    let project_claude_md = Path::new(cwd).join("CLAUDE.md");
    if project_claude_md.exists()
        && let Ok(content) = std::fs::read_to_string(&project_claude_md)
    {
        let rules = extract_critical_rules(&content);
        if !rules.is_empty() {
            all_rules.push(format!("## Project Rules ({cwd})\n{rules}"));
        }
    }

    // 2. Check global CLAUDE.md at ~/.claude/CLAUDE.md
    if let Some(home) = dirs::home_dir() {
        let global_claude_md = home.join(".claude").join("CLAUDE.md");
        if global_claude_md.exists()
            && let Ok(content) = std::fs::read_to_string(&global_claude_md)
        {
            let rules = extract_critical_rules(&content);
            if !rules.is_empty() {
                all_rules.push(format!("## Global Rules (~/.claude/CLAUDE.md)\n{rules}"));
            }
        }
    }

    if all_rules.is_empty() {
        debug!("No CLAUDE.md rules found");
        None
    } else {
        Some(all_rules.join("\n\n"))
    }
}

/// Extract critical rules from CLAUDE.md content
/// Looks for sections marked with priority indicators like [CRITICAL], [MUST], [STRICT], etc.
pub(crate) fn extract_critical_rules(content: &str) -> String {
    let sections = clx_core::text::extract_critical_sections(content);
    let result = sections.join("\n---\n");
    if result.len() > 2000 {
        format!(
            "{}...\n[Truncated - use clx_rules for full rules]",
            truncate_to_char_boundary(&result, 2000)
        )
    } else {
        result
    }
}
