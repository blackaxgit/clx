//! Context loading for session start (previous summaries, project rules).

use crate::embedding::truncate_to_char_boundary;
use crate::host::Host;
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

/// Load rules from the host's instructions file (project-specific and global).
///
/// The instructions filename and the global path are routed through the
/// `Host` trait so that non-Claude hosts read `AGENTS.md` / `.cursor/rules`
/// instead of `CLAUDE.md`. For `ClaudeHost` the behaviour is byte-identical
/// to the pre-v0.10.0 implementation: project file `cwd/CLAUDE.md`, global
/// file `~/.claude/CLAUDE.md`, and the same header strings.
pub(crate) fn load_project_rules(cwd: &str, host: &dyn Host) -> Option<String> {
    use std::path::Path;

    let mut all_rules = Vec::new();
    let label = host.instructions_file_label();

    // 1. Check project-specific instructions file (e.g. cwd/CLAUDE.md).
    let project_instructions = Path::new(cwd).join(label);
    if project_instructions.exists()
        && let Ok(content) = std::fs::read_to_string(&project_instructions)
    {
        let rules = extract_critical_rules(&content);
        if !rules.is_empty() {
            all_rules.push(format!("## Project Rules ({cwd})\n{rules}"));
        }
    }

    // 2. Check the host's global instructions file (e.g. ~/.claude/CLAUDE.md).
    //    Cursor has no global file (`global_instructions_path` -> None).
    if let Some(home) = dirs::home_dir()
        && let Some(global_path) = host.global_instructions_path(&home)
        && global_path.exists()
        && let Ok(content) = std::fs::read_to_string(&global_path)
    {
        let rules = extract_critical_rules(&content);
        if !rules.is_empty() {
            // Render the global path with a `~` prefix when it lives under
            // $HOME, preserving the historical "~/.claude/CLAUDE.md" header.
            let display = global_path.strip_prefix(&home).map_or_else(
                |_| global_path.display().to_string(),
                |rel| format!("~/{}", rel.display()),
            );
            all_rules.push(format!("## Global Rules ({display})\n{rules}"));
        }
    }

    if all_rules.is_empty() {
        debug!("No {label} rules found");
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
