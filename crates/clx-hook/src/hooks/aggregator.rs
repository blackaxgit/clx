//! Pure aggregator helpers for `tool_events`.
//!
//! Layering: this module is *domain / pure* — no IO, no storage handles,
//! no async. It owns three pieces of logic that the orchestration layer
//! (`hooks::post_tool_use`) consumes:
//!
//! 1. Whitelist membership — which tools are considered mutators.
//! 2. Target normalization — `derive_target(tool, input)`.
//! 3. Summary templating  — `derive_summary(tool, input, outcome)`.
//!
//! Everything here is deterministic and safe to call from any context.

use std::path::{Component, Path, PathBuf};
use std::sync::OnceLock;

use regex::Regex;
use serde_json::Value;

use clx_core::types::ToolOutcome;

use crate::host::Host;

/// Maximum length (in chars, not bytes) of a generated summary line.
const SUMMARY_MAX_CHARS: usize = 160;

/// Maximum length (in chars) of the Bash command appended to a summary.
const BASH_TRUNCATE_CHARS: usize = 80;

/// Return `true` if `tool` is a text-mutator for `host`.
///
/// Host-aware: delegates to [`Host::is_mutator_tool`] so the mutator set is the
/// host's own (Claude Edit/Write/..., Codex `apply_patch`, Cursor `edit_file`).
#[must_use]
pub fn is_text_mutator(tool: &str, host: &dyn Host) -> bool {
    host.is_mutator_tool(tool)
}

/// Return `true` if `tool` should be aggregated for `host` (text mutator or
/// mutator Bash). Host-aware: the text-mutator check routes through
/// [`Host::is_mutator_tool`].
#[must_use]
pub fn should_aggregate(tool: &str, input: &Value, host: &dyn Host) -> bool {
    if is_text_mutator(tool, host) {
        return true;
    }
    if tool == "Bash"
        && let Some(cmd) = input.get("command").and_then(Value::as_str)
    {
        return is_mutator_bash(cmd);
    }
    false
}

/// Return `true` if a Bash `command` string looks like a mutating action.
///
/// The regex is intentionally conservative: it matches on the leading verb
/// of the command. Users can disable the entire aggregator via
/// `retention.tool_events_days: 0` if they want to opt out.
#[must_use]
pub fn is_mutator_bash(command: &str) -> bool {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        // Anchored at start with optional leading whitespace. Captures the
        // common mutating verbs and shell redirections that write files.
        Regex::new(
            r"(?i)^\s*(git\s+(commit|push|reset|rebase|merge|cherry-pick|checkout\s+-{1,2})\b|rm\s|cargo\s+install\b|npm\s+install\b|pip\s+install\b|mv\s|cp\s|chmod\s|chown\s|>\s*/)",
        )
        .expect("aggregator: static mutator-bash regex must compile")
    });
    re.is_match(command)
}

/// Derive the normalized target for a tool invocation.
///
/// - Edit / Write / `MultiEdit` / `NotebookEdit`: canonicalize `file_path` (or
///   `notebook_path`) via [`normalize_path`]. Returns `None` if the field
///   is missing.
/// - Bash: lowercase the first verb token, joining `git X` style two-word
///   verbs with a dash (e.g. `git commit ...` -> `git-commit`).
/// - Anything else: `None`.
#[must_use]
pub fn derive_target(tool: &str, input: &Value) -> Option<String> {
    match tool {
        "Edit" | "Write" | "MultiEdit" => input
            .get("file_path")
            .and_then(Value::as_str)
            .map(normalize_path),
        "NotebookEdit" => input
            .get("notebook_path")
            .and_then(Value::as_str)
            .map(normalize_path),
        "Bash" => input
            .get("command")
            .and_then(Value::as_str)
            .map(derive_bash_verb),
        _ => None,
    }
}

/// Derive a deterministic 1-line summary for a tool invocation.
///
/// Templates (see plan §C1.5):
/// - `Edit`: `edit <basename> (chars: <old_len>-><new_len>)`
/// - `Write`: `write <basename> (<bytes> bytes)`
/// - `MultiEdit`: `multi-edit <basename> (<n> edits)`
/// - `NotebookEdit`: `notebook <basename> cell <cell_id_or_idx>`
/// - `Bash`: `bash <verb>: <truncated 80 chars>`
///
/// Includes `[error]` prefix when `outcome == Error`.
#[must_use]
pub fn derive_summary(tool: &str, input: &Value, outcome: ToolOutcome) -> String {
    let body = match tool {
        "Edit" => {
            let basename = basename_or_unknown(input.get("file_path").and_then(Value::as_str));
            let old_len = input
                .get("old_string")
                .and_then(Value::as_str)
                .map_or(0, |s| s.chars().count());
            let new_len = input
                .get("new_string")
                .and_then(Value::as_str)
                .map_or(0, |s| s.chars().count());
            format!("edit {basename} (chars: {old_len}->{new_len})")
        }
        "Write" => {
            let basename = basename_or_unknown(input.get("file_path").and_then(Value::as_str));
            let bytes = input
                .get("content")
                .and_then(Value::as_str)
                .map_or(0, str::len);
            format!("write {basename} ({bytes} bytes)")
        }
        "MultiEdit" => {
            let basename = basename_or_unknown(input.get("file_path").and_then(Value::as_str));
            let n = input
                .get("edits")
                .and_then(Value::as_array)
                .map_or(0, Vec::len);
            format!("multi-edit {basename} ({n} edits)")
        }
        "NotebookEdit" => {
            let basename = basename_or_unknown(input.get("notebook_path").and_then(Value::as_str));
            let cell = input
                .get("cell_id")
                .and_then(Value::as_str)
                .map(str::to_string)
                .or_else(|| {
                    input
                        .get("cell_number")
                        .and_then(Value::as_i64)
                        .map(|i| i.to_string())
                })
                .unwrap_or_else(|| "?".to_string());
            format!("notebook {basename} cell {cell}")
        }
        "Bash" => {
            let cmd = input.get("command").and_then(Value::as_str).unwrap_or("");
            let verb = derive_bash_verb(cmd);
            let snippet = truncate_chars(cmd.trim(), BASH_TRUNCATE_CHARS);
            format!("bash {verb}: {snippet}")
        }
        other => format!("{other} (no template)"),
    };

    let summary = match outcome {
        ToolOutcome::Success => body,
        ToolOutcome::Error => format!("[error] {body}"),
    };
    truncate_chars(&summary, SUMMARY_MAX_CHARS)
}

// ---- internal helpers ----------------------------------------------------

fn basename_or_unknown(path: Option<&str>) -> String {
    match path {
        Some(p) => {
            let pb = PathBuf::from(p);
            pb.file_name()
                .map_or_else(|| "?".to_string(), |s| s.to_string_lossy().to_string())
        }
        None => "?".to_string(),
    }
}

/// Normalize a path by stripping leading `./` and collapsing `..` in a
/// purely-lexical fashion (no filesystem touch, no symlink resolution).
///
/// Trailing separators are preserved as-is from `PathBuf::components`.
#[must_use]
pub fn normalize_path(path: &str) -> String {
    let p = Path::new(path);
    let mut out = PathBuf::new();
    for comp in p.components() {
        match comp {
            Component::CurDir => {}
            Component::ParentDir => {
                // Lexical `..` collapse: pop if we have something to pop,
                // otherwise preserve the `..`.
                if !out.pop() {
                    out.push("..");
                }
            }
            Component::Normal(s) => out.push(s),
            Component::RootDir => out.push("/"),
            Component::Prefix(p) => out.push(p.as_os_str()),
        }
    }
    let s = out.to_string_lossy().to_string();
    if s.is_empty() { path.to_string() } else { s }
}

/// Derive the verb token for a Bash command (e.g. `git commit -m ...` ->
/// `git-commit`).
///
/// Lowercased. Two-word verbs of the form `git <sub>` collapse into
/// `git-<sub>`. Unknown commands fall back to the first whitespace-
/// separated token. Empty input returns `"unknown"`.
#[must_use]
pub fn derive_bash_verb(command: &str) -> String {
    let trimmed = command.trim();
    if trimmed.is_empty() {
        return "unknown".to_string();
    }
    let mut tokens = trimmed.split_whitespace();
    let first = tokens.next().unwrap_or("").to_lowercase();
    if first == "git"
        && let Some(sub) = tokens.next()
    {
        return format!("git-{}", sub.to_lowercase());
    }
    first
}

fn truncate_chars(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::{ClaudeHost, CodexHost, CursorHost};
    use serde_json::json;

    // --- whitelist (host-aware + host-less fallback) ---

    #[test]
    fn is_text_mutator_recognizes_all_four() {
        let host = ClaudeHost;
        for t in ["Edit", "Write", "MultiEdit", "NotebookEdit"] {
            assert!(is_text_mutator(t, &host), "{t} should be a mutator");
        }
    }

    #[test]
    fn is_text_mutator_rejects_reads() {
        let host = ClaudeHost;
        for t in ["Read", "Grep", "Glob", "LS", "WebFetch", "Bash"] {
            assert!(!is_text_mutator(t, &host));
        }
    }

    #[test]
    fn is_text_mutator_is_host_specific() {
        // Codex aggregates apply_patch, not Claude's Edit/Write.
        let codex = CodexHost;
        assert!(is_text_mutator("apply_patch", &codex));
        assert!(!is_text_mutator("Edit", &codex));
        // Cursor aggregates edit_file.
        let cursor = CursorHost;
        assert!(is_text_mutator("edit_file", &cursor));
        assert!(!is_text_mutator("apply_patch", &cursor));
    }

    #[test]
    fn claude_host_mutator_set_is_exactly_the_four_text_mutators() {
        // The Claude mutator set (formerly the host-less `CLAUDE_MUTATOR_TOOLS`
        // const, now removed) is exercised through the authoritative host-aware
        // path: ClaudeHost::is_mutator_tool must accept exactly the four text
        // mutators and reject everything else.
        let host = ClaudeHost;
        for t in ["Edit", "Write", "MultiEdit", "NotebookEdit"] {
            assert!(is_text_mutator(t, &host), "{t} must be a Claude mutator");
        }
        for t in ["Read", "Grep", "Glob", "LS", "WebFetch", "Bash", "Task"] {
            assert!(
                !is_text_mutator(t, &host),
                "{t} must NOT be a Claude text mutator"
            );
        }
    }

    // --- should_aggregate (host-aware) ---

    #[test]
    fn should_aggregate_edit_yes() {
        let host = ClaudeHost;
        assert!(should_aggregate(
            "Edit",
            &json!({"file_path": "a.rs"}),
            &host
        ));
    }

    #[test]
    fn should_aggregate_read_no() {
        let host = ClaudeHost;
        assert!(!should_aggregate(
            "Read",
            &json!({"file_path": "a.rs"}),
            &host
        ));
    }

    #[test]
    fn should_aggregate_codex_apply_patch_yes() {
        let codex = CodexHost;
        assert!(should_aggregate(
            "apply_patch",
            &json!({"input": "diff"}),
            &codex
        ));
    }

    #[test]
    fn should_aggregate_bash_mutator_yes() {
        let host = ClaudeHost;
        assert!(should_aggregate(
            "Bash",
            &json!({"command": "git commit -m 'x'"}),
            &host
        ));
    }

    #[test]
    fn should_aggregate_bash_reads_no() {
        let host = ClaudeHost;
        assert!(!should_aggregate(
            "Bash",
            &json!({"command": "ls -la"}),
            &host
        ));
        assert!(!should_aggregate(
            "Bash",
            &json!({"command": "git status"}),
            &host
        ));
        assert!(!should_aggregate(
            "Bash",
            &json!({"command": "grep -r foo ."}),
            &host
        ));
    }

    // --- is_mutator_bash ---

    #[test]
    fn is_mutator_bash_matches_git_commit() {
        assert!(is_mutator_bash("git commit -m 'msg'"));
        assert!(is_mutator_bash("  git commit"));
        assert!(is_mutator_bash("git push origin main"));
        assert!(is_mutator_bash("git reset --hard HEAD"));
    }

    #[test]
    fn is_mutator_bash_rejects_git_status() {
        assert!(!is_mutator_bash("git status"));
        assert!(!is_mutator_bash("git log -5"));
        assert!(!is_mutator_bash("git diff"));
    }

    #[test]
    fn is_mutator_bash_rejects_ls() {
        assert!(!is_mutator_bash("ls -la"));
        assert!(!is_mutator_bash("cat foo.rs"));
        assert!(!is_mutator_bash("grep -r pattern ."));
    }

    #[test]
    fn is_mutator_bash_matches_rm_mv_cp() {
        assert!(is_mutator_bash("rm -rf build/"));
        assert!(is_mutator_bash("mv a.txt b.txt"));
        assert!(is_mutator_bash("cp a.txt b.txt"));
    }

    #[test]
    fn is_mutator_bash_matches_install() {
        assert!(is_mutator_bash("cargo install ripgrep"));
        assert!(is_mutator_bash("npm install"));
        assert!(is_mutator_bash("pip install requests"));
    }

    #[test]
    fn is_mutator_bash_matches_chmod_chown() {
        assert!(is_mutator_bash("chmod +x build.sh"));
        assert!(is_mutator_bash("chown root:wheel /etc/foo"));
    }

    // --- derive_target ---

    #[test]
    fn derive_target_edit_normalizes_relative_path() {
        let t = derive_target("Edit", &json!({"file_path": "./src/foo.rs"}));
        assert_eq!(t.as_deref(), Some("src/foo.rs"));
    }

    #[test]
    fn derive_target_edit_collapses_dotdot() {
        let t = derive_target("Edit", &json!({"file_path": "src/../lib/bar.rs"}));
        assert_eq!(t.as_deref(), Some("lib/bar.rs"));
    }

    #[test]
    fn derive_target_edit_preserves_absolute_path() {
        let t = derive_target("Edit", &json!({"file_path": "/abs/foo.rs"}));
        assert_eq!(t.as_deref(), Some("/abs/foo.rs"));
    }

    #[test]
    fn derive_target_write_uses_file_path() {
        let t = derive_target("Write", &json!({"file_path": "./out.txt"}));
        assert_eq!(t.as_deref(), Some("out.txt"));
    }

    #[test]
    fn derive_target_multiedit_uses_file_path() {
        let t = derive_target("MultiEdit", &json!({"file_path": "./x.rs"}));
        assert_eq!(t.as_deref(), Some("x.rs"));
    }

    #[test]
    fn derive_target_notebook_edit_uses_notebook_path() {
        let t = derive_target("NotebookEdit", &json!({"notebook_path": "./nb.ipynb"}));
        assert_eq!(t.as_deref(), Some("nb.ipynb"));
    }

    #[test]
    fn derive_target_bash_lowercases_verb() {
        let t = derive_target("Bash", &json!({"command": "Git Commit -m 'x'"}));
        assert_eq!(t.as_deref(), Some("git-commit"));
    }

    #[test]
    fn derive_target_bash_single_token_verb() {
        let t = derive_target("Bash", &json!({"command": "RM -rf /tmp/foo"}));
        assert_eq!(t.as_deref(), Some("rm"));
    }

    #[test]
    fn derive_target_unknown_tool_is_none() {
        let t = derive_target("Read", &json!({"file_path": "a.rs"}));
        assert_eq!(t, None);
    }

    #[test]
    fn derive_target_missing_field_is_none() {
        let t = derive_target("Edit", &json!({}));
        assert_eq!(t, None);
    }

    // --- derive_summary ---

    #[test]
    fn derive_summary_edit_template() {
        let s = derive_summary(
            "Edit",
            &json!({
                "file_path": "src/foo.rs",
                "old_string": "abc",
                "new_string": "abcdef",
            }),
            ToolOutcome::Success,
        );
        assert_eq!(s, "edit foo.rs (chars: 3->6)");
    }

    #[test]
    fn derive_summary_write_template() {
        let s = derive_summary(
            "Write",
            &json!({"file_path": "out.txt", "content": "hello"}),
            ToolOutcome::Success,
        );
        assert_eq!(s, "write out.txt (5 bytes)");
    }

    #[test]
    fn derive_summary_multiedit_template() {
        let s = derive_summary(
            "MultiEdit",
            &json!({"file_path": "src/x.rs", "edits": [{}, {}, {}]}),
            ToolOutcome::Success,
        );
        assert_eq!(s, "multi-edit x.rs (3 edits)");
    }

    #[test]
    fn derive_summary_notebook_template_with_cell_id() {
        let s = derive_summary(
            "NotebookEdit",
            &json!({"notebook_path": "nb.ipynb", "cell_id": "abc-123"}),
            ToolOutcome::Success,
        );
        assert_eq!(s, "notebook nb.ipynb cell abc-123");
    }

    #[test]
    fn derive_summary_notebook_template_with_cell_number() {
        let s = derive_summary(
            "NotebookEdit",
            &json!({"notebook_path": "nb.ipynb", "cell_number": 4}),
            ToolOutcome::Success,
        );
        assert_eq!(s, "notebook nb.ipynb cell 4");
    }

    #[test]
    fn derive_summary_bash_template() {
        let s = derive_summary(
            "Bash",
            &json!({"command": "git commit -m 'my message'"}),
            ToolOutcome::Success,
        );
        assert_eq!(s, "bash git-commit: git commit -m 'my message'");
    }

    #[test]
    fn derive_summary_bash_truncates_at_80_chars_utf8_safe() {
        // 200 char command including multi-byte chars must not panic and
        // must respect char (not byte) truncation in the snippet body.
        let long = "git commit -m '".to_string() + &"é".repeat(200) + "'";
        let s = derive_summary("Bash", &json!({"command": long}), ToolOutcome::Success);
        // Just verify no panic and that snippet portion is bounded.
        // Total summary cap is SUMMARY_MAX_CHARS.
        assert!(s.chars().count() <= 160);
        assert!(s.starts_with("bash git-commit:"));
    }

    #[test]
    fn derive_summary_error_outcome_prefixed() {
        let s = derive_summary(
            "Edit",
            &json!({"file_path": "a.rs", "old_string": "x", "new_string": "y"}),
            ToolOutcome::Error,
        );
        assert!(s.starts_with("[error]"));
        assert!(s.contains("edit a.rs"));
    }

    #[test]
    fn derive_summary_missing_fields_dont_panic() {
        let s = derive_summary("Edit", &json!({}), ToolOutcome::Success);
        assert!(s.starts_with("edit ?"));
    }

    // --- normalize_path / derive_bash_verb edge cases ---

    #[test]
    fn normalize_path_strips_curdir() {
        assert_eq!(normalize_path("./a/b.rs"), "a/b.rs");
    }

    #[test]
    fn normalize_path_collapses_parent() {
        assert_eq!(normalize_path("a/../b"), "b");
    }

    #[test]
    fn derive_bash_verb_empty_returns_unknown() {
        assert_eq!(derive_bash_verb(""), "unknown");
        assert_eq!(derive_bash_verb("   "), "unknown");
    }

    #[test]
    fn derive_bash_verb_lone_git_returns_git() {
        assert_eq!(derive_bash_verb("git"), "git");
    }
}
