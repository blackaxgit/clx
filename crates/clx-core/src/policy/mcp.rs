//! MCP tool command extraction.
//!
//! Extracts executable commands from MCP tool inputs so they can be
//! validated through the same [`PolicyEngine`](super::PolicyEngine)
//! used for Bash commands.

use super::matching::glob_match;
use crate::config::McpCommandTool;

/// Result of attempting to extract a command from an MCP tool call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum McpExtraction {
    /// Tool matched a registry entry and a command was extracted. `command`
    /// may be EMPTY when the registry entry matched but `command_field` was
    /// missing/absent from `tool_input` — see [`McpExtraction::is_missing_command`]
    /// (P2-2): callers MUST treat that case as fail-CLOSED (Ask/Deny), never
    /// as an implicit Allow.
    Command(String),

    /// Tool is not in the command-tools registry (not a command-bearing tool).
    NotCommandTool,
}

impl McpExtraction {
    /// P2-2: true if this is a matched command-tool call whose command is
    /// missing or empty.
    ///
    /// A registry entry matched `tool_name` (this IS a command-bearing tool),
    /// but `tool_input[command_field]` was absent, non-string, or the empty
    /// string. This is NOT "safe to allow" — an empty command commonly
    /// indicates a malformed/spoofed tool-call envelope (a field rename, a
    /// client bug, or an attacker probing the registry match without
    /// supplying a payload) rather than a genuinely empty, harmless
    /// invocation. Callers MUST route this to a fail-CLOSED decision (Ask or
    /// Deny) rather than the Allow a truly absent/`NotCommandTool` case might
    /// otherwise receive via a permissive `default_decision`.
    #[must_use]
    pub fn is_missing_command(&self) -> bool {
        matches!(self, Self::Command(cmd) if cmd.is_empty())
    }
}

/// Extract an executable command from an MCP tool's input.
///
/// Iterates `command_tools`, matching `tool_name` against each entry's
/// `tool_pattern` using glob matching. On the first match, extracts
/// `tool_input[command_field]` as the command string.
///
/// - Match found, field present  → `Command(value)`
/// - Match found, field missing  → `Command("")`. This does NOT mean "safe to
///   allow" (P2-2) — callers MUST check
///   [`McpExtraction::is_missing_command`] and fail CLOSED (Ask/Deny) for
///   this case rather than treating an empty command as an implicit auto-allow.
/// - No match                    → `NotCommandTool`
#[must_use]
pub fn extract_mcp_command(
    tool_name: &str,
    tool_input: &serde_json::Value,
    command_tools: &[McpCommandTool],
) -> McpExtraction {
    for entry in command_tools {
        if glob_match(&entry.tool_pattern, tool_name) {
            let command = tool_input
                .get(&entry.command_field)
                .and_then(serde_json::Value::as_str)
                .unwrap_or("")
                .to_string();
            return McpExtraction::Command(command);
        }
    }
    McpExtraction::NotCommandTool
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn default_command_tools() -> Vec<McpCommandTool> {
        vec![
            McpCommandTool {
                tool_pattern: "mcp__*__execute".to_string(),
                command_field: "command".to_string(),
            },
            McpCommandTool {
                tool_pattern: "mcp__puppeteer__puppeteer_evaluate".to_string(),
                command_field: "script".to_string(),
            },
            McpCommandTool {
                tool_pattern: "mcp__playwright__browser_evaluate".to_string(),
                command_field: "function".to_string(),
            },
            McpCommandTool {
                tool_pattern: "mcp__playwright__browser_run_code".to_string(),
                command_field: "code".to_string(),
            },
        ]
    }

    #[test]
    fn test_ssh_execute_extraction() {
        let tools = default_command_tools();
        let input = json!({"command": "rm -rf /tmp/foo"});

        let result = extract_mcp_command("mcp__ssh__execute", &input, &tools);
        assert_eq!(
            result,
            McpExtraction::Command("rm -rf /tmp/foo".to_string())
        );
    }

    #[test]
    fn test_any_server_execute_matches_wildcard() {
        let tools = default_command_tools();
        let input = json!({"command": "ls -la"});

        let result = extract_mcp_command("mcp__myserver__execute", &input, &tools);
        assert_eq!(result, McpExtraction::Command("ls -la".to_string()));
    }

    #[test]
    fn test_playwright_evaluate_extraction() {
        let tools = default_command_tools();
        let input = json!({"function": "() => document.title"});

        let result = extract_mcp_command("mcp__playwright__browser_evaluate", &input, &tools);
        assert_eq!(
            result,
            McpExtraction::Command("() => document.title".to_string())
        );
    }

    #[test]
    fn test_playwright_run_code_extraction() {
        let tools = default_command_tools();
        let input = json!({"code": "async (page) => { await page.goto('http://example.com'); }"});

        let result = extract_mcp_command("mcp__playwright__browser_run_code", &input, &tools);
        assert_eq!(
            result,
            McpExtraction::Command(
                "async (page) => { await page.goto('http://example.com'); }".to_string()
            )
        );
    }

    #[test]
    fn test_puppeteer_evaluate_extraction() {
        let tools = default_command_tools();
        let input = json!({"script": "document.cookie"});

        let result = extract_mcp_command("mcp__puppeteer__puppeteer_evaluate", &input, &tools);
        assert_eq!(
            result,
            McpExtraction::Command("document.cookie".to_string())
        );
    }

    #[test]
    fn test_non_command_tool_returns_not_command() {
        let tools = default_command_tools();
        let input = json!({"libraryName": "react", "query": "hooks"});

        let result = extract_mcp_command("mcp__context7__resolve-library-id", &input, &tools);
        assert_eq!(result, McpExtraction::NotCommandTool);
    }

    #[test]
    fn test_missing_command_field_returns_empty() {
        let tools = default_command_tools();
        let input = json!({"other_field": "value"});

        let result = extract_mcp_command("mcp__ssh__execute", &input, &tools);
        assert_eq!(result, McpExtraction::Command(String::new()));
    }

    // =====================================================================
    // P2-2 — missing/empty MCP command must fail CLOSED, not Allow.
    //
    // `extract_mcp_command` itself only extracts; it does not decide. The
    // decision (auto-allow vs. Ask/Deny) is made by the caller
    // (`crates/clx-hook/src/hooks/pre_tool_use.rs`), which is out of this
    // module's scope. `McpExtraction::is_missing_command` is the fail-closed
    // primitive this module now exposes so that caller can distinguish "a
    // matched command-tool with no usable command" (must Ask/Deny) from "a
    // matched command-tool with a real command" (must go through normal L0/L1
    // validation) — see the updated `McpExtraction::Command` doc comment,
    // which no longer claims empty is "safe to allow".
    // =====================================================================

    #[test]
    fn p2_2_is_missing_command_true_for_absent_field() {
        let tools = default_command_tools();
        let input = json!({"other_field": "value"});
        let result = extract_mcp_command("mcp__ssh__execute", &input, &tools);
        assert!(
            result.is_missing_command(),
            "a matched command-tool with an absent command field must be flagged missing"
        );
    }

    #[test]
    fn p2_2_is_missing_command_true_for_empty_string_field() {
        let tools = default_command_tools();
        let input = json!({"command": ""});
        let result = extract_mcp_command("mcp__ssh__execute", &input, &tools);
        assert!(
            result.is_missing_command(),
            "a matched command-tool with an explicit empty-string command must be flagged missing"
        );
    }

    #[test]
    fn p2_2_is_missing_command_false_for_real_command() {
        let tools = default_command_tools();
        let input = json!({"command": "ls -la"});
        let result = extract_mcp_command("mcp__ssh__execute", &input, &tools);
        assert!(
            !result.is_missing_command(),
            "a real, non-empty command must not be flagged missing"
        );
    }

    #[test]
    fn p2_2_is_missing_command_false_for_not_command_tool() {
        let tools = default_command_tools();
        let input = json!({"libraryName": "react"});
        let result = extract_mcp_command("mcp__context7__resolve-library-id", &input, &tools);
        assert!(
            !result.is_missing_command(),
            "NotCommandTool is a distinct case from a matched-but-empty command"
        );
    }

    #[test]
    fn test_empty_registry() {
        let tools: Vec<McpCommandTool> = vec![];
        let input = json!({"command": "ls"});

        let result = extract_mcp_command("mcp__ssh__execute", &input, &tools);
        assert_eq!(result, McpExtraction::NotCommandTool);
    }

    #[test]
    fn test_non_mcp_tool_not_matched() {
        let tools = default_command_tools();
        let input = json!({"command": "ls"});

        let result = extract_mcp_command("Bash", &input, &tools);
        assert_eq!(result, McpExtraction::NotCommandTool);
    }

    #[test]
    fn test_first_matching_pattern_wins() {
        let tools = vec![
            McpCommandTool {
                tool_pattern: "mcp__ssh__*".to_string(),
                command_field: "cmd".to_string(),
            },
            McpCommandTool {
                tool_pattern: "mcp__*__execute".to_string(),
                command_field: "command".to_string(),
            },
        ];
        let input = json!({"cmd": "first", "command": "second"});

        let result = extract_mcp_command("mcp__ssh__execute", &input, &tools);
        assert_eq!(result, McpExtraction::Command("first".to_string()));
    }
}
