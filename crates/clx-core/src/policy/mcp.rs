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
    /// Tool matched a registry entry and a command was extracted.
    Command(String),

    /// Tool is not in the command-tools registry (not a command-bearing tool).
    NotCommandTool,
}

/// Extract an executable command from an MCP tool's input.
///
/// Iterates `command_tools`, matching `tool_name` against each entry's
/// `tool_pattern` using glob matching. On the first match, extracts
/// `tool_input[command_field]` as the command string.
///
/// - Match found, field present  → `Command(value)`
/// - Match found, field missing  → `Command("")` (empty = safe to allow)
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
