//! Type definitions and constants for the CLX hook binary.

use clx_core::types::SessionId;
use serde::{Deserialize, Serialize};

/// Maximum input size from stdin (1MB) to prevent `DoS` via memory exhaustion.
pub(crate) const MAX_INPUT_SIZE: u64 = 1_048_576;

/// Default summarization prompt for `PreCompact`.
pub(crate) const SUMMARIZE_PROMPT: &str = r#"Summarize this conversation transcript for context continuity. Extract:
1. Key decisions made
2. Important facts discovered
3. Pending TODOs
4. Current task status

Transcript:
{{transcript}}

Respond in this JSON format:
{"summary": "brief summary", "key_facts": ["fact1", "fact2"], "todos": ["todo1", "todo2"]}"#;

/// Hook input from Claude Code (common fields for all hooks)
/// Note: Claude Code sends `snake_case` JSON keys
#[derive(Debug, Deserialize)]
pub(crate) struct HookInput {
    /// Session ID from Claude Code
    pub session_id: SessionId,

    /// Path to transcript JSONL file
    pub transcript_path: Option<String>,

    /// Current working directory
    pub cwd: String,

    /// Name of the hook event
    pub hook_event_name: String,

    /// Tool name (for PreToolUse/PostToolUse)
    pub tool_name: Option<String>,

    /// Tool use ID (for PreToolUse/PostToolUse)
    pub tool_use_id: Option<String>,

    /// Tool input (for PreToolUse/PostToolUse)
    pub tool_input: Option<serde_json::Value>,

    /// Tool response/output (for `PostToolUse`) - Claude Code sends "`tool_response`"
    pub tool_response: Option<serde_json::Value>,

    /// Session source (for `SessionStart`)
    pub source: Option<String>,

    /// Trigger type (for `PreCompact`)
    pub trigger: Option<String>,

    /// User prompt text (for `UserPromptSubmit`)
    /// Used by auto-recall in the `UserPromptSubmit` hook handler.
    pub prompt: Option<String>,
}

/// Hook output for `PreToolUse`
#[derive(Debug, Serialize)]
pub(crate) struct HookOutput {
    #[serde(rename = "hookSpecificOutput")]
    pub hook_specific_output: HookSpecificOutput,

    #[serde(rename = "systemMessage", skip_serializing_if = "Option::is_none")]
    pub system_message: Option<String>,
}

/// Hook-specific output details
#[derive(Debug, Serialize)]
pub(crate) struct HookSpecificOutput {
    #[serde(rename = "hookEventName")]
    pub hook_event_name: String,

    #[serde(rename = "permissionDecision")]
    pub permission_decision: String,

    #[serde(
        rename = "permissionDecisionReason",
        skip_serializing_if = "Option::is_none"
    )]
    pub permission_decision_reason: Option<String>,

    #[serde(rename = "additionalContext", skip_serializing_if = "Option::is_none")]
    pub additional_context: Option<String>,
}

/// Generic hook output for events without permission decisions
/// (`SubagentStart`, `UserPromptSubmit`, `SessionStart`, etc.)
#[derive(Debug, Serialize)]
pub(crate) struct HookGenericOutput {
    #[serde(rename = "hookSpecificOutput")]
    pub hook_specific_output: HookGenericSpecificOutput,

    #[serde(rename = "systemMessage", skip_serializing_if = "Option::is_none")]
    pub system_message: Option<String>,
}

/// Generic hook-specific output without permission decision fields
#[derive(Debug, Serialize)]
pub(crate) struct HookGenericSpecificOutput {
    #[serde(rename = "hookEventName")]
    pub hook_event_name: String,

    #[serde(rename = "additionalContext", skip_serializing_if = "Option::is_none")]
    pub additional_context: Option<String>,
}

/// Message content in transcript - can be object with content field or string
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub(crate) enum TranscriptMessage {
    Object { content: String },
    String(String),
}

impl TranscriptMessage {
    pub fn content(&self) -> &str {
        match self {
            TranscriptMessage::Object { content } => content,
            TranscriptMessage::String(s) => s,
        }
    }
}

/// Transcript entry from JSONL file
#[derive(Debug, Deserialize)]
pub(crate) struct TranscriptEntry {
    #[serde(rename = "type")]
    pub entry_type: Option<String>,
    pub message: Option<TranscriptMessage>,
    pub tool: Option<String>,
}

/// Summary response from LLM
#[derive(Debug, Deserialize)]
pub(crate) struct SummaryResponse {
    pub summary: String,
    pub key_facts: Option<Vec<String>>,
    pub todos: Option<Vec<String>>,
}

/// Result from processing a transcript file
pub(crate) struct TranscriptResult {
    pub summary: Option<String>,
    pub key_facts: Option<String>,
    pub todos: Option<String>,
    pub message_count: Option<i32>,
    pub input_tokens: i64,
    pub output_tokens: i64,
}
