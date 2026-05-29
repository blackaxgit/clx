//! Type definitions and constants for the CLX hook binary.

use std::collections::HashMap;

use clx_core::types::SessionId;
use serde::{Deserialize, Serialize};

use crate::host::HostId;

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

/// Host-neutral hook input (v0.10.0).
///
/// This is the former `HookInput` (the Claude Code envelope shape) plus three
/// host-abstraction fields. For Claude the mapping is lossless: every legacy
/// field is carried verbatim, and the three new fields default
/// (`host = Claude`, `direct_command = None`, `extras = {}`). Other hosts
/// populate `direct_command` (Cursor `beforeShellExecution.command`),
/// `host`, and `extras` (Codex `model`/`turn_id`/`permission_mode`, etc.)
/// during their `Host::parse_hook_input`.
///
/// Note: hosts send `snake_case` JSON keys for the shared fields.
#[derive(Debug, Deserialize)]
pub(crate) struct HostNeutralInput {
    /// Session ID from the host.
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

    /// Tool response/output (for `PostToolUse`) - sent as "`tool_response`"
    pub tool_response: Option<serde_json::Value>,

    /// Session source (for `SessionStart`)
    pub source: Option<String>,

    /// Trigger type (for `PreCompact`)
    pub trigger: Option<String>,

    /// User prompt text (for `UserPromptSubmit`)
    /// Used by auto-recall in the `UserPromptSubmit` hook handler.
    pub prompt: Option<String>,

    /// A command surfaced at the top level of the envelope rather than under
    /// `tool_input.command` (e.g. Cursor `beforeShellExecution.command`).
    /// `None` for Claude. Defaulted on deserialize so the Claude envelope
    /// parses losslessly. Populated and consumed by the P2 host parsers.
    #[serde(default)]
    #[allow(dead_code)]
    pub direct_command: Option<String>,

    /// Which host produced this input. Defaults to `Claude` (the historical
    /// behaviour and the ambiguous-envelope fallback). Hosts overwrite this
    /// in their `parse_hook_input`.
    #[serde(default)]
    pub host: HostId,

    /// Host-specific envelope fields with no host-neutral home (Codex
    /// `model`/`turn_id`/`permission_mode`, etc.). Empty for Claude.
    /// Populated and consumed by the P2 host parsers.
    #[serde(default)]
    #[allow(dead_code)]
    pub extras: HashMap<String, serde_json::Value>,
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
