//! `CursorHost`: the Cursor IDE host.
//!
//! Capability methods are real (resolved from P0 evidence F7 + research).
//! P2 fills the `beforeShellExecution` envelope parser, the flat-`permission`
//! response writer, and the `state.vscdb` `SQLite` transcript parser
//! (`cursor/transcript.rs`).
//!
//! P0 findings encoded here:
//! - F7: Cursor hooks are GUI-only (no `cursor-agent` CLI surface), so
//!   gating scope is [`GatingScope::GuiOnly`].
//! - F7: Cursor DOES support interactive `ask` via a flat `permission`
//!   field ([`AskChannel::FlatPermissionField`]).
//! - F7: the documented `beforeShellExecution` envelope carries a top-level
//!   `command`, a `conversation_id`, and `workspace_roots`. CLX maps
//!   `conversation_id` -> `session_id`, `workspace_roots[0]` -> `cwd`, the
//!   top-level `command` -> `direct_command`, and normalizes the camelCase
//!   event name to the `PascalCase` the handlers expect.
//! - Transcript lives in `SQLite` (`state.vscdb`), not JSONL.
//! - Cursor uses project-scoped `.cursor/rules` only - no global
//!   instructions file, so `global_instructions_path` returns `None`.

use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clx_core::policy::PolicyDecision;
use clx_core::types::SessionId;
use serde::{Deserialize, Serialize};

use super::{AskChannel, GatingScope, Host, HostId, TranscriptBackend};
use crate::types::HostNeutralInput;

pub(crate) mod transcript;

/// The Cursor IDE host.
pub(crate) struct CursorHost;

/// The raw Cursor hook envelope (documented `beforeShellExecution` /
/// `beforeMCPExecution` shape, F7). Every field is optional so a partial or
/// forward-evolved envelope still parses; the mapping into
/// [`HostNeutralInput`] applies the documented defaults.
#[derive(Debug, Deserialize, Default)]
struct CursorEnvelope {
    /// Cursor's session identifier. CLX maps this to `session_id`.
    conversation_id: Option<String>,
    /// Some builds also expose a plain `session_id`; honoured as a fallback.
    session_id: Option<String>,
    /// Open workspace roots; `[0]` becomes `cwd`.
    #[serde(default)]
    workspace_roots: Vec<String>,
    /// Explicit cwd, if the envelope carries one (preferred over roots).
    cwd: Option<String>,
    /// camelCase event name (`beforeShellExecution`, ...).
    hook_event_name: Option<String>,
    /// Top-level shell command (the gating subject for shell events).
    command: Option<String>,
    /// Tool name for MCP execution events.
    tool_name: Option<String>,
    /// Tool input payload, if present.
    tool_input: Option<serde_json::Value>,
}

/// Cursor's flat-`permission` response (F7). Unlike Claude/Codex there is no
/// `hookSpecificOutput` envelope: the decision is a single top-level field.
#[derive(Debug, Serialize)]
struct CursorDecisionOutput {
    /// `allow` / `deny` / `ask` (Cursor supports interactive ask).
    permission: String,

    /// Human-readable reason surfaced in the GUI prompt.
    #[serde(rename = "userMessage", skip_serializing_if = "Option::is_none")]
    user_message: Option<String>,

    /// Optional extra context (system message folded in).
    #[serde(rename = "agentMessage", skip_serializing_if = "Option::is_none")]
    agent_message: Option<String>,
}

/// Cursor's generic (no permission) response for lifecycle events.
#[derive(Debug, Serialize)]
struct CursorGenericOutput {
    #[serde(rename = "agentMessage", skip_serializing_if = "Option::is_none")]
    agent_message: Option<String>,
}

/// Normalize a Cursor camelCase event name to the `PascalCase` the CLX
/// handlers dispatch on. `beforeShellExecution` -> `PreToolUse` (shell gating
/// is the `PreToolUse` surface), `beforeMCPExecution` -> `PreToolUse`.
/// Lifecycle names are `PascalCase` so they line up with the shared router
/// arms. Unknown names pass through unchanged so forward-compat events are not
/// silently dropped.
fn normalize_event_name(raw: &str) -> String {
    match raw {
        // Gating surfaces both map to the shared PreToolUse handler.
        "beforeShellExecution" | "beforeMCPExecution" => "PreToolUse".to_string(),
        "afterShellExecution" | "afterMCPExecution" => "PostToolUse".to_string(),
        // Lifecycle events: lower-camel -> Pascal.
        "sessionStart" => "SessionStart".to_string(),
        "sessionEnd" => "SessionEnd".to_string(),
        "userPromptSubmit" => "UserPromptSubmit".to_string(),
        "stop" => "Stop".to_string(),
        // Already-Pascal or unknown: leave as-is.
        other => other.to_string(),
    }
}

/// Fold an optional ctx + system message into a single string (Cursor has no
/// dedicated systemMessage slot in the decision shape).
fn fold_messages(ctx: Option<&str>, sys: Option<&str>) -> Option<String> {
    match (ctx, sys) {
        (Some(c), Some(s)) => Some(format!("{c}\n{s}")),
        (Some(c), None) => Some(c.to_string()),
        (None, Some(s)) => Some(s.to_string()),
        (None, None) => None,
    }
}

impl Host for CursorHost {
    fn host_id(&self) -> HostId {
        HostId::Cursor
    }

    fn parse_hook_input(&self, raw: &str) -> Result<HostNeutralInput> {
        let env: CursorEnvelope = serde_json::from_str(raw).context("parse Cursor hook input")?;

        // session_id: conversation_id first (F7), then a plain session_id, then
        // a deterministic placeholder so downstream code never sees an empty id.
        let session_id = env
            .conversation_id
            .or(env.session_id)
            .unwrap_or_else(|| "cursor-unknown-session".to_string());

        // cwd: explicit cwd wins, else first workspace root, else empty.
        let cwd = env
            .cwd
            .or_else(|| env.workspace_roots.into_iter().next())
            .unwrap_or_default();

        // event name: camelCase -> PascalCase for the shared handlers.
        let hook_event_name = env
            .hook_event_name
            .as_deref()
            .map(normalize_event_name)
            .unwrap_or_default();

        Ok(HostNeutralInput {
            session_id: SessionId::new(session_id),
            transcript_path: None,
            cwd,
            hook_event_name,
            // Cursor surfaces a tool_name only for MCP events; shell events
            // are represented purely by `direct_command`.
            tool_name: env.tool_name,
            tool_use_id: None,
            tool_input: env.tool_input,
            tool_response: None,
            source: None,
            trigger: None,
            prompt: None,
            // F7: the shell command lives at the top level, not under
            // tool_input.command. The pre_tool_use handler reads this.
            direct_command: env.command,
            host: HostId::Cursor,
            extras: std::collections::HashMap::new(),
        })
    }

    fn write_decision(
        &self,
        w: &mut dyn Write,
        _event: &str,
        d: &PolicyDecision,
        ctx: Option<&str>,
        sys: Option<&str>,
    ) -> Result<()> {
        // F7: Cursor supports interactive ask, so the three-valued verdict
        // maps directly via `to_cursor_format` (allow/deny/ask). The reason
        // becomes the GUI `userMessage`.
        let output = CursorDecisionOutput {
            permission: d.to_cursor_format().to_string(),
            user_message: d.reason().map(str::to_string),
            agent_message: fold_messages(ctx, sys),
        };
        let json = serde_json::to_string(&output).context("serialize Cursor decision")?;
        writeln!(w, "{json}").context("write Cursor decision")?;
        Ok(())
    }

    fn write_generic(
        &self,
        w: &mut dyn Write,
        _event: &str,
        ctx: Option<&str>,
        sys: Option<&str>,
    ) -> Result<()> {
        let output = CursorGenericOutput {
            agent_message: fold_messages(ctx, sys),
        };
        let json = serde_json::to_string(&output).context("serialize Cursor generic")?;
        writeln!(w, "{json}").context("write Cursor generic")?;
        Ok(())
    }

    fn ask_channel(&self) -> AskChannel {
        // F7: Cursor supports interactive ask via a flat permission field.
        AskChannel::FlatPermissionField
    }

    fn gating_scope(&self) -> GatingScope {
        // F7: GUI-only; the cursor-agent CLI exposes no command-gating hook.
        GatingScope::GuiOnly
    }

    fn transcript_backend(&self) -> TranscriptBackend {
        // Cursor stores conversation state in SQLite (state.vscdb).
        TranscriptBackend::Sqlite
    }

    fn global_instructions_path(&self, _home: &Path) -> Option<PathBuf> {
        // Cursor uses project-scoped `.cursor/rules` only; no global file.
        None
    }

    fn instructions_file_label(&self) -> &'static str {
        ".cursor/rules"
    }

    fn provenance_env_vars(&self) -> &'static [&'static str] {
        &[]
    }

    fn session_id_env_var(&self) -> Option<&'static str> {
        None
    }

    fn mcp_config_target(&self, home: &Path) -> PathBuf {
        // ~/.cursor/mcp.json
        home.join(".cursor").join("mcp.json")
    }

    fn is_mutator_tool(&self, tool: &str) -> bool {
        // Cursor file-edit tool (P0 F7 fallback name; confirmed in P7).
        matches!(tool, "edit_file")
    }

    fn canonical_tool_name(&self, tool: &str) -> String {
        // Cursor shell tool maps to the canonical Bash class; edit_file maps
        // to the canonical file-edit class. Full map is finalized in P7.
        match tool {
            "run_terminal_cmd" => "Bash".to_string(),
            "edit_file" => "FileEdit".to_string(),
            other => other.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn before_shell_envelope() -> String {
        serde_json::json!({
            "conversation_id": "conv-cursor-001",
            "hook_event_name": "beforeShellExecution",
            "command": "rm -rf /tmp/x",
            "workspace_roots": ["/Users/dev/project", "/Users/dev/other"]
        })
        .to_string()
    }

    fn render_decision(d: &PolicyDecision) -> serde_json::Value {
        let host = CursorHost;
        let mut buf = Vec::new();
        host.write_decision(&mut buf, "PreToolUse", d, None, None)
            .unwrap();
        serde_json::from_str(String::from_utf8(buf).unwrap().trim()).unwrap()
    }

    #[test]
    fn cursor_capabilities() {
        let host = CursorHost;
        assert_eq!(host.host_id(), HostId::Cursor);
        assert!(matches!(
            host.ask_channel(),
            AskChannel::FlatPermissionField
        ));
        assert!(matches!(host.gating_scope(), GatingScope::GuiOnly));
        assert!(matches!(
            host.transcript_backend(),
            TranscriptBackend::Sqlite
        ));
        assert_eq!(host.instructions_file_label(), ".cursor/rules");
        assert_eq!(host.session_id_env_var(), None);
        assert!(host.provenance_env_vars().is_empty());
        assert!(host.is_mutator_tool("edit_file"));
        assert!(!host.is_mutator_tool("Bash"));
        assert_eq!(host.canonical_tool_name("run_terminal_cmd"), "Bash");
        assert_eq!(host.canonical_tool_name("edit_file"), "FileEdit");
    }

    #[test]
    fn cursor_has_no_global_instructions_path() {
        let host = CursorHost;
        assert!(
            host.global_instructions_path(Path::new("/home/u"))
                .is_none()
        );
    }

    #[test]
    fn cursor_mcp_target() {
        let host = CursorHost;
        assert_eq!(
            host.mcp_config_target(Path::new("/home/u")),
            Path::new("/home/u/.cursor/mcp.json")
        );
    }

    // -- F7 envelope parse ------------------------------------------------

    #[test]
    fn parse_before_shell_maps_fields() {
        let input = CursorHost
            .parse_hook_input(&before_shell_envelope())
            .unwrap();
        assert_eq!(input.host, HostId::Cursor);
        // conversation_id -> session_id.
        assert_eq!(input.session_id.as_str(), "conv-cursor-001");
        // workspace_roots[0] -> cwd.
        assert_eq!(input.cwd, "/Users/dev/project");
        // camelCase -> PascalCase.
        assert_eq!(input.hook_event_name, "PreToolUse");
        // top-level command -> direct_command (not tool_input.command).
        assert_eq!(input.direct_command.as_deref(), Some("rm -rf /tmp/x"));
        assert!(input.tool_input.is_none());
    }

    #[test]
    fn parse_falls_back_to_session_id_and_explicit_cwd() {
        let env = serde_json::json!({
            "session_id": "plain-sess",
            "cwd": "/explicit/cwd",
            "hook_event_name": "beforeMCPExecution",
            "tool_name": "some_mcp_tool",
            "tool_input": { "arg": 1 }
        })
        .to_string();
        let input = CursorHost.parse_hook_input(&env).unwrap();
        assert_eq!(input.session_id.as_str(), "plain-sess");
        assert_eq!(input.cwd, "/explicit/cwd");
        assert_eq!(input.hook_event_name, "PreToolUse");
        assert_eq!(input.tool_name.as_deref(), Some("some_mcp_tool"));
    }

    #[test]
    fn parse_missing_session_uses_placeholder() {
        let env = serde_json::json!({
            "hook_event_name": "beforeShellExecution",
            "command": "ls"
        })
        .to_string();
        let input = CursorHost.parse_hook_input(&env).unwrap();
        assert_eq!(input.session_id.as_str(), "cursor-unknown-session");
        assert!(input.cwd.is_empty());
    }

    #[test]
    fn normalize_event_name_table() {
        assert_eq!(normalize_event_name("beforeShellExecution"), "PreToolUse");
        assert_eq!(normalize_event_name("beforeMCPExecution"), "PreToolUse");
        assert_eq!(normalize_event_name("afterShellExecution"), "PostToolUse");
        assert_eq!(normalize_event_name("sessionStart"), "SessionStart");
        assert_eq!(normalize_event_name("userPromptSubmit"), "UserPromptSubmit");
        assert_eq!(normalize_event_name("stop"), "Stop");
        // Unknown / already-Pascal pass through.
        assert_eq!(normalize_event_name("SomethingNew"), "SomethingNew");
    }

    #[test]
    fn parse_rejects_invalid_json() {
        assert!(CursorHost.parse_hook_input("not json").is_err());
    }

    // -- F7 flat-permission response (Cursor supports ask) ----------------

    #[test]
    fn allow_emits_flat_permission_no_reason() {
        let v = render_decision(&PolicyDecision::Allow);
        assert_eq!(v["permission"], "allow");
        assert!(v.get("userMessage").is_none());
        // No hookSpecificOutput envelope for Cursor.
        assert!(v.get("hookSpecificOutput").is_none());
    }

    #[test]
    fn deny_emits_flat_permission_with_reason() {
        let v = render_decision(&PolicyDecision::Deny {
            reason: "blocked".to_string(),
        });
        assert_eq!(v["permission"], "deny");
        assert_eq!(v["userMessage"], "blocked");
    }

    #[test]
    fn ask_is_preserved_for_cursor() {
        // F7: unlike Codex, Cursor keeps the interactive ask.
        let v = render_decision(&PolicyDecision::Ask {
            reason: "needs review".to_string(),
        });
        assert_eq!(v["permission"], "ask");
        assert_eq!(v["userMessage"], "needs review");
    }

    #[test]
    fn decision_folds_messages_into_agent_message() {
        let host = CursorHost;
        let mut buf = Vec::new();
        host.write_decision(
            &mut buf,
            "PreToolUse",
            &PolicyDecision::Allow,
            Some("CTX"),
            Some("SYS"),
        )
        .unwrap();
        let v: serde_json::Value =
            serde_json::from_str(String::from_utf8(buf).unwrap().trim()).unwrap();
        assert_eq!(v["agentMessage"], "CTX\nSYS");
    }

    #[test]
    fn generic_output_shape() {
        let host = CursorHost;
        let mut buf = Vec::new();
        host.write_generic(&mut buf, "SessionStart", Some("ctx"), None)
            .unwrap();
        let v: serde_json::Value =
            serde_json::from_str(String::from_utf8(buf).unwrap().trim()).unwrap();
        assert_eq!(v["agentMessage"], "ctx");
        assert!(v.get("permission").is_none());
    }
}
