//! `ClaudeHost`: the Anthropic Claude Code host.
//!
//! This is a verbatim lift of CLX's pre-v0.10.0 behaviour. Every method
//! reproduces exactly what the hook binary did before the host abstraction
//! existed, so the existing test suite (which drives Claude-shaped JSON)
//! stays byte-for-byte green.

use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clx_core::policy::PolicyDecision;

use super::{AskChannel, GatingScope, Host, HostId, TranscriptBackend};
use crate::types::{
    HookGenericOutput, HookGenericSpecificOutput, HookOutput, HookSpecificOutput, HostNeutralInput,
};

/// Env var Claude Code sets carrying the current session id. Lifted from the
/// pre-refactor `trust.rs` lookup (gap-scan gap #1).
pub(crate) const CLAUDE_SESSION_ID_ENV_VAR: &str = "CLAUDE_CODE_SESSION_ID";

/// The Anthropic Claude Code host (default, historical behaviour).
pub(crate) struct ClaudeHost;

impl Host for ClaudeHost {
    fn host_id(&self) -> HostId {
        HostId::Claude
    }

    fn parse_hook_input(&self, raw: &str) -> Result<HostNeutralInput> {
        // Verbatim lift of `router::parse_input`: the Claude envelope IS the
        // host-neutral shape (the new fields default), so a direct serde
        // parse is lossless.
        serde_json::from_str::<HostNeutralInput>(raw).context("parse Claude hook input")
    }

    fn write_decision(
        &self,
        w: &mut dyn Write,
        event: &str,
        d: &PolicyDecision,
        ctx: Option<&str>,
        sys: Option<&str>,
    ) -> Result<()> {
        // Byte-identical to the pre-refactor `output::output_decision`: the
        // `HookOutput`/`HookSpecificOutput` serialization is the same code
        // path, only the sink changes from `println!` to `w`.
        let output = HookOutput {
            hook_specific_output: HookSpecificOutput {
                hook_event_name: event.to_string(),
                permission_decision: d.to_permission_decision().to_string(),
                permission_decision_reason: d.reason().map(str::to_string),
                additional_context: ctx.map(str::to_string),
            },
            system_message: sys.map(str::to_string),
        };
        let json = serde_json::to_string(&output).context("serialize Claude decision")?;
        writeln!(w, "{json}").context("write Claude decision")?;
        Ok(())
    }

    fn write_generic(
        &self,
        w: &mut dyn Write,
        event: &str,
        ctx: Option<&str>,
        sys: Option<&str>,
    ) -> Result<()> {
        // Byte-identical to the pre-refactor `output::output_generic`.
        let output = HookGenericOutput {
            hook_specific_output: HookGenericSpecificOutput {
                hook_event_name: event.to_string(),
                additional_context: ctx.map(str::to_string),
            },
            system_message: sys.map(str::to_string),
        };
        let json = serde_json::to_string(&output).context("serialize Claude generic")?;
        writeln!(w, "{json}").context("write Claude generic")?;
        Ok(())
    }

    fn ask_channel(&self) -> AskChannel {
        AskChannel::InlinePermissionDecision
    }

    fn gating_scope(&self) -> GatingScope {
        GatingScope::Cli
    }

    fn transcript_backend(&self) -> TranscriptBackend {
        TranscriptBackend::Jsonl
    }

    fn global_instructions_path(&self, home: &Path) -> Option<PathBuf> {
        // ~/.claude/CLAUDE.md (context.rs:46 pre-refactor).
        Some(home.join(".claude").join("CLAUDE.md"))
    }

    fn instructions_file_label(&self) -> &'static str {
        "CLAUDE.md"
    }

    fn provenance_env_vars(&self) -> &'static [&'static str] {
        // Lifted from router::CLAUDE_PROVENANCE_ENV_VARS.
        crate::router::CLAUDE_PROVENANCE_ENV_VARS
    }

    fn session_id_env_var(&self) -> Option<&'static str> {
        Some(CLAUDE_SESSION_ID_ENV_VAR)
    }

    fn mcp_config_target(&self, home: &Path) -> PathBuf {
        // ~/.claude/settings.json
        home.join(".claude").join("settings.json")
    }

    fn is_mutator_tool(&self, tool: &str) -> bool {
        // Verbatim Claude mutator set (aggregator::CLAUDE_MUTATOR_TOOLS).
        matches!(tool, "Edit" | "Write" | "MultiEdit" | "NotebookEdit")
    }

    fn canonical_tool_name(&self, tool: &str) -> String {
        // P7: collapse the four Claude file-mutators into the shared canonical
        // class `FileEdit` so learned rules and L0 matching do not bifurcate
        // across hosts. Bash keeps its name (the canonical Bash class).
        // Everything else passes through unchanged.
        match tool {
            "Edit" | "Write" | "MultiEdit" | "NotebookEdit" => "FileEdit".to_string(),
            "Bash" => "Bash".to_string(),
            other => other.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn render_decision(d: &PolicyDecision) -> String {
        let host = ClaudeHost;
        let mut buf = Vec::new();
        host.write_decision(&mut buf, "PreToolUse", d, Some("CTX"), None)
            .unwrap();
        String::from_utf8(buf).unwrap()
    }

    #[test]
    fn allow_output_is_byte_identical_to_legacy() {
        let out = render_decision(&PolicyDecision::Allow);
        let v: serde_json::Value = serde_json::from_str(out.trim()).unwrap();
        assert_eq!(v["hookSpecificOutput"]["hookEventName"], "PreToolUse");
        assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "allow");
        // Allow carries no reason.
        assert!(
            v["hookSpecificOutput"]
                .get("permissionDecisionReason")
                .is_none()
        );
        assert_eq!(v["hookSpecificOutput"]["additionalContext"], "CTX");
        assert!(out.ends_with('\n'));
    }

    #[test]
    fn ask_output_carries_reason() {
        let out = render_decision(&PolicyDecision::Ask {
            reason: "needs review".to_string(),
        });
        let v: serde_json::Value = serde_json::from_str(out.trim()).unwrap();
        assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "ask");
        assert_eq!(
            v["hookSpecificOutput"]["permissionDecisionReason"],
            "needs review"
        );
    }

    #[test]
    fn deny_output_carries_reason() {
        let out = render_decision(&PolicyDecision::Deny {
            reason: "blocked".to_string(),
        });
        let v: serde_json::Value = serde_json::from_str(out.trim()).unwrap();
        assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "deny");
        assert_eq!(
            v["hookSpecificOutput"]["permissionDecisionReason"],
            "blocked"
        );
    }

    #[test]
    fn generic_output_shape() {
        let host = ClaudeHost;
        let mut buf = Vec::new();
        host.write_generic(&mut buf, "SessionStart", None, Some("sys"))
            .unwrap();
        let s = String::from_utf8(buf).unwrap();
        let v: serde_json::Value = serde_json::from_str(s.trim()).unwrap();
        assert_eq!(v["hookSpecificOutput"]["hookEventName"], "SessionStart");
        assert_eq!(v["systemMessage"], "sys");
        assert!(v["hookSpecificOutput"].get("permissionDecision").is_none());
    }

    #[test]
    fn capabilities_match_claude_defaults() {
        let host = ClaudeHost;
        assert_eq!(host.host_id(), HostId::Claude);
        assert!(matches!(
            host.ask_channel(),
            AskChannel::InlinePermissionDecision
        ));
        assert!(matches!(host.gating_scope(), GatingScope::Cli));
        assert!(matches!(
            host.transcript_backend(),
            TranscriptBackend::Jsonl
        ));
        assert_eq!(host.instructions_file_label(), "CLAUDE.md");
        assert_eq!(host.session_id_env_var(), Some("CLAUDE_CODE_SESSION_ID"));
        assert!(host.is_mutator_tool("Edit"));
        assert!(host.is_mutator_tool("NotebookEdit"));
        assert!(!host.is_mutator_tool("Bash"));
        // P7: the four file-mutators collapse to the canonical `FileEdit`.
        assert_eq!(host.canonical_tool_name("Edit"), "FileEdit");
        assert_eq!(host.canonical_tool_name("Write"), "FileEdit");
        assert_eq!(host.canonical_tool_name("MultiEdit"), "FileEdit");
        assert_eq!(host.canonical_tool_name("NotebookEdit"), "FileEdit");
        assert_eq!(host.canonical_tool_name("Bash"), "Bash");
        // Unknown / read-only tools pass through unchanged.
        assert_eq!(host.canonical_tool_name("Read"), "Read");
    }

    #[test]
    fn paths_use_home() {
        let host = ClaudeHost;
        let home = Path::new("/home/u");
        assert_eq!(
            host.global_instructions_path(home).unwrap(),
            Path::new("/home/u/.claude/CLAUDE.md")
        );
        assert_eq!(
            host.mcp_config_target(home),
            Path::new("/home/u/.claude/settings.json")
        );
    }
}
