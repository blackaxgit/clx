//! `CodexHost`: the Codex CLI host.
//!
//! Capability methods are real (resolved from P0 evidence F1/F2/F4/F5/F6).
//! P2 fills the envelope parser, the response writer, and the rollout-JSONL
//! transcript parser (`codex/transcript.rs`).
//!
//! P0 findings encoded here:
//! - F1: Codex 0.135.0 hooks support only allow/deny - no interactive `ask`.
//!   CLX maps `ask` to a fail-closed `deny` ([`AskChannel::FailClosedDeny`]).
//! - F2: command gating fires in interactive `codex`, not `codex exec`. The
//!   gating *scope* is still CLI (the hook surface exists on the CLI); the
//!   exec-mode caveat is documented in P9, not modelled as `GuiOnly`.
//! - F4: `PreToolUse` envelope is Claude-shaped plus the Codex-specific extras
//!   `model`, `turn_id`, `permission_mode`. These are absorbed into
//!   [`HostNeutralInput::extras`] so no host-neutral field is lost.
//! - F5: the response is `hookSpecificOutput` with
//!   `permissionDecision: allow|deny` (+ optional `permissionDecisionReason`,
//!   + optional `updatedInput`). Allow-without-rewrite carries no reason.
//! - F6: session id comes from the envelope `session_id` field, not an env
//!   var, so `session_id_env_var()` is `None`.

use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clx_core::policy::PolicyDecision;
use serde::Serialize;

use super::{AskChannel, GatingScope, Host, HostId, TranscriptBackend};
use crate::types::HostNeutralInput;

pub(crate) mod transcript;

/// Envelope keys that have a host-neutral home in [`HostNeutralInput`] and so
/// must NOT be duplicated into `extras`. Everything else in the Codex envelope
/// object is lifted into `extras` verbatim (F4: `model`, `turn_id`,
/// `permission_mode`, plus any forward-compat field Codex adds later).
const NEUTRAL_KEYS: &[&str] = &[
    "session_id",
    "transcript_path",
    "cwd",
    "hook_event_name",
    "tool_name",
    "tool_use_id",
    "tool_input",
    "tool_response",
    "source",
    "trigger",
    "prompt",
];

/// Reason attached to a Codex `deny` that originated from an `ask` verdict.
///
/// Codex 0.135.0 has no interactive `ask` (F1); CLX fails closed and tells the
/// user how to proceed. Kept as a constant so the response writer and any
/// future `PermissionRequest` path stay in lockstep.
pub(crate) const CODEX_ASK_FAILCLOSED_REASON: &str =
    "CLX requires manual approval; Codex does not support interactive ask - re-run if intended.";

/// The Codex CLI host.
pub(crate) struct CodexHost;

/// Codex `PreToolUse` response (F5): `hookSpecificOutput` with allow/deny.
///
/// `updatedInput` is reserved for the command-rewrite path (not used by the
/// current allow/deny mapping); it is omitted when `None` so an unchanged
/// allow is the documented "exit 0, decision only" shape.
#[derive(Debug, Serialize)]
struct CodexHookOutput {
    #[serde(rename = "hookSpecificOutput")]
    hook_specific_output: CodexHookSpecificOutput,
}

#[derive(Debug, Serialize)]
struct CodexHookSpecificOutput {
    #[serde(rename = "hookEventName")]
    hook_event_name: String,

    #[serde(rename = "permissionDecision")]
    permission_decision: String,

    #[serde(
        rename = "permissionDecisionReason",
        skip_serializing_if = "Option::is_none"
    )]
    permission_decision_reason: Option<String>,

    #[serde(rename = "additionalContext", skip_serializing_if = "Option::is_none")]
    additional_context: Option<String>,
}

/// Generic Codex response (no permission decision) for lifecycle events.
#[derive(Debug, Serialize)]
struct CodexGenericOutput {
    #[serde(rename = "hookSpecificOutput")]
    hook_specific_output: CodexGenericSpecificOutput,
}

#[derive(Debug, Serialize)]
struct CodexGenericSpecificOutput {
    #[serde(rename = "hookEventName")]
    hook_event_name: String,

    #[serde(rename = "additionalContext", skip_serializing_if = "Option::is_none")]
    additional_context: Option<String>,
}

impl Host for CodexHost {
    fn host_id(&self) -> HostId {
        HostId::Codex
    }

    fn parse_hook_input(&self, raw: &str) -> Result<HostNeutralInput> {
        // F4: the Codex envelope is the Claude-shaped envelope plus extras.
        // Deserialize the shared fields with the existing serde derive (the
        // unknown Codex keys are ignored by serde), then re-walk the raw JSON
        // object to lift every non-neutral key into `extras` so nothing is
        // silently dropped.
        let mut input: HostNeutralInput =
            serde_json::from_str(raw).context("parse Codex hook input")?;
        input.host = HostId::Codex;

        // F6: session id arrives in the envelope, not an env var. The serde
        // pass above already populated `session_id`; no env fallback here.

        if let Ok(serde_json::Value::Object(map)) = serde_json::from_str::<serde_json::Value>(raw) {
            for (key, value) in map {
                if !NEUTRAL_KEYS.contains(&key.as_str()) {
                    input.extras.insert(key, value);
                }
            }
        }
        Ok(input)
    }

    fn write_decision(
        &self,
        w: &mut dyn Write,
        event: &str,
        d: &PolicyDecision,
        ctx: Option<&str>,
        sys: Option<&str>,
    ) -> Result<()> {
        // F5: emit `hookSpecificOutput` with `permissionDecision`. F1: there
        // is no interactive `ask`, so `to_codex_format` collapses ask -> deny
        // (fail closed). The reason for an ask-origin deny is the documented
        // fail-closed message; deny carries its own reason; allow carries no
        // reason (the "exit 0, decision only" shape).
        let decision = d.to_codex_format();
        let reason = match d {
            PolicyDecision::Allow => None,
            PolicyDecision::Deny { reason } => Some(reason.clone()),
            // ask -> deny: replace the host-neutral ask reason with the
            // Codex-specific fail-closed guidance.
            PolicyDecision::Ask { .. } => Some(CODEX_ASK_FAILCLOSED_REASON.to_string()),
        };
        // Codex has no top-level `systemMessage` slot (F5); fold any caller
        // system message into additionalContext so it is not dropped.
        let additional_context = match (ctx, sys) {
            (Some(c), Some(s)) => Some(format!("{c}\n{s}")),
            (Some(c), None) => Some(c.to_string()),
            (None, Some(s)) => Some(s.to_string()),
            (None, None) => None,
        };
        let output = CodexHookOutput {
            hook_specific_output: CodexHookSpecificOutput {
                hook_event_name: event.to_string(),
                permission_decision: decision.to_string(),
                permission_decision_reason: reason,
                additional_context,
            },
        };
        let json = serde_json::to_string(&output).context("serialize Codex decision")?;
        writeln!(w, "{json}").context("write Codex decision")?;
        Ok(())
    }

    fn write_generic(
        &self,
        w: &mut dyn Write,
        event: &str,
        ctx: Option<&str>,
        sys: Option<&str>,
    ) -> Result<()> {
        // F5: no permission decision, no top-level systemMessage. Fold the
        // system message into additionalContext (same rationale as above).
        let additional_context = match (ctx, sys) {
            (Some(c), Some(s)) => Some(format!("{c}\n{s}")),
            (Some(c), None) => Some(c.to_string()),
            (None, Some(s)) => Some(s.to_string()),
            (None, None) => None,
        };
        let output = CodexGenericOutput {
            hook_specific_output: CodexGenericSpecificOutput {
                hook_event_name: event.to_string(),
                additional_context,
            },
        };
        let json = serde_json::to_string(&output).context("serialize Codex generic")?;
        writeln!(w, "{json}").context("write Codex generic")?;
        Ok(())
    }

    fn ask_channel(&self) -> AskChannel {
        // F1: no interactive ask; map ask -> deny (fail closed).
        AskChannel::FailClosedDeny
    }

    fn gating_scope(&self) -> GatingScope {
        GatingScope::Cli
    }

    fn transcript_backend(&self) -> TranscriptBackend {
        // Codex rollout-*.jsonl files.
        TranscriptBackend::Jsonl
    }

    fn global_instructions_path(&self, home: &Path) -> Option<PathBuf> {
        // ~/.codex/AGENTS.md
        Some(home.join(".codex").join("AGENTS.md"))
    }

    fn instructions_file_label(&self) -> &'static str {
        "AGENTS.md"
    }

    fn provenance_env_vars(&self) -> &'static [&'static str] {
        // F6 fallback: no confirmed Codex provenance env vars; empty slice
        // (provenance is best-effort defense-in-depth, fail-safe).
        &[]
    }

    fn session_id_env_var(&self) -> Option<&'static str> {
        // F6: session id comes from the envelope, not an env var.
        None
    }

    fn mcp_config_target(&self, home: &Path) -> PathBuf {
        // ~/.codex/config.toml [mcp_servers.clx]
        home.join(".codex").join("config.toml")
    }

    fn is_mutator_tool(&self, tool: &str) -> bool {
        // Codex uses `apply_patch` for diff-style edits (gap-scan gap #2).
        matches!(tool, "apply_patch")
    }

    fn canonical_tool_name(&self, tool: &str) -> String {
        // Codex `apply_patch` maps to the canonical file-edit class; Bash
        // commands keep their name. Full canonical-name migration is P7.
        match tool {
            "apply_patch" => "FileEdit".to_string(),
            other => other.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn codex_envelope() -> String {
        serde_json::json!({
            "session_id": "sess-codex-001",
            "transcript_path": "/tmp/codex/rollout.jsonl",
            "cwd": "/tmp/project",
            "hook_event_name": "PreToolUse",
            "model": "gpt-5.4-codex",
            "turn_id": "turn-7",
            "tool_name": "Bash",
            "tool_use_id": "call-42",
            "tool_input": { "command": "ls -la" },
            "permission_mode": "default"
        })
        .to_string()
    }

    fn render_decision(d: &PolicyDecision) -> serde_json::Value {
        let host = CodexHost;
        let mut buf = Vec::new();
        host.write_decision(&mut buf, "PreToolUse", d, None, None)
            .unwrap();
        let s = String::from_utf8(buf).unwrap();
        serde_json::from_str(s.trim()).unwrap()
    }

    #[test]
    fn codex_capabilities() {
        let host = CodexHost;
        assert_eq!(host.host_id(), HostId::Codex);
        assert!(matches!(host.ask_channel(), AskChannel::FailClosedDeny));
        assert!(matches!(host.gating_scope(), GatingScope::Cli));
        assert!(matches!(
            host.transcript_backend(),
            TranscriptBackend::Jsonl
        ));
        assert_eq!(host.instructions_file_label(), "AGENTS.md");
        assert_eq!(host.session_id_env_var(), None);
        assert!(host.provenance_env_vars().is_empty());
        assert!(host.is_mutator_tool("apply_patch"));
        assert!(!host.is_mutator_tool("Bash"));
        assert_eq!(host.canonical_tool_name("apply_patch"), "FileEdit");
    }

    #[test]
    fn codex_paths() {
        let host = CodexHost;
        let home = Path::new("/home/u");
        assert_eq!(
            host.global_instructions_path(home).unwrap(),
            Path::new("/home/u/.codex/AGENTS.md")
        );
        assert_eq!(
            host.mcp_config_target(home),
            Path::new("/home/u/.codex/config.toml")
        );
    }

    // -- F4 envelope round-trip ------------------------------------------

    #[test]
    fn parse_lifts_shared_fields_and_sets_host() {
        let input = CodexHost.parse_hook_input(&codex_envelope()).unwrap();
        assert_eq!(input.host, HostId::Codex);
        assert_eq!(input.session_id.as_str(), "sess-codex-001");
        assert_eq!(input.cwd, "/tmp/project");
        assert_eq!(input.hook_event_name, "PreToolUse");
        assert_eq!(input.tool_name.as_deref(), Some("Bash"));
        assert_eq!(input.tool_use_id.as_deref(), Some("call-42"));
        assert_eq!(
            input.transcript_path.as_deref(),
            Some("/tmp/codex/rollout.jsonl")
        );
        assert_eq!(
            input.tool_input.as_ref().unwrap()["command"],
            serde_json::json!("ls -la")
        );
    }

    #[test]
    fn parse_lifts_codex_extras_into_extras_map() {
        let input = CodexHost.parse_hook_input(&codex_envelope()).unwrap();
        // F4 Codex-specific extras land in `extras`, not lost.
        assert_eq!(input.extras["model"], serde_json::json!("gpt-5.4-codex"));
        assert_eq!(input.extras["turn_id"], serde_json::json!("turn-7"));
        assert_eq!(
            input.extras["permission_mode"],
            serde_json::json!("default")
        );
        // Neutral keys are NOT duplicated into extras.
        assert!(!input.extras.contains_key("session_id"));
        assert!(!input.extras.contains_key("tool_input"));
        assert!(!input.extras.contains_key("cwd"));
    }

    #[test]
    fn parse_forward_compat_unknown_key_goes_to_extras() {
        let env = serde_json::json!({
            "session_id": "s",
            "cwd": "/tmp",
            "hook_event_name": "PreToolUse",
            "turn_id": "t",
            "permission_mode": "default",
            "future_codex_field": { "nested": true }
        })
        .to_string();
        let input = CodexHost.parse_hook_input(&env).unwrap();
        assert_eq!(
            input.extras["future_codex_field"],
            serde_json::json!({ "nested": true })
        );
    }

    #[test]
    fn parse_rejects_invalid_json() {
        assert!(CodexHost.parse_hook_input("not json").is_err());
    }

    // -- F5 response shape + F1 ask->deny --------------------------------

    #[test]
    fn allow_decision_carries_no_reason() {
        let v = render_decision(&PolicyDecision::Allow);
        assert_eq!(v["hookSpecificOutput"]["hookEventName"], "PreToolUse");
        assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "allow");
        assert!(
            v["hookSpecificOutput"]
                .get("permissionDecisionReason")
                .is_none()
        );
    }

    #[test]
    fn deny_decision_carries_reason() {
        let v = render_decision(&PolicyDecision::Deny {
            reason: "blocked by L0".to_string(),
        });
        assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "deny");
        assert_eq!(
            v["hookSpecificOutput"]["permissionDecisionReason"],
            "blocked by L0"
        );
    }

    #[test]
    fn ask_decision_maps_to_failclosed_deny() {
        let v = render_decision(&PolicyDecision::Ask {
            reason: "would-be ask".to_string(),
        });
        // F1: Codex has no interactive ask; CLX fails closed to deny.
        assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "deny");
        assert_eq!(
            v["hookSpecificOutput"]["permissionDecisionReason"],
            CODEX_ASK_FAILCLOSED_REASON
        );
        // The original ask reason must NOT leak; only the fail-closed text.
        assert!(
            !v["hookSpecificOutput"]["permissionDecisionReason"]
                .as_str()
                .unwrap()
                .contains("would-be ask")
        );
    }

    #[test]
    fn decision_folds_system_message_into_additional_context() {
        let host = CodexHost;
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
        assert_eq!(v["hookSpecificOutput"]["additionalContext"], "CTX\nSYS");
        // Codex has no top-level systemMessage field.
        assert!(v.get("systemMessage").is_none());
    }

    #[test]
    fn generic_output_shape() {
        let host = CodexHost;
        let mut buf = Vec::new();
        host.write_generic(&mut buf, "SessionStart", Some("ctx"), None)
            .unwrap();
        let v: serde_json::Value =
            serde_json::from_str(String::from_utf8(buf).unwrap().trim()).unwrap();
        assert_eq!(v["hookSpecificOutput"]["hookEventName"], "SessionStart");
        assert_eq!(v["hookSpecificOutput"]["additionalContext"], "ctx");
        assert!(v["hookSpecificOutput"].get("permissionDecision").is_none());
    }
}
