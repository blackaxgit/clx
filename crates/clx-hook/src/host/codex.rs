//! `CodexHost`: the Codex CLI host (P1 stub).
//!
//! Capability methods are real (resolved from P0 evidence F1/F2/F4/F5/F6).
//! Parse/write methods are stubbed with `unimplemented!()`; P2 fills the
//! envelope parser and P4 wires the response writer + ask-channel.
//!
//! P0 findings encoded here:
//! - F1: Codex 0.135.0 hooks support only allow/deny - no interactive `ask`.
//!   CLX maps `ask` to a fail-closed `deny` ([`AskChannel::FailClosedDeny`]).
//! - F2: command gating fires in interactive `codex`, not `codex exec`. The
//!   gating *scope* is still CLI (the hook surface exists on the CLI); the
//!   exec-mode caveat is documented in P9, not modelled as `GuiOnly`.
//! - F4/F5: envelope + response are Claude-shaped plus extras.
//! - F6: session id comes from the envelope `session_id` field, not an env
//!   var, so `session_id_env_var()` is `None`.

use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::Result;
use clx_core::policy::PolicyDecision;

use super::{AskChannel, GatingScope, Host, HostId, TranscriptBackend};
use crate::types::HostNeutralInput;

/// The Codex CLI host.
pub(crate) struct CodexHost;

impl Host for CodexHost {
    fn host_id(&self) -> HostId {
        HostId::Codex
    }

    fn parse_hook_input(&self, _raw: &str) -> Result<HostNeutralInput> {
        // P2: parse the Codex envelope (F4) into HostNeutralInput, lifting
        // Codex-specific extras (model, turn_id, permission_mode) into
        // `extras` and synthesizing the session id from the envelope (F6).
        unimplemented!("CodexHost::parse_hook_input is implemented in P2")
    }

    fn write_decision(
        &self,
        _w: &mut dyn Write,
        _event: &str,
        _d: &PolicyDecision,
        _ctx: Option<&str>,
        _sys: Option<&str>,
    ) -> Result<()> {
        // P4: emit the Codex response (F5) with allow/deny only, mapping
        // `ask` -> fail-closed deny per F1.
        unimplemented!("CodexHost::write_decision is implemented in P4")
    }

    fn write_generic(
        &self,
        _w: &mut dyn Write,
        _event: &str,
        _ctx: Option<&str>,
        _sys: Option<&str>,
    ) -> Result<()> {
        unimplemented!("CodexHost::write_generic is implemented in P4")
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

    #[test]
    #[should_panic(expected = "P2")]
    fn parse_is_unimplemented_until_p2() {
        let _ = CodexHost.parse_hook_input("{}");
    }
}
