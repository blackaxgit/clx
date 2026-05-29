//! `CursorHost`: the Cursor IDE host (P1 stub).
//!
//! Capability methods are real (resolved from P0 evidence F7 + research).
//! Parse/write methods are stubbed with `unimplemented!()`; P2 fills the
//! `state.vscdb` transcript parser and P4 wires the response writer.
//!
//! P0 findings encoded here:
//! - F7: Cursor hooks are GUI-only (no `cursor-agent` CLI surface), so
//!   gating scope is [`GatingScope::GuiOnly`].
//! - F7: Cursor DOES support interactive `ask` via a flat `permission`
//!   field ([`AskChannel::FlatPermissionField`]).
//! - Transcript lives in `SQLite` (`state.vscdb`), not JSONL.
//! - Cursor uses project-scoped `.cursor/rules` only - no global
//!   instructions file, so `global_instructions_path` returns `None`.

use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::Result;
use clx_core::policy::PolicyDecision;

use super::{AskChannel, GatingScope, Host, HostId, TranscriptBackend};
use crate::types::HostNeutralInput;

/// The Cursor IDE host.
pub(crate) struct CursorHost;

impl Host for CursorHost {
    fn host_id(&self) -> HostId {
        HostId::Cursor
    }

    fn parse_hook_input(&self, _raw: &str) -> Result<HostNeutralInput> {
        // P2: parse the Cursor `beforeShellExecution` / `beforeMCPExecution`
        // envelope into HostNeutralInput.
        unimplemented!("CursorHost::parse_hook_input is implemented in P2")
    }

    fn write_decision(
        &self,
        _w: &mut dyn Write,
        _event: &str,
        _d: &PolicyDecision,
        _ctx: Option<&str>,
        _sys: Option<&str>,
    ) -> Result<()> {
        // P4: emit the Cursor flat `permission: allow|deny|ask` response.
        unimplemented!("CursorHost::write_decision is implemented in P4")
    }

    fn write_generic(
        &self,
        _w: &mut dyn Write,
        _event: &str,
        _ctx: Option<&str>,
        _sys: Option<&str>,
    ) -> Result<()> {
        unimplemented!("CursorHost::write_generic is implemented in P4")
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

    #[test]
    #[should_panic(expected = "P2")]
    fn parse_is_unimplemented_until_p2() {
        let _ = CursorHost.parse_hook_input("{}");
    }
}
