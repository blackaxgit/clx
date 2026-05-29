//! CLX Hook library.
//!
//! This crate is consumed two ways:
//!
//! 1. As the binary `clx-hook` (see `src/main.rs`), which is invoked
//!    automatically by Claude Code via the hook protocol.
//! 2. As a library, so integration tests and the contract suite can drive
//!    `router::handle_event` end-to-end with in-memory readers and
//!    writers without spawning a subprocess.
//!
//! Layering follows the project rules (Orchestration -> Domain ->
//! Infrastructure -> Mapping). `router` is the Orchestration layer entry
//! point; everything else is internal.

pub(crate) mod audit;
pub(crate) mod audit_chain;
pub(crate) mod context;
pub(crate) mod embedding;
// The host abstraction lands in P1; several capability methods, enums, and
// the Codex/Cursor stubs are consumed by later phases (P2 parsers, P3 install
// path lookups, P4 ask-channel routing). Allow dead code crate-locally so the
// P1 scaffolding compiles under `-D warnings` before its consumers exist.
pub(crate) mod hooks;
#[allow(dead_code)]
pub(crate) mod host;
pub(crate) mod learning;
pub(crate) mod output;
pub mod router;
pub(crate) mod transcript;
pub(crate) mod types;

#[cfg(test)]
mod tests;

pub use router::{
    CLAUDE_PROVENANCE_ENV_VARS, HookDeps, HookExit, Provenance, classify_provenance, handle_event,
};

/// Test-only seam exposing the P7 canonical tool-name adapter to integration
/// tests (the `Host` trait itself stays crate-private).
///
/// These thin wrappers let `tests/tool_name_adapter.rs` assert the per-host
/// `canonical_tool_name` / `is_mutator_tool` behaviour without promoting the
/// whole `host` module to `pub`. They carry no behaviour of their own - they
/// delegate straight to the corresponding `Host` impl.
#[doc(hidden)]
pub mod testing {
    use crate::host::{ClaudeHost, CodexHost, CursorHost, Host, HostId};

    /// Build the `Host` impl for a `HostId` discriminant string
    /// (`"claude"` / `"codex"` / `"cursor"`), defaulting to Claude.
    fn host_for(label: &str) -> Box<dyn Host> {
        match label {
            "codex" => Box::new(CodexHost) as Box<dyn Host>,
            "cursor" => Box::new(CursorHost) as Box<dyn Host>,
            _ => Box::new(ClaudeHost) as Box<dyn Host>,
        }
    }

    /// Canonical tool name for `tool` under host `label`.
    #[must_use]
    pub fn canonical_tool_name(label: &str, tool: &str) -> String {
        host_for(label).canonical_tool_name(tool)
    }

    /// Whether `tool` is a file-mutator for host `label`.
    #[must_use]
    pub fn is_mutator_tool(label: &str, tool: &str) -> bool {
        host_for(label).is_mutator_tool(tool)
    }

    /// The set of host labels the adapter covers, for table-driven tests.
    #[must_use]
    pub fn host_labels() -> &'static [&'static str] {
        &["claude", "codex", "cursor"]
    }

    /// Assert the seam stays wired to the three known hosts (compile-time use
    /// of `HostId` so an enum change surfaces here too).
    #[must_use]
    pub fn host_id_count() -> usize {
        // Touch each discriminant so adding a HostId variant forces a review.
        [HostId::Claude, HostId::Codex, HostId::Cursor].len()
    }
}
