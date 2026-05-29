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
