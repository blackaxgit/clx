//! Holistic RED-R1 PoC tests: audit chain + audit-write redaction surfaces.
//!
//! All tests are `#[ignore]`-gated so the default suite stays green. Run with:
//!   cargo nextest run -p clx-hook --test holistic_red_r1_poc -- --ignored
//!
//! Synthetic placeholders ONLY. Hermetic: in-memory sqlite + pure functions.

#![allow(
    clippy::pedantic,
    clippy::restriction,
    clippy::nursery,
    clippy::doc_markdown
)]

use clx_core::redaction::redact_secrets;
use clx_core::storage::Storage;
use clx_core::types::{AuditDecision, AuditLogEntry, SessionId};

// =============================================================================
// SURFACE 3 - Audit write path: PostToolUse working_dir is NOT redacted
// =============================================================================

/// R1-RED-J (CONFIRMED, release-class redaction gap): the PostToolUse hook
/// (`post_tool_use.rs:134`) builds the audit row INLINE and sets
/// `entry.working_dir = Some(input.cwd.clone())` -- VERBATIM, no redaction.
///
/// The PreToolUse path routes through `audit::log_audit_entry`, which applies
/// `entry.working_dir = Some(redact_secrets(working_dir))` (audit.rs:60). The
/// PostToolUse path bypasses that helper, so an attacker-influenced cwd that
/// embeds an inline secret is persisted to `audit_log.working_dir` in the
/// clear -- the exact B6-3 class the team documented as closed.
///
/// This test reproduces the PostToolUse mapping against an in-memory DB and
/// reads the row back, proving the raw secret is stored.
#[test]
#[ignore = "RED PoC: PostToolUse persists raw (unredacted) working_dir"]
fn red_j_post_tool_use_working_dir_is_not_redacted() {
    let storage = Storage::open_in_memory().expect("in-memory sqlite");
    let session = SessionId::new("red-r1-j-session");

    // Attacker-influenced cwd embedding an sk- token (synthetic).
    let dirty_cwd = "/home/u/proj/sk-abc123LONGTOKENLEAKMARKER456/work";

    // Mirror post_tool_use.rs:127-137 EXACTLY (the inline mapping, no helper):
    let mut entry = AuditLogEntry::new(
        session.clone(),
        redact_secrets("ls"),
        "PostToolUse".to_string(),
        AuditDecision::Allowed,
    );
    entry.working_dir = Some(dirty_cwd.to_string()); // <-- post_tool_use.rs:134 verbatim

    storage
        .create_audit_log_with_host(&entry, "claude")
        .expect("audit write");

    let rows = storage
        .get_audit_log_by_session(session.as_str())
        .expect("read back");
    let stored = rows[0].working_dir.clone().unwrap_or_default();

    // GAP: the raw sk- token is persisted in the clear.
    assert!(
        stored.contains("sk-abc123LONGTOKENLEAKMARKER456"),
        "RED-J: PostToolUse working_dir must leak the raw secret (proving the gap); got: {stored}"
    );

    // Contrast: the PreToolUse path WOULD have redacted it.
    let what_pre_tool_use_would_store = redact_secrets(dirty_cwd);
    assert!(
        !what_pre_tool_use_would_store.contains("sk-abc123LONGTOKENLEAKMARKER456"),
        "control: log_audit_entry (PreToolUse) redacts the same cwd"
    );
}

// =============================================================================
// SURFACE 3 - Audit chain honesty
// =============================================================================
//
// R1-RED-K (REFUTED): the audit-chain module (`audit_chain.rs`, crate-private)
// honestly documents a PER-EVENT fingerprint, NOT a cross-process hash chain.
// The proof lives in the in-crate unit test
// `audit_chain::tests::separate_process_invocations_are_not_linked`, which
// shows two separate-invocation records both start at GENESIS/seq=1 and CANNOT
// be presented as a linked sequence. `build_record` is `pub(crate)` so it is
// unreachable from this integration-test crate; re-asserting it here would only
// duplicate the in-crate proof. No external PoC is added for R1-K by design.
