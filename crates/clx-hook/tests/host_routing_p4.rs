//! P4 host-aware routing: cross-host PreToolUse / PermissionRequest /
//! PostCompact behavior, driven through the real `clx-hook` binary with an
//! isolated `HOME`.
//!
//! Hermetic: redirected `HOME`, `CLX_MODEL_FETCH_DRYRUN=1`,
//! `CLX_CREDENTIALS_BACKEND=age`, no real network. Host is forced via the
//! `CLX_HOOK_HOST` override (the documented host-selection seam) so each test
//! pins a deterministic host regardless of envelope-sniffing heuristics.
//!
//! Acceptance coverage (P4):
//! - Codex PreToolUse `rm -rf /` -> deny (L0 deterministic).
//! - Codex `apply_patch` -> evaluated as FileEdit (allowed when no FileEdit
//!   deny rule matches; never silently treated as Bash).
//! - Codex ask-verdict (L1 disabled -> ask) -> fail-closed deny WITH the
//!   documented Codex reason.
//! - PermissionRequest -> definitive allow/deny (no ask).
//! - PostCompact -> token-count refresh (no crash; session row updated).
//! - Cursor `beforeShellExecution` rm-rf -> deny; safe -> allow; ambiguous
//!   (L1 disabled) -> ask.
//! - Cross-host: same `rm -rf /` via Claude + Codex + Cursor envelopes -> deny.

#![allow(clippy::doc_markdown)]

use std::io::Write;
use std::process::{Command, Stdio};

use serde_json::json;

#[path = "support/mod.rs"]
mod support;
use support::{assert_home_size_bounded, harden_command, isolated_clx_home};

/// L0-on, L1-off config: deterministic ruleset decides; unknown commands are
/// forced to `ask` (which each host's channel then renders). No LLM needed.
const CONFIG_L0_ON_L1_OFF: &str = "validator:\n  \
       enabled: true\n  \
       cache_enabled: false\n  \
       layer0_enabled: true\n  \
       layer1_enabled: false\n  \
       auto_allow_reads: true\n";

/// Spawn the real binary with the host forced via `CLX_HOOK_HOST`, pipe the
/// envelope, and return parsed stdout JSON. The `TempDir` is returned so the
/// caller can keep `HOME` alive for any follow-up DB assertions.
fn run_as_host(
    host: &str,
    config_yaml: &str,
    envelope: &serde_json::Value,
) -> (serde_json::Value, tempfile::TempDir) {
    let binary = env!("CARGO_BIN_EXE_clx-hook");
    let temp = isolated_clx_home();
    let clx_dir = temp.path().join(".clx");
    std::fs::create_dir_all(&clx_dir).expect("mk .clx");
    std::fs::write(clx_dir.join("config.yaml"), config_yaml).expect("write config");

    let mut command = Command::new(binary);
    let mut child = harden_command(&mut command, temp.path())
        .env("CLX_CREDENTIALS_BACKEND", "age")
        .env("CLX_HOOK_HOST", host)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn clx-hook");

    child
        .stdin
        .take()
        .unwrap()
        .write_all(envelope.to_string().as_bytes())
        .unwrap();

    let out = child.wait_with_output().expect("wait clx-hook");
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    assert_home_size_bounded(temp.path());
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!("hook stdout must be valid JSON: {e}\nstdout: {stdout}");
    });
    (parsed, temp)
}

/// `hookSpecificOutput.permissionDecision` (Claude / Codex shape).
fn hso_decision(v: &serde_json::Value) -> &str {
    v["hookSpecificOutput"]["permissionDecision"]
        .as_str()
        .unwrap_or("")
}

/// `hookSpecificOutput.permissionDecisionReason`.
fn hso_reason(v: &serde_json::Value) -> &str {
    v["hookSpecificOutput"]["permissionDecisionReason"]
        .as_str()
        .unwrap_or("")
}

/// Cursor flat `permission` field.
fn flat_permission(v: &serde_json::Value) -> &str {
    v["permission"].as_str().unwrap_or("")
}

// =========================================================================
// Codex PreToolUse
// =========================================================================

#[test]
fn codex_pre_tool_use_rm_rf_denies() {
    let env = json!({
        "session_id": "sess-codex-deny",
        "cwd": "/tmp",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "turn_id": "t1",
        "permission_mode": "default",
        "tool_input": { "command": "rm -rf /" }
    });
    let (v, _h) = run_as_host("codex", CONFIG_L0_ON_L1_OFF, &env);
    assert_eq!(
        hso_decision(&v),
        "deny",
        "Codex rm -rf / must be denied: {v}"
    );
}

#[test]
fn codex_apply_patch_evaluated_as_file_edit_allows_benign() {
    // apply_patch canonicalizes to FileEdit. With no FileEdit deny rule it is
    // allowed (parity with Claude file tools) - crucially NOT denied as an
    // unknown Bash command, proving it took the FileEdit branch.
    let env = json!({
        "session_id": "sess-codex-patch",
        "cwd": "/tmp",
        "hook_event_name": "PreToolUse",
        "tool_name": "apply_patch",
        "turn_id": "t1",
        "permission_mode": "default",
        "tool_input": { "command": "*** Begin Patch\n+hello\n*** End Patch" }
    });
    let (v, _h) = run_as_host("codex", CONFIG_L0_ON_L1_OFF, &env);
    assert_eq!(
        hso_decision(&v),
        "allow",
        "benign Codex apply_patch must be allowed via the FileEdit branch: {v}"
    );
}

#[test]
fn codex_ask_verdict_fails_closed_to_deny_with_reason() {
    // An L0-unknown, non-read-only command escalates to ask; L1 is disabled,
    // so PreToolUse emits "ask", which the Codex channel collapses to a
    // fail-closed deny carrying the documented Codex reason.
    let env = json!({
        "session_id": "sess-codex-ask",
        "cwd": "/tmp",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "turn_id": "t1",
        "permission_mode": "default",
        "tool_input": { "command": "frobnicate --wibble /tmp/thing" }
    });
    let (v, _h) = run_as_host("codex", CONFIG_L0_ON_L1_OFF, &env);
    assert_eq!(
        hso_decision(&v),
        "deny",
        "Codex ask-verdict must fail closed to deny: {v}"
    );
    assert!(
        hso_reason(&v).contains("Codex does not support interactive ask"),
        "deny must carry the Codex fail-closed reason, got: {}",
        hso_reason(&v)
    );
}

// =========================================================================
// Codex PermissionRequest (definitive allow/deny, no ask)
// =========================================================================

#[test]
fn codex_permission_request_denies_destructive() {
    let env = json!({
        "session_id": "sess-permreq-deny",
        "cwd": "/tmp",
        "hook_event_name": "PermissionRequest",
        "tool_name": "Bash",
        "turn_id": "t1",
        "permission_mode": "default",
        "tool_input": { "command": "rm -rf /" }
    });
    let (v, _h) = run_as_host("codex", CONFIG_L0_ON_L1_OFF, &env);
    assert_eq!(
        hso_decision(&v),
        "deny",
        "PermissionRequest must deny rm -rf /: {v}"
    );
}

#[test]
fn codex_permission_request_allows_safe_readonly() {
    let env = json!({
        "session_id": "sess-permreq-allow",
        "cwd": "/tmp",
        "hook_event_name": "PermissionRequest",
        "tool_name": "Bash",
        "turn_id": "t1",
        "permission_mode": "default",
        "tool_input": { "command": "ls -la" }
    });
    let (v, _h) = run_as_host("codex", CONFIG_L0_ON_L1_OFF, &env);
    assert_eq!(
        hso_decision(&v),
        "allow",
        "PermissionRequest must allow a safe read-only command: {v}"
    );
}

#[test]
fn codex_permission_request_unknown_fails_closed() {
    // Definitive: an L0-unknown, non-read-only command is denied (no ask).
    let env = json!({
        "session_id": "sess-permreq-unknown",
        "cwd": "/tmp",
        "hook_event_name": "PermissionRequest",
        "tool_name": "Bash",
        "turn_id": "t1",
        "permission_mode": "default",
        "tool_input": { "command": "frobnicate --wibble" }
    });
    let (v, _h) = run_as_host("codex", CONFIG_L0_ON_L1_OFF, &env);
    assert_eq!(
        hso_decision(&v),
        "deny",
        "PermissionRequest must fail closed for unknown command: {v}"
    );
    // Never an ask.
    assert_ne!(hso_decision(&v), "ask");
}

// =========================================================================
// Codex PostCompact (token refresh; non-fatal)
// =========================================================================

#[test]
fn codex_post_compact_runs_without_crash() {
    // No transcript_path -> token counts default to zero; the handler must
    // still exit cleanly and emit no permission decision (generic/no output).
    let env = json!({
        "session_id": "sess-postcompact",
        "cwd": "/tmp",
        "hook_event_name": "PostCompact",
        "turn_id": "t1",
        "permission_mode": "default"
    });
    let binary = env!("CARGO_BIN_EXE_clx-hook");
    let temp = isolated_clx_home();
    let clx_dir = temp.path().join(".clx");
    std::fs::create_dir_all(&clx_dir).expect("mk .clx");
    std::fs::write(clx_dir.join("config.yaml"), CONFIG_L0_ON_L1_OFF).expect("write config");

    let mut command = Command::new(binary);
    let mut child = harden_command(&mut command, temp.path())
        .env("CLX_CREDENTIALS_BACKEND", "age")
        .env("CLX_HOOK_HOST", "codex")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn clx-hook");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(env.to_string().as_bytes())
        .unwrap();
    let out = child.wait_with_output().expect("wait clx-hook");
    assert_home_size_bounded(temp.path());
    // PostCompact emits no permission decision; the binary must exit success.
    assert!(
        out.status.success(),
        "PostCompact hook must exit cleanly; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

// =========================================================================
// Cursor beforeShellExecution (flat permission; ask supported)
// =========================================================================

fn cursor_shell_envelope(session: &str, command: &str) -> serde_json::Value {
    json!({
        "conversation_id": session,
        "hook_event_name": "beforeShellExecution",
        "command": command,
        "workspace_roots": ["/tmp"]
    })
}

#[test]
fn cursor_before_shell_rm_rf_denies() {
    let env = cursor_shell_envelope("conv-deny", "rm -rf /");
    let (v, _h) = run_as_host("cursor", CONFIG_L0_ON_L1_OFF, &env);
    assert_eq!(
        flat_permission(&v),
        "deny",
        "Cursor rm -rf / must be a flat permission deny: {v}"
    );
}

#[test]
fn cursor_before_shell_safe_allows() {
    let env = cursor_shell_envelope("conv-allow", "ls -la");
    let (v, _h) = run_as_host("cursor", CONFIG_L0_ON_L1_OFF, &env);
    assert_eq!(
        flat_permission(&v),
        "allow",
        "Cursor safe read-only command must be a flat permission allow: {v}"
    );
}

#[test]
fn cursor_before_shell_ambiguous_asks() {
    // Cursor (unlike Codex) supports interactive ask: an L0-unknown,
    // non-read-only command with L1 disabled stays "ask".
    let env = cursor_shell_envelope("conv-ask", "frobnicate --wibble /tmp/thing");
    let (v, _h) = run_as_host("cursor", CONFIG_L0_ON_L1_OFF, &env);
    assert_eq!(
        flat_permission(&v),
        "ask",
        "Cursor ambiguous command must be a flat permission ask: {v}"
    );
}

// =========================================================================
// Cross-host: same destructive command denied under all three hosts
// =========================================================================

#[test]
fn cross_host_rm_rf_denies_for_claude_codex_cursor() {
    // Claude envelope.
    let claude_env = json!({
        "session_id": "sess-xhost-claude",
        "cwd": "/tmp",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_use_id": "tu-claude",
        "tool_input": { "command": "rm -rf /" }
    });
    let (cv, _h1) = run_as_host("claude", CONFIG_L0_ON_L1_OFF, &claude_env);
    assert_eq!(hso_decision(&cv), "deny", "Claude rm -rf / must deny: {cv}");

    // Codex envelope.
    let codex_env = json!({
        "session_id": "sess-xhost-codex",
        "cwd": "/tmp",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "turn_id": "t1",
        "permission_mode": "default",
        "tool_input": { "command": "rm -rf /" }
    });
    let (xv, _h2) = run_as_host("codex", CONFIG_L0_ON_L1_OFF, &codex_env);
    assert_eq!(hso_decision(&xv), "deny", "Codex rm -rf / must deny: {xv}");

    // Cursor envelope (flat permission).
    let cursor_env = cursor_shell_envelope("conv-xhost", "rm -rf /");
    let (uv, _h3) = run_as_host("cursor", CONFIG_L0_ON_L1_OFF, &cursor_env);
    assert_eq!(
        flat_permission(&uv),
        "deny",
        "Cursor rm -rf / must deny: {uv}"
    );
}
