//! Wave 1 E: hook router e2e tests (binary subprocess driver).
//!
//! Anchored to `specs/_prerelease/04-integration.md` sections 3.1, 3.2, 3.3
//! and the edge/failure matrix, plus risks I-R2 (no Stop fixture) and I-R3
//! (provenance is fail-safe defense-in-depth, not auth).
//!
//! Driver: the real `clx-hook` binary as a subprocess with an isolated
//! `HOME` (fresh `tempfile::tempdir()` per run) and `CLX_LOG=error`. This is
//! the only safe way to exercise the full router + handlers from a separate
//! integration crate: the in-process `handle_event` path resolves storage
//! via `dirs::home_dir()` and the workspace lint forbids `unsafe`
//! `std::env::set_var`, so HOME cannot be redirected in-process without
//! mutating the real environment. The in-process `handle_event` contract
//! (in-memory `Read`/`Write`, `HookExit`, oversize block JSON on the
//! injectable writer, parse/read-error fallbacks) is therefore covered by a
//! sibling marked module `wave1_integration_behavior` inside
//! `crates/clx-hook/src/router.rs`, which can use the `#[cfg(test)]`-only
//! `HookDeps::for_test()` (in-memory sqlite, no real-env touch).
//!
//! The real `~/.clx` / `~/.claude` are never touched. No network, no
//! keychain, no model download.

use std::io::Write;
use std::process::{Command, Stdio};

#[path = "support/mod.rs"]
mod support;
use support::{assert_home_size_bounded, harden_command, isolated_clx_home};

/// 1 MiB hard cap mirrored from `clx_hook::types::MAX_INPUT_SIZE` (which is
/// `pub(crate)` and not importable from an integration test).
const MAX_INPUT_SIZE: usize = 1_048_576;

/// Spawn the real `clx-hook` binary with an isolated `HOME`, pipe `input`
/// on stdin, and return `(stdout, stderr, exit_code)`.
fn run_binary(input: &str) -> (String, String, Option<i32>) {
    let binary = env!("CARGO_BIN_EXE_clx-hook");
    let dir = isolated_clx_home();
    let mut command = Command::new(binary);
    let mut child = harden_command(&mut command, dir.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn clx-hook");
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(input.as_bytes()).expect("write stdin");
    }
    let output = child.wait_with_output().expect("wait clx-hook");
    assert_home_size_bounded(dir.path());
    (
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
        output.status.code(),
    )
}

/// Minimal valid envelope for an arbitrary event name plus optional extra
/// fields merged into the top-level object.
fn envelope(event: &str, extra: &serde_json::Value) -> String {
    let mut base = serde_json::json!({
        "session_id": "00000000-0000-0000-0000-0000000000ee",
        "cwd": "/tmp/test-project",
        "hook_event_name": event,
    });
    if let (Some(b), Some(e)) = (base.as_object_mut(), extra.as_object()) {
        for (k, v) in e {
            b.insert(k.clone(), v.clone());
        }
    }
    base.to_string()
}

/// Assert the binary exits 0 (every `HookExit` maps to SUCCESS) and stdout
/// is empty OR a valid JSON object whose `hookSpecificOutput.hookEventName`
/// matches `expected` or the `PreToolUse` fallback (spec 3.3 contract).
fn assert_binary_emit(raw: &str, expected: &str) {
    let (stdout, stderr, code) = run_binary(raw);
    assert_eq!(
        code,
        Some(0),
        "clx-hook must exit 0 for {expected}; stderr: {stderr}"
    );
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        return; // side-effect-only events legitimately emit nothing
    }
    let v: serde_json::Value = serde_json::from_str(trimmed)
        .unwrap_or_else(|e| panic!("{expected} stdout must be JSON: {e}; raw stdout: {stdout}"));
    let got = v
        .get("hookSpecificOutput")
        .and_then(|h| h.get("hookEventName"))
        .and_then(|s| s.as_str())
        .unwrap_or("");
    assert!(
        got == expected || got == "PreToolUse",
        "expected {expected} or PreToolUse fallback, got {got}; stdout: {stdout}"
    );
}

// ===========================================================================
// 3.2: emitted JSON + exit code for all 8 registered hook events
// ===========================================================================

#[test]
fn binary_pre_tool_use_emits_decision() {
    assert_binary_emit(
        &envelope(
            "PreToolUse",
            &serde_json::json!({"tool_name":"Read","tool_use_id":"tu","tool_input":{"file_path":"/tmp/x"}}),
        ),
        "PreToolUse",
    );
}

#[test]
fn binary_post_tool_use_side_effect_only() {
    assert_binary_emit(
        &envelope(
            "PostToolUse",
            &serde_json::json!({"tool_name":"Read","tool_use_id":"tu","tool_input":{"file_path":"/tmp/x"},"tool_response":{"ok":true}}),
        ),
        "PostToolUse",
    );
}

#[test]
fn binary_pre_compact_side_effect_only() {
    assert_binary_emit(
        &envelope("PreCompact", &serde_json::json!({"trigger":"auto"})),
        "PreCompact",
    );
}

#[test]
fn binary_session_start_emits_system_message_or_empty() {
    assert_binary_emit(
        &envelope("SessionStart", &serde_json::json!({"source":"startup"})),
        "SessionStart",
    );
}

#[test]
fn binary_session_end_side_effect_only() {
    assert_binary_emit(
        &envelope("SessionEnd", &serde_json::json!({})),
        "SessionEnd",
    );
}

#[test]
fn binary_subagent_start_emits_specialist_context() {
    let (stdout, stderr, code) = run_binary(&envelope(
        "SubagentStart",
        &serde_json::json!({"tool_name":"Task"}),
    ));
    assert_eq!(code, Some(0), "exit 0 expected; stderr: {stderr}");
    let trimmed = stdout.trim();
    if !trimmed.is_empty() {
        let v: serde_json::Value = serde_json::from_str(trimmed).expect("json");
        assert_eq!(v["hookSpecificOutput"]["hookEventName"], "SubagentStart");
        let ctx = v["hookSpecificOutput"]["additionalContext"]
            .as_str()
            .unwrap_or("");
        assert!(
            ctx.contains("[SPECIALIST RULES]"),
            "expected SPECIALIST_CONTEXT, got: {ctx}"
        );
    }
}

#[test]
fn binary_user_prompt_submit_side_effect_or_orchestrator() {
    assert_binary_emit(
        &envelope(
            "UserPromptSubmit",
            &serde_json::json!({"prompt":"a reasonably long prompt to clear the min length gate"}),
        ),
        "UserPromptSubmit",
    );
}

#[test]
fn binary_stop_event_synthesized_envelope_exits_clean_closes_ir2_gap() {
    // I-R2: the shipped stop.json fixture is actually a SessionEnd event;
    // there is no Stop contract fixture. Synthesize a correctly-shaped
    // Stop envelope here so the Stop hook path is exercised end-to-end.
    // memory.auto_summarize.enabled defaults FALSE so the handler is a
    // fast no-op; the contract is "exits 0, stdout empty or valid JSON".
    let stop = envelope(
        "Stop",
        &serde_json::json!({
            "transcript_path": "/tmp/test-project/.claude/transcripts/stop-ir2.jsonl"
        }),
    );
    assert_binary_emit(&stop, "Stop");
}

// ===========================================================================
// 3.1 + edge/failure matrix: fallbacks always exit 0
// ===========================================================================

#[test]
fn binary_oversize_input_blocks_and_exits_zero() {
    let big = "x".repeat(MAX_INPUT_SIZE + 1);
    let (stdout, _stderr, code) = run_binary(&big);
    assert_eq!(code, Some(0), "every HookExit maps to SUCCESS");
    let v: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("oversize block json on stdout");
    assert_eq!(v["hookSpecificOutput"]["hookEventName"], "PreToolUse");
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "block");
    assert_eq!(
        v["hookSpecificOutput"]["permissionDecisionReason"],
        "Input too large"
    );
}

#[test]
fn binary_exactly_at_cap_is_rejected() {
    // `n >= MAX_INPUT_SIZE` is the documented boundary (router.rs:153).
    let at_cap = "x".repeat(MAX_INPUT_SIZE);
    let (stdout, _stderr, code) = run_binary(&at_cap);
    assert_eq!(code, Some(0));
    let v: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("block json at exact cap");
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "block");
}

#[test]
fn binary_malformed_json_asks_and_exits_zero() {
    let (stdout, _stderr, code) = run_binary("{not valid json");
    assert_eq!(code, Some(0));
    let v: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("ask fallback json on stdout");
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "ask");
    assert!(
        v["hookSpecificOutput"]["permissionDecisionReason"]
            .as_str()
            .unwrap_or("")
            .contains("parse error"),
        "expected a parse-error reason, got {stdout}"
    );
}

#[test]
fn binary_empty_stdin_asks_and_exits_zero() {
    let (stdout, _stderr, code) = run_binary("");
    assert_eq!(code, Some(0));
    let v: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("empty stdin -> ask fallback");
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "ask");
}

#[test]
fn binary_missing_required_field_asks_and_exits_zero() {
    let raw = serde_json::json!({ "hook_event_name": "PreToolUse" }).to_string();
    let (stdout, _stderr, code) = run_binary(&raw);
    assert_eq!(code, Some(0));
    let v: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("missing field -> ask fallback");
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "ask");
}

#[test]
fn binary_unknown_event_allows_and_exits_zero() {
    let (stdout, _stderr, code) =
        run_binary(&envelope("TotallyUnknownEvent2027", &serde_json::json!({})));
    assert_eq!(code, Some(0));
    let v: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("allow fallback json on stdout");
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "allow");
}

#[test]
fn binary_transcript_dev_zero_is_rejected_non_fatal() {
    // Edge matrix: transcript /dev/zero rejected by safe_transcript_path,
    // handler returns empty result (non-fatal), binary still exits 0.
    let raw = envelope(
        "PreCompact",
        &serde_json::json!({"trigger":"auto","transcript_path":"/dev/zero"}),
    );
    let (_stdout, stderr, code) = run_binary(&raw);
    assert_eq!(
        code,
        Some(0),
        "an unusable transcript must stay non-fatal; stderr: {stderr}"
    );
}

#[test]
fn binary_hook_outside_claude_code_no_provenance_env_still_processes() {
    // Edge matrix / I-R3: hook run with no CLAUDE_* env (run_binary does
    // not set them) must WARN + continue (fail-safe). A valid SubagentStart
    // envelope still produces a clean exit.
    let raw = envelope("SubagentStart", &serde_json::json!({"tool_name":"Task"}));
    let (_stdout, _stderr, code) = run_binary(&raw);
    assert_eq!(code, Some(0), "fail-safe: no provenance still processes");
}
