//! Host transcript/event routing matrix (Cursor + Codex + Claude), driven
//! through the real `clx-hook` binary with an isolated `HOME`.
//!
//! Behavior dossier (mode: coverage_gap)
//! ------------------------------------
//! Boundary under test: the `clx-hook` binary's host-detection + response
//! mapping. The host-classification API (`host::sniff_envelope`,
//! `host::detect_host`, the `Host` trait, `HostId`) is crate-private, so the
//! nearest practical public boundary is the process itself: stdin envelope ->
//! stdout decision JSON, with the host forced via the documented
//! `CLX_HOOK_HOST` seam OR inferred from the envelope shape.
//!
//! Real contract (read from crates/clx-hook/src/host.rs, NOT invented):
//!   1. `CLX_HOOK_HOST` (claude/codex/cursor, case-insensitive, trimmed) wins.
//!   2. else envelope sniffing: `hook_event_name == beforeShellExecution`
//!      -> Cursor; a top-level `turn_id` key -> Codex; everything else
//!      (including unknown/ambiguous/malformed) -> Claude (the documented
//!      safe default).
//!   3. each host emits its own response SHAPE: Claude/Codex use
//!      `hookSpecificOutput.permissionDecision`; Cursor uses a flat top-level
//!      `permission` field. A host never emits another host's shape.
//!   4. Codex has no interactive ask: an ask verdict collapses to a
//!      fail-closed deny carrying the documented Codex reason.
//!   5. secrets/PII in agent-influenced fields (command, cwd) must never be
//!      echoed verbatim into the emitted decision JSON (redaction promise).
//!   6. malformed / provenance-absent envelopes must not panic; the binary
//!      exits successfully and emits a safe fallback decision.
//!
//! Hermetic: redirected `HOME`, `CLX_MODEL_FETCH_DRYRUN=1`,
//! `CLX_CREDENTIALS_BACKEND=age`. No network / keychain / model. All secrets
//! are synthetic; no real Azure tenant or key appears.

#![allow(clippy::doc_markdown)]

use std::io::Write;
use std::process::{Command, Stdio};

use serde_json::json;

#[path = "support/mod.rs"]
mod support;
use support::{assert_home_size_bounded, harden_command, isolated_clx_home};

/// L0-on, L1-off: the deterministic ruleset alone decides. `rm -rf /` is a
/// hard L0 deny under every host; an L0-unknown non-read-only command escalates
/// to ask. No LLM is needed so verdicts are deterministic across hosts.
const CONFIG_L0_ON_L1_OFF: &str = "validator:\n  \
       enabled: true\n  \
       cache_enabled: false\n  \
       layer0_enabled: true\n  \
       layer1_enabled: false\n  \
       auto_allow_reads: true\n";

/// Outcome of one hook invocation: parsed stdout JSON + exit success flag +
/// raw stdout/stderr (so leak assertions can scan everything emitted).
struct HookRun {
    stdout_json: Option<serde_json::Value>,
    raw_stdout: String,
    raw_stderr: String,
    success: bool,
}

/// Run the real binary with an isolated HOME. `host` is the `CLX_HOOK_HOST`
/// override (or `None` to exercise envelope sniffing). The config is written
/// into the sandbox so the deterministic ruleset is active.
fn run(host: Option<&str>, envelope_bytes: &[u8]) -> HookRun {
    let binary = env!("CARGO_BIN_EXE_clx-hook");
    let temp = isolated_clx_home();
    let clx_dir = temp.path().join(".clx");
    std::fs::create_dir_all(&clx_dir).expect("mk .clx");
    std::fs::write(clx_dir.join("config.yaml"), CONFIG_L0_ON_L1_OFF).expect("write config");

    let mut command = Command::new(binary);
    let cmd = harden_command(&mut command, temp.path())
        .env("CLX_CREDENTIALS_BACKEND", "age")
        // Issue 2: a truthy CLAUDECODE forces HostId::Claude (precedence above
        // envelope sniffing). The envelope-sniff routing tests must be hermetic,
        // so clear any ambient CLAUDECODE inherited from a Claude Code test
        // runner; the dedicated CLAUDECODE-precedence tests live in host.rs.
        .env_remove("CLAUDECODE");
    if let Some(h) = host {
        cmd.env("CLX_HOOK_HOST", h);
    }
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn clx-hook");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(envelope_bytes)
        .unwrap();
    let out = child.wait_with_output().expect("wait clx-hook");
    assert_home_size_bounded(temp.path());

    let raw_stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let raw_stderr = String::from_utf8_lossy(&out.stderr).to_string();
    let stdout_json = serde_json::from_str(raw_stdout.trim()).ok();
    HookRun {
        stdout_json,
        raw_stdout,
        raw_stderr,
        success: out.status.success(),
    }
}

fn run_json(host: Option<&str>, envelope: &serde_json::Value) -> HookRun {
    run(host, envelope.to_string().as_bytes())
}

/// `hookSpecificOutput.permissionDecision` (Claude / Codex response shape).
fn hso_decision(v: &serde_json::Value) -> Option<&str> {
    v.get("hookSpecificOutput")?
        .get("permissionDecision")?
        .as_str()
}

/// `hookSpecificOutput.permissionDecisionReason`.
fn hso_reason(v: &serde_json::Value) -> &str {
    v.get("hookSpecificOutput")
        .and_then(|h| h.get("permissionDecisionReason"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or("")
}

/// Cursor flat top-level `permission` field.
fn flat_permission(v: &serde_json::Value) -> Option<&str> {
    v.get("permission")?.as_str()
}

/// Synthetic secret + PII blob embedded in a command. Never a real credential.
const SECRET_CMD: &str = "curl -H 'Authorization: Bearer SYNTHabcdef0123456789' https://x/?key=sk-SYNTH0123456789abcdef \
     # contact alice-synth@example.com";

fn claude_pre_tool(session: &str, command: &str) -> serde_json::Value {
    json!({
        "session_id": session,
        "cwd": "/tmp",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_use_id": "tu-1",
        "tool_input": { "command": command }
    })
}

fn codex_pre_tool(session: &str, command: &str) -> serde_json::Value {
    json!({
        "session_id": session,
        "cwd": "/tmp",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "turn_id": "t1",
        "permission_mode": "default",
        "tool_input": { "command": command }
    })
}

fn cursor_shell(conv: &str, command: &str) -> serde_json::Value {
    json!({
        "conversation_id": conv,
        "hook_event_name": "beforeShellExecution",
        "command": command,
        "workspace_roots": ["/tmp"]
    })
}

// ===========================================================================
// Happy path per host: each host classifies and emits ITS OWN response shape.
// ===========================================================================

#[test]
fn claude_happy_path_emits_inline_permission_decision_shape() {
    // Forced Claude. A hard L0 deny is deterministic and exercises the
    // Claude inline `hookSpecificOutput.permissionDecision` shape.
    let r = run_json(Some("claude"), &claude_pre_tool("s-claude", "rm -rf /"));
    let v = r.stdout_json.expect("claude stdout must be JSON");
    assert_eq!(
        hso_decision(&v),
        Some("deny"),
        "Claude must use the inline permissionDecision shape: {v}"
    );
    // Claude must NOT emit Cursor's flat permission field.
    assert_eq!(
        flat_permission(&v),
        None,
        "Claude must never emit a Cursor-style flat `permission`: {v}"
    );
}

#[test]
fn codex_happy_path_emits_inline_shape_and_fails_closed_on_ask() {
    // Forced Codex. An L0-unknown non-read-only command escalates to ask;
    // Codex has no interactive ask, so it collapses to a fail-closed deny
    // carrying the documented reason. This proves the Codex ask-channel
    // contract AND that Codex uses the inline shape (not Cursor's flat one).
    let r = run_json(
        Some("codex"),
        &codex_pre_tool("s-codex", "frobnicate --wibble /tmp/thing"),
    );
    let v = r.stdout_json.expect("codex stdout must be JSON");
    assert_eq!(
        hso_decision(&v),
        Some("deny"),
        "Codex ask-verdict must fail closed to deny: {v}"
    );
    assert!(
        hso_reason(&v).contains("Codex does not support interactive ask"),
        "Codex fail-closed deny must carry the documented reason, got: {}",
        hso_reason(&v)
    );
    assert_eq!(
        flat_permission(&v),
        None,
        "Codex must never emit a Cursor-style flat `permission`: {v}"
    );
}

#[test]
fn cursor_happy_path_emits_flat_permission_shape() {
    // Forced Cursor. Same rm -rf / hard deny, but Cursor's response is a flat
    // top-level `permission` field with NO hookSpecificOutput envelope.
    let r = run_json(Some("cursor"), &cursor_shell("conv-1", "rm -rf /"));
    let v = r.stdout_json.expect("cursor stdout must be JSON");
    assert_eq!(
        flat_permission(&v),
        Some("deny"),
        "Cursor must use the flat permission shape: {v}"
    );
    // Cursor must NOT emit the Claude/Codex inline shape.
    assert!(
        v.get("hookSpecificOutput").is_none(),
        "Cursor must never emit a Claude/Codex-style hookSpecificOutput: {v}"
    );
}

#[test]
fn cursor_ambiguous_command_asks_codex_same_command_denies() {
    // The same L0-unknown command is an interactive `ask` under Cursor (which
    // supports ask) but a fail-closed `deny` under Codex (which does not).
    // This is the host-capability divergence, asserted side by side.
    let cmd = "frobnicate --wibble /tmp/thing";
    let cur = run_json(Some("cursor"), &cursor_shell("conv-ask", cmd));
    let cur_v = cur.stdout_json.expect("cursor json");
    assert_eq!(
        flat_permission(&cur_v),
        Some("ask"),
        "Cursor ambiguous command must ask: {cur_v}"
    );

    let cdx = run_json(Some("codex"), &codex_pre_tool("s-codex-ask", cmd));
    let cdx_v = cdx.stdout_json.expect("codex json");
    assert_eq!(
        hso_decision(&cdx_v),
        Some("deny"),
        "Codex ambiguous command must fail closed to deny: {cdx_v}"
    );
}

// ===========================================================================
// Envelope sniffing (provenance via shape, NO override): the documented
// resolution order. This is the "provenance present in the envelope" matrix.
// ===========================================================================

#[test]
fn sniff_turn_id_routes_to_codex_shape() {
    // No override: a top-level `turn_id` is the Codex marker. The Codex shape
    // (inline + fail-closed reason on ask) proves classification took effect.
    let r = run_json(None, &codex_pre_tool("s-sniff-codex", "frobnicate --x"));
    let v = r.stdout_json.expect("json");
    assert_eq!(hso_decision(&v), Some("deny"), "{v}");
    assert!(
        hso_reason(&v).contains("Codex does not support interactive ask"),
        "sniffed-Codex must use the Codex ask-channel: {}",
        hso_reason(&v)
    );
}

#[test]
fn sniff_before_shell_execution_routes_to_cursor_shape() {
    // No override: `beforeShellExecution` is the Cursor marker. The flat
    // permission shape with `ask` (Cursor supports ask) proves it.
    let r = run_json(None, &cursor_shell("conv-sniff", "frobnicate --x"));
    let v = r.stdout_json.expect("json");
    assert_eq!(
        flat_permission(&v),
        Some("ask"),
        "sniffed-Cursor must use the flat permission ask shape: {v}"
    );
}

#[test]
fn ambiguous_envelope_defaults_to_claude_shape() {
    // No override, no Codex/Cursor marker: the documented safe default is
    // Claude. A plain Claude-style envelope with a hard deny proves the
    // default path emits the Claude inline shape (not Cursor's flat one).
    let r = run_json(None, &claude_pre_tool("s-default", "rm -rf /"));
    let v = r.stdout_json.expect("json");
    assert_eq!(hso_decision(&v), Some("deny"), "{v}");
    assert_eq!(
        flat_permission(&v),
        None,
        "ambiguous envelope must default to the Claude inline shape: {v}"
    );
}

#[test]
fn permission_mode_alone_does_not_misclassify_as_codex() {
    // Regression guard (documented in host.rs): Claude Code also emits a
    // top-level `permission_mode`; it must NOT be a Codex marker. With no
    // `turn_id`, this must stay Claude. An L0-unknown command would be a
    // Claude `ask`, never a Codex fail-closed deny with the Codex reason.
    let env = json!({
        "session_id": "s-pm",
        "cwd": "/tmp",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "permission_mode": "default",
        "tool_input": { "command": "frobnicate --wibble" }
    });
    let r = run_json(None, &env);
    let v = r.stdout_json.expect("json");
    assert!(
        !hso_reason(&v).contains("Codex does not support interactive ask"),
        "permission_mode alone must not route to Codex: {v}"
    );
    // Claude surfaces the ask inline (host supports interactive ask).
    assert_eq!(
        hso_decision(&v),
        Some("ask"),
        "Claude must surface the ask verdict inline: {v}"
    );
}

// ===========================================================================
// Unknown / override edge handling
// ===========================================================================

#[test]
fn unknown_override_falls_through_to_envelope_sniffing() {
    // An unrecognized CLX_HOOK_HOST value must be ignored (fall through to
    // envelope detection), NOT silently treated as some default host that
    // changes the response shape. Envelope carries the Cursor marker, so the
    // flat Cursor shape must still appear.
    let r = run_json(
        Some("windsurf"),
        &cursor_shell("conv-fallthrough", "rm -rf /"),
    );
    let v = r.stdout_json.expect("json");
    assert_eq!(
        flat_permission(&v),
        Some("deny"),
        "unknown override must fall through to envelope sniffing (Cursor): {v}"
    );
}

#[test]
fn override_is_case_insensitive_and_trimmed() {
    // "  CURSOR " must force Cursor even though the envelope is a Claude-style
    // PreToolUse (no Cursor marker). The flat permission shape proves the
    // override won despite the Claude-shaped envelope.
    let r = run_json(Some("  CURSOR "), &claude_pre_tool("s-ci", "rm -rf /"));
    let v = r.stdout_json.expect("json");
    assert_eq!(
        flat_permission(&v),
        Some("deny"),
        "trimmed/case-insensitive override must force the Cursor shape: {v}"
    );
}

// ===========================================================================
// Provenance-absent / malformed: no panic, safe fallback, clean exit.
// ===========================================================================

#[test]
fn malformed_json_envelope_exits_clean_without_panic() {
    // Not valid JSON. The binary must not crash; it emits a safe fallback
    // (parse-error path) and exits successfully (per HookExit mapping).
    let r = run(None, b"{ this is : not valid json ");
    assert!(
        r.success,
        "malformed envelope must exit cleanly; stderr: {}",
        r.raw_stderr
    );
    // It must not be a silent crash: some JSON decision should be emitted.
    assert!(
        r.stdout_json.is_some(),
        "malformed envelope must still emit a fallback decision; stdout: {}",
        r.raw_stdout
    );
}

#[test]
fn empty_stdin_exits_clean_without_panic() {
    let r = run(None, b"");
    assert!(
        r.success,
        "empty stdin must exit cleanly; stderr: {}",
        r.raw_stderr
    );
}

#[test]
fn empty_json_object_defaults_to_claude_and_exits_clean() {
    // Provenance-absent: `{}` has no markers and no required fields. The
    // documented sniff default is Claude; missing required fields make this a
    // parse error which falls back safely. Either way: no panic, clean exit.
    let r = run(None, b"{}");
    assert!(
        r.success,
        "empty-object envelope must exit cleanly; stderr: {}",
        r.raw_stderr
    );
    assert!(
        r.stdout_json.is_some(),
        "empty-object envelope must emit a fallback decision; stdout: {}",
        r.raw_stdout
    );
}

#[test]
fn unknown_event_name_is_allowed_safely_for_each_host() {
    // A forward-compat event the router does not recognize must reach the
    // safe allow fallback (never crash) regardless of forced host.
    for host in ["claude", "codex", "cursor"] {
        let env = json!({
            "session_id": "s-unknown-event",
            "cwd": "/tmp",
            "hook_event_name": "SomeFutureEvent2099",
            "turn_id": "t1"
        });
        let r = run_json(Some(host), &env);
        assert!(
            r.success,
            "host {host}: unknown event must exit cleanly; stderr: {}",
            r.raw_stderr
        );
    }
}

// ===========================================================================
// Cross-host leak defense: a secret/PII-bearing command must never be echoed
// verbatim into ANY host's emitted decision JSON or stderr.
// ===========================================================================

#[test]
fn secret_bearing_command_is_not_echoed_into_any_host_response() {
    let cases: [(&str, serde_json::Value); 3] = [
        ("claude", claude_pre_tool("s-leak-claude", SECRET_CMD)),
        ("codex", codex_pre_tool("s-leak-codex", SECRET_CMD)),
        ("cursor", cursor_shell("conv-leak", SECRET_CMD)),
    ];
    for (host, env) in cases {
        let r = run_json(Some(host), &env);
        // The synthetic secrets must not appear verbatim anywhere the host
        // surfaces back to the agent (stdout decision) nor in stderr logs.
        for needle in [
            "SYNTHabcdef0123456789",
            "sk-SYNTH0123456789abcdef",
            "alice-synth@example.com",
        ] {
            assert!(
                !r.raw_stdout.contains(needle),
                "host {host}: secret `{needle}` leaked into stdout decision: {}",
                r.raw_stdout
            );
            assert!(
                !r.raw_stderr.contains(needle),
                "host {host}: secret `{needle}` leaked into stderr: {}",
                r.raw_stderr
            );
        }
    }
}

#[test]
fn cross_host_same_destructive_command_denies_in_each_native_shape() {
    // The SAME destructive command is denied under all three hosts, each in
    // its own native response shape. This locks the host-routing matrix:
    // classification + per-host shape + deterministic L0 deny together.
    let claude = run_json(Some("claude"), &claude_pre_tool("x-claude", "rm -rf /"));
    assert_eq!(
        hso_decision(&claude.stdout_json.expect("claude json")),
        Some("deny")
    );

    let codex = run_json(Some("codex"), &codex_pre_tool("x-codex", "rm -rf /"));
    assert_eq!(
        hso_decision(&codex.stdout_json.expect("codex json")),
        Some("deny")
    );

    let cursor = run_json(Some("cursor"), &cursor_shell("x-cursor", "rm -rf /"));
    assert_eq!(
        flat_permission(&cursor.stdout_json.expect("cursor json")),
        Some("deny")
    );
}
