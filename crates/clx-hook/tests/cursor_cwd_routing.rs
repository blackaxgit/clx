//! Regression: cwd-less Cursor envelopes must be routed, validated, and
//! answered in Cursor's own protocol - never dropped as a parse error.
//!
//! Field report (`~/.clx/logs/clx.log`, 1 671 occurrences):
//!
//! ```text
//! ERROR clx_hook::router: Failed to parse hook input: missing field `cwd`
//! ```
//!
//! Cause: cursor-agent stamps `workspace_roots` on every hook payload and
//! never sends a `cwd` key. Host detection only recognised the two
//! `before*Execution` gating events, so every other Cursor event fell through
//! to the Claude default, where the strict `cwd: String` parse hard-failed.
//! The event was then answered with a Claude-shaped `hookSpecificOutput`
//! blob that Cursor cannot read - so neither L0 nor L1 ran for it and no
//! decision reached the host either.
//!
//! Unlike the sibling `host_routing_p4.rs`, these tests deliberately do NOT
//! set `CLX_HOOK_HOST`: the host must be resolved from the envelope itself,
//! which is the seam that was broken. `CLAUDECODE=1` is set on purpose - it
//! reproduces a `cursor-agent` launched from a Claude Code shell, which
//! inherits that variable and previously forced the wrong host.
//!
//! Hermetic: redirected `HOME`, `CLX_MODEL_FETCH_DRYRUN=1`,
//! `CLX_CREDENTIALS_BACKEND=age`, no network.

#![allow(clippy::doc_markdown)]

use std::io::Write;
use std::process::{Command, Stdio};

use serde_json::json;

#[path = "support/mod.rs"]
mod support;
use support::{assert_home_size_bounded, harden_command, isolated_clx_home};

/// L0-on, L1-off: the deterministic ruleset alone decides, so `rm -rf /` is a
/// stable deny with no LLM in the loop.
const CONFIG_L0_ON_L1_OFF: &str = "validator:\n  \
       enabled: true\n  \
       cache_enabled: false\n  \
       layer0_enabled: true\n  \
       layer1_enabled: false\n  \
       auto_allow_reads: true\n";

/// Run the real binary with NO `CLX_HOOK_HOST` override, so host detection
/// runs for real, and with `CLAUDECODE=1` to emulate a nested spawn.
/// Returns the raw stdout plus the `TempDir` keeping `HOME` alive.
fn run_autodetect(envelope: &str) -> (String, tempfile::TempDir) {
    let binary = env!("CARGO_BIN_EXE_clx-hook");
    let temp = isolated_clx_home();
    let clx_dir = temp.path().join(".clx");
    std::fs::create_dir_all(&clx_dir).expect("mk .clx");
    std::fs::write(clx_dir.join("config.yaml"), CONFIG_L0_ON_L1_OFF).expect("write config");

    let mut command = Command::new(binary);
    let mut child = harden_command(&mut command, temp.path())
        .env("CLX_CREDENTIALS_BACKEND", "age")
        .env("CLAUDECODE", "1")
        .env_remove("CLX_HOOK_HOST")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn clx-hook");

    child
        .stdin
        .take()
        .unwrap()
        .write_all(envelope.as_bytes())
        .unwrap();

    let out = child.wait_with_output().expect("wait clx-hook");
    assert_home_size_bounded(temp.path());
    (String::from_utf8_lossy(&out.stdout).to_string(), temp)
}

/// A real cursor-agent payload shape: `workspace_roots`, `cursor_version`,
/// `conversation_id` - and no `cwd` key at all.
fn cursor_envelope(event: &str, extra: &serde_json::Value) -> String {
    let mut base = json!({
        "conversation_id": "conv-cwdless",
        "session_id": "sess-cwdless",
        "hook_event_name": event,
        "cursor_version": "2026.07.17",
        "workspace_roots": ["/tmp"],
        "user_email": "dev@example.com"
    });
    if let (Some(b), Some(e)) = (base.as_object_mut(), extra.as_object()) {
        for (k, v) in e {
            b.insert(k.clone(), v.clone());
        }
    }
    base.to_string()
}

fn parse_stdout(stdout: &str) -> serde_json::Value {
    serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("hook stdout must be valid JSON: {e}\nstdout: {stdout}"))
}

/// The security-relevant assertion. A cwd-less Cursor gating envelope must be
/// validated by L0 and denied.
///
/// FAIL-BEFORE: with `CLAUDECODE=1` inherited, the envelope resolved to
/// `ClaudeHost`, died on a `missing-field-cwd`, and `rm -rf /` was never
/// evaluated.
/// PASS-AFTER: the envelope is recognised as Cursor, L0 runs, and the deny is
/// written in Cursor's flat-`permission` protocol.
#[test]
fn cwdless_cursor_shell_envelope_is_validated_and_denied() {
    let env = cursor_envelope("beforeShellExecution", &json!({ "command": "rm -rf /" }));
    let (stdout, _home) = run_autodetect(&env);
    let v = parse_stdout(&stdout);

    assert_eq!(
        v["permission"], "deny",
        "L0 must evaluate a cwd-less Cursor envelope and deny `rm -rf /`: {v}"
    );
    assert!(
        v.get("hookSpecificOutput").is_none(),
        "the decision must be in Cursor's flat-permission shape, not Claude's: {v}"
    );
}

/// A safe command through the same cwd-less path still allows: the fix must
/// not turn every Cursor event into a blanket block.
#[test]
fn cwdless_cursor_shell_envelope_allows_safe_command() {
    let env = cursor_envelope("beforeShellExecution", &json!({ "command": "ls -la" }));
    let (stdout, _home) = run_autodetect(&env);
    let v = parse_stdout(&stdout);
    assert_eq!(
        v["permission"], "allow",
        "a safe command must still be allowed: {v}"
    );
}

/// The events that produced the 1 671 log lines: every Cursor lifecycle
/// event other than the two `before*Execution` ones. None may come back as
/// the Claude-shaped parse-error `ask`.
#[test]
fn cwdless_cursor_lifecycle_events_are_not_parse_errors() {
    for (event, extra) in [
        ("afterShellExecution", json!({ "command": "ls -la" })),
        ("sessionStart", json!({})),
        ("sessionEnd", json!({})),
        ("stop", json!({})),
        ("userPromptSubmit", json!({ "prompt": "hello there" })),
    ] {
        let env = cursor_envelope(event, &extra);
        let (stdout, _home) = run_autodetect(&env);

        assert!(
            !stdout.contains("Input parse error"),
            "Cursor {event} must not be dropped as a parse error; stdout: {stdout}"
        );
        assert!(
            !stdout.contains("permissionDecision"),
            "Cursor {event} must not be answered with a Claude permission \
             decision - that is the parse-error fallback path; stdout: {stdout}"
        );
    }
}

/// A genuinely unparseable envelope that is still identifiable as Cursor must
/// fail CLOSED in Cursor's own protocol (F7 posture, matching
/// `on_validator_unavailable`).
///
/// FAIL-BEFORE: the fallback always emitted Claude's `hookSpecificOutput`
/// `ask`, which Cursor cannot read - a fail-open wearing a fail-closed label.
/// PASS-AFTER: `{"permission":"ask", ...}`.
#[test]
fn unparseable_cursor_envelope_fails_closed_in_cursor_protocol() {
    // `session_id` as a number: valid JSON, invalid envelope. The Cursor
    // marker keys are still present, so host detection succeeds.
    let env = json!({
        "session_id": 12345,
        "hook_event_name": "beforeShellExecution",
        "command": "rm -rf /",
        "cursor_version": "2026.07.17",
        "workspace_roots": ["/tmp"]
    })
    .to_string();
    let (stdout, _home) = run_autodetect(&env);
    let v = parse_stdout(&stdout);

    assert_eq!(
        v["permission"], "ask",
        "an unparseable Cursor envelope must fail closed to ask: {v}"
    );
    assert_ne!(
        v["permission"], "allow",
        "a parse failure must never resolve to allow: {v}"
    );
}

/// Inverse guard: a genuine Claude envelope under the same conditions is
/// untouched - still validated, still answered in Claude's shape.
#[test]
fn claude_envelope_is_unaffected_by_cursor_detection() {
    let env = json!({
        "session_id": "sess-claude-guard",
        "cwd": "/tmp",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_use_id": "tu-guard",
        "tool_input": { "command": "rm -rf /" }
    })
    .to_string();
    let (stdout, _home) = run_autodetect(&env);
    let v = parse_stdout(&stdout);

    assert_eq!(
        v["hookSpecificOutput"]["permissionDecision"], "deny",
        "Claude envelopes must keep their own protocol and verdict: {v}"
    );
    assert!(
        v.get("permission").is_none(),
        "Claude output must not acquire Cursor's flat permission field: {v}"
    );
}
