//! Cross-host audit-row regression (P8 / D6).
//!
//! The sibling `host_routing_p4.rs::cross_host_rm_rf_denies_for_claude_codex_cursor`
//! proves that the SAME destructive command is denied under Claude, Codex, and
//! Cursor. That test uses a fresh isolated `HOME` (and therefore a fresh
//! `SQLite` DB) per host, so it cannot observe the persisted audit rows.
//!
//! This test closes the remaining matrix gap from spec §5:
//!
//! > Cross-host: same `rm -rf /` via all 3 envelopes -> deny each; SQLite
//! > `host` column distinguishes rows.
//!
//! It drives all three hosts against a SINGLE shared `HOME` (one `clx.db`),
//! asserts each host denies the destructive command, then reads the
//! `audit_log` table back and proves the v8 `host` column attributes each
//! row to the host that produced it (`'claude'` / `'codex'` / `'cursor'`).
//!
//! Hermetic: redirected `HOME`, `CLX_MODEL_FETCH_DRYRUN=1`,
//! `CLX_CREDENTIALS_BACKEND=age`, host forced via `CLX_HOOK_HOST`. No network.

#![allow(clippy::doc_markdown)]

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use serde_json::json;

#[path = "support/mod.rs"]
mod support;
use support::{assert_home_size_bounded, harden_command, isolated_clx_home};

/// L0-on, L1-off: the deterministic ruleset alone decides. `rm -rf /` is a
/// hard L0 deny under every host, so no LLM is needed and the verdict is
/// stable across hosts.
const CONFIG_L0_ON_L1_OFF: &str = "validator:\n  \
       enabled: true\n  \
       cache_enabled: false\n  \
       layer0_enabled: true\n  \
       layer1_enabled: false\n  \
       auto_allow_reads: true\n";

/// Run the real `clx-hook` binary against the *given* shared `HOME`, forcing
/// `host` via `CLX_HOOK_HOST`. Returns parsed stdout JSON.
///
/// Unlike `host_routing_p4::run_as_host`, this does NOT create its own
/// `HOME`: all callers share one so their audit rows land in one DB.
fn run_in_home(home: &Path, host: &str, envelope: &serde_json::Value) -> serde_json::Value {
    let binary = env!("CARGO_BIN_EXE_clx-hook");

    let mut command = Command::new(binary);
    let mut child = harden_command(&mut command, home)
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
    serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("hook stdout must be valid JSON: {e}\nstdout: {stdout}"))
}

/// Run the real `clx-hook` binary against `home` forcing `host`, ignoring
/// stdout. For lifecycle events (PostToolUse) that persist state but emit no
/// permission decision. Asserts the binary exits successfully.
fn run_in_home_lifecycle(home: &Path, host: &str, envelope: &serde_json::Value) {
    let binary = env!("CARGO_BIN_EXE_clx-hook");

    let mut command = Command::new(binary);
    let mut child = harden_command(&mut command, home)
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
    assert!(
        out.status.success(),
        "lifecycle hook must exit cleanly; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// `hookSpecificOutput.permissionDecision` (Claude / Codex shape).
fn hso_decision(v: &serde_json::Value) -> &str {
    v["hookSpecificOutput"]["permissionDecision"]
        .as_str()
        .unwrap_or("")
}

/// Cursor flat `permission` field.
fn flat_permission(v: &serde_json::Value) -> &str {
    v["permission"].as_str().unwrap_or("")
}

/// Read every `(session_id, host)` pair from the shared DB's `audit_log`.
///
/// Opens the on-disk `clx.db` read-only via `rusqlite` directly (the test
/// only needs the two columns, not the typed `Storage` API).
fn audit_session_hosts(home: &Path) -> Vec<(String, String)> {
    let db = home.join(".clx").join("data").join("clx.db");
    assert!(
        db.exists(),
        "hook runs must have created the shared DB at {}",
        db.display()
    );
    let conn = rusqlite::Connection::open(&db).expect("open shared clx.db");
    let mut stmt = conn
        .prepare("SELECT session_id, host FROM audit_log ORDER BY id ASC")
        .expect("prepare audit query");
    stmt.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })
    .expect("query audit_log")
    .filter_map(Result::ok)
    .collect()
}

/// The host recorded for a given session id (the destructive command is the
/// only audited write per session, so a session maps to exactly one host).
fn host_for_session(pairs: &[(String, String)], session: &str) -> String {
    let hosts: std::collections::BTreeSet<&str> = pairs
        .iter()
        .filter(|(s, _)| s == session)
        .map(|(_, h)| h.as_str())
        .collect();
    assert!(
        !hosts.is_empty(),
        "session {session} must have at least one audit row; got pairs: {pairs:?}"
    );
    assert_eq!(
        hosts.len(),
        1,
        "session {session} must map to exactly one host; got {hosts:?}"
    );
    (*hosts.iter().next().unwrap()).to_string()
}

#[test]
fn same_destructive_command_denied_under_all_hosts_and_audit_rows_carry_distinct_host() {
    // Shared HOME -> shared clx.db -> all three hosts' audit rows in one table.
    let home_guard = isolated_clx_home();
    let home = home_guard.path();
    let clx_dir = home.join(".clx");
    std::fs::create_dir_all(&clx_dir).expect("mk .clx");
    std::fs::write(clx_dir.join("config.yaml"), CONFIG_L0_ON_L1_OFF).expect("write config");

    let destructive = "rm -rf /";

    // --- Claude: PreToolUse, inline permissionDecision ---
    let claude_env = json!({
        "session_id": "xhost-claude",
        "cwd": "/tmp",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_use_id": "tu-claude",
        "tool_input": { "command": destructive }
    });
    let cv = run_in_home(home, "claude", &claude_env);
    assert_eq!(
        hso_decision(&cv),
        "deny",
        "Claude must deny `{destructive}`: {cv}"
    );

    // --- Codex: PreToolUse, inline permissionDecision ---
    let codex_env = json!({
        "session_id": "xhost-codex",
        "cwd": "/tmp",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "turn_id": "t1",
        "permission_mode": "default",
        "tool_input": { "command": destructive }
    });
    let xv = run_in_home(home, "codex", &codex_env);
    assert_eq!(
        hso_decision(&xv),
        "deny",
        "Codex must deny `{destructive}`: {xv}"
    );

    // --- Cursor: beforeShellExecution, flat permission ---
    let cursor_env = json!({
        "conversation_id": "xhost-cursor",
        "hook_event_name": "beforeShellExecution",
        "command": destructive,
        "workspace_roots": ["/tmp"]
    });
    let uv = run_in_home(home, "cursor", &cursor_env);
    assert_eq!(
        flat_permission(&uv),
        "deny",
        "Cursor must deny `{destructive}`: {uv}"
    );

    assert_home_size_bounded(home);

    // --- The D6 assertion: audit rows distinguish the three hosts ---
    let pairs = audit_session_hosts(home);
    assert!(
        !pairs.is_empty(),
        "the three deny decisions must have produced audit rows"
    );

    // Each session is attributed to the host that produced it.
    assert_eq!(
        host_for_session(&pairs, "xhost-claude"),
        "claude",
        "Claude session's audit rows must carry host='claude'"
    );
    assert_eq!(
        host_for_session(&pairs, "xhost-codex"),
        "codex",
        "Codex session's audit rows must carry host='codex'"
    );
    assert_eq!(
        host_for_session(&pairs, "xhost-cursor"),
        "cursor",
        "Cursor session's audit rows must carry host='cursor'"
    );

    // The three host values are distinct (the capability D6 intended).
    let distinct: std::collections::BTreeSet<&str> =
        pairs.iter().map(|(_, h)| h.as_str()).collect();
    assert_eq!(
        distinct,
        ["claude", "codex", "cursor"]
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>(),
        "the shared audit_log must contain exactly the three distinct host values; got {distinct:?}"
    );
}

/// Per-host PostToolUse coverage: an executed command persists a PostToolUse
/// audit row attributed to the originating host (the PostToolUse write path
/// is a separate `create_audit_log_with_host` call site from PreToolUse).
#[test]
fn post_tool_use_audit_row_carries_codex_host() {
    let home_guard = isolated_clx_home();
    let home = home_guard.path();
    let clx_dir = home.join(".clx");
    std::fs::create_dir_all(&clx_dir).expect("mk .clx");
    std::fs::write(clx_dir.join("config.yaml"), CONFIG_L0_ON_L1_OFF).expect("write config");

    // PostToolUse for an executed benign command -> one PostToolUse audit row.
    let env = json!({
        "session_id": "xhost-post-codex",
        "cwd": "/tmp",
        "hook_event_name": "PostToolUse",
        "tool_name": "Bash",
        "tool_use_id": "tu-post",
        "tool_input": { "command": "echo hello" },
        "tool_response": { "stdout": "hello\n" }
    });
    run_in_home_lifecycle(home, "codex", &env);
    assert_home_size_bounded(home);

    let pairs = audit_session_hosts(home);
    let host = host_for_session(&pairs, "xhost-post-codex");
    assert_eq!(
        host, "codex",
        "PostToolUse audit row must be attributed to the Codex host; got pairs {pairs:?}"
    );
}
