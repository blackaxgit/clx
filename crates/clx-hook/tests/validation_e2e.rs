//! End-to-end behavior tests for the validation pipeline through the real
//! `clx-hook` binary (Wave B / spec 01-validation.md).
//!
//! These drive the actual binary with `PreToolUse` JSON envelopes on stdin,
//! an isolated `HOME` (so the real `~/.clx` is never touched), and assert the
//! EMITTED Claude Code decision envelope -- not just an internal enum. Where a
//! behavior writes an audit row, we re-open the temp-home `SQLite` DB and assert
//! the persisted row (layer, decision, redacted command).
//!
//! No real LLM/network: L1 paths point Ollama at a dead local port so the
//! documented `default_decision` fallback fires deterministically.

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use clx_core::storage::Storage;

#[path = "support/mod.rs"]
mod support;
use support::{assert_home_size_bounded, harden_command, isolated_clx_home};

/// Spawn the binary with an isolated HOME and the given config.yaml body,
/// pipe `envelope` on stdin, and return `(parsed_output_json, home_dir)`.
/// The returned `tempfile::TempDir` must be kept alive by the caller.
fn run_with_config(
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
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("hook stdout must be valid JSON: {e}\nstdout: {stdout}"));
    (parsed, temp)
}

fn decision(v: &serde_json::Value) -> String {
    v["hookSpecificOutput"]["permissionDecision"]
        .as_str()
        .unwrap_or("")
        .to_string()
}

fn pre_tool_use(session: &str, command: &str) -> serde_json::Value {
    serde_json::json!({
        "session_id": session,
        "cwd": "/tmp",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_use_id": format!("tu-{session}"),
        "tool_input": { "command": command }
    })
}

/// Re-open the temp-home audit DB and return rows for a session.
fn audit_rows(home: &Path, session: &str) -> Vec<clx_core::types::AuditLogEntry> {
    let db = home.join(".clx/data/clx.db");
    if !db.exists() {
        return Vec::new();
    }
    let st = Storage::open(&db).expect("open audit db");
    st.get_audit_log_by_session(session).expect("query audit")
}

// =========================================================================
// 3.1 validator.enabled: false -> full bypass (allow, no audit row).
// =========================================================================

#[test]
fn enabled_false_bypasses_pipeline_no_audit() {
    let cfg = "validator:\n  enabled: false\n";
    let env = pre_tool_use("e2e-bypass", "rm -rf /");
    let (out, home) = run_with_config(cfg, &env);
    assert_eq!(
        decision(&out),
        "allow",
        "validator.enabled=false must allow even `rm -rf /`"
    );
    let rows = audit_rows(home.path(), "e2e-bypass");
    assert!(
        rows.is_empty(),
        "bypass must write NO audit row, found: {rows:?}"
    );
}

/// Same dangerous command WITH the validator enabled -> blocked at L0 and an
/// `L0`/`blocked` audit row exists (the contrast that proves bypass is real).
#[test]
fn enabled_true_blocks_and_audits_l0() {
    let cfg = "validator:\n  enabled: true\n  layer1_enabled: false\n";
    let env = pre_tool_use("e2e-l0deny", "rm -rf /");
    let (out, home) = run_with_config(cfg, &env);
    assert_eq!(decision(&out), "deny", "L0 blacklist must deny `rm -rf /`");
    let rows = audit_rows(home.path(), "e2e-l0deny");
    assert_eq!(rows.len(), 1, "exactly one audit row expected");
    assert_eq!(rows[0].layer, "L0");
    assert_eq!(rows[0].decision.as_str(), "blocked");
}

// =========================================================================
// Edge: empty command short-circuits to allow BEFORE the enabled check.
// =========================================================================

#[test]
fn empty_command_allows_with_no_audit() {
    // enabled:false would also allow; use enabled:true so we prove the
    // empty-command short-circuit specifically (it runs before the check).
    let cfg = "validator:\n  enabled: true\n";
    let env = pre_tool_use("e2e-empty", "");
    let (out, home) = run_with_config(cfg, &env);
    assert_eq!(decision(&out), "allow");
    assert!(
        audit_rows(home.path(), "e2e-empty").is_empty(),
        "empty command must not be audited"
    );
}

// =========================================================================
// Edge: non-Bash, non-MCP tool auto-allows with no audit.
// =========================================================================

#[test]
fn non_bash_tool_auto_allows() {
    let cfg = "validator:\n  enabled: true\n";
    let env = serde_json::json!({
        "session_id": "e2e-read",
        "cwd": "/tmp",
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_use_id": "tu-read",
        "tool_input": { "file_path": "/etc/passwd" }
    });
    let (out, home) = run_with_config(cfg, &env);
    assert_eq!(decision(&out), "allow", "Read tool must auto-allow");
    assert!(audit_rows(home.path(), "e2e-read").is_empty());
}

// =========================================================================
// 3.2 L0 hard-allow + L0-READ auto-allow.
// =========================================================================

#[test]
fn l0_hard_allow_whitelisted_command_emits_allow() {
    let cfg = "validator:\n  enabled: true\n  layer1_enabled: false\n";
    let env = pre_tool_use("e2e-l0allow", "git status");
    let (out, home) = run_with_config(cfg, &env);
    assert_eq!(decision(&out), "allow");
    let rows = audit_rows(home.path(), "e2e-l0allow");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].layer, "L0");
    assert_eq!(rows[0].decision.as_str(), "allowed");
}

/// An unknown READ-only command is auto-allowed at L0-READ (not escalated),
/// when `auto_allow_reads` is on (default).
#[test]
fn l0_read_unknown_readonly_auto_allows() {
    let cfg = "validator:\n  enabled: true\n  layer1_enabled: false\n  auto_allow_reads: true\n";
    // `du` is read-only (read_only.rs list) but is NOT in the L0 whitelist,
    // so L0 escalates to Ask and the read-only fast lane (L0-READ) kicks in.
    let env = pre_tool_use("e2e-l0read", "du -sh /var/log");
    let (out, home) = run_with_config(cfg, &env);
    assert_eq!(decision(&out), "allow");
    let rows = audit_rows(home.path(), "e2e-l0read");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].layer, "L0-READ", "expected the read-only fast lane");
    assert_eq!(rows[0].decision.as_str(), "allowed");
}

// =========================================================================
// 3.3 L1 disabled -> ask "Command requires review", audit L0/prompted,
//      and NOT cached.
// =========================================================================

#[test]
fn l1_disabled_unknown_command_asks_and_not_cached() {
    let cfg = "validator:\n  enabled: true\n  layer1_enabled: false\n  auto_allow_reads: false\n";
    let env = pre_tool_use("e2e-l1off", "mycustomtool --apply");
    let (out, home) = run_with_config(cfg, &env);
    assert_eq!(decision(&out), "ask");
    assert_eq!(
        out["hookSpecificOutput"]["permissionDecisionReason"],
        "Command requires review"
    );
    let rows = audit_rows(home.path(), "e2e-l1off");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].layer, "L0");
    assert_eq!(rows[0].decision.as_str(), "prompted");
    assert_eq!(rows[0].reasoning.as_deref(), Some("L1 disabled"));

    // The L1-disabled branch must NOT write a decision-cache row.
    let db = home.path().join(".clx/data/clx.db");
    let st = Storage::open(&db).expect("open db");
    let n: i64 = st
        .connection()
        .query_row("SELECT COUNT(*) FROM validation_cache", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n, 0, "L1-disabled ask must not be cached");
}

// =========================================================================
// 3.4 default_decision on L1 provider-down (Ollama unreachable).
// =========================================================================

fn ollama_down_cfg(default_decision: &str) -> String {
    format!(
        "validator:\n  enabled: true\n  layer1_enabled: true\n  \
         default_decision: {default_decision}\n  auto_allow_reads: false\n  \
         cache_enabled: false\nollama:\n  host: \"http://127.0.0.1:9\"\n  \
         timeout_ms: 800\n  max_retries: 0\n"
    )
}

#[test]
fn l1_provider_down_default_decision_deny_emits_block() {
    let env = pre_tool_use("e2e-ddeny", "frobnicate --x");
    let (out, home) = run_with_config(&ollama_down_cfg("deny"), &env);
    assert_eq!(
        decision(&out),
        "deny",
        "default_decision=deny must emit a block when Ollama is down"
    );
    let rows = audit_rows(home.path(), "e2e-ddeny");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].layer, "L1");
    assert_eq!(rows[0].decision.as_str(), "blocked");
}

#[test]
fn l1_provider_down_default_decision_allow_emits_allow() {
    let env = pre_tool_use("e2e-dallow", "frobnicate --x");
    let (out, home) = run_with_config(&ollama_down_cfg("allow"), &env);
    assert_eq!(decision(&out), "allow");
    let rows = audit_rows(home.path(), "e2e-dallow");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].layer, "L1");
    assert_eq!(rows[0].decision.as_str(), "allowed");
}

#[test]
fn l1_provider_down_default_decision_ask_emits_ask() {
    let env = pre_tool_use("e2e-dask", "frobnicate --x");
    let (out, home) = run_with_config(&ollama_down_cfg("ask"), &env);
    assert_eq!(decision(&out), "ask");
    let rows = audit_rows(home.path(), "e2e-dask");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].layer, "L1");
    assert_eq!(rows[0].decision.as_str(), "prompted");
}

// =========================================================================
// 3.6 decision cache hit: a pre-seeded cache row short-circuits to L1-CACHE.
// =========================================================================

#[test]
fn decision_cache_hit_short_circuits_to_l1_cache() {
    let binary = env!("CARGO_BIN_EXE_clx-hook");
    let temp = isolated_clx_home();
    let clx_dir = temp.path().join(".clx");
    std::fs::create_dir_all(clx_dir.join("data")).expect("mk data");
    std::fs::write(
        clx_dir.join("config.yaml"),
        "validator:\n  enabled: true\n  layer1_enabled: true\n  \
         cache_enabled: true\n  auto_allow_reads: false\n",
    )
    .unwrap();

    // Pre-seed the SQLite decision cache with an ALLOW for this command+cwd
    // so the hook never needs to reach an LLM.
    let command = "cachedtool --go";
    let cwd = "/tmp";
    {
        let st = Storage::open(clx_dir.join("data/clx.db")).expect("open db");
        let key = clx_core::policy::compute_cache_key(command, cwd);
        st.cache_decision(&key, "allow", None, Some(1), 3600)
            .unwrap();
    }

    let env = pre_tool_use("e2e-cache", command);
    let mut command = Command::new(binary);
    let mut child = harden_command(&mut command, temp.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(env.to_string().as_bytes())
        .unwrap();
    let out = child.wait_with_output().expect("wait");
    assert_home_size_bounded(temp.path());
    let parsed: serde_json::Value =
        serde_json::from_str(String::from_utf8_lossy(&out.stdout).trim()).expect("json");
    assert_eq!(
        decision(&parsed),
        "allow",
        "a cached allow must short-circuit before any LLM call"
    );
    let rows = audit_rows(temp.path(), "e2e-cache");
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0].layer, "L1-CACHE",
        "cache hit must audit as L1-CACHE"
    );
    assert_eq!(rows[0].decision.as_str(), "allowed");
}

// =========================================================================
// 3.9 trust mode: valid legacy token auto-allows + TRUST audit row.
// =========================================================================

#[test]
fn trust_mode_valid_legacy_token_auto_allows_with_trust_audit() {
    let cfg = "validator:\n  enabled: true\n  trust_mode: true\n  layer1_enabled: false\n";
    let binary = env!("CARGO_BIN_EXE_clx-hook");
    let temp = isolated_clx_home();
    let clx_dir = temp.path().join(".clx");
    std::fs::create_dir_all(&clx_dir).unwrap();
    std::fs::write(clx_dir.join("config.yaml"), cfg).unwrap();
    // Fresh legacy plain-text token (mtime = now -> valid < 3600s).
    std::fs::write(clx_dir.join(".trust_mode_token"), "trust_mode_active").unwrap();

    let env = pre_tool_use("e2e-trust", "rm -rf /tmp/whatever");
    let mut command = Command::new(binary);
    let mut child = harden_command(&mut command, temp.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(env.to_string().as_bytes())
        .unwrap();
    let out = child.wait_with_output().expect("wait");
    assert_home_size_bounded(temp.path());
    let parsed: serde_json::Value =
        serde_json::from_str(String::from_utf8_lossy(&out.stdout).trim()).expect("json");
    assert_eq!(
        decision(&parsed),
        "allow",
        "trust mode must auto-allow even a normally-L0-denied command"
    );
    let rows = audit_rows(temp.path(), "e2e-trust");
    assert_eq!(rows.len(), 1, "trust-allowed commands are still audited");
    assert_eq!(rows[0].layer, "TRUST");
    assert_eq!(rows[0].decision.as_str(), "allowed");
}

/// V-R9 (pinned): an EXPIRED legacy token (mtime > 3600s) is rejected; the
/// token file is deleted and the hook falls through to normal validation
/// (here L0 denies the dangerous command). Pins the documented fall-through.
#[test]
fn v_r9_expired_legacy_token_falls_through_and_is_deleted() {
    let cfg = "validator:\n  enabled: true\n  trust_mode: true\n  layer1_enabled: false\n";
    let binary = env!("CARGO_BIN_EXE_clx-hook");
    let temp = isolated_clx_home();
    let clx_dir = temp.path().join(".clx");
    std::fs::create_dir_all(&clx_dir).unwrap();
    std::fs::write(clx_dir.join("config.yaml"), cfg).unwrap();
    let token = clx_dir.join(".trust_mode_token");
    std::fs::write(&token, "trust_mode_active").unwrap();
    // Backdate mtime to 2h ago -> legacy token is stale (>3600s).
    let two_h_ago = std::time::SystemTime::now() - std::time::Duration::from_hours(2);
    let times = std::fs::FileTimes::new()
        .set_modified(two_h_ago)
        .set_accessed(two_h_ago);
    std::fs::File::options()
        .write(true)
        .open(&token)
        .unwrap()
        .set_times(times)
        .unwrap();

    let env = pre_tool_use("e2e-trustx", "rm -rf /");
    let mut command = Command::new(binary);
    let mut child = harden_command(&mut command, temp.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(env.to_string().as_bytes())
        .unwrap();
    let out = child.wait_with_output().expect("wait");
    assert_home_size_bounded(temp.path());
    let parsed: serde_json::Value =
        serde_json::from_str(String::from_utf8_lossy(&out.stdout).trim()).expect("json");
    assert_eq!(
        decision(&parsed),
        "deny",
        "expired trust token must fall through to L0 (which denies `rm -rf /`)"
    );
    assert!(
        !token.exists(),
        "V-R9: an expired legacy token must be deleted after detection"
    );
}

// =========================================================================
// 3.11 audit redaction guarantee end-to-end: a secret-bearing command is
//      redacted in the persisted audit row (V-R7 known-pattern case).
// =========================================================================

#[test]
fn audit_redacts_secret_in_persisted_command() {
    let cfg = "validator:\n  enabled: true\n  layer1_enabled: false\n  auto_allow_reads: false\n";
    // Unknown, non-read-only command carrying a known-prefix secret. L1 is
    // disabled so it audits at L0/prompted -- the row we then inspect.
    let secret = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef0123456789";
    let env = pre_tool_use("e2e-redact", &format!("deploytool --token={secret}"));
    let (out, home) = run_with_config(cfg, &env);
    assert_eq!(decision(&out), "ask");
    let rows = audit_rows(home.path(), "e2e-redact");
    assert_eq!(rows.len(), 1);
    assert!(
        !rows[0].command.contains(secret),
        "raw secret must NEVER reach audit_log.command, got: {}",
        rows[0].command
    );
    assert!(
        rows[0].command.contains("ghp_***REDACTED***"),
        "expected redacted marker, got: {}",
        rows[0].command
    );
}

// =========================================================================
// Edge: MCP non-command tool uses mcp_tools.default_decision, no audit.
// =========================================================================

#[test]
fn mcp_non_command_tool_uses_mcp_default_decision() {
    let cfg = "validator:\n  enabled: true\nmcp_tools:\n  enabled: true\n  \
               default_decision: deny\n";
    let env = serde_json::json!({
        "session_id": "e2e-mcp",
        "cwd": "/tmp",
        "hook_event_name": "PreToolUse",
        "tool_name": "mcp__context7__resolve-library-id",
        "tool_use_id": "tu-mcp",
        "tool_input": { "libraryName": "react" }
    });
    let (out, home) = run_with_config(cfg, &env);
    assert_eq!(
        decision(&out),
        "deny",
        "a non-command MCP tool must use mcp_tools.default_decision"
    );
    assert!(
        audit_rows(home.path(), "e2e-mcp").is_empty(),
        "non-command MCP routing must not write an audit row"
    );
}

// =========================================================================
// Edge: malformed config swallowed (V-R8) -> binary still emits a decision.
// =========================================================================

/// V-R8 (pinned end-to-end): a malformed config.yaml does NOT crash the hook;
/// `unwrap_or_default()` silently reverts to defaults and a decision is still
/// emitted (defaults => validator enabled => `rm -rf /` denied at L0).
#[test]
fn v_r8_malformed_config_still_emits_decision() {
    let cfg = "validator: : : not yaml [[[ totally broken";
    let env = pre_tool_use("e2e-badcfg", "rm -rf /");
    let (out, _home) = run_with_config(cfg, &env);
    let d = decision(&out);
    assert_eq!(
        d, "deny",
        "V-R8: malformed config silently reverts to defaults (validator \
         enabled) so L0 still denies; no user-visible config error surfaces"
    );
}
