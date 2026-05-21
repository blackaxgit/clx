//! End-to-end behavior tests for the `validator.layer0_enabled` toggle
//! (v0.9.0 Stream P1).
//!
//! Mirrors `pre_tool_use_l1_e2e.rs` structure: drives the **real `clx-hook`
//! binary** with a `config.yaml` written into an isolated `HOME`, pipes a
//! `PreToolUse` envelope on stdin, and asserts the observable output decision
//! envelope plus audit-DB side effects.
//!
//! Hermetic: no real network beyond loopback wiremock,
//! `CLX_MODEL_FETCH_DRYRUN=1`, `CLX_CREDENTIALS_BACKEND=age`.
//! No `#[ignore]`, no mock introspection — behaviour contracts only.
//!
//! ## Test cases
//!
//! 1. L0 disabled, L1 enabled → LLM evaluates; verdict drives output.
//!    A deterministic-blacklist command (`rm -rf /`) is no longer denied at L0.
//! 2. L0 disabled, L1 disabled → forced "ask" (fail-to-defined-policy).
//! 3. L0 enabled (default), L1 enabled → existing L0-deterministic behaviour
//!    unchanged (regression guard).
//! 4. Env override `CLX_VALIDATOR_LAYER0_ENABLED=false` emits WARN + is
//!    reported by `security_env_overrides_active()`.
//! 5. Config-driven `validator.layer0_enabled: false` triggers the SECURITY-CFG
//!    audit-chain fingerprint (locked decision §4 of the plan).

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use clx_core::storage::Storage;
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[path = "support/mod.rs"]
mod support;
use support::{assert_home_size_bounded, harden_command, isolated_clx_home};

// =========================================================================
// Harness helpers (mirror pre_tool_use_l1_e2e.rs)
// =========================================================================

/// Spawn the real `clx-hook` binary with an isolated `HOME` + the given
/// `config.yaml`, pipe `envelope` on stdin, return the parsed decision JSON
/// plus the live `TempDir` (kept alive so audit-DB assertions can re-open it).
fn run(config_yaml: &str, envelope: &serde_json::Value) -> (serde_json::Value, tempfile::TempDir) {
    run_with_extra_env(config_yaml, envelope, &[])
}

fn run_with_extra_env(
    config_yaml: &str,
    envelope: &serde_json::Value,
    extra_env: &[(&str, &str)],
) -> (serde_json::Value, tempfile::TempDir) {
    let binary = env!("CARGO_BIN_EXE_clx-hook");
    let temp = isolated_clx_home();
    let clx_dir = temp.path().join(".clx");
    std::fs::create_dir_all(&clx_dir).expect("mk .clx");
    std::fs::write(clx_dir.join("config.yaml"), config_yaml).expect("write config");

    let mut command = Command::new(binary);
    let mut cmd = harden_command(&mut command, temp.path())
        .env("CLX_CREDENTIALS_BACKEND", "age")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    for (k, v) in extra_env {
        cmd = cmd.env(k, v);
    }

    let mut child = cmd.spawn().expect("spawn clx-hook");

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

fn decision(v: &serde_json::Value) -> &str {
    v["hookSpecificOutput"]["permissionDecision"]
        .as_str()
        .unwrap_or("")
}

fn pre_tool_use(session: &str, command: &str) -> serde_json::Value {
    json!({
        "session_id": session,
        "cwd": "/tmp",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_use_id": format!("tu-{session}"),
        "tool_input": { "command": command }
    })
}

fn audit_rows(home: &Path, session: &str) -> Vec<clx_core::types::AuditLogEntry> {
    let db = home.join(".clx/data/clx.db");
    if !db.exists() {
        return Vec::new();
    }
    let st = Storage::open(&db).expect("open audit db");
    st.get_audit_log_by_session(session).expect("query audit")
}

#[allow(dead_code)]
fn db(home: &Path) -> Storage {
    Storage::open(home.join(".clx/data/clx.db")).expect("open sandbox db")
}

/// A config whose legacy `ollama:` block points L1's chat client at `uri`.
/// Layer0 and layer1 enabled flags are set via the `validator_extra` parameter.
fn cfg_pointing_at(uri: &str, validator_extra: &str) -> String {
    format!(
        "validator:\n  \
           enabled: true\n  \
           cache_enabled: false\n{validator_extra}\
         ollama:\n  \
           host: \"{uri}\"\n  \
           model: \"test-model\"\n  \
           max_retries: 0\n"
    )
}

/// Mount `POST /api/generate` returning `verdict_json` as Ollama `response`.
async fn mount_generate(server: &MockServer, verdict_json: &str) {
    Mock::given(method("POST"))
        .and(path("/api/generate"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(
            json!({ "response": verdict_json, "done": true }).to_string(),
            "application/json",
        ))
        .mount(server)
        .await;
}

/// Mount `GET /api/tags` so the health probe returns available.
async fn mount_health_up(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/api/tags"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_raw(json!({ "models": [] }).to_string(), "application/json"),
        )
        .mount(server)
        .await;
}

// A command that L0 deterministic rules classify as Deny (blacklisted):
// used to prove the blacklist is bypassed when L0 is disabled.
const BLACKLIST_CMD: &str = "rm -rf /";

// A command L0 returns Ask for (not on any list) — falls through to L1.
const ASK_CMD: &str = "frobnicate --apply";

// =========================================================================
// Test 1: L0 disabled, L1 enabled — LLM verdict drives output.
// A deterministic-blacklist command is no longer denied at L0.
// =========================================================================

/// When `layer0_enabled: false` and L1 is enabled, even a command that is on
/// the L0 deterministic blacklist (`rm -rf /`) is NOT denied at L0 — it falls
/// through to L1, and the LLM verdict (allow here) determines the outcome.
/// This confirms the security weakening is intentional and observable.
#[tokio::test]
async fn l0_disabled_blacklisted_command_falls_through_to_l1_allow() {
    let server = MockServer::start().await;
    mount_health_up(&server).await;
    // L1 says allow (low risk) — proves the LLM drove the decision, not L0.
    mount_generate(
        &server,
        r#"{"risk_score":1,"reasoning":"test context: safe","category":"safe"}"#,
    )
    .await;

    let cfg = cfg_pointing_at(
        &server.uri(),
        "  layer0_enabled: false\n  layer1_enabled: true\n",
    );
    let env = pre_tool_use("e2e-l0off-bl-allow", BLACKLIST_CMD);
    let (out, home) = run(&cfg, &env);

    // L0 deterministic deny is bypassed; LLM allow drives the decision.
    assert_eq!(
        decision(&out),
        "allow",
        "L0 disabled: blacklisted command must NOT be denied at L0; \
         LLM verdict (allow) must drive the output"
    );

    // Audit trail: an L0/prompted row for L0-DISABLED, then an L1/allowed row.
    let rows = audit_rows(home.path(), "e2e-l0off-bl-allow");
    // Filter to command rows (exclude SECURITY-CFG meta row).
    let cmd_rows: Vec<_> = rows.iter().filter(|r| r.command == BLACKLIST_CMD).collect();
    assert!(
        !cmd_rows.is_empty(),
        "must have at least one audit row for the command; rows: {rows:?}"
    );
    // The L0-DISABLED row must be present (L0 skip was recorded).
    assert!(
        cmd_rows
            .iter()
            .any(|r| r.layer == "L0" && r.reasoning.as_deref() == Some("L0-DISABLED")),
        "must have an L0/prompted row with reasoning L0-DISABLED; cmd_rows: {cmd_rows:?}"
    );
    // The final audit row for the command must be L1/allowed.
    assert!(
        cmd_rows
            .iter()
            .any(|r| r.layer == "L1" && r.decision.as_str() == "allowed"),
        "must have an L1/allowed audit row; cmd_rows: {cmd_rows:?}"
    );
}

/// When `layer0_enabled: false` and L1 is enabled, an L1 Deny verdict
/// (high risk score) still produces a deny — the LLM (not L0) decides.
#[tokio::test]
async fn l0_disabled_l1_deny_emits_block() {
    let server = MockServer::start().await;
    mount_health_up(&server).await;
    mount_generate(
        &server,
        r#"{"risk_score":9,"reasoning":"irreversible","category":"critical"}"#,
    )
    .await;

    let cfg = cfg_pointing_at(
        &server.uri(),
        "  layer0_enabled: false\n  layer1_enabled: true\n",
    );
    let env = pre_tool_use("e2e-l0off-l1deny", ASK_CMD);
    let (out, home) = run(&cfg, &env);

    assert_eq!(
        decision(&out),
        "deny",
        "L0 disabled + L1 deny: output must be deny (LLM verdict)"
    );

    let rows = audit_rows(home.path(), "e2e-l0off-l1deny");
    let cmd_rows: Vec<_> = rows.iter().filter(|r| r.command == ASK_CMD).collect();
    assert!(
        cmd_rows
            .iter()
            .any(|r| r.layer == "L1" && r.decision.as_str() == "blocked"),
        "must have L1/blocked row; cmd_rows: {cmd_rows:?}"
    );
}

// =========================================================================
// Test 2: L0 disabled, L1 disabled — forced "ask" (both-off posture).
// =========================================================================

/// When both `layer0_enabled: false` AND `layer1_enabled: false`, the hook
/// must force the decision to "ask" regardless of `default_decision`.
/// This is the fail-to-defined-policy posture (research item 4, plan §C).
#[tokio::test]
async fn l0_and_l1_disabled_forces_ask() {
    let server = MockServer::start().await;
    // No mocks needed — neither L0 nor L1 runs. The server is started to
    // provide a valid URI for the config; no requests should reach it.

    // default_decision: allow to prove it is NOT honored when both layers off.
    let cfg = cfg_pointing_at(
        &server.uri(),
        "  layer0_enabled: false\n  layer1_enabled: false\n  default_decision: \"allow\"\n",
    );
    let env = pre_tool_use("e2e-both-off", ASK_CMD);
    let (out, home) = run(&cfg, &env);

    assert_eq!(
        decision(&out),
        "ask",
        "both L0 and L1 disabled: must force ask (fail-to-defined-policy), \
         not honor default_decision=allow"
    );

    // Audit trail must contain the L0-DISABLED row, then the L1-DISABLED row.
    let rows = audit_rows(home.path(), "e2e-both-off");
    let cmd_rows: Vec<_> = rows.iter().filter(|r| r.command == ASK_CMD).collect();
    assert!(
        cmd_rows
            .iter()
            .any(|r| r.layer == "L0" && r.reasoning.as_deref() == Some("L0-DISABLED")),
        "must have L0/L0-DISABLED row; cmd_rows: {cmd_rows:?}"
    );
    // v0.9.0 dual-emit window: the L1-DISABLED reasoning carries BOTH the
    // canonical "L1-DISABLED" and the legacy "L1 disabled" alias as
    // substrings so v0.8.x log parsers keep working through v0.9.0. v0.10.0
    // plan: drop the legacy alias. See `specs/2026-05-20-v090-red-findings.md`
    // (T9.5 / L1-rename deprecation hygiene).
    assert!(
        cmd_rows.iter().any(
            |r| r.layer == "L0" && r.reasoning.as_deref().unwrap_or("").contains("L1-DISABLED")
        ),
        "must have L0/L1-DISABLED row (forced ask audit); cmd_rows: {cmd_rows:?}"
    );
}

// =========================================================================
// Test 3: L0 enabled (default), L1 enabled — regression guard.
// L0 deterministic deny is still enforced when layer0_enabled is true.
// =========================================================================

/// Regression guard: when L0 is enabled (default), a deterministic-blacklist
/// command is still denied at L0 without reaching L1 at all.
#[tokio::test]
async fn l0_enabled_default_blacklist_still_denied_at_l0() {
    let server = MockServer::start().await;
    // Mount health and a permissive L1 verdict — proving L1 is NOT reached.
    mount_health_up(&server).await;
    mount_generate(
        &server,
        r#"{"risk_score":1,"reasoning":"would allow if reached","category":"safe"}"#,
    )
    .await;

    // layer0_enabled omitted → defaults to true.
    let cfg = cfg_pointing_at(&server.uri(), "  layer1_enabled: true\n");
    let env = pre_tool_use("e2e-l0on-bl", BLACKLIST_CMD);
    let (out, home) = run(&cfg, &env);

    assert_eq!(
        decision(&out),
        "deny",
        "L0 enabled (default): blacklisted command must be denied at L0 \
         even though L1 verdict would be allow"
    );

    let rows = audit_rows(home.path(), "e2e-l0on-bl");
    let cmd_rows: Vec<_> = rows.iter().filter(|r| r.command == BLACKLIST_CMD).collect();
    assert!(
        cmd_rows
            .iter()
            .any(|r| r.layer == "L0" && r.decision.as_str() == "blocked"),
        "must have L0/blocked row; cmd_rows: {cmd_rows:?}"
    );
    // L1 must NOT have been reached (no L1 row).
    assert!(
        !cmd_rows.iter().any(|r| r.layer == "L1"),
        "L1 must not be reached when L0 blocks; cmd_rows: {cmd_rows:?}"
    );
}

// =========================================================================
// Test 4: Env override CLX_VALIDATOR_LAYER0_ENABLED=false
// — WARN emitted + security_env_overrides_active() reports it.
// =========================================================================

/// When `CLX_VALIDATOR_LAYER0_ENABLED=false` is set as an env var, the hook
/// must emit a SECURITY-ENV audit row (the env-override audit-chain path).
/// We verify this by inspecting the audit DB for a SECURITY-ENV layer row.
#[tokio::test]
async fn env_override_layer0_disabled_emits_security_env_audit_row() {
    let server = MockServer::start().await;
    mount_health_up(&server).await;
    // L1 returns allow so the hook completes without blocking.
    mount_generate(
        &server,
        r#"{"risk_score":1,"reasoning":"benign","category":"safe"}"#,
    )
    .await;

    // Config has layer0_enabled: true — the env var overrides it to false.
    let cfg = cfg_pointing_at(
        &server.uri(),
        "  layer0_enabled: true\n  layer1_enabled: true\n",
    );
    let env = pre_tool_use("e2e-env-l0off", ASK_CMD);
    let (out, home) = run_with_extra_env(&cfg, &env, &[("CLX_VALIDATOR_LAYER0_ENABLED", "false")]);

    // The hook must still return a valid decision (L0 disabled → L1 runs).
    assert!(
        matches!(decision(&out), "allow" | "ask" | "deny"),
        "hook must return a valid decision; got: {out}"
    );

    // The env-override audit path must have emitted a SECURITY-ENV row.
    let rows = audit_rows(home.path(), "e2e-env-l0off");
    assert!(
        rows.iter().any(|r| r.layer == "SECURITY-ENV"),
        "CLX_VALIDATOR_LAYER0_ENABLED=false env override must emit a \
         SECURITY-ENV audit row; rows: {rows:?}"
    );

    // The behavioural contract that `security_env_overrides_active()`
    // reports `CLX_VALIDATOR_LAYER0_ENABLED=false` is covered by the
    // SECURITY-ENV audit-row assertion above — the hook subprocess sets
    // the env on its own command line via `harden_command`, exercises
    // the same accessor in-process, and writes the audit row that this
    // test reads. Mutating the parent test process's env here would
    // require `unsafe`, which the workspace forbids (`unsafe_code = "deny"`),
    // and would race other parallel tests. A direct-API unit test for
    // the accessor lives in `crates/clx-core/src/config/mod.rs` under
    // `b5_4_*` where the existing serial-test pattern handles env
    // mutation safely.
}

// =========================================================================
// Test 5: Config-driven layer0_enabled: false triggers SECURITY-CFG
// audit-chain fingerprint (locked decision §4).
// =========================================================================

/// When `validator.layer0_enabled: false` is set in config (not via env),
/// the hook must emit a SECURITY-CFG audit row containing the trigger key
/// `validator.layer0_enabled=false` with a SHA-256 event fingerprint.
/// This is the config-driven audit-chain extension (plan decision §4).
#[tokio::test]
async fn config_driven_layer0_disabled_emits_security_cfg_audit_row() {
    let server = MockServer::start().await;
    mount_health_up(&server).await;
    mount_generate(
        &server,
        r#"{"risk_score":1,"reasoning":"benign","category":"safe"}"#,
    )
    .await;

    // Config disables L0 — no env var involved.
    let cfg = cfg_pointing_at(
        &server.uri(),
        "  layer0_enabled: false\n  layer1_enabled: true\n",
    );
    let env = pre_tool_use("e2e-cfg-l0off", ASK_CMD);
    let (out, home) = run(&cfg, &env);

    assert!(
        matches!(decision(&out), "allow" | "ask" | "deny"),
        "hook must return a valid decision; got: {out}"
    );

    // The config-driven audit-chain path must have emitted a SECURITY-CFG row.
    let rows = audit_rows(home.path(), "e2e-cfg-l0off");
    let sec_cfg_rows: Vec<_> = rows.iter().filter(|r| r.layer == "SECURITY-CFG").collect();
    assert!(
        !sec_cfg_rows.is_empty(),
        "config-driven layer0_enabled=false must emit a SECURITY-CFG audit row; \
         rows: {rows:?}"
    );

    // The trigger key string must name the config path explicitly.
    assert!(
        sec_cfg_rows.iter().any(|r| r
            .reasoning
            .as_deref()
            .unwrap_or("")
            .contains("validator.layer0_enabled=false")),
        "SECURITY-CFG reasoning must contain 'validator.layer0_enabled=false'; \
         sec_cfg_rows: {sec_cfg_rows:?}"
    );

    // The reasoning must also contain an event_fingerprint (SHA-256 hex, 64 chars).
    assert!(
        sec_cfg_rows.iter().any(|r| {
            let reasoning = r.reasoning.as_deref().unwrap_or("");
            reasoning.contains("event_fingerprint=")
        }),
        "SECURITY-CFG reasoning must contain an event_fingerprint field; \
         sec_cfg_rows: {sec_cfg_rows:?}"
    );
}

/// When `validator.layer1_enabled: false` is set in config (not via env),
/// the hook must also emit a SECURITY-CFG audit row for layer1 disable —
/// the config-driven path covers both layers symmetrically.
#[tokio::test]
async fn config_driven_layer1_disabled_emits_security_cfg_audit_row() {
    // No wiremock needed — L1 is disabled, no provider call.
    let cfg = "validator:\n  \
                 enabled: true\n  \
                 layer0_enabled: true\n  \
                 layer1_enabled: false\n  \
                 cache_enabled: false\n";
    let env = pre_tool_use("e2e-cfg-l1off", ASK_CMD);
    let (out, home) = run(cfg, &env);

    // L1 disabled + L0 Ask → forced ask.
    assert_eq!(
        decision(&out),
        "ask",
        "L1 disabled in config: must force ask"
    );

    let rows = audit_rows(home.path(), "e2e-cfg-l1off");
    let sec_cfg_rows: Vec<_> = rows.iter().filter(|r| r.layer == "SECURITY-CFG").collect();
    assert!(
        !sec_cfg_rows.is_empty(),
        "config-driven layer1_enabled=false must emit a SECURITY-CFG audit row; \
         rows: {rows:?}"
    );
    assert!(
        sec_cfg_rows.iter().any(|r| r
            .reasoning
            .as_deref()
            .unwrap_or("")
            .contains("validator.layer1_enabled=false")),
        "SECURITY-CFG reasoning must contain 'validator.layer1_enabled=false'; \
         sec_cfg_rows: {sec_cfg_rows:?}"
    );
}
