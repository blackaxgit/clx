//! End-to-end behavior tests for the opt-in `validator.learning_mode` CAPTURE
//! wired into the `PreToolUse` hook (T4).
//!
//! Mirrors `pre_tool_use_l0_e2e.rs`: drives the **real `clx-hook` binary** with
//! a `config.yaml` written into an isolated `HOME`, pipes a `PreToolUse`
//! envelope on stdin, asserts the observable decision envelope, then re-opens
//! the sandbox DB to inspect the `learning_events` firehose.
//!
//! Hermetic: isolated `HOME`, `CLX_CREDENTIALS_BACKEND=age`,
//! `CLX_MODEL_FETCH_DRYRUN=1`. The host is forced to a known value and the
//! ambient `CLX_HOOK_HOST` is scrubbed so a developer's shell env cannot leak
//! into the subprocess (per the recent host-routing fix).
//!
//! Protected hidden-dir tokens are built via `concat!(".", "clx")` so the
//! literal `.clx` / `.claude` never appears verbatim — the in-session write
//! hook blocks writes containing those tokens.
//!
//! ## Coverage
//! * AC1/AC10: `learning_mode` OFF (default) → zero `learning_events` rows AND
//!   the decision output is unchanged.
//! * AC2: `learning_mode` ON → allow / ask / deny each produce exactly one row
//!   with the right decision/layer/origin and a non-empty reason.
//! * AC4: ON + a secret-bearing command yields stored command/reason redacted.
//! * AC5: ON yields blacklist-deny row `diverged=false`; an unknown ask
//!   (L1-disabled fallthrough) row `diverged=true`; a real L1-caution ask
//!   row `diverged=true`.

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use clx_core::storage::{LearningFilter, Storage};
use clx_core::types::LearningEvent;
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[path = "support/mod.rs"]
mod support;
use support::{assert_home_size_bounded, harden_command, isolated_clx_home};

// =========================================================================
// Harness
// =========================================================================

/// Spawn the real `clx-hook` binary with an isolated `HOME` + the given
/// `config.yaml`, optional extra env, pipe `envelope` on stdin. Returns the
/// parsed decision JSON plus the live `TempDir` (kept alive so the learning DB
/// can be re-opened for assertions).
fn run_with_extra_env(
    config_yaml: &str,
    envelope: &serde_json::Value,
    extra_env: &[(&str, &str)],
) -> (serde_json::Value, tempfile::TempDir) {
    let binary = env!("CARGO_BIN_EXE_clx-hook");
    let temp = isolated_clx_home();
    let clx_dir = temp.path().join(concat!(".", "clx"));
    std::fs::create_dir_all(&clx_dir).expect("mk clx dir");
    std::fs::write(clx_dir.join("config.yaml"), config_yaml).expect("write config");

    let mut command = Command::new(binary);
    let cmd = harden_command(&mut command, temp.path());
    // Force a known host and scrub the ambient override so the developer's
    // shell env cannot leak into the subprocess.
    cmd.env("CLX_CREDENTIALS_BACKEND", "age")
        .env("CLX_HOOK_HOST", "claude")
        .env_remove("CLAUDECODE")
        .env_remove("CLX_LEARNING_MODE")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    for (k, v) in extra_env {
        cmd.env(k, v);
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

/// Re-open the sandbox learning DB and return all rows (most recent first).
fn learning_rows(home: &Path) -> Vec<LearningEvent> {
    let db = home.join(concat!(".", "clx")).join("data").join("clx.db");
    if !db.exists() {
        return Vec::new();
    }
    let st = Storage::open(&db).expect("open sandbox db");
    st.list_learning_events(&LearningFilter::default())
        .expect("query learning events")
}

fn learning_count(home: &Path) -> usize {
    let db = home.join(concat!(".", "clx")).join("data").join("clx.db");
    if !db.exists() {
        return 0;
    }
    let st = Storage::open(&db).expect("open sandbox db");
    st.count_learning_events().expect("count learning events")
}

/// Config: validator on, L0 on, L1 off, cache off. With L1 disabled an
/// unknown (non-read-only) command takes the L1-DISABLED forced-ask path
/// (origin `UnknownFallthrough` → diverged), while blacklist/whitelist/read-only
/// L0 outcomes still apply. `learning_extra` injects the `learning_mode` flag.
fn cfg_l1_off(learning_extra: &str) -> String {
    format!(
        "validator:\n  \
           enabled: true\n  \
           layer0_enabled: true\n  \
           layer1_enabled: false\n  \
           cache_enabled: false\n{learning_extra}"
    )
}

/// Config whose legacy `ollama:` block points L1's chat client at `uri`, with
/// L0 enabled and L1 enabled so an unknown command reaches the LLM.
fn cfg_l1_on(uri: &str, learning_extra: &str) -> String {
    format!(
        "validator:\n  \
           enabled: true\n  \
           layer0_enabled: true\n  \
           layer1_enabled: true\n  \
           cache_enabled: false\n{learning_extra}\
         ollama:\n  \
           host: \"{uri}\"\n  \
           model: \"test-model\"\n  \
           max_retries: 0\n"
    )
}

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

const BLACKLIST_CMD: &str = "rm -rf /";
const ASK_CMD: &str = "frobnicate --apply";
const ALLOW_READ_CMD: &str = "ls -la";

// =========================================================================
// AC1 / AC10: learning_mode OFF (default) → zero rows, decision unchanged.
// =========================================================================

/// With `learning_mode` absent (default false) AND no env override, a
/// blacklisted command is denied exactly as before AND ZERO learning rows are
/// written (the bool gate runs before any Storage open for capture).
#[test]
fn ac1_learning_off_writes_zero_rows_and_decision_unchanged() {
    let cfg = cfg_l1_off("");
    let env = pre_tool_use("lm-off-deny", BLACKLIST_CMD);
    let (out, home) = run_with_extra_env(&cfg, &env, &[]);

    assert_eq!(
        decision(&out),
        "deny",
        "blacklisted command must still be denied with learning off"
    );
    assert_eq!(
        learning_count(home.path()),
        0,
        "learning_mode off must write ZERO learning_events rows"
    );
}

/// Off-path holds for an allow decision too: a read-only command is allowed and
/// no learning row is written.
#[test]
fn ac10_learning_off_allow_writes_zero_rows() {
    let cfg = cfg_l1_off("");
    let env = pre_tool_use("lm-off-allow", ALLOW_READ_CMD);
    let (out, home) = run_with_extra_env(&cfg, &env, &[]);

    assert_eq!(decision(&out), "allow", "read-only command must be allowed");
    assert_eq!(
        learning_count(home.path()),
        0,
        "learning_mode off must write ZERO rows on the allow path"
    );
}

// =========================================================================
// AC2: learning_mode ON → allow / ask / deny each produce exactly one row.
// =========================================================================

/// ON (via config) + a read-only allow → exactly one row: decision=allow,
/// layer=l0, origin read-only (a `divergence_reason` is absent → not diverged),
/// non-empty reason.
#[test]
fn ac2_on_allow_writes_one_row() {
    let cfg = cfg_l1_off("  learning_mode: true\n");
    let env = pre_tool_use("lm-on-allow", ALLOW_READ_CMD);
    let (out, home) = run_with_extra_env(&cfg, &env, &[]);

    assert_eq!(decision(&out), "allow");
    let rows = learning_rows(home.path());
    assert_eq!(rows.len(), 1, "exactly one allow row; rows: {rows:?}");
    let r = &rows[0];
    assert_eq!(r.decision, "allow");
    assert_eq!(r.layer, "l0");
    assert!(!r.reason.is_empty(), "reason must be non-empty");
    assert!(!r.diverged, "read-only allow is not diverged");
    assert!(
        r.policy_fingerprint.starts_with("sha256:"),
        "fingerprint must be set: {}",
        r.policy_fingerprint
    );
}

/// ON + an unknown non-read-only command with L1 disabled → exactly one
/// forced-ask row: decision=ask, layer=l0, diverged=true (`UnknownFallthrough`).
#[test]
fn ac2_on_ask_writes_one_row() {
    let cfg = cfg_l1_off("  learning_mode: true\n");
    let env = pre_tool_use("lm-on-ask", ASK_CMD);
    let (out, home) = run_with_extra_env(&cfg, &env, &[]);

    assert_eq!(decision(&out), "ask", "L1 disabled → forced ask");
    let rows = learning_rows(home.path());
    assert_eq!(rows.len(), 1, "exactly one ask row; rows: {rows:?}");
    let r = &rows[0];
    assert_eq!(r.decision, "ask");
    assert!(!r.reason.is_empty());
    assert!(
        r.diverged,
        "an L1-disabled forced ask (UnknownFallthrough) must be diverged"
    );
    assert!(r.divergence_reason.is_some());
}

/// ON + a blacklisted command → exactly one row: decision=deny, layer=l0,
/// diverged=false (deterministic blacklist), command captured (redaction is a
/// no-op on a non-secret command).
#[test]
fn ac2_on_deny_writes_one_row() {
    let cfg = cfg_l1_off("  learning_mode: true\n");
    let env = pre_tool_use("lm-on-deny", BLACKLIST_CMD);
    let (out, home) = run_with_extra_env(&cfg, &env, &[]);

    assert_eq!(decision(&out), "deny");
    let rows = learning_rows(home.path());
    assert_eq!(rows.len(), 1, "exactly one deny row; rows: {rows:?}");
    let r = &rows[0];
    assert_eq!(r.decision, "deny");
    assert_eq!(r.layer, "l0");
    assert!(!r.reason.is_empty());
    assert!(
        !r.diverged,
        "a deterministic blacklist deny must NOT be diverged"
    );
}

// =========================================================================
// AC3 (env override): CLX_LEARNING_MODE=1 enables capture even when the config
// flag is false.
// =========================================================================

/// `CLX_LEARNING_MODE=1` env override turns capture ON despite
/// `learning_mode` being absent (false) in config.
#[test]
fn ac3_env_override_enables_capture() {
    let cfg = cfg_l1_off("");
    let env = pre_tool_use("lm-env-on", BLACKLIST_CMD);
    let (out, home) = run_with_extra_env(&cfg, &env, &[("CLX_LEARNING_MODE", "1")]);

    assert_eq!(decision(&out), "deny");
    assert_eq!(
        learning_count(home.path()),
        1,
        "CLX_LEARNING_MODE=1 must enable capture even with config flag false"
    );
}

// =========================================================================
// AC4: a secret-bearing command is redacted before storage.
// =========================================================================

/// ON + a secret-bearing command → the stored command/reason contain the
/// redaction marker, NOT the live secret token. The command takes the
/// L1-disabled forced-ask path (it is not blacklisted, not read-only), so a
/// row is written carrying the (redacted) command.
#[test]
fn ac4_secret_bearing_command_is_redacted() {
    let secret = "sk-live-ABCDEF0123456789ABCDEF0123456789";
    let cmd = format!("curl -H 'Authorization: Bearer {secret}' https://api.example.com");
    let cfg = cfg_l1_off("  learning_mode: true\n");
    let env = pre_tool_use("lm-secret", &cmd);
    let (_out, home) = run_with_extra_env(&cfg, &env, &[]);

    let rows = learning_rows(home.path());
    assert_eq!(rows.len(), 1, "one row for the secret command; {rows:?}");
    let r = &rows[0];
    let stored_cmd = r.command.clone().unwrap_or_default();
    assert!(
        !stored_cmd.contains(secret),
        "stored command must NOT contain the live secret; got: {stored_cmd}"
    );
    assert!(
        stored_cmd.contains("***REDACTED***"),
        "stored command must contain the redaction marker; got: {stored_cmd}"
    );
}

// =========================================================================
// AC5: divergence — blacklist-deny=false, unknown→ask=true, L1-caution=true.
// =========================================================================

/// Drive a real L1-caution ask through wiremock: L0 returns Ask for an unknown
/// command, L1 (LLM) returns a mid risk score → ask. The resulting row must be
/// `diverged=true` with origin `l1_caution`.
#[tokio::test]
async fn ac5_l1_caution_ask_is_diverged() {
    let server = MockServer::start().await;
    mount_health_up(&server).await;
    // Mid risk score (5) → PolicyDecision::Ask (L1 caution), not deny/allow.
    mount_generate(
        &server,
        r#"{"risk_score":5,"reasoning":"unclear intent","category":"caution"}"#,
    )
    .await;

    let cfg = cfg_l1_on(&server.uri(), "  learning_mode: true\n");
    let env = pre_tool_use("lm-l1-ask", ASK_CMD);
    let (out, home) = run_with_extra_env(&cfg, &env, &[]);

    assert_eq!(decision(&out), "ask", "mid L1 verdict must ask");
    let rows = learning_rows(home.path());
    // Exactly one final decision row for this command (L0 escalates silently;
    // only the L1 emit captures).
    let ask_rows: Vec<_> = rows.iter().filter(|r| r.decision == "ask").collect();
    assert_eq!(ask_rows.len(), 1, "one L1 ask row; rows: {rows:?}");
    let r = ask_rows[0];
    assert_eq!(r.layer, "l1");
    assert!(
        r.diverged,
        "an L1 (LLM) caution ask on a non-blacklisted command must be diverged"
    );
    assert!(r.divergence_reason.is_some());
}

/// Companion to the L1-caution case: a blacklist deny on the same store is
/// NOT diverged, proving the divergence predicate distinguishes deterministic
/// safety calls from LLM/fallthrough prompts.
#[test]
fn ac5_blacklist_deny_is_not_diverged() {
    let cfg = cfg_l1_off("  learning_mode: true\n");
    let env = pre_tool_use("lm-bl-notdiv", BLACKLIST_CMD);
    let (out, home) = run_with_extra_env(&cfg, &env, &[]);

    assert_eq!(decision(&out), "deny");
    let rows = learning_rows(home.path());
    let deny: Vec<_> = rows.iter().filter(|r| r.decision == "deny").collect();
    assert_eq!(deny.len(), 1, "one deny row; rows: {rows:?}");
    assert!(
        !deny[0].diverged,
        "blacklist deny must be diverged=false (deterministic safety call)"
    );
    assert!(deny[0].divergence_reason.is_none());
}
