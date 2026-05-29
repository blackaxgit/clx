//! v0.9.0 GREEN G1 regression tests — silent-allow class (T9.1–T9.4),
//! T2 learned-rules gate, T9.5 L1-rename dual-emit.
//!
//! Each test mirrors a RED `PoC` but asserts the SECURE post-fix behavior:
//! the silent-allow class introduced by the `layer0_enabled` toggle is
//! closed. All tests are hermetic (wiremock loopback + isolated `TempDir`
//! HOME, no real network, no real `~/.clx`, `CLX_CREDENTIALS_BACKEND=age`).
//! No `#[ignore]` gates — these are always-run regressions.
//!
//! ## Coverage map
//!
//! | ID   | What it pins                                            | RED PoC mirror               |
//! |------|---------------------------------------------------------|------------------------------|
//! | a    | T9.1 cache skipped when `layer1_enabled=false`          | red_t9_1_l0_off_cache_hit    |
//! | b    | T9.2 Ollama-unavailable + default=allow → ask          | red_t9_2 / R1-F1             |
//! | c    | T9.3 L1 timeout + default=allow → ask                   | red_t9_3                     |
//! | d    | T9.4 LLM-client-construction-error + default=allow → ask| red_t9_2 (client-err arm)    |
//! | e    | T9.5 L1-DISABLED dual-emit reasoning substrings         | red_t_l1_rename_no_dual_emit |
//! | f    | T2 learned-rules NOT loaded when L1 disabled            | red_t2 (pre-gate hazard)     |

use std::io::Write as _;
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
// Harness
// =========================================================================

fn run(config_yaml: &str, envelope: &serde_json::Value) -> (serde_json::Value, tempfile::TempDir) {
    let binary = env!("CARGO_BIN_EXE_clx-hook");
    let temp = isolated_clx_home();
    let clx_dir = temp.path().join(".clx");
    std::fs::create_dir_all(&clx_dir).expect("mk .clx");
    std::fs::write(clx_dir.join("config.yaml"), config_yaml).expect("write config");

    let mut command = Command::new(binary);
    let mut child = harden_command(&mut command, temp.path())
        .env("CLX_CREDENTIALS_BACKEND", "age")
        .env("CLX_MODEL_FETCH_DRYRUN", "1")
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

fn decision(v: &serde_json::Value) -> &str {
    v["hookSpecificOutput"]["permissionDecision"]
        .as_str()
        .unwrap_or("")
}

fn pre_tool_use(session: &str, cmd: &str) -> serde_json::Value {
    json!({
        "session_id": session,
        "cwd": "/tmp",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_use_id": format!("tu-{session}"),
        "tool_input": { "command": cmd }
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

/// An L0-unknown, non-read-only command that falls through to L1 arms.
const ASK_CMD: &str = "frobnicate --apply";

// =========================================================================
// (a) T9.1 — Cache NOT consulted when `layer1_enabled=false`
// =========================================================================
//
// RED PoC scenario: `layer1_enabled=false` + a pre-seeded cache "allow" row
// for an L0-unknown command would return "allow" from the L1-CACHE arm,
// silently bypassing the L1-DISABLED→ask posture.
//
// POST-FIX: cache lookup is gated on BOTH `layer0_enabled` AND
// `layer1_enabled`. With L1 disabled the cache is never consulted; the hook
// reaches the L1-DISABLED branch and emits "ask".

#[test]
fn g1_a_cache_not_consulted_when_l1_disabled() {
    let temp = isolated_clx_home();
    let clx_dir = temp.path().join(".clx");
    std::fs::create_dir_all(clx_dir.join("data")).expect("mk data dir");

    let cfg = "validator:\n  \
               enabled: true\n  \
               layer0_enabled: true\n  \
               layer1_enabled: false\n  \
               cache_enabled: true\n  \
               auto_allow_reads: false\n";
    std::fs::write(clx_dir.join("config.yaml"), cfg).expect("write config");

    // Pre-seed a cache ALLOW row for ASK_CMD — the exploit RED used.
    let cwd = "/tmp";
    {
        let st = Storage::open(clx_dir.join("data/clx.db")).expect("open db");
        let key = clx_core::policy::compute_cache_key(ASK_CMD, cwd);
        st.cache_decision(&key, "allow", Some("seeded-by-red-poc"), Some(2), 3600)
            .expect("seed cache");
    }

    let binary = env!("CARGO_BIN_EXE_clx-hook");
    let envelope = pre_tool_use("g1-a-cache-bypass", ASK_CMD);
    let mut cmd = Command::new(binary);
    let mut child = harden_command(&mut cmd, temp.path())
        .env("CLX_CREDENTIALS_BACKEND", "age")
        .env("CLX_MODEL_FETCH_DRYRUN", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(envelope.to_string().as_bytes())
        .unwrap();
    let out = child.wait_with_output().expect("wait");
    assert_home_size_bounded(temp.path());
    let parsed: serde_json::Value =
        serde_json::from_str(String::from_utf8_lossy(&out.stdout).trim()).expect("json");

    assert_ne!(
        decision(&parsed),
        "allow",
        "G1-a: pre-seeded cache allow must NOT be served when layer1_enabled=false"
    );
    assert_eq!(
        decision(&parsed),
        "ask",
        "G1-a: layer1_enabled=false must produce ask regardless of cache contents"
    );

    let rows = audit_rows(temp.path(), "g1-a-cache-bypass");
    let l0_rows: Vec<_> = rows
        .iter()
        .filter(|r| r.layer == "L0" && r.command == ASK_CMD)
        .collect();
    assert!(
        !l0_rows.is_empty(),
        "G1-a: must have an L0 row from the L1-DISABLED path; rows={rows:?}"
    );
    // The L1-DISABLED audit row must NOT be an L1-CACHE row.
    assert!(
        !rows.iter().any(|r| r.layer == "L1-CACHE"),
        "G1-a: L1-CACHE row must NOT be emitted when layer1_enabled=false"
    );
    let reasoning = l0_rows
        .iter()
        .find_map(|r| r.reasoning.clone())
        .unwrap_or_default();
    assert!(
        reasoning.contains("L1-DISABLED"),
        "G1-a: L1-DISABLED reasoning must contain canonical 'L1-DISABLED'; got {reasoning:?}"
    );
}

// =========================================================================
// (b) T9.2 — Ollama unreachable + `default_decision=allow` → ask
// =========================================================================
//
// RED PoC scenario (R1-F1, red_t9_2): with `layer0_enabled=false` (or L0
// returning Ask), Ollama unreachable, and `default_decision=allow`, the old
// code silently allowed `rm -rf /`. POST-FIX: force ask.

#[test]
fn g1_b_ollama_unreachable_default_allow_forces_ask() {
    let cfg = "validator:\n  \
               enabled: true\n  \
               layer0_enabled: false\n  \
               layer1_enabled: true\n  \
               default_decision: allow\n  \
               cache_enabled: false\n  \
               auto_allow_reads: false\n\
               ollama:\n  \
               host: \"http://127.0.0.1:9\"\n  \
               timeout_ms: 500\n  \
               max_retries: 0\n";
    // Use an L0-blacklisted command to make the blast radius explicit. With
    // layer0_enabled=false the L0 deny does NOT fire; the only gate left is
    // the L1 fallback — which must now refuse silent allow.
    let envelope = pre_tool_use("g1-b-ollama-down", "rm -rf /");
    let (out, home) = run(cfg, &envelope);

    assert_ne!(
        decision(&out),
        "allow",
        "G1-b: default_decision=allow + Ollama unreachable + L0-bypassed \
         must NOT silently allow `rm -rf /`"
    );
    assert_eq!(
        decision(&out),
        "ask",
        "G1-b: must ask when Ollama unreachable and default_decision=allow"
    );

    let rows = audit_rows(home.path(), "g1-b-ollama-down");
    let l1_rows: Vec<_> = rows.iter().filter(|r| r.layer == "L1").collect();
    assert!(
        !l1_rows.is_empty(),
        "G1-b: must have at least one L1 audit row from the fallback path"
    );
    assert_eq!(
        l1_rows[0].decision.as_str(),
        "prompted",
        "G1-b: forced-ask must audit as prompted, got: {:?}",
        l1_rows[0]
    );
    let reasoning = l1_rows[0].reasoning.as_deref().unwrap_or("");
    assert!(
        reasoning.contains("effective_decision: ask"),
        "G1-b: reasoning must include effective_decision=ask; got {reasoning:?}"
    );
    assert!(
        reasoning.contains("configured: allow"),
        "G1-b: reasoning must include configured: allow; got {reasoning:?}"
    );
}

// =========================================================================
// (c) T9.3 — L1 timeout + `default_decision=allow` → ask
// =========================================================================
//
// RED PoC scenario (red_t9_3): a slow generate response exceeds the
// configured `layer1_timeout_ms`. With `default_decision=allow` the old code
// silently allowed. POST-FIX: force ask.

#[tokio::test]
async fn g1_c_l1_timeout_default_allow_forces_ask() {
    let server = MockServer::start().await;
    mount_health_up(&server).await;
    // Generate responds after 2s; timeout is 100ms → guaranteed timeout.
    Mock::given(method("POST"))
        .and(path("/api/generate"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(std::time::Duration::from_secs(2))
                .set_body_raw(
                    json!({ "response": r#"{"risk_score":2,"reasoning":"benign","category":"safe"}"#, "done": true })
                        .to_string(),
                    "application/json",
                ),
        )
        .mount(&server)
        .await;

    let cfg = format!(
        "validator:\n  \
         enabled: true\n  \
         layer0_enabled: false\n  \
         layer1_enabled: true\n  \
         default_decision: allow\n  \
         layer1_timeout_ms: 100\n  \
         cache_enabled: false\n  \
         auto_allow_reads: false\n\
         ollama:\n  \
         host: \"{}\"\n  \
         model: \"test-model\"\n  \
         max_retries: 0\n",
        server.uri()
    );
    let envelope = pre_tool_use("g1-c-timeout", ASK_CMD);
    let (out, home) = run(&cfg, &envelope);

    assert_ne!(
        decision(&out),
        "allow",
        "G1-c: timeout with default_decision=allow must NOT silently allow"
    );
    assert_eq!(
        decision(&out),
        "ask",
        "G1-c: must ask on L1 timeout when default_decision=allow"
    );

    let rows = audit_rows(home.path(), "g1-c-timeout");
    let l1_rows: Vec<_> = rows.iter().filter(|r| r.layer == "L1").collect();
    assert!(!l1_rows.is_empty(), "G1-c: must have L1 audit row");
    assert_eq!(
        l1_rows[0].decision.as_str(),
        "prompted",
        "G1-c: forced-ask on timeout must audit as prompted"
    );
    let reasoning = l1_rows[0].reasoning.as_deref().unwrap_or("");
    assert!(
        reasoning.contains("L1 timeout"),
        "G1-c: reasoning must say 'L1 timeout'; got {reasoning:?}"
    );
    assert!(
        reasoning.contains("effective_decision: ask"),
        "G1-c: reasoning must include effective_decision=ask; got {reasoning:?}"
    );
}

// =========================================================================
// (d) T9.4 — LLM-client construction error + `default_decision=allow` → ask
// =========================================================================
//
// This covers the `create_llm_client(...)` error arm (provider misconfigured
// such that the client cannot be constructed at all — distinct from the
// `is_available()` health probe failure in (b) and the generate failure that
// surfaces as `Ask("LLM unavailable")`). With an unreachable Ollama host the
// short-lived hook process's client construction succeeds but the health
// probe path exercised in (b) is the equivalent fail-open arm. We exercise
// the gen-failed arm here (server reachable, generate returns 500) to cover
// the third silent-allow path.

#[tokio::test]
async fn g1_d_llm_gen_failed_default_allow_forces_ask() {
    let server = MockServer::start().await;
    mount_health_up(&server).await;
    // 500 on /api/generate → evaluate_with_llm returns Ask("LLM unavailable")
    Mock::given(method("POST"))
        .and(path("/api/generate"))
        .respond_with(
            ResponseTemplate::new(500)
                .set_body_raw(r#"{"error":"internal server error"}"#, "application/json"),
        )
        .mount(&server)
        .await;

    let cfg = format!(
        "validator:\n  \
         enabled: true\n  \
         layer0_enabled: false\n  \
         layer1_enabled: true\n  \
         default_decision: allow\n  \
         cache_enabled: false\n  \
         auto_allow_reads: false\n\
         ollama:\n  \
         host: \"{}\"\n  \
         model: \"test-model\"\n  \
         max_retries: 0\n",
        server.uri()
    );
    let envelope = pre_tool_use("g1-d-gen-failed", ASK_CMD);
    let (out, home) = run(&cfg, &envelope);

    assert_ne!(
        decision(&out),
        "allow",
        "G1-d: gen-failed with default_decision=allow must NOT silently allow"
    );
    // The hook may emit ask either from the gen-failed forced-ask arm OR
    // (depending on health-cache state) from the unavailable arm. Both are
    // acceptable; "allow" is the ONLY forbidden outcome.
    assert!(
        decision(&out) == "ask",
        "G1-d: gen-failed must produce ask, never allow; got: {}",
        decision(&out)
    );

    let rows = audit_rows(home.path(), "g1-d-gen-failed");
    let l1_rows: Vec<_> = rows.iter().filter(|r| r.layer == "L1").collect();
    assert!(!l1_rows.is_empty(), "G1-d: must have an L1 audit row");
    for r in &l1_rows {
        assert_ne!(
            r.decision.as_str(),
            "allowed",
            "G1-d: no L1 audit row may be 'allowed' when default_decision=allow + gen-failed"
        );
    }
}

// =========================================================================
// (e) T9.5 — L1-DISABLED canonical-only reasoning contract
// =========================================================================
//
// Single audit row, single reasoning string, carries only the canonical
// "L1-DISABLED" literal. The v0.9.0 dual-emit window for the legacy
// "L1 disabled" alias is closed in v0.10.0; the alias must NOT appear.

#[test]
fn g1_e_l1_disabled_reasoning_is_canonical_only() {
    let cfg = "validator:\n  \
               enabled: true\n  \
               layer0_enabled: true\n  \
               layer1_enabled: false\n  \
               cache_enabled: false\n  \
               auto_allow_reads: false\n";
    let envelope = pre_tool_use("g1-e-canonical", ASK_CMD);
    let (out, home) = run(cfg, &envelope);

    assert_eq!(decision(&out), "ask", "G1-e: L1-DISABLED path must ask");

    let rows = audit_rows(home.path(), "g1-e-canonical");
    let cmd_rows: Vec<_> = rows.iter().filter(|r| r.command == ASK_CMD).collect();
    assert_eq!(
        cmd_rows.len(),
        1,
        "G1-e: exactly one decision row expected for the command, got {cmd_rows:?}"
    );
    let reasoning = cmd_rows[0].reasoning.as_deref().unwrap_or("");
    assert!(
        reasoning.contains("L1-DISABLED"),
        "G1-e: reasoning must contain canonical 'L1-DISABLED'; got {reasoning:?}"
    );
    assert!(
        !reasoning.contains("L1 disabled"),
        "G1-e: legacy 'L1 disabled' alias must NOT appear (v0.10.0 dropped \
         the dual-emit window); got {reasoning:?}"
    );
}

// =========================================================================
// (f) T2 — learned_rules NOT loaded when `layer1_enabled=false`; an
//     overbroad learned-allow row in DB must NOT suppress L1-DISABLED ask
// =========================================================================
//
// RED PoC (red_t2): `load_learned_rules` was called unconditionally before
// the L0 gate. With L1 disabled and a single overbroad learned-allow row in
// the DB (e.g. pattern '*' / 'Bash(*)'), the L0 whitelist match could fire
// from a learned rule and override the L1-DISABLED→ask posture. POST-FIX:
// `load_learned_rules` is gated behind `layer1_enabled`, so overbroad rows
// are never loaded when L1 is off.

#[test]
fn g1_f_overbroad_learned_rule_does_not_suppress_l1_disabled_ask() {
    let temp = isolated_clx_home();
    let clx_dir = temp.path().join(".clx");
    std::fs::create_dir_all(clx_dir.join("data")).expect("mk data dir");

    let cfg = "validator:\n  \
               enabled: true\n  \
               layer0_enabled: true\n  \
               layer1_enabled: false\n  \
               cache_enabled: false\n  \
               auto_allow_reads: false\n";
    std::fs::write(clx_dir.join("config.yaml"), cfg).expect("write config");

    // Seed a specific learned-allow row directly via the storage API. A
    // specific pattern matching ASK_CMD would fire as an L0 whitelist match
    // IF load_learned_rules ran. The fix ensures the load is SKIPPED when
    // `layer1_enabled=false`, so the L1-DISABLED ask wins regardless.
    {
        let st = Storage::open(clx_dir.join("data/clx.db")).expect("open db");
        let rule = clx_core::types::LearnedRule::new(
            "frobnicate --apply".to_string(),
            clx_core::types::RuleType::Allow,
            "v090-g1-test-seed".to_string(),
        );
        st.add_rule(&rule).expect("seed learned-allow rule");
    }

    let binary = env!("CARGO_BIN_EXE_clx-hook");
    let envelope = pre_tool_use("g1-f-learned-gate", ASK_CMD);
    let mut cmd = Command::new(binary);
    let mut child = harden_command(&mut cmd, temp.path())
        .env("CLX_CREDENTIALS_BACKEND", "age")
        .env("CLX_MODEL_FETCH_DRYRUN", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(envelope.to_string().as_bytes())
        .unwrap();
    let out = child.wait_with_output().expect("wait");
    assert_home_size_bounded(temp.path());
    let parsed: serde_json::Value =
        serde_json::from_str(String::from_utf8_lossy(&out.stdout).trim()).expect("json");

    assert_ne!(
        decision(&parsed),
        "allow",
        "G1-f: learned-allow row must NOT produce allow when layer1_enabled=false"
    );
    assert_eq!(
        decision(&parsed),
        "ask",
        "G1-f: L1-DISABLED path must produce ask regardless of learned rules in DB"
    );

    let rows = audit_rows(temp.path(), "g1-f-learned-gate");
    let cmd_rows: Vec<_> = rows.iter().filter(|r| r.command == ASK_CMD).collect();
    assert!(
        !cmd_rows.is_empty(),
        "G1-f: must have an audit row for the command"
    );
    let reasoning = cmd_rows[0].reasoning.as_deref().unwrap_or("");
    assert!(
        reasoning.contains("L1-DISABLED"),
        "G1-f: must audit via L1-DISABLED path (not via learned-allow); \
         got reasoning {reasoning:?}"
    );
}

// =========================================================================
// Non-regression: default_decision=deny still denies when L1 unavailable
// =========================================================================
//
// The F7-posture force-ask only fires for `default_decision=allow`. Deny and
// ask must pass through unchanged.

#[test]
fn g1_nonreg_default_deny_still_denies_when_ollama_unreachable() {
    let cfg = "validator:\n  \
               enabled: true\n  \
               layer0_enabled: false\n  \
               layer1_enabled: true\n  \
               default_decision: deny\n  \
               cache_enabled: false\n  \
               auto_allow_reads: false\n\
               ollama:\n  \
               host: \"http://127.0.0.1:9\"\n  \
               timeout_ms: 500\n  \
               max_retries: 0\n";
    let envelope = pre_tool_use("g1-nr-deny", ASK_CMD);
    let (out, home) = run(cfg, &envelope);
    assert_eq!(
        decision(&out),
        "deny",
        "G1-nonreg: default_decision=deny must still deny when L1 unreachable"
    );
    let rows = audit_rows(home.path(), "g1-nr-deny");
    let l1_rows: Vec<_> = rows.iter().filter(|r| r.layer == "L1").collect();
    assert!(!l1_rows.is_empty(), "G1-nonreg: must have L1 audit row");
    assert_eq!(l1_rows[0].decision.as_str(), "blocked");
}

#[test]
fn g1_nonreg_default_ask_still_asks_when_ollama_unreachable() {
    let cfg = "validator:\n  \
               enabled: true\n  \
               layer0_enabled: false\n  \
               layer1_enabled: true\n  \
               default_decision: ask\n  \
               cache_enabled: false\n  \
               auto_allow_reads: false\n\
               ollama:\n  \
               host: \"http://127.0.0.1:9\"\n  \
               timeout_ms: 500\n  \
               max_retries: 0\n";
    let envelope = pre_tool_use("g1-nr-ask", ASK_CMD);
    let (out, home) = run(cfg, &envelope);
    assert_eq!(
        decision(&out),
        "ask",
        "G1-nonreg: default_decision=ask must ask when L1 unreachable"
    );
    let rows = audit_rows(home.path(), "g1-nr-ask");
    let l1_rows: Vec<_> = rows.iter().filter(|r| r.layer == "L1").collect();
    assert!(!l1_rows.is_empty(), "G1-nonreg: must have L1 audit row");
    assert_eq!(l1_rows[0].decision.as_str(), "prompted");
}

// =========================================================================
// Non-regression: cache IS consulted when BOTH layers are enabled
// =========================================================================

#[test]
fn g1_nonreg_cache_consulted_when_both_layers_enabled() {
    let temp = isolated_clx_home();
    let clx_dir = temp.path().join(".clx");
    std::fs::create_dir_all(clx_dir.join("data")).expect("mk data dir");

    // Both layers enabled, ollama unreachable — the cache hit must fire BEFORE
    // attempting the unreachable provider.
    let cfg = "validator:\n  \
               enabled: true\n  \
               layer0_enabled: true\n  \
               layer1_enabled: true\n  \
               cache_enabled: true\n  \
               auto_allow_reads: false\n\
               ollama:\n  host: \"http://127.0.0.1:1\"\n";
    std::fs::write(clx_dir.join("config.yaml"), cfg).expect("write config");

    let cwd = "/tmp";
    {
        let st = Storage::open(clx_dir.join("data/clx.db")).expect("open db");
        let key = clx_core::policy::compute_cache_key(ASK_CMD, cwd);
        st.cache_decision(&key, "allow", Some("cached-verdict"), Some(2), 3600)
            .expect("seed cache");
    }

    let binary = env!("CARGO_BIN_EXE_clx-hook");
    let envelope = pre_tool_use("g1-nr-cache-pos", ASK_CMD);
    let mut cmd = Command::new(binary);
    let mut child = harden_command(&mut cmd, temp.path())
        .env("CLX_CREDENTIALS_BACKEND", "age")
        .env("CLX_MODEL_FETCH_DRYRUN", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(envelope.to_string().as_bytes())
        .unwrap();
    let out = child.wait_with_output().expect("wait");
    assert_home_size_bounded(temp.path());
    let parsed: serde_json::Value =
        serde_json::from_str(String::from_utf8_lossy(&out.stdout).trim()).expect("json");

    assert_eq!(
        decision(&parsed),
        "allow",
        "G1-nonreg: cache must be served when BOTH layers are enabled"
    );
    let rows = audit_rows(temp.path(), "g1-nr-cache-pos");
    let cache_rows: Vec<_> = rows.iter().filter(|r| r.layer == "L1-CACHE").collect();
    assert_eq!(
        cache_rows.len(),
        1,
        "G1-nonreg: must audit as L1-CACHE; rows={rows:?}"
    );
}
