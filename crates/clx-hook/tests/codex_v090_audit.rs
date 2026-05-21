//! Codex independent v0.9.0 audit tests.
//!
//! Ignored by default so the normal workspace suite stays fast. These tests
//! drive the real `clx-hook` binary with isolated HOME directories and
//! hermetic loopback providers.

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

const ASK_CMD: &str = "frobnicate --apply";
const DANGER_CMD: &str = "rm -rf /";
const SAFE_CMD: &str = "git status --short";

fn write_config(home: &Path, config_yaml: &str) {
    let clx_dir = home.join(".clx");
    std::fs::create_dir_all(&clx_dir).expect("mk .clx");
    std::fs::write(clx_dir.join("config.yaml"), config_yaml).expect("write config");
}

fn run(config_yaml: &str, envelope: &serde_json::Value) -> (serde_json::Value, tempfile::TempDir) {
    let temp = isolated_clx_home();
    write_config(temp.path(), config_yaml);
    let parsed = run_in_home(temp.path(), envelope);
    (parsed, temp)
}

fn run_in_home(home: &Path, envelope: &serde_json::Value) -> serde_json::Value {
    let binary = env!("CARGO_BIN_EXE_clx-hook");
    let mut command = Command::new(binary);
    let mut child = harden_command(&mut command, home)
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
        .expect("stdin")
        .write_all(envelope.to_string().as_bytes())
        .expect("write stdin");

    let out = child.wait_with_output().expect("wait clx-hook");
    assert_home_size_bounded(home);
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("hook stdout must be valid JSON: {e}\nstdout: {stdout}"))
}

fn decision(v: &serde_json::Value) -> &str {
    v["hookSpecificOutput"]["permissionDecision"]
        .as_str()
        .unwrap_or("")
}

fn reason(v: &serde_json::Value) -> &str {
    v["hookSpecificOutput"]["permissionDecisionReason"]
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

fn cfg_ollama(host: &str, validator_extra: &str) -> String {
    format!(
        "validator:\n  \
         enabled: true\n  \
         cache_enabled: false\n  \
         auto_allow_reads: false\n{validator_extra}\
         ollama:\n  \
         host: \"{host}\"\n  \
         model: \"test-model\"\n  \
         max_retries: 0\n"
    )
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

#[test]
#[ignore = "Codex v0.9.0 audit: cache must not bypass L1 disabled"]
fn rb1_cache_populated_l1_disabled_does_not_consult_cache() {
    let temp = isolated_clx_home();
    let cfg = "validator:\n  \
               enabled: true\n  \
               layer0_enabled: true\n  \
               layer1_enabled: false\n  \
               cache_enabled: true\n  \
               auto_allow_reads: false\n";
    write_config(temp.path(), cfg);

    let clx_dir = temp.path().join(".clx");
    std::fs::create_dir_all(clx_dir.join("data")).expect("mk data");
    let st = Storage::open(clx_dir.join("data/clx.db")).expect("open db");
    let key = clx_core::policy::compute_cache_key(ASK_CMD, "/tmp");
    st.cache_decision(&key, "allow", Some("seeded audit cache"), Some(1), 3600)
        .expect("seed cache");
    drop(st);

    let out = run_in_home(temp.path(), &pre_tool_use("codex-cache-l1-off", ASK_CMD));
    assert_eq!(decision(&out), "ask");

    let rows = audit_rows(temp.path(), "codex-cache-l1-off");
    assert!(
        !rows.iter().any(|r| r.layer == "L1-CACHE"),
        "cache row must not be used when L1 is disabled: {rows:?}"
    );
    assert!(
        rows.iter().any(|r| {
            r.command == ASK_CMD && r.reasoning.as_deref().unwrap_or("").contains("L1-DISABLED")
        }),
        "L1 disabled ask row must be emitted: {rows:?}"
    );
}

#[test]
#[ignore = "Codex v0.9.0 audit: Ollama unavailable fallback matrix"]
fn rb1_ollama_unreachable_default_matrix_is_gated() {
    let cfg_allow = cfg_ollama(
        "http://127.0.0.1:9",
        "  layer0_enabled: false\n  layer1_enabled: true\n  default_decision: allow\n",
    );
    let (out_allow, _) = run(&cfg_allow, &pre_tool_use("codex-down-allow", DANGER_CMD));
    assert_eq!(decision(&out_allow), "ask");
    assert!(reason(&out_allow).contains("LLM unavailable"));

    let cfg_deny = cfg_ollama(
        "http://127.0.0.1:9",
        "  layer0_enabled: false\n  layer1_enabled: true\n  default_decision: deny\n",
    );
    let (out_deny, _) = run(&cfg_deny, &pre_tool_use("codex-down-deny", ASK_CMD));
    assert_eq!(decision(&out_deny), "deny");

    let cfg_ask = cfg_ollama(
        "http://127.0.0.1:9",
        "  layer0_enabled: false\n  layer1_enabled: true\n  default_decision: ask\n",
    );
    let (out_ask, _) = run(&cfg_ask, &pre_tool_use("codex-down-ask", ASK_CMD));
    assert_eq!(decision(&out_ask), "ask");
    assert!(reason(&out_ask).contains("LLM unavailable"));
}

#[tokio::test]
#[ignore = "Codex v0.9.0 audit: L1 timeout fallback matrix"]
async fn rb1_l1_timeout_default_matrix_is_gated() {
    if std::env::var_os("CLX_CODEX_RUN_LOOPBACK_TESTS").is_none() {
        eprintln!("skipping loopback-bound timeout case in restricted sandbox");
        return;
    }

    let server = MockServer::start().await;
    mount_health_up(&server).await;
    Mock::given(method("POST"))
        .and(path("/api/generate"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(std::time::Duration::from_secs(2))
                .set_body_raw(
                    json!({
                        "response": r#"{"risk_score":1,"reasoning":"late","category":"safe"}"#,
                        "done": true
                    })
                    .to_string(),
                    "application/json",
                ),
        )
        .mount(&server)
        .await;

    let allow_cfg = cfg_ollama(
        &server.uri(),
        "  layer0_enabled: false\n  layer1_enabled: true\n  layer1_timeout_ms: 100\n  default_decision: allow\n",
    );
    let (out_allow, _) = run(&allow_cfg, &pre_tool_use("codex-timeout-allow", ASK_CMD));
    assert_eq!(decision(&out_allow), "ask");
    assert!(reason(&out_allow).contains("LLM timeout"));

    let deny_cfg = cfg_ollama(
        &server.uri(),
        "  layer0_enabled: false\n  layer1_enabled: true\n  layer1_timeout_ms: 100\n  default_decision: deny\n",
    );
    let (out_deny, _) = run(&deny_cfg, &pre_tool_use("codex-timeout-deny", ASK_CMD));
    assert_eq!(decision(&out_deny), "deny");
}

#[test]
#[ignore = "Codex v0.9.0 audit: client construction error fallback matrix"]
fn rb1_llm_client_construction_error_default_matrix_is_gated() {
    let cfg_allow = "validator:\n  \
                     enabled: true\n  \
                     layer0_enabled: false\n  \
                     layer1_enabled: true\n  \
                     default_decision: allow\n  \
                     cache_enabled: false\n  \
                     auto_allow_reads: false\n\
                     llm:\n  \
                     chat: { provider: \"missing-provider\", model: \"m\" }\n  \
                     embeddings: { provider: \"missing-provider\", model: \"e\" }\n";
    let (out_allow, _) = run(cfg_allow, &pre_tool_use("codex-client-allow", ASK_CMD));
    assert_eq!(decision(&out_allow), "ask");
    assert!(reason(&out_allow).contains("LLM unavailable"));

    let cfg_deny = cfg_allow.replace("default_decision: allow", "default_decision: deny");
    let (out_deny, _) = run(&cfg_deny, &pre_tool_use("codex-client-deny", ASK_CMD));
    assert_eq!(decision(&out_deny), "deny");
}

#[test]
#[ignore = "Codex v0.9.0 audit: learned rules must not suppress L1 disabled ask"]
fn rb1_l1_disabled_learned_rule_does_not_suppress_ask() {
    let temp = isolated_clx_home();
    let cfg = "validator:\n  \
               enabled: true\n  \
               layer0_enabled: true\n  \
               layer1_enabled: false\n  \
               cache_enabled: false\n  \
               auto_allow_reads: false\n";
    write_config(temp.path(), cfg);

    let clx_dir = temp.path().join(".clx");
    std::fs::create_dir_all(clx_dir.join("data")).expect("mk data");
    let st = Storage::open(clx_dir.join("data/clx.db")).expect("open db");
    let rule = clx_core::types::LearnedRule::new(
        ASK_CMD.to_string(),
        clx_core::types::RuleType::Allow,
        "codex-audit-seed".to_string(),
    );
    st.add_rule(&rule).expect("seed learned rule");
    drop(st);

    let out = run_in_home(temp.path(), &pre_tool_use("codex-learned-l1-off", ASK_CMD));
    assert_eq!(decision(&out), "ask");
    let rows = audit_rows(temp.path(), "codex-learned-l1-off");
    assert!(
        rows.iter().any(|r| {
            r.command == ASK_CMD && r.reasoning.as_deref().unwrap_or("").contains("L1-DISABLED")
        }),
        "L1 disabled ask must win over learned allow rows: {rows:?}"
    );
}

#[test]
#[ignore = "Codex v0.9.0 audit: L0 whitelist must still pass with default allow"]
fn tier2_whitelisted_l0_allow_still_passes_with_l1_down() {
    let cfg = cfg_ollama(
        "http://127.0.0.1:9",
        "  layer0_enabled: true\n  layer1_enabled: true\n  default_decision: allow\n",
    );
    let (out, home) = run(&cfg, &pre_tool_use("codex-whitelist", SAFE_CMD));
    assert_eq!(decision(&out), "allow");
    let rows = audit_rows(home.path(), "codex-whitelist");
    assert!(
        rows.iter()
            .any(|r| r.command == SAFE_CMD && r.layer == "L0" && r.decision.as_str() == "allowed"),
        "whitelist allow must be decided at L0: {rows:?}"
    );
    assert!(
        !rows.iter().any(|r| r.layer == "L1"),
        "L1 must not run after an L0 allow: {rows:?}"
    );
}

#[test]
#[ignore = "Codex v0.9.0 audit: cache remains active when both layers are enabled"]
fn tier2_cache_still_read_when_both_layers_enabled() {
    let temp = isolated_clx_home();
    let cfg = "validator:\n  \
               enabled: true\n  \
               layer0_enabled: true\n  \
               layer1_enabled: true\n  \
               cache_enabled: true\n  \
               auto_allow_reads: false\n\
               ollama:\n  host: \"http://127.0.0.1:9\"\n";
    write_config(temp.path(), cfg);

    let clx_dir = temp.path().join(".clx");
    std::fs::create_dir_all(clx_dir.join("data")).expect("mk data");
    let st = Storage::open(clx_dir.join("data/clx.db")).expect("open db");
    let key = clx_core::policy::compute_cache_key(ASK_CMD, "/tmp");
    st.cache_decision(&key, "allow", Some("codex seeded cache"), Some(1), 3600)
        .expect("seed cache");
    drop(st);

    let out = run_in_home(temp.path(), &pre_tool_use("codex-cache-both-on", ASK_CMD));
    assert_eq!(decision(&out), "allow");
    let rows = audit_rows(temp.path(), "codex-cache-both-on");
    assert!(
        rows.iter().any(|r| r.layer == "L1-CACHE"),
        "cache must be consulted when both layers are enabled: {rows:?}"
    );
}
