//! End-to-end behavior tests for the `pre_tool_use` L1 orchestration arms
//! (Stream 3 / Seam C of the 0.8.1 coverage campaign v2).
//!
//! These drive the **real `clx-hook` binary** with a `config.yaml` written
//! into an isolated `HOME` whose legacy `ollama:` block points the provider
//! `host` at a local wiremock [`MockServer`]. `Config::load()` translates the
//! legacy block into `providers:` + `llm:` in memory
//! (`config/mod.rs::translate_legacy_in_place`), so the L1 chat client the
//! hook builds internally talks to wiremock instead of a real Ollama. This
//! exercises every previously-unreachable arm of
//! `crates/clx-hook/src/hooks/pre_tool_use.rs:223-545` **without any
//! production change** (the Ollama backend already accepts a configurable
//! host).
//!
//! Hermetic: no real network beyond loopback wiremock, no keychain, no model
//! (`CLX_MODEL_FETCH_DRYRUN=1` via `harden_command`,
//! `CLX_CREDENTIALS_BACKEND=age` exported per-process). Tests assert
//! observable outputs (the emitted Claude Code decision envelope) AND side
//! effects (audit rows, cache rows, learned-rule `denial_count`, health file)
//! read back from the sandbox DB. Contracts, not implementation pinning.
//!
//! Arm coverage map (verified against the working tree):
//! - cache-HIT early return ............ `pre_tool_use.rs:223-252`
//! - L1 Allow + cache-write ............ `pre_tool_use.rs:434-460`
//! - L1 Deny + `track_user_decision` ... `pre_tool_use.rs:461-487` (V-R5)
//! - L1 Ask + cache-write (ask) ........ `pre_tool_use.rs:519-544`
//! - L0-READ precedence (pins why the L1-READ arm
//!   `pre_tool_use.rs:488-518` is structurally dead) ... `:204-217`
//! - L1 timeout + `write_health(false)` ... `pre_tool_use.rs:374-400`
//! - LLM-unavailable post-call arm ..... `pre_tool_use.rs:405-429`
//! - client-unavailable fallback ....... `pre_tool_use.rs:328-353`

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
// Harness
// =========================================================================

/// Spawn the real `clx-hook` binary with an isolated `HOME` + the given
/// `config.yaml`, pipe `envelope` on stdin, and return the parsed decision
/// JSON plus the live `TempDir` (kept alive by the caller so side-effect
/// assertions can re-open the sandbox DB).
fn run(config_yaml: &str, envelope: &serde_json::Value) -> (serde_json::Value, tempfile::TempDir) {
    let binary = env!("CARGO_BIN_EXE_clx-hook");
    let temp = isolated_clx_home();
    let clx_dir = temp.path().join(".clx");
    std::fs::create_dir_all(&clx_dir).expect("mk .clx");
    std::fs::write(clx_dir.join("config.yaml"), config_yaml).expect("write config");

    let mut command = Command::new(binary);
    let mut child = harden_command(&mut command, temp.path())
        // Keep credential resolution off the real keychain; the hermetic
        // suite-wide invariant. No provider in these tests reads a secret,
        // but this matches scripts/test.sh and is defense-in-depth.
        .env("CLX_CREDENTIALS_BACKEND", "age")
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

fn decision(v: &serde_json::Value) -> String {
    v["hookSpecificOutput"]["permissionDecision"]
        .as_str()
        .unwrap_or("")
        .to_string()
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

/// Re-open the sandbox audit DB and return rows for a session.
fn audit_rows(home: &Path, session: &str) -> Vec<clx_core::types::AuditLogEntry> {
    let db = home.join(".clx/data/clx.db");
    if !db.exists() {
        return Vec::new();
    }
    let st = Storage::open(&db).expect("open audit db");
    st.get_audit_log_by_session(session).expect("query audit")
}

fn db(home: &Path) -> Storage {
    Storage::open(home.join(".clx/data/clx.db")).expect("open sandbox db")
}

/// Read the file-based LLM health cache from the sandbox `HOME`.
/// Returns `Some("ok")`, `Some("down")`, or `None` if absent.
fn health_marker(home: &Path) -> Option<String> {
    let p = home.join(".clx/data/ollama_health");
    std::fs::read_to_string(p)
        .ok()
        .map(|s| s.trim().to_string())
}

/// A config whose legacy `ollama:` block points L1's chat client at `uri`.
/// `layer1_timeout_ms` is generous unless a test overrides it. Caching on so
/// the cache-write arms execute. `auto_allow_reads` on (the default) so the
/// read-only arms are reachable with a read-only command.
fn cfg_pointing_at(uri: &str, extra_validator: &str) -> String {
    format!(
        "validator:\n  \
           enabled: true\n  \
           layer1_enabled: true\n  \
           cache_enabled: true\n{extra_validator}\
         ollama:\n  \
           host: \"{uri}\"\n  \
           model: \"test-model\"\n  \
           max_retries: 0\n"
    )
}

/// Mount `POST /api/generate` returning the given verdict JSON as the Ollama
/// `response` field, optionally after a delay (to drive the timeout arm).
async fn mount_generate(server: &MockServer, verdict_json: &str, delay_ms: Option<u64>) {
    let mut tmpl = ResponseTemplate::new(200).set_body_raw(
        json!({ "response": verdict_json, "done": true }).to_string(),
        "application/json",
    );
    if let Some(ms) = delay_ms {
        tmpl = tmpl.set_delay(std::time::Duration::from_millis(ms));
    }
    Mock::given(method("POST"))
        .and(path("/api/generate"))
        .respond_with(tmpl)
        .mount(server)
        .await;
}

/// Mount the health probe `GET /api/tags` so `is_available()` returns true.
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

// A command L0 classifies as Ask (not allow-listed, not blacklisted) and
// that is NOT read-only — the path that falls through to the L1 arms.
const ASK_CMD: &str = "frobnicate --apply";

// =========================================================================
// SUB-TASK FIRST: cache-HIT early return — NO provider needed.
// pre_tool_use.rs:223-252
// =========================================================================

/// Pre-seeding a `validation_cache` row makes the hook short-circuit at the
/// L1-CACHE arm with NO LLM client construction at all. Asserts the emitted
/// envelope AND the `L1-CACHE`/`allowed` audit side effect. This is the
/// cheap-win sub-task that has zero production dependency.
#[test]
fn cache_hit_short_circuits_before_any_provider() {
    let temp = isolated_clx_home();
    let clx_dir = temp.path().join(".clx");
    std::fs::create_dir_all(clx_dir.join("data")).expect("mk data dir");
    // A config that would otherwise need a provider (L1 enabled) but points
    // nowhere reachable — proving the cache arm returns *before* that.
    let cfg = "validator:\n  enabled: true\n  layer1_enabled: true\n  \
               cache_enabled: true\nollama:\n  host: \"http://127.0.0.1:1\"\n";
    std::fs::write(clx_dir.join("config.yaml"), cfg).expect("write config");

    let command = "cache_seeded_tool --run";
    let cwd = "/tmp";
    {
        let st = Storage::open(clx_dir.join("data/clx.db")).expect("open db");
        let key = clx_core::policy::compute_cache_key(command, cwd);
        st.cache_decision(&key, "allow", Some("seeded"), Some(2), 3600)
            .expect("seed cache");
    }

    let binary = env!("CARGO_BIN_EXE_clx-hook");
    let env = pre_tool_use("e2e-cachehit", command);
    let mut cmd = Command::new(binary);
    let mut child = harden_command(&mut cmd, temp.path())
        .env("CLX_CREDENTIALS_BACKEND", "age")
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
        "a seeded cache ALLOW must short-circuit before any provider call"
    );
    let rows = audit_rows(temp.path(), "e2e-cachehit");
    assert_eq!(rows.len(), 1, "exactly one L1-CACHE audit row");
    assert_eq!(rows[0].layer, "L1-CACHE", "cache hit audits as L1-CACHE");
    assert_eq!(rows[0].decision.as_str(), "allowed");
}

// =========================================================================
// L1 Allow + cache-write. pre_tool_use.rs:434-460
// =========================================================================

#[tokio::test]
async fn l1_allow_emits_allow_and_writes_cache_and_health_ok() {
    let server = MockServer::start().await;
    mount_health_up(&server).await;
    mount_generate(
        &server,
        r#"{"risk_score":2,"reasoning":"benign tool invocation","category":"safe"}"#,
        None,
    )
    .await;

    let cfg = cfg_pointing_at(&server.uri(), "");
    let env = pre_tool_use("e2e-allow", ASK_CMD);
    let (out, home) = run(&cfg, &env);

    assert_eq!(
        decision(&out),
        "allow",
        "risk_score 2 -> L1 Allow -> emitted envelope must be allow"
    );

    // Side effect 1: an L1/allowed audit row.
    let rows = audit_rows(home.path(), "e2e-allow");
    assert_eq!(rows.len(), 1, "one L1 audit row, got: {rows:?}");
    assert_eq!(rows[0].layer, "L1");
    assert_eq!(rows[0].decision.as_str(), "allowed");

    // Side effect 2: the allow decision was written to the SQLite cache.
    let key = clx_core::policy::compute_cache_key(ASK_CMD, "/tmp");
    let cached = db(home.path())
        .get_cached_decision(&key)
        .expect("cache query")
        .expect("an allow cache row must have been written");
    assert_eq!(cached.decision, "allow", "cached decision must be allow");

    // Side effect 3: a successful LLM interaction marks health "ok".
    assert_eq!(
        health_marker(home.path()).as_deref(),
        Some("ok"),
        "successful L1 must write_health(true)"
    );
}

// =========================================================================
// L1 Deny + track_user_decision (Issue 9: automated denials never learn).
// pre_tool_use.rs:461-487
// =========================================================================

#[tokio::test]
async fn l1_deny_emits_block_and_does_not_learn() {
    let server = MockServer::start().await;
    mount_health_up(&server).await;
    mount_generate(
        &server,
        r#"{"risk_score":9,"reasoning":"irreversible destruction","category":"critical"}"#,
        None,
    )
    .await;

    let cfg = cfg_pointing_at(&server.uri(), "");
    let env = pre_tool_use("e2e-deny", ASK_CMD);
    let (out, home) = run(&cfg, &env);

    assert_eq!(
        decision(&out),
        "deny",
        "risk_score 9 -> L1 Deny -> emitted envelope must be a block"
    );

    let rows = audit_rows(home.path(), "e2e-deny");
    assert_eq!(rows.len(), 1, "one L1 audit row");
    assert_eq!(rows[0].layer, "L1");
    assert_eq!(rows[0].decision.as_str(), "blocked");

    // Issue 9: an AUTOMATED (LLM-originated) L1 deny must NOT learn. The
    // pre-Issue-9 V-R5 contract (deny increments denial_count) now applies
    // only to genuine user rejections; automated denials early-return in
    // track_user_decision (DecisionSource::Automated) so two LLM denials can
    // never auto-blacklist a pattern behind the user's back.
    let pattern = learned_rule_pattern(ASK_CMD);
    assert!(
        db(home.path())
            .get_rule_by_pattern(&pattern)
            .expect("rule query")
            .is_none(),
        "Issue 9: an automated L1 deny must NOT create/track a learned rule"
    );

    // A deny is NOT cached (only allow/ask arms cache); pin that contract.
    let key = clx_core::policy::compute_cache_key(ASK_CMD, "/tmp");
    assert!(
        db(home.path())
            .get_cached_decision(&key)
            .expect("cache query")
            .is_none(),
        "an L1 deny must NOT write a cache row"
    );
}

/// Mirror of the hook's learned-rule pattern format for a plain
/// (non-git/npm/rm/...) command: `Bash(<cmd>:*)` where `<cmd>` is the
/// path-stripped first token (see `learning::extract_command_pattern`). The
/// test addresses the learned-rule row by this observable key rather than
/// importing the crate-private fn. Behavior contract, not an impl import.
fn learned_rule_pattern(command: &str) -> String {
    let raw = command.split_whitespace().next().unwrap_or(command);
    let cmd = std::path::Path::new(raw)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(raw);
    format!("Bash({cmd}:*)")
}

// =========================================================================
// L1 Ask + cache-write (non-read-only -> ask). pre_tool_use.rs:519-544
// =========================================================================

#[tokio::test]
async fn l1_ask_non_readonly_emits_ask_and_caches_ask() {
    let server = MockServer::start().await;
    mount_health_up(&server).await;
    mount_generate(
        &server,
        r#"{"risk_score":5,"reasoning":"ambiguous side effects","category":"caution"}"#,
        None,
    )
    .await;

    // auto_allow_reads off is irrelevant here (cmd is not read-only); keep
    // default. The ASK_CMD is not read-only so the ask branch is taken.
    let cfg = cfg_pointing_at(&server.uri(), "");
    let env = pre_tool_use("e2e-ask", ASK_CMD);
    let (out, home) = run(&cfg, &env);

    assert_eq!(
        decision(&out),
        "ask",
        "risk_score 5 + non-read-only -> emitted envelope must be ask"
    );

    let rows = audit_rows(home.path(), "e2e-ask");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].layer, "L1");
    assert_eq!(rows[0].decision.as_str(), "prompted");

    let key = clx_core::policy::compute_cache_key(ASK_CMD, "/tmp");
    let cached = db(home.path())
        .get_cached_decision(&key)
        .expect("cache query")
        .expect("an ask cache row must have been written");
    assert_eq!(
        cached.decision, "ask",
        "the ask arm must cache an 'ask' decision (not allow)"
    );
}

// =========================================================================
// READ-ONLY auto-allow precedence (pins the structural reason the L1-READ
// arm at pre_tool_use.rs:488-518 is unreachable via *any* hook input).
//
// `is_read_only` is computed ONCE (pre_tool_use.rs:155) and the L0-Ask
// branch (pre_tool_use.rs:204-217) returns early with an `L0-READ` audit
// whenever it is true. L0 Allow/Deny also return early. Therefore reaching
// the L1-READ branch (`:491`, the `if is_read_only` inside the L1 Ask arm)
// would require `is_read_only == true` AND L0 to NOT have returned — which
// no input can satisfy. The L1-READ arm is dead via `handle_pre_tool_use`;
// closing it would need a logic change to `pre_tool_use.rs` beyond a thin
// injection wrapper, which is out of this stream's ownership (reported).
//
// This test pins the *observable* contract that makes it dead: a read-only
// command that L0 leaves as Ask is auto-allowed at L0 (`L0-READ`), never
// reaching L1 — so even with a wiremock provider configured, no `/api/*`
// call is made.
// =========================================================================

#[tokio::test]
async fn readonly_command_is_auto_allowed_at_l0_never_reaching_l1() {
    let server = MockServer::start().await;
    // Mount BOTH endpoints; if the hook reached L1 these would be hit. The
    // contract is that they are NOT (L0-READ short-circuit precedence).
    mount_health_up(&server).await;
    mount_generate(
        &server,
        r#"{"risk_score":9,"reasoning":"would deny if reached","category":"critical"}"#,
        None,
    )
    .await;

    // `jq` is read-only (policy::read_only) but is NOT in the L0
    // deterministic whitelist, so L0 returns Ask -> the `:204` L0-READ
    // auto-allow branch fires (a whitelisted read-only cmd like `cat`
    // would instead return at the plain L0 Allow arm).
    let readonly_cmd = "jq . /tmp/nope.json";
    let cfg = cfg_pointing_at(&server.uri(), "");
    let env = pre_tool_use("e2e-l0read", readonly_cmd);
    let (out, home) = run(&cfg, &env);

    assert_eq!(
        decision(&out),
        "allow",
        "a read-only command is auto-allowed before L1 even though the \
         provider verdict would be deny"
    );

    let rows = audit_rows(home.path(), "e2e-l0read");
    assert_eq!(rows.len(), 1, "exactly one audit row");
    assert_eq!(
        rows[0].layer, "L0-READ",
        "read-only auto-allow happens at L0 (precedence over L1); the \
         L1-READ arm is consequently unreachable via any input"
    );
    assert_eq!(rows[0].decision.as_str(), "allowed");

    // Proof the provider was never consulted: no decision was cached
    // (the L0-READ arm does not cache) and health stayed Unknown (no probe).
    let key = clx_core::policy::compute_cache_key(readonly_cmd, "/tmp");
    assert!(
        db(home.path())
            .get_cached_decision(&key)
            .expect("cache query")
            .is_none(),
        "L0-READ short-circuit must not write a cache row"
    );
    assert_eq!(
        health_marker(home.path()),
        None,
        "L0-READ short-circuit must never probe the provider (no health write)"
    );
}

// =========================================================================
// L1 timeout arm + write_health(false). pre_tool_use.rs:374-400
// =========================================================================

#[tokio::test]
async fn l1_timeout_applies_default_decision_and_marks_health_down() {
    let server = MockServer::start().await;
    mount_health_up(&server).await;
    // Generate responds, but only after 1500ms — far beyond the 150ms L1
    // budget below — so tokio::time::timeout fires.
    mount_generate(
        &server,
        r#"{"risk_score":2,"reasoning":"would be allow","category":"safe"}"#,
        Some(1500),
    )
    .await;

    // default_decision: deny so the timeout fallback is observable as a block
    // (distinct from the default Ask).
    let cfg = cfg_pointing_at(
        &server.uri(),
        "  layer1_timeout_ms: 150\n  default_decision: \"deny\"\n",
    );
    let env = pre_tool_use("e2e-timeout", ASK_CMD);
    let (out, home) = run(&cfg, &env);

    assert_eq!(
        decision(&out),
        "deny",
        "an L1 timeout must apply default_decision (deny here), not the \
         would-be allow verdict"
    );

    let rows = audit_rows(home.path(), "e2e-timeout");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].layer, "L1");
    assert_eq!(rows[0].decision.as_str(), "blocked");

    // The timeout arm explicitly writes health=false.
    assert_eq!(
        health_marker(home.path()).as_deref(),
        Some("down"),
        "the L1 timeout arm must write_health(false)"
    );

    // A timeout fallback must not be cached.
    let key = clx_core::policy::compute_cache_key(ASK_CMD, "/tmp");
    assert!(
        db(home.path())
            .get_cached_decision(&key)
            .expect("cache query")
            .is_none(),
        "timeout fallback must not write a cache row"
    );
}

// =========================================================================
// LLM-unavailable post-call arm: generate() errors -> Ask("LLM unavailable")
// -> default_decision fallback + write_health(false).
// pre_tool_use.rs:405-429
// =========================================================================

#[tokio::test]
async fn l1_generate_error_falls_back_and_marks_health_down() {
    let server = MockServer::start().await;
    mount_health_up(&server).await;
    // /api/generate returns HTTP 500 -> evaluate_with_llm yields
    // Ask("LLM unavailable") -> the hook's post-call fallback arm.
    Mock::given(method("POST"))
        .and(path("/api/generate"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;

    let cfg = cfg_pointing_at(&server.uri(), "  default_decision: \"deny\"\n");
    let env = pre_tool_use("e2e-generr", ASK_CMD);
    let (out, home) = run(&cfg, &env);

    assert_eq!(
        decision(&out),
        "deny",
        "a failed generate() must converge on default_decision (deny)"
    );

    let rows = audit_rows(home.path(), "e2e-generr");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].layer, "L1");
    assert_eq!(rows[0].decision.as_str(), "blocked");

    assert_eq!(
        health_marker(home.path()).as_deref(),
        Some("down"),
        "the LLM-unavailable post-call arm must write_health(false)"
    );
}

// =========================================================================
// Client-unavailable fallback: is_available() == false (no /api/tags mock,
// server up but 404s the probe) -> default_decision fallback.
// pre_tool_use.rs:328-353
// =========================================================================

#[tokio::test]
async fn l1_client_unavailable_falls_back_to_default_decision() {
    let server = MockServer::start().await;
    // Health probe GET /api/tags is NOT mounted -> wiremock 404 ->
    // is_available() == false -> the !ollama_available fallback arm.
    // (No generate mock either; it must never be reached.)
    let cfg = cfg_pointing_at(&server.uri(), "  default_decision: \"deny\"\n");
    let env = pre_tool_use("e2e-unavail", ASK_CMD);
    let (out, home) = run(&cfg, &env);

    assert_eq!(
        decision(&out),
        "deny",
        "an unavailable client must apply default_decision (deny)"
    );

    let rows = audit_rows(home.path(), "e2e-unavail");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].layer, "L1");
    assert_eq!(
        rows[0].decision.as_str(),
        "blocked",
        "client-unavailable fallback with default_decision=deny audits blocked"
    );
}
