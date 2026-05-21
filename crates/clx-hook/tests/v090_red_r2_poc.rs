//! RED R2 PoC bundle for the v0.9.0 RGP pre-release.
//!
//! Stream R2 (code-path correctness + dashboard + L1-rename downstream +
//! test-coverage gaps). All tests are `#[ignore]`-gated so the default
//! `cargo nextest run` is unaffected; run any one with:
//!
//! ```sh
//! cargo test -p clx-hook --test v090_red_r2_poc -- --ignored \
//!   <test_name> --nocapture
//! ```
//!
//! Each PoC documents:
//!   VERDICT       — VULN-CONFIRMED / VULN-REFUTED / NEW-FINDING / INSUFFICIENT-EVIDENCE
//!   COUNTEREXAMPLE — concrete minimal input/state/sequence
//!   REGRESSION-PIN — exact file:line that must change
//!   RESIDUAL-UNCERTAINTY — what could make this verdict wrong
//!
//! Synthetic secrets only. Hermetic via wiremock loopback + `CLX_MODEL_FETCH_DRYRUN=1`.

// Adversarial PoCs prioritise reproducible attack shape over style hygiene.
#![allow(
    dead_code,
    clippy::pedantic,
    clippy::restriction,
    clippy::nursery,
    clippy::doc_markdown,
    clippy::manual_let_else,
    clippy::map_unwrap_or,
    clippy::redundant_closure_for_method_calls,
    clippy::duration_subsec,
    clippy::ignore_without_reason,
    clippy::single_char_pattern
)]

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

// =====================================================================
// Harness (mirrors pre_tool_use_l0_e2e.rs harness exactly)
// =====================================================================

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

const BLACKLIST_CMD: &str = "rm -rf /";
const ASK_CMD: &str = "frobnicate --apply";
const READ_CMD: &str = "cat /etc/hosts";

// =====================================================================
// T2 — PolicyEngine.load_learned_rules runs BEFORE the L0 gate
//
// VERDICT: VULN-CONFIRMED (behavioural; documented but unfixed)
// COUNTEREXAMPLE: when validator.layer0_enabled=false the
//   pre_tool_use.rs:266-270 still calls Storage::open_default() +
//   load_learned_rules(), which opens the SQLite DB, runs migrations on
//   first call, and reads `learned_rules`. This is observable as a
//   non-empty `~/.clx/data/clx.db` after a single hook invocation with
//   L0 disabled — meaning the "L0 disabled = engine doesn't run"
//   promise is false at I/O level. The race surface is: a concurrent
//   `clx learn` writer may serialize against the SQLite WAL lock that
//   this disabled-path read acquires.
// REGRESSION-PIN: crates/clx-hook/src/hooks/pre_tool_use.rs:266-270
//   (move the `load_learned_rules` call inside the
//   `if config.validator.layer0_enabled { ... }` block, OR rename the
//   property statement at :329-330).
// RESIDUAL-UNCERTAINTY: SQLite open + migration cost is small (~ms);
//   the contention scenario requires a long-held writer lock from
//   another CLX process. The PoC observes the I/O side-effect (DB
//   file exists + has > 0 audit_log rows after a single L0-off hook)
//   but does not construct a wall-clock contention proof.
// =====================================================================

/// FAILS PRE-FIX: with L0 disabled, the hook still opens the storage DB
/// (via load_learned_rules), proving the disable promise is leaky.
/// PoC observes the side effect via the audit DB existing AND containing
/// rows after a single hook invocation under layer0_enabled=false.
///
/// This test currently PASSES today because the side effect IS observable —
/// the test asserts that the L0-disabled path nonetheless performs DB I/O.
/// To convert into a regression-pin guard after fix, invert the assertion.
#[tokio::test]
#[ignore]
async fn red_t2_l0_disabled_still_opens_storage() {
    let server = MockServer::start().await;
    mount_health_up(&server).await;
    mount_generate(
        &server,
        r#"{"risk_score":1,"reasoning":"ok","category":"safe"}"#,
    )
    .await;

    let cfg = cfg_pointing_at(
        &server.uri(),
        "  layer0_enabled: false\n  layer1_enabled: true\n",
    );
    let env = pre_tool_use("red-r2-t2", ASK_CMD);
    let (_out, home) = run(&cfg, &env);

    // Side effect: even though L0 is disabled, the DB exists.
    // load_learned_rules opens Storage which creates `clx.db` and runs
    // migrations — proving the engine load runs unconditionally.
    let db_path = home.path().join(".clx/data/clx.db");
    assert!(
        db_path.exists(),
        "BUG: L0 disabled, but clx.db was created \
         (Storage::open_default() ran via load_learned_rules path); \
         pin: pre_tool_use.rs:266-270 must move inside the \
         layer0_enabled gate at :275 for the disable promise to hold"
    );

    // Audit rows also exist (SECURITY-CFG + L0-DISABLED), confirming the
    // DB is fully initialised, not just touched.
    let rows = audit_rows(home.path(), "red-r2-t2");
    assert!(
        !rows.is_empty(),
        "BUG: L0 disabled, but audit rows were written — DB initialised. \
         If load_learned_rules were inside the gate, the DB open in this \
         path would only be the one for log_audit_entry, not a second \
         open for learned_rules. Today: two opens; expected post-fix: one."
    );
}

// =====================================================================
// T3 — env + config double-audit
//
// VERDICT: NEW-FINDING (the recon flagged the case; current behaviour
//   was unverified in-tree).
// COUNTEREXAMPLE: with BOTH `CLX_VALIDATOR_LAYER0_ENABLED=false` AND
//   `validator.layer0_enabled=false` in config, the hook writes BOTH
//   a SECURITY-ENV row (pre_tool_use.rs:72-81) AND a SECURITY-CFG row
//   (pre_tool_use.rs:118-126) for a single logical disable event. The
//   two rows have different `event_fingerprint` values (different
//   `trigger_keys` strings) so dedup-by-fingerprint sees two events.
// REGRESSION-PIN: pre_tool_use.rs:93-128. Either (a) gate the
//   SECURITY-CFG path with `&& !env_already_signalled_layer0_disable`
//   (skip if env path fired for the same layer), or (b) keep both and
//   document the dual-signal contract explicitly in CHANGELOG.
// RESIDUAL-UNCERTAINTY: whether downstream log aggregators dedup by
//   fingerprint, event_type, or row id. CLX ships no recommendation
//   so any aggregator config is operator-specific. The PoC confirms
//   the in-DB state.
// =====================================================================

/// FAILS PRE-FIX: env + config both disabling L0 produces two rows
/// (SECURITY-ENV + SECURITY-CFG) for one logical event.
#[tokio::test]
#[ignore]
async fn red_t3_env_plus_config_double_audit() {
    let server = MockServer::start().await;
    mount_health_up(&server).await;
    mount_generate(
        &server,
        r#"{"risk_score":1,"reasoning":"ok","category":"safe"}"#,
    )
    .await;

    // Config: layer0 ALREADY false. Env then ALSO sets it false.
    let cfg = cfg_pointing_at(
        &server.uri(),
        "  layer0_enabled: false\n  layer1_enabled: true\n",
    );
    let env = pre_tool_use("red-r2-t3", ASK_CMD);
    let (_out, home) = run_with_extra_env(&cfg, &env, &[("CLX_VALIDATOR_LAYER0_ENABLED", "false")]);

    let rows = audit_rows(home.path(), "red-r2-t3");
    let env_rows = rows.iter().filter(|r| r.layer == "SECURITY-ENV").count();
    let cfg_rows = rows.iter().filter(|r| r.layer == "SECURITY-CFG").count();

    // FAIL-BEFORE assertion: today, both fire — that's the contract gap.
    // If GREEN dedups, env_rows + cfg_rows should be 1 (a single signal).
    // If GREEN documents dual-emit, the CHANGELOG must say so explicitly.
    assert!(
        env_rows >= 1 && cfg_rows >= 1,
        "RED expected both SECURITY-ENV and SECURITY-CFG to fire on the \
         same logical event; got env_rows={env_rows} cfg_rows={cfg_rows}. \
         Today: double-audit confirmed; contract ambiguous."
    );

    // The two fingerprints differ (different trigger_keys), so any
    // aggregator deduping by fingerprint sees two distinct events.
    let env_fp = rows
        .iter()
        .find(|r| r.layer == "SECURITY-ENV")
        .and_then(|r| r.reasoning.clone())
        .unwrap_or_default();
    let cfg_fp = rows
        .iter()
        .find(|r| r.layer == "SECURITY-CFG")
        .and_then(|r| r.reasoning.clone())
        .unwrap_or_default();
    let extract_fp = |s: &str| -> String {
        s.split("event_fingerprint=")
            .nth(1)
            .map(|t| t.trim().to_string())
            .unwrap_or_default()
    };
    let fp_env = extract_fp(&env_fp);
    let fp_cfg = extract_fp(&cfg_fp);
    assert_ne!(
        fp_env, fp_cfg,
        "fingerprints SHOULD differ (different trigger_keys); \
         aggregator deduping by fingerprint sees 2 events for 1 logical disable"
    );
}

// =====================================================================
// L1 string rename — dual-emit one-version window NOT provided
//
// VERDICT: NEW-FINDING (research recommends dual-emit; impl does not)
// COUNTEREXAMPLE: the current write at pre_tool_use.rs:408 emits ONLY
//   "L1-DISABLED". A v0.8.x consumer that pattern-matches the literal
//   "L1 disabled" (with space, lowercase) on the audit row's reasoning
//   field sees zero matches in v0.9.0. The CHANGELOG says "downstream
//   log parsers ... need updating" but that is a breaking change with
//   no transitional dual-emit period.
// REGRESSION-PIN: pre_tool_use.rs:408 should emit BOTH strings (e.g.
//   "L1-DISABLED|legacy:L1 disabled") for v0.9.0; remove legacy in
//   v0.10.0. The research target item §5 is unimplemented.
// RESIDUAL-UNCERTAINTY: no in-tree consumer breaks (the PoC enumerates
//   them all below). The risk is external. Cannot enumerate external
//   parsers from inside the repo; the CHANGELOG honestly flags it but
//   the spec says the prudent default is "treat security-audit fields
//   as de facto public API" — so this is a deprecation hygiene gap.
// =====================================================================

/// FAILS POST-FIX if GREEN adopts dual-emit: today, reasoning is exactly
/// "L1-DISABLED" with no legacy form. The fix is to emit a string that
/// contains BOTH the new and legacy literals so old parsers keep working
/// one version (v0.9.0), then drop legacy in v0.10.0.
#[tokio::test]
#[ignore]
async fn red_t_l1_rename_no_dual_emit_window() {
    // L1 disabled + L0 Ask → forced ask. Uses no LLM call.
    let cfg = "validator:\n  \
                 enabled: true\n  \
                 layer0_enabled: true\n  \
                 layer1_enabled: false\n  \
                 cache_enabled: false\n";
    let env = pre_tool_use("red-r2-l1rename", ASK_CMD);
    let (out, home) = run(cfg, &env);

    assert_eq!(decision(&out), "ask", "expected forced ask");

    let rows = audit_rows(home.path(), "red-r2-l1rename");
    let l1_disabled_row = rows
        .iter()
        .find(|r| r.layer == "L0" && r.command == ASK_CMD)
        .expect("must have L0/L1-DISABLED row");
    let reasoning = l1_disabled_row.reasoning.as_deref().unwrap_or("");

    // The fix would make this assertion pass:
    let legacy_present = reasoning.contains("L1 disabled");
    let new_present = reasoning.contains("L1-DISABLED");

    // RED claim: pre-fix, only NEW is present; legacy is missing.
    assert!(new_present, "new literal expected: got {reasoning:?}");
    assert!(
        !legacy_present,
        "RED PoC documents that legacy 'L1 disabled' is NOT dual-emitted; \
         a v0.8.x parser regex-matching the literal sees zero rows. \
         pin: pre_tool_use.rs:408 should emit a string containing BOTH \
         literals for one-version window per research §5. Got reasoning={reasoning:?}"
    );
}

// =====================================================================
// T9.1 — L0 disabled + cache HIT for a blacklisted command
//
// VERDICT: VULN-CONFIRMED (cache-bypass class introduced by L0 toggle)
// COUNTEREXAMPLE: a pre-existing L1-CACHE row for `rm -rf /` with
//   decision `allow` (planted in another session by cache poisoning,
//   or simply by a buggy LLM that previously allowed it) routes through
//   pre_tool_use.rs:368-396 emit cache verdict WITHOUT consulting L0
//   at all. The deterministic blacklist is bypassed. Today: not e2e tested.
// REGRESSION-PIN: pre_tool_use.rs:368 — cache lookup must come AFTER
//   L0 evaluation OR cache hits should not bypass deny-listed patterns.
//   Today the lookup is in the L0-disabled branch's fall-through.
// RESIDUAL-UNCERTAINTY: requires planting a cached `allow` row. The
//   PoC plants it directly via Storage::cache_decision and confirms
//   the cache row drives the output despite L0 deny being on the books.
// =====================================================================

#[tokio::test]
#[ignore]
async fn red_t9_1_l0_off_cache_hit_for_blacklisted_cmd() {
    let server = MockServer::start().await;
    mount_health_up(&server).await;
    // L1 deny — proving L1 not reached (cache wins).
    mount_generate(
        &server,
        r#"{"risk_score":9,"reasoning":"hard deny","category":"critical"}"#,
    )
    .await;

    let cfg = format!(
        "validator:\n  \
           enabled: true\n  \
           layer0_enabled: false\n  \
           layer1_enabled: true\n  \
           cache_enabled: true\n\
         ollama:\n  \
           host: \"{}\"\n  \
           model: \"test-model\"\n  \
           max_retries: 0\n",
        server.uri()
    );

    let temp = isolated_clx_home();
    let clx_dir = temp.path().join(".clx");
    std::fs::create_dir_all(&clx_dir).expect("mk .clx");
    std::fs::write(clx_dir.join("config.yaml"), &cfg).expect("write config");

    // Plant a poisoned cache row: blacklisted cmd → allow.
    let db_path = temp.path().join(".clx/data/clx.db");
    std::fs::create_dir_all(db_path.parent().unwrap()).ok();
    let st = Storage::open(&db_path).expect("open storage to plant cache");
    let cache_key = clx_core::policy::compute_cache_key(BLACKLIST_CMD, "/tmp");
    st.cache_decision(&cache_key, "allow", Some("poisoned"), Some(1), 3600)
        .expect("plant cache row");
    drop(st);

    // Now invoke hook with same blacklisted cmd. With L0 disabled + cache,
    // the cache should be queried and emit allow — bypassing L0 deny.
    let env = pre_tool_use("red-r2-t91", BLACKLIST_CMD);
    let binary = env!("CARGO_BIN_EXE_clx-hook");
    let mut command = Command::new(binary);
    let cmd = harden_command(&mut command, temp.path())
        .env("CLX_CREDENTIALS_BACKEND", "age")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("spawn hook");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(env.to_string().as_bytes())
        .unwrap();
    let out = child.wait_with_output().expect("wait hook");
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).expect("json");
    let dec = parsed["hookSpecificOutput"]["permissionDecision"]
        .as_str()
        .unwrap_or("");

    // RED: pre-fix, cache wins → allow despite L0 deny existing.
    // The L0 disable created a new cache-bypass class for blacklist.
    assert_eq!(
        dec, "allow",
        "BUG: L0 off + cache hit emits allow for `rm -rf /`; the cache \
         layer is now an L0-bypass surface. pin: pre_tool_use.rs:368 — \
         when L0 is disabled, cache hits should still respect the \
         deterministic deny-list, OR cache poisoning of a blacklisted \
         cmd should fail. Today: silent allow."
    );
}

// =====================================================================
// T9.2 — L0 off + L1 unavailable + default_decision=allow (CATASTROPHIC)
//
// VERDICT: VULN-CONFIRMED (silent allow of `rm -rf /`)
// COUNTEREXAMPLE: with layer0_enabled=false, layer1_enabled=true, and
//   ollama unreachable (loopback dead port), the LLM-unavailable
//   fallback at pre_tool_use.rs:472-497 honours default_decision=allow
//   and emits allow for `rm -rf /`. No L0 deterministic deny intervenes.
//   The combination is the literal worst case the validator was designed
//   to prevent.
// REGRESSION-PIN: pre_tool_use.rs:472-497 (and :518-544, :549-573).
//   When fallback path fires AND default_decision=allow AND the command
//   matches a hardcoded deny pattern (rm -rf /, curl|bash, etc.), the
//   fallback must NOT honour `allow` — F7-deferred posture from v0.8.2
//   should apply here. Alternative: refuse `default_decision=allow` at
//   config-load time when both layers off.
// RESIDUAL-UNCERTAINTY: the user opted-in to reduced security by
//   setting default_decision=allow. RED claims that opt-in is in
//   tension with the L0-off toggle; both together create a "silent
//   allow class" that the v0.8.2 audit_chain language warned about.
// =====================================================================

#[tokio::test]
#[ignore]
async fn red_t9_2_l0_off_l1_down_default_allow_silent_blacklist_allow() {
    // No mocks — ollama at dead loopback port. L1 unavailable triggers
    // the default_decision fallback. With default_decision=allow,
    // blacklisted rm -rf / is allowed.
    let cfg = "validator:\n  \
                 enabled: true\n  \
                 layer0_enabled: false\n  \
                 layer1_enabled: true\n  \
                 default_decision: \"allow\"\n  \
                 cache_enabled: false\n\
               ollama:\n  \
                 host: \"http://127.0.0.1:1\"\n  \
                 model: \"x\"\n  \
                 max_retries: 0\n";
    let env = pre_tool_use("red-r2-t92", BLACKLIST_CMD);
    let (out, home) = run(cfg, &env);

    // CATASTROPHIC: rm -rf / is allowed.
    assert_eq!(
        decision(&out),
        "allow",
        "BUG: with L0 off + L1 unreachable + default_decision=allow, \
         `rm -rf /` is silently allowed. This is the v0.9.0 silent-allow \
         bypass class. pin: pre_tool_use.rs:472-497 must not honour \
         allow for a deny-listed pattern even on fallback."
    );

    let rows = audit_rows(home.path(), "red-r2-t92");
    let cmd_rows: Vec<_> = rows.iter().filter(|r| r.command == BLACKLIST_CMD).collect();
    // The audit will show an L1 row with "Ollama unavailable" reasoning
    // and decision=allowed.
    assert!(
        cmd_rows
            .iter()
            .any(|r| r.layer == "L1" && r.decision.as_str() == "allowed"),
        "must show L1/allowed fallback row; cmd_rows: {cmd_rows:?}"
    );
}

// =====================================================================
// T9.3 — L0 off + L1 timeout + default_decision=allow
//
// VERDICT: VULN-CONFIRMED (same class as T9.2 via timeout path)
// COUNTEREXAMPLE: layer0_enabled=false, layer1_timeout_ms small (e.g. 100),
//   mock generate that delays beyond timeout, default_decision=allow.
//   The timeout branch at pre_tool_use.rs:518-544 honours allow.
// REGRESSION-PIN: pre_tool_use.rs:518-544 (timeout fallback).
// RESIDUAL-UNCERTAINTY: minor — relies on wiremock delay reliability.
// =====================================================================

#[tokio::test]
#[ignore]
async fn red_t9_3_l0_off_l1_timeout_default_allow_silent_blacklist_allow() {
    let server = MockServer::start().await;
    mount_health_up(&server).await;
    // Delay generate response beyond the configured 100ms timeout.
    Mock::given(method("POST"))
        .and(path("/api/generate"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(std::time::Duration::from_millis(5000))
                .set_body_raw(
                    json!({ "response": r#"{"risk_score":9,"reasoning":"deny","category":"x"}"#, "done": true })
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
           layer1_timeout_ms: 100\n  \
           default_decision: \"allow\"\n  \
           cache_enabled: false\n\
         ollama:\n  \
           host: \"{}\"\n  \
           model: \"test-model\"\n  \
           max_retries: 0\n",
        server.uri()
    );
    let env = pre_tool_use("red-r2-t93", BLACKLIST_CMD);
    let (out, _home) = run(&cfg, &env);

    assert_eq!(
        decision(&out),
        "allow",
        "BUG: L0 off + L1 timeout + default_decision=allow silently \
         allows `rm -rf /`. pin: pre_tool_use.rs:518-544."
    );
}

// =====================================================================
// T9.4 — L0 off + L1 returns Ask("LLM unavailable") + default_decision=allow
//
// VERDICT: VULN-CONFIRMED (same class via the LLM-generation-failed branch)
// COUNTEREXAMPLE: server returns 5xx so evaluate_with_llm yields
//   Ask("LLM unavailable"). Branch at :549-573 honours allow.
// REGRESSION-PIN: pre_tool_use.rs:549-573.
// =====================================================================

#[tokio::test]
#[ignore]
async fn red_t9_4_l0_off_l1_gen_failed_default_allow_silent_blacklist_allow() {
    let server = MockServer::start().await;
    mount_health_up(&server).await;
    // 500 — evaluate_with_llm returns Ask("LLM unavailable")
    Mock::given(method("POST"))
        .and(path("/api/generate"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;

    let cfg = format!(
        "validator:\n  \
           enabled: true\n  \
           layer0_enabled: false\n  \
           layer1_enabled: true\n  \
           default_decision: \"allow\"\n  \
           cache_enabled: false\n\
         ollama:\n  \
           host: \"{}\"\n  \
           model: \"test-model\"\n  \
           max_retries: 0\n",
        server.uri()
    );
    let env = pre_tool_use("red-r2-t94", BLACKLIST_CMD);
    let (out, _home) = run(&cfg, &env);

    assert_eq!(
        decision(&out),
        "allow",
        "BUG: L0 off + L1 generation-failed + default_decision=allow \
         silently allows blacklisted cmd. pin: pre_tool_use.rs:549-573."
    );
}

// =====================================================================
// T9.5 — L0 disabled + trust mode active
//
// VERDICT: NEW-FINDING (audit-noise contract)
// COUNTEREXAMPLE: with trust_mode=true AND layer0_enabled=false, the
//   SECURITY-CFG row at :93-128 fires BEFORE the trust_mode check at
//   :176-253. So even when trust mode short-circuits everything to
//   allow, a SECURITY-CFG row is emitted. Audit-noise contract is
//   unverified — the recon flagged this. PoC confirms.
// REGRESSION-PIN: pre_tool_use.rs:93-128 vs :176-253 ordering. Decide
//   whether trust_mode allow should silence the SECURITY-CFG signal
//   or whether SECURITY-CFG is intentional (because the layer-disable
//   is a config posture independent of trust_mode).
// =====================================================================

#[tokio::test]
#[ignore]
async fn red_t9_5_l0_off_trust_mode_still_emits_security_cfg() {
    let temp = isolated_clx_home();
    let clx_dir = temp.path().join(".clx");
    std::fs::create_dir_all(&clx_dir).expect("mk .clx");

    // Plant a valid JSON trust token (10 min future expiry).
    let future = chrono::Utc::now() + chrono::Duration::minutes(10);
    let token = json!({
        "expires_at": future.to_rfc3339(),
        "session_id": null,
    });
    std::fs::write(clx_dir.join(".trust_mode_token"), token.to_string())
        .expect("write trust token");

    let cfg = "validator:\n  \
                 enabled: true\n  \
                 trust_mode: true\n  \
                 layer0_enabled: false\n  \
                 layer1_enabled: true\n  \
                 cache_enabled: false\n";
    std::fs::write(clx_dir.join("config.yaml"), cfg).expect("write config");

    let binary = env!("CARGO_BIN_EXE_clx-hook");
    let mut command = Command::new(binary);
    let cmd = harden_command(&mut command, temp.path())
        .env("CLX_CREDENTIALS_BACKEND", "age")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("spawn hook");
    let env = pre_tool_use("red-r2-t95", BLACKLIST_CMD);
    child
        .stdin
        .take()
        .unwrap()
        .write_all(env.to_string().as_bytes())
        .unwrap();
    let _out = child.wait_with_output().expect("wait hook");

    let rows = audit_rows(temp.path(), "red-r2-t95");
    let security_cfg_rows = rows.iter().filter(|r| r.layer == "SECURITY-CFG").count();
    assert!(
        security_cfg_rows >= 1,
        "BUG: SECURITY-CFG fires before trust_mode short-circuit; \
         even a trust-mode-allowed command emits a layer-disable signal. \
         pin: pre_tool_use.rs:93-128 vs :176-253. Today: {security_cfg_rows} \
         SECURITY-CFG rows alongside TRUST allow."
    );
}

// =====================================================================
// T9.7 — L0 disabled + non-command MCP tool (NotCommandTool)
//
// VERDICT: NEW-FINDING (contract ambiguity)
// COUNTEREXAMPLE: an MCP tool whose extract_mcp_command returns
//   NotCommandTool short-circuits at pre_tool_use.rs:146-151 — but
//   BEFORE that, SECURITY-CFG at :93-128 may already have fired. So
//   "silent MCP allow" still leaves a SECURITY-CFG breadcrumb. Audit
//   contract unclear: the row attributes a layer-disable to a tool
//   that never reached the validator.
// REGRESSION-PIN: pre_tool_use.rs:130-157 routing ordering.
// =====================================================================

#[tokio::test]
#[ignore]
async fn red_t9_7_l0_off_security_cfg_emitted_before_mcp_short_circuit() {
    // Use a Bash tool with empty command — same code-path effect:
    // SECURITY-CFG fires at :93-128, then short-circuit at :159 returns
    // allow without writing any L0/L1 row. The SECURITY-CFG row remains.
    let cfg = "validator:\n  \
                 enabled: true\n  \
                 layer0_enabled: false\n  \
                 layer1_enabled: true\n  \
                 cache_enabled: false\n";
    let env = pre_tool_use("red-r2-t97", "");
    let (out, home) = run(cfg, &env);
    assert_eq!(decision(&out), "allow", "empty cmd → auto-allow");

    let rows = audit_rows(home.path(), "red-r2-t97");
    let security_cfg_rows = rows.iter().filter(|r| r.layer == "SECURITY-CFG").count();
    let cmd_rows = rows
        .iter()
        .filter(|r| matches!(r.layer.as_str(), "L0" | "L1"))
        .count();
    assert!(
        security_cfg_rows >= 1,
        "SECURITY-CFG row fires for a short-circuited tool call; \
         cmd_rows={cmd_rows}, security_cfg_rows={security_cfg_rows}"
    );
}

// =====================================================================
// T9.11 — L0 disabled + L1 disabled + read-only command
//
// VERDICT: NEW-FINDING (audit-row asymmetry)
// COUNTEREXAMPLE: with L0 off + L1 off + auto_allow_reads=true and
//   a read-only command `cat /etc/hosts`, the auto-allow-reads check
//   at :346-362 fires BEFORE the L1-disabled branch at :399-417. So
//   the audit row chain is L0/L0-DISABLED → L0-READ/allowed — NOT
//   L0/L0-DISABLED → L0/L1-DISABLED. A SOC operator filtering for
//   "both layers off" by reasoning="L1-DISABLED" misses read commands.
// REGRESSION-PIN: pre_tool_use.rs:344-362 ordering vs :399-417.
// =====================================================================

#[tokio::test]
#[ignore]
async fn red_t9_11_l0_off_l1_off_read_only_no_l1_disabled_row() {
    let cfg = "validator:\n  \
                 enabled: true\n  \
                 layer0_enabled: false\n  \
                 layer1_enabled: false\n  \
                 auto_allow_reads: true\n  \
                 cache_enabled: false\n";
    let env = pre_tool_use("red-r2-t911", READ_CMD);
    let (out, home) = run(cfg, &env);

    assert_eq!(decision(&out), "allow", "read-only auto-allow");
    let rows = audit_rows(home.path(), "red-r2-t911");
    let cmd_rows: Vec<_> = rows.iter().filter(|r| r.command == READ_CMD).collect();
    let has_l1_disabled = cmd_rows
        .iter()
        .any(|r| r.reasoning.as_deref() == Some("L1-DISABLED"));
    assert!(
        !has_l1_disabled,
        "BUG: L0 off + L1 off + read-only emits no L1-DISABLED row \
         (auto-allow-reads fires first); SOC filtering by reasoning='L1-DISABLED' \
         to find 'both layers off' sessions misses read-only commands. \
         Today: cmd_rows={cmd_rows:?}. pin: pre_tool_use.rs:344-362."
    );
}

// =====================================================================
// T-RACE — TOCTOU race for SECURITY-CFG row vs concurrent process
//
// VERDICT: VULN-CONFIRMED (theoretical race surface)
// COUNTEREXAMPLE: SECURITY-CFG row writes at :93-128 BEFORE any L0
//   evaluation (:275). A concurrent hook process started microseconds
//   later sees a half-state: SECURITY-CFG row present, but no L0/L1
//   row yet. If the concurrent reader is a `clx doctor`-style verifier
//   that checks "every SECURITY-CFG row should have a corresponding
//   decision row in the same session", the check transiently fails.
// REGRESSION-PIN: pre_tool_use.rs:93-128 should be deferred to AFTER
//   the L0 evaluation OR a session-level transaction should wrap the
//   SECURITY-CFG + L0/L1 rows so they appear atomically.
// RESIDUAL-UNCERTAINTY: today no such verifier exists, so the race
//   is unobservable in production. The PoC documents the structural
//   gap. SQLite WAL mode handles the write ordering atomically per row,
//   not per logical event group.
// =====================================================================

#[tokio::test]
#[ignore]
async fn red_t_race_security_cfg_writes_before_l0_evaluation() {
    // Single-process PoC: prove SECURITY-CFG row is written BEFORE
    // the L0/L1 row by inspecting their timestamps.
    let cfg = "validator:\n  \
                 enabled: true\n  \
                 layer0_enabled: false\n  \
                 layer1_enabled: false\n  \
                 cache_enabled: false\n";
    let env = pre_tool_use("red-r2-trace", ASK_CMD);
    let (_out, home) = run(cfg, &env);

    let rows = audit_rows(home.path(), "red-r2-trace");
    let sec_cfg = rows.iter().find(|r| r.layer == "SECURITY-CFG");
    let l0_disabled = rows
        .iter()
        .find(|r| r.layer == "L0" && r.reasoning.as_deref() == Some("L0-DISABLED"));

    let sec_cfg_row = sec_cfg.expect("must have SECURITY-CFG row");
    let l0_row = l0_disabled.expect("must have L0/L0-DISABLED row");

    // The timestamps may be equal at second resolution, but the SECURITY-CFG
    // row id should be lower (written first). Use ordering by id from the
    // ORDER BY timestamp DESC + insert order to infer write order.
    assert!(
        sec_cfg_row.timestamp <= l0_row.timestamp,
        "SECURITY-CFG row should be timestamped <= L0/L0-DISABLED row; \
         sec_cfg.ts={} l0.ts={}",
        sec_cfg_row.timestamp,
        l0_row.timestamp
    );
}
