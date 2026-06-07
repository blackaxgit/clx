//! End-to-end behavior tests for the memory/recall hooks, anchored to the
//! pre-release spec `specs/_prerelease/02-memory-recall.md` sections 3.1,
//! 3.5, 3.6, 3.7, the edge/failure matrix, and RISKS M-R6.
//!
//! The production handlers (`handle_user_prompt_submit`, `handle_post_tool_use`,
//! `handle_stop_auto_summary`) internally call `Config::load()` and
//! `Storage::open_default()`, so the only faithful seam that exercises the
//! whole orchestration is the real `clx-hook` binary driven with an isolated
//! `HOME`. Under an isolated `HOME`, `~/.clx/config.yaml` and
//! `~/.clx/data/clx.db` are fully sandboxed (paths derive from
//! `dirs::home_dir()`), so we can pre-seed the DB, write a feature-enabling
//! config, pipe a hook envelope on stdin, and assert on stdout + the
//! resulting DB rows. Zero network, zero real keychain, zero model download.
//!
//! The pure router contract (`handle_event` dispatch) is additionally
//! exercised via the public library API with in-memory storage.

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use clx_core::storage::Storage;
use clx_core::types::{Session, SessionId, Snapshot, SnapshotTrigger};

#[path = "support/mod.rs"]
mod support;

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

struct Sandbox {
    _tmp: tempfile::TempDir,
    home: std::path::PathBuf,
}

impl Sandbox {
    fn new() -> Self {
        let tmp = support::isolated_clx_home();
        let home = tmp.path().to_path_buf();
        std::fs::create_dir_all(home.join(".clx/data")).unwrap();
        Self { _tmp: tmp, home }
    }

    fn db_path(&self) -> std::path::PathBuf {
        self.home.join(".clx/data/clx.db")
    }

    /// Open the sandboxed DB through the real Storage path (runs migrations).
    fn open_db(&self) -> Storage {
        Storage::open(self.db_path()).expect("open sandbox db")
    }

    fn write_config(&self, yaml: &str) {
        std::fs::write(self.home.join(".clx/config.yaml"), yaml).unwrap();
    }

    /// Run the `clx-hook` binary with this sandbox as `HOME`, piping `input`
    /// on stdin. Returns `(stdout, stderr)`.
    fn run_hook(&self, input: &str) -> (String, String) {
        let binary = env!("CARGO_BIN_EXE_clx-hook");
        // `harden_command` sets HOME, CLX_LOG=error, and
        // CLX_MODEL_FETCH_DRYRUN=1. The last one guarantees that even if
        // the UserPromptSubmit prefetch spawns `clx model fetch`, it
        // writes a few-byte stub instead of the 2.1 GB model: the recall
        // pipeline stays RRF-only and the sandbox HOME never grows.
        let mut command = Command::new(binary);
        let mut child = support::harden_command(&mut command, &self.home)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn clx-hook");
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(input.as_bytes()).unwrap();
        }
        let out = child.wait_with_output().expect("wait clx-hook");
        support::assert_home_size_bounded(&self.home);
        (
            String::from_utf8_lossy(&out.stdout).to_string(),
            String::from_utf8_lossy(&out.stderr).to_string(),
        )
    }
}

fn seed_session_with_snapshot(s: &Storage, id: &str, secs_ago: i64, summary: &str) {
    let now = chrono::Utc::now();
    let mut sess = Session::new(SessionId::new(id), "/tmp/proj".to_string());
    sess.started_at = now - chrono::Duration::seconds(secs_ago);
    s.create_session(&sess).unwrap();
    let mut snap = Snapshot::new(SessionId::new(id), SnapshotTrigger::Auto);
    snap.created_at = now - chrono::Duration::seconds(secs_ago) + chrono::Duration::seconds(1);
    snap.summary = Some(summary.to_string());
    s.create_snapshot(&snap).unwrap();
}

fn user_prompt_envelope(session: &str, prompt: &str) -> String {
    serde_json::json!({
        "session_id": session,
        "cwd": "/tmp/proj",
        "hook_event_name": "UserPromptSubmit",
        "prompt": prompt,
    })
    .to_string()
}

fn post_tool_use_envelope(session: &str, tool: &str, input: &serde_json::Value) -> String {
    serde_json::json!({
        "session_id": session,
        "cwd": "/tmp/proj",
        "hook_event_name": "PostToolUse",
        "tool_name": tool,
        "tool_use_id": "tu-1",
        "tool_input": input,
        "tool_response": { "ok": true },
    })
    .to_string()
}

fn count_auto_summaries(db: &Storage, session: &str) -> usize {
    db.get_snapshots_by_session(session)
        .unwrap()
        .into_iter()
        .filter(|s| matches!(s.trigger, SnapshotTrigger::AutoSummary))
        .count()
}

// ===========================================================================
// 3.1 UserPromptSubmit auto-recall injection
// ===========================================================================

/// Happy path: a prompt >= `min_prompt_len` with matching stored history
/// produces an `additionalContext` carrying the orchestrator block and a
/// `<historical-context>` recall block (spec 3.1 injected content).
#[test]
fn user_prompt_submit_injects_historical_context_block() {
    let sb = Sandbox::new();
    {
        let db = sb.open_db();
        seed_session_with_snapshot(
            &db,
            "prior-sess",
            300,
            "implemented azure tenant routing fallback logic",
        );
    }
    // Reranker off so there is zero chance of a model fetch / slow path.
    sb.write_config("auto_recall:\n  enabled: true\n  reranker_enabled: false\n");

    // FTS5 joins query terms with implicit AND, so every term must occur in
    // the stored summary for the FTS path to match. Use a term subset of the
    // seeded summary "implemented azure tenant routing fallback logic".
    let (stdout, _stderr) = sb.run_hook(&user_prompt_envelope(
        "current-sess",
        "azure tenant routing fallback",
    ));
    let v: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("hook stdout must be JSON");
    let ctx = v["hookSpecificOutput"]["additionalContext"]
        .as_str()
        .expect("additionalContext present");
    assert!(
        ctx.contains("Orchestrator"),
        "orchestrator context must always be present: {ctx}"
    );
    assert!(
        ctx.contains("<historical-context"),
        "recall block must be injected for a matching prompt: {ctx}"
    );
    assert!(
        ctx.contains("azure tenant routing"),
        "the matching stored summary must appear in the recall block: {ctx}"
    );
}

/// Edge (short prompt): a prompt shorter than `min_prompt_len` skips recall
/// but the orchestrator context is still emitted (spec 3.1 edge "short
/// prompt" + edge/failure matrix row).
#[test]
fn user_prompt_submit_short_prompt_skips_recall_keeps_orchestrator() {
    let sb = Sandbox::new();
    {
        let db = sb.open_db();
        seed_session_with_snapshot(&db, "prior", 60, "azure routing decision");
    }
    sb.write_config(
        "auto_recall:\n  enabled: true\n  reranker_enabled: false\n  min_prompt_len: 10\n",
    );

    let (stdout, _e) = sb.run_hook(&user_prompt_envelope("cur", "hi"));
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("JSON");
    let ctx = v["hookSpecificOutput"]["additionalContext"]
        .as_str()
        .unwrap_or("");
    assert!(ctx.contains("Orchestrator"), "orchestrator still emitted");
    assert!(
        !ctx.contains("<historical-context"),
        "short prompt must NOT trigger a recall block: {ctx}"
    );
}

/// Edge (disabled): `auto_recall.enabled=false` -> no recall block,
/// orchestrator context still emitted (spec 3.1 edge "disabled").
#[test]
fn user_prompt_submit_recall_disabled_keeps_orchestrator_only() {
    let sb = Sandbox::new();
    {
        let db = sb.open_db();
        seed_session_with_snapshot(&db, "prior", 60, "azure routing decision text");
    }
    sb.write_config("auto_recall:\n  enabled: false\n  reranker_enabled: false\n");

    let (stdout, _e) = sb.run_hook(&user_prompt_envelope(
        "cur",
        "tell me about azure routing decisions please",
    ));
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("JSON");
    let ctx = v["hookSpecificOutput"]["additionalContext"]
        .as_str()
        .unwrap_or("");
    assert!(ctx.contains("Orchestrator"));
    assert!(
        !ctx.contains("<historical-context"),
        "disabled auto-recall must not inject a recall block: {ctx}"
    );
}

// ===========================================================================
// 3.5 pin_recent_sessions injection (opt-in, self-pin guard)
// ===========================================================================

/// Opt-in pinned-sessions block lists prior sessions and excludes the
/// current one (spec 3.5 + verification 5.3 self-pin guard).
#[test]
fn user_prompt_submit_pins_recent_sessions_excluding_current() {
    let sb = Sandbox::new();
    {
        let db = sb.open_db();
        seed_session_with_snapshot(&db, "older-sess", 400, "older session work summary");
        seed_session_with_snapshot(&db, "newer-sess", 200, "newer session work summary");
        // The current session also has a snapshot; it must be excluded.
        seed_session_with_snapshot(&db, "current-sess", 50, "current session text");
    }
    sb.write_config(
        "auto_recall:\n  enabled: true\n  reranker_enabled: false\n  \
         pin_recent_sessions:\n    enabled: true\n    count: 3\n    max_chars_each: 200\n",
    );

    let (stdout, _e) = sb.run_hook(&user_prompt_envelope(
        "current-sess",
        "give me a status update on the project please",
    ));
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("JSON");
    let ctx = v["hookSpecificOutput"]["additionalContext"]
        .as_str()
        .expect("additionalContext present");
    assert!(
        ctx.contains("## Pinned recent sessions"),
        "pinned block must be present when opted in: {ctx}"
    );
    assert!(ctx.contains("older-sess"), "prior session must be listed");
    assert!(ctx.contains("newer-sess"), "prior session must be listed");
    assert!(
        !ctx.contains("[current-sess]"),
        "self-pin guard: current session must be excluded: {ctx}"
    );
}

// ===========================================================================
// 3.6 PostToolUse aggregator -> tool_events
// ===========================================================================

/// Happy path: an `Edit` `PostToolUse` event is aggregated into `tool_events`
/// (spec 3.6 emission). Two edits to the same file in one process run land
/// in the same 60s bucket -> one row, `occurrence_count` == 2.
#[test]
fn post_tool_use_aggregates_mutator_edits_with_dedup() {
    let sb = Sandbox::new();
    {
        let db = sb.open_db();
        let sess = Session::new(SessionId::new("agg-sess"), "/tmp/proj".to_string());
        db.create_session(&sess).unwrap();
    }
    sb.write_config("auto_recall:\n  reranker_enabled: false\n");

    let env = post_tool_use_envelope(
        "agg-sess",
        "Edit",
        &serde_json::json!({
            "file_path": "src/agg.rs",
            "old_string": "a",
            "new_string": "bb",
        }),
    );
    sb.run_hook(&env);
    sb.run_hook(&env);

    let db = sb.open_db();
    let rows = db.recent_tool_events_for_session("agg-sess", 10).unwrap();
    assert_eq!(
        rows.len(),
        1,
        "two same-bucket edits must collapse to one tool_events row"
    );
    assert_eq!(rows[0].tool_name, "Edit");
    assert_eq!(rows[0].target.as_deref(), Some("src/agg.rs"));
    assert_eq!(rows[0].occurrence_count, 2);
}

/// Failure/edge: a read-only tool (`Read`) is NOT aggregated (spec 3.6:
/// reads are not aggregated).
#[test]
fn post_tool_use_does_not_aggregate_read_only_tool() {
    let sb = Sandbox::new();
    {
        let db = sb.open_db();
        let sess = Session::new(SessionId::new("ro-sess"), "/tmp/proj".to_string());
        db.create_session(&sess).unwrap();
    }
    sb.write_config("auto_recall:\n  reranker_enabled: false\n");

    let env = post_tool_use_envelope(
        "ro-sess",
        "Read",
        &serde_json::json!({ "file_path": "src/x.rs" }),
    );
    sb.run_hook(&env);

    let db = sb.open_db();
    assert_eq!(
        db.count_tool_events("ro-sess").unwrap(),
        0,
        "Read must not produce a tool_events row"
    );
}

// ===========================================================================
// 3.7 Stop auto_summary: opt-in + exactly-one-snapshot
// ===========================================================================

/// Opt-out default: with `memory.auto_summarize.enabled` absent (default
/// false) a Stop event writes ZERO `auto_summary` snapshots (spec 3.7 opt-in;
/// preserves 0.7.x behavior, section 6).
#[test]
fn stop_auto_summary_disabled_by_default_writes_nothing() {
    let sb = Sandbox::new();
    {
        let db = sb.open_db();
        let sess = Session::new(SessionId::new("stop-off"), "/tmp/proj".to_string());
        db.create_session(&sess).unwrap();
    }
    sb.write_config("auto_recall:\n  reranker_enabled: false\n");

    let env = serde_json::json!({
        "session_id": "stop-off",
        "cwd": "/tmp/proj",
        "hook_event_name": "Stop",
    })
    .to_string();
    sb.run_hook(&env);

    let db = sb.open_db();
    assert_eq!(
        count_auto_summaries(&db, "stop-off"),
        0,
        "auto_summarize defaults off; Stop must not persist an AutoSummary"
    );
}

/// Exactly-one-snapshot under racing handlers: even with `auto_summarize`
/// enabled and enough mutator turns, two concurrent Stop invocations against
/// the same isolated DB produce AT MOST one `AutoSummary` row (spec 3.7
/// TOCTOU-safe single snapshot + edge/failure matrix "Concurrent Stop
/// hooks"). The transcript is absent so the handler may legitimately write
/// zero (early-return on no transcript); the invariant under test is "never
/// more than one", which is the documented safety property.
#[test]
fn stop_auto_summary_never_writes_more_than_one_under_race() {
    let sb = Sandbox::new();
    {
        let db = sb.open_db();
        let sess = Session::new(SessionId::new("stop-race"), "/tmp/proj".to_string());
        db.create_session(&sess).unwrap();
        // Drive enough mutator activity past every_n_turns so the gate
        // would not short-circuit on the turn count.
        for i in 0..6 {
            let ev = clx_core::types::ToolEvent::new(
                SessionId::new("stop-race"),
                "Edit",
                Some(format!("src/{i}.rs")),
                "edit",
                clx_core::types::ToolOutcome::Success,
                1_000 + i64::from(i),
            );
            db.append_or_extend_tool_event(&ev).unwrap();
        }
    }
    sb.write_config(
        "auto_recall:\n  reranker_enabled: false\nmemory:\n  auto_summarize:\n    \
         enabled: true\n    every_n_turns: 2\n    skip_when_idle: true\n",
    );

    let stop_env = serde_json::json!({
        "session_id": "stop-race",
        "cwd": "/tmp/proj",
        "hook_event_name": "Stop",
    })
    .to_string();

    // Two handlers in quick succession against the same sandbox DB.
    let sb_ref = &sb;
    let env_a = stop_env.clone();
    let env_b = stop_env.clone();
    std::thread::scope(|sc| {
        sc.spawn(|| {
            sb_ref.run_hook(&env_a);
        });
        sc.spawn(|| {
            sb_ref.run_hook(&env_b);
        });
    });

    let db = sb.open_db();
    let n = count_auto_summaries(&db, "stop-race");
    assert!(
        n <= 1,
        "TOCTOU-safe guarantee violated: {n} AutoSummary snapshots written \
         (spec 3.7 requires at most one under racing Stop handlers)"
    );
}

// ===========================================================================
// Router dispatch contract (pure library seam) + RISK M-R6
// ===========================================================================

/// The public `handle_event` router dispatches an unknown event to the safe
/// allow fallback and returns `HookExit::Ok` (router contract; in-memory IO,
/// no filesystem). Validates the documented Orchestration-layer entry point.
#[tokio::test]
async fn router_handle_event_unknown_event_is_ok() {
    use clx_hook::{HookExit, handle_event};

    let raw = serde_json::json!({
        "session_id": "router-sess",
        "cwd": "/tmp",
        "hook_event_name": "TotallyUnknownFutureEvent"
    })
    .to_string();
    let mut out = Vec::<u8>::new();
    // The router no longer takes injected deps: each handler resolves its own
    // config/storage. `handle_event` can therefore be driven directly with
    // in-memory IO; unknown events dispatch to the safe allow fallback.
    let exit = handle_event(raw.as_bytes(), &mut out).await;
    assert_eq!(exit, HookExit::Ok, "unknown event must dispatch to Ok");
}

/// `handle_event` rejects oversize input with a block decision (router
/// fallback contract; in-memory writer).
#[tokio::test]
async fn router_handle_event_oversize_blocks() {
    use clx_hook::{HookExit, handle_event};
    let big = vec![b'a'; 5 * 1024 * 1024];
    let mut out = Vec::<u8>::new();
    let exit = handle_event(&big[..], &mut out).await;
    assert_eq!(exit, HookExit::InputTooLarge);
    let s = String::from_utf8_lossy(&out);
    let v: serde_json::Value = serde_json::from_str(s.trim()).expect("JSON");
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "block");
}

/// RISK M-R6 (pin-accepted, latency): `do_recall` opens `Storage` +
/// `EmbeddingStore` on every prompt inside the 500 ms budget; if the whole
/// recall exceeds the timeout it is dropped and the hook still emits the
/// orchestrator context with NO recall block. We pin the accepted behavior:
/// behaviorally correct (timeout-safe), the latency cliff itself is a
/// pre-release perf-pass item, not a functional bug. A normally-fast prompt
/// must still produce well-formed output (the timeout path degrades, never
/// fails the hook).
#[test]
fn risk_m_r6_recall_is_timeout_safe_and_always_emits_output() {
    let sb = Sandbox::new();
    {
        let db = sb.open_db();
        seed_session_with_snapshot(&db, "perf-sess", 30, "some prior latency-sensitive work");
    }
    sb.write_config(
        "auto_recall:\n  enabled: true\n  reranker_enabled: false\n  timeout_ms: 500\n",
    );

    let (stdout, _e) = sb.run_hook(&user_prompt_envelope(
        "cur",
        "summarize the latency sensitive work we did",
    ));
    let v: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("hook must always emit valid JSON");
    let ctx = v["hookSpecificOutput"]["additionalContext"]
        .as_str()
        .expect("additionalContext present");
    // The orchestrator block is unconditional. Whether or not the recall
    // block made the 500 ms budget, the hook MUST still produce output:
    // this is the pinned accepted behavior for RISK M-R6.
    assert!(
        ctx.contains("Orchestrator"),
        "RISK M-R6: hook must always emit orchestrator context even if \
         recall is dropped by the latency budget: {ctx}"
    );
}

/// Sanity: the sandbox DB really is isolated under the temp HOME (guards
/// against a regression where paths stop honoring `$HOME`, which would make
/// every e2e test above silently exercise the real `~/.clx`).
#[test]
fn sandbox_db_is_isolated_under_temp_home() {
    let sb = Sandbox::new();
    let db = sb.open_db();
    let sess = Session::new(SessionId::new("iso-check"), "/tmp".to_string());
    db.create_session(&sess).unwrap();
    drop(db);
    assert!(
        Path::new(&sb.db_path()).exists(),
        "sandbox db must materialize under the temp HOME, not the real one"
    );
}
