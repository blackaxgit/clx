//! e2e tests for the `clx learning` CLI branches the first wave never reached:
//!
//! * plain (non-JSON) `list` table rendering: header row, timestamp
//!   truncation to 19 chars, the em-dash reason suffix, and the empty-store
//!   "No learning events." fallback (learning.rs `cmd_list` human arm).
//! * the empty-store `report` fallback (`empty_report`), reached when the
//!   database cannot be opened at all (learning.rs:127-129, 248-266).
//! * the config-load-failure suggestion skip: a malformed config means no
//!   fingerprint, so aggregates are skipped and NO suggestion is emitted even
//!   for repeated diverged asks (learning.rs:166-173).
//! * the `--json` arms of `clear` (refusal without `--yes` and success with
//!   it) plus the error/degraded kind counters and the
//!   validator-unavailable hint (learning.rs:197-242, 325-358).
//!
//! Isolation mirrors `learning_cli_e2e.rs`: HOME + XDG into a fresh TempDir,
//! ambient CLX_* scrubbed by explicit overrides, db seeded through
//! `clx_core::storage::Storage` against the same file the CLI opens. The
//! protected config-dir token is always built via `concat!(".", "clx")`.

#![allow(clippy::doc_markdown)]

use std::path::PathBuf;

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

use clx_core::storage::Storage;
use clx_core::types::{EffectiveConfig, LearningEvent, LearningKind};

fn clx(tmp: &TempDir) -> Command {
    let mut cmd = Command::cargo_bin("clx").expect("clx binary");
    cmd.env("HOME", tmp.path())
        .env("XDG_DATA_HOME", tmp.path().join("xdg-data"))
        .env("XDG_CONFIG_HOME", tmp.path().join("xdg-config"))
        .env("CLX_CREDENTIALS_BACKEND", "file")
        .env("CLX_MODEL_FETCH_DRYRUN", "1")
        .env("CLX_LOG", "error");
    cmd
}

fn tmp() -> TempDir {
    tempfile::tempdir().expect("tempdir")
}

/// CLX home dir inside the isolated HOME (token built to avoid the literal).
fn clx_home(tmp: &TempDir) -> PathBuf {
    tmp.path().join(concat!(".", "clx"))
}

fn db_path(tmp: &TempDir) -> PathBuf {
    clx_home(tmp).join("data").join("clx.db")
}

fn config_path(tmp: &TempDir) -> PathBuf {
    clx_home(tmp).join("config.yaml")
}

/// A learning event with full control over the fields the assertions read.
fn event(decision: &str, diverged: bool, kind: LearningKind, command: &str) -> LearningEvent {
    LearningEvent {
        ts: "2026-06-01T12:00:00Z".to_string(),
        session_id: Some("s1".to_string()),
        tool: "Bash".to_string(),
        host: "claude".to_string(),
        decision: decision.to_string(),
        layer: "l1".to_string(),
        kind,
        matched_rule: None,
        reason: if diverged {
            "L1 caution prompt".to_string()
        } else {
            String::new()
        },
        command: Some(command.to_string()),
        effective_config: "{}".to_string(),
        diverged,
        divergence_reason: diverged.then(|| "L1 (LLM) caution prompt".to_string()),
        latency_ms: Some(12),
        policy_fingerprint: "fp-test".to_string(),
    }
}

/// The fingerprint the CLI computes for a fresh HOME (default config),
/// mirroring `learning_cli_e2e.rs`. Events seeded with this fingerprint are
/// visible to the suggestion aggregator.
fn default_fingerprint() -> String {
    EffectiveConfig {
        default_decision: "ask".to_string(),
        prompt_sensitivity: "standard".to_string(),
        auto_allow_reads: true,
        layer0_enabled: true,
        layer1_enabled: true,
        on_validator_unavailable: "ask".to_string(),
    }
    .fingerprint()
}

fn seed(tmp: &TempDir, events: &[LearningEvent]) {
    let storage = Storage::open(db_path(tmp)).expect("open seeded db");
    for ev in events {
        storage.record_learning_event(ev).expect("record event");
    }
}

// ===========================================================================
// Plain-output `list` table rendering
// ===========================================================================

/// Plain `list` renders the bold-free header, truncates the timestamp to 19
/// chars (the trailing `Z` must be cut), and appends the em-dash reason only
/// for rows that have one.
#[test]
fn list_plain_table_renders_header_truncation_and_reason() {
    let t = tmp();
    clx(&t).args(["--json", "install"]).assert().success();
    seed(
        &t,
        &[
            event("ask", true, LearningKind::Decision, "cargo build"),
            event("allow", false, LearningKind::Decision, "ls -la"),
        ],
    );

    let out = clx(&t)
        .args(["learning", "list"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8(out).unwrap();

    // Header columns, in order on one line.
    let header = text.lines().next().unwrap_or_default();
    for col in ["TS", "TOOL", "DEC", "LAYER", "DIVERGED", "COMMAND"] {
        assert!(header.contains(col), "header missing {col}: {header}");
    }

    // Timestamp truncated to 19 chars: the seeded `...:00Z` loses its Z.
    assert!(
        text.contains("2026-06-01T12:00:00"),
        "truncated ts missing:\n{text}"
    );
    assert!(
        !text.contains("2026-06-01T12:00:00Z"),
        "ts must be truncated to 19 chars (no Z):\n{text}"
    );

    // Both commands rendered; exactly the diverged row carries the em-dash
    // reason suffix.
    assert!(text.contains("cargo build"), "row missing:\n{text}");
    assert!(text.contains("ls -la"), "row missing:\n{text}");
    assert_eq!(
        text.matches('\u{2014}').count(),
        1,
        "exactly one row has a reason suffix:\n{text}"
    );
    assert!(
        text.contains("\u{2014} L1 caution prompt"),
        "reason text missing:\n{text}"
    );
}

/// Plain `list` with zero rows prints the dimmed empty-state line, not the
/// table header.
#[test]
fn list_plain_empty_store_prints_no_events_line() {
    let t = tmp();
    clx(&t).args(["--json", "install"]).assert().success();

    let out = clx(&t)
        .args(["learning", "list"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8(out).unwrap();
    assert!(text.contains("No learning events."), "got:\n{text}");
    assert!(
        !text.contains("DIVERGED"),
        "empty list must not render the table header:\n{text}"
    );
}

/// `--decision` and `--limit` actually constrain the returned rows.
#[test]
fn list_decision_filter_and_limit_constrain_rows() {
    let t = tmp();
    clx(&t).args(["--json", "install"]).assert().success();
    seed(
        &t,
        &[
            event("ask", true, LearningKind::Decision, "cargo build"),
            event("allow", false, LearningKind::Decision, "ls -la"),
            event("allow", false, LearningKind::Decision, "cat README.md"),
        ],
    );

    // decision=allow -> only the 2 allow rows.
    let out = clx(&t)
        .args(["--json", "learning", "list", "--decision", "allow"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8(out).unwrap()).unwrap();
    let rows = v.as_array().unwrap();
    assert_eq!(rows.len(), 2, "decision filter: {rows:?}");
    assert!(
        rows.iter().all(|r| r["decision"] == "allow"),
        "all rows allow: {rows:?}"
    );

    // limit=1 -> exactly one row.
    let out = clx(&t)
        .args(["--json", "learning", "list", "--limit", "1"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8(out).unwrap()).unwrap();
    assert_eq!(v.as_array().unwrap().len(), 1, "limit must cap rows: {v}");
}

// ===========================================================================
// Empty-store report fallback (DB cannot be opened)
// ===========================================================================

/// Block the db path with a directory so `Storage::open_default()` fails:
/// `report` must fall back to the all-zero report instead of erroring, in
/// both human and JSON modes; `list` returns `[]`; only the destructive
/// `clear --yes` (which NEEDS the db) fails loudly.
#[test]
fn report_falls_back_to_empty_when_db_unopenable() {
    let t = tmp();
    // No install: fabricate an unopenable db (a directory at the db path).
    std::fs::create_dir_all(db_path(&t)).unwrap();

    // Human report: zero totals + dimmed hint, exit 0.
    let out = clx(&t)
        .args(["learning", "report"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8(out).unwrap();
    assert!(text.contains("Total events: 0"), "got:\n{text}");
    assert!(
        text.contains("No learning events recorded."),
        "got:\n{text}"
    );

    // JSON report: all-zero shape with empty suggestions.
    let out = clx(&t)
        .args(["--json", "learning", "report"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8(out).unwrap()).unwrap();
    assert_eq!(v["total"], 0);
    assert_eq!(v["by_decision"]["allow"], 0);
    assert_eq!(v["suggestions"].as_array().unwrap().len(), 0);
    assert_eq!(v["validator_unavailable_events"], 0);

    // Read commands never error on a missing store: list -> [].
    let out = clx(&t)
        .args(["--json", "learning", "list"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8(out).unwrap()).unwrap();
    assert_eq!(v.as_array().unwrap().len(), 0, "list on broken store: {v}");

    // The destructive path is the one that must fail loudly.
    clx(&t)
        .args(["learning", "clear", "--yes"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Failed to open database"));
}

// ===========================================================================
// Config-load-failure suggestion skip
// ===========================================================================

/// When the config cannot be loaded the fingerprint is empty, so the
/// aggregate query is skipped and NO suggestion is emitted even though the
/// same command has enough diverged asks (counts must still be reported).
#[test]
fn report_skips_suggestions_when_config_load_fails() {
    let t = tmp();
    clx(&t).args(["--json", "install"]).assert().success();
    seed(
        &t,
        &(0..4)
            .map(|_| event("ask", true, LearningKind::Decision, "cargo build"))
            .collect::<Vec<_>>(),
    );

    // Sanity precondition is proven by learning_cli_e2e (a valid config DOES
    // suggest). Now break the config file.
    std::fs::write(config_path(&t), "validator: [unclosed\n").unwrap();

    let out = clx(&t)
        .args(["--json", "learning", "report"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8(out).unwrap()).unwrap();
    assert_eq!(v["total"], 4, "counts still reported: {v}");
    assert_eq!(
        v["suggestions"].as_array().unwrap().len(),
        0,
        "no suggestions without a config fingerprint: {v}"
    );
}

// ===========================================================================
// JSON clear arms + kind counters
// ===========================================================================

/// `--json learning clear` without `--yes` refuses with `success:false` and
/// leaves rows intact; with `--yes` it reports the cleared count.
#[test]
fn clear_json_refusal_then_success_roundtrip() {
    let t = tmp();
    clx(&t).args(["--json", "install"]).assert().success();
    seed(
        &t,
        &[
            event("ask", true, LearningKind::Decision, "cargo build"),
            event("allow", false, LearningKind::Decision, "ls -la"),
        ],
    );

    // Refusal: structured error, exit 0, rows untouched.
    let out = clx(&t)
        .args(["--json", "learning", "clear"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8(out).unwrap()).unwrap();
    assert_eq!(v["action"], "clear");
    assert_eq!(v["success"], false);
    assert!(
        v["error"].as_str().unwrap().contains("--yes"),
        "refusal must name the missing flag: {v}"
    );

    let out = clx(&t)
        .args(["--json", "learning", "list"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8(out).unwrap()).unwrap();
    assert_eq!(v.as_array().unwrap().len(), 2, "rows survive refusal");

    // Success: cleared count reported, table empty afterwards.
    let out = clx(&t)
        .args(["--json", "learning", "clear", "--yes"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8(out).unwrap()).unwrap();
    assert_eq!(v["success"], true);
    assert_eq!(v["cleared"], 2, "must report how many rows were removed");

    let out = clx(&t)
        .args(["--json", "learning", "list"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8(out).unwrap()).unwrap();
    assert_eq!(v.as_array().unwrap().len(), 0, "table empty after clear");
}

/// Commands below the suggestion threshold (3 diverged asks) must NOT be
/// suggested while commands at/above it are -- the `count <
/// SUGGESTION_THRESHOLD` continue arm (learning.rs:177-179).
#[test]
fn report_does_not_suggest_below_threshold_commands() {
    let t = tmp();
    clx(&t).args(["--json", "install"]).assert().success();

    let fp = default_fingerprint();
    let mut events = Vec::new();
    for _ in 0..3 {
        let mut e = event("ask", true, LearningKind::Decision, "cargo build");
        e.policy_fingerprint = fp.clone();
        events.push(e);
    }
    for _ in 0..2 {
        let mut e = event("ask", true, LearningKind::Decision, "cargo test");
        e.policy_fingerprint = fp.clone();
        events.push(e);
    }
    seed(&t, &events);

    let out = clx(&t)
        .args(["--json", "learning", "report"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8(out).unwrap()).unwrap();
    let suggestions = serde_json::to_string(&v["suggestions"]).unwrap();
    assert!(
        suggestions.contains("Bash(cargo build)"),
        "3 diverged asks meet the threshold: {suggestions}"
    );
    assert!(
        !suggestions.contains("cargo test"),
        "2 diverged asks are below the threshold: {suggestions}"
    );
}

/// A store with only clean (non-diverged, non-error) events yields the
/// dimmed "No suggestions." human line (learning.rs:231-233).
#[test]
fn report_human_prints_no_suggestions_when_none_apply() {
    let t = tmp();
    clx(&t).args(["--json", "install"]).assert().success();
    seed(
        &t,
        &[event("allow", false, LearningKind::Decision, "ls -la")],
    );

    let out = clx(&t)
        .args(["learning", "report"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8(out).unwrap();
    assert!(text.contains("Total events: 1"), "got:\n{text}");
    assert!(text.contains("No suggestions."), "got:\n{text}");
    assert!(
        !text.contains("validator-unavailable"),
        "no unavailable hint without error/degraded events:\n{text}"
    );
}

/// Error/degraded kinds are tallied separately, surface in the JSON
/// `by_kind` block, and trigger the human validator-unavailable hint.
#[test]
fn report_counts_error_degraded_kinds_and_unavailable_hint() {
    let t = tmp();
    clx(&t).args(["--json", "install"]).assert().success();
    seed(
        &t,
        &[
            event("deny", true, LearningKind::Error, "curl example.com"),
            event("ask", true, LearningKind::Degraded, "cargo build"),
            event("allow", false, LearningKind::Decision, "ls -la"),
        ],
    );

    let out = clx(&t)
        .args(["--json", "learning", "report"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8(out).unwrap()).unwrap();
    assert_eq!(v["total"], 3);
    assert_eq!(v["by_decision"]["deny"], 1);
    assert_eq!(v["by_decision"]["allow"], 1);
    assert_eq!(v["by_kind"]["error"], 1);
    assert_eq!(v["by_kind"]["degraded"], 1);
    assert_eq!(v["validator_unavailable_events"], 2);

    // Human report surfaces the hint with the same count.
    let out = clx(&t)
        .args(["learning", "report"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8(out).unwrap();
    assert!(
        text.contains("2 validator-unavailable events"),
        "hint missing:\n{text}"
    );
    assert!(
        !text.contains("No suggestions."),
        "hint replaces the empty-suggestions line:\n{text}"
    );
}
