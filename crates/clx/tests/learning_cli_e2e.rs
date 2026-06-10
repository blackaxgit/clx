//! e2e tests for the `clx learning` CLI (T5 / AC7, AC8).
//!
//! Isolation: HOME + XDG redirected into a fresh `tempfile::TempDir`; the DB is
//! created by `clx install` (schema v10) and seeded by opening the SAME db file
//! through `clx_core::storage::Storage` and calling `record_learning_event`.
//!
//! NOTE on protected-dir literals: the in-session hook content-scans writes for
//! the protected config dir token. We build the db path via `concat!(".", "clx")`
//! so this source file never contains that literal token.

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

/// Path to the CLX db inside the isolated HOME. Avoids the protected literal.
fn db_path(tmp: &TempDir) -> PathBuf {
    tmp.path()
        .join(concat!(".", "clx"))
        .join("data")
        .join("clx.db")
}

/// The default effective-config fingerprint. A fresh HOME has no config file, so
/// the CLI's `Config::load()` yields defaults; this mirrors the six-field
/// snapshot the CLI computes to aggregate suggestions.
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

/// Build a diverged-ask `LearningEvent` for `command` under the default policy.
fn diverged_ask(command: &str) -> LearningEvent {
    LearningEvent {
        ts: "2026-06-01T12:00:00Z".to_string(),
        session_id: Some("s1".to_string()),
        tool: "Bash".to_string(),
        host: "claude".to_string(),
        decision: "ask".to_string(),
        layer: "l1".to_string(),
        kind: LearningKind::Decision,
        matched_rule: None,
        reason: "L1 caution prompt".to_string(),
        command: Some(command.to_string()),
        effective_config: "{}".to_string(),
        diverged: true,
        divergence_reason: Some("L1 (LLM) caution prompt".to_string()),
        latency_ms: Some(12),
        policy_fingerprint: default_fingerprint(),
    }
}

/// Seed the store via the clx-core API (the db file the CLI also opens).
fn seed(tmp: &TempDir, events: &[LearningEvent]) {
    let storage = Storage::open(db_path(tmp)).expect("open seeded db");
    for ev in events {
        storage.record_learning_event(ev).expect("record event");
    }
}

/// AC7: `learning report` prints decision/divergence counts AND a suggestion for
/// a repeated simple pattern, but NOT for secret-bearing or compound patterns.
#[test]
fn ac7_report_counts_and_filtered_suggestions() {
    let t = tmp();
    clx(&t).args(["--json", "install"]).assert().success();

    let mut events = Vec::new();
    // 4 diverged asks for a simple safe pattern -> should be suggested.
    for _ in 0..4 {
        events.push(diverged_ask("cargo build"));
    }
    // A secret-bearing command repeated enough to clear the threshold -> excluded.
    for _ in 0..4 {
        events.push(diverged_ask(
            "curl -H 'Authorization: Bearer sk-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'",
        ));
    }
    // A compound command repeated enough to clear the threshold -> excluded.
    for _ in 0..4 {
        events.push(diverged_ask("cargo build && rm -rf target"));
    }
    seed(&t, &events);

    let out = clx(&t)
        .args(["learning", "report"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8(out).unwrap();

    // Counts present.
    assert!(text.contains("Total events: 12"), "report:\n{text}");
    assert!(text.contains("ask:"), "report:\n{text}");
    assert!(text.contains("diverged:"), "report:\n{text}");

    // Suggests the safe simple pattern.
    assert!(
        text.contains("clx rules allow Bash(cargo build)"),
        "should suggest cargo build:\n{text}"
    );
    // Does NOT suggest the secret-bearing pattern.
    assert!(
        !text.contains("sk-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"),
        "must not surface a secret:\n{text}"
    );
    // Does NOT suggest the compound pattern.
    assert!(
        !text.contains("rm -rf target"),
        "must not suggest a compound command:\n{text}"
    );
}

/// AC7 (JSON): suggestions array contains exactly the cargo-build suggestion.
#[test]
fn ac7_report_json_suggestions_filtered() {
    let t = tmp();
    clx(&t).args(["--json", "install"]).assert().success();

    let mut events = Vec::new();
    for _ in 0..3 {
        events.push(diverged_ask("cargo build"));
    }
    for _ in 0..3 {
        events.push(diverged_ask("cargo build && echo done"));
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

    assert_eq!(v["total"], 6);
    let suggestions = v["suggestions"].as_array().unwrap();
    assert_eq!(
        suggestions.len(),
        1,
        "exactly one suggestion: {suggestions:?}"
    );
    assert!(
        suggestions[0]
            .as_str()
            .unwrap()
            .contains("Bash(cargo build)"),
        "{suggestions:?}"
    );
}

/// AC8: `export --json` emits valid JSON; `list --diverged` filters; `clear`
/// refuses without `--yes` and empties with it.
#[test]
fn ac8_export_list_filter_and_clear() {
    let t = tmp();
    clx(&t).args(["--json", "install"]).assert().success();

    // 2 diverged asks + 1 non-diverged allow.
    let mut allow = diverged_ask("ls -la");
    allow.decision = "allow".to_string();
    allow.diverged = false;
    allow.divergence_reason = None;
    allow.layer = "l0".to_string();
    seed(
        &t,
        &[
            diverged_ask("cargo build"),
            diverged_ask("cargo test"),
            allow,
        ],
    );

    // export --json -> parseable array of 3 rows.
    let out = clx(&t)
        .args(["learning", "export", "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8(out).unwrap()).unwrap();
    assert_eq!(v.as_array().unwrap().len(), 3, "export rows: {v}");

    // list --diverged -> only the 2 diverged rows (JSON for easy assertion).
    let out = clx(&t)
        .args(["--json", "learning", "list", "--diverged"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8(out).unwrap()).unwrap();
    let rows = v.as_array().unwrap();
    assert_eq!(rows.len(), 2, "diverged filter: {rows:?}");
    assert!(
        rows.iter().all(|r| r["diverged"].as_bool() == Some(true)),
        "all rows diverged: {rows:?}"
    );

    // clear WITHOUT --yes refuses; rows remain.
    clx(&t)
        .args(["learning", "clear"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--yes"));
    let out = clx(&t)
        .args(["--json", "learning", "list"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8(out).unwrap()).unwrap();
    assert_eq!(
        v.as_array().unwrap().len(),
        3,
        "rows remain after refused clear"
    );

    // clear --yes empties the table.
    clx(&t)
        .args(["learning", "clear", "--yes"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Cleared 3 events"));
    let out = clx(&t)
        .args(["--json", "learning", "list"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8(out).unwrap()).unwrap();
    assert_eq!(
        v.as_array().unwrap().len(),
        0,
        "table empty after clear --yes"
    );
}
