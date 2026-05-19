//! Wave: residual coverage for `clx` (no subcommand) / `clx maintenance
//! trim` / `clx model fetch --background`.
//!
//! Closes regions the existing deep suites leave uncovered:
//!   * `commands/version.rs:38-65` -- `cmd_default` (the `None`
//!     no-subcommand dispatch arm). The deep suite only drives
//!     `clx version`, never bare `clx`.
//!   * `commands/maintenance.rs:86-114` -- the NON-dry-run trim path:
//!     real `cleanup_old_tool_events` / `cleanup_old_audit_logs` plus the
//!     JSON + human result renderers and the `audit_days == 0` skip arm.
//!     The offline suite only ever hits the dry-run branch.
//!   * `commands/model.rs:104-115,392-407` -- the `--background` detached
//!     spawn path (`spawn_detached_fetch`), never exercised elsewhere.
//!
//! Hermetic: HOME/XDG isolated; `CLX_MODEL_FETCH_DRYRUN=1` so the detached
//! child (which inherits env) also dry-runs -- no 568MB download, no
//! network, no keychain.

#![allow(clippy::doc_markdown)]

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

fn clx(tmp: &TempDir) -> Command {
    let mut cmd = Command::cargo_bin("clx").expect("clx binary");
    cmd.env("HOME", tmp.path())
        .env("XDG_DATA_HOME", tmp.path().join("xdg-data"))
        .env("XDG_CONFIG_HOME", tmp.path().join("xdg-config"))
        .env("CLX_CREDENTIALS_BACKEND", "file")
        .env("CLX_MODEL_FETCH_DRYRUN", "1")
        .env("CLX_RERANKER_ENABLED", "false")
        .env("CLX_LOG", "error");
    cmd
}

fn tmp() -> TempDir {
    tempfile::tempdir().expect("tempdir")
}

// ===========================================================================
// version.rs: cmd_default (bare `clx`, no subcommand) -- human + --json arms
// ===========================================================================

#[test]
fn bare_clx_human_prints_quick_start_default_screen() {
    // The `None` dispatch arm (main.rs) -> cmd_default human branch
    // (version.rs:47-61).
    let t = tmp();
    clx(&t)
        .assert()
        .success()
        .stdout(predicate::str::contains("CLX"))
        .stdout(predicate::str::contains(
            "A command validation and context persistence layer for Claude Code.",
        ))
        .stdout(predicate::str::contains("Quick Start"))
        .stdout(predicate::str::contains("clx dashboard"))
        .stdout(predicate::str::contains("clx config"))
        .stdout(predicate::str::contains("clx rules list"))
        .stdout(predicate::str::contains("clx --help"));
}

#[test]
fn bare_clx_json_emits_version_and_help_hint() {
    // cmd_default --json branch (version.rs:39-46).
    let t = tmp();
    let out = clx(&t)
        .arg("--json")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value =
        serde_json::from_str(&String::from_utf8(out).unwrap()).expect("bare --json is JSON");
    assert!(
        v["version"].as_str().is_some_and(|s| !s.is_empty()),
        "default --json must carry a non-empty version: {v}"
    );
    assert!(
        v["hint"].as_str().is_some_and(|s| s.contains("clx --help")),
        "default --json must carry the --help hint: {v}"
    );
}

// ===========================================================================
// maintenance.rs: NON-dry-run trim -- real deletes + JSON/human renderers
// ===========================================================================

/// Insert an OLD (`created_at` 100 days ago) tool_events row through the
/// same on-disk DB the binary opens, behind a FK-valid session.
fn seed_old_tool_event(t: &TempDir) {
    use clx_core::storage::Storage;
    use clx_core::types::{Session, SessionId};

    let db = t.path().join(".clx/data/clx.db");
    let storage = Storage::open(&db).expect("open storage");
    storage
        .create_session(&Session::new(
            SessionId::new("sess-maint-1"),
            "/tmp/p".to_string(),
        ))
        .expect("create session");
    storage
        .connection()
        .execute(
            "INSERT INTO tool_events ( \
                 session_id, tool_name, target, summary, outcome, \
                 window_start_unix, window_end_unix, occurrence_count, created_at \
             ) VALUES ('sess-maint-1','Bash','x','old row','ok',0,0,1, \
                       datetime('now','-100 days'))",
            [],
        )
        .expect("seed old tool_event");
}

/// Insert an OLD (`timestamp` 100 days ago) audit_log row behind a
/// FK-valid session, through the same on-disk DB the binary opens.
fn seed_old_audit_log(t: &TempDir) {
    use clx_core::storage::Storage;
    use clx_core::types::{Session, SessionId};

    let db = t.path().join(".clx/data/clx.db");
    let storage = Storage::open(&db).expect("open storage");
    let _ = storage.create_session(&Session::new(
        SessionId::new("sess-maint-audit"),
        "/tmp/p".to_string(),
    ));
    storage
        .connection()
        .execute(
            "INSERT INTO audit_log ( \
                 session_id, timestamp, command, working_dir, layer, decision \
             ) VALUES ('sess-maint-audit', datetime('now','-100 days'), \
                       'rm -rf /tmp/x', '/tmp', 'L1', 'deny')",
            [],
        )
        .expect("seed old audit_log");
}

#[test]
fn maintenance_trim_json_deletes_old_rows_and_reports_counts() {
    // create_llm_client / provider are NOT involved here: trim is pure
    // storage. The old row is older than the 30-day window so it must be
    // deleted and reported (maintenance.rs:86,93-102).
    let t = tmp();
    clx(&t).args(["--json", "install"]).assert().success();
    seed_old_tool_event(&t);
    seed_old_audit_log(&t);

    let out = clx(&t)
        .args([
            "--json",
            "maintenance",
            "trim",
            "--tool-events-days",
            "30",
            "--audit-days",
            "90",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value =
        serde_json::from_str(&String::from_utf8(out).unwrap()).expect("trim --json is JSON");
    assert_eq!(
        v["tool_events_deleted"], 1,
        "the 100-day-old tool_events row must be swept by a 30-day window: {v}"
    );
    assert_eq!(
        v["audit_log_deleted"], 1,
        "the 100-day-old audit_log row must be swept by the 90-day window: {v}"
    );
    assert_eq!(v["tool_events_days"], 30);
    assert_eq!(v["audit_days"], 90);
}

#[test]
fn maintenance_trim_human_arm_reports_removed_rows() {
    let t = tmp();
    clx(&t).args(["--json", "install"]).assert().success();
    seed_old_tool_event(&t);

    clx(&t)
        .args(["maintenance", "trim", "--tool-events-days", "30"])
        .assert()
        .success()
        .stdout(predicate::str::contains("clx maintenance trim"))
        .stdout(predicate::str::contains("tool_events"))
        .stdout(predicate::str::contains("row(s) removed"))
        .stdout(predicate::str::contains("audit_log"));
}

#[test]
fn maintenance_trim_audit_days_zero_skips_audit_sweep() {
    // au_days == 0 -> the audit cleanup is skipped (maintenance.rs:87-91:
    // `if au_days == 0 { 0 }`), reported as audit_log_deleted: 0 with
    // audit_days: 0. Distinct from the default-90 arm above.
    let t = tmp();
    clx(&t).args(["--json", "install"]).assert().success();
    seed_old_tool_event(&t);
    // A 100-day-old audit row: if the audit_days==0 guard is bypassed it
    // WOULD be deleted; with the guard intact it must survive.
    seed_old_audit_log(&t);

    let out = clx(&t)
        .args([
            "--json",
            "maintenance",
            "trim",
            "--tool-events-days",
            "30",
            "--audit-days",
            "0",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8(out).unwrap()).unwrap();
    assert_eq!(v["audit_days"], 0);
    assert_eq!(
        v["audit_log_deleted"], 0,
        "audit sweep must be skipped when audit_days==0: {v}"
    );
    assert_eq!(
        v["tool_events_deleted"], 1,
        "tool_events sweep still runs independently: {v}"
    );

    // Behavior proof the row genuinely SURVIVED the audit_days==0 run:
    // a follow-up sweep with a real window now deletes exactly that row.
    let out2 = clx(&t)
        .args([
            "--json",
            "maintenance",
            "trim",
            "--tool-events-days",
            "0",
            "--audit-days",
            "30",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v2: serde_json::Value = serde_json::from_str(&String::from_utf8(out2).unwrap()).unwrap();
    assert_eq!(
        v2["audit_log_deleted"], 1,
        "the audit row must have survived the audit_days==0 run and be \
         deletable now (proves the guard did not silently delete it): {v2}"
    );
}

#[test]
fn maintenance_trim_tool_events_days_zero_is_noop_for_tool_events() {
    // tool_events_days == 0 -> cleanup_old_tool_events returns 0 without
    // deleting (storage guard). The old row must SURVIVE.
    let t = tmp();
    clx(&t).args(["--json", "install"]).assert().success();
    seed_old_tool_event(&t);

    let out = clx(&t)
        .args(["--json", "maintenance", "trim", "--tool-events-days", "0"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8(out).unwrap()).unwrap();
    assert_eq!(
        v["tool_events_deleted"], 0,
        "days==0 must disable the sweep, not delete everything: {v}"
    );

    // Confirm the row really survived (behavior, not just the counter).
    let still = clx(&t)
        .args([
            "--json",
            "maintenance",
            "trim",
            "--tool-events-days",
            "30",
            "--dry-run",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let sv: serde_json::Value = serde_json::from_str(&String::from_utf8(still).unwrap()).unwrap();
    assert_eq!(
        sv["tool_events_would_delete"], 1,
        "the row must still be present after the days==0 no-op: {sv}"
    );
}

// ===========================================================================
// model.rs: --background detached spawn (spawn_detached_fetch)
// ===========================================================================

#[test]
fn model_fetch_background_json_returns_spawned_immediately() {
    // model.rs:104-115 + spawn_detached_fetch (:392-407): the parent
    // spawns a detached child and returns the `spawned` status without
    // blocking on the download.
    let t = tmp();
    let out = clx(&t)
        .args(["--json", "model", "fetch", "--background"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value =
        serde_json::from_str(&String::from_utf8(out).unwrap()).expect("bg fetch --json is JSON");
    assert_eq!(
        v["status"], "spawned",
        "background fetch must report spawned and return immediately: {v}"
    );
}

#[test]
fn model_fetch_background_human_reports_started_in_background() {
    let t = tmp();
    clx(&t)
        .args(["model", "fetch", "--background"])
        .assert()
        .success()
        .stdout(predicate::str::contains("background"));
}

#[test]
fn model_fetch_background_eventually_writes_ready_sentinel() {
    // Behavior contract for the detached child: because it inherits
    // CLX_MODEL_FETCH_DRYRUN + HOME, it completes the dry-run fetch and
    // writes the `.ready` sentinel into the isolated HOME. Poll briefly
    // (bounded) so the test stays deterministic, not flaky.
    let t = tmp();
    clx(&t)
        .args(["--json", "model", "fetch", "--background"])
        .assert()
        .success();
    let ready = t.path().join(".clx/models/bge-reranker-v2-m3/.ready");
    let mut seen = false;
    for _ in 0..100 {
        if ready.exists() {
            seen = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    assert!(
        seen,
        "detached --background child must eventually write the .ready sentinel at {}",
        ready.display()
    );
}
