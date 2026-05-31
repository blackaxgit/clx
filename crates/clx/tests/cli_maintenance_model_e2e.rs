//! E2E: `clx maintenance` and `clx model` boundary defense.
//!
//! Scope chosen to AVOID mirroring the existing `cli_misc_commands_e2e.rs`
//! (which already covers `maintenance trim` non-dry-run sweeps and
//! `model fetch --background`). This suite instead pins:
//!   * the invalid-arg / missing-subcommand rejection contracts for both
//!     `maintenance` and `model` (clap exit code 2 + usage on stderr), and
//!   * the read-only `model status` / `model list` happy paths, including a
//!     JSON-shape assertion that is NOT exercised elsewhere.
//!
//! Isolation: HOME + XDG redirected into a fresh `tempfile::TempDir`.
//! `CLX_RERANKER_ENABLED=false` + `CLX_MODEL_FETCH_DRYRUN=1` guarantee no
//! 568MB download and no network even if a code path tried to fetch.

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

fn clx(tmp: &TempDir) -> Command {
    let mut cmd = Command::cargo_bin("clx").expect("clx binary");
    cmd.env("HOME", tmp.path())
        .env("XDG_DATA_HOME", tmp.path().join("xdg-data"))
        .env("XDG_CONFIG_HOME", tmp.path().join("xdg-config"))
        .env("CLX_CREDENTIALS_BACKEND", "file")
        .env("CLX_RERANKER_ENABLED", "false")
        .env("CLX_MODEL_FETCH_DRYRUN", "1")
        .env("CLX_LOG", "error")
        .current_dir(tmp.path());
    cmd
}

fn tmp() -> TempDir {
    tempfile::tempdir().expect("tempdir")
}

// ===========================================================================
// maintenance: invalid-arg / missing-subcommand boundary
// ===========================================================================

#[test]
fn maintenance_without_subcommand_is_rejected_with_usage() {
    // `maintenance` requires a subcommand (`trim`). Bare invocation must be
    // a clap usage error (exit 2), not a silent success or a panic.
    let t = tmp();
    clx(&t)
        .arg("maintenance")
        .assert()
        .code(2)
        .stderr(predicate::str::contains("Usage"))
        .stderr(predicate::str::contains("trim"));
}

#[test]
fn maintenance_unknown_subcommand_is_rejected() {
    let t = tmp();
    clx(&t)
        .args(["maintenance", "obliterate"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("obliterate").or(predicate::str::contains("subcommand")));
}

#[test]
fn maintenance_trim_rejects_nonnumeric_days() {
    // `--tool-events-days` is numeric; a non-numeric value must be a clap
    // value-parse error (exit 2), proving the boundary validates input
    // before touching any storage.
    let t = tmp();
    clx(&t)
        .args(["maintenance", "trim", "--tool-events-days", "soon"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("soon").or(predicate::str::contains("invalid")));
}

#[test]
fn maintenance_trim_dry_run_on_empty_db_reports_zero_without_deleting() {
    // Happy path on a freshly-installed (empty) DB: dry-run must succeed and
    // report zero would-delete counts. Distinct from misc suite which seeds
    // OLD rows; here the contract is "nothing to do" cleanliness.
    let t = tmp();
    clx(&t)
        .args(["--json", "install", "--target", "claude"])
        .assert()
        .success();

    let out = clx(&t)
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
    let v: serde_json::Value =
        serde_json::from_str(&String::from_utf8(out).unwrap()).expect("trim --json is JSON");
    assert_eq!(
        v["tool_events_would_delete"], 0,
        "empty DB dry-run must report zero would-delete: {v}"
    );
}

// ===========================================================================
// model: invalid-arg boundary + read-only status/list happy paths
// ===========================================================================

#[test]
fn model_without_subcommand_is_rejected_with_usage() {
    let t = tmp();
    clx(&t)
        .arg("model")
        .assert()
        .code(2)
        .stderr(predicate::str::contains("Usage"))
        .stderr(predicate::str::contains("status"));
}

#[test]
fn model_unknown_subcommand_is_rejected() {
    let t = tmp();
    clx(&t)
        .args(["model", "summon"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("summon").or(predicate::str::contains("subcommand")));
}

#[test]
fn model_status_json_lists_reranker_with_installed_flag() {
    // Read-only happy path. On a fresh HOME the reranker is NOT downloaded,
    // so its installed flag must be false. This proves status reflects real
    // on-disk state (a regression hard-coding installed=true is caught).
    let t = tmp();
    let out = clx(&t)
        .args(["--json", "model", "status"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let raw = String::from_utf8(out).unwrap();
    let v: serde_json::Value =
        serde_json::from_str(&raw).expect("model status --json must be valid JSON");
    // The payload must mention the bge reranker model by name somewhere.
    assert!(
        raw.contains("bge-reranker-v2-m3"),
        "model status must name the reranker model: {v}"
    );
    // And it must not falsely claim the (never-downloaded) model is present.
    assert!(
        !raw.contains("\"installed\": true") && !raw.contains("\"installed\":true"),
        "fresh HOME must not report the reranker as installed: {v}"
    );
}

#[test]
fn model_list_human_names_the_reranker() {
    let t = tmp();
    clx(&t)
        .args(["model", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("bge-reranker-v2-m3"));
}
