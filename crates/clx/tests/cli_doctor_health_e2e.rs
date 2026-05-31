//! E2E: `clx health` boundary defense.
//!
//! NOTE: the task brief asked for `clx doctor`, but that subcommand does
//! NOT exist in this binary (`clx --help` lists `health`, not `doctor`).
//! The health diagnostic is the real equivalent, so this suite drives
//! `clx health` for both the degraded path (fresh HOME: DB + binaries
//! missing -> non-zero exit + actionable stderr/stdout hints) and the
//! recovered path (after `clx install`: DB + hook/mcp binaries present).
//!
//! Isolation: HOME + XDG redirected into a fresh `tempfile::TempDir`. No
//! network call is asserted on (the Ollama check is best-effort and its
//! pass/fail is intentionally NOT asserted, so the suite is hermetic
//! whether or not a local Ollama happens to be running). The real
//! `~/.clx`, `~/.claude`, and the keychain are never touched.

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

fn clx(tmp: &TempDir) -> Command {
    let mut cmd = Command::cargo_bin("clx").expect("clx binary");
    cmd.env("HOME", tmp.path())
        .env("XDG_DATA_HOME", tmp.path().join("xdg-data"))
        .env("XDG_CONFIG_HOME", tmp.path().join("xdg-config"))
        .env("CLX_CREDENTIALS_BACKEND", "file")
        .env("CLX_LOG", "error")
        .current_dir(tmp.path());
    cmd
}

fn tmp() -> TempDir {
    tempfile::tempdir().expect("tempdir")
}

/// Parse the `--json` health report regardless of exit code (health exits
/// non-zero when any check fails, but still prints the JSON body).
fn health_json(t: &TempDir) -> serde_json::Value {
    let out = clx(t)
        .args(["--json", "health"])
        .assert()
        .get_output()
        .stdout
        .clone();
    serde_json::from_str(&String::from_utf8(out).expect("utf8")).expect("health --json is JSON")
}

// ===========================================================================
// Degraded path: fresh HOME, nothing installed -> non-zero exit + hints
// ===========================================================================

#[test]
fn health_on_fresh_home_exits_nonzero_with_database_missing_hint() {
    // Failure proof: on a pristine HOME the DB does not exist, so health
    // must report a non-success exit AND surface the actionable remediation
    // ("clx install"). A regression that swallowed failures (always exit 0)
    // or dropped the hint would be caught here.
    let t = tmp();
    clx(&t)
        .arg("health")
        .assert()
        .failure()
        .stdout(predicate::str::contains("Database"))
        .stdout(predicate::str::contains("not found"))
        .stdout(predicate::str::contains("clx install"));
}

#[test]
fn health_json_on_fresh_home_marks_database_and_binaries_failed() {
    // Same degraded state, asserted on the machine-readable contract so we
    // are not coupled to exact human glyphs/spacing. Database, Hook binary,
    // and MCP binary must all be status=fail before install.
    let t = tmp();
    let v = health_json(&t);

    let status_of = |name: &str| -> Option<String> {
        v["checks"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"] == name)
            .and_then(|c| c["status"].as_str())
            .map(str::to_owned)
    };

    assert_eq!(
        status_of("Database").as_deref(),
        Some("fail"),
        "fresh HOME must report Database as failed: {v}"
    );
    assert_eq!(
        status_of("Hook binary").as_deref(),
        Some("fail"),
        "fresh HOME must report Hook binary as failed: {v}"
    );
    assert_eq!(
        status_of("MCP binary").as_deref(),
        Some("fail"),
        "fresh HOME must report MCP binary as failed: {v}"
    );
    assert!(
        v["summary"]["failed"].as_u64().unwrap_or(0) >= 3,
        "fresh HOME must report at least 3 failed checks: {v}"
    );
    assert!(
        v["version"].as_str().is_some_and(|s| !s.is_empty()),
        "health report must carry a non-empty version: {v}"
    );
}

// ===========================================================================
// Recovered path: after `clx install` the DB + binaries exist
// ===========================================================================

#[test]
fn health_after_install_flips_database_and_binaries_to_pass() {
    // Lifecycle proof: install -> the previously-failing infra checks must
    // become non-failing. This is the strong companion to the degraded
    // test: it proves health actually observes the on-disk state change
    // rather than hard-coding fail/pass.
    let t = tmp();

    // Before: Database is failing (precondition guard).
    let before = health_json(&t);
    let db_before = before["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "Database")
        .and_then(|c| c["status"].as_str());
    assert_eq!(
        db_before,
        Some("fail"),
        "precondition: DB fails pre-install"
    );

    clx(&t)
        .args(["--json", "install", "--target", "claude"])
        .assert()
        .success();

    // After: the install must have created the DB and copied the binaries,
    // so those three checks must no longer be "fail".
    let after = health_json(&t);
    let after_status = |name: &str| -> Option<String> {
        after["checks"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"] == name)
            .and_then(|c| c["status"].as_str())
            .map(str::to_owned)
    };
    assert_ne!(
        after_status("Database").as_deref(),
        Some("fail"),
        "install must initialize the DB so health stops failing it: {after}"
    );
    assert_ne!(
        after_status("Hook binary").as_deref(),
        Some("fail"),
        "install must place the hook binary: {after}"
    );
    assert_ne!(
        after_status("MCP binary").as_deref(),
        Some("fail"),
        "install must place the mcp binary: {after}"
    );
    assert!(
        after["summary"]["failed"].as_u64().unwrap_or(99)
            < before["summary"]["failed"].as_u64().unwrap_or(0),
        "install must strictly reduce the number of failed checks: \
         before={before}, after={after}"
    );
}
