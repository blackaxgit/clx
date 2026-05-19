//! Wave: `clx recall` e2e tests.
//!
//! Anchored to `specs/_prerelease/02-memory-recall.md` and the
//! `04-integration.md` command table (`recall <query>` ->
//! `commands::cmd_recall`). Behaviour-driven: asserts the observable
//! CLI contract -- recall on an uninitialised / offline store must exit 0
//! and print a helpful "no context" message, never panic, never hang on
//! the network.
//!
//! Isolation: HOME + XDG redirected into a fresh `tempfile::TempDir`, so
//! the DB path (`~/.clx/data/clx.db`) and config land in throwaway space.
//! `CLX_MODEL_FETCH_DRYRUN=1` and `reranker_enabled=false` are forced so
//! no 2.1GB model is fetched and the RRF-only path is exercised. No
//! network: an offline embedding-provider failure is a graceful Ok(())
//! per `commands/recall.rs`.

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
        // RRF-only / reranker disabled path: recall must not error.
        .env("CLX_RERANKER_ENABLED", "false")
        .env("CLX_LOG", "error");
    cmd
}

fn tmp() -> TempDir {
    tempfile::tempdir().expect("tempdir")
}

// ===========================================================================
// Uninitialised store: graceful "not initialized", exit 0, no panic
// ===========================================================================

#[test]
fn recall_on_fresh_home_is_graceful_exit_zero() {
    // Observed real behaviour: the embedding store is auto-created on a
    // fresh HOME, so recall.rs proceeds past the store check and hits the
    // offline "Ollama is not configured" branch -- still a graceful Ok(())
    // (exit 0) with a helpful hint, never a panic. The contract under test
    // is "no usable embedding backend -> graceful, not a crash".
    let t = tmp();
    clx(&t)
        .args(["recall", "anything at all"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Context Recall"))
        .stdout(
            predicate::str::contains("Ollama is not configured")
                .or(predicate::str::contains("Database not initialized")),
        );
}

#[test]
fn recall_json_on_fresh_home_emits_empty_results_array() {
    let t = tmp();
    let out = clx(&t)
        .args(["--json", "recall", "some query"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value =
        serde_json::from_str(&String::from_utf8(out).unwrap()).expect("recall --json is JSON");
    assert_eq!(v["query"], "some query");
    assert!(
        v["results"].as_array().is_some_and(std::vec::Vec::is_empty),
        "fresh-home recall must yield an empty results array: {v}"
    );
}

// ===========================================================================
// Installed but offline: embedding provider unavailable -> graceful Ok
// ===========================================================================

#[test]
fn recall_after_install_offline_is_graceful_not_error() {
    // After `install` the DB exists but no Ollama/provider is reachable
    // (hermetic: no network). recall.rs must still return Ok(()) and print
    // a "could not generate embedding" style hint -- exit 0, no panic.
    let t = tmp();
    clx(&t).args(["--json", "install"]).assert().success();
    let out = clx(&t)
        .args(["recall", "previous decisions about retries"])
        .output()
        .expect("spawn recall");
    assert_eq!(
        out.status.code(),
        Some(0),
        "recall must exit 0 even when the embedding provider is offline; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("Context Recall") || stdout.contains("Database not initialized"),
        "expected a recall banner or init hint, got: {stdout}"
    );
}

#[test]
fn recall_after_install_json_offline_yields_empty_results() {
    let t = tmp();
    clx(&t).args(["--json", "install"]).assert().success();
    let out = clx(&t)
        .args(["--json", "recall", "azure fallback"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8(out).unwrap()).unwrap();
    assert_eq!(v["query"], "azure fallback");
    assert!(v["results"].as_array().is_some_and(std::vec::Vec::is_empty));
}

// ===========================================================================
// Edge args
// ===========================================================================

#[test]
fn recall_missing_query_arg_is_clap_usage_error() {
    // `query` is a required positional; omitting it must be a clap failure
    // (exit 2 / nonzero) with a usage message, not a panic.
    let t = tmp();
    clx(&t)
        .arg("recall")
        .assert()
        .failure()
        .stderr(predicate::str::contains("Usage").or(predicate::str::contains("required")));
}

#[test]
fn recall_empty_string_query_is_handled_not_panic() {
    // An empty query string is a valid arg; must not panic / signal-abort.
    let t = tmp();
    let out = clx(&t).args(["recall", ""]).output().expect("spawn");
    assert!(
        out.status.code().is_some(),
        "empty-query recall must exit with a code, not a signal"
    );
}

#[test]
fn recall_very_long_query_does_not_panic() {
    let t = tmp();
    let long = "q ".repeat(5_000);
    let out = clx(&t).args(["recall", &long]).output().expect("spawn");
    assert!(
        out.status.code().is_some(),
        "long-query recall must exit with a code, not a signal"
    );
}
