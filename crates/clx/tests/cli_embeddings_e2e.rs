//! Wave: `clx embeddings` + `clx embed-backfill` e2e tests.
//!
//! Anchored to `specs/_prerelease/02-memory-recall.md` (embedding model
//! identity / dimension migration) and the `04-integration.md` command
//! table (`embeddings <action>`, `embed-backfill [--dry-run]`).
//! Behaviour-driven: asserts the observable CLI contract on a fresh /
//! offline store -- status reports stable fields, the no-provider path is
//! a graceful Ok, argument validation rejects garbage.
//!
//! Isolation: HOME + XDG redirected into a fresh `tempfile::TempDir`.
//! `CLX_MODEL_FETCH_DRYRUN=1` so no 2.1GB model is fetched. No network:
//! provider-unavailable is the expected hermetic path.

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
// `clx embeddings status`
// ===========================================================================

#[test]
fn embeddings_status_after_install_reports_model_and_zero_count() {
    let t = tmp();
    clx(&t).args(["--json", "install"]).assert().success();
    let out = clx(&t)
        .args(["--json", "embeddings", "status"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value =
        serde_json::from_str(&String::from_utf8(out).unwrap()).expect("status --json is JSON");
    assert!(
        v["model"].as_str().is_some_and(|s| !s.is_empty()),
        "status must report a model: {v}"
    );
    assert!(v["dimension"].is_number(), "status must report dimension");
    assert_eq!(
        v["stored_embeddings"], 0,
        "fresh DB must have zero stored embeddings"
    );
    assert!(v["needs_migration"].is_boolean());
}

#[test]
fn embeddings_status_human_output_after_install_has_header() {
    let t = tmp();
    clx(&t).args(["--json", "install"]).assert().success();
    clx(&t)
        .args(["embeddings", "status"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Embedding Status"))
        .stdout(predicate::str::contains("Stored embeddings:"));
}

#[test]
fn embeddings_status_on_fresh_home_auto_creates_store_zero_count() {
    // Observed real behaviour: `create_embedding_store_with_dimension`
    // creates the parent dir + DB on demand, so status on a never-installed
    // HOME succeeds with zero stored embeddings (exit 0, no panic). This
    // pins the actual contract rather than an assumed "must fail".
    let t = tmp();
    let out = clx(&t)
        .args(["--json", "embeddings", "status"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8(out).unwrap()).unwrap();
    assert_eq!(v["stored_embeddings"], 0);
    assert!(v["model"].as_str().is_some_and(|s| !s.is_empty()));
}

// ===========================================================================
// `clx embeddings rebuild --dry-run` (no provider needed for dry run)
// ===========================================================================

#[test]
fn embeddings_rebuild_dry_run_json_reports_plan_without_provider() {
    // Dry run resolves provider/model and snapshot counts but performs no
    // network work -- safe and hermetic on a fresh DB.
    let t = tmp();
    clx(&t).args(["--json", "install"]).assert().success();
    let out = clx(&t)
        .args(["--json", "embeddings", "rebuild", "--dry-run"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8(out).unwrap()).unwrap();
    assert_eq!(v["dry_run"], true);
    assert!(v["model"].as_str().is_some());
    assert_eq!(
        v["total_snapshots"], 0,
        "fresh DB has no snapshots to regenerate"
    );
    assert_eq!(v["would_regenerate"], 0);
}

#[test]
fn embeddings_rebuild_dry_run_human_output_succeeds() {
    let t = tmp();
    clx(&t).args(["--json", "install"]).assert().success();
    clx(&t)
        .args(["embeddings", "rebuild", "--dry-run"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Embedding Rebuild (dry run)"))
        .stdout(predicate::str::contains("Run without --dry-run"));
}

// ===========================================================================
// `clx embed-backfill` (top-level command)
// ===========================================================================

#[test]
fn embed_backfill_offline_is_graceful_exit_zero() {
    // After install the DB exists but no provider is reachable; backfill
    // must return Ok(()) with a "not available" / "Failed to create LLM
    // client" hint -- exit 0, never panic.
    let t = tmp();
    clx(&t).args(["--json", "install"]).assert().success();
    let out = clx(&t)
        .args(["--json", "embed-backfill", "--dry-run"])
        .output()
        .expect("spawn");
    assert_eq!(
        out.status.code(),
        Some(0),
        "embed-backfill must exit 0 even when the provider is offline; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    // Output is valid JSON in --json mode regardless of which graceful
    // branch (no-client vs provider-unavailable vs zero-snapshots) is hit.
    let stdout = String::from_utf8_lossy(&out.stdout);
    serde_json::from_str::<serde_json::Value>(stdout.trim())
        .expect("embed-backfill --json output must be valid JSON");
}

#[test]
fn embed_backfill_on_fresh_home_is_graceful_no_llm_client() {
    // Observed real behaviour: on a fresh HOME the embedding store is
    // auto-created, then LLM-client creation fails (no `llm:`/`ollama:`
    // config) and the command returns a graceful Ok(()) JSON error object
    // with exit 0 -- never a panic / signal.
    let t = tmp();
    let out = clx(&t)
        .args(["--json", "embed-backfill", "--dry-run"])
        .output()
        .expect("spawn");
    assert_eq!(
        out.status.code(),
        Some(0),
        "embed-backfill must exit 0 on a fresh home; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let v: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("embed-backfill --json must be valid JSON");
    assert!(
        v.get("error").is_some() || v.get("total").is_some(),
        "expected a graceful error object or a summary: {v}"
    );
}

// ===========================================================================
// Argument validation
// ===========================================================================

#[test]
fn embeddings_unknown_subcommand_is_clap_error() {
    let t = tmp();
    clx(&t)
        .args(["embeddings", "frobnicate"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("unrecognized").or(predicate::str::contains("Usage")));
}

#[test]
fn embeddings_no_subcommand_is_clap_error() {
    // `EmbeddingsAction` is a required subcommand.
    let t = tmp();
    clx(&t).args(["embeddings"]).assert().failure();
}
