//! Wave: `clx embeddings` / `clx embed-backfill` DEEP e2e tests.
//!
//! The existing `cli_embeddings_e2e.rs` only reaches the dry-run and the
//! no-`llm:`-config graceful arms. With a real `llm:` routing block that
//! points at a closed local port, `create_llm_client(Embeddings)`
//! SUCCEEDS so the pipeline advances past that guard and then hits the
//! provider-`is_available()==false` branch -- previously uncovered:
//!   * `embeddings rebuild` (no `--dry-run`): table is dropped+recreated
//!     (`embeddings.rs:155-184`), then the `!is_available()` arm fires
//!     (`embeddings.rs:213-234`) with `table_rebuilt:true`.
//!   * `embed-backfill` (no `--dry-run`): the create-client SUCCESS path
//!     followed by the provider-unavailable arm (`embeddings.rs:358-376`)
//!     -- a different branch than the no-client arm the old test hits.
//!
//! Isolation: HOME + XDG redirected into a fresh RAII `tempfile::TempDir`.
//! The seeded ollama host is `127.0.0.1:1` (closed): the availability
//! probe fails fast locally, no outbound network.
//!
//! Residual (NOT reachable offline): the per-snapshot `client.embed()`
//! loop that actually stores vectors (`embeddings.rs:246-311`,
//! `:411-445`) needs a live provider. Left for main-session triage.

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

/// Seed a routed config whose ollama provider is a closed local port:
/// client construction succeeds, the availability probe fails fast.
fn seed_unreachable_ollama_config(t: &TempDir) {
    let clx_dir = t.path().join(".clx");
    std::fs::create_dir_all(&clx_dir).unwrap();
    std::fs::write(
        clx_dir.join("config.yaml"),
        concat!(
            "providers:\n",
            "  ollama-local:\n",
            "    kind: ollama\n",
            "    host: \"http://127.0.0.1:1\"\n",
            "    model: \"qwen2.5:3b\"\n",
            "    embedding_model: \"nomic-embed-text\"\n",
            "    embedding_dim: 768\n",
            "llm:\n",
            "  chat:\n",
            "    provider: ollama-local\n",
            "    model: \"qwen2.5:3b\"\n",
            "  embeddings:\n",
            "    provider: ollama-local\n",
            "    model: \"nomic-embed-text\"\n",
        ),
    )
    .unwrap();
}

// ===========================================================================
// `embeddings rebuild` (no --dry-run): table rebuilt + provider-unavailable
// ===========================================================================

#[test]
fn embeddings_rebuild_nondryrun_json_rebuilds_table_then_provider_unavailable() {
    // Drives embeddings.rs:155-234: the table is dropped & recreated, the
    // LLM client is created OK (valid routing), then is_available() is
    // false -> the JSON arm reports table_rebuilt:true with zero
    // embeddings generated. This is the success-path-up-to-provider that
    // the dry-run-only existing test never reaches.
    let t = tmp();
    seed_unreachable_ollama_config(&t);
    clx(&t).args(["--json", "install"]).assert().success();
    let out = clx(&t)
        .args(["--json", "embeddings", "rebuild"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value =
        serde_json::from_str(&String::from_utf8(out).unwrap()).expect("rebuild --json is JSON");
    assert_eq!(
        v["table_rebuilt"], true,
        "table must be rebuilt before the provider check: {v}"
    );
    assert_eq!(v["embeddings_generated"], 0);
    assert_eq!(v["provider"], "ollama-local");
    assert!(
        v["error"]
            .as_str()
            .is_some_and(|s| s.contains("not available")),
        "expected a 'not available' provider error: {v}"
    );
}

#[test]
fn embeddings_rebuild_nondryrun_human_arm_reports_rebuilt_not_regenerated() {
    // Non-json arm of the same branch: header + the "Table ... recreated"
    // line + "Provider ... is not available." hint.
    let t = tmp();
    seed_unreachable_ollama_config(&t);
    clx(&t).args(["--json", "install"]).assert().success();
    clx(&t)
        .args(["embeddings", "rebuild"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Embedding Rebuild"))
        .stdout(predicate::str::contains("recreated").or(predicate::str::contains("rebuilt")))
        .stdout(predicate::str::contains("is not available"));
}

#[test]
fn embeddings_rebuild_nondryrun_exits_zero_no_panic() {
    let t = tmp();
    seed_unreachable_ollama_config(&t);
    clx(&t).args(["--json", "install"]).assert().success();
    let out = clx(&t)
        .args(["embeddings", "rebuild"])
        .output()
        .expect("spawn");
    assert_eq!(
        out.status.code(),
        Some(0),
        "rebuild-then-unavailable must be a graceful exit 0; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

// ===========================================================================
// `embeddings status` against a populated (post-rebuild) store
// ===========================================================================

#[test]
fn embeddings_status_human_after_rebuild_shows_no_migration_needed() {
    // After a rebuild at the configured dimension the store no longer
    // needs migration: the "Migration needed:  no" arm of the human
    // status renderer (embeddings.rs:84-86) -- distinct from the
    // needs-migration arm.
    let t = tmp();
    seed_unreachable_ollama_config(&t);
    clx(&t).args(["--json", "install"]).assert().success();
    clx(&t).args(["embeddings", "rebuild"]).assert().success();
    clx(&t)
        .args(["embeddings", "status"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Embedding Status"))
        .stdout(predicate::str::contains("Migration needed:"))
        .stdout(predicate::str::contains("no"));
}

// ===========================================================================
// `embed-backfill` (no --dry-run): create-client SUCCESS -> unavailable arm
// ===========================================================================

#[test]
fn embed_backfill_nondryrun_json_hits_provider_unavailable_arm() {
    // With valid routing the client is created OK, so the code reaches
    // the `!is_available()` arm (embeddings.rs:358-376) and emits the
    // provider-unavailable JSON object -- NOT the no-client arm the
    // existing fresh-home test covers.
    let t = tmp();
    seed_unreachable_ollama_config(&t);
    clx(&t).args(["--json", "install"]).assert().success();
    let out = clx(&t)
        .args(["--json", "embed-backfill"])
        .output()
        .expect("spawn");
    assert_eq!(
        out.status.code(),
        Some(0),
        "backfill must exit 0 on provider-unavailable; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_str(String::from_utf8_lossy(&out.stdout).trim())
        .expect("backfill --json must be valid JSON");
    assert_eq!(v["provider"], "ollama-local");
    assert!(
        v["error"]
            .as_str()
            .is_some_and(|s| s.contains("not available")),
        "expected provider-unavailable error: {v}"
    );
}

#[test]
fn embed_backfill_nondryrun_human_arm_reports_not_available() {
    // Non-json arm of the provider-unavailable backfill branch.
    let t = tmp();
    seed_unreachable_ollama_config(&t);
    clx(&t).args(["--json", "install"]).assert().success();
    clx(&t)
        .args(["embed-backfill"])
        .assert()
        .success()
        .stdout(predicate::str::contains("is not available"))
        .stdout(predicate::str::contains(
            "Check provider configuration before running backfill.",
        ));
}
