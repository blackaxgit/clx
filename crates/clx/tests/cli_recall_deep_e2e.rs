//! Wave: `clx recall` DEEP e2e tests -- success/branch pipelines.
//!
//! The existing `cli_recall_e2e.rs` only reaches the first two graceful
//! guards of `commands/recall.rs` (no embedding store, then no LLM
//! client because the default `config.yaml` has `llm: null`). These
//! tests seed a real `llm:` routing block pointed at an UNREACHABLE
//! ollama host so `Config::create_llm_client(Embeddings)` SUCCEEDS, the
//! pipeline advances past the `create_llm_client` guard, and the
//! query-embedding call then fails at the network boundary -- driving
//! the previously-uncovered embed-error branch
//! (`recall.rs:69-93`, both the `--json` and human arms).
//!
//! Isolation: HOME + XDG redirected into a fresh `tempfile::TempDir`
//! (RAII; auto-removed on drop, panic-safe). The env trio
//! `CLX_CREDENTIALS_BACKEND=file`, `CLX_MODEL_FETCH_DRYRUN=1`,
//! `CLX_RERANKER_ENABLED=false` keeps the run hermetic: no keychain
//! prompt, no 2.1GB model, no real provider. The seeded host
//! `http://127.0.0.1:1` is a closed port; the embed call fails fast
//! locally with no outbound network.
//!
//! Residual (NOT reachable offline): the actual results/ranking/format
//! block (`recall.rs:96-178`) requires a live embedding provider to
//! produce a query vector before `find_similar` runs. Left for
//! main-session triage; not faked here.

#![allow(clippy::doc_markdown)]

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

/// A `clx` command with HOME + XDG fully isolated to `tmp`.
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

/// Seed `~/.clx/config.yaml` with an `llm:` routing block whose ollama
/// provider points at a closed local port. `create_llm_client` then
/// succeeds (client construction does no IO) but `embed()` fails fast at
/// the socket -- the exact precondition for the embed-error branch.
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
// Embed-error branch (recall.rs:69-93) -- previously uncovered.
// ===========================================================================

#[test]
fn recall_human_with_routed_provider_hits_embed_error_branch() {
    // create_llm_client SUCCEEDS (valid `llm:` routing) so the pipeline
    // advances past the no-client guard; the query embed() then fails at
    // the closed socket, exercising the human-mode embed-error arm
    // ("Make sure Ollama is running: ollama serve" + "Error: ...").
    let t = tmp();
    seed_unreachable_ollama_config(&t);
    clx(&t).args(["--json", "install"]).assert().success();
    clx(&t)
        .args(["recall", "previous retry decisions"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Context Recall"))
        .stdout(predicate::str::contains("Query:  previous retry decisions"))
        .stdout(predicate::str::contains(
            "Could not generate embedding for query.",
        ))
        .stdout(predicate::str::contains("ollama serve"))
        .stdout(predicate::str::contains("Error:"));
}

#[test]
fn recall_json_with_routed_provider_hits_embed_error_branch_empty_results() {
    // Same precondition, `--json` arm of the embed-error branch: a valid
    // RecallOutput with the echoed query and an empty results array.
    let t = tmp();
    seed_unreachable_ollama_config(&t);
    clx(&t).args(["--json", "install"]).assert().success();
    let out = clx(&t)
        .args(["--json", "recall", "azure fallback wiring"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value =
        serde_json::from_str(&String::from_utf8(out).unwrap()).expect("recall --json is JSON");
    assert_eq!(v["query"], "azure fallback wiring");
    assert!(
        v["results"].as_array().is_some_and(std::vec::Vec::is_empty),
        "embed-error branch must still yield an empty results array: {v}"
    );
}

#[test]
fn recall_embed_error_branch_exits_zero_no_panic() {
    // The embed-error branch is a graceful Ok(()): exit 0 with a code
    // (never a signal/panic), even though embedding generation failed.
    let t = tmp();
    seed_unreachable_ollama_config(&t);
    clx(&t).args(["--json", "install"]).assert().success();
    let out = clx(&t)
        .args(["recall", "some long-lived query string"])
        .output()
        .expect("spawn recall");
    assert_eq!(
        out.status.code(),
        Some(0),
        "embed-error recall must exit 0; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

// ===========================================================================
// No-client branch on a routed-but-malformed config (distinct guard).
// ===========================================================================

#[test]
fn recall_json_with_unknown_provider_route_hits_no_client_branch() {
    // `llm:` routes to a provider name absent from `providers:`, so
    // create_llm_client returns Err -> the no-client `--json` arm
    // (recall.rs:40-57). This is a different guard than the embed-error
    // branch above, reached via a malformed-but-present routing block.
    let t = tmp();
    let clx_dir = t.path().join(".clx");
    std::fs::create_dir_all(&clx_dir).unwrap();
    std::fs::write(
        clx_dir.join("config.yaml"),
        concat!(
            "providers: {}\n",
            "llm:\n",
            "  chat:\n",
            "    provider: ghost\n",
            "    model: \"m\"\n",
            "  embeddings:\n",
            "    provider: ghost\n",
            "    model: \"m\"\n",
        ),
    )
    .unwrap();
    clx(&t).args(["--json", "install"]).assert().success();
    let out = clx(&t)
        .args(["--json", "recall", "q"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8(out).unwrap()).unwrap();
    assert_eq!(v["query"], "q");
    assert!(v["results"].as_array().is_some_and(std::vec::Vec::is_empty));
}
