//! Wave: `clx recall` SEMANTIC e2e tests — the post-embedding
//! ranking + format path (`commands/recall.rs:96-178`).
//!
//! `cli_recall_deep_e2e.rs` reaches only the early-return guards (no DB /
//! no client / embed-error) and explicitly defers the
//! results/ranking/format block to 0.8.1 because that block requires a
//! live embedding provider to produce a query vector before the
//! similarity search runs.
//!
//! The 0.8.1 seam refactor (campaign v2 Stream 1) routes that step
//! through the existing `QueryEmbedder` / `SnapshotRepo` ports, exactly
//! as the proven reference `clx-mcp/src/tools/recall.rs` drives
//! `RecallEngine`. These tests reach the previously-unreachable block
//! **offline** with the established `recall_behavior.rs:431-472`
//! wiremock-Ollama + config-in-sandbox pattern:
//!
//! 1. An isolated `HOME` tempdir holds the sandbox `~/.clx`.
//! 2. The sandbox DB (`~/.clx/data/clx.db`) is seeded in-process via
//!    `clx-core` with a session + snapshot and (for the non-empty cases)
//!    a stored embedding vector.
//! 3. `config.yaml` points the `ollama` provider `host` at a wiremock
//!    server whose `POST /api/embeddings` returns the *same* vector, so
//!    the real `clx recall` binary's port-driven similarity search
//!    surfaces the seeded snapshot deterministically — no network, no
//!    model, no keychain.
//!
//! Behaviour contract asserted (observable CLI output is byte-identical
//! to the pre-refactor raw `find_similar` path; this is a seam refactor):
//!
//! | Test | recall.rs lines exercised |
//! |---|---|
//! | json non-empty | `:102-124` (JSON results loop + truncation + RecallResult build) |
//! | json empty | `:102-124` with empty `results` array |
//! | human non-empty (2 hits, multi-line) | `:125-178` (rank header / distance / Session / Time / Summary+Key Facts `.lines().take(3)`) |
//! | human empty | `:132-142` ("No matching context found." + embedding_count branch) |

#![allow(clippy::doc_markdown)]

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use clx_core::embeddings::{DEFAULT_EMBEDDING_DIM, EmbeddingStore};
use clx_core::storage::Storage;
use clx_core::types::{Session, SessionId, Snapshot, SnapshotTrigger};

/// A `clx` command with HOME + XDG fully isolated to `tmp` and the
/// hermetic env trio set (no keychain prompt, no 2.1GB model, RRF-only).
fn clx(tmp: &TempDir) -> Command {
    let mut cmd = Command::cargo_bin("clx").expect("clx binary");
    cmd.env("HOME", tmp.path())
        .env("XDG_DATA_HOME", tmp.path().join("xdg-data"))
        .env("XDG_CONFIG_HOME", tmp.path().join("xdg-config"))
        .env("CLX_CREDENTIALS_BACKEND", "age")
        .env("CLX_MODEL_FETCH_DRYRUN", "1")
        .env("CLX_RERANKER_ENABLED", "false")
        .env("CLX_LOG", "error");
    cmd
}

fn tmp() -> TempDir {
    tempfile::tempdir().expect("tempdir")
}

/// The sandbox DB path the `clx` binary will resolve from the isolated
/// `HOME` (`~/.clx/data/clx.db`). The in-process seeding writes the very
/// same file the subprocess later reads.
fn sandbox_db_path(t: &TempDir) -> std::path::PathBuf {
    t.path().join(".clx").join("data").join("clx.db")
}

/// Write a minimal `config.yaml` routing both capabilities at an `ollama`
/// provider whose `host` is the wiremock server. `create_llm_client`
/// then succeeds and `embed()` round-trips to the mock — no real network.
fn seed_wiremock_config(t: &TempDir, host: &str) {
    let clx_dir = t.path().join(".clx");
    std::fs::create_dir_all(&clx_dir).unwrap();
    std::fs::write(
        clx_dir.join("config.yaml"),
        format!(
            concat!(
                "providers:\n",
                "  ollama-mock:\n",
                "    kind: ollama\n",
                "    host: \"{host}\"\n",
                "    model: \"qwen2.5:3b\"\n",
                "    embedding_model: \"nomic-embed-text\"\n",
                "    max_retries: 0\n",
                "llm:\n",
                "  chat:\n",
                "    provider: ollama-mock\n",
                "    model: \"qwen2.5:3b\"\n",
                "  embeddings:\n",
                "    provider: ollama-mock\n",
                "    model: \"nomic-embed-text\"\n",
            ),
            host = host
        ),
    )
    .unwrap();
}

/// Seed one session + one snapshot into the sandbox DB. Returns the
/// snapshot id (auto-generated primary key).
fn seed_snapshot(t: &TempDir, sess: &str, summary: &str, key_facts: &str) -> i64 {
    let storage = Storage::open(sandbox_db_path(t)).expect("open sandbox storage");
    let session = Session::new(SessionId::new(sess), "/tmp/proj".to_string());
    storage.create_session(&session).unwrap();
    let mut snap = Snapshot::new(SessionId::new(sess), SnapshotTrigger::Auto);
    snap.summary = Some(summary.to_string());
    snap.key_facts = Some(key_facts.to_string());
    storage.create_snapshot(&snap).unwrap()
}

/// Store `vector` as the embedding for `snapshot_id` in the sandbox DB.
fn seed_embedding(t: &TempDir, snapshot_id: i64, vector: Vec<f32>) {
    clx_core::init_sqlite_vec();
    let store = EmbeddingStore::open(sandbox_db_path(t)).expect("open sandbox embedding store");
    store.store_embedding(snapshot_id, vector).unwrap();
}

/// A deterministic `DEFAULT_EMBEDDING_DIM`-length vector. The wiremock
/// returns the identical vector, so `find_similar` yields distance ~0.
fn fixed_vector() -> Vec<f32> {
    vec![0.25f32; DEFAULT_EMBEDDING_DIM]
}

/// Mount `POST /api/embeddings` returning the given vector as the Ollama
/// `{"embedding":[...]}` body.
async fn mount_embedding(server: &MockServer, vector: &[f32]) {
    let values: Vec<String> = vector
        .iter()
        .map(std::string::ToString::to_string)
        .collect();
    let body = format!("{{\"embedding\":[{}]}}", values.join(","));
    Mock::given(method("POST"))
        .and(path("/api/embeddings"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(body, "application/json"))
        .mount(server)
        .await;
}

// ===========================================================================
// JSON arm — non-empty results (recall.rs:102-124)
// ===========================================================================

#[tokio::test]
async fn recall_json_semantic_hit_builds_recallresult() {
    let t = tmp();
    let server = MockServer::start().await;
    mount_embedding(&server, &fixed_vector()).await;
    seed_wiremock_config(&t, &server.uri());

    let id = seed_snapshot(
        &t,
        "sess-json-hit",
        "Implemented Azure fallback wiring for the embeddings route",
        "decision: prefer age credential backend",
    );
    seed_embedding(&t, id, fixed_vector());

    let out = clx(&t)
        .args(["--json", "recall", "azure fallback"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value =
        serde_json::from_str(&String::from_utf8(out).unwrap()).expect("recall --json is JSON");

    assert_eq!(v["query"], "azure fallback");
    let results = v["results"].as_array().expect("results array");
    assert_eq!(results.len(), 1, "exactly the one seeded snapshot: {v}");
    let r = &results[0];
    assert_eq!(r["session_id"], "sess-json-hit");
    // RecallResult.content is the truncated Summary/Key Facts/TODOs blob.
    let content = r["content"].as_str().unwrap();
    assert!(
        content.contains("Summary: Implemented Azure fallback wiring"),
        "content must carry the summary: {content}"
    );
    assert!(
        content.contains("Key Facts: decision: prefer age credential backend"),
        "content must carry the key facts: {content}"
    );
    assert!(
        content.contains("TODOs: "),
        "content must carry TODOs label"
    );
    // distance present and finite (deterministic ~0 for identical vectors).
    assert!(
        r["distance"].as_f64().is_some_and(f64::is_finite),
        "distance must be a finite number: {r}"
    );
    assert!(
        r["timestamp"].as_str().is_some_and(|s| !s.is_empty()),
        "timestamp must be a non-empty rfc3339 string: {r}"
    );
}

// ===========================================================================
// JSON arm — empty results (recall.rs:102-124, empty `results`)
// ===========================================================================

#[tokio::test]
async fn recall_json_no_embeddings_yields_empty_results_array() {
    let t = tmp();
    let server = MockServer::start().await;
    mount_embedding(&server, &fixed_vector()).await;
    seed_wiremock_config(&t, &server.uri());

    // Snapshot exists but NO embedding stored -> find_similar returns [].
    seed_snapshot(
        &t,
        "sess-json-empty",
        "unembedded summary",
        "unembedded facts",
    );

    let out = clx(&t)
        .args(["--json", "recall", "anything"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value =
        serde_json::from_str(&String::from_utf8(out).unwrap()).expect("recall --json is JSON");

    assert_eq!(v["query"], "anything");
    assert!(
        v["results"].as_array().is_some_and(std::vec::Vec::is_empty),
        "no stored embedding -> empty results array: {v}"
    );
}

// ===========================================================================
// Human arm — non-empty, multi-hit, multi-line (recall.rs:125-178)
// ===========================================================================

#[tokio::test]
async fn recall_human_semantic_two_hits_render_rank_distance_summary_facts() {
    let t = tmp();
    let server = MockServer::start().await;
    mount_embedding(&server, &fixed_vector()).await;
    seed_wiremock_config(&t, &server.uri());

    // Two snapshots, each with a multi-line summary + key_facts so the
    // `.lines().take(3)` rendering is exercised.
    let multi_summary = "line one of summary\nline two of summary\nline three\nline four (dropped)";
    let multi_facts = "fact alpha\nfact beta\nfact gamma\nfact delta (dropped)";
    let id1 = seed_snapshot(&t, "sess-h1", multi_summary, multi_facts);
    let id2 = seed_snapshot(&t, "sess-h2", multi_summary, multi_facts);
    seed_embedding(&t, id1, fixed_vector());
    seed_embedding(&t, id2, fixed_vector());

    clx(&t)
        .args(["recall", "previous retry decisions"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Context Recall"))
        .stdout(predicate::str::contains("Query:  previous retry decisions"))
        // rank header + distance line
        .stdout(predicate::str::contains("1. Snapshot #"))
        .stdout(predicate::str::contains("2. Snapshot #"))
        .stdout(predicate::str::contains("(distance:"))
        // per-hit metadata
        .stdout(predicate::str::contains("Session: sess-h1"))
        .stdout(predicate::str::contains("Session: sess-h2"))
        .stdout(predicate::str::contains("Time: "))
        .stdout(predicate::str::contains("Summary:"))
        .stdout(predicate::str::contains("Key Facts:"))
        // first 3 lines kept, 4th dropped by .lines().take(3)
        .stdout(predicate::str::contains("line one of summary"))
        .stdout(predicate::str::contains("line three"))
        .stdout(predicate::str::contains("fact gamma"))
        .stdout(predicate::str::contains("line four (dropped)").not())
        .stdout(predicate::str::contains("fact delta (dropped)").not());
}

// ===========================================================================
// Human arm — empty (recall.rs:132-142)
// ===========================================================================

#[tokio::test]
async fn recall_human_no_embeddings_says_no_matching_and_no_embeddings_yet() {
    let t = tmp();
    let server = MockServer::start().await;
    mount_embedding(&server, &fixed_vector()).await;
    seed_wiremock_config(&t, &server.uri());

    // Snapshot but no embedding -> similar empty AND count_embeddings()==0,
    // so the "No embeddings stored yet." sub-branch renders.
    seed_snapshot(&t, "sess-h-empty", "summary", "facts");

    clx(&t)
        .args(["recall", "no match query"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Context Recall"))
        .stdout(predicate::str::contains("Query:  no match query"))
        .stdout(predicate::str::contains("No matching context found."))
        .stdout(predicate::str::contains("No embeddings stored yet."))
        .stdout(predicate::str::contains(
            "Run: clx embed-backfill to generate embeddings",
        ));
}

// ===========================================================================
// Seam contract: the port-driven path is a graceful Ok(()) (exit 0).
// ===========================================================================

#[tokio::test]
async fn recall_semantic_hit_exits_zero_no_panic() {
    let t = tmp();
    let server = MockServer::start().await;
    mount_embedding(&server, &fixed_vector()).await;
    seed_wiremock_config(&t, &server.uri());

    let id = seed_snapshot(&t, "sess-exit", "graceful summary", "graceful facts");
    seed_embedding(&t, id, fixed_vector());

    let out = clx(&t)
        .args(["recall", "graceful"])
        .output()
        .expect("spawn recall");
    assert_eq!(
        out.status.code(),
        Some(0),
        "port-driven recall must exit 0; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}
