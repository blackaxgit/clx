//! Hermetic e2e for the `clx embeddings rebuild` / `clx embed-backfill`
//! per-snapshot embed loops, driving the REAL `clx` binary against a
//! `wiremock` Ollama. This closes the Seam B gap from the 0.8.1 coverage
//! campaign (`specs/2026-05-19-coverage-gap-map.md` S4b): the extracted
//! pure fns `rebuild_embeddings` / `backfill_embeddings` in
//! `crates/clx/src/commands/embeddings.rs` (lines 68-186 of that file) are
//! only reachable when a provider returns `Ok(embedding)`. Pointing the
//! `ollama` provider `host` at a `MockServer` makes the *real* extracted
//! code execute end-to-end with no network, no model download, no keychain.
//!
//! `clx` is a binary-only crate (no `[lib]`), so this is necessarily an
//! assert_cmd e2e against the built binary, not a clx-core unit test —
//! intentional, per the task brief.
//!
//! Region map (file = `crates/clx/src/commands/embeddings.rs`; gap-map
//! region refs are S4b `:246-282` rebuild and `:394-445` backfill):
//!
//! * rebuild processed arm  — embeddings.rs:95-104 (`embed` Ok ->
//!   `store_with_model` Ok -> `counts.processed`).
//! * rebuild skipped arm    — embeddings.rs:80-83 (empty text ->
//!   `counts.skipped`, `continue`).
//! * rebuild error arm      — embeddings.rs:97-101 (`store_with_model`
//!   Err on a wrong-dimension vector -> `counts.errors`) and 106-111
//!   (`embed` Err -> `counts.errors`).
//! * rebuild JSON summary   — embeddings.rs:422-435.
//! * rebuild human summary  — embeddings.rs:436-449.
//! * backfill has_embedding skip — embeddings.rs:135-138.
//! * backfill empty skip    — embeddings.rs:140-143.
//! * backfill dry-run arm   — embeddings.rs:150-158.
//! * backfill processed arm — embeddings.rs:160-173 (`embed` Ok ->
//!   `store_with_model` Ok -> `OK` + `counts.processed`).
//! * backfill error arm     — embeddings.rs:162-167 / 175-180.
//! * backfill JSON/human totals — embeddings.rs:543-572.
//!
//! Assertions are behavior contracts: observable stdout / JSON counts AND
//! the resulting DB state (embedding count + per-snapshot `has_embedding`
//! via `EmbeddingStore`). No mockall, no implementation pinning.

#![allow(clippy::doc_markdown)]

use assert_cmd::Command;
use clx_core::embeddings::DEFAULT_EMBEDDING_DIM;
use clx_core::storage::Storage;
use clx_core::types::{Session, SessionId, Snapshot, SnapshotTrigger};
use tempfile::TempDir;
use wiremock::matchers::{body_string_contains, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

// ---------------------------------------------------------------------------
// Sandbox + binary harness
// ---------------------------------------------------------------------------

fn tmp() -> TempDir {
    tempfile::tempdir().expect("tempdir")
}

/// The on-disk DB the real binary uses: `$HOME/.clx/data/clx.db`
/// (`clx_core::paths::database_path()` with `HOME` redirected).
fn db_path(t: &TempDir) -> std::path::PathBuf {
    t.path().join(".clx").join("data").join("clx.db")
}

fn clx(t: &TempDir) -> Command {
    let mut cmd = Command::cargo_bin("clx").expect("clx binary");
    cmd.env("HOME", t.path())
        .env("XDG_DATA_HOME", t.path().join("xdg-data"))
        .env("XDG_CONFIG_HOME", t.path().join("xdg-config"))
        .env("CLX_CREDENTIALS_BACKEND", "age")
        .env("CLX_MODEL_FETCH_DRYRUN", "1")
        .env("CLX_RERANKER_ENABLED", "false")
        .env("CLX_LOG", "error");
    cmd
}

/// Write a routed config whose `ollama` provider `host` points at the
/// wiremock server. `embedding_dim` is left at the default (1024 =
/// `DEFAULT_EMBEDDING_DIM`) so seeded + canned vectors line up.
fn seed_config(t: &TempDir, mock_uri: &str) {
    let clx_dir = t.path().join(".clx");
    std::fs::create_dir_all(&clx_dir).unwrap();
    std::fs::write(
        clx_dir.join("config.yaml"),
        format!(
            concat!(
                "providers:\n",
                "  ollama-local:\n",
                "    kind: ollama\n",
                "    host: \"{uri}\"\n",
                "    model: \"qwen2.5:3b\"\n",
                "    embedding_model: \"nomic-embed-text\"\n",
                "llm:\n",
                "  chat:\n",
                "    provider: ollama-local\n",
                "    model: \"qwen2.5:3b\"\n",
                "  embeddings:\n",
                "    provider: ollama-local\n",
                "    model: \"nomic-embed-text\"\n",
            ),
            uri = mock_uri
        ),
    )
    .unwrap();
}

/// Insert a snapshot row directly through the same `clx-core` API the
/// production binary uses, into the binary's on-disk DB. Returns the
/// snapshot id. `summary` becomes the embed `prompt` text (joined with
/// key_facts/todos by `iter_snapshots_for_rebuild`).
fn seed_snapshot(storage: &Storage, session: &SessionId, summary: Option<&str>) -> i64 {
    let mut snap = Snapshot::new(session.clone(), SnapshotTrigger::Auto);
    snap.summary = summary.map(str::to_string);
    snap.key_facts = None;
    snap.todos = None;
    storage.create_snapshot(&snap).expect("create snapshot")
}

/// Distinctive marker the wiremock body matcher uses to route ONE
/// snapshot's embed request to a wrong-dimension (512) response so the
/// real `store_with_model` returns `Err` (the error arm).
const BAD_DIM_MARKER: &str = "FORCE_WRONG_DIMENSION_ERROR_ARM";

/// Mount the two endpoints the embed path hits:
///   * `GET  /api/tags`       — `is_available()` probe (must 200).
///   * `POST /api/embeddings` — default: a fixed 1024-dim vector;
///     the `BAD_DIM_MARKER` request gets a 512-dim vector instead so
///     `EmbeddingStore::store_with_model` rejects it (dimension mismatch).
async fn mount_ollama(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/api/tags"))
        .respond_with(
            ResponseTemplate::new(200).set_body_raw(r#"{"models":[]}"#, "application/json"),
        )
        .mount(server)
        .await;

    let good = {
        let v = vec!["0.01"; DEFAULT_EMBEDDING_DIM];
        format!(r#"{{"embedding":[{}]}}"#, v.join(","))
    };
    let bad = {
        let v = vec!["0.01"; 512];
        format!(r#"{{"embedding":[{}]}}"#, v.join(","))
    };

    // Specific (wrong-dimension) mock for the error-arm snapshot — mounted
    // first and body-scoped so it wins over the default.
    Mock::given(method("POST"))
        .and(path("/api/embeddings"))
        .and(body_string_contains(BAD_DIM_MARKER))
        .respond_with(ResponseTemplate::new(200).set_body_raw(bad, "application/json"))
        .mount(server)
        .await;

    Mock::given(method("POST"))
        .and(path("/api/embeddings"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(good, "application/json"))
        .mount(server)
        .await;
}

/// Count stored embeddings via the same store the production code uses,
/// asserting resulting DB state (not just stdout).
fn embedding_count(t: &TempDir) -> i64 {
    clx_core::init_sqlite_vec();
    let store = Storage::create_embedding_store_with_dimension(db_path(t), DEFAULT_EMBEDDING_DIM)
        .expect("open embedding store");
    store.count_embeddings().expect("count")
}

fn has_embedding(t: &TempDir, id: i64) -> bool {
    clx_core::init_sqlite_vec();
    let store = Storage::create_embedding_store_with_dimension(db_path(t), DEFAULT_EMBEDDING_DIM)
        .expect("open embedding store");
    store.has_embedding(id).expect("has_embedding")
}

// ===========================================================================
// rebuild: processed + skipped + error permutation, JSON summary
//   Exercises embeddings.rs rebuild_embeddings (file lines 68-116):
//     :80-83  skipped (empty text)
//     :95-104 processed (embed Ok -> store_with_model Ok)
//     :97-101 error    (store_with_model Err: wrong-dim vector)
//   plus the JSON summary at embeddings.rs:422-435 (S4b :246-282 + summary)
// ===========================================================================

#[tokio::test]
async fn rebuild_json_covers_processed_skipped_error_arms_and_db_state() {
    let t = tmp();
    let server = MockServer::start().await;
    mount_ollama(&server).await;
    seed_config(&t, &server.uri());

    // `clx install` initializes the DB/integration the same way a user would.
    clx(&t).args(["--json", "install"]).assert().success();

    // Seed three snapshots into the binary's on-disk DB.
    let (good_id, empty_id, bad_id) = {
        let storage = Storage::open(db_path(&t)).expect("open db");
        let session = SessionId::new("sess-embed-rebuild");
        storage
            .create_session(&Session::new(session.clone(), "/tmp/proj".to_string()))
            .expect("create session");
        let good = seed_snapshot(
            &storage,
            &session,
            Some("normal snapshot that embeds cleanly"),
        );
        // Empty summary -> joined text is whitespace-only -> skipped arm.
        let empty = seed_snapshot(&storage, &session, None);
        let bad = seed_snapshot(
            &storage,
            &session,
            Some(&format!("snapshot {BAD_DIM_MARKER} triggers store error")),
        );
        (good, empty, bad)
    };

    let out = clx(&t)
        .args(["--json", "embeddings", "rebuild"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value =
        serde_json::from_str(String::from_utf8_lossy(&out).trim()).expect("rebuild --json is JSON");

    // Observable counts: 1 processed, 1 skipped (empty), 1 error (bad dim).
    assert_eq!(v["processed"], 1, "exactly the good snapshot embeds: {v}");
    assert_eq!(v["skipped"], 1, "the empty-text snapshot is skipped: {v}");
    assert_eq!(v["errors"], 1, "the wrong-dim snapshot errors: {v}");
    assert_eq!(v["total_snapshots"], 3, "{v}");
    assert_eq!(v["provider"], "ollama-local");

    // Resulting DB state: only the good snapshot got an embedding row.
    assert_eq!(embedding_count(&t), 1, "exactly one stored embedding");
    assert!(has_embedding(&t, good_id), "good snapshot embedded");
    assert!(!has_embedding(&t, empty_id), "empty snapshot not embedded");
    assert!(!has_embedding(&t, bad_id), "errored snapshot not embedded");
}

// ===========================================================================
// rebuild: human (non-JSON) summary arm — embeddings.rs:436-449
//   Same loop arms as above; asserts the human Summary block + Processed
//   line render, and DB state matches.
// ===========================================================================

#[tokio::test]
async fn rebuild_human_renders_summary_and_processes_snapshot() {
    let t = tmp();
    let server = MockServer::start().await;
    mount_ollama(&server).await;
    seed_config(&t, &server.uri());
    clx(&t).args(["--json", "install"]).assert().success();

    let good_id = {
        let storage = Storage::open(db_path(&t)).expect("open db");
        let session = SessionId::new("sess-embed-rebuild-human");
        storage
            .create_session(&Session::new(session.clone(), "/tmp/proj".to_string()))
            .expect("create session");
        seed_snapshot(&storage, &session, Some("human-mode rebuild snapshot"))
    };

    clx(&t)
        .args(["embeddings", "rebuild"])
        .assert()
        .success()
        .stdout(predicates::str::contains("Embedding Rebuild"))
        .stdout(predicates::str::contains("Summary:"))
        .stdout(predicates::str::contains("Processed:"))
        .stdout(predicates::str::contains("Provider:"));

    assert_eq!(embedding_count(&t), 1, "human rebuild stored one embedding");
    assert!(has_embedding(&t, good_id));
}

// ===========================================================================
// rebuild: embed-error arm — embeddings.rs:106-111
//   wiremock returns HTTP 500 on /api/embeddings -> `client.embed` Err ->
//   the Err(e) branch counts as an error (distinct from the store-Err arm).
// ===========================================================================

#[tokio::test]
async fn rebuild_embed_http_error_counts_as_error_arm() {
    let t = tmp();
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/tags"))
        .respond_with(
            ResponseTemplate::new(200).set_body_raw("{\"models\":[]}", "application/json"),
        )
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/embeddings"))
        .respond_with(ResponseTemplate::new(500).set_body_raw("boom", "text/plain"))
        .mount(&server)
        .await;
    seed_config(&t, &server.uri());
    clx(&t).args(["--json", "install"]).assert().success();

    {
        let storage = Storage::open(db_path(&t)).expect("open db");
        let session = SessionId::new("sess-embed-err");
        storage
            .create_session(&Session::new(session.clone(), "/tmp/proj".to_string()))
            .expect("create session");
        seed_snapshot(&storage, &session, Some("snapshot whose embed call 500s"));
    }

    let out = clx(&t)
        .args(["--json", "embeddings", "rebuild"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value =
        serde_json::from_str(String::from_utf8_lossy(&out).trim()).expect("JSON");
    assert_eq!(v["processed"], 0, "embed failed -> nothing processed: {v}");
    assert_eq!(v["errors"], 1, "embed HTTP 500 -> error arm: {v}");
    assert_eq!(embedding_count(&t), 0, "no embedding stored on embed error");
}

// ===========================================================================
// backfill: has_embedding skip + empty skip + fresh processed, JSON totals
//   Exercises embeddings.rs backfill_embeddings (file lines 122-186):
//     :135-138 already-embedded skip
//     :140-143 empty-text skip
//     :160-173 fresh embed Ok -> store_with_model Ok -> processed
//   plus JSON totals at embeddings.rs:543-555 (S4b :394-445 + totals)
// ===========================================================================

#[tokio::test]
async fn backfill_json_covers_has_embedding_skip_empty_skip_and_fresh_processed() {
    let t = tmp();
    let server = MockServer::start().await;
    mount_ollama(&server).await;
    seed_config(&t, &server.uri());
    clx(&t).args(["--json", "install"]).assert().success();

    let (already_id, empty_id, fresh_id) = {
        let storage = Storage::open(db_path(&t)).expect("open db");
        let session = SessionId::new("sess-embed-backfill");
        storage
            .create_session(&Session::new(session.clone(), "/tmp/proj".to_string()))
            .expect("create session");
        let already = seed_snapshot(&storage, &session, Some("already embedded snapshot"));
        let empty = seed_snapshot(&storage, &session, None);
        let fresh = seed_snapshot(&storage, &session, Some("fresh snapshot needing backfill"));
        (already, empty, fresh)
    };

    // Pre-store an embedding for `already_id` so has_embedding() short-circuits.
    {
        clx_core::init_sqlite_vec();
        let store =
            Storage::create_embedding_store_with_dimension(db_path(&t), DEFAULT_EMBEDDING_DIM)
                .expect("open embedding store");
        store
            .store_embedding(already_id, vec![1.0f32; DEFAULT_EMBEDDING_DIM])
            .expect("pre-seed embedding");
    }

    let out = clx(&t)
        .args(["--json", "embed-backfill"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value =
        serde_json::from_str(String::from_utf8_lossy(&out).trim()).expect("backfill --json");

    assert_eq!(v["processed"], 1, "only the fresh snapshot embeds: {v}");
    assert_eq!(
        v["skipped"], 2,
        "already-embedded + empty-text both skipped: {v}"
    );
    assert_eq!(v["errors"], 0, "{v}");
    assert_eq!(v["dry_run"], false, "{v}");

    // DB state: already (pre-seeded) + fresh now embedded; empty never is.
    assert_eq!(embedding_count(&t), 2, "pre-seeded + freshly backfilled");
    assert!(has_embedding(&t, already_id));
    assert!(has_embedding(&t, fresh_id), "fresh snapshot backfilled");
    assert!(
        !has_embedding(&t, empty_id),
        "empty snapshot never embedded"
    );
}

// ===========================================================================
// backfill: dry-run arm — embeddings.rs:150-158
//   dry_run=true counts a "would process" without calling embed/store;
//   no embedding row is written.
// ===========================================================================

#[tokio::test]
async fn backfill_dry_run_counts_without_writing_embeddings() {
    let t = tmp();
    let server = MockServer::start().await;
    mount_ollama(&server).await;
    seed_config(&t, &server.uri());
    clx(&t).args(["--json", "install"]).assert().success();

    {
        let storage = Storage::open(db_path(&t)).expect("open db");
        let session = SessionId::new("sess-embed-dry");
        storage
            .create_session(&Session::new(session.clone(), "/tmp/proj".to_string()))
            .expect("create session");
        seed_snapshot(&storage, &session, Some("dry-run candidate one"));
        seed_snapshot(&storage, &session, Some("dry-run candidate two"));
    }

    let out = clx(&t)
        .args(["--json", "embed-backfill", "--dry-run"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value =
        serde_json::from_str(String::from_utf8_lossy(&out).trim()).expect("JSON");
    assert_eq!(v["dry_run"], true, "{v}");
    assert_eq!(
        v["processed"], 2,
        "dry-run counts both as would-process: {v}"
    );
    assert_eq!(
        embedding_count(&t),
        0,
        "dry-run must NOT write any embedding row"
    );
}

// ===========================================================================
// backfill: human (non-JSON) dry-run arm — embeddings.rs:150-158 + 565-571
//   asserts the "Would process" line + the dry-run footer render.
// ===========================================================================

#[tokio::test]
async fn backfill_human_dry_run_renders_would_process_and_footer() {
    let t = tmp();
    let server = MockServer::start().await;
    mount_ollama(&server).await;
    seed_config(&t, &server.uri());
    clx(&t).args(["--json", "install"]).assert().success();

    {
        let storage = Storage::open(db_path(&t)).expect("open db");
        let session = SessionId::new("sess-embed-dry-human");
        storage
            .create_session(&Session::new(session.clone(), "/tmp/proj".to_string()))
            .expect("create session");
        seed_snapshot(&storage, &session, Some("human dry-run candidate"));
    }

    clx(&t)
        .args(["embed-backfill", "--dry-run"])
        .assert()
        .success()
        .stdout(predicates::str::contains("Would process snapshot"))
        .stdout(predicates::str::contains("This was a dry run"));
    assert_eq!(embedding_count(&t), 0, "human dry-run writes nothing");
}

// ===========================================================================
// backfill: error arm — embeddings.rs:175-180
//   wrong-dimension vector -> store_with_model Err -> counts.errors,
//   and the human "Error:" line renders.
// ===========================================================================

#[tokio::test]
async fn backfill_human_store_error_arm_counts_error_and_renders() {
    let t = tmp();
    let server = MockServer::start().await;
    mount_ollama(&server).await;
    seed_config(&t, &server.uri());
    clx(&t).args(["--json", "install"]).assert().success();

    {
        let storage = Storage::open(db_path(&t)).expect("open db");
        let session = SessionId::new("sess-embed-backfill-err");
        storage
            .create_session(&Session::new(session.clone(), "/tmp/proj".to_string()))
            .expect("create session");
        seed_snapshot(
            &storage,
            &session,
            Some(&format!("backfill {BAD_DIM_MARKER} should error")),
        );
    }

    clx(&t)
        .args(["embed-backfill"])
        .assert()
        .success()
        .stdout(predicates::str::contains("Embedding Backfill"))
        .stdout(predicates::str::contains("Error:"));
    assert_eq!(
        embedding_count(&t),
        0,
        "store error must not persist an embedding"
    );
}
