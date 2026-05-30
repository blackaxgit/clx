//! RED-R2 delta pre-release PoCs (surfaces 4-7).
//!
//! ALL tests are `#[ignore]`-gated: they are adversarial counterexamples /
//! re-confirmations, not part of the default green suite. Run explicitly with:
//!   cargo test -p clx-core --test delta_red_r2_poc -- --ignored
//!
//! Hermetic: in-memory SQLite only, synthetic provider/model idents only.
//! NEVER reproduces the previously-leaked Azure tenant URL or key; the only
//! "azure"-shaped strings here are the synthetic `azure-prod:text-embedding-*`
//! idents and `*.example.invalid` hosts.

use rusqlite::Connection;

use clx_core::embeddings::{DEFAULT_EMBEDDING_DIM, EmbeddingStore};

/// Build an in-memory store whose connection also has a minimal `snapshots`
/// table (id + embedding_model), matching the v5 schema columns the migration
/// logic reads. Mirrors the store's own test helper but lives here so the PoC
/// is self-contained.
fn store_with_snapshots(dim: usize) -> EmbeddingStore {
    clx_core::init_sqlite_vec();
    let conn = Connection::open_in_memory().unwrap();
    conn.execute_batch(
        "CREATE TABLE snapshots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            summary TEXT,
            key_facts TEXT,
            todos TEXT,
            embedding_model TEXT NOT NULL DEFAULT '<unknown-pre-migration>'
        );",
    )
    .unwrap();
    EmbeddingStore::with_dimension(conn, dim).unwrap()
}

fn insert_snapshot(store: &EmbeddingStore, summary: &str) -> i64 {
    store
        .connection()
        .execute(
            "INSERT INTO snapshots (summary) VALUES (?1)",
            rusqlite::params![summary],
        )
        .unwrap();
    store.connection().last_insert_rowid()
}

// ===========================================================================
// Surface 4: REFUTED-4 - same-dim provider/model swap IS detected.
//
// The probe in the RED prompt: "can the {provider,model,dim} compare MISS a
// real mismatch (report 'no migration' when the stored vectors were produced
// by a DIFFERENT model)?" This PoC shows it does NOT miss: a qwen3->azure swap
// at the SAME dimension is flagged by needs_model_migration even though
// needs_dimension_migration alone says "no migration".
// ===========================================================================
#[test]
#[ignore = "RED-R2 PoC: run with --ignored"]
fn poc_same_dim_provider_swap_is_detected() {
    let store = store_with_snapshots(DEFAULT_EMBEDDING_DIM);
    let snap = insert_snapshot(&store, "synthetic snapshot text");
    // Index built by the local ollama qwen3 model at 1024 dims.
    store
        .store_with_model(
            snap,
            vec![0.1f32; DEFAULT_EMBEDDING_DIM],
            "ollama-local:qwen3-embedding:0.6b",
        )
        .unwrap();

    // Dimension-only check would say "no migration" (both 1024)...
    assert!(
        !store.needs_dimension_migration(DEFAULT_EMBEDDING_DIM),
        "dim is unchanged; dim-only check must NOT flag migration"
    );
    // ...but the active route now points at a DIFFERENT model at the SAME dim.
    // The model-ident compare MUST flag migration (no silent stale-context).
    assert!(
        store
            .needs_model_migration("azure-prod:text-embedding-3-small")
            .unwrap(),
        "SECURITY/correctness: a same-dim provider/model swap MUST require \
         model migration; missing this would silently serve stale-model \
         vectors as valid recall context"
    );
}

// ===========================================================================
// Surface 4: REFUTED-4 (edge cases) - empty / sentinel-only / fresh index
// must NOT raise a false migration alarm (no false positive that would push
// an operator into a needless destructive rebuild), and an absent snapshots
// table must map to "no stored model" rather than an error.
// ===========================================================================
#[test]
#[ignore = "RED-R2 PoC: run with --ignored"]
fn poc_empty_sentinel_and_fresh_index_no_false_alarm() {
    // (a) empty index: nothing stored -> no model migration.
    let empty = store_with_snapshots(DEFAULT_EMBEDDING_DIM);
    assert_eq!(empty.current_model().unwrap(), None);
    assert!(
        !empty
            .needs_model_migration("azure-prod:text-embedding-3-small")
            .unwrap(),
        "empty index must not raise a false model-migration alarm"
    );

    // (b) sentinel-only (pre-migration) index: current_model ignores the
    // sentinel -> None -> no model migration.
    let sentinel = store_with_snapshots(DEFAULT_EMBEDDING_DIM);
    let snap = insert_snapshot(&sentinel, "old pre-migration snapshot");
    sentinel
        .store_embedding(snap, vec![0.2f32; DEFAULT_EMBEDDING_DIM])
        .unwrap();
    assert_eq!(sentinel.current_model().unwrap(), None);
    assert!(
        !sentinel
            .needs_model_migration("azure-prod:text-embedding-3-small")
            .unwrap(),
        "sentinel-only index must not raise a false model-migration alarm"
    );

    // (c) fresh store with NO snapshots table (brand-new HOME before install):
    // current_model maps "no such table" to None (not an error), and
    // needs_model_migration is false. Build via the public with_dimension on a
    // bare in-memory connection (no snapshots table created).
    clx_core::init_sqlite_vec();
    let bare = Connection::open_in_memory().unwrap();
    let fresh = EmbeddingStore::with_dimension(bare, DEFAULT_EMBEDDING_DIM).unwrap(); // vec0 table only
    assert_eq!(
        fresh.current_model().unwrap(),
        None,
        "missing snapshots table must map to None, not an error"
    );
    assert!(
        !fresh
            .needs_model_migration("azure-prod:text-embedding-3-small")
            .unwrap(),
        "fresh store (no snapshots table) must not flag model migration"
    );
}

// ===========================================================================
// Surface 4: NEW-FINDING F1 - the migration DIMENSION is sourced from the
// ollama-block embedding_dim, not from the active route (ResolvedRoute carries
// no dimension). This PoC demonstrates the consequence at the store level:
// needs_dimension_migration's verdict depends entirely on which dim the caller
// passes. If a remote route's true dim differs from the ollama-block dim the
// command always passes, the dim-migration row is computed against the WRONG
// number. (LOW severity: writes are fail-closed on length, and the model-ident
// compare independently catches a model swap; this is a status-correctness gap,
// not a recall-integrity bypass.)
// ===========================================================================
#[test]
#[ignore = "RED-R2 PoC: run with --ignored"]
fn poc_status_dim_sourced_from_ollama_block_not_route() {
    // Index physically built at 1024 (the ollama-block default the command
    // would pass for create_embedding_store_with_dimension).
    let store = store_with_snapshots(DEFAULT_EMBEDDING_DIM);

    // The command passes ollama_cfg.embedding_dim (1024) regardless of the
    // active route. Against 1024 the table matches -> "no dim migration".
    assert!(
        !store.needs_dimension_migration(DEFAULT_EMBEDDING_DIM),
        "table built at 1024 vs probed-with 1024 => no dim migration"
    );

    // But the ACTIVE remote route's true native dimension may differ (e.g. a
    // 1536-dim remote embedding model). The store, asked against the route's
    // real dimension, WOULD report a migration -- a verdict the status/rebuild
    // command never computes because it only ever passes the ollama-block dim.
    let route_true_dim = 1536usize;
    assert!(
        store.needs_dimension_migration(route_true_dim),
        "against the route's TRUE dim the store flags migration; the command \
         never asks this because ResolvedRoute carries no dimension and the \
         command always passes ollama_cfg.embedding_dim (F1)"
    );

    // Recall-integrity is still preserved by the write-side length guard: a
    // wrong-length vector for the active dim is REJECTED at store time, so the
    // index can never silently hold mismatched vectors.
    let wrong_len = vec![0.0f32; route_true_dim]; // 1536 into a 1024 table
    assert!(
        store.store_embedding(1, wrong_len).is_err(),
        "write path must fail closed on a dimension mismatch (no silent \
         wrong-dim vector in the index)"
    );
}

// ===========================================================================
// Surface 7: REFUTED-7a - mcp_tools config-trust drop.
//
// NOTE: `clx_core::config::project` is `pub(crate)`, so `filter_inert_only`
// cannot be exercised from this external test crate. The closure is pinned by
// the in-crate unit tests in `src/config/project.rs`
// (`b4_1_untrusted_config_cannot_set_any_validator_or_user_learning_key`,
// `untrusted_layer_drops_entire_providers_block`) plus the `NON_INERT_KEY_
// PATTERNS` array which includes `"mcp_tools"` (project.rs:93). Re-confirmed by
// inspection; documented in the fragment doc REFUTED-7a. No external PoC.
// ===========================================================================

