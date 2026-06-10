//! Behavior tests for the recall substring fallback — the last-resort
//! lexical stage that runs when FTS5 finds nothing (engine
//! `try_substring_fallback`). This is the only stage that can rescue
//! queries the FTS5 sanitizer legally erases (operator words like `or`,
//! one-letter terms, punctuation-only queries), so its hit-construction
//! path is a real product surface, not an internal detail.
//!
//! Driven end-to-end through the production wiring: in-memory `Storage`
//! -> `StorageSnapshotRepo` -> `RecallEngine::query` (the same path the
//! MCP `clx_recall` tool uses). No mocks of the subject.

use clx_core::recall::{RecallEngine, RecallQueryConfig, RecallSearchType};
use clx_core::storage::{Storage, StorageSnapshotRepo};
use clx_core::types::{Session, SessionId, Snapshot, SnapshotTrigger};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn cfg() -> RecallQueryConfig {
    RecallQueryConfig {
        max_results: 10,
        similarity_threshold: 0.35,
        fallback_to_fts: true,
        include_key_facts: true,
        rrf_enabled: true,
        rrf_k: 60,
        time_decay_half_life_days: 0.0,
        percentile_gate: 0,
        reranker_enabled: false,
        reranker_timeout_ms: 250,
    }
}

/// Storage with one ACTIVE session and one snapshot carrying the given
/// summary/`key_facts`. The session must be active: the substring fallback
/// only scans active sessions.
fn seeded(summary: Option<&str>, key_facts: Option<&str>) -> Storage {
    let storage = Storage::open_in_memory().expect("in-memory storage");
    let session = Session::new(SessionId::new("sess-sub-1"), "/tmp/proj".to_string());
    storage.create_session(&session).unwrap();
    let mut snap = Snapshot::new(SessionId::new("sess-sub-1"), SnapshotTrigger::Auto);
    snap.summary = summary.map(str::to_string);
    snap.key_facts = key_facts.map(str::to_string);
    storage.create_snapshot(&snap).unwrap();
    storage
}

// ===========================================================================
// Substring fallback rescues sanitizer-erased queries
// ===========================================================================

/// `or` is an FTS5 operator word: the sanitizer erases it, so the FTS5
/// stage legally returns nothing. The substring stage must still find the
/// snapshot whose summary contains it, and the hit must be attributed to
/// the Text stage. A regression that drops the fallback turns every
/// operator-word query into a silent "no relevant context".
#[tokio::test]
async fn operator_word_query_is_rescued_by_substring_stage() {
    let storage = seeded(Some("migrated executor to tokio"), None);
    let repo = StorageSnapshotRepo::new(&storage, None);
    let engine = RecallEngine::new(&repo);

    let result = engine.query("or", &cfg()).await;

    assert!(
        !result.degraded,
        "FTS5 returning empty then substring succeeding is healthy, not degraded"
    );
    assert_eq!(result.hits.len(), 1, "hits: {:?}", result.hits);
    let hit = &result.hits[0];
    assert_eq!(
        hit.search_type,
        RecallSearchType::Text,
        "the rescue must be attributed to the substring stage"
    );
    assert_eq!(hit.session_id, "sess-sub-1");
    assert_eq!(hit.summary.as_deref(), Some("migrated executor to tokio"));
}

/// The substring match is case-insensitive in both directions.
#[tokio::test]
async fn substring_match_is_case_insensitive() {
    let storage = seeded(Some("Refactor TOKIO executor"), None);
    let repo = StorageSnapshotRepo::new(&storage, None);
    let engine = RecallEngine::new(&repo);

    // "OR" uppercases to an FTS5 operator (erased by the sanitizer) and
    // lowercases to a substring of "Refactor".
    let result = engine.query("OR", &cfg()).await;
    assert_eq!(
        result.hits.len(),
        1,
        "case-insensitive substring must match 'Refactor': {:?}",
        result.hits
    );
}

/// A snapshot whose SUMMARY does not contain the query but whose
/// `key_facts` does must still match (the `matches_facts` arm).
#[tokio::test]
async fn key_facts_only_match_counts() {
    let storage = seeded(Some("unrelated summary text"), Some("decision: chose tokio or smol"));
    let repo = StorageSnapshotRepo::new(&storage, None);
    let engine = RecallEngine::new(&repo);

    let result = engine.query("or", &cfg()).await;
    assert_eq!(result.hits.len(), 1, "hits: {:?}", result.hits);
    assert_eq!(
        result.hits[0].key_facts.as_deref(),
        Some("decision: chose tokio or smol")
    );
}

/// No lexical match anywhere: a clean empty, NOT a degraded result and
/// not an error — callers render this as "no relevant context".
#[tokio::test]
async fn no_match_is_clean_empty_not_degraded() {
    let storage = seeded(Some("alpha beta gamma"), Some("delta")); // no "zz"
    let repo = StorageSnapshotRepo::new(&storage, None);
    let engine = RecallEngine::new(&repo);

    let result = engine.query("zzqq", &cfg()).await;
    assert!(result.hits.is_empty());
    assert!(!result.degraded, "healthy empty must not be flagged degraded");
}

/// Ended sessions are invisible to the substring stage (it only scans
/// active sessions): ending the only session removes the rescue.
#[tokio::test]
async fn ended_session_is_not_scanned() {
    let storage = seeded(Some("migrated executor to tokio"), None);
    storage.end_session("sess-sub-1").unwrap();
    let repo = StorageSnapshotRepo::new(&storage, None);
    let engine = RecallEngine::new(&repo);

    let result = engine.query("or", &cfg()).await;
    assert!(
        result.hits.is_empty(),
        "ended session's snapshots must not be substring-scanned: {:?}",
        result.hits
    );
}
