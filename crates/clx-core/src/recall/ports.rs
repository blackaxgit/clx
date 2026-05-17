//! Domain ports for the recall pipeline (Hexagonal Architecture).
//!
//! These traits express what the recall pipeline *needs* in terms of pure
//! Domain types (`Snapshot`, `Session`, `SessionSummary` — all from
//! `crate::types`). Infrastructure types (`Storage`, `LlmClient`,
//! `EmbeddingStore`) implement these traits as adapters; the recall engine
//! itself never names them.
//!
//! ## Layering rule
//!
//! Per project CLAUDE.md, the recall module (Domain) must not depend on
//! Infrastructure types. Before 0.8.0 the engine called `Storage::*`,
//! `LlmClient::embed`, and `EmbeddingStore::find_similar` directly. Ports
//! make those dependencies abstract; concrete impls live alongside their
//! adapters in `storage::recall_repo` and `recall::adapters`.
//!
//! ## Why two traits
//!
//! The recall pipeline has two distinct collaborators:
//! 1. A read-only repository of snapshots and session summaries
//!    ([`SnapshotRepo`]). Used by every stage of the pipeline.
//! 2. A query embedder ([`QueryEmbedder`]) that maps the raw user query
//!    to a vector for the semantic stage. Optional — when absent the
//!    pipeline falls back to FTS5 / substring search.

use async_trait::async_trait;

use crate::types::{Session, SessionSummary, Snapshot};

/// Domain-level repository for snapshots and session summaries.
///
/// Pure read-only port surfacing the four operations the recall pipeline
/// needs: FTS5 full-text search, semantic vector search, single-snapshot
/// lookup, and recent-session-summary listing. Sync because the underlying
/// `SQLite` calls are sync; the async pipeline awaits at the boundary.
pub trait SnapshotRepo {
    /// FTS5 full-text search returning `(snapshot, bm25_score)` pairs.
    ///
    /// The score is the BM25 rank, already normalised to `[0.0, 1.0]` by
    /// the storage layer. Returns an empty vec when the query sanitises to
    /// empty or no snapshot matches.
    fn search_fts(&self, query: &str, limit: usize) -> crate::Result<Vec<(Snapshot, f64)>>;

    /// Latest snapshot summaries for the most recently started sessions.
    ///
    /// Mirrors `Storage::recent_session_summaries`. `exclude_session_id`
    /// suppresses self-pinning when the caller wants to omit their own
    /// session from the result.
    fn recent_session_summaries(
        &self,
        n: usize,
        exclude_session_id: Option<&str>,
    ) -> crate::Result<Vec<SessionSummary>>;

    /// Semantic vector search.
    ///
    /// Returns `(snapshot_id, distance)` pairs ordered by ascending
    /// distance (closer = more similar). The `threshold` is a similarity
    /// score in `[0.0, 1.0]`; the adapter converts it to a distance ceiling
    /// internally. Returns an empty vec when no embedding store is
    /// available or vector search is disabled.
    fn semantic_similar(
        &self,
        query_embedding: &[f32],
        limit: usize,
    ) -> crate::Result<Vec<(i64, f32)>>;

    /// Whether semantic search is wired up at all (sqlite-vec available
    /// and an embedding store attached). When `false` the engine skips
    /// the semantic stage and goes straight to FTS5.
    fn semantic_enabled(&self) -> bool;

    /// Fetch one snapshot by primary key. `Ok(None)` when missing.
    fn snapshot_by_id(&self, id: i64) -> crate::Result<Option<Snapshot>>;

    /// Currently-active sessions ordered newest-first. Used by the
    /// substring fallback search to pick which sessions to scan.
    fn list_active_sessions(&self) -> crate::Result<Vec<Session>>;

    /// All snapshots for a session ordered newest-first. Used by the
    /// substring fallback search.
    fn snapshots_by_session(&self, session_id: &str) -> crate::Result<Vec<Snapshot>>;

    /// The model identifier (`"<provider>:<model>"`) of the most recent
    /// non-sentinel embedding row. Used for mismatch detection. Returns
    /// `Ok(None)` when the database is empty or every row carries the
    /// pre-migration sentinel.
    fn current_embedding_model(&self) -> crate::Result<Option<String>>;
}

/// Domain-level port for embedding the user query into a vector suitable
/// for [`SnapshotRepo::semantic_similar`].
///
/// Async because real backends (Ollama, `OpenAI`) round-trip to a
/// remote service. The recall pipeline holds an `Option<&dyn QueryEmbedder>`
/// and degrades gracefully to FTS5 when absent.
#[async_trait]
pub trait QueryEmbedder: Send + Sync {
    /// Produce an embedding vector for `text`. Errors are caller-visible
    /// so the pipeline can warn and fall back to FTS5.
    async fn embed_query(&self, text: &str) -> crate::Result<Vec<f32>>;
}
