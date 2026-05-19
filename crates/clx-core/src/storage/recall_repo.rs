//! Adapter that implements [`crate::recall::ports::SnapshotRepo`] over a
//! borrowed [`Storage`] plus optional [`EmbeddingStore`].
//!
//! The adapter lives in the storage module (the Infrastructure layer) so
//! the recall Domain code never has to import storage types directly.

use super::Storage;
use crate::embeddings::EmbeddingStore;
use crate::recall::ports::SnapshotRepo;
use crate::types::{Session, SessionSummary, Snapshot};

/// Snapshot-repo adapter. Borrows the underlying stores so the engine
/// does not take ownership.
///
/// `embeddings` is optional: when `None`, [`SnapshotRepo::semantic_enabled`]
/// returns `false` and the semantic stage is skipped. This mirrors the
/// pre-refactor behaviour where the engine accepted
/// `Option<&EmbeddingStore>`.
pub struct StorageSnapshotRepo<'a> {
    storage: &'a Storage,
    embeddings: Option<&'a EmbeddingStore>,
}

impl<'a> StorageSnapshotRepo<'a> {
    /// Build a new adapter. Pass `None` for `embeddings` when running
    /// in FTS5-only mode (e.g. unit tests).
    #[must_use]
    pub fn new(storage: &'a Storage, embeddings: Option<&'a EmbeddingStore>) -> Self {
        Self {
            storage,
            embeddings,
        }
    }
}

impl SnapshotRepo for StorageSnapshotRepo<'_> {
    fn search_fts(&self, query: &str, limit: usize) -> crate::Result<Vec<(Snapshot, f64)>> {
        self.storage.search_snapshots_fts(query, limit)
    }

    fn recent_session_summaries(
        &self,
        n: usize,
        exclude_session_id: Option<&str>,
    ) -> crate::Result<Vec<SessionSummary>> {
        self.storage.recent_session_summaries(n, exclude_session_id)
    }

    fn semantic_similar(
        &self,
        query_embedding: &[f32],
        limit: usize,
    ) -> crate::Result<Vec<(i64, f32)>> {
        match self.embeddings {
            Some(store) => store.find_similar(query_embedding, limit),
            None => Ok(Vec::new()),
        }
    }

    fn semantic_enabled(&self) -> bool {
        self.embeddings
            .is_some_and(EmbeddingStore::is_vector_search_enabled)
    }

    fn snapshot_by_id(&self, id: i64) -> crate::Result<Option<Snapshot>> {
        self.storage.get_snapshot(id)
    }

    fn list_active_sessions(&self) -> crate::Result<Vec<Session>> {
        self.storage.list_active_sessions()
    }

    fn snapshots_by_session(&self, session_id: &str) -> crate::Result<Vec<Snapshot>> {
        self.storage.get_snapshots_by_session(session_id)
    }

    fn current_embedding_model(&self) -> crate::Result<Option<String>> {
        match self.embeddings {
            Some(store) => store.current_model(),
            None => Ok(None),
        }
    }
}
