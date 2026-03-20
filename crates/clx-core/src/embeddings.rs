//! Vector embeddings storage using sqlite-vec extension
//!
//! Provides semantic search capability for context recall using the sqlite-vec
//! extension, which is statically linked into the binary at compile time.

use rusqlite::Connection;
use std::path::Path;
use tracing::{debug, info, warn};

/// Default embedding dimension for qwen3-embedding:0.6b
pub const DEFAULT_EMBEDDING_DIM: usize = 1024;

/// Embedding store with vector search capabilities
///
/// Uses sqlite-vec extension (statically linked) for efficient vector similarity search.
pub struct EmbeddingStore {
    conn: Connection,
    embedding_dim: usize,
}

impl EmbeddingStore {
    /// Create a new embedding store using an existing connection
    ///
    /// The sqlite-vec extension is registered globally via `init_sqlite_vec()`,
    /// so vec0 virtual tables are available on every connection.
    pub fn new(conn: Connection) -> crate::Result<Self> {
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        let store = Self {
            conn,
            embedding_dim: DEFAULT_EMBEDDING_DIM,
        };
        store.create_embeddings_table()?;
        info!("EmbeddingStore initialized with sqlite-vec support");
        Ok(store)
    }

    /// Create a new embedding store with a custom dimension
    pub fn with_dimension(conn: Connection, embedding_dim: usize) -> crate::Result<Self> {
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        let store = Self {
            conn,
            embedding_dim,
        };

        if let Some(actual_dim) = store.get_table_dimension()
            && actual_dim != embedding_dim
        {
            warn!(
                "Embedding dimension mismatch: table has {} dimensions, \
                     expected {}. Run 'clx embeddings rebuild' to migrate.",
                actual_dim, embedding_dim
            );
        }
        store.create_embeddings_table()?;
        info!(
            "EmbeddingStore initialized with sqlite-vec support (dim={})",
            embedding_dim
        );
        Ok(store)
    }

    /// Open an embedding store at the given database path
    pub fn open<P: AsRef<Path>>(path: P) -> crate::Result<Self> {
        let path = path.as_ref();

        // Create parent directories if needed
        if let Some(parent) = path.parent()
            && !parent.exists()
        {
            std::fs::create_dir_all(parent)?;
            debug!("Created database directory: {}", parent.display());
        }

        let conn = Connection::open(path)?;
        Self::new(conn)
    }

    /// Open an in-memory embedding store (useful for testing)
    pub fn open_in_memory() -> crate::Result<Self> {
        let conn = Connection::open_in_memory()?;
        Self::new(conn)
    }

    /// Check if vector search is available.
    ///
    /// Always returns true when sqlite-vec is statically linked.
    pub fn is_vector_search_enabled(&self) -> bool {
        true
    }

    /// Get the embedding dimension
    pub fn embedding_dim(&self) -> usize {
        self.embedding_dim
    }

    /// Create the embeddings virtual table
    ///
    /// Uses vec0 virtual table format for sqlite-vec.
    fn create_embeddings_table(&self) -> crate::Result<()> {
        // Create the vec0 virtual table for embeddings
        // Format: CREATE VIRTUAL TABLE name USING vec0(column_name float[dimension])
        let create_sql = format!(
            "CREATE VIRTUAL TABLE IF NOT EXISTS snapshot_embeddings USING vec0(
                snapshot_id INTEGER PRIMARY KEY,
                embedding float[{}]
            )",
            self.embedding_dim
        );

        self.conn.execute(&create_sql, [])?;
        debug!(
            "Created snapshot_embeddings table with {} dimensions",
            self.embedding_dim
        );

        Ok(())
    }

    /// Store an embedding for a snapshot
    ///
    /// # Arguments
    /// * `snapshot_id` - The ID of the snapshot
    /// * `embedding` - The embedding vector (must match configured dimension)
    ///
    /// # Errors
    /// Returns an error if:
    /// - The embedding dimension doesn't match
    /// - Database operation fails
    #[allow(clippy::needless_pass_by_value)] // Public API accepts owned Vec for caller convenience
    pub fn store_embedding(&self, snapshot_id: i64, embedding: Vec<f32>) -> crate::Result<()> {
        if embedding.len() != self.embedding_dim {
            return Err(crate::Error::InvalidInput(format!(
                "Embedding dimension mismatch: expected {}, got {}",
                self.embedding_dim,
                embedding.len()
            )));
        }

        // Convert embedding to blob format for sqlite-vec
        let embedding_blob = embedding_to_blob(&embedding);

        self.conn.execute(
            "INSERT OR REPLACE INTO snapshot_embeddings (snapshot_id, embedding) VALUES (?1, ?2)",
            rusqlite::params![snapshot_id, embedding_blob],
        )?;

        debug!("Stored embedding for snapshot {}", snapshot_id);
        Ok(())
    }

    /// Find snapshots similar to the query embedding
    ///
    /// Returns snapshot IDs and their distances, ordered by similarity (closest first).
    ///
    /// # Arguments
    /// * `query_embedding` - The embedding to search for
    /// * `limit` - Maximum number of results to return
    ///
    /// # Returns
    /// Vec of (`snapshot_id`, distance) tuples, where lower distance means more similar.
    pub fn find_similar(
        &self,
        query_embedding: &[f32],
        limit: usize,
    ) -> crate::Result<Vec<(i64, f32)>> {
        if query_embedding.len() != self.embedding_dim {
            return Err(crate::Error::InvalidInput(format!(
                "Query embedding dimension mismatch: expected {}, got {}",
                self.embedding_dim,
                query_embedding.len()
            )));
        }

        let query_blob = embedding_to_blob(query_embedding);

        // Use vec0's KNN search syntax
        let mut stmt = self.conn.prepare(
            "SELECT snapshot_id, distance
             FROM snapshot_embeddings
             WHERE embedding MATCH ?1
             ORDER BY distance
             LIMIT ?2",
        )?;

        let results = stmt
            .query_map(rusqlite::params![query_blob, limit as i64], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, f32>(1)?))
            })?
            .filter_map(std::result::Result::ok)
            .collect();

        Ok(results)
    }

    /// Delete an embedding for a snapshot
    pub fn delete_embedding(&self, snapshot_id: i64) -> crate::Result<()> {
        self.conn.execute(
            "DELETE FROM snapshot_embeddings WHERE snapshot_id = ?1",
            [snapshot_id],
        )?;

        debug!("Deleted embedding for snapshot {}", snapshot_id);
        Ok(())
    }

    /// Check if an embedding exists for a snapshot
    pub fn has_embedding(&self, snapshot_id: i64) -> crate::Result<bool> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM snapshot_embeddings WHERE snapshot_id = ?1",
            [snapshot_id],
            |row| row.get(0),
        )?;

        Ok(count > 0)
    }

    /// Get the number of stored embeddings
    pub fn count_embeddings(&self) -> crate::Result<i64> {
        let count: i64 =
            self.conn
                .query_row("SELECT COUNT(*) FROM snapshot_embeddings", [], |row| {
                    row.get(0)
                })?;

        Ok(count)
    }

    /// Check if the existing table's dimension differs from the expected dimension.
    ///
    /// Parses the table definition from `sqlite_master` to determine the actual
    /// dimension of the stored embeddings. Returns true if a migration is needed.
    pub fn needs_dimension_migration(&self, expected_dim: usize) -> bool {
        match self.get_table_dimension() {
            Some(actual_dim) => actual_dim != expected_dim,
            None => false, // Table doesn't exist yet, no migration needed
        }
    }

    /// Rebuild the embedding table with a new dimension.
    ///
    /// Drops the existing `snapshot_embeddings` table and recreates it with
    /// the specified dimension. All existing embeddings are lost.
    pub fn rebuild_table(&mut self, dimension: usize) -> crate::Result<()> {
        info!(
            "Rebuilding embedding table: {} -> {} dimensions",
            self.embedding_dim, dimension
        );

        self.conn
            .execute("DROP TABLE IF EXISTS snapshot_embeddings", [])?;

        self.embedding_dim = dimension;
        self.create_embeddings_table()?;

        info!(
            "Embedding table rebuilt with {} dimensions",
            self.embedding_dim
        );
        Ok(())
    }

    /// Open an embedding store at the given path with a specific dimension.
    pub fn open_with_dimension<P: AsRef<Path>>(path: P, dimension: usize) -> crate::Result<Self> {
        let path = path.as_ref();

        if let Some(parent) = path.parent()
            && !parent.exists()
        {
            std::fs::create_dir_all(parent)?;
            debug!("Created database directory: {}", parent.display());
        }

        let conn = Connection::open(path)?;
        Self::with_dimension(conn, dimension)
    }

    /// Get the actual dimension of the existing embeddings table by
    /// parsing the CREATE TABLE statement from `sqlite_master`.
    fn get_table_dimension(&self) -> Option<usize> {
        let sql: String = self
            .conn
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name='snapshot_embeddings'",
                [],
                |row| row.get(0),
            )
            .ok()?;

        // Parse dimension from: "... embedding float[1024] ..."
        if let Some(start) = sql.find("float[") {
            let rest = &sql[start + 6..];
            if let Some(end) = rest.find(']') {
                return rest[..end].parse::<usize>().ok();
            }
        }

        None
    }

    /// Get a reference to the underlying connection
    pub fn connection(&self) -> &Connection {
        &self.conn
    }
}

/// Convert an embedding vector to a blob for sqlite-vec
fn embedding_to_blob(embedding: &[f32]) -> Vec<u8> {
    // sqlite-vec expects embeddings as a blob of little-endian f32 values
    let mut blob = Vec::with_capacity(embedding.len() * 4);
    for &val in embedding {
        blob.extend_from_slice(&val.to_le_bytes());
    }
    blob
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Create a test embedding store
    fn create_test_store() -> EmbeddingStore {
        crate::init_sqlite_vec();
        EmbeddingStore::open_in_memory().expect("Failed to create in-memory store")
    }

    #[test]
    fn test_store_creation() {
        let store = create_test_store();
        assert!(store.is_vector_search_enabled());
        assert_eq!(store.embedding_dim(), DEFAULT_EMBEDDING_DIM);
    }

    #[test]
    fn test_custom_dimension() {
        crate::init_sqlite_vec();
        let conn = Connection::open_in_memory().unwrap();
        let store = EmbeddingStore::with_dimension(conn, 384).unwrap();
        assert_eq!(store.embedding_dim(), 384);
    }

    #[test]
    fn test_embedding_to_blob() {
        let embedding = vec![1.0f32, 2.0, 3.0];
        let blob = embedding_to_blob(&embedding);

        assert_eq!(blob.len(), 12); // 3 floats * 4 bytes

        // Verify first float
        let first_bytes: [u8; 4] = blob[0..4].try_into().unwrap();
        #[allow(clippy::float_cmp)]
        {
            assert_eq!(f32::from_le_bytes(first_bytes), 1.0);
        }
    }

    #[test]
    fn test_store_and_find() {
        let store = create_test_store();

        // Store some embeddings
        let emb1 = vec![1.0f32; DEFAULT_EMBEDDING_DIM];
        let emb2 = vec![0.5f32; DEFAULT_EMBEDDING_DIM];
        let emb3 = vec![0.0f32; DEFAULT_EMBEDDING_DIM];

        store.store_embedding(1, emb1).unwrap();
        store.store_embedding(2, emb2).unwrap();
        store.store_embedding(3, emb3).unwrap();

        // Query with similar embedding
        let query = vec![1.0f32; DEFAULT_EMBEDDING_DIM];
        let results = store.find_similar(&query, 2).unwrap();

        assert_eq!(results.len(), 2);
        // First result should be snapshot 1 (exact match)
        assert_eq!(results[0].0, 1);
    }

    #[test]
    fn test_dimension_mismatch() {
        let store = create_test_store();

        // Wrong dimension should fail
        let wrong_embedding = vec![0.0f32; 100];
        let result = store.store_embedding(1, wrong_embedding);
        assert!(result.is_err());
    }

    #[test]
    fn test_query_dimension_mismatch() {
        let store = create_test_store();

        // Wrong query dimension should fail
        let wrong_query = vec![0.0f32; 100];
        let result = store.find_similar(&wrong_query, 10);
        assert!(result.is_err());
    }

    #[test]
    fn test_default_embedding_dim_is_1024() {
        assert_eq!(DEFAULT_EMBEDDING_DIM, 1024);
    }

    #[test]
    fn test_get_dimension() {
        let store = create_test_store();
        assert_eq!(store.embedding_dim(), DEFAULT_EMBEDDING_DIM);
        assert_eq!(store.embedding_dim(), 1024);
    }

    #[test]
    fn test_get_dimension_custom() {
        let conn = Connection::open_in_memory().unwrap();
        let store = EmbeddingStore::with_dimension(conn, 768).unwrap();
        assert_eq!(store.embedding_dim(), 768);
    }

    #[test]
    fn test_needs_dimension_migration_match() {
        let store = create_test_store();
        // Table was created with DEFAULT_EMBEDDING_DIM (1024)
        assert!(!store.needs_dimension_migration(DEFAULT_EMBEDDING_DIM));
    }

    #[test]
    fn test_needs_dimension_migration_mismatch() {
        let store = create_test_store();
        // Table was created with 1024, checking against 768 should need migration
        assert!(store.needs_dimension_migration(768));
    }

    #[test]
    fn test_rebuild_table() {
        let mut store = create_test_store();

        // Store an embedding with original dimension
        let emb = vec![1.0f32; DEFAULT_EMBEDDING_DIM];
        store.store_embedding(1, emb).unwrap();
        assert_eq!(store.count_embeddings().unwrap(), 1);

        // Rebuild with new dimension
        store.rebuild_table(768).unwrap();
        assert_eq!(store.embedding_dim(), 768);

        // Old embeddings should be gone
        assert_eq!(store.count_embeddings().unwrap(), 0);

        // Should accept embeddings with new dimension
        let new_emb = vec![1.0f32; 768];
        store.store_embedding(1, new_emb).unwrap();
        assert_eq!(store.count_embeddings().unwrap(), 1);
    }

    #[test]
    fn test_delete_embedding_removes_row() {
        let store = create_test_store();

        let emb = vec![0.1f32; DEFAULT_EMBEDDING_DIM];
        store.store_embedding(99, emb).unwrap();
        assert!(store.has_embedding(99).unwrap());

        store.delete_embedding(99).unwrap();
        assert!(!store.has_embedding(99).unwrap());
    }

    #[test]
    fn test_has_embedding_false_for_different_key() {
        let store = create_test_store();

        let emb = vec![0.5f32; DEFAULT_EMBEDDING_DIM];
        store.store_embedding(1, emb).unwrap();

        let result = store.has_embedding(2).unwrap();
        assert!(!result);
    }

    #[test]
    fn test_needs_dimension_migration_returns_false_on_match() {
        let store = create_test_store();
        let result = store.needs_dimension_migration(DEFAULT_EMBEDDING_DIM);
        assert!(!result);
    }

    #[test]
    fn test_store_embedding_has_embedding_returns_true() {
        let store = create_test_store();

        let embedding = vec![0.42f32; DEFAULT_EMBEDDING_DIM];
        store.store_embedding(10, embedding).unwrap();

        assert!(
            store.has_embedding(10).unwrap(),
            "has_embedding should return true after a successful store_embedding call"
        );
    }

    #[test]
    fn test_rebuild_table_clears_all_three_embeddings() {
        let mut store = create_test_store();

        store
            .store_embedding(1, vec![0.1f32; DEFAULT_EMBEDDING_DIM])
            .unwrap();
        store
            .store_embedding(2, vec![0.5f32; DEFAULT_EMBEDDING_DIM])
            .unwrap();
        store
            .store_embedding(3, vec![0.9f32; DEFAULT_EMBEDDING_DIM])
            .unwrap();
        assert_eq!(
            store.count_embeddings().unwrap(),
            3,
            "should have 3 embeddings before rebuild"
        );

        let new_dim = 512usize;
        store.rebuild_table(new_dim).unwrap();

        assert_eq!(
            store.count_embeddings().unwrap(),
            0,
            "all embeddings must be removed after rebuild_table"
        );
        assert_eq!(
            store.embedding_dim(),
            new_dim,
            "embedding_dim should reflect the new dimension after rebuild"
        );

        store.store_embedding(99, vec![0.7f32; new_dim]).unwrap();
        assert_eq!(store.count_embeddings().unwrap(), 1);
    }

    #[test]
    fn test_find_similar_returns_stored_key() {
        let store = create_test_store();

        let embedding = vec![0.8f32; DEFAULT_EMBEDDING_DIM];
        store.store_embedding(42, embedding.clone()).unwrap();

        let results = store.find_similar(&embedding, 5).unwrap();

        assert!(
            !results.is_empty(),
            "find_similar should return at least one result after storing an embedding"
        );
        let returned_ids: Vec<i64> = results.iter().map(|(id, _)| *id).collect();
        assert!(
            returned_ids.contains(&42),
            "find_similar should include the stored snapshot_id 42 in results, got: {returned_ids:?}"
        );
    }
}
