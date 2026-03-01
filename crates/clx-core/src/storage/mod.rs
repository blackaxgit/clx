//! `SQLite` storage layer for CLX
//!
//! Provides persistent storage for sessions, snapshots, events, audit logs,
//! learned rules, and analytics using `SQLite` with WAL mode.
//!
//! The storage module is organized into sub-modules by domain:
//! - `migration` - Schema versioning and incremental migrations
//! - `session` - Session CRUD operations
//! - `snapshot` - Snapshot operations with FTS5 search
//! - `event` - Session event logging
//! - `audit` - Audit log operations
//! - `rules` - Learned rules management
//! - `analytics` - Metrics recording and aggregation
//! - `util` - Shared helper functions

mod analytics;
mod audit;
mod event;
mod migration;
mod rules;
mod session;
mod snapshot;
mod traits;
mod util;

pub use traits::StorageBackend;

use rusqlite::Connection;
use std::fs;
use std::path::Path;
use tracing::{debug, info};

/// `SQLite` storage backend
pub struct Storage {
    // pub(super) so sub-modules (migration, session, tests, etc.) can access
    pub(super) conn: Connection,
}

impl Storage {
    /// Open or create a database at the given path
    ///
    /// Creates parent directories if they don't exist.
    /// Initializes WAL mode and runs migrations.
    pub fn open<P: AsRef<Path>>(path: P) -> crate::Result<Self> {
        let path = path.as_ref();

        // Create parent directories if needed
        if let Some(parent) = path.parent()
            && !parent.exists()
        {
            fs::create_dir_all(parent)?;
            debug!("Created database directory: {}", parent.display());
        }

        let conn = Connection::open(path)?;
        let storage = Self { conn };
        storage.configure_pragmas()?;
        storage.run_migrations()?;
        info!("Opened database at {}", path.display());
        Ok(storage)
    }

    /// Open an in-memory database (useful for testing)
    pub fn open_in_memory() -> crate::Result<Self> {
        let conn = Connection::open_in_memory()?;
        let storage = Self { conn };
        storage.configure_pragmas()?;
        storage.run_migrations()?;
        debug!("Opened in-memory database");
        Ok(storage)
    }

    /// Open the default CLX database at ~/.clx/data/clx.db
    pub fn open_default() -> crate::Result<Self> {
        Self::open(crate::paths::database_path())
    }

    /// Get a reference to the underlying connection
    ///
    /// Use with caution - prefer the typed methods for most operations.
    pub fn connection(&self) -> &Connection {
        &self.conn
    }

    /// Get the current schema version
    pub fn schema_version(&self) -> crate::Result<i32> {
        let version: i32 = self
            .conn
            .query_row(
                "SELECT COALESCE(MAX(version), 0) FROM schema_version",
                [],
                |row| row.get(0),
            )
            .unwrap_or(0);
        Ok(version)
    }

    /// Create an embedding store using the same database path
    ///
    /// Opens a new connection to the database for vector operations.
    /// The sqlite-vec extension is optional - if not available, vector
    /// search will be disabled but other operations will continue to work.
    ///
    /// # Arguments
    /// * `path` - Path to the database file (same as used for Storage)
    ///
    /// # Example
    /// ```ignore
    /// let storage = Storage::open("clx.db")?;
    /// let embeddings = Storage::create_embedding_store("clx.db")?;
    /// ```
    pub fn create_embedding_store<P: AsRef<Path>>(
        path: P,
    ) -> crate::Result<crate::embeddings::EmbeddingStore> {
        crate::embeddings::EmbeddingStore::open(path)
    }

    /// Create an embedding store at the given path with a specific dimension
    pub fn create_embedding_store_with_dimension<P: AsRef<Path>>(
        path: P,
        dimension: usize,
    ) -> crate::Result<crate::embeddings::EmbeddingStore> {
        crate::embeddings::EmbeddingStore::open_with_dimension(path, dimension)
    }

    /// Create an in-memory embedding store (useful for testing)
    pub fn create_embedding_store_in_memory() -> crate::Result<crate::embeddings::EmbeddingStore> {
        crate::embeddings::EmbeddingStore::open_in_memory()
    }
}

#[cfg(test)]
mod tests;
