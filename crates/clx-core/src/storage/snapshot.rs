//! Snapshot operations
//!
//! Create, read, list, and search snapshots with FTS5 full-text search.

use rusqlite::{OptionalExtension, Row, params};
use tracing::{debug, warn};

use super::Storage;
use super::util::{parse_datetime, sanitize_fts_query};
use crate::types::{Snapshot, SnapshotTrigger};

impl Storage {
    /// Create a new snapshot
    pub fn create_snapshot(&self, snapshot: &Snapshot) -> crate::Result<i64> {
        self.conn.execute(
            "INSERT INTO snapshots (session_id, created_at, trigger, summary, key_facts, todos, message_count, input_tokens, output_tokens)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                snapshot.session_id,
                snapshot.created_at.to_rfc3339(),
                snapshot.trigger.as_str(),
                snapshot.summary,
                snapshot.key_facts,
                snapshot.todos,
                snapshot.message_count,
                snapshot.input_tokens,
                snapshot.output_tokens,
            ],
        )?;
        let id = self.conn.last_insert_rowid();
        debug!(
            "Created snapshot {} for session {}",
            id, snapshot.session_id
        );
        Ok(id)
    }

    /// Get a snapshot by ID
    pub fn get_snapshot(&self, id: i64) -> crate::Result<Option<Snapshot>> {
        let result = self
            .conn
            .query_row(
                "SELECT id, session_id, created_at, trigger, summary, key_facts, todos, message_count, input_tokens, output_tokens
                 FROM snapshots WHERE id = ?1",
                [id],
                Self::row_to_snapshot,
            )
            .optional()?;
        Ok(result)
    }

    /// Get all snapshots for a session
    pub fn get_snapshots_by_session(&self, session_id: &str) -> crate::Result<Vec<Snapshot>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, session_id, created_at, trigger, summary, key_facts, todos, message_count, input_tokens, output_tokens
             FROM snapshots WHERE session_id = ?1 ORDER BY created_at DESC",
        )?;
        let snapshots = stmt
            .query_map([session_id], Self::row_to_snapshot)?
            .filter_map(|r| match r {
                Ok(v) => Some(v),
                Err(e) => {
                    warn!("Row deserialization error (skipped): {}", e);
                    None
                }
            })
            .collect();
        Ok(snapshots)
    }

    /// Get the latest snapshot for a session
    pub fn get_latest_snapshot(&self, session_id: &str) -> crate::Result<Option<Snapshot>> {
        let result = self
            .conn
            .query_row(
                "SELECT id, session_id, created_at, trigger, summary, key_facts, todos, message_count, input_tokens, output_tokens
                 FROM snapshots WHERE session_id = ?1 ORDER BY created_at DESC LIMIT 1",
                [session_id],
                Self::row_to_snapshot,
            )
            .optional()?;
        Ok(result)
    }

    /// List all snapshots (for backfill purposes)
    pub fn list_all_snapshots(&self) -> crate::Result<Vec<Snapshot>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, session_id, created_at, trigger, summary, key_facts, todos, message_count, input_tokens, output_tokens
             FROM snapshots ORDER BY id ASC",
        )?;
        let snapshots = stmt
            .query_map([], Self::row_to_snapshot)?
            .filter_map(|r| match r {
                Ok(v) => Some(v),
                Err(e) => {
                    warn!("Row deserialization error (skipped): {}", e);
                    None
                }
            })
            .collect();
        Ok(snapshots)
    }

    /// Search snapshots using FTS5 full-text search with BM25 ranking
    ///
    /// Returns matching snapshots paired with their relevance score (0.0-1.0),
    /// where higher scores indicate better matches.
    ///
    /// The query is sanitized for FTS5 syntax: special characters are stripped
    /// and terms are joined with spaces (implicit AND).
    pub fn search_snapshots_fts(
        &self,
        query: &str,
        limit: usize,
    ) -> crate::Result<Vec<(Snapshot, f64)>> {
        let sanitized = sanitize_fts_query(query);
        if sanitized.is_empty() {
            return Ok(Vec::new());
        }

        let mut stmt = self.conn.prepare(
            "SELECT s.id, s.session_id, s.created_at, s.trigger, s.summary, s.key_facts,
                    s.todos, s.message_count, s.input_tokens, s.output_tokens, fts.rank
             FROM snapshots_fts fts
             JOIN snapshots s ON s.id = fts.rowid
             WHERE snapshots_fts MATCH ?1
             ORDER BY fts.rank
             LIMIT ?2",
        )?;

        let results = stmt
            .query_map(params![sanitized, limit as i64], |row| {
                let snapshot = Self::row_to_snapshot(row)?;
                // FTS5 rank is negative; more negative = better match
                // Normalize to 0.0-1.0: score = 1.0 / (1.0 - rank)
                let rank: f64 = row.get(10)?;
                let score = 1.0 / (1.0 - rank);
                Ok((snapshot, score))
            })?
            .filter_map(|r| match r {
                Ok(v) => Some(v),
                Err(e) => {
                    warn!("Row deserialization error (skipped): {}", e);
                    None
                }
            })
            .collect();

        Ok(results)
    }

    fn row_to_snapshot(row: &Row) -> rusqlite::Result<Snapshot> {
        let created_at_str: String = row.get(2)?;
        let trigger_str: String = row.get(3)?;

        Ok(Snapshot {
            id: Some(row.get(0)?),
            session_id: row.get(1)?,
            created_at: parse_datetime(&created_at_str),
            trigger: SnapshotTrigger::parse(&trigger_str),
            summary: row.get(4)?,
            key_facts: row.get(5)?,
            todos: row.get(6)?,
            message_count: row.get(7)?,
            input_tokens: row.get(8)?,
            output_tokens: row.get(9)?,
        })
    }
}
