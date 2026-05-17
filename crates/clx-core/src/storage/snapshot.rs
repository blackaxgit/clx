//! Snapshot operations
//!
//! Create, read, list, and search snapshots with FTS5 full-text search.

use chrono::{DateTime, Utc};
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

    /// Count mutating tool turns since the last `AutoSummary` snapshot.
    ///
    /// Production hook writers record mutating assistant work in
    /// `tool_events`, so the threshold follows the same source that
    /// `had_mutator_activity_since_last_auto_summary` uses.
    ///
    /// Behavior:
    /// - If no `auto_summary` snapshot exists for the session, return the
    ///   total `tool_events` count for that session.
    /// - Otherwise, return the count of `tool_events` strictly after the
    ///   most recent `auto_summary` snapshot's `created_at`.
    pub fn turns_since_last_auto_summary(&self, session_id: &str) -> crate::Result<u32> {
        let last_ts: Option<String> = self
            .conn
            .query_row(
                "SELECT MAX(created_at) FROM snapshots \
                 WHERE session_id = ?1 AND trigger = 'auto_summary'",
                [session_id],
                |row| row.get(0),
            )
            .optional()?
            .flatten();

        let count: i64 = match last_ts {
            Some(ts) => self.conn.query_row(
                "SELECT COUNT(*) FROM tool_events \
                 WHERE session_id = ?1 \
                   AND created_at > ?2",
                rusqlite::params![session_id, ts],
                |row| row.get(0),
            )?,
            None => self.conn.query_row(
                "SELECT COUNT(*) FROM tool_events WHERE session_id = ?1",
                [session_id],
                |row| row.get(0),
            )?,
        };
        // Clamp to u32 (rows fit comfortably; defensive cast keeps the
        // public surface boolean-arithmetic-friendly).
        Ok(u32::try_from(count).unwrap_or(u32::MAX))
    }

    /// Timestamp of the most recent `AutoSummary` snapshot for `session_id`,
    /// or `Ok(None)` when none exists.
    ///
    /// Used by the Stop-hook auto-summary handler as an optimistic-concurrency
    /// gate: between the moment the handler starts and the moment it persists
    /// its snapshot, another handler in a parallel Stop event could have
    /// already written one. Re-reading this timestamp immediately before the
    /// insert lets the second handler detect the race and skip cleanly,
    /// preventing duplicate AutoSummary snapshots for the same session/window.
    pub fn last_auto_summary_at(
        &self,
        session_id: &str,
    ) -> crate::Result<Option<DateTime<Utc>>> {
        let ts: Option<String> = self
            .conn
            .query_row(
                "SELECT MAX(created_at) FROM snapshots \
                 WHERE session_id = ?1 AND trigger = 'auto_summary'",
                [session_id],
                |row| row.get(0),
            )
            .optional()?
            .flatten();
        Ok(ts.map(|s| parse_datetime(&s)))
    }

    /// Did any mutating tool fire since the last `AutoSummary` snapshot for
    /// the session? Reads the `tool_events` table (schema v6 / Wave 1).
    ///
    /// Returns:
    /// - `Ok(true)` when at least one `tool_events` row exists for the
    ///   session with `created_at` strictly after the last `auto_summary`
    ///   snapshot's timestamp (or any row exists, when no prior summary).
    /// - `Ok(false)` when the session has been read-only since the last
    ///   summary (or since session start, when none exist).
    ///
    /// If the `tool_events` query errors (e.g. migration not yet applied),
    /// returns `Ok(true)` so the caller does not silently skip the
    /// summary; the conservative default is to assume activity.
    pub fn had_mutator_activity_since_last_auto_summary(
        &self,
        session_id: &str,
    ) -> crate::Result<bool> {
        let last_ts: Option<String> = self
            .conn
            .query_row(
                "SELECT MAX(created_at) FROM snapshots \
                 WHERE session_id = ?1 AND trigger = 'auto_summary'",
                [session_id],
                |row| row.get(0),
            )
            .optional()?
            .flatten();

        let count: rusqlite::Result<i64> = match last_ts {
            Some(ts) => self.conn.query_row(
                "SELECT COUNT(*) FROM tool_events \
                 WHERE session_id = ?1 AND created_at > ?2",
                rusqlite::params![session_id, ts],
                |row| row.get(0),
            ),
            None => self.conn.query_row(
                "SELECT COUNT(*) FROM tool_events WHERE session_id = ?1",
                [session_id],
                |row| row.get(0),
            ),
        };

        match count {
            Ok(n) => Ok(n > 0),
            Err(e) => {
                warn!(
                    "had_mutator_activity_since_last_auto_summary: tool_events query failed: {e}"
                );
                Ok(true) // conservative: don't skip the summary on query failure
            }
        }
    }
}

#[cfg(test)]
mod auto_summary_tests {
    use super::*;
    use crate::types::{Snapshot, SnapshotTrigger, ToolEvent, ToolOutcome};

    fn mk_storage() -> Storage {
        Storage::open_in_memory().expect("open in-memory storage")
    }

    fn seed_session(s: &Storage, id: &str) {
        s.conn
            .execute(
                "INSERT OR IGNORE INTO sessions (id, project_path, started_at, source, status) \
                 VALUES (?1, '', datetime('now'), 'manual', 'active')",
                [id],
            )
            .expect("seed session");
    }

    fn append_tool_event(s: &Storage, session: &str, idx: usize) {
        let summary = format!("edit src/{idx}.rs");
        let ev = ToolEvent::new(
            crate::types::SessionId::new(session),
            "Edit",
            Some(format!("src/{idx}.rs")),
            &summary,
            ToolOutcome::Success,
            1_000,
        );
        s.append_or_extend_tool_event(&ev)
            .expect("append tool event");
    }

    fn append_auto_summary(s: &Storage, session: &str) {
        let mut snap = Snapshot::new(
            crate::types::SessionId::new(session),
            SnapshotTrigger::AutoSummary,
        );
        snap.summary = Some("prior auto-summary".to_string());
        s.create_snapshot(&snap)
            .expect("create auto_summary snapshot");
    }

    #[test]
    fn turns_since_zero_on_empty_session() {
        let s = mk_storage();
        seed_session(&s, "sess-A");
        let n = s.turns_since_last_auto_summary("sess-A").unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn turns_since_counts_all_tool_events_when_no_prior_summary() {
        let s = mk_storage();
        seed_session(&s, "sess-A");
        for idx in 0..3 {
            append_tool_event(&s, "sess-A", idx);
        }
        let n = s.turns_since_last_auto_summary("sess-A").unwrap();
        assert_eq!(n, 3);
    }

    #[test]
    fn turns_since_counts_only_after_last_summary() {
        let s = mk_storage();
        seed_session(&s, "sess-A");
        // 2 tool events before summary, then summary, then 4 after.
        append_tool_event(&s, "sess-A", 0);
        append_tool_event(&s, "sess-A", 1);
        // Sleep one second so DATETIME() bucket increments, sqlite stores
        // RFC3339 strings; comparisons are lexicographic.
        std::thread::sleep(std::time::Duration::from_millis(1100));
        append_auto_summary(&s, "sess-A");
        std::thread::sleep(std::time::Duration::from_millis(1100));
        for idx in 2..6 {
            append_tool_event(&s, "sess-A", idx);
        }
        let n = s.turns_since_last_auto_summary("sess-A").unwrap();
        assert_eq!(n, 4, "should only count post-summary tool events");
    }

    #[test]
    fn turns_since_exactly_n_returns_n() {
        let s = mk_storage();
        seed_session(&s, "sess-A");
        for idx in 0..5 {
            append_tool_event(&s, "sess-A", idx);
        }
        let n = s.turns_since_last_auto_summary("sess-A").unwrap();
        assert_eq!(n, 5);
    }

    #[test]
    fn mutator_activity_false_when_no_tool_events() {
        let s = mk_storage();
        seed_session(&s, "sess-A");
        let had = s
            .had_mutator_activity_since_last_auto_summary("sess-A")
            .unwrap();
        assert!(!had, "fresh session must not show mutator activity");
    }

    #[test]
    fn mutator_activity_true_when_tool_event_exists() {
        let s = mk_storage();
        seed_session(&s, "sess-A");
        let ev = ToolEvent::new(
            crate::types::SessionId::new("sess-A"),
            "Edit",
            Some("src/foo.rs".to_string()),
            "edit foo.rs",
            ToolOutcome::Success,
            1_000,
        );
        s.append_or_extend_tool_event(&ev).unwrap();
        let had = s
            .had_mutator_activity_since_last_auto_summary("sess-A")
            .unwrap();
        assert!(had);
    }
}
