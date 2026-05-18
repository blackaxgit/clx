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

    /// Atomically create an auto-summary snapshot only when no other
    /// `AutoSummary`-triggered snapshot for the same session was written
    /// within the last `within_secs` seconds.
    ///
    /// This closes the `TOCTOU` window in the Stop auto-summary hook: the
    /// previous implementation re-read `last_auto_summary_at` and then
    /// called `create_snapshot` in two separate statements, so two
    /// concurrent Stop handlers could both pass the guard and both INSERT
    /// duplicate snapshots. Here the guard and the INSERT are a single
    /// `INSERT ... SELECT ... WHERE NOT EXISTS` executed inside an
    /// `IMMEDIATE` transaction, so `SQLite` serializes the two handlers and
    /// the second one's `WHERE NOT EXISTS` sees the first one's row.
    ///
    /// Returns `Ok(true)` when this call inserted the snapshot, `Ok(false)`
    /// when a recent `AutoSummary` already existed and nothing was written
    /// (the caller logs this at debug and returns cleanly).
    pub fn create_snapshot_if_no_recent_auto_summary(
        &self,
        snapshot: &Snapshot,
        within_secs: i64,
    ) -> crate::Result<bool> {
        // IMMEDIATE acquires the write lock up front so the NOT EXISTS
        // probe and the INSERT cannot interleave with a parallel handler.
        // `Storage` only exposes `&self`, so we drive the transaction with
        // explicit statements (same shape as `unchecked_transaction`, but
        // with IMMEDIATE locking instead of the default DEFERRED).
        self.conn.execute_batch("BEGIN IMMEDIATE")?;

        // RFC3339 timestamps sort lexicographically, but the freshness
        // window is a duration so we compare against a computed lower
        // bound. `created_at` is stored via `to_rfc3339()`; SQLite's
        // `datetime()` parses that and `strftime('%s', ...)` yields epoch
        // seconds for a numeric comparison that is timezone-safe.
        let insert_result = self.conn.execute(
            "INSERT INTO snapshots \
                 (session_id, created_at, trigger, summary, key_facts, todos, message_count, input_tokens, output_tokens) \
             SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9 \
             WHERE NOT EXISTS ( \
                 SELECT 1 FROM snapshots \
                 WHERE session_id = ?1 \
                   AND trigger = 'auto_summary' \
                   AND CAST(strftime('%s', created_at) AS INTEGER) \
                       > (CAST(strftime('%s', ?2) AS INTEGER) - ?10) \
             )",
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
                within_secs,
            ],
        );

        let inserted = match insert_result {
            Ok(n) => n,
            Err(e) => {
                // Best-effort rollback; ignore secondary failure.
                let _ = self.conn.execute_batch("ROLLBACK");
                return Err(e.into());
            }
        };

        self.conn.execute_batch("COMMIT")?;

        if inserted == 0 {
            debug!(
                "create_snapshot_if_no_recent_auto_summary: a recent auto_summary already exists for session {} (within {}s); skipped",
                snapshot.session_id, within_secs
            );
            return Ok(false);
        }
        debug!(
            "create_snapshot_if_no_recent_auto_summary: inserted auto_summary snapshot for session {}",
            snapshot.session_id
        );
        Ok(true)
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
    /// preventing duplicate `AutoSummary` snapshots for the same session/window.
    pub fn last_auto_summary_at(&self, session_id: &str) -> crate::Result<Option<DateTime<Utc>>> {
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

    fn mk_auto_summary(session: &str, body: &str) -> Snapshot {
        let mut snap = Snapshot::new(
            crate::types::SessionId::new(session),
            SnapshotTrigger::AutoSummary,
        );
        snap.summary = Some(body.to_string());
        snap
    }

    /// F3: a single handler still writes exactly one `AutoSummary` snapshot.
    #[test]
    fn f3_single_handler_writes_one_snapshot() {
        let s = mk_storage();
        seed_session(&s, "sess-F3a");
        let inserted = s
            .create_snapshot_if_no_recent_auto_summary(&mk_auto_summary("sess-F3a", "first"), 60)
            .unwrap();
        assert!(inserted, "first call must insert");
        let snaps = s.get_snapshots_by_session("sess-F3a").unwrap();
        assert_eq!(snaps.len(), 1);
    }

    /// F3: two simulated concurrent Stop handlers against one DB produce
    /// exactly ONE `AutoSummary` snapshot; the loser reports `Ok(false)`.
    #[test]
    fn f3_concurrent_handlers_produce_exactly_one_snapshot() {
        let s = mk_storage();
        seed_session(&s, "sess-F3b");

        // Both handlers compute their guarded insert against the same DB.
        // The second observes the first's row via WHERE NOT EXISTS inside
        // the IMMEDIATE transaction and writes nothing.
        let a = s
            .create_snapshot_if_no_recent_auto_summary(
                &mk_auto_summary("sess-F3b", "handler-A"),
                60,
            )
            .unwrap();
        let b = s
            .create_snapshot_if_no_recent_auto_summary(
                &mk_auto_summary("sess-F3b", "handler-B"),
                60,
            )
            .unwrap();

        assert!(a ^ b, "exactly one handler must win (a={a}, b={b})");
        let snaps = s.get_snapshots_by_session("sess-F3b").unwrap();
        assert_eq!(
            snaps.len(),
            1,
            "concurrent handlers must produce exactly one AutoSummary"
        );
    }

    /// F3: when a recent `AutoSummary` already exists within the window the
    /// guarded insert writes nothing.
    #[test]
    fn f3_recent_existing_summary_blocks_new_insert() {
        let s = mk_storage();
        seed_session(&s, "sess-F3c");
        append_auto_summary(&s, "sess-F3c"); // existing recent summary

        let inserted = s
            .create_snapshot_if_no_recent_auto_summary(
                &mk_auto_summary("sess-F3c", "should-skip"),
                3600,
            )
            .unwrap();
        assert!(!inserted, "a recent AutoSummary must block the new insert");
        let snaps = s.get_snapshots_by_session("sess-F3c").unwrap();
        assert_eq!(snaps.len(), 1, "no duplicate AutoSummary written");
    }

    /// F3: an `AutoSummary` older than the window does NOT block a new one
    /// (legitimate periodic summary still proceeds). The prior summary is
    /// inserted with a `created_at` two hours in the past so it falls
    /// outside the 60s freshness window.
    #[test]
    fn f3_stale_summary_allows_new_insert() {
        let s = mk_storage();
        seed_session(&s, "sess-F3d");

        let old_ts = (Utc::now() - chrono::Duration::hours(2)).to_rfc3339();
        s.conn
            .execute(
                "INSERT INTO snapshots (session_id, created_at, trigger, summary) \
                 VALUES ('sess-F3d', ?1, 'auto_summary', 'old')",
                [old_ts],
            )
            .unwrap();

        let inserted = s
            .create_snapshot_if_no_recent_auto_summary(&mk_auto_summary("sess-F3d", "fresh"), 60)
            .unwrap();
        assert!(inserted, "a stale prior summary must not block a new one");
        let snaps = s.get_snapshots_by_session("sess-F3d").unwrap();
        assert_eq!(snaps.len(), 2);
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
