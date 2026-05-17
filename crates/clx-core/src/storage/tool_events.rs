//! Aggregated tool-event operations.
//!
//! Backs the `tool_events` table introduced in schema version 6. Each row
//! represents one or more invocations of a mutator tool (`Edit`, `Write`,
//! `MultiEdit`, `NotebookEdit`, or a mutator `Bash` command) within a
//! 60-second window per `(tool_name, target)` pair.
//!
//! Layering: pure infrastructure. The aggregator that decides *whether* to
//! emit a row, the target normalization, and the summary template live in
//! `clx-hook::hooks::aggregator` (domain / pure). This module is responsible
//! only for transactional persistence and queries.

use rusqlite::{OptionalExtension, Row, params};
use tracing::{debug, warn};

use super::Storage;
use super::util::parse_datetime;
use crate::types::{SessionId, ToolEvent, ToolOutcome};

/// 60-second deduplication window for aggregating tool invocations.
pub const DEDUP_WINDOW_SECS: i64 = 60;

impl Storage {
    /// Append a new aggregated tool event or extend an existing in-window row.
    ///
    /// Behaviour:
    /// 1. Ensures the referenced session row exists via `INSERT OR IGNORE`
    ///    (mirrors the FK-safe pattern in `audit.rs`).
    /// 2. Within a transaction, looks for a recent row matching
    ///    `(tool_name, target)` whose `window_end_unix >= now - 60`.
    /// 3. If a match is found, increments `occurrence_count`, advances
    ///    `window_end_unix` to `now`, and replaces `outcome` and `summary`
    ///    with the latest values.
    /// 4. Otherwise, inserts a new row.
    ///
    /// Returns the row id of the inserted or updated row.
    pub fn append_or_extend_tool_event(&self, ev: &ToolEvent) -> crate::Result<i64> {
        // FK-safe placeholder: matches the proven pattern from `create_audit_log`.
        self.conn.execute(
            "INSERT OR IGNORE INTO sessions (id, project_path, started_at, source, status) \
             VALUES (?1, '', datetime('now'), 'audit-placeholder', 'active')",
            params![ev.session_id],
        )?;

        let tx = self.conn.unchecked_transaction()?;

        let cutoff = ev.window_end_unix - DEDUP_WINDOW_SECS;
        let existing: Option<i64> = tx
            .query_row(
                "SELECT id FROM tool_events \
                 WHERE tool_name = ?1 \
                   AND COALESCE(target, '') = COALESCE(?2, '') \
                   AND session_id = ?3 \
                   AND window_end_unix >= ?4 \
                 ORDER BY id DESC LIMIT 1",
                params![
                    ev.tool_name,
                    ev.target,
                    ev.session_id,
                    cutoff,
                ],
                |row| row.get(0),
            )
            .optional()?;

        let id = if let Some(existing_id) = existing {
            tx.execute(
                "UPDATE tool_events \
                 SET occurrence_count = occurrence_count + 1, \
                     window_end_unix = ?1, \
                     outcome = ?2, \
                     summary = ?3 \
                 WHERE id = ?4",
                params![
                    ev.window_end_unix,
                    ev.outcome.as_str(),
                    ev.summary,
                    existing_id,
                ],
            )?;
            debug!(
                "Extended tool_event {} (tool={} target={:?})",
                existing_id, ev.tool_name, ev.target
            );
            existing_id
        } else {
            tx.execute(
                "INSERT INTO tool_events ( \
                    session_id, tool_name, target, summary, outcome, \
                    window_start_unix, window_end_unix, occurrence_count, created_at \
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    ev.session_id,
                    ev.tool_name,
                    ev.target,
                    ev.summary,
                    ev.outcome.as_str(),
                    ev.window_start_unix,
                    ev.window_end_unix,
                    ev.occurrence_count,
                    ev.created_at.to_rfc3339(),
                ],
            )?;
            let new_id = tx.last_insert_rowid();
            debug!(
                "Inserted tool_event {} (tool={} target={:?})",
                new_id, ev.tool_name, ev.target
            );
            new_id
        };

        tx.commit()?;
        Ok(id)
    }

    /// Return the most recent `limit` tool events for a session, newest first.
    pub fn recent_tool_events_for_session(
        &self,
        session_id: &str,
        limit: i64,
    ) -> crate::Result<Vec<ToolEvent>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, session_id, tool_name, target, summary, outcome, \
                    window_start_unix, window_end_unix, occurrence_count, created_at \
             FROM tool_events \
             WHERE session_id = ?1 \
             ORDER BY id DESC LIMIT ?2",
        )?;
        let rows = stmt
            .query_map(params![session_id, limit], Self::row_to_tool_event)?
            .filter_map(|r| match r {
                Ok(v) => Some(v),
                Err(e) => {
                    warn!("Row deserialization error in tool_events (skipped): {}", e);
                    None
                }
            })
            .collect();
        Ok(rows)
    }

    /// Return all tool events targeting `target` across sessions, newest first.
    pub fn tool_events_by_target(
        &self,
        target: &str,
        limit: i64,
    ) -> crate::Result<Vec<ToolEvent>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, session_id, tool_name, target, summary, outcome, \
                    window_start_unix, window_end_unix, occurrence_count, created_at \
             FROM tool_events \
             WHERE target = ?1 \
             ORDER BY id DESC LIMIT ?2",
        )?;
        let rows = stmt
            .query_map(params![target, limit], Self::row_to_tool_event)?
            .filter_map(|r| match r {
                Ok(v) => Some(v),
                Err(e) => {
                    warn!("Row deserialization error in tool_events (skipped): {}", e);
                    None
                }
            })
            .collect();
        Ok(rows)
    }

    /// Delete tool events older than `days` days based on `created_at`.
    ///
    /// `days == 0` retains everything (returns `Ok(0)` without issuing a
    /// DELETE) so users can opt out of retention entirely.
    pub fn cleanup_old_tool_events(&self, days: u32) -> crate::Result<usize> {
        if days == 0 {
            return Ok(0);
        }
        let cutoff_secs = i64::from(days) * 86400;
        let deleted = self.conn.execute(
            "DELETE FROM tool_events WHERE created_at < datetime('now', '-' || ?1 || ' seconds')",
            [cutoff_secs],
        )?;
        Ok(deleted)
    }

    /// Count `tool_events` rows for a session (used by tests + diagnostics).
    pub fn count_tool_events(&self, session_id: &str) -> crate::Result<i64> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM tool_events WHERE session_id = ?1",
            [session_id],
            |row| row.get(0),
        )?;
        Ok(count)
    }

    fn row_to_tool_event(row: &Row) -> rusqlite::Result<ToolEvent> {
        let created_at_str: String = row.get(9)?;
        let outcome_str: String = row.get(5)?;
        Ok(ToolEvent {
            id: Some(row.get(0)?),
            session_id: SessionId::new(row.get::<_, String>(1)?),
            tool_name: row.get(2)?,
            target: row.get(3)?,
            summary: row.get(4)?,
            outcome: ToolOutcome::parse(&outcome_str),
            window_start_unix: row.get(6)?,
            window_end_unix: row.get(7)?,
            occurrence_count: row.get(8)?,
            created_at: parse_datetime(&created_at_str),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{SessionId, ToolEvent, ToolOutcome};

    fn mk_storage() -> Storage {
        Storage::open_in_memory().expect("open in-memory storage")
    }

    fn mk_event(
        session: &str,
        tool: &str,
        target: Option<&str>,
        summary: &str,
        now: i64,
    ) -> ToolEvent {
        ToolEvent::new(
            SessionId::new(session),
            tool,
            target.map(str::to_string),
            summary,
            ToolOutcome::Success,
            now,
        )
    }

    #[test]
    fn append_inserts_new_row_on_empty_db() {
        let s = mk_storage();
        let ev = mk_event("sess-A", "Edit", Some("src/foo.rs"), "edit foo.rs", 1_000);
        let id = s.append_or_extend_tool_event(&ev).unwrap();
        assert!(id >= 1);
        assert_eq!(s.count_tool_events("sess-A").unwrap(), 1);
        let rows = s.recent_tool_events_for_session("sess-A", 10).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].tool_name, "Edit");
        assert_eq!(rows[0].target.as_deref(), Some("src/foo.rs"));
        assert_eq!(rows[0].occurrence_count, 1);
    }

    #[test]
    fn append_extends_within_60s_window() {
        let s = mk_storage();
        let ev1 = mk_event("sess-A", "Edit", Some("src/foo.rs"), "edit foo.rs v1", 1_000);
        let ev2 = mk_event("sess-A", "Edit", Some("src/foo.rs"), "edit foo.rs v2", 1_030);
        let id1 = s.append_or_extend_tool_event(&ev1).unwrap();
        let id2 = s.append_or_extend_tool_event(&ev2).unwrap();
        assert_eq!(id1, id2, "second call should extend the same row");
        let rows = s.recent_tool_events_for_session("sess-A", 10).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].occurrence_count, 2);
        assert_eq!(rows[0].window_end_unix, 1_030);
        assert_eq!(rows[0].summary, "edit foo.rs v2");
    }

    #[test]
    fn append_inserts_new_row_outside_60s_window() {
        let s = mk_storage();
        let ev1 = mk_event("sess-A", "Edit", Some("src/foo.rs"), "edit foo.rs v1", 1_000);
        let ev2 = mk_event("sess-A", "Edit", Some("src/foo.rs"), "edit foo.rs v2", 1_061);
        let id1 = s.append_or_extend_tool_event(&ev1).unwrap();
        let id2 = s.append_or_extend_tool_event(&ev2).unwrap();
        assert_ne!(id1, id2);
        assert_eq!(s.count_tool_events("sess-A").unwrap(), 2);
    }

    #[test]
    fn append_distinct_targets_get_distinct_rows() {
        let s = mk_storage();
        let ev1 = mk_event("sess-A", "Edit", Some("src/foo.rs"), "edit foo.rs", 1_000);
        let ev2 = mk_event("sess-A", "Edit", Some("src/bar.rs"), "edit bar.rs", 1_000);
        s.append_or_extend_tool_event(&ev1).unwrap();
        s.append_or_extend_tool_event(&ev2).unwrap();
        assert_eq!(s.count_tool_events("sess-A").unwrap(), 2);
    }

    #[test]
    fn append_distinct_tools_get_distinct_rows_same_target() {
        let s = mk_storage();
        let ev1 = mk_event("sess-A", "Edit", Some("src/foo.rs"), "edit foo.rs", 1_000);
        let ev2 = mk_event("sess-A", "Write", Some("src/foo.rs"), "write foo.rs", 1_000);
        s.append_or_extend_tool_event(&ev1).unwrap();
        s.append_or_extend_tool_event(&ev2).unwrap();
        assert_eq!(s.count_tool_events("sess-A").unwrap(), 2);
    }

    #[test]
    fn append_distinct_sessions_do_not_merge() {
        let s = mk_storage();
        let ev1 = mk_event("sess-A", "Edit", Some("src/foo.rs"), "edit foo.rs", 1_000);
        let ev2 = mk_event("sess-B", "Edit", Some("src/foo.rs"), "edit foo.rs", 1_010);
        s.append_or_extend_tool_event(&ev1).unwrap();
        s.append_or_extend_tool_event(&ev2).unwrap();
        assert_eq!(s.count_tool_events("sess-A").unwrap(), 1);
        assert_eq!(s.count_tool_events("sess-B").unwrap(), 1);
    }

    #[test]
    fn append_null_targets_merge_with_each_other() {
        let s = mk_storage();
        let ev1 = mk_event("sess-A", "Bash", None, "bash command 1", 1_000);
        let ev2 = mk_event("sess-A", "Bash", None, "bash command 2", 1_020);
        s.append_or_extend_tool_event(&ev1).unwrap();
        s.append_or_extend_tool_event(&ev2).unwrap();
        // COALESCE(NULL,'') = COALESCE(NULL,'') -> merge.
        assert_eq!(s.count_tool_events("sess-A").unwrap(), 1);
        let rows = s.recent_tool_events_for_session("sess-A", 10).unwrap();
        assert_eq!(rows[0].occurrence_count, 2);
    }

    #[test]
    fn append_fk_safe_with_synthetic_session_id() {
        // Regression: tool_events.session_id -> sessions.id FK.
        // append_or_extend_tool_event must succeed even when no sessions row
        // exists for the given id (INSERT OR IGNORE inserts a placeholder).
        let s = mk_storage();
        let ev = mk_event("synthetic-no-session", "Edit", Some("a.rs"), "edit a.rs", 1_000);
        let id = s.append_or_extend_tool_event(&ev).unwrap();
        assert!(id >= 1);
        // Sessions placeholder exists.
        let count: i64 = s
            .conn
            .query_row(
                "SELECT COUNT(*) FROM sessions WHERE id = ?1",
                ["synthetic-no-session"],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn outcome_is_replaced_on_extend() {
        let s = mk_storage();
        let mut ev1 = mk_event("sess-A", "Edit", Some("src/foo.rs"), "v1", 1_000);
        ev1.outcome = ToolOutcome::Success;
        s.append_or_extend_tool_event(&ev1).unwrap();

        let mut ev2 = mk_event("sess-A", "Edit", Some("src/foo.rs"), "v2", 1_030);
        ev2.outcome = ToolOutcome::Error;
        s.append_or_extend_tool_event(&ev2).unwrap();

        let rows = s.recent_tool_events_for_session("sess-A", 10).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].outcome, ToolOutcome::Error);
    }

    #[test]
    fn recent_tool_events_respects_limit_and_order() {
        let s = mk_storage();
        for i in 0..5 {
            let ev = mk_event(
                "sess-A",
                "Edit",
                Some(&format!("f{i}.rs")),
                &format!("edit f{i}.rs"),
                1_000 + i64::from(i),
            );
            s.append_or_extend_tool_event(&ev).unwrap();
        }
        let rows = s.recent_tool_events_for_session("sess-A", 3).unwrap();
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].target.as_deref(), Some("f4.rs"));
        assert_eq!(rows[2].target.as_deref(), Some("f2.rs"));
    }

    #[test]
    fn tool_events_by_target_returns_only_matching() {
        let s = mk_storage();
        let a = mk_event("sess-A", "Edit", Some("src/foo.rs"), "edit foo.rs", 1_000);
        let b = mk_event("sess-A", "Edit", Some("src/bar.rs"), "edit bar.rs", 1_000);
        let c = mk_event("sess-B", "Edit", Some("src/foo.rs"), "edit foo.rs", 1_000);
        s.append_or_extend_tool_event(&a).unwrap();
        s.append_or_extend_tool_event(&b).unwrap();
        s.append_or_extend_tool_event(&c).unwrap();
        let rows = s.tool_events_by_target("src/foo.rs", 10).unwrap();
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().all(|r| r.target.as_deref() == Some("src/foo.rs")));
    }

    #[test]
    fn cleanup_zero_days_is_a_no_op() {
        let s = mk_storage();
        let ev = mk_event("sess-A", "Edit", Some("src/foo.rs"), "edit foo.rs", 1_000);
        s.append_or_extend_tool_event(&ev).unwrap();
        let deleted = s.cleanup_old_tool_events(0).unwrap();
        assert_eq!(deleted, 0);
        assert_eq!(s.count_tool_events("sess-A").unwrap(), 1);
    }

    #[test]
    fn cleanup_deletes_only_rows_older_than_window() {
        let s = mk_storage();
        // Seed two rows: one with stale created_at, one fresh.
        let fresh = mk_event("sess-A", "Edit", Some("a.rs"), "fresh", 1_000);
        s.append_or_extend_tool_event(&fresh).unwrap();
        let stale = mk_event("sess-A", "Edit", Some("b.rs"), "stale", 1_000);
        s.append_or_extend_tool_event(&stale).unwrap();

        // Backdate one row by 45 days.
        s.conn
            .execute(
                "UPDATE tool_events SET created_at = datetime('now', '-45 days') WHERE target = 'b.rs'",
                [],
            )
            .unwrap();

        let deleted = s.cleanup_old_tool_events(30).unwrap();
        assert_eq!(deleted, 1);
        assert_eq!(s.count_tool_events("sess-A").unwrap(), 1);
        let rows = s.recent_tool_events_for_session("sess-A", 10).unwrap();
        assert_eq!(rows[0].target.as_deref(), Some("a.rs"));
    }

    #[test]
    fn cleanup_large_retention_keeps_recent_rows() {
        let s = mk_storage();
        let ev = mk_event("sess-A", "Edit", Some("a.rs"), "fresh", 1_000);
        s.append_or_extend_tool_event(&ev).unwrap();
        let deleted = s.cleanup_old_tool_events(365).unwrap();
        assert_eq!(deleted, 0);
        assert_eq!(s.count_tool_events("sess-A").unwrap(), 1);
    }

    #[test]
    fn recent_tool_events_empty_session_returns_empty_vec() {
        let s = mk_storage();
        let rows = s.recent_tool_events_for_session("unknown", 10).unwrap();
        assert!(rows.is_empty());
    }

    #[test]
    fn count_tool_events_for_unknown_session_is_zero() {
        let s = mk_storage();
        assert_eq!(s.count_tool_events("ghost").unwrap(), 0);
    }

    #[test]
    fn append_round_trip_preserves_fields() {
        let s = mk_storage();
        let mut ev = mk_event("sess-A", "Write", Some("src/a.rs"), "write a.rs (12 bytes)", 5_000);
        ev.outcome = ToolOutcome::Success;
        s.append_or_extend_tool_event(&ev).unwrap();

        let rows = s.recent_tool_events_for_session("sess-A", 10).unwrap();
        assert_eq!(rows.len(), 1);
        let r = &rows[0];
        assert_eq!(r.session_id.as_str(), "sess-A");
        assert_eq!(r.tool_name, "Write");
        assert_eq!(r.target.as_deref(), Some("src/a.rs"));
        assert_eq!(r.summary, "write a.rs (12 bytes)");
        assert_eq!(r.outcome, ToolOutcome::Success);
        assert_eq!(r.window_start_unix, 5_000);
        assert_eq!(r.window_end_unix, 5_000);
        assert_eq!(r.occurrence_count, 1);
    }
}
