//! Session CRUD operations
//!
//! Create, read, update, list, count, and end sessions.

use std::fmt::Write as _;

use chrono::{DateTime, Utc};
use rusqlite::{OptionalExtension, Row, params};
use tracing::{debug, warn};

use super::Storage;
use super::util::{parse_datetime, validate_session_id};
use crate::types::{Session, SessionSource, SessionStatus};

impl Storage {
    /// Create a new session
    pub fn create_session(&self, session: &Session) -> crate::Result<()> {
        validate_session_id(session.id.as_str())?;
        self.conn.execute(
            "INSERT INTO sessions (id, project_path, transcript_path, started_at, ended_at, source, message_count, command_count, input_tokens, output_tokens, status)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                session.id,
                session.project_path,
                session.transcript_path,
                session.started_at.to_rfc3339(),
                session.ended_at.map(|dt| dt.to_rfc3339()),
                session.source.as_str(),
                session.message_count,
                session.command_count,
                session.input_tokens,
                session.output_tokens,
                session.status.as_str(),
            ],
        )?;
        debug!("Created session: {}", session.id);
        Ok(())
    }

    /// Get a session by ID
    pub fn get_session(&self, id: &str) -> crate::Result<Option<Session>> {
        validate_session_id(id)?;
        let result = self
            .conn
            .query_row(
                "SELECT id, project_path, transcript_path, started_at, ended_at, source, message_count, command_count, input_tokens, output_tokens, status
                 FROM sessions WHERE id = ?1",
                [id],
                Self::row_to_session,
            )
            .optional()?;
        Ok(result)
    }

    /// Update a session
    pub fn update_session(&self, session: &Session) -> crate::Result<()> {
        self.conn.execute(
            "UPDATE sessions SET project_path = ?2, transcript_path = ?3, started_at = ?4, ended_at = ?5, source = ?6, message_count = ?7, command_count = ?8, input_tokens = ?9, output_tokens = ?10, status = ?11
             WHERE id = ?1",
            params![
                session.id,
                session.project_path,
                session.transcript_path,
                session.started_at.to_rfc3339(),
                session.ended_at.map(|dt| dt.to_rfc3339()),
                session.source.as_str(),
                session.message_count,
                session.command_count,
                session.input_tokens,
                session.output_tokens,
                session.status.as_str(),
            ],
        )?;
        debug!("Updated session: {}", session.id);
        Ok(())
    }

    /// List active sessions
    pub fn list_active_sessions(&self) -> crate::Result<Vec<Session>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, project_path, transcript_path, started_at, ended_at, source, message_count, command_count, input_tokens, output_tokens, status
             FROM sessions WHERE status = 'active' ORDER BY started_at DESC",
        )?;
        let sessions = stmt
            .query_map([], Self::row_to_session)?
            .filter_map(|r| match r {
                Ok(v) => Some(v),
                Err(e) => {
                    warn!("Row deserialization error (skipped): {}", e);
                    None
                }
            })
            .collect();
        Ok(sessions)
    }

    /// List sessions by project path
    pub fn list_sessions_by_project(&self, project_path: &str) -> crate::Result<Vec<Session>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, project_path, transcript_path, started_at, ended_at, source, message_count, command_count, input_tokens, output_tokens, status
             FROM sessions WHERE project_path = ?1 ORDER BY started_at DESC",
        )?;
        let sessions = stmt
            .query_map([project_path], Self::row_to_session)?
            .filter_map(|r| match r {
                Ok(v) => Some(v),
                Err(e) => {
                    warn!("Row deserialization error (skipped): {}", e);
                    None
                }
            })
            .collect();
        Ok(sessions)
    }

    /// List recent sessions with optional limit and date filter
    pub fn list_recent_sessions(
        &self,
        since: Option<DateTime<Utc>>,
        limit: Option<i64>,
    ) -> crate::Result<Vec<Session>> {
        const BASE: &str = "SELECT id, project_path, transcript_path, started_at, ended_at, source, \
             message_count, command_count, input_tokens, output_tokens, status FROM sessions";

        let mut clauses = String::new();
        let mut param_values: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();

        if let Some(dt) = since {
            clauses.push_str(" WHERE started_at >= ?1");
            param_values.push(Box::new(dt.to_rfc3339()));
        }

        clauses.push_str(" ORDER BY started_at DESC");

        if let Some(lim) = limit {
            let idx = param_values.len() + 1;
            let _ = write!(clauses, " LIMIT ?{idx}");
            param_values.push(Box::new(lim));
        }

        let query = format!("{BASE}{clauses}");
        let mut stmt = self.conn.prepare(&query)?;
        let params: Vec<&dyn rusqlite::types::ToSql> =
            param_values.iter().map(AsRef::as_ref).collect();
        let sessions = stmt
            .query_map(params.as_slice(), Self::row_to_session)?
            .filter_map(|r| match r {
                Ok(v) => Some(v),
                Err(e) => {
                    warn!("Row deserialization error (skipped): {}", e);
                    None
                }
            })
            .collect();
        Ok(sessions)
    }

    /// Count all sessions (optionally since a given date)
    pub fn count_sessions(&self, since: Option<DateTime<Utc>>) -> crate::Result<i64> {
        let count: i64 = if let Some(dt) = since {
            self.conn.query_row(
                "SELECT COUNT(*) FROM sessions WHERE started_at >= ?1",
                [dt.to_rfc3339()],
                |row| row.get(0),
            )?
        } else {
            self.conn
                .query_row("SELECT COUNT(*) FROM sessions", [], |row| row.get(0))?
        };
        Ok(count)
    }

    /// End a session
    pub fn end_session(&self, id: &str) -> crate::Result<()> {
        let now = Utc::now().to_rfc3339();
        self.conn.execute(
            "UPDATE sessions SET status = 'ended', ended_at = ?2 WHERE id = ?1",
            params![id, now],
        )?;
        debug!("Ended session: {}", id);
        Ok(())
    }

    /// Increment message count for a session
    pub fn increment_message_count(&self, session_id: &str) -> crate::Result<()> {
        self.conn.execute(
            "UPDATE sessions SET message_count = message_count + 1 WHERE id = ?1",
            [session_id],
        )?;
        Ok(())
    }

    /// Increment command count for a session
    pub fn increment_command_count(&self, session_id: &str) -> crate::Result<()> {
        self.conn.execute(
            "UPDATE sessions SET command_count = command_count + 1 WHERE id = ?1",
            [session_id],
        )?;
        Ok(())
    }

    /// Get total token counts for all sessions (optionally filtered by date)
    pub fn get_token_totals(&self, since: Option<DateTime<Utc>>) -> crate::Result<(i64, i64)> {
        let (sql, params): (&str, Vec<String>) = if let Some(dt) = since {
            (
                "SELECT COALESCE(SUM(input_tokens), 0), COALESCE(SUM(output_tokens), 0) FROM sessions WHERE started_at >= ?1",
                vec![dt.to_rfc3339()],
            )
        } else {
            (
                "SELECT COALESCE(SUM(input_tokens), 0), COALESCE(SUM(output_tokens), 0) FROM sessions",
                vec![],
            )
        };

        let result = if params.is_empty() {
            self.conn.query_row(sql, [], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?))
            })?
        } else {
            self.conn.query_row(sql, [&params[0]], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?))
            })?
        };

        Ok(result)
    }

    /// Mark a session as abandoned (crashed/interrupted without `SessionEnd`)
    pub fn mark_session_abandoned(&self, id: &str) -> crate::Result<()> {
        let now = Utc::now().to_rfc3339();
        self.conn.execute(
            "UPDATE sessions SET status = 'abandoned', ended_at = ?2 WHERE id = ?1",
            params![id, now],
        )?;
        debug!("Marked session as abandoned: {id}");
        Ok(())
    }

    /// Find active sessions for a project that are likely abandoned.
    /// Returns sessions with status='active' in the same project,
    /// started more than `stale_hours` ago, excluding `exclude_session_id`.
    pub fn find_stale_active_sessions(
        &self,
        project_path: &str,
        stale_hours: u32,
        exclude_session_id: &str,
    ) -> crate::Result<Vec<Session>> {
        let cutoff = (Utc::now() - chrono::Duration::hours(i64::from(stale_hours))).to_rfc3339();
        let mut stmt = self.conn.prepare(
            "SELECT id, project_path, transcript_path, started_at, ended_at, source, message_count, command_count, input_tokens, output_tokens, status
             FROM sessions
             WHERE status = 'active'
               AND project_path = ?1
               AND started_at < ?2
               AND id != ?3
             ORDER BY started_at DESC",
        )?;
        let sessions = stmt
            .query_map(
                params![project_path, cutoff, exclude_session_id],
                Self::row_to_session,
            )?
            .filter_map(std::result::Result::ok)
            .collect();
        Ok(sessions)
    }

    fn row_to_session(row: &Row) -> rusqlite::Result<Session> {
        let started_at_str: String = row.get(3)?;
        let ended_at_str: Option<String> = row.get(4)?;
        let source_str: String = row.get(5)?;
        let status_str: String = row.get(10)?;

        Ok(Session {
            id: row.get(0)?,
            project_path: row.get(1)?,
            transcript_path: row.get(2)?,
            started_at: parse_datetime(&started_at_str),
            ended_at: ended_at_str.map(|s| parse_datetime(&s)),
            source: SessionSource::parse(&source_str),
            message_count: row.get(6)?,
            command_count: row.get(7)?,
            input_tokens: row.get(8)?,
            output_tokens: row.get(9)?,
            status: SessionStatus::parse(&status_str),
        })
    }
}
