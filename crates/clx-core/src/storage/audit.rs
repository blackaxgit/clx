//! Audit log operations
//!
//! Create, query, count, and manage audit log entries.

use chrono::{DateTime, Utc};
use rusqlite::{OptionalExtension, Row, params};
use tracing::{debug, warn};

use super::Storage;
use super::util::parse_datetime;
use crate::types::{AuditDecision, AuditLogEntry, UserDecision};

impl Storage {
    /// Create an audit log entry.
    ///
    /// First ensures the referenced session row exists (INSERT OR IGNORE with
    /// safe defaults). Without this guard, fast-path / synthetic / fabricated
    /// session IDs trip the `audit_log` → `sessions` FOREIGN KEY constraint.
    pub fn create_audit_log(&self, entry: &AuditLogEntry) -> crate::Result<i64> {
        // Ensure the FK target exists. No-op if the session was already created
        // by SessionStart hook; a synthetic placeholder otherwise.
        self.conn.execute(
            "INSERT OR IGNORE INTO sessions (id, project_path, started_at, source, status) \
             VALUES (?1, '', datetime('now'), 'audit-placeholder', 'active')",
            params![entry.session_id],
        )?;
        self.conn.execute(
            "INSERT INTO audit_log (session_id, timestamp, command, working_dir, layer, decision, risk_score, reasoning, user_decision)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                entry.session_id,
                entry.timestamp.to_rfc3339(),
                entry.command,
                entry.working_dir,
                entry.layer,
                entry.decision.as_str(),
                entry.risk_score,
                entry.reasoning,
                entry.user_decision.as_ref().map(super::super::types::UserDecision::as_str),
            ],
        )?;
        let id = self.conn.last_insert_rowid();
        debug!("Created audit log {} for session {}", id, entry.session_id);
        Ok(id)
    }

    /// Get audit log entries for a session
    pub fn get_audit_log_by_session(&self, session_id: &str) -> crate::Result<Vec<AuditLogEntry>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, session_id, timestamp, command, working_dir, layer, decision, risk_score, reasoning, user_decision
             FROM audit_log WHERE session_id = ?1 ORDER BY timestamp DESC",
        )?;
        let entries = stmt
            .query_map([session_id], Self::row_to_audit_log)?
            .filter_map(|r| match r {
                Ok(v) => Some(v),
                Err(e) => {
                    warn!("Row deserialization error (skipped): {}", e);
                    None
                }
            })
            .collect();
        Ok(entries)
    }

    /// Get recent audit log entries across all sessions
    pub fn get_recent_audit_log(&self, limit: i64) -> crate::Result<Vec<AuditLogEntry>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, session_id, timestamp, command, working_dir, layer, decision, risk_score, reasoning, user_decision
             FROM audit_log ORDER BY timestamp DESC LIMIT ?1",
        )?;
        let entries = stmt
            .query_map([limit], Self::row_to_audit_log)?
            .filter_map(|r| match r {
                Ok(v) => Some(v),
                Err(e) => {
                    warn!("Row deserialization error (skipped): {}", e);
                    None
                }
            })
            .collect();
        Ok(entries)
    }

    /// Get audit log entry by ID
    pub fn get_audit_log(&self, id: i64) -> crate::Result<Option<AuditLogEntry>> {
        let result = self
            .conn
            .query_row(
                "SELECT id, session_id, timestamp, command, working_dir, layer, decision, risk_score, reasoning, user_decision
                 FROM audit_log WHERE id = ?1",
                [id],
                Self::row_to_audit_log,
            )
            .optional()?;
        Ok(result)
    }

    /// Get audit log entries since a given date
    pub fn get_audit_log_since(&self, since: DateTime<Utc>) -> crate::Result<Vec<AuditLogEntry>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, session_id, timestamp, command, working_dir, layer, decision, risk_score, reasoning, user_decision
             FROM audit_log WHERE timestamp >= ?1 ORDER BY timestamp DESC",
        )?;
        let entries = stmt
            .query_map([since.to_rfc3339()], Self::row_to_audit_log)?
            .filter_map(|r| match r {
                Ok(v) => Some(v),
                Err(e) => {
                    warn!("Row deserialization error (skipped): {}", e);
                    None
                }
            })
            .collect();
        Ok(entries)
    }

    /// Count audit log entries by decision type since a given date
    pub fn count_audit_by_decision(
        &self,
        since: Option<DateTime<Utc>>,
    ) -> crate::Result<std::collections::HashMap<String, i64>> {
        let query = if since.is_some() {
            "SELECT decision, COUNT(*) FROM audit_log WHERE timestamp >= ?1 GROUP BY decision"
        } else {
            "SELECT decision, COUNT(*) FROM audit_log GROUP BY decision"
        };

        let mut stmt = self.conn.prepare(query)?;
        let mut counts = std::collections::HashMap::new();

        let rows: Box<dyn Iterator<Item = rusqlite::Result<(String, i64)>>> =
            if let Some(dt) = since {
                Box::new(stmt.query_map([dt.to_rfc3339()], |row| Ok((row.get(0)?, row.get(1)?)))?)
            } else {
                Box::new(stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?)
            };

        for row in rows {
            match row {
                Ok(r) => {
                    counts.insert(r.0, r.1);
                }
                Err(e) => {
                    warn!("Row deserialization error in audit counts (skipped): {}", e);
                }
            }
        }
        Ok(counts)
    }

    /// Get top denied command patterns (first word of command) since a given date
    pub fn get_top_denied_patterns(
        &self,
        since: Option<DateTime<Utc>>,
        limit: i64,
    ) -> crate::Result<Vec<(String, i64)>> {
        // Extract the base command (first word) for grouping
        let query = if since.is_some() {
            "SELECT
                CASE
                    WHEN INSTR(command, ' ') > 0 THEN SUBSTR(command, 1, INSTR(command, ' ') - 1)
                    ELSE command
                END as base_cmd,
                COUNT(*) as cnt
             FROM audit_log
             WHERE decision = 'blocked' AND timestamp >= ?1
             GROUP BY base_cmd
             ORDER BY cnt DESC
             LIMIT ?2"
        } else {
            "SELECT
                CASE
                    WHEN INSTR(command, ' ') > 0 THEN SUBSTR(command, 1, INSTR(command, ' ') - 1)
                    ELSE command
                END as base_cmd,
                COUNT(*) as cnt
             FROM audit_log
             WHERE decision = 'blocked'
             GROUP BY base_cmd
             ORDER BY cnt DESC
             LIMIT ?1"
        };

        let mut stmt = self.conn.prepare(query)?;
        let patterns: Vec<(String, i64)> = if let Some(dt) = since {
            stmt.query_map(params![dt.to_rfc3339(), limit], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })?
            .filter_map(|r| match r {
                Ok(v) => Some(v),
                Err(e) => {
                    warn!("Row deserialization error (skipped): {}", e);
                    None
                }
            })
            .collect()
        } else {
            stmt.query_map(params![limit], |row| Ok((row.get(0)?, row.get(1)?)))?
                .filter_map(|r| match r {
                    Ok(v) => Some(v),
                    Err(e) => {
                        warn!("Row deserialization error (skipped): {}", e);
                        None
                    }
                })
                .collect()
        };
        Ok(patterns)
    }

    /// Get risk score distribution since a given date
    /// Returns counts for ranges: 1-3 (low), 4-7 (medium), 8-10 (high)
    pub fn get_risk_distribution(
        &self,
        since: Option<DateTime<Utc>>,
    ) -> crate::Result<(i64, i64, i64)> {
        let base_query = if since.is_some() {
            "SELECT
                SUM(CASE WHEN risk_score BETWEEN 1 AND 3 THEN 1 ELSE 0 END) as low,
                SUM(CASE WHEN risk_score BETWEEN 4 AND 7 THEN 1 ELSE 0 END) as medium,
                SUM(CASE WHEN risk_score BETWEEN 8 AND 10 THEN 1 ELSE 0 END) as high
             FROM audit_log WHERE risk_score IS NOT NULL AND timestamp >= ?1"
        } else {
            "SELECT
                SUM(CASE WHEN risk_score BETWEEN 1 AND 3 THEN 1 ELSE 0 END) as low,
                SUM(CASE WHEN risk_score BETWEEN 4 AND 7 THEN 1 ELSE 0 END) as medium,
                SUM(CASE WHEN risk_score BETWEEN 8 AND 10 THEN 1 ELSE 0 END) as high
             FROM audit_log WHERE risk_score IS NOT NULL"
        };

        let (low, medium, high): (i64, i64, i64) = if let Some(dt) = since {
            self.conn.query_row(base_query, [dt.to_rfc3339()], |row| {
                Ok((
                    row.get::<_, Option<i64>>(0)?.unwrap_or(0),
                    row.get::<_, Option<i64>>(1)?.unwrap_or(0),
                    row.get::<_, Option<i64>>(2)?.unwrap_or(0),
                ))
            })?
        } else {
            self.conn.query_row(base_query, [], |row| {
                Ok((
                    row.get::<_, Option<i64>>(0)?.unwrap_or(0),
                    row.get::<_, Option<i64>>(1)?.unwrap_or(0),
                    row.get::<_, Option<i64>>(2)?.unwrap_or(0),
                ))
            })?
        };
        Ok((low, medium, high))
    }

    /// Delete audit log entries older than `days` days.
    ///
    /// Returns the number of deleted entries. Use this to implement a
    /// retention policy and prevent unbounded growth of the audit log table.
    pub fn cleanup_old_audit_logs(&self, days: u32) -> crate::Result<usize> {
        let cutoff_secs = i64::from(days) * 86400;
        let deleted = self.conn.execute(
            "DELETE FROM audit_log WHERE timestamp < datetime('now', '-' || ?1 || ' seconds')",
            [cutoff_secs],
        )?;
        Ok(deleted)
    }

    /// Count total audit log entries since a given date
    pub fn count_audit_log(&self, since: Option<DateTime<Utc>>) -> crate::Result<i64> {
        let count: i64 = if let Some(dt) = since {
            self.conn.query_row(
                "SELECT COUNT(*) FROM audit_log WHERE timestamp >= ?1",
                [dt.to_rfc3339()],
                |row| row.get(0),
            )?
        } else {
            self.conn
                .query_row("SELECT COUNT(*) FROM audit_log", [], |row| row.get(0))?
        };
        Ok(count)
    }

    fn row_to_audit_log(row: &Row) -> rusqlite::Result<AuditLogEntry> {
        let timestamp_str: String = row.get(2)?;
        let decision_str: String = row.get(6)?;
        let user_decision_str: Option<String> = row.get(9)?;

        Ok(AuditLogEntry {
            id: Some(row.get(0)?),
            session_id: row.get(1)?,
            timestamp: parse_datetime(&timestamp_str),
            command: row.get(3)?,
            working_dir: row.get(4)?,
            layer: row.get(5)?,
            decision: AuditDecision::parse(&decision_str),
            risk_score: row.get(7)?,
            reasoning: row.get(8)?,
            user_decision: user_decision_str.map(|s| UserDecision::parse(&s)),
        })
    }
}
