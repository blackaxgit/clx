//! Learning/debug event storage operations (opt-in firehose).
//!
//! When `validator.learning_mode` is enabled, every final `PreToolUse` decision
//! (plus error/degraded arms) is captured as a `learning_events` row. This
//! module is the storage layer for that firehose:
//!
//! - [`Storage::record_learning_event`] is the single write entry point and the
//!   **redaction choke-point**: it routes every free-text field through
//!   `redact_secrets` / `redact_json_value` before any value is bound.
//! - Retention is enforced after each insert via a deterministic COUNT-guard
//!   (cap at [`MAX_LEARNING_EVENTS`]) plus a 30-day TTL prune. Both are single
//!   atomic statements, race-safe under WAL.
//! - The read API ([`Storage::list_learning_events`],
//!   [`Storage::count_learning_events`], [`Storage::clear_learning_events`],
//!   [`Storage::learning_pattern_aggregates`]) backs the `clx learning` CLI.

use rusqlite::params;
use serde_json::Value;
use tracing::debug;

use super::Storage;
use crate::redaction::{redact_json_value, redact_secrets};
use crate::types::{LearningEvent, LearningKind};

/// Maximum number of retained `learning_events` rows. Oldest rows (lowest id)
/// are evicted once the count exceeds this cap.
pub const MAX_LEARNING_EVENTS: usize = 10_000;

/// Time-to-live for learning rows, in days. Rows older than this are pruned.
const LEARNING_TTL_DAYS: i64 = 30;

/// A redacted, bind-ready learning row produced by the choke-point.
struct LearningRow {
    ts: String,
    session_id: Option<String>,
    tool: String,
    host: String,
    decision: String,
    layer: String,
    kind: String,
    matched_rule: Option<String>,
    reason: String,
    command: Option<String>,
    effective_config: String,
    diverged: i64,
    divergence_reason: Option<String>,
    latency_ms: Option<i64>,
    policy_fingerprint: String,
}

/// Build a fully-redacted row from a raw [`LearningEvent`].
///
/// This is the SINGLE redaction choke-point for the firehose: `reason`,
/// `command`, and `matched_rule` are scrubbed with `redact_secrets`; the parsed
/// `effective_config` JSON is scrubbed with `redact_json_value` and
/// re-serialized. If `effective_config` is not valid JSON, the string is treated
/// as a free-text leaf and scrubbed with `redact_secrets` (defense-in-depth).
fn build_learning_row(ev: &LearningEvent) -> LearningRow {
    let effective_config = match serde_json::from_str::<Value>(&ev.effective_config) {
        Ok(v) => {
            let redacted = redact_json_value(&v);
            serde_json::to_string(&redacted)
                .unwrap_or_else(|_| redact_secrets(&ev.effective_config))
        }
        Err(_) => redact_secrets(&ev.effective_config),
    };

    LearningRow {
        ts: ev.ts.clone(),
        session_id: ev.session_id.clone(),
        tool: ev.tool.clone(),
        host: ev.host.clone(),
        decision: ev.decision.clone(),
        layer: ev.layer.clone(),
        kind: ev.kind.as_str().to_string(),
        matched_rule: ev.matched_rule.as_deref().map(redact_secrets),
        reason: redact_secrets(&ev.reason),
        command: ev.command.as_deref().map(redact_secrets),
        effective_config,
        diverged: i64::from(ev.diverged),
        divergence_reason: ev.divergence_reason.clone(),
        latency_ms: ev.latency_ms,
        policy_fingerprint: ev.policy_fingerprint.clone(),
    }
}

/// Filter for [`Storage::list_learning_events`].
#[derive(Debug, Clone, Default)]
pub struct LearningFilter {
    /// Restrict to a single decision string (`allow`/`ask`/`deny`).
    pub decision: Option<String>,
    /// Restrict to diverged / non-diverged rows.
    pub diverged: Option<bool>,
    /// Cap the number of rows returned (most recent first).
    pub limit: Option<usize>,
}

impl Storage {
    /// Record a learning event (the redaction choke-point + bounded retention).
    ///
    /// Every free-text field is redacted via [`build_learning_row`] before bind.
    /// After insert, retention is enforced: if the row count exceeds
    /// [`MAX_LEARNING_EVENTS`] the oldest rows are evicted, and rows older than
    /// the 30-day TTL are pruned. Both prunes are single atomic statements.
    pub fn record_learning_event(&self, ev: &LearningEvent) -> crate::Result<()> {
        let row = build_learning_row(ev);

        {
            let mut stmt = self.conn.prepare_cached(
                "INSERT INTO learning_events (
                    ts, session_id, tool, host, decision, layer, kind,
                    matched_rule, reason, command, effective_config,
                    diverged, divergence_reason, latency_ms, policy_fingerprint
                 ) VALUES (
                    ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15
                 )",
            )?;
            stmt.execute(params![
                row.ts,
                row.session_id,
                row.tool,
                row.host,
                row.decision,
                row.layer,
                row.kind,
                row.matched_rule,
                row.reason,
                row.command,
                row.effective_config,
                row.diverged,
                row.divergence_reason,
                row.latency_ms,
                row.policy_fingerprint,
            ])?;
        }

        self.enforce_learning_retention()?;
        debug!("Recorded learning event ({})", row.kind);
        Ok(())
    }

    /// Enforce the COUNT-guard cap + TTL prune. Deterministic and testable:
    /// the cap prune fires whenever the row count exceeds
    /// [`MAX_LEARNING_EVENTS`]; the TTL prune always runs (a no-op when nothing
    /// is stale). Both are single atomic statements, WAL-safe.
    fn enforce_learning_retention(&self) -> crate::Result<()> {
        let count: i64 =
            self.conn
                .query_row("SELECT COUNT(*) FROM learning_events", [], |row| row.get(0))?;

        if count > MAX_LEARNING_EVENTS as i64 {
            // Keep the newest MAX_LEARNING_EVENTS rows (highest id), evict the rest.
            self.conn.execute(
                "DELETE FROM learning_events
                 WHERE id NOT IN (
                     SELECT id FROM learning_events ORDER BY id DESC LIMIT ?1
                 )",
                params![MAX_LEARNING_EVENTS as i64],
            )?;
        }

        // TTL prune: drop rows older than the retention window.
        self.conn.execute(
            "DELETE FROM learning_events
             WHERE ts < datetime('now', ?1)",
            params![format!("-{LEARNING_TTL_DAYS} days")],
        )?;

        Ok(())
    }

    /// List learning events (most recent first) matching `filter`.
    pub fn list_learning_events(
        &self,
        filter: &LearningFilter,
    ) -> crate::Result<Vec<LearningEvent>> {
        let mut sql = String::from(
            "SELECT ts, session_id, tool, host, decision, layer, kind,
                    matched_rule, reason, command, effective_config,
                    diverged, divergence_reason, latency_ms, policy_fingerprint
             FROM learning_events",
        );

        let mut clauses: Vec<String> = Vec::new();
        let mut binds: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();

        if let Some(decision) = &filter.decision {
            clauses.push(format!("decision = ?{}", binds.len() + 1));
            binds.push(Box::new(decision.clone()));
        }
        if let Some(diverged) = filter.diverged {
            clauses.push(format!("diverged = ?{}", binds.len() + 1));
            binds.push(Box::new(i64::from(diverged)));
        }
        if !clauses.is_empty() {
            sql.push_str(" WHERE ");
            sql.push_str(&clauses.join(" AND "));
        }
        sql.push_str(" ORDER BY id DESC");
        if let Some(limit) = filter.limit {
            use std::fmt::Write as _;
            let _ = write!(sql, " LIMIT {limit}");
        }

        let mut stmt = self.conn.prepare(&sql)?;
        let bind_refs: Vec<&dyn rusqlite::ToSql> = binds.iter().map(AsRef::as_ref).collect();
        let rows = stmt.query_map(bind_refs.as_slice(), |row| {
            Ok(LearningEvent {
                ts: row.get(0)?,
                session_id: row.get(1)?,
                tool: row.get(2)?,
                host: row.get(3)?,
                decision: row.get(4)?,
                layer: row.get(5)?,
                kind: row
                    .get::<_, String>(6)?
                    .parse::<LearningKind>()
                    .unwrap_or(LearningKind::Decision),
                matched_rule: row.get(7)?,
                reason: row.get(8)?,
                command: row.get(9)?,
                effective_config: row.get(10)?,
                diverged: row.get::<_, i64>(11)? != 0,
                divergence_reason: row.get(12)?,
                latency_ms: row.get(13)?,
                policy_fingerprint: row.get(14)?,
            })
        })?;

        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// Total number of learning events stored.
    pub fn count_learning_events(&self) -> crate::Result<usize> {
        let count: i64 =
            self.conn
                .query_row("SELECT COUNT(*) FROM learning_events", [], |row| row.get(0))?;
        Ok(usize::try_from(count).unwrap_or(0))
    }

    /// Delete all learning events; returns the number of rows removed.
    pub fn clear_learning_events(&self) -> crate::Result<usize> {
        let removed = self.conn.execute("DELETE FROM learning_events", [])?;
        Ok(removed)
    }

    /// Aggregate diverged-`ask` commands for the given policy fingerprint into
    /// `(command, count)` pairs, most frequent first.
    ///
    /// Backs the deterministic CLI suggestion heuristic (R8): only diverged
    /// asks under the CURRENT effective policy are candidates. Rows with a NULL
    /// command are skipped. Commands are returned redacted (they were redacted
    /// at write time).
    pub fn learning_pattern_aggregates(
        &self,
        fingerprint: &str,
    ) -> crate::Result<Vec<(String, i64)>> {
        let mut stmt = self.conn.prepare(
            "SELECT command, COUNT(*) AS n
             FROM learning_events
             WHERE diverged = 1
               AND decision = 'ask'
               AND command IS NOT NULL
               AND policy_fingerprint = ?1
             GROUP BY command
             ORDER BY n DESC, command ASC",
        )?;
        let rows = stmt.query_map(params![fingerprint], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }
}
