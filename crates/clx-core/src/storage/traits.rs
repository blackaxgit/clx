//! Trait abstraction for storage operations.
//!
//! `StorageBackend` covers the ~16 methods used by external crates (clx-hook,
//! clx-mcp, clx CLI). The concrete implementation is [`super::Storage`] (`SQLite`).
//!
//! This trait enables:
//! - Mock implementations for unit testing without a real database
//! - Future alternative backends (e.g., `PostgreSQL`, in-memory stores)

use crate::types::{AuditLogEntry, Event, LearnedRule, Session, Snapshot};

/// Trait for storage operations used by CLX binaries.
///
/// The concrete implementation is `Storage` (`SQLite`). All methods mirror the
/// inherent methods on `Storage` and delegate directly to them in the default
/// implementation.
pub trait StorageBackend {
    // ── Session operations ───────────────────────────────────────────

    /// Create a new session.
    fn create_session(&self, session: &Session) -> crate::Result<()>;

    /// Get a session by ID.
    fn get_session(&self, id: &str) -> crate::Result<Option<Session>>;

    /// Update an existing session.
    fn update_session(&self, session: &Session) -> crate::Result<()>;

    /// End a session (set status to ended, record end time).
    fn end_session(&self, id: &str) -> crate::Result<()>;

    /// Increment the message count for a session.
    fn increment_message_count(&self, session_id: &str) -> crate::Result<()>;

    /// Increment the command count for a session.
    fn increment_command_count(&self, session_id: &str) -> crate::Result<()>;

    // ── Snapshot operations ──────────────────────────────────────────

    /// Create a new snapshot, returning its ID.
    fn create_snapshot(&self, snapshot: &Snapshot) -> crate::Result<i64>;

    /// Get all snapshots for a session, ordered by creation time (newest first).
    fn get_snapshots_by_session(&self, session_id: &str) -> crate::Result<Vec<Snapshot>>;

    /// Get the most recent snapshot for a session.
    fn get_latest_snapshot(&self, session_id: &str) -> crate::Result<Option<Snapshot>>;

    /// Search snapshots using FTS5 full-text search with BM25 ranking.
    ///
    /// Returns matching snapshots paired with their relevance score (0.0-1.0).
    fn search_snapshots_fts(
        &self,
        query: &str,
        limit: usize,
    ) -> crate::Result<Vec<(Snapshot, f64)>>;

    // ── Event operations ─────────────────────────────────────────────

    /// Append an event to the session, returning its ID.
    fn append_event(&self, event: &Event) -> crate::Result<i64>;

    // ── Audit operations ─────────────────────────────────────────────

    /// Create an audit log entry, returning its ID.
    fn create_audit_log(&self, entry: &AuditLogEntry) -> crate::Result<i64>;

    /// Get recent audit log entries across all sessions.
    fn get_recent_audit_log(&self, limit: i64) -> crate::Result<Vec<AuditLogEntry>>;

    // ── Learned rules ────────────────────────────────────────────────

    /// Get all learned rules.
    fn get_rules(&self) -> crate::Result<Vec<LearnedRule>>;

    /// Add or update a learned rule, returning its ID.
    fn add_rule(&self, rule: &LearnedRule) -> crate::Result<i64>;

    /// Delete a learned rule by pattern.
    fn delete_rule(&self, pattern: &str) -> crate::Result<()>;
}

// ── Blanket implementation for Storage ───────────────────────────────────
//
// Each method delegates to the identically-named inherent method on Storage.
// Rust resolves inherent methods over trait methods by default, so existing
// code calling `storage.create_session()` on a `Storage` value continues to
// use the inherent method. The trait is used only when code takes
// `&dyn StorageBackend` or `impl StorageBackend`.

impl StorageBackend for super::Storage {
    fn create_session(&self, session: &Session) -> crate::Result<()> {
        self.create_session(session)
    }

    fn get_session(&self, id: &str) -> crate::Result<Option<Session>> {
        self.get_session(id)
    }

    fn update_session(&self, session: &Session) -> crate::Result<()> {
        self.update_session(session)
    }

    fn end_session(&self, id: &str) -> crate::Result<()> {
        self.end_session(id)
    }

    fn increment_message_count(&self, session_id: &str) -> crate::Result<()> {
        self.increment_message_count(session_id)
    }

    fn increment_command_count(&self, session_id: &str) -> crate::Result<()> {
        self.increment_command_count(session_id)
    }

    fn create_snapshot(&self, snapshot: &Snapshot) -> crate::Result<i64> {
        self.create_snapshot(snapshot)
    }

    fn get_snapshots_by_session(&self, session_id: &str) -> crate::Result<Vec<Snapshot>> {
        self.get_snapshots_by_session(session_id)
    }

    fn get_latest_snapshot(&self, session_id: &str) -> crate::Result<Option<Snapshot>> {
        self.get_latest_snapshot(session_id)
    }

    fn search_snapshots_fts(
        &self,
        query: &str,
        limit: usize,
    ) -> crate::Result<Vec<(Snapshot, f64)>> {
        self.search_snapshots_fts(query, limit)
    }

    fn append_event(&self, event: &Event) -> crate::Result<i64> {
        self.append_event(event)
    }

    fn create_audit_log(&self, entry: &AuditLogEntry) -> crate::Result<i64> {
        self.create_audit_log(entry)
    }

    fn get_recent_audit_log(&self, limit: i64) -> crate::Result<Vec<AuditLogEntry>> {
        self.get_recent_audit_log(limit)
    }

    fn get_rules(&self) -> crate::Result<Vec<LearnedRule>> {
        self.get_rules()
    }

    fn add_rule(&self, rule: &LearnedRule) -> crate::Result<i64> {
        self.add_rule(rule)
    }

    fn delete_rule(&self, pattern: &str) -> crate::Result<()> {
        self.delete_rule(pattern)
    }
}
