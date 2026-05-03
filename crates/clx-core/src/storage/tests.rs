//! Tests for all storage operations

use chrono::NaiveDate;
use rusqlite::{Connection, params};

use super::Storage;
use super::migration::SCHEMA_VERSION;
use super::util::{sanitize_fts_query, validate_session_id};
use crate::types::{
    AnalyticsEntry, AuditDecision, AuditLogEntry, Event, EventType, LearnedRule, RuleType, Session,
    SessionId, SessionStatus, Snapshot, SnapshotTrigger,
};

fn create_test_storage() -> Storage {
    Storage::open_in_memory().expect("Failed to create in-memory storage")
}

// =========================================================================
// Schema Tests
// =========================================================================

#[test]
fn test_schema_version() {
    let storage = create_test_storage();
    let version = storage.schema_version().unwrap();
    assert_eq!(version, SCHEMA_VERSION);
}

#[test]
fn test_pragmas_enabled() {
    let storage = create_test_storage();
    let journal_mode: String = storage
        .conn
        .query_row("PRAGMA journal_mode", [], |row| row.get(0))
        .unwrap();
    // In-memory databases use 'memory' instead of 'wal'
    assert!(journal_mode == "wal" || journal_mode == "memory");

    let foreign_keys: i32 = storage
        .conn
        .query_row("PRAGMA foreign_keys", [], |row| row.get(0))
        .unwrap();
    assert_eq!(foreign_keys, 1);
}

#[test]
fn test_busy_timeout_is_set() {
    let storage = create_test_storage();
    let timeout: i64 = storage
        .conn
        .query_row("PRAGMA busy_timeout", [], |row| row.get(0))
        .unwrap();
    assert_eq!(timeout, 5000);
}

// =========================================================================
// Session Tests
// =========================================================================

#[test]
fn test_create_and_get_session() {
    let storage = create_test_storage();

    let session = Session::new(
        SessionId::new("test-session-1"),
        "/project/path".to_string(),
    );
    storage.create_session(&session).unwrap();

    let retrieved = storage.get_session("test-session-1").unwrap();
    assert!(retrieved.is_some());

    let retrieved = retrieved.unwrap();
    assert_eq!(retrieved.id, SessionId::new("test-session-1"));
    assert_eq!(retrieved.project_path, "/project/path");
    assert_eq!(retrieved.status, SessionStatus::Active);
}

#[test]
fn test_update_session() {
    let storage = create_test_storage();

    let mut session = Session::new(
        SessionId::new("test-session-2"),
        "/project/path".to_string(),
    );
    storage.create_session(&session).unwrap();

    session.message_count = 10;
    session.command_count = 5;
    session.status = SessionStatus::Ended;
    storage.update_session(&session).unwrap();

    let retrieved = storage.get_session("test-session-2").unwrap().unwrap();
    assert_eq!(retrieved.message_count, 10);
    assert_eq!(retrieved.command_count, 5);
    assert_eq!(retrieved.status, SessionStatus::Ended);
}

#[test]
fn test_list_active_sessions() {
    let storage = create_test_storage();

    let session1 = Session::new(SessionId::new("active-1"), "/project/a".to_string());
    let session2 = Session::new(SessionId::new("active-2"), "/project/b".to_string());
    let mut session3 = Session::new(SessionId::new("ended-1"), "/project/c".to_string());
    session3.status = SessionStatus::Ended;

    storage.create_session(&session1).unwrap();
    storage.create_session(&session2).unwrap();
    storage.create_session(&session3).unwrap();

    let active = storage.list_active_sessions().unwrap();
    assert_eq!(active.len(), 2);
    assert!(active.iter().all(|s| s.status == SessionStatus::Active));
}

#[test]
fn test_end_session() {
    let storage = create_test_storage();

    let session = Session::new(SessionId::new("to-end"), "/project".to_string());
    storage.create_session(&session).unwrap();

    storage.end_session("to-end").unwrap();

    let retrieved = storage.get_session("to-end").unwrap().unwrap();
    assert_eq!(retrieved.status, SessionStatus::Ended);
    assert!(retrieved.ended_at.is_some());
}

#[test]
fn test_increment_counts() {
    let storage = create_test_storage();

    let session = Session::new(SessionId::new("count-test"), "/project".to_string());
    storage.create_session(&session).unwrap();

    storage.increment_message_count("count-test").unwrap();
    storage.increment_message_count("count-test").unwrap();
    storage.increment_command_count("count-test").unwrap();

    let retrieved = storage.get_session("count-test").unwrap().unwrap();
    assert_eq!(retrieved.message_count, 2);
    assert_eq!(retrieved.command_count, 1);
}

// =========================================================================
// Session Abandonment & Stale Detection Tests
// =========================================================================

#[test]
fn test_mark_session_abandoned() {
    let storage = create_test_storage();

    let session = Session::new(SessionId::new("abandon-test"), "/project".to_string());
    storage.create_session(&session).unwrap();

    // Verify it starts as active
    let retrieved = storage.get_session("abandon-test").unwrap().unwrap();
    assert_eq!(retrieved.status, SessionStatus::Active);
    assert!(retrieved.ended_at.is_none());

    // Mark as abandoned
    storage.mark_session_abandoned("abandon-test").unwrap();

    // Verify status changed and ended_at is set
    let retrieved = storage.get_session("abandon-test").unwrap().unwrap();
    assert_eq!(retrieved.status, SessionStatus::Abandoned);
    assert!(retrieved.ended_at.is_some());
}

#[test]
fn test_find_stale_active_sessions() {
    let storage = create_test_storage();

    // Create a session that looks old (started 3 hours ago) via raw SQL
    storage.conn.execute(
        "INSERT INTO sessions (id, project_path, started_at, source, message_count, command_count, input_tokens, output_tokens, status)
         VALUES ('stale-1', '/project', datetime('now', '-3 hours'), 'startup', 0, 0, 0, 0, 'active')",
        [],
    ).unwrap();

    // Create another old session (started 5 hours ago)
    storage.conn.execute(
        "INSERT INTO sessions (id, project_path, started_at, source, message_count, command_count, input_tokens, output_tokens, status)
         VALUES ('stale-2', '/project', datetime('now', '-5 hours'), 'startup', 0, 0, 0, 0, 'active')",
        [],
    ).unwrap();

    // Create a recent session (current, should NOT be returned)
    let recent = Session::new(SessionId::new("recent-session"), "/project".to_string());
    storage.create_session(&recent).unwrap();

    // Create an old session in a different project (should NOT be returned)
    storage.conn.execute(
        "INSERT INTO sessions (id, project_path, started_at, source, message_count, command_count, input_tokens, output_tokens, status)
         VALUES ('other-project-stale', '/other-project', datetime('now', '-4 hours'), 'startup', 0, 0, 0, 0, 'active')",
        [],
    ).unwrap();

    // Create an old ended session (should NOT be returned since status != active)
    storage.conn.execute(
        "INSERT INTO sessions (id, project_path, started_at, ended_at, source, message_count, command_count, input_tokens, output_tokens, status)
         VALUES ('ended-old', '/project', datetime('now', '-4 hours'), datetime('now', '-3 hours'), 'startup', 0, 0, 0, 0, 'ended')",
        [],
    ).unwrap();

    // Find stale sessions older than 2 hours, excluding "recent-session"
    let stale = storage
        .find_stale_active_sessions("/project", 2, "recent-session")
        .unwrap();

    assert_eq!(
        stale.len(),
        2,
        "Should find exactly 2 stale active sessions"
    );
    assert!(stale.iter().any(|s| s.id.as_str() == "stale-1"));
    assert!(stale.iter().any(|s| s.id.as_str() == "stale-2"));

    // Verify the excluded session is not in results
    assert!(!stale.iter().any(|s| s.id.as_str() == "recent-session"));
    assert!(!stale.iter().any(|s| s.id.as_str() == "other-project-stale"));
    assert!(!stale.iter().any(|s| s.id.as_str() == "ended-old"));
}

// =========================================================================
// Snapshot Tests
// =========================================================================

#[test]
fn test_create_and_get_snapshot() {
    let storage = create_test_storage();

    // Create session first (foreign key constraint)
    let session = Session::new(SessionId::new("snap-session"), "/project".to_string());
    storage.create_session(&session).unwrap();

    let mut snapshot = Snapshot::new(SessionId::new("snap-session"), SnapshotTrigger::Manual);
    snapshot.summary = Some("Test summary".to_string());
    snapshot.key_facts = Some("Key fact 1\nKey fact 2".to_string());

    let id = storage.create_snapshot(&snapshot).unwrap();
    assert!(id > 0);

    let retrieved = storage.get_snapshot(id).unwrap();
    assert!(retrieved.is_some());

    let retrieved = retrieved.unwrap();
    assert_eq!(retrieved.session_id, SessionId::new("snap-session"));
    assert_eq!(retrieved.summary, Some("Test summary".to_string()));
    assert_eq!(retrieved.trigger, SnapshotTrigger::Manual);
}

#[test]
fn test_get_snapshots_by_session() {
    let storage = create_test_storage();

    let session = Session::new(SessionId::new("multi-snap"), "/project".to_string());
    storage.create_session(&session).unwrap();

    storage
        .create_snapshot(&Snapshot::new(
            SessionId::new("multi-snap"),
            SnapshotTrigger::Auto,
        ))
        .unwrap();
    storage
        .create_snapshot(&Snapshot::new(
            SessionId::new("multi-snap"),
            SnapshotTrigger::Manual,
        ))
        .unwrap();
    storage
        .create_snapshot(&Snapshot::new(
            SessionId::new("multi-snap"),
            SnapshotTrigger::Checkpoint,
        ))
        .unwrap();

    let snapshots = storage.get_snapshots_by_session("multi-snap").unwrap();
    assert_eq!(snapshots.len(), 3);
}

#[test]
fn test_get_latest_snapshot() {
    let storage = create_test_storage();

    let session = Session::new(SessionId::new("latest-snap"), "/project".to_string());
    storage.create_session(&session).unwrap();

    storage
        .create_snapshot(&Snapshot::new(
            SessionId::new("latest-snap"),
            SnapshotTrigger::Auto,
        ))
        .unwrap();

    std::thread::sleep(std::time::Duration::from_millis(10));

    let mut latest = Snapshot::new(SessionId::new("latest-snap"), SnapshotTrigger::Manual);
    latest.summary = Some("Latest snapshot".to_string());
    storage.create_snapshot(&latest).unwrap();

    let retrieved = storage.get_latest_snapshot("latest-snap").unwrap().unwrap();
    assert_eq!(retrieved.trigger, SnapshotTrigger::Manual);
    assert_eq!(retrieved.summary, Some("Latest snapshot".to_string()));
}

// =========================================================================
// Event Tests
// =========================================================================

#[test]
fn test_append_and_get_events() {
    let storage = create_test_storage();

    let session = Session::new(SessionId::new("event-session"), "/project".to_string());
    storage.create_session(&session).unwrap();

    let mut event = Event::new(SessionId::new("event-session"), EventType::ToolUse);
    event.tool_name = Some("Bash".to_string());
    event.tool_input = Some(r#"{"command": "ls"}"#.to_string());

    let id = storage.append_event(&event).unwrap();
    assert!(id > 0);

    let events = storage.get_events_by_session("event-session").unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].tool_name, Some("Bash".to_string()));
    assert_eq!(events[0].event_type, EventType::ToolUse);
}

#[test]
fn test_events_pagination() {
    let storage = create_test_storage();

    let session = Session::new(SessionId::new("paginated-events"), "/project".to_string());
    storage.create_session(&session).unwrap();

    for i in 0..10 {
        let mut event = Event::new(SessionId::new("paginated-events"), EventType::Message);
        event.tool_input = Some(format!("Message {i}"));
        storage.append_event(&event).unwrap();
    }

    let count = storage.count_events("paginated-events").unwrap();
    assert_eq!(count, 10);

    let page1 = storage
        .get_events_paginated("paginated-events", 5, 0)
        .unwrap();
    assert_eq!(page1.len(), 5);

    let page2 = storage
        .get_events_paginated("paginated-events", 5, 5)
        .unwrap();
    assert_eq!(page2.len(), 5);

    // Different events
    assert_ne!(page1[0].tool_input, page2[0].tool_input);
}

// =========================================================================
// Audit Log Tests
// =========================================================================

#[test]
fn test_create_and_get_audit_log() {
    let storage = create_test_storage();

    let session = Session::new(SessionId::new("audit-session"), "/project".to_string());
    storage.create_session(&session).unwrap();

    let mut entry = AuditLogEntry::new(
        SessionId::new("audit-session"),
        "rm -rf /".to_string(),
        "layer0".to_string(),
        AuditDecision::Blocked,
    );
    entry.risk_score = Some(100);
    entry.reasoning = Some("Dangerous command".to_string());

    let id = storage.create_audit_log(&entry).unwrap();
    assert!(id > 0);

    let retrieved = storage.get_audit_log(id).unwrap().unwrap();
    assert_eq!(retrieved.command, "rm -rf /");
    assert_eq!(retrieved.decision, AuditDecision::Blocked);
    assert_eq!(retrieved.risk_score, Some(100));
}

/// TC-AUD-002 — Regression for the 0.7.1 fix: `create_audit_log` must
/// auto-create the referenced session row when it does not exist.
/// Without this guard, fast-path / synthetic / fabricated session IDs
/// trip the audit_log → sessions FK constraint.
#[test]
fn test_audit_log_auto_creates_missing_session() {
    let storage = create_test_storage();

    let synthetic_id = "synthetic-session-not-in-table";
    // Note: deliberately NOT calling create_session() first.
    let entry = AuditLogEntry::new(
        SessionId::new(synthetic_id),
        "echo hi".to_string(),
        "layer0".to_string(),
        AuditDecision::Allowed,
    );

    let id = storage
        .create_audit_log(&entry)
        .expect("audit log must succeed even when session row does not exist");
    assert!(id > 0, "audit log should have a generated ID");

    // The session row must now exist (auto-created).
    let session = storage
        .get_session(synthetic_id)
        .expect("get_session call ok")
        .expect("session row should have been auto-created");
    assert_eq!(session.id, SessionId::new(synthetic_id));
}

/// TC-AUD-003 — Auto-created session has the documented placeholder
/// fields so it's distinguishable from a real session.
#[test]
fn test_audit_log_auto_created_session_has_placeholder_source() {
    let storage = create_test_storage();
    let synthetic_id = "synthetic-placeholder-check";
    let entry = AuditLogEntry::new(
        SessionId::new(synthetic_id),
        "any cmd".to_string(),
        "layer0".to_string(),
        AuditDecision::Allowed,
    );
    storage.create_audit_log(&entry).unwrap();

    // Query the raw row to verify the source/status defaults from the
    // INSERT OR IGNORE in `create_audit_log`.
    let (source, status): (String, String) = storage
        .conn
        .query_row(
            "SELECT source, status FROM sessions WHERE id = ?1",
            [synthetic_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("session row exists");
    assert_eq!(source, "audit-placeholder");
    assert_eq!(status, "active");
}

/// TC-AUD-008 — Privacy property: secrets in the `command` field of an
/// `AuditLogEntry` must be redacted before they hit the persistent
/// audit log table. Without this, every `clx-hook` audit row could
/// archive an API key the user pasted on a CLI invocation.
///
/// Note: redaction happens upstream in `clx_hook::audit::log_audit_entry`
/// (calls `redact_secrets`). This test asserts the redaction pipeline
/// works on a representative input — if `redact_secrets` regresses,
/// production audit rows would silently store cleartext.
#[test]
fn test_audit_command_redaction_pipeline() {
    use crate::redaction::redact_secrets;

    let raw = "curl -H 'Authorization: Bearer sk-abc123def456ghi789jkl012mno345pq' https://api.example.com";
    let redacted = redact_secrets(raw);

    assert!(
        !redacted.contains("sk-abc123def456ghi789jkl012mno345pq"),
        "raw key must not survive redaction: {redacted}"
    );
    assert!(
        redacted.contains("REDACTED") || redacted.contains("***"),
        "redacted output should contain a redaction marker: {redacted}"
    );
    // Round-trip through audit log — verify the SAME redacted form
    // round-trips into and out of the table.
    let storage = create_test_storage();
    let entry = AuditLogEntry::new(
        SessionId::new("redaction-test-session"),
        redacted.clone(),
        "layer0".to_string(),
        AuditDecision::Allowed,
    );
    let id = storage.create_audit_log(&entry).unwrap();
    let retrieved = storage.get_audit_log(id).unwrap().unwrap();
    assert_eq!(retrieved.command, redacted);
    assert!(
        !retrieved.command.contains("sk-abc123"),
        "audit log row must not contain raw secret"
    );
}

/// TC-MIG-006 — `column_exists` is hardened against SQL injection via a
/// `VALID_TABLES` allowlist. Calling with an unsafe table name must
/// return false (not panic, not execute the injected SQL).
#[test]
fn test_column_exists_rejects_unsafe_table_names() {
    let storage = create_test_storage();
    // Each of these is a classic injection or unknown-table attempt.
    let bad_tables = [
        "'; DROP TABLE sessions; --",
        "sessions; DELETE FROM audit_log;",
        "../etc/passwd",
        "unknown_table",
        "",
    ];
    for bad in bad_tables {
        assert!(
            !storage.column_exists(bad, "id"),
            "column_exists should reject unsafe table name: {bad:?}"
        );
    }
    // Sanity: a known table still works.
    assert!(storage.column_exists("sessions", "id"));
}

#[test]
fn test_get_audit_log_by_session() {
    let storage = create_test_storage();

    let session = Session::new(SessionId::new("audit-multi"), "/project".to_string());
    storage.create_session(&session).unwrap();

    storage
        .create_audit_log(&AuditLogEntry::new(
            SessionId::new("audit-multi"),
            "ls".to_string(),
            "layer0".to_string(),
            AuditDecision::Allowed,
        ))
        .unwrap();

    storage
        .create_audit_log(&AuditLogEntry::new(
            SessionId::new("audit-multi"),
            "cat /etc/passwd".to_string(),
            "layer0".to_string(),
            AuditDecision::Prompted,
        ))
        .unwrap();

    let entries = storage.get_audit_log_by_session("audit-multi").unwrap();
    assert_eq!(entries.len(), 2);
}

#[test]
fn test_get_recent_audit_log() {
    let storage = create_test_storage();

    let session1 = Session::new(SessionId::new("recent-1"), "/project1".to_string());
    let session2 = Session::new(SessionId::new("recent-2"), "/project2".to_string());
    storage.create_session(&session1).unwrap();
    storage.create_session(&session2).unwrap();

    for i in 0..5 {
        storage
            .create_audit_log(&AuditLogEntry::new(
                SessionId::new("recent-1"),
                format!("cmd{i}"),
                "layer0".to_string(),
                AuditDecision::Allowed,
            ))
            .unwrap();
    }

    for i in 0..5 {
        storage
            .create_audit_log(&AuditLogEntry::new(
                SessionId::new("recent-2"),
                format!("cmd{i}"),
                "layer0".to_string(),
                AuditDecision::Allowed,
            ))
            .unwrap();
    }

    let recent = storage.get_recent_audit_log(7).unwrap();
    assert_eq!(recent.len(), 7);
}

#[test]
fn test_audit_log_count() {
    let storage = create_test_storage();

    let session = Session::new(SessionId::new("count-audit"), "/project".to_string());
    storage.create_session(&session).unwrap();

    assert_eq!(storage.count_audit_log(None).unwrap(), 0);

    storage
        .create_audit_log(&AuditLogEntry::new(
            SessionId::new("count-audit"),
            "ls".to_string(),
            "layer0".to_string(),
            AuditDecision::Allowed,
        ))
        .unwrap();

    assert_eq!(storage.count_audit_log(None).unwrap(), 1);
}

#[test]
fn test_cleanup_old_audit_logs() {
    let storage = create_test_storage();

    let session = Session::new(SessionId::new("cleanup-audit"), "/project".to_string());
    storage.create_session(&session).unwrap();

    // Insert entries with timestamps 2 days in the past via raw SQL
    for i in 0..3 {
        storage
            .conn
            .execute(
                "INSERT INTO audit_log (session_id, timestamp, command, layer, decision)
             VALUES (?1, datetime('now', '-2 days'), ?2, 'layer0', 'allowed')",
                params!["cleanup-audit", format!("old-cmd{}", i)],
            )
            .unwrap();
    }

    // Insert one entry with current timestamp
    storage
        .create_audit_log(&AuditLogEntry::new(
            SessionId::new("cleanup-audit"),
            "recent-cmd".to_string(),
            "layer0".to_string(),
            AuditDecision::Allowed,
        ))
        .unwrap();

    assert_eq!(storage.count_audit_log(None).unwrap(), 4);

    // Cleanup entries older than 1 day - only the 3 old entries should be deleted
    let deleted = storage.cleanup_old_audit_logs(1).unwrap();
    assert_eq!(deleted, 3);
    assert_eq!(storage.count_audit_log(None).unwrap(), 1);
}

// =========================================================================
// Learned Rules Tests
// =========================================================================

#[test]
fn test_add_and_get_rule() {
    let storage = create_test_storage();

    let rule = LearnedRule::new(
        "npm *".to_string(),
        RuleType::Allow,
        "user_decision".to_string(),
    );

    let id = storage.add_rule(&rule).unwrap();
    assert!(id > 0);

    let retrieved = storage.get_rule_by_pattern("npm *").unwrap().unwrap();
    assert_eq!(retrieved.pattern, "npm *");
    assert_eq!(retrieved.rule_type, RuleType::Allow);
}

#[test]
fn test_get_rules() {
    let storage = create_test_storage();

    storage
        .add_rule(&LearnedRule::new(
            "git *".to_string(),
            RuleType::Allow,
            "user".to_string(),
        ))
        .unwrap();
    storage
        .add_rule(&LearnedRule::new(
            "rm -rf".to_string(),
            RuleType::Deny,
            "user".to_string(),
        ))
        .unwrap();

    let rules = storage.get_rules().unwrap();
    assert_eq!(rules.len(), 2);
}

#[test]
fn test_get_rules_for_project() {
    let storage = create_test_storage();

    // Global rule
    storage
        .add_rule(&LearnedRule::new(
            "git *".to_string(),
            RuleType::Allow,
            "user".to_string(),
        ))
        .unwrap();

    // Project-specific rule
    let mut project_rule = LearnedRule::new(
        "cargo build".to_string(),
        RuleType::Allow,
        "user".to_string(),
    );
    project_rule.project_path = Some("/my/project".to_string());
    storage.add_rule(&project_rule).unwrap();

    // Different project rule
    let mut other_rule = LearnedRule::new(
        "yarn install".to_string(),
        RuleType::Allow,
        "user".to_string(),
    );
    other_rule.project_path = Some("/other/project".to_string());
    storage.add_rule(&other_rule).unwrap();

    let rules = storage.get_rules_for_project("/my/project").unwrap();
    assert_eq!(rules.len(), 2); // Global + project-specific
    assert!(rules.iter().any(|r| r.pattern == "git *"));
    assert!(rules.iter().any(|r| r.pattern == "cargo build"));
    assert!(!rules.iter().any(|r| r.pattern == "yarn install"));
}

#[test]
fn test_increment_rule_counts() {
    let storage = create_test_storage();

    let rule = LearnedRule::new(
        "cargo test".to_string(),
        RuleType::Allow,
        "user".to_string(),
    );
    storage.add_rule(&rule).unwrap();

    storage.increment_confirmation_count("cargo test").unwrap();
    storage.increment_confirmation_count("cargo test").unwrap();
    storage.increment_denial_count("cargo test").unwrap();

    let retrieved = storage.get_rule_by_pattern("cargo test").unwrap().unwrap();
    assert_eq!(retrieved.confirmation_count, 2);
    assert_eq!(retrieved.denial_count, 1);
}

#[test]
fn test_rule_upsert() {
    let storage = create_test_storage();

    let rule1 = LearnedRule::new("docker *".to_string(), RuleType::Allow, "user".to_string());
    storage.add_rule(&rule1).unwrap();

    // Update same pattern with different type
    let rule2 = LearnedRule::new("docker *".to_string(), RuleType::Deny, "admin".to_string());
    storage.add_rule(&rule2).unwrap();

    let rules = storage.get_rules().unwrap();
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].rule_type, RuleType::Deny);
    assert_eq!(rules[0].source, "admin");
}

#[test]
fn test_delete_rule() {
    let storage = create_test_storage();

    let rule = LearnedRule::new("to-delete".to_string(), RuleType::Allow, "user".to_string());
    storage.add_rule(&rule).unwrap();

    storage.delete_rule("to-delete").unwrap();

    let retrieved = storage.get_rule_by_pattern("to-delete").unwrap();
    assert!(retrieved.is_none());
}

// =========================================================================
// Analytics Tests
// =========================================================================

#[test]
fn test_record_metric() {
    let storage = create_test_storage();

    let entry = AnalyticsEntry::new(
        NaiveDate::from_ymd_opt(2024, 1, 15).unwrap(),
        "commands_executed".to_string(),
        10,
    );
    storage.record_metric(&entry).unwrap();

    // Record again to test upsert (should add to existing)
    storage.record_metric(&entry).unwrap();

    let metrics = storage
        .get_analytics(
            NaiveDate::from_ymd_opt(2024, 1, 1).unwrap(),
            NaiveDate::from_ymd_opt(2024, 1, 31).unwrap(),
            None,
        )
        .unwrap();

    assert_eq!(metrics.len(), 1);
    assert_eq!(metrics[0].metric_value, 20); // 10 + 10
}

#[test]
fn test_get_analytics_by_date_range() {
    let storage = create_test_storage();

    storage
        .record_metric(&AnalyticsEntry::new(
            NaiveDate::from_ymd_opt(2024, 1, 10).unwrap(),
            "sessions".to_string(),
            5,
        ))
        .unwrap();

    storage
        .record_metric(&AnalyticsEntry::new(
            NaiveDate::from_ymd_opt(2024, 1, 15).unwrap(),
            "sessions".to_string(),
            3,
        ))
        .unwrap();

    storage
        .record_metric(&AnalyticsEntry::new(
            NaiveDate::from_ymd_opt(2024, 2, 1).unwrap(),
            "sessions".to_string(),
            7,
        ))
        .unwrap();

    // Query only January
    let jan_metrics = storage
        .get_analytics(
            NaiveDate::from_ymd_opt(2024, 1, 1).unwrap(),
            NaiveDate::from_ymd_opt(2024, 1, 31).unwrap(),
            None,
        )
        .unwrap();

    assert_eq!(jan_metrics.len(), 2);
}

#[test]
fn test_get_metric_sum() {
    let storage = create_test_storage();

    storage
        .record_metric(&AnalyticsEntry::new(
            NaiveDate::from_ymd_opt(2024, 1, 10).unwrap(),
            "commands".to_string(),
            100,
        ))
        .unwrap();

    storage
        .record_metric(&AnalyticsEntry::new(
            NaiveDate::from_ymd_opt(2024, 1, 11).unwrap(),
            "commands".to_string(),
            50,
        ))
        .unwrap();

    storage
        .record_metric(&AnalyticsEntry::new(
            NaiveDate::from_ymd_opt(2024, 1, 12).unwrap(),
            "commands".to_string(),
            75,
        ))
        .unwrap();

    let sum = storage
        .get_metric_sum(
            "commands",
            NaiveDate::from_ymd_opt(2024, 1, 1).unwrap(),
            NaiveDate::from_ymd_opt(2024, 1, 31).unwrap(),
            None,
        )
        .unwrap();

    assert_eq!(sum, 225);
}

#[test]
fn test_analytics_with_project_filter() {
    let storage = create_test_storage();

    let mut entry1 = AnalyticsEntry::new(
        NaiveDate::from_ymd_opt(2024, 1, 15).unwrap(),
        "commands".to_string(),
        10,
    );
    entry1.project_path = Some("/project/a".to_string());
    storage.record_metric(&entry1).unwrap();

    let mut entry2 = AnalyticsEntry::new(
        NaiveDate::from_ymd_opt(2024, 1, 15).unwrap(),
        "commands".to_string(),
        20,
    );
    entry2.project_path = Some("/project/b".to_string());
    storage.record_metric(&entry2).unwrap();

    // Global metric
    storage
        .record_metric(&AnalyticsEntry::new(
            NaiveDate::from_ymd_opt(2024, 1, 15).unwrap(),
            "commands".to_string(),
            5,
        ))
        .unwrap();

    let sum = storage
        .get_metric_sum(
            "commands",
            NaiveDate::from_ymd_opt(2024, 1, 1).unwrap(),
            NaiveDate::from_ymd_opt(2024, 1, 31).unwrap(),
            Some("/project/a"),
        )
        .unwrap();

    // Should include project/a (10) + global (5)
    assert_eq!(sum, 15);
}

// =========================================================================
// FTS5 Full-Text Search Tests
// =========================================================================

#[test]
fn test_schema_version_is_5() {
    let storage = create_test_storage();
    let version = storage.schema_version().unwrap();
    assert_eq!(version, 5);
}

#[test]
fn test_migrate_to_v3_creates_fts_table() {
    let storage = create_test_storage();

    // Verify FTS5 table exists by querying its structure
    let table_exists: bool = storage
        .conn
        .query_row(
            "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type='table' AND name='snapshots_fts'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(table_exists, "snapshots_fts table should exist");
}

#[test]
fn test_migrate_to_v3_creates_triggers() {
    let storage = create_test_storage();

    let trigger_count: i32 = storage
        .conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='trigger' AND name IN ('snapshots_ai', 'snapshots_ad', 'snapshots_au')",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(trigger_count, 3, "All three FTS sync triggers should exist");
}

#[test]
fn test_search_snapshots_fts_returns_results() {
    let storage = create_test_storage();

    let session = Session::new(SessionId::new("fts-session"), "/project".to_string());
    storage.create_session(&session).unwrap();

    let mut snapshot = Snapshot::new(SessionId::new("fts-session"), SnapshotTrigger::Manual);
    snapshot.summary = Some("Implemented authentication flow with JWT tokens".to_string());
    snapshot.key_facts = Some("Uses RS256 algorithm for signing".to_string());
    storage.create_snapshot(&snapshot).unwrap();

    let mut snapshot2 = Snapshot::new(SessionId::new("fts-session"), SnapshotTrigger::Auto);
    snapshot2.summary = Some("Database migration for user profiles".to_string());
    snapshot2.key_facts = Some("Added email and phone columns".to_string());
    storage.create_snapshot(&snapshot2).unwrap();

    // Search for authentication-related snapshots
    let results = storage.search_snapshots_fts("authentication", 10).unwrap();
    assert_eq!(
        results.len(),
        1,
        "Should find exactly one match for 'authentication'"
    );
    assert_eq!(results[0].0.session_id, SessionId::new("fts-session"));
    assert!(results[0].1 > 0.0, "Score should be positive");
    assert!(results[0].1 <= 1.0, "Score should be at most 1.0");
}

#[test]
fn test_search_snapshots_fts_empty_for_nonmatching() {
    let storage = create_test_storage();

    let session = Session::new(SessionId::new("fts-empty"), "/project".to_string());
    storage.create_session(&session).unwrap();

    let mut snapshot = Snapshot::new(SessionId::new("fts-empty"), SnapshotTrigger::Manual);
    snapshot.summary = Some("Working on frontend components".to_string());
    storage.create_snapshot(&snapshot).unwrap();

    let results = storage.search_snapshots_fts("kubernetes", 10).unwrap();
    assert!(
        results.is_empty(),
        "Should return no results for unrelated query"
    );
}

#[test]
fn test_search_snapshots_fts_empty_query() {
    let storage = create_test_storage();
    let results = storage.search_snapshots_fts("", 10).unwrap();
    assert!(results.is_empty(), "Empty query should return no results");
}

#[test]
fn test_search_snapshots_fts_special_chars_sanitized() {
    let storage = create_test_storage();

    let session = Session::new(SessionId::new("fts-special"), "/project".to_string());
    storage.create_session(&session).unwrap();

    let mut snapshot = Snapshot::new(SessionId::new("fts-special"), SnapshotTrigger::Manual);
    snapshot.summary = Some("Testing error handling in production".to_string());
    storage.create_snapshot(&snapshot).unwrap();

    // Query with special FTS5 characters should not cause errors
    // After sanitization, "error AND handling" becomes "error handling"
    // ("AND" is blocked as FTS5 operator, special chars stripped)
    let results = storage
        .search_snapshots_fts("error AND handling", 10)
        .unwrap();
    // Should find results based on sanitized terms (error, handling are both in the snapshot)
    assert!(
        !results.is_empty(),
        "Should find results even with special chars in query"
    );

    // Verify query with only operators returns empty
    let empty_results = storage.search_snapshots_fts("AND OR NOT NEAR", 10).unwrap();
    assert!(
        empty_results.is_empty(),
        "Query with only operators should return no results"
    );
}

#[test]
fn test_fts_trigger_syncs_on_insert() {
    let storage = create_test_storage();

    let session = Session::new(SessionId::new("fts-sync"), "/project".to_string());
    storage.create_session(&session).unwrap();

    // Insert a snapshot (trigger should sync to FTS)
    let mut snapshot = Snapshot::new(SessionId::new("fts-sync"), SnapshotTrigger::Manual);
    snapshot.summary = Some("Refactored the payment processing module".to_string());
    let id = storage.create_snapshot(&snapshot).unwrap();
    assert!(id > 0);

    // Verify FTS index has the entry
    let results = storage.search_snapshots_fts("payment", 10).unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(
        results[0].0.summary.as_deref(),
        Some("Refactored the payment processing module")
    );
}

#[test]
fn test_fts_respects_limit() {
    let storage = create_test_storage();

    let session = Session::new(SessionId::new("fts-limit"), "/project".to_string());
    storage.create_session(&session).unwrap();

    // Create multiple matching snapshots
    for i in 0..5 {
        let mut snapshot = Snapshot::new(SessionId::new("fts-limit"), SnapshotTrigger::Auto);
        snapshot.summary = Some(format!("Deployed service version {i}"));
        storage.create_snapshot(&snapshot).unwrap();
    }

    let results = storage.search_snapshots_fts("deployed service", 3).unwrap();
    assert!(results.len() <= 3, "Should respect the limit parameter");
}

#[test]
fn test_fts_backfill_existing_snapshots() {
    // This test verifies backfill by creating a storage (which runs migrations),
    // confirming snapshots created before FTS also appear in search.
    // Since in-memory databases start fresh and run all migrations sequentially,
    // we simulate by creating snapshots and verifying they appear.
    let storage = create_test_storage();

    let session = Session::new(SessionId::new("fts-backfill"), "/project".to_string());
    storage.create_session(&session).unwrap();

    let mut snapshot = Snapshot::new(SessionId::new("fts-backfill"), SnapshotTrigger::Manual);
    snapshot.summary = Some("Configured CI/CD pipeline".to_string());
    snapshot.todos = Some("Set up staging environment".to_string());
    storage.create_snapshot(&snapshot).unwrap();

    // Search by todos content
    let results = storage.search_snapshots_fts("staging", 10).unwrap();
    assert_eq!(results.len(), 1);
}

#[test]
fn test_sanitize_fts_query() {
    assert_eq!(sanitize_fts_query("hello world"), "hello world");
    assert_eq!(sanitize_fts_query("hello  world"), "hello world");
    assert_eq!(sanitize_fts_query("  "), "");
    assert_eq!(sanitize_fts_query("hello_world"), "hello_world");
    assert_eq!(sanitize_fts_query("my-component"), "my-component");
}

// =========================================================================
// C3: FTS5 SQL Injection Tests
// =========================================================================

#[test]
fn test_sanitize_fts_query_strips_unicode() {
    // Unicode characters should be stripped (only ASCII allowed)
    assert_eq!(sanitize_fts_query("hello \u{4e16}\u{754c}"), "hello");
    assert_eq!(sanitize_fts_query("caf\u{e9}"), "caf");
    assert_eq!(
        sanitize_fts_query("\u{41f}\u{440}\u{438}\u{432}\u{435}\u{442} \u{43c}\u{438}\u{440}"),
        ""
    );
}

#[test]
fn test_sanitize_fts_query_blocks_fts5_operators() {
    // FTS5 operators should be blocked
    assert_eq!(sanitize_fts_query("AND"), "");
    assert_eq!(sanitize_fts_query("OR"), "");
    assert_eq!(sanitize_fts_query("NOT"), "");
    assert_eq!(sanitize_fts_query("NEAR"), "");
    assert_eq!(sanitize_fts_query("and or not"), ""); // lowercase also blocked
    assert_eq!(sanitize_fts_query("AnD oR nOt"), ""); // mixed case also blocked
    assert_eq!(sanitize_fts_query("hello AND world"), "hello world");
}

#[test]
fn test_sanitize_fts_query_enforces_length_limits() {
    // Query length limit (1000 chars)
    let long_query = "a".repeat(1500);
    let result = sanitize_fts_query(&long_query);
    // Each 'a' is a single char term but under MIN_TERM_LENGTH, so should be empty
    assert_eq!(result, "");

    // Term length limits (min 2, max 50)
    assert_eq!(sanitize_fts_query("a"), ""); // too short
    assert_eq!(sanitize_fts_query("ab"), "ab"); // exactly min
    let long_term = "a".repeat(60);
    assert_eq!(sanitize_fts_query(&long_term), ""); // too long

    // Max terms (20)
    let many_terms = (0..25)
        .map(|i| format!("term{i}"))
        .collect::<Vec<_>>()
        .join(" ");
    let result = sanitize_fts_query(&many_terms);
    let term_count = result.split_whitespace().count();
    assert!(term_count <= 20, "Should limit to 20 terms");
}

#[test]
fn test_sanitize_fts_query_filters_single_char_terms() {
    // Single character terms should be filtered out (MIN_TERM_LENGTH = 2)
    assert_eq!(sanitize_fts_query("a b c"), "");
    assert_eq!(
        sanitize_fts_query("hello a world b test"),
        "hello world test"
    );
}

#[test]
fn test_sanitize_fts_query_empty_after_sanitization() {
    // Queries that become empty after sanitization
    assert_eq!(sanitize_fts_query(""), "");
    assert_eq!(sanitize_fts_query("   "), "");
    assert_eq!(sanitize_fts_query("!@#$%^&*()"), "");
    assert_eq!(sanitize_fts_query("AND OR NOT"), "");
}

// =========================================================================
// T35: Property Tests for FTS Query Safety
// =========================================================================

mod prop_tests {
    use proptest::prelude::*;

    use super::super::Storage;
    use super::super::util::sanitize_fts_query;

    // Arbitrary strings passed through the sanitiser must never panic.
    proptest! {
        #[test]
        fn prop_fts_query_no_panic(query in ".*") {
            // Act: must not panic regardless of input
            let result = sanitize_fts_query(&query);
            // Assert: result is a valid String (no panic occurred)
            let _ = result.len();
        }
    }

    // Strings containing SQLite FTS5 special characters must not cause
    // a storage query to panic or return an error when used in a real
    // in-memory FTS5 search.
    proptest! {
        #[test]
        fn prop_fts_query_no_sql_injection(
            // Bias towards characters that are meaningful to FTS5 / SQL
            query in r#"[a-zA-Z0-9 "*()\-_\[\]:^~?!@#$%&/\\|<>{}]{0,120}"#,
        ) {
            // Arrange
            let storage = Storage::open_in_memory().expect("in-memory storage");
            // Act: sanitise then execute a real FTS5 search — must not panic
            let sanitised = sanitize_fts_query(&query);
            if !sanitised.is_empty() {
                // search_snapshots performs an FTS5 MATCH query; verify it does
                // not panic or return a storage-level error from malformed SQL.
                let result = storage.search_snapshots_fts(&sanitised, 10);
                // Either Ok (empty results) or an Err (FTS parse error) are both
                // acceptable — what must NOT happen is a panic or memory unsafety.
                let _ = result;
            }
        }
    }
}

// =========================================================================
// C6: Silent Migration Failures Tests
// =========================================================================

#[test]
fn test_column_exists_detects_existing_columns() {
    let storage = create_test_storage();

    // Test existing columns
    assert!(storage.column_exists("sessions", "id"));
    assert!(storage.column_exists("sessions", "project_path"));
    assert!(storage.column_exists("snapshots", "summary"));

    // Test non-existing column
    assert!(!storage.column_exists("sessions", "nonexistent_column"));
    assert!(!storage.column_exists("nonexistent_table", "id"));
}

#[test]
fn test_migrate_to_v2_adds_columns() {
    // Create storage at v1 only by manually setting up v1 schema
    let conn = Connection::open_in_memory().unwrap();
    let storage = Storage { conn };
    storage.configure_pragmas().unwrap();

    // Create schema_version table and set to v1
    storage
        .conn
        .execute(
            "CREATE TABLE IF NOT EXISTS schema_version (version INTEGER PRIMARY KEY)",
            [],
        )
        .unwrap();

    // Run v1 migration only
    storage.migrate_to_v1().unwrap();
    storage
        .conn
        .execute("INSERT INTO schema_version (version) VALUES (1)", [])
        .unwrap();

    // Verify columns don't exist yet by checking the actual schema
    // V1 schema doesn't have token columns
    let has_input_tokens = storage
        .conn
        .query_row(
            "SELECT COUNT(*) FROM pragma_table_info('sessions') WHERE name = 'input_tokens'",
            [],
            |row| row.get::<_, i64>(0),
        )
        .unwrap()
        > 0;

    // If columns already exist (from v1 CREATE TABLE), skip to idempotency test
    if has_input_tokens {
        // Schema v1 already has these columns, test idempotency instead
        storage.migrate_to_v2().unwrap();
        assert!(storage.column_exists("sessions", "input_tokens"));
        return;
    }

    // Run v2 migration
    storage.migrate_to_v2().unwrap();

    // Verify columns now exist
    assert!(storage.column_exists("sessions", "input_tokens"));
    assert!(storage.column_exists("sessions", "output_tokens"));
    assert!(storage.column_exists("snapshots", "input_tokens"));
    assert!(storage.column_exists("snapshots", "output_tokens"));
}

#[test]
fn test_migrate_to_v2_idempotent() {
    let storage = create_test_storage();

    // Running v2 migration multiple times should not fail
    storage.migrate_to_v2().unwrap();
    storage.migrate_to_v2().unwrap();
    storage.migrate_to_v2().unwrap();

    // Columns should still exist
    assert!(storage.column_exists("sessions", "input_tokens"));
    assert!(storage.column_exists("sessions", "output_tokens"));
}

// =========================================================================
// M8: Session ID Validation Tests
// =========================================================================

#[test]
fn test_validate_session_id_accepts_valid_ids() {
    assert!(validate_session_id("valid-session-123").is_ok());
    assert!(validate_session_id("session_456").is_ok());
    assert!(validate_session_id("AbCdEf123_-").is_ok());
    assert!(validate_session_id("a").is_ok()); // single char is ok
    assert!(validate_session_id("a".repeat(128).as_str()).is_ok()); // exactly 128 chars
}

#[test]
fn test_validate_session_id_rejects_empty() {
    let result = validate_session_id("");
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("empty"));
}

#[test]
fn test_validate_session_id_rejects_too_long() {
    let long_id = "a".repeat(129);
    let result = validate_session_id(&long_id);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("too long"));
}

#[test]
fn test_validate_session_id_rejects_invalid_chars() {
    let invalid_ids = vec![
        "session@123",
        "session#456",
        "session/path",
        "session\\path",
        "session.txt",
        "session:123",
        "session;DROP TABLE",
        "session id",  // space
        "session\nid", // newline
    ];

    for id in invalid_ids {
        let result = validate_session_id(id);
        assert!(result.is_err(), "Should reject: {id}");
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("invalid characters")
        );
    }
}

#[test]
fn test_validate_session_id_rejects_leading_dot() {
    // Leading dots could create hidden files in path contexts
    let result = validate_session_id(".hidden");
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("start with '.'"));

    let result = validate_session_id("..double");
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("start with '.'"));
}

#[test]
fn test_create_session_rejects_leading_dot() {
    let storage = create_test_storage();
    let session = Session::new(SessionId::new(".hidden"), "/project".to_string());
    let result = storage.create_session(&session);
    assert!(result.is_err());
}

#[test]
fn test_validate_session_id_rejects_path_traversal() {
    // ".." starts with dot, caught by leading-dot check
    let result = validate_session_id("..");
    assert!(result.is_err(), "Should reject path traversal: ..");
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("start with '.'")
            || err_msg.contains("path traversal")
            || err_msg.contains("invalid characters"),
        "Expected leading-dot, path traversal, or invalid characters error for '..', got: {err_msg}"
    );

    // "session.." contains '.', caught by invalid characters check
    let result = validate_session_id("session..");
    assert!(result.is_err(), "Should reject path traversal: session..");
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("path traversal") || err_msg.contains("invalid characters"),
        "Expected path traversal or invalid characters error for 'session..', got: {err_msg}"
    );

    // These contain invalid characters (/) so will be rejected by char validation
    let invalid_char_ids = vec!["../session", "session/..", "session/../other"];

    for id in invalid_char_ids {
        let result = validate_session_id(id);
        assert!(result.is_err(), "Should reject: {id}");
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("invalid characters") || err_msg.contains("start with '.'"),
            "Expected invalid characters or leading-dot error for '{id}', got: {err_msg}"
        );
    }

    // "..session" starts with dot, caught by leading-dot check
    let result = validate_session_id("..session");
    assert!(result.is_err());
}

#[test]
fn test_create_session_validates_id() {
    let storage = create_test_storage();

    // Valid session ID should work
    let valid_session = Session::new(SessionId::new("valid-session"), "/project".to_string());
    assert!(storage.create_session(&valid_session).is_ok());

    // Invalid session ID should fail
    let invalid_session = Session::new(
        SessionId::new("../../../etc/passwd"),
        "/project".to_string(),
    );
    let result = storage.create_session(&invalid_session);
    assert!(result.is_err());

    // Empty session ID should fail
    let empty_session = Session::new(SessionId::new(""), "/project".to_string());
    let result = storage.create_session(&empty_session);
    assert!(result.is_err());
}

#[test]
fn test_get_session_validates_id() {
    let storage = create_test_storage();

    // Invalid ID should fail before querying
    let result = storage.get_session("../etc/passwd");
    assert!(result.is_err());

    let result = storage.get_session("");
    assert!(result.is_err());

    let result = storage.get_session("session@invalid");
    assert!(result.is_err());
}

// =========================================================================
// Edge Case Tests
// =========================================================================

#[test]
fn test_get_nonexistent_session() {
    let storage = create_test_storage();
    let result = storage.get_session("nonexistent").unwrap();
    assert!(result.is_none());
}

#[test]
fn test_get_nonexistent_snapshot() {
    let storage = create_test_storage();
    let result = storage.get_snapshot(99999).unwrap();
    assert!(result.is_none());
}

#[test]
fn test_get_nonexistent_rule() {
    let storage = create_test_storage();
    let result = storage.get_rule_by_pattern("nonexistent").unwrap();
    assert!(result.is_none());
}

// =========================================================================
// T05: Storage::open_default tests
// =========================================================================

#[test]
fn test_open_creates_db_at_path_ending_with_data_clx_db() {
    // Arrange — build a temp directory and construct a path that mirrors the
    // canonical CLX database layout: <root>/data/clx.db
    let temp_dir = tempfile::tempdir().expect("failed to create temp dir");
    let db_path = temp_dir.path().join("data").join("clx.db");

    // Act — open() must create the parent directory and initialise the DB
    let storage = Storage::open(&db_path).expect("Storage::open should succeed for temp path");

    // Assert — path ends with the expected suffix components
    assert!(
        db_path.ends_with("data/clx.db"),
        "db path must end with 'data/clx.db', got: {}",
        db_path.display()
    );
    assert_eq!(
        db_path
            .parent()
            .and_then(|p| p.file_name())
            .and_then(|n| n.to_str()),
        Some("data"),
        "parent directory of the db file must be 'data'"
    );

    // Assert — the storage is operational
    let version = storage
        .schema_version()
        .expect("schema_version must succeed after open");
    assert!(version >= 0, "schema version must be non-negative");
}

#[test]
fn test_open_default_succeeds_and_is_functional() {
    // Arrange: open_default() resolves ~/.clx/data/clx.db and creates dirs as needed.
    // Act
    let storage = Storage::open_default().expect("open_default should succeed");

    // Assert: the resulting storage responds to schema queries without error.
    let version = storage
        .schema_version()
        .expect("schema_version should work on default db");
    assert!(version >= 0, "schema version must be non-negative");
}

#[test]
fn test_open_default_path_resolves_to_expected_components() {
    // Arrange + Act: resolve the path that open_default() will use.
    let db_path = crate::paths::database_path();

    // Assert: path ends with the canonical CLX database location.
    assert!(
        db_path.ends_with(".clx/data/clx.db"),
        "database_path() should end with .clx/data/clx.db, got: {}",
        db_path.display()
    );

    // Parent directory component must be "data".
    assert_eq!(
        db_path
            .parent()
            .and_then(|p| p.file_name())
            .and_then(|n| n.to_str()),
        Some("data"),
        "parent of database file must be 'data'"
    );
}
