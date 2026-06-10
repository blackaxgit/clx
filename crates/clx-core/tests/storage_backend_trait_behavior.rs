//! Behavior test for the `StorageBackend` trait surface consumed by
//! clx-hook / clx-mcp / the CLI through `&dyn StorageBackend`.
//!
//! The blanket impl on `Storage` forwards every trait method to the
//! identically-named inherent method. That wiring is a real external
//! contract: a rename, a signature drift, or a default-impl stub would
//! compile fine inside clx-core (inherent methods win name resolution)
//! and only break the downstream crates that hold `dyn StorageBackend`.
//! This test drives the FULL trait surface through a trait object so a
//! forwarding regression fails here, in the owning crate.
//!
//! Deliberately a single lifecycle (setup -> mutate -> read back) per
//! resource rather than one test per method: the contract under test is
//! "the trait object reaches the same database the inherent API writes".

use clx_core::storage::{Storage, StorageBackend};
use clx_core::types::{
    AuditDecision, AuditLogEntry, Event, EventType, LearnedRule, RuleType, Session, SessionId,
    SessionStatus, Snapshot, SnapshotTrigger,
};

fn mem() -> Storage {
    Storage::open_in_memory().expect("in-memory storage")
}

/// Session lifecycle through the trait object: create -> increment ->
/// update -> end, each step read back through the same trait object.
#[test]
fn dyn_backend_session_lifecycle_round_trips() {
    let storage = mem();
    let backend: &dyn StorageBackend = &storage;

    let session = Session::new(SessionId::new("dyn-sess"), "/proj".to_string());
    backend.create_session(&session).unwrap();

    backend.increment_message_count("dyn-sess").unwrap();
    backend.increment_message_count("dyn-sess").unwrap();
    backend.increment_command_count("dyn-sess").unwrap();

    let mut loaded = backend
        .get_session("dyn-sess")
        .unwrap()
        .expect("created session is visible through the trait");
    assert_eq!(loaded.message_count, 2, "increments must persist");
    assert_eq!(loaded.command_count, 1);

    loaded.input_tokens = 123;
    backend.update_session(&loaded).unwrap();
    let updated = backend.get_session("dyn-sess").unwrap().unwrap();
    assert_eq!(updated.input_tokens, 123, "update must persist");

    backend.end_session("dyn-sess").unwrap();
    let ended = backend.get_session("dyn-sess").unwrap().unwrap();
    assert_eq!(ended.status, SessionStatus::Ended);
    assert!(ended.ended_at.is_some(), "end must stamp ended_at");
}

/// Snapshot create/list/latest/FTS through the trait object — the exact
/// surface MCP recall uses when handed an `impl StorageBackend`.
#[test]
fn dyn_backend_snapshot_create_and_search_round_trips() {
    let storage = mem();
    let backend: &dyn StorageBackend = &storage;

    backend
        .create_session(&Session::new(SessionId::new("dyn-snap"), "/p".into()))
        .unwrap();

    let mut older = Snapshot::new(SessionId::new("dyn-snap"), SnapshotTrigger::Manual);
    older.summary = Some("postgres connection pooling decision".to_string());
    let older_id = backend.create_snapshot(&older).unwrap();
    assert!(older_id > 0);

    let mut newer = Snapshot::new(SessionId::new("dyn-snap"), SnapshotTrigger::Auto);
    newer.summary = Some("switched cache to redis".to_string());
    newer.created_at = older.created_at + chrono::Duration::seconds(1);
    backend.create_snapshot(&newer).unwrap();

    let all = backend.get_snapshots_by_session("dyn-snap").unwrap();
    assert_eq!(all.len(), 2);

    let latest = backend
        .get_latest_snapshot("dyn-snap")
        .unwrap()
        .expect("latest snapshot exists");
    assert_eq!(
        latest.summary.as_deref(),
        Some("switched cache to redis"),
        "latest must be the newer snapshot"
    );

    let found = backend.search_snapshots_fts("postgres pooling", 10).unwrap();
    assert_eq!(found.len(), 1, "FTS through the trait must hit: {found:?}");
    assert_eq!(
        found[0].0.summary.as_deref(),
        Some("postgres connection pooling decision")
    );
    assert!(
        found[0].1 > 0.0 && found[0].1 <= 1.0,
        "BM25 score must be normalised to (0, 1], got {}",
        found[0].1
    );
}

/// Event + audit log through the trait object (the hook's `PostToolUse` /
/// audit write path when generic over `StorageBackend`).
#[test]
fn dyn_backend_event_and_audit_round_trip() {
    let storage = mem();
    let backend: &dyn StorageBackend = &storage;

    backend
        .create_session(&Session::new(SessionId::new("dyn-ev"), "/p".into()))
        .unwrap();

    let mut event = Event::new(SessionId::new("dyn-ev"), EventType::ToolUse);
    event.tool_name = Some("Bash".to_string());
    let event_id = backend.append_event(&event).unwrap();
    assert!(event_id > 0);

    let entry = AuditLogEntry::new(
        SessionId::new("dyn-ev"),
        "git status".to_string(),
        "layer0".to_string(),
        AuditDecision::Allowed,
    );
    let audit_id = backend.create_audit_log(&entry).unwrap();
    assert!(audit_id > 0);

    let recent = backend.get_recent_audit_log(10).unwrap();
    assert_eq!(recent.len(), 1);
    assert_eq!(recent[0].command, "git status");
    assert_eq!(recent[0].decision, AuditDecision::Allowed);
}

/// Learned-rule add/list/delete through the trait object (the CLI's
/// whitelist management path).
#[test]
fn dyn_backend_rule_add_list_delete_round_trips() {
    let storage = mem();
    let backend: &dyn StorageBackend = &storage;

    let rule = LearnedRule::new(
        "Bash(git status*)".to_string(),
        RuleType::Allow,
        "user_decision".to_string(),
    );
    let id = backend.add_rule(&rule).unwrap();
    assert!(id > 0);

    let rules = backend.get_rules().unwrap();
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].pattern, "Bash(git status*)");
    assert_eq!(rules[0].rule_type, RuleType::Allow);

    backend.delete_rule("Bash(git status*)").unwrap();
    assert!(
        backend.get_rules().unwrap().is_empty(),
        "deleted rule must not be returned"
    );
}
