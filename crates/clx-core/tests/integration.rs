//! Integration tests for clx-core
//!
//! These tests exercise cross-module interactions between Storage, `PolicyEngine`,
//! and `EmbeddingStore` using in-memory databases (no filesystem side effects).

use clx_core::policy::{PolicyDecision, PolicyEngine};
use clx_core::storage::{Storage, StorageBackend};
use clx_core::types::{
    AuditDecision, AuditLogEntry, Event, EventType, LearnedRule, RuleType, Session, SessionId,
    SessionStatus, Snapshot, SnapshotTrigger,
};

// =========================================================================
// Helper
// =========================================================================

fn new_storage() -> Storage {
    Storage::open_in_memory().expect("Failed to create in-memory storage")
}

// =========================================================================
// 1. Storage + Policy integration
// =========================================================================

#[test]
fn test_storage_policy_integration() {
    let storage = new_storage();

    // Add learned rules via storage
    let allow_rule = LearnedRule::new(
        "cargo test *".to_string(),
        RuleType::Allow,
        "user_decision".to_string(),
    );
    let deny_rule = LearnedRule::new(
        "rm -rf /tmp/*".to_string(),
        RuleType::Deny,
        "user_decision".to_string(),
    );

    storage.add_rule(&allow_rule).unwrap();
    storage.add_rule(&deny_rule).unwrap();

    // Verify rules are stored
    let rules = storage.get_rules().unwrap();
    assert_eq!(rules.len(), 2);

    // Load rules into PolicyEngine
    let mut engine = PolicyEngine::new();
    engine.load_learned_rules(&storage).unwrap();

    // Evaluate: learned allow rule should match
    let decision = engine.evaluate("Bash", "cargo test --release");
    assert_eq!(decision, PolicyDecision::Allow);

    // Evaluate: learned deny rule should match
    let decision = engine.evaluate("Bash", "rm -rf /tmp/foo");
    match decision {
        PolicyDecision::Deny { .. } => {} // expected
        other => panic!("Expected Deny, got {other:?}"),
    }
}

// =========================================================================
// 2. Session lifecycle
// =========================================================================

#[test]
fn test_session_lifecycle() {
    let storage = new_storage();
    let sid = SessionId::new("lifecycle-test-001");

    // Step 1: Create session
    let session = Session::new(sid.clone(), "/home/user/project".to_string());
    storage.create_session(&session).unwrap();

    let retrieved = storage.get_session(sid.as_str()).unwrap().unwrap();
    assert_eq!(retrieved.status, SessionStatus::Active);
    assert_eq!(retrieved.message_count, 0);

    // Step 2: Add events
    let mut event = Event::new(sid.clone(), EventType::ToolUse);
    event.tool_name = Some("Bash".to_string());
    event.tool_input = Some(r#"{"command":"ls -la"}"#.to_string());
    let event_id = storage.append_event(&event).unwrap();
    assert!(event_id > 0);

    storage.increment_message_count(sid.as_str()).unwrap();
    storage.increment_command_count(sid.as_str()).unwrap();

    // Step 3: Create snapshot
    let mut snapshot = Snapshot::new(sid.clone(), SnapshotTrigger::Auto);
    snapshot.summary = Some("User is exploring the project directory structure".to_string());
    snapshot.key_facts = Some("Project uses Rust with Cargo workspace".to_string());
    snapshot.message_count = Some(1);
    let snap_id = storage.create_snapshot(&snapshot).unwrap();
    assert!(snap_id > 0);

    // Step 4: Search snapshots via FTS
    let results = storage
        .search_snapshots_fts("directory structure", 10)
        .unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].0.session_id, sid);
    assert!(results[0].1 > 0.0); // positive relevance score

    // Step 5: End session
    storage.end_session(sid.as_str()).unwrap();
    let ended = storage.get_session(sid.as_str()).unwrap().unwrap();
    assert_eq!(ended.status, SessionStatus::Ended);
    assert!(ended.ended_at.is_some());
    assert_eq!(ended.message_count, 1);
    assert_eq!(ended.command_count, 1);
}

// =========================================================================
// 3. Policy evaluation flow
// =========================================================================

#[test]
fn test_policy_evaluation_flow() {
    // Start with empty engine (no built-in rules)
    let mut engine = PolicyEngine::empty();

    // Initially everything is Ask
    let decision = engine.evaluate("Bash", "ls -la");
    match decision {
        PolicyDecision::Ask { .. } => {}
        other => panic!("Expected Ask, got {other:?}"),
    }

    // Add whitelist
    engine.add_whitelist("Bash(ls:*)");
    engine.add_whitelist("Bash(git:status*)");

    // Add blacklist
    engine.add_blacklist("Bash(rm:-rf /*)");

    // Whitelisted commands are allowed
    assert_eq!(engine.evaluate("Bash", "ls -la"), PolicyDecision::Allow);
    assert_eq!(
        engine.evaluate("Bash", "git status --short"),
        PolicyDecision::Allow
    );

    // Blacklisted commands are denied
    match engine.evaluate("Bash", "rm -rf /var") {
        PolicyDecision::Deny { .. } => {}
        other => panic!("Expected Deny for blacklisted command, got {other:?}"),
    }

    // Blacklist takes priority over whitelist
    engine.add_whitelist("Bash(rm:*)");
    match engine.evaluate("Bash", "rm -rf /var") {
        PolicyDecision::Deny { .. } => {} // blacklist still wins
        other => panic!("Expected Deny (blacklist priority), got {other:?}"),
    }

    // Unknown commands return Ask
    match engine.evaluate("Bash", "unknown-command --flag") {
        PolicyDecision::Ask { .. } => {}
        other => panic!("Expected Ask for unknown command, got {other:?}"),
    }

    // Non-Bash tools always return Ask (not evaluated by policy)
    match engine.evaluate("Read", "/etc/passwd") {
        PolicyDecision::Ask { .. } => {}
        other => panic!("Expected Ask for non-Bash tool, got {other:?}"),
    }
}

// =========================================================================
// 4. Storage snapshot FTS search with ranking
// =========================================================================

#[test]
fn test_storage_snapshot_fts_search_ranking() {
    let storage = new_storage();
    let sid = SessionId::new("fts-rank-session");
    storage
        .create_session(&Session::new(sid.clone(), "/project".to_string()))
        .unwrap();

    // Create snapshots with varying content
    let mut snap1 = Snapshot::new(sid.clone(), SnapshotTrigger::Auto);
    snap1.summary = Some("Implemented user authentication with JWT tokens".to_string());
    snap1.key_facts = Some("JWT uses RS256 for token signing".to_string());
    storage.create_snapshot(&snap1).unwrap();

    let mut snap2 = Snapshot::new(sid.clone(), SnapshotTrigger::Auto);
    snap2.summary = Some("Set up database migrations for user profiles".to_string());
    snap2.key_facts = Some("Added email column to users table".to_string());
    storage.create_snapshot(&snap2).unwrap();

    let mut snap3 = Snapshot::new(sid.clone(), SnapshotTrigger::Checkpoint);
    snap3.summary = Some("Deployed authentication service to staging".to_string());
    snap3.key_facts = Some("Authentication endpoint is /api/auth/login".to_string());
    storage.create_snapshot(&snap3).unwrap();

    // Search for "authentication" - should match snap1 and snap3
    let results = storage.search_snapshots_fts("authentication", 10).unwrap();
    assert_eq!(results.len(), 2);
    // Both results should have positive scores
    for (snapshot, score) in &results {
        assert!(
            *score > 0.0,
            "Score should be positive for matching snapshot"
        );
        assert!(
            snapshot
                .summary
                .as_ref()
                .unwrap()
                .contains("authentication")
                || snapshot
                    .key_facts
                    .as_ref()
                    .unwrap_or(&String::new())
                    .contains("authentication")
                || snapshot
                    .key_facts
                    .as_ref()
                    .unwrap_or(&String::new())
                    .contains("Authentication"),
        );
    }

    // Search for "database" - should match only snap2
    let results = storage.search_snapshots_fts("database", 10).unwrap();
    assert_eq!(results.len(), 1);
    assert!(results[0].0.summary.as_ref().unwrap().contains("database"));

    // Non-matching query - empty results
    let results = storage.search_snapshots_fts("kubernetes", 10).unwrap();
    assert!(results.is_empty());
}

// =========================================================================
// 5. Embedding store creation
// =========================================================================

#[test]
fn test_embedding_store_creation_from_storage() {
    // Verify in-memory embedding store can be created via Storage helper
    let store = Storage::create_embedding_store_in_memory().unwrap();

    // Store initializes, dimension is correct
    assert_eq!(
        store.embedding_dim(),
        clx_core::embeddings::DEFAULT_EMBEDDING_DIM
    );

    // Graceful degradation when sqlite-vec not loaded
    if !store.is_vector_search_enabled() {
        let query = vec![0.0f32; store.embedding_dim()];
        let results = store.find_similar(&query, 10).unwrap();
        assert!(results.is_empty());
        assert_eq!(store.count_embeddings().unwrap(), 0);
    }
}

// =========================================================================
// 6. Learned rules round-trip: storage -> policy -> decision
// =========================================================================

#[test]
fn test_learned_rules_to_policy_roundtrip() {
    let storage = new_storage();

    // Add several learned rules
    storage
        .add_rule(&LearnedRule::new(
            "docker compose up".to_string(),
            RuleType::Allow,
            "user_decision".to_string(),
        ))
        .unwrap();

    storage
        .add_rule(&LearnedRule::new(
            "docker run --privileged*".to_string(),
            RuleType::Deny,
            "user_decision".to_string(),
        ))
        .unwrap();

    // Verify storage returns the rules
    let stored_rules = storage.get_rules().unwrap();
    assert_eq!(stored_rules.len(), 2);

    // Load into a fresh policy engine (empty - no built-ins)
    let mut engine = PolicyEngine::empty();
    engine.load_learned_rules(&storage).unwrap();

    // The learned allow rule should be matched
    let decision = engine.evaluate("Bash", "docker compose up");
    assert_eq!(decision, PolicyDecision::Allow);

    // The learned deny rule should be matched
    let decision = engine.evaluate("Bash", "docker run --privileged -it ubuntu");
    match decision {
        PolicyDecision::Deny { .. } => {}
        other => panic!("Expected Deny for privileged docker run, got {other:?}"),
    }

    // Unmatched command returns Ask
    match engine.evaluate("Bash", "python3 script.py") {
        PolicyDecision::Ask { .. } => {}
        other => panic!("Expected Ask for unmatched command, got {other:?}"),
    }
}

// =========================================================================
// 7. Audit log + session cross-module
// =========================================================================

#[test]
fn test_audit_log_session_integration() {
    let storage = new_storage();
    let sid = SessionId::new("audit-integration-test");

    // Create session
    storage
        .create_session(&Session::new(sid.clone(), "/project".to_string()))
        .unwrap();

    // Log several audit entries
    storage
        .create_audit_log(&AuditLogEntry::new(
            sid.clone(),
            "ls -la".to_string(),
            "L0".to_string(),
            AuditDecision::Allowed,
        ))
        .unwrap();

    let mut blocked_entry = AuditLogEntry::new(
        sid.clone(),
        "rm -rf /".to_string(),
        "L0".to_string(),
        AuditDecision::Blocked,
    );
    blocked_entry.risk_score = Some(100);
    blocked_entry.reasoning = Some("Recursive deletion from root".to_string());
    storage.create_audit_log(&blocked_entry).unwrap();

    storage
        .create_audit_log(&AuditLogEntry::new(
            sid.clone(),
            "curl https://example.com".to_string(),
            "L1".to_string(),
            AuditDecision::Prompted,
        ))
        .unwrap();

    // Verify via recent audit log (cross-session query)
    let recent = storage.get_recent_audit_log(10).unwrap();
    assert_eq!(recent.len(), 3);

    // Verify via session-specific query
    let session_audit = storage.get_audit_log_by_session(sid.as_str()).unwrap();
    assert_eq!(session_audit.len(), 3);

    // Verify the blocked entry preserved its metadata
    let blocked = session_audit
        .iter()
        .find(|e| e.decision == AuditDecision::Blocked)
        .unwrap();
    assert_eq!(blocked.command, "rm -rf /");
    assert_eq!(blocked.risk_score, Some(100));
    assert_eq!(
        blocked.reasoning.as_deref(),
        Some("Recursive deletion from root")
    );
}

// =========================================================================
// 8. StorageBackend trait usage
// =========================================================================

#[test]
fn test_storage_backend_trait_polymorphism() {
    let storage = new_storage();
    let sid = SessionId::new("trait-poly-test");

    // Use StorageBackend trait through a reference
    let backend: &dyn StorageBackend = &storage;

    // All trait methods work through the trait object
    let session = Session::new(sid.clone(), "/project".to_string());
    backend.create_session(&session).unwrap();

    let retrieved = backend.get_session(sid.as_str()).unwrap();
    assert!(retrieved.is_some());

    backend.increment_message_count(sid.as_str()).unwrap();
    backend.increment_command_count(sid.as_str()).unwrap();

    let snapshot = Snapshot::new(sid.clone(), SnapshotTrigger::Manual);
    let snap_id = backend.create_snapshot(&snapshot).unwrap();
    assert!(snap_id > 0);

    let snapshots = backend.get_snapshots_by_session(sid.as_str()).unwrap();
    assert_eq!(snapshots.len(), 1);

    let latest = backend.get_latest_snapshot(sid.as_str()).unwrap();
    assert!(latest.is_some());

    backend.end_session(sid.as_str()).unwrap();
    let ended = backend.get_session(sid.as_str()).unwrap().unwrap();
    assert_eq!(ended.status, SessionStatus::Ended);
}

// =========================================================================
// 9. Concurrent access with busy_timeout
// =========================================================================

#[test]
fn test_concurrent_storage_access() {
    use std::sync::{Arc, Barrier};
    use std::thread;

    let dir = tempfile::tempdir().expect("Failed to create temp dir");
    let db_path = dir.path().join("concurrent.db");

    // Initialize the database with one connection first
    {
        let storage = Storage::open(&db_path).expect("Failed to open storage");
        let sid = SessionId::new("setup-session");
        storage
            .create_session(&Session::new(sid, "/project".to_string()))
            .unwrap();
    }

    let path = Arc::new(db_path);
    let barrier = Arc::new(Barrier::new(2));

    let handles: Vec<_> = (0..2)
        .map(|i| {
            let path = Arc::clone(&path);
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                let storage = Storage::open(path.as_ref()).expect("Failed to open storage");
                // Synchronize threads to maximize contention
                barrier.wait();
                for j in 0..20 {
                    let sid = SessionId::new(format!("thread-{i}-session-{j}"));
                    let session = Session::new(sid.clone(), format!("/project/{i}/{j}"));
                    storage.create_session(&session).unwrap();

                    let mut event = Event::new(sid, EventType::ToolUse);
                    event.tool_name = Some(format!("tool-{i}-{j}"));
                    storage.append_event(&event).unwrap();
                }
            })
        })
        .collect();

    for h in handles {
        h.join().expect("Thread panicked");
    }

    // Verify all writes persisted
    let storage = Storage::open(path.as_ref()).expect("Failed to reopen storage");
    for i in 0..2 {
        for j in 0..20 {
            let sid = format!("thread-{i}-session-{j}");
            let session = storage.get_session(&sid).unwrap();
            assert!(session.is_some(), "Missing session {sid}");
        }
    }
    // Also verify the setup session
    assert!(storage.get_session("setup-session").unwrap().is_some());
}
