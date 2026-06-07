//! Behavior tests for memory storage, anchored to the pre-release spec
//! `specs/_prerelease/02-memory-recall.md` sections 3.6 (`tool_events`),
//! 3.7 (`auto_summarize` storage primitives), the migration chain, the
//! edge/failure matrix, and RISKS M-R1 / M-R3.
//!
//! Disjoint from the in-crate `#[cfg(test)]` modules: these are
//! integration-level tests that drive the public `Storage` API on a fresh
//! in-memory or on-disk database.

use clx_core::storage::Storage;
use clx_core::types::{SessionId, Snapshot, SnapshotTrigger, ToolEvent, ToolOutcome};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn mem() -> Storage {
    Storage::open_in_memory().expect("in-memory storage")
}

fn seed_session(s: &Storage, id: &str) {
    s.connection()
        .execute(
            "INSERT OR IGNORE INTO sessions (id, project_path, started_at, source, status) \
             VALUES (?1, '', datetime('now'), 'manual', 'active')",
            [id],
        )
        .expect("seed session");
}

fn ev(session: &str, tool: &str, target: Option<&str>, summary: &str, now: i64) -> ToolEvent {
    ToolEvent::new(
        SessionId::new(session),
        tool,
        target.map(str::to_string),
        summary,
        ToolOutcome::Success,
        now,
    )
}

// ===========================================================================
// 3.6 tool_events: 60s dedup window + occurrence_count
// ===========================================================================

/// Two events on the same `(session, tool, target)` inside the same 60s
/// bucket collapse to one row with `occurrence_count == 2` (spec 3.6 dedup).
#[test]
fn tool_events_60s_window_dedups_to_single_row() {
    let s = mem();
    // 1_200/60 == 1_230/60 == 20 -> same bucket.
    let id1 = s
        .append_or_extend_tool_event(&ev("sess-A", "Edit", Some("src/a.rs"), "v1", 1_200))
        .unwrap();
    let id2 = s
        .append_or_extend_tool_event(&ev("sess-A", "Edit", Some("src/a.rs"), "v2", 1_230))
        .unwrap();
    assert_eq!(id1, id2, "same bucket must hit the same row");
    let rows = s.recent_tool_events_for_session("sess-A", 10).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].occurrence_count, 2);
    assert_eq!(rows[0].summary, "v2", "summary replaced with newest");
}

/// Failure/edge: a second event in a different minute bucket inserts a new
/// row (spec 3.6: bucket = `window_end_unix` / 60).
#[test]
fn tool_events_distinct_window_creates_new_row() {
    let s = mem();
    // 1_000/60 == 16 ; 1_260/60 == 21 -> distinct buckets.
    let id1 = s
        .append_or_extend_tool_event(&ev("sess-A", "Edit", Some("src/a.rs"), "v1", 1_000))
        .unwrap();
    let id2 = s
        .append_or_extend_tool_event(&ev("sess-A", "Edit", Some("src/a.rs"), "v2", 1_260))
        .unwrap();
    assert_ne!(id1, id2);
    assert_eq!(s.count_tool_events("sess-A").unwrap(), 2);
}

/// v7 unique index makes cross-handle inserts atomic: two independent
/// `Storage` handles against one DB file in the same bucket collapse to a
/// single row with `occurrence_count == 2` (spec 3.6 v7 regression /
/// edge-matrix "`tool_events` under concurrent hooks").
#[test]
fn tool_events_v7_unique_index_collapses_two_independent_stores() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let db = tmp.path().join("clx.db");
    let s1 = Storage::open(&db).expect("open s1");
    let s2 = Storage::open(&db).expect("open s2");

    s1.append_or_extend_tool_event(&ev("sess-race", "Edit", Some("src/r.rs"), "A", 1_200))
        .unwrap();
    s2.append_or_extend_tool_event(&ev("sess-race", "Edit", Some("src/r.rs"), "B", 1_240))
        .unwrap();

    let rows = s1.recent_tool_events_for_session("sess-race", 10).unwrap();
    assert_eq!(
        rows.len(),
        1,
        "v7 UNIQUE INDEX must collapse two independent writers to one row"
    );
    assert_eq!(rows[0].occurrence_count, 2);
}

/// FK safety: appending a tool event for a session that has no `sessions`
/// row still succeeds (INSERT OR IGNORE placeholder, spec 3.6 FK safety).
#[test]
fn tool_events_fk_safe_without_existing_session() {
    let s = mem();
    let id = s
        .append_or_extend_tool_event(&ev("ghost-session", "Write", Some("x.rs"), "w", 1_000))
        .unwrap();
    assert!(id >= 1);
    let placeholder: i64 = s
        .connection()
        .query_row(
            "SELECT COUNT(*) FROM sessions WHERE id = ?1",
            ["ghost-session"],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(placeholder, 1, "FK placeholder session row must exist");
}

// ===========================================================================
// 3.6 retention trim: days==0 keeps all; cleanup_old_tool_events
// ===========================================================================

/// `cleanup_old_tool_events(0)` is a no-op: every row is retained (spec 3.6
/// retention "days==0 keep all").
#[test]
fn retention_trim_zero_days_keeps_everything() {
    let s = mem();
    s.append_or_extend_tool_event(&ev("sess-A", "Edit", Some("a.rs"), "x", 1_000))
        .unwrap();
    let deleted = s.cleanup_old_tool_events(0).unwrap();
    assert_eq!(deleted, 0);
    assert_eq!(s.count_tool_events("sess-A").unwrap(), 1);
}

/// Happy path: a row older than the retention window is trimmed; a fresh
/// row survives (spec 3.6 retention; default 30 via `clx maintenance trim`).
#[test]
fn retention_trim_deletes_only_stale_rows() {
    let s = mem();
    s.append_or_extend_tool_event(&ev("sess-A", "Edit", Some("fresh.rs"), "f", 1_000))
        .unwrap();
    s.append_or_extend_tool_event(&ev("sess-A", "Edit", Some("stale.rs"), "s", 1_000))
        .unwrap();
    s.connection()
        .execute(
            "UPDATE tool_events SET created_at = datetime('now', '-45 days') \
             WHERE target = 'stale.rs'",
            [],
        )
        .unwrap();
    let deleted = s.cleanup_old_tool_events(30).unwrap();
    assert_eq!(deleted, 1);
    let rows = s.recent_tool_events_for_session("sess-A", 10).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].target.as_deref(), Some("fresh.rs"));
}

// ===========================================================================
// 3.x snapshots: create + FTS5 search round-trip
// ===========================================================================

/// A created snapshot is discoverable via FTS5 search on its summary text
/// (spec 1.1 stage [1] / 3.x storage primitive backing recall).
#[test]
fn snapshot_create_then_fts_search_round_trip() {
    let s = mem();
    seed_session(&s, "sess-snap");
    let mut snap = Snapshot::new(SessionId::new("sess-snap"), SnapshotTrigger::Manual);
    snap.summary = Some("implemented azure tenant routing fallback".to_string());
    snap.key_facts = Some("azure, tenant, routing".to_string());
    let id = s.create_snapshot(&snap).unwrap();
    assert!(id >= 1);

    let results = s.search_snapshots_fts("azure", 10).unwrap();
    assert!(
        results.iter().any(|(snap, _score)| snap.id == Some(id)),
        "FTS5 must surface the created snapshot for a summary term"
    );
}

/// Failure path: FTS5 search for a non-matching term returns nothing and
/// does not error (spec edge/failure matrix "no match").
#[test]
fn snapshot_fts_search_no_match_is_empty() {
    let s = mem();
    seed_session(&s, "sess-snap");
    let mut snap = Snapshot::new(SessionId::new("sess-snap"), SnapshotTrigger::Manual);
    snap.summary = Some("graphql resolver patterns".to_string());
    s.create_snapshot(&snap).unwrap();
    let results = s.search_snapshots_fts("xyzzy_nonexistent_qqq", 10).unwrap();
    assert!(results.is_empty(), "non-matching FTS query must be empty");
}

// ===========================================================================
// 3.7 auto_summarize storage primitives: turns_since + idle gate
// ===========================================================================

/// `turns_since_last_auto_summary` counts ALL tool events when no prior
/// `auto_summary` snapshot exists (spec 3.7 `every_n_turns`).
#[test]
fn turns_since_counts_all_when_no_prior_summary() {
    let s = mem();
    seed_session(&s, "sess-A");
    for i in 0..4 {
        s.append_or_extend_tool_event(&ev(
            "sess-A",
            "Edit",
            Some(&format!("f{i}.rs")),
            "e",
            1_000 + i64::from(i),
        ))
        .unwrap();
    }
    assert_eq!(s.turns_since_last_auto_summary("sess-A").unwrap(), 4);
}

/// `had_mutator_activity_since_last_auto_summary` is false on a read-only
/// session and true once a mutator event lands (spec 3.7 `skip_when_idle`).
#[test]
fn idle_gate_reflects_mutator_activity() {
    let s = mem();
    seed_session(&s, "sess-A");
    assert!(
        !s.had_mutator_activity_since_last_auto_summary("sess-A")
            .unwrap(),
        "fresh session is idle"
    );
    s.append_or_extend_tool_event(&ev("sess-A", "Edit", Some("a.rs"), "e", 1_000))
        .unwrap();
    assert!(
        s.had_mutator_activity_since_last_auto_summary("sess-A")
            .unwrap(),
        "after a mutator event the session is no longer idle"
    );
}

/// TOCTOU-safe exactly-one-snapshot: two racing guarded inserts against one
/// DB produce exactly ONE `AutoSummary` row; the loser reports `Ok(false)`
/// (spec 3.7 + edge/failure matrix "Concurrent Stop hooks").
#[test]
fn auto_summary_guarded_insert_exactly_one_under_race() {
    let s = mem();
    seed_session(&s, "sess-toctou");
    let mk = |body: &str| {
        let mut snap = Snapshot::new(SessionId::new("sess-toctou"), SnapshotTrigger::AutoSummary);
        snap.summary = Some(body.to_string());
        snap
    };
    let a = s
        .create_snapshot_if_no_recent_auto_summary(&mk("handler-A"), 60)
        .unwrap();
    let b = s
        .create_snapshot_if_no_recent_auto_summary(&mk("handler-B"), 60)
        .unwrap();
    assert!(a ^ b, "exactly one handler must win (a={a} b={b})");
    let snaps = s.get_snapshots_by_session("sess-toctou").unwrap();
    assert_eq!(
        snaps.len(),
        1,
        "concurrent Stop handlers must yield exactly one AutoSummary"
    );
}

/// Failure path: a stale `auto_summary` (outside the freshness window) does
/// NOT block a new one (spec 3.7: legitimate periodic summary proceeds).
#[test]
fn auto_summary_stale_does_not_block_new() {
    let s = mem();
    seed_session(&s, "sess-stale");
    let old = (chrono::Utc::now() - chrono::Duration::hours(2)).to_rfc3339();
    s.connection()
        .execute(
            "INSERT INTO snapshots (session_id, created_at, trigger, summary) \
             VALUES ('sess-stale', ?1, 'auto_summary', 'old')",
            [old],
        )
        .unwrap();
    let mut snap = Snapshot::new(SessionId::new("sess-stale"), SnapshotTrigger::AutoSummary);
    snap.summary = Some("fresh".to_string());
    let inserted = s
        .create_snapshot_if_no_recent_auto_summary(&snap, 60)
        .unwrap();
    assert!(inserted, "a stale prior summary must not block a new one");
    assert_eq!(s.get_snapshots_by_session("sess-stale").unwrap().len(), 2);
}

// ===========================================================================
// Migration chain v1..v7 contiguity + SCHEMA_VERSION + v5->v7 upgrade
// ===========================================================================

/// A freshly opened DB is at the highest schema version (spec 5: migration
/// chain v1..v9 contiguous, `SCHEMA_VERSION` matches highest = 9).
#[test]
fn fresh_db_is_at_schema_version_9() {
    let s = mem();
    assert_eq!(
        s.schema_version().unwrap(),
        9,
        "fresh DB must be migrated to the highest schema version"
    );
}

/// The full schema is present after migration: every table the recall +
/// memory pipeline depends on exists (proves the chain ran contiguously,
/// spec 5).
#[test]
fn migrated_db_has_all_pipeline_tables() {
    let s = mem();
    for table in [
        "sessions",
        "snapshots",
        "snapshots_fts",
        "events",
        "audit_log",
        "tool_events",
    ] {
        let n: i64 = s
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE name = ?1",
                [table],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 1, "table `{table}` must exist after migration");
    }
    // v7 dedup unique index must be present.
    let idx: i64 = s
        .connection()
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master \
             WHERE type='index' AND name='tool_events_dedup_idx'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(idx, 1, "v7 tool_events_dedup_idx must exist");
}

/// A DB stuck at a v5-era state (no `tool_events` table, `schema_version`=5)
/// upgrades cleanly to v8 with no data loss: a pre-existing snapshot row
/// survives, the v6/v7 `tool_events` table appears, and the v8 `host` column
/// is added (spec 6: additive migration, no data loss; edge "v5-state DB
/// upgrades to head").
#[test]
fn v5_state_db_upgrades_to_v8_without_data_loss() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let db = tmp.path().join("legacy.db");

    {
        // Build a minimal v5-shaped DB by hand: v1 core tables + the v5
        // embedding_model column, schema_version pinned at 5, NO
        // tool_events table (that arrives in v6).
        let conn = rusqlite::Connection::open(&db).unwrap();
        conn.execute_batch(
            "CREATE TABLE schema_version (version INTEGER PRIMARY KEY);
             CREATE TABLE sessions (
                 id TEXT PRIMARY KEY, project_path TEXT NOT NULL,
                 transcript_path TEXT, started_at TEXT NOT NULL, ended_at TEXT,
                 source TEXT NOT NULL DEFAULT 'startup',
                 message_count INTEGER DEFAULT 0, command_count INTEGER DEFAULT 0,
                 input_tokens INTEGER DEFAULT 0, output_tokens INTEGER DEFAULT 0,
                 status TEXT DEFAULT 'active');
             CREATE TABLE snapshots (
                 id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT NOT NULL,
                 created_at TEXT NOT NULL, trigger TEXT NOT NULL, summary TEXT,
                 key_facts TEXT, todos TEXT, message_count INTEGER,
                 input_tokens INTEGER, output_tokens INTEGER,
                 embedding_model TEXT NOT NULL DEFAULT '<unknown-pre-migration>');
             INSERT INTO sessions (id, project_path, started_at) \
                 VALUES ('legacy-sess', '/tmp', datetime('now'));
             INSERT INTO snapshots (session_id, created_at, trigger, summary) \
                 VALUES ('legacy-sess', datetime('now'), 'manual', 'legacy data');
             INSERT INTO schema_version (version) VALUES (5);",
        )
        .unwrap();
    }

    // Re-open through the real Storage path: migrations v6..v9 must run.
    let s = Storage::open(&db).expect("upgrade open");
    assert_eq!(
        s.schema_version().unwrap(),
        9,
        "v5 DB must migrate forward to v9"
    );

    // No data loss: the legacy snapshot survived.
    let snaps = s.get_snapshots_by_session("legacy-sess").unwrap();
    assert_eq!(snaps.len(), 1, "pre-existing snapshot must survive upgrade");
    assert_eq!(snaps[0].summary.as_deref(), Some("legacy data"));

    // v6/v7 additive: tool_events now usable.
    s.append_or_extend_tool_event(&ev(
        "legacy-sess",
        "Edit",
        Some("n.rs"),
        "post-upgrade",
        1_000,
    ))
    .unwrap();
    assert_eq!(s.count_tool_events("legacy-sess").unwrap(), 1);

    // v8 additive: the `host` column now exists on the legacy row and was
    // backfilled to the 'claude' default (no data loss for pre-v0.10.0 rows).
    let host: String = s
        .connection()
        .query_row(
            "SELECT host FROM sessions WHERE id = 'legacy-sess'",
            [],
            |r| r.get(0),
        )
        .expect("v8 host column must exist and be readable");
    assert_eq!(
        host, "claude",
        "pre-v8 session row must backfill host to the 'claude' default"
    );
}

/// RISK M-R1 (resolved): the newer-schema guard now exists. A DB whose
/// `schema_version` is GREATER than the current `SCHEMA_VERSION` is REFUSED
/// at open time with an actionable error, instead of being silently
/// tolerated. Running an older binary against a newer schema risks silent
/// corruption / data loss, so the migration entrypoint fails fast (spec
/// RISKS #1 + section 6). This test asserts the corrected behavior:
///   - a future-schema DB returns `Err` with the documented message;
///   - a normal older -> current DB still migrates forward without error.
#[test]
fn m_r1_newer_schema_db_is_refused() {
    let tmp = tempfile::tempdir().expect("tempdir");

    // --- Case 1: future-schema DB must be refused ----------------------
    let future_db = tmp.path().join("future.db");
    {
        // Real migrated DB, then bump schema_version far into the future.
        let s = Storage::open(&future_db).expect("initial open");
        drop(s);
        let conn = rusqlite::Connection::open(&future_db).unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO schema_version (version) VALUES (999)",
            [],
        )
        .unwrap();
    }
    let reopened = Storage::open(&future_db);
    let err = reopened
        .err()
        .expect("RISK M-R1: opening a newer-schema DB MUST be refused");
    let msg = err.to_string();
    assert!(
        msg.contains("newer CLX") && msg.contains("upgrade CLX"),
        "RISK M-R1: refusal error must carry the documented actionable \
         message, got: {msg}"
    );
    assert!(
        msg.contains("999"),
        "RISK M-R1: refusal message must report the offending future \
         schema version, got: {msg}"
    );

    // --- Case 2: a fresh (version 0) DB still migrates forward --------
    // The guard must only reject *newer* schemas; an empty/older DB must
    // still run the full migration chain up to the current version. (The
    // realistic v5 -> v7 legacy upgrade is covered separately above.)
    let normal_db = tmp.path().join("normal.db");
    let migrated =
        Storage::open(&normal_db).expect("RISK M-R1: a fresh/older DB must still migrate forward");
    assert!(
        migrated.schema_version().unwrap() >= 7,
        "fresh DB must migrate up to the current supported schema version"
    );
}
