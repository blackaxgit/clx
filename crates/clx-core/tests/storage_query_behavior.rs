//! Behavior tests for storage query paths with no prior direct coverage:
//!
//! - `get_analytics` with a project filter (the dashboard's per-project
//!   view): must include the project's rows AND global rows, exclude
//!   other projects, honor the inclusive date range, and map the empty
//!   project sentinel back to `None`.
//! - `count_audit_log` with a `since` cutoff (MCP `clx_stats`).
//! - `list_all_snapshots` (embedding backfill/rebuild walks every row in
//!   insertion order).
//! - `last_auto_summary_at` (Stop-hook optimistic-concurrency gate).
//! - the `Some(last_summary)` arm of
//!   `had_mutator_activity_since_last_auto_summary` (strictly-after
//!   comparison decides whether a read-only session is re-summarized).
//!
//! Integration-level: drives only the public `Storage` API on a fresh
//! in-memory database.

use chrono::{DateTime, NaiveDate, Utc};
use clx_core::storage::Storage;
use clx_core::types::{
    AnalyticsEntry, AuditDecision, AuditLogEntry, Session, SessionId, Snapshot, SnapshotTrigger,
    ToolEvent, ToolOutcome,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn mem() -> Storage {
    Storage::open_in_memory().expect("in-memory storage")
}

fn ts(rfc3339: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(rfc3339)
        .expect("valid rfc3339 fixture")
        .with_timezone(&Utc)
}

fn date(d: &str) -> NaiveDate {
    NaiveDate::parse_from_str(d, "%Y-%m-%d").expect("valid date fixture")
}

fn seed_session(s: &Storage, id: &str) {
    let session = Session::new(SessionId::new(id), "/proj".to_string());
    s.create_session(&session).expect("seed session");
}

fn metric(s: &Storage, d: &str, project: Option<&str>, name: &str, value: i64) {
    let mut entry = AnalyticsEntry::new(date(d), name.to_string(), value);
    entry.project_path = project.map(str::to_string);
    s.record_metric(&entry).expect("record metric");
}

fn audit_at(s: &Storage, session: &str, command: &str, at: &str) {
    let mut entry = AuditLogEntry::new(
        SessionId::new(session),
        command.to_string(),
        "layer0".to_string(),
        AuditDecision::Allowed,
    );
    entry.timestamp = ts(at);
    s.create_audit_log(&entry).expect("create audit row");
}

fn snapshot_at(s: &Storage, session: &str, trigger: SnapshotTrigger, summary: &str, at: &str) -> i64 {
    let mut snap = Snapshot::new(SessionId::new(session), trigger);
    snap.summary = Some(summary.to_string());
    snap.created_at = ts(at);
    s.create_snapshot(&snap).expect("create snapshot")
}

fn tool_event_at(s: &Storage, session: &str, target: &str, at: &str) {
    let mut ev = ToolEvent::new(
        SessionId::new(session),
        "Edit",
        Some(target.to_string()),
        &format!("edit {target}"),
        ToolOutcome::Success,
        1_000,
    );
    ev.created_at = ts(at);
    s.append_or_extend_tool_event(&ev).expect("append tool event");
}

const T1: &str = "2026-01-01T00:00:01+00:00";
const T2: &str = "2026-01-01T00:00:02+00:00";
const T3: &str = "2026-01-01T00:00:03+00:00";

// ===========================================================================
// get_analytics with project filter
// ===========================================================================

/// The project-filtered arm must return the project's rows PLUS global
/// rows (empty-string sentinel), and never a sibling project's rows.
/// The sentinel must round-trip back to `project_path == None`.
#[test]
fn get_analytics_project_filter_includes_global_excludes_siblings() {
    let s = mem();
    metric(&s, "2026-01-10", Some("/proj/a"), "commands_validated", 5);
    metric(&s, "2026-01-10", None, "commands_validated", 7); // global
    metric(&s, "2026-01-10", Some("/proj/b"), "commands_validated", 11);

    let got = s
        .get_analytics(date("2026-01-01"), date("2026-01-31"), Some("/proj/a"))
        .unwrap();

    let mut values: Vec<(Option<&str>, i64)> = got
        .iter()
        .map(|e| (e.project_path.as_deref(), e.metric_value))
        .collect();
    values.sort();
    assert_eq!(
        values,
        vec![(None, 7), (Some("/proj/a"), 5)],
        "must return project + global rows only; sibling /proj/b leaked or sentinel not mapped"
    );
}

/// The date range is inclusive on both edges; rows outside it are dropped
/// and results are ordered newest date first.
#[test]
fn get_analytics_project_filter_honors_inclusive_date_range_desc() {
    let s = mem();
    metric(&s, "2026-01-09", Some("/proj/a"), "m", 1); // before range
    metric(&s, "2026-01-10", Some("/proj/a"), "m", 2); // start edge
    metric(&s, "2026-01-15", Some("/proj/a"), "m", 3); // inside
    metric(&s, "2026-01-20", Some("/proj/a"), "m", 4); // end edge
    metric(&s, "2026-01-21", Some("/proj/a"), "m", 5); // after range

    let got = s
        .get_analytics(date("2026-01-10"), date("2026-01-20"), Some("/proj/a"))
        .unwrap();

    let values: Vec<i64> = got.iter().map(|e| e.metric_value).collect();
    assert_eq!(
        values,
        vec![4, 3, 2],
        "edges must be included, out-of-range dropped, order newest-first"
    );
}

// ===========================================================================
// count_audit_log with since cutoff
// ===========================================================================

/// `since` is an inclusive lower bound on the audit timeline; an entry
/// stamped exactly at the cutoff counts. Kills a `>=` -> `>` mutant and
/// keeps MCP `clx_stats` consistent with the audit list views.
#[test]
fn count_audit_log_since_cutoff_is_inclusive() {
    let s = mem();
    seed_session(&s, "sess-audit");
    audit_at(&s, "sess-audit", "echo one", T1);
    audit_at(&s, "sess-audit", "echo two", T2);
    audit_at(&s, "sess-audit", "echo three", T3);

    assert_eq!(s.count_audit_log(None).unwrap(), 3);
    assert_eq!(
        s.count_audit_log(Some(ts(T2))).unwrap(),
        2,
        "cutoff == entry-two timestamp must count entries two and three"
    );
    assert_eq!(
        s.count_audit_log(Some(ts("2027-01-01T00:00:00+00:00")))
            .unwrap(),
        0
    );
}

// ===========================================================================
// list_all_snapshots
// ===========================================================================

/// Every snapshot across every session comes back in insertion (id ASC)
/// order — the embedding rebuild walks this list and must not silently
/// skip a session or reorder rows.
#[test]
fn list_all_snapshots_returns_every_session_in_insertion_order() {
    let s = mem();
    seed_session(&s, "sess-1");
    seed_session(&s, "sess-2");
    let id_a = snapshot_at(&s, "sess-1", SnapshotTrigger::Manual, "first", T1);
    let id_b = snapshot_at(&s, "sess-2", SnapshotTrigger::Manual, "second", T2);
    let id_c = snapshot_at(&s, "sess-1", SnapshotTrigger::Manual, "third", T3);

    let got = s.list_all_snapshots().unwrap();
    let got_ids: Vec<i64> = got.iter().filter_map(|sn| sn.id).collect();
    assert_eq!(
        got_ids,
        vec![id_a, id_b, id_c],
        "all sessions' snapshots, ascending insertion order"
    );
    let summaries: Vec<Option<&str>> = got.iter().map(|sn| sn.summary.as_deref()).collect();
    assert_eq!(
        summaries,
        vec![Some("first"), Some("second"), Some("third")]
    );
}

/// Empty database yields an empty vec, not an error.
#[test]
fn list_all_snapshots_empty_db_is_empty() {
    let s = mem();
    assert!(s.list_all_snapshots().unwrap().is_empty());
}

// ===========================================================================
// last_auto_summary_at
// ===========================================================================

/// No `auto_summary` snapshot -> None, even when other triggers exist
/// (a Manual snapshot must NOT satisfy the auto-summary race gate).
#[test]
fn last_auto_summary_at_ignores_non_auto_summary_triggers() {
    let s = mem();
    seed_session(&s, "sess-A");
    snapshot_at(&s, "sess-A", SnapshotTrigger::Manual, "manual", T3);

    assert_eq!(
        s.last_auto_summary_at("sess-A").unwrap(),
        None,
        "a Manual snapshot must not be mistaken for an auto_summary"
    );
}

/// Returns the NEWEST `auto_summary` timestamp for the session, not an
/// older one and not another session's. Kills MAX -> MIN and a dropped
/// session filter.
#[test]
fn last_auto_summary_at_picks_newest_for_the_session_only() {
    let s = mem();
    seed_session(&s, "sess-A");
    seed_session(&s, "sess-B");
    snapshot_at(&s, "sess-A", SnapshotTrigger::AutoSummary, "old", T1);
    snapshot_at(&s, "sess-A", SnapshotTrigger::AutoSummary, "new", T2);
    snapshot_at(&s, "sess-B", SnapshotTrigger::AutoSummary, "other", T3);

    assert_eq!(
        s.last_auto_summary_at("sess-A").unwrap(),
        Some(ts(T2)),
        "must be sess-A's newest auto_summary, not T1 (old) or T3 (sess-B)"
    );
}

// ===========================================================================
// had_mutator_activity_since_last_auto_summary: Some(last_ts) arm
// ===========================================================================

/// A session whose only tool activity happened BEFORE the last
/// `auto_summary` is read-only since that summary -> false. A regression
/// that ignores the timestamp filter would re-summarize idle sessions on
/// every Stop event.
#[test]
fn mutator_activity_false_when_all_events_predate_last_summary() {
    let s = mem();
    seed_session(&s, "sess-A");
    tool_event_at(&s, "sess-A", "src/old.rs", T1);
    snapshot_at(&s, "sess-A", SnapshotTrigger::AutoSummary, "sum", T2);

    assert!(
        !s.had_mutator_activity_since_last_auto_summary("sess-A")
            .unwrap(),
        "event at T1 predates summary at T2 -> no new activity"
    );
}

/// An event stamped exactly AT the last summary's timestamp is not
/// "after" it: the comparison is strictly greater. Pins the `>` boundary
/// so a `>=` regression (double-summarizing the same instant) fails.
#[test]
fn mutator_activity_event_at_summary_instant_does_not_count() {
    let s = mem();
    seed_session(&s, "sess-A");
    snapshot_at(&s, "sess-A", SnapshotTrigger::AutoSummary, "sum", T2);
    tool_event_at(&s, "sess-A", "src/same-instant.rs", T2);

    assert!(
        !s.had_mutator_activity_since_last_auto_summary("sess-A")
            .unwrap(),
        "created_at == last summary timestamp must not count as new activity"
    );
}

/// An event strictly after the last `auto_summary` flips the gate to true.
#[test]
fn mutator_activity_true_for_event_after_last_summary() {
    let s = mem();
    seed_session(&s, "sess-A");
    snapshot_at(&s, "sess-A", SnapshotTrigger::AutoSummary, "sum", T1);
    tool_event_at(&s, "sess-A", "src/new.rs", T2);

    assert!(
        s.had_mutator_activity_since_last_auto_summary("sess-A")
            .unwrap(),
        "event at T2 after summary at T1 must report activity"
    );
}
