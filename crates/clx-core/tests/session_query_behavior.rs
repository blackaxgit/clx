//! Behavior tests for the session *query* APIs on `Storage`
//! (`list_recent_sessions`, `count_sessions`, `get_token_totals`,
//! `list_sessions_by_project`).
//!
//! These APIs back real product surfaces — the `clx` dashboard
//! (`dashboard/data.rs`), MCP `clx_stats` (`tools/stats.rs`) and the hook
//! context builder (`clx-hook/src/context.rs`) — but previously had no
//! direct clx-core tests. The dynamic SQL assembly in
//! `list_recent_sessions` (positional `?N` placeholders computed from how
//! many filters are present) is exactly the kind of code an off-by-one
//! parameter-index regression silently breaks, so every since/limit
//! combination is pinned here.
//!
//! Disjoint from the in-crate `#[cfg(test)]` modules: integration-level
//! tests driving the public `Storage` API on a fresh in-memory database.

use chrono::{DateTime, Utc};
use clx_core::storage::Storage;
use clx_core::types::{Session, SessionId};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn mem() -> Storage {
    Storage::open_in_memory().expect("in-memory storage")
}

fn ts(rfc3339: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(rfc3339)
        .expect("valid rfc3339 in test fixture")
        .with_timezone(&Utc)
}

/// Create a session with a pinned `started_at` and token counts. All
/// timestamps in these tests use the same second-precision `+00:00` shape so
/// `SQLite`'s lexicographic TEXT comparison is identical to chronological
/// ordering (matching how production rows are written via `to_rfc3339`).
fn seed(
    s: &Storage,
    id: &str,
    project: &str,
    started_at: &str,
    input_tokens: i64,
    output_tokens: i64,
) {
    let mut session = Session::new(SessionId::new(id), project.to_string());
    session.started_at = ts(started_at);
    session.input_tokens = input_tokens;
    session.output_tokens = output_tokens;
    s.create_session(&session).expect("seed session");
}

fn ids(sessions: &[Session]) -> Vec<&str> {
    sessions.iter().map(|s| s.id.as_str()).collect()
}

const T1: &str = "2026-01-01T00:00:01+00:00";
const T2: &str = "2026-01-01T00:00:02+00:00";
const T3: &str = "2026-01-01T00:00:03+00:00";

/// Three sessions in three distinct seconds, oldest -> newest = a -> c.
fn seed_three(s: &Storage) {
    seed(s, "sess-a", "/proj/x", T1, 10, 1);
    seed(s, "sess-b", "/proj/x", T2, 20, 2);
    seed(s, "sess-c", "/proj/y", T3, 40, 4);
}

// ===========================================================================
// list_recent_sessions: since x limit matrix
// ===========================================================================

/// No filters: every session comes back, newest first. Kills an
/// `ORDER BY ... DESC` -> `ASC` regression and any accidental WHERE clause.
#[test]
fn list_recent_sessions_no_filters_returns_all_newest_first() {
    let s = mem();
    seed_three(&s);

    let got = s.list_recent_sessions(None, None).unwrap();
    assert_eq!(ids(&got), vec!["sess-c", "sess-b", "sess-a"]);
}

/// `since` is an INCLUSIVE lower bound: a session started exactly at the
/// cutoff must be returned. Kills a `>=` -> `>` boundary mutant.
#[test]
fn list_recent_sessions_since_cutoff_is_inclusive() {
    let s = mem();
    seed_three(&s);

    let got = s.list_recent_sessions(Some(ts(T2)), None).unwrap();
    assert_eq!(
        ids(&got),
        vec!["sess-c", "sess-b"],
        "cutoff == sess-b.started_at must include sess-b and exclude only sess-a"
    );
}

/// `limit` WITHOUT `since` exercises the placeholder-index branch where
/// `LIMIT` must bind as `?1` (no WHERE parameter precedes it). A parameter
/// index regression here either errors or silently ignores the limit.
#[test]
fn list_recent_sessions_limit_without_since_caps_to_newest() {
    let s = mem();
    seed_three(&s);

    let got = s.list_recent_sessions(None, Some(2)).unwrap();
    assert_eq!(
        ids(&got),
        vec!["sess-c", "sess-b"],
        "limit-only must keep the 2 newest sessions, not 2 arbitrary rows"
    );
}

/// `since` + `limit` together: filter first, then cap. The limit binds as
/// `?2` in this branch.
#[test]
fn list_recent_sessions_since_and_limit_compose() {
    let s = mem();
    seed_three(&s);

    let got = s.list_recent_sessions(Some(ts(T2)), Some(1)).unwrap();
    assert_eq!(
        ids(&got),
        vec!["sess-c"],
        "since must drop sess-a, then limit 1 must keep only the newest survivor"
    );
}

/// Edge: limit 0 returns an empty page rather than everything.
#[test]
fn list_recent_sessions_limit_zero_returns_empty() {
    let s = mem();
    seed_three(&s);

    let got = s.list_recent_sessions(None, Some(0)).unwrap();
    assert!(got.is_empty(), "LIMIT 0 must return no rows, got {got:?}");
}

/// Edge: a cutoff newer than every session yields an empty, non-error result.
#[test]
fn list_recent_sessions_future_cutoff_is_empty_not_error() {
    let s = mem();
    seed_three(&s);

    let got = s
        .list_recent_sessions(Some(ts("2027-01-01T00:00:00+00:00")), None)
        .unwrap();
    assert!(got.is_empty());
}

// ===========================================================================
// count_sessions
// ===========================================================================

/// Counts all sessions with no cutoff, and applies the same inclusive
/// `since` semantics as the list API (a divergence between the two would
/// make the dashboard's "total sessions" disagree with its session list).
#[test]
fn count_sessions_total_and_inclusive_since_cutoff() {
    let s = mem();
    seed_three(&s);

    assert_eq!(s.count_sessions(None).unwrap(), 3);
    assert_eq!(
        s.count_sessions(Some(ts(T2))).unwrap(),
        2,
        "cutoff == sess-b.started_at must count sess-b and sess-c"
    );
    assert_eq!(
        s.count_sessions(Some(ts("2027-01-01T00:00:00+00:00")))
            .unwrap(),
        0
    );
}

// ===========================================================================
// get_token_totals
// ===========================================================================

/// Input and output tokens are summed in separate, NON-interchangeable
/// columns. The asymmetric fixture values (sum 70 vs 7) kill a
/// column-swap regression and a SUM -> COUNT regression.
#[test]
fn get_token_totals_sums_input_and_output_separately() {
    let s = mem();
    seed_three(&s);

    let (input, output) = s.get_token_totals(None).unwrap();
    assert_eq!(
        (input, output),
        (70, 7),
        "input must be 10+20+40 and output 1+2+4; a swap or COUNT would differ"
    );
}

/// The `since` arm of `get_token_totals` must exclude sessions started
/// before the cutoff (inclusive at the boundary, like the other APIs).
#[test]
fn get_token_totals_since_excludes_older_sessions() {
    let s = mem();
    seed_three(&s);

    let (input, output) = s.get_token_totals(Some(ts(T2))).unwrap();
    assert_eq!(
        (input, output),
        (60, 6),
        "sess-a (10/1) is before the cutoff; sess-b + sess-c remain"
    );
}

/// Empty database: COALESCE must yield (0, 0) rather than a NULL-decode
/// error — the dashboard renders this on first launch.
#[test]
fn get_token_totals_empty_db_is_zero_zero() {
    let s = mem();
    let (input, output) = s.get_token_totals(None).unwrap();
    assert_eq!((input, output), (0, 0));
}

// ===========================================================================
// list_sessions_by_project
// ===========================================================================

/// Exact-path filter: only sessions for the requested project, newest
/// first, and never a neighbour project's rows (the hook context builder
/// uses this to resume the right project's session).
#[test]
fn list_sessions_by_project_filters_exact_path_newest_first() {
    let s = mem();
    seed_three(&s);

    let got = s.list_sessions_by_project("/proj/x").unwrap();
    assert_eq!(ids(&got), vec!["sess-b", "sess-a"]);
    assert!(
        got.iter().all(|sess| sess.project_path == "/proj/x"),
        "no cross-project leak"
    );

    let other = s.list_sessions_by_project("/proj/y").unwrap();
    assert_eq!(ids(&other), vec!["sess-c"]);
}

/// Unknown project path returns an empty vec, not an error.
#[test]
fn list_sessions_by_project_unknown_path_is_empty() {
    let s = mem();
    seed_three(&s);

    let got = s.list_sessions_by_project("/does/not/exist").unwrap();
    assert!(got.is_empty());
}

/// A prefix of a real project path must NOT match (exact equality, not
/// LIKE/prefix semantics — prefix matching would leak sibling-project
/// sessions into the hook context).
#[test]
fn list_sessions_by_project_prefix_does_not_match() {
    let s = mem();
    seed_three(&s);

    let got = s.list_sessions_by_project("/proj").unwrap();
    assert!(
        got.is_empty(),
        "'/proj' is a prefix of '/proj/x' and must not match: {got:?}"
    );
}
