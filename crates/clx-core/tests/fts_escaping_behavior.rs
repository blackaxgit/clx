//! Behavior tests for FTS5 query escaping (issue #38).
//!
//! The auto-recall FTS lane must (1) never raise an FTS5 syntax error from
//! metacharacters in untrusted text (colons, URLs, `HH:MM`, quotes, operators,
//! NUL/control chars), and (2) still match content it indexed — including
//! non-ASCII terms that the previous strip-sanitizer silently dropped.
//!
//! Driven through the public `Storage::search_snapshots_fts`, the same call
//! `RecallEngine::try_fts` uses in production.

use clx_core::storage::Storage;
use clx_core::types::{Session, SessionId, Snapshot, SnapshotTrigger};

/// In-memory Storage seeded with one snapshot carrying `summary`.
fn seeded(summary: &str) -> Storage {
    let storage = Storage::open_in_memory().expect("in-memory storage");
    let session = Session::new(SessionId::new("fts-esc"), "/tmp/p".to_string());
    storage.create_session(&session).unwrap();
    let mut snap = Snapshot::new(SessionId::new("fts-esc"), SnapshotTrigger::Auto);
    snap.summary = Some(summary.to_string());
    storage.create_snapshot(&snap).unwrap();
    storage
}

// ---------------------------------------------------------------------------
// (1) Metacharacters never error, and real terms still match
// ---------------------------------------------------------------------------

/// The exact reported case: a colon in the query must not raise
/// `no such column: <token>`; the term still matches the indexed content.
#[test]
fn colon_query_never_errors_and_matches() {
    let storage = seeded("notification gateway is down");
    let hits = storage
        .search_snapshots_fts("notification: gateway", 10)
        .expect("colon query must not raise an FTS5 error");
    assert_eq!(
        hits.len(),
        1,
        "colon-bearing query should still match: {hits:?}"
    );
}

/// URLs (`http:`), timestamps (`14:`), quotes, `*`, parens, operator words —
/// all previously error-prone — must return Ok (never an FTS5 syntax error).
#[test]
fn adversarial_metachars_never_error() {
    let storage = seeded("deploy notes for the api service");
    for q in [
        "see http://host/path?a=b",
        "meeting at 14:30 tomorrow",
        "unbalanced \" quote",
        "prefix* and (grouping)",
        "hello AND world OR NOT near",
        "col:term ^anchor -neg +phrase",
        "日本語: メモ",
        "emoji 🚀 test",
    ] {
        let res = storage.search_snapshots_fts(q, 10);
        assert!(res.is_ok(), "query {q:?} must not error, got {res:?}");
    }
}

/// A NUL / control character in the query must not break the `SQLite` text or
/// FTS5 parse (the codex-flagged edge case).
#[test]
fn nul_and_control_chars_never_error() {
    let storage = seeded("alpha beta gamma");
    let res = storage.search_snapshots_fts("al\u{0}pha be\tta", 10);
    assert!(res.is_ok(), "NUL/control chars must not error: {res:?}");
}

// ---------------------------------------------------------------------------
// (2) Non-ASCII recall recovered (the live defect on main)
// ---------------------------------------------------------------------------

/// CJK term indexed by the unicode61 tokenizer must be findable — the previous
/// ASCII-only strip returned zero hits.
#[test]
fn cjk_term_is_recalled() {
    let storage = seeded("\u{65e5}\u{672c}\u{8a9e} \u{306e}\u{30e1}\u{30e2} gateway");
    let hits = storage
        .search_snapshots_fts("\u{65e5}\u{672c}\u{8a9e}", 10)
        .unwrap();
    assert_eq!(
        hits.len(),
        1,
        "CJK query should match indexed CJK term: {hits:?}"
    );
}

/// Accented term must be findable (the previous strip mangled `café` -> `caf`).
#[test]
fn accented_term_is_recalled() {
    let storage = seeded("caf\u{e9} renovation notes");
    let hits = storage.search_snapshots_fts("caf\u{e9}", 10).unwrap();
    assert_eq!(
        hits.len(),
        1,
        "accented query should match indexed term: {hits:?}"
    );
}

/// Cyrillic term must be findable (previously stripped to empty -> zero hits).
#[test]
fn cyrillic_term_is_recalled() {
    let storage = seeded("\u{41f}\u{440}\u{438}\u{432}\u{435}\u{442} team notes");
    let hits = storage
        .search_snapshots_fts("\u{41f}\u{440}\u{438}\u{432}\u{435}\u{442}", 10)
        .unwrap();
    assert_eq!(
        hits.len(),
        1,
        "Cyrillic query should match indexed term: {hits:?}"
    );
}

// ---------------------------------------------------------------------------
// Clean empty (not error) when nothing matches
// ---------------------------------------------------------------------------

/// A query whose literal terms are absent returns a clean empty, not an error.
#[test]
fn absent_terms_return_clean_empty() {
    let storage = seeded("alpha beta gamma");
    let hits = storage
        .search_snapshots_fts("kubernetes: (helm)", 10)
        .unwrap();
    assert!(
        hits.is_empty(),
        "absent terms must return empty, not error: {hits:?}"
    );
}
