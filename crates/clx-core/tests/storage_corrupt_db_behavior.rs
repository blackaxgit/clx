//! Error-path behavior tests for `clx_core::storage::Storage`.
//!
//! Public boundary: `Storage::open(&Path) -> Result<Storage>`. These tests
//! prove that the storage open + migration path returns an `Err` (never panics
//! / never aborts the process) on a corrupt `SQLite` file or an unwritable
//! location, and that opening a fresh path succeeds (migrations run on an empty
//! DB).
//!
//! Hermetic: all paths live under a per-test `TempDir`; no real `~/.clx`,
//! no network, no keychain.
//!
//! Fault model targeted: a regression that `unwrap()`s the rusqlite open or
//! migration result would turn a recoverable error into a process panic in a
//! hook/MCP path; these tests would then fail (panic) instead of asserting an
//! `Err`.

use std::fs;

use clx_core::storage::Storage;
use tempfile::TempDir;

/// Happy path: opening a brand-new path creates the DB and runs migrations
/// without error. This is the lifecycle baseline the error paths contrast with.
#[test]
fn open_fresh_path_succeeds_and_runs_migrations() {
    let tmp = TempDir::new().unwrap();
    let db = tmp.path().join("fresh.db");
    let storage = Storage::open(&db);
    assert!(
        storage.is_ok(),
        "fresh DB open must succeed (is_err={})",
        storage.is_err()
    );
    // The file must now exist on disk (Connection::open created it).
    assert!(db.exists(), "open must create the database file");
}

/// `open` must also create missing parent directories on a fresh nested path
/// (documented behavior: "Creates parent directories if they don't exist").
/// This is the lifecycle contrast to the corrupt/error cases below.
#[test]
fn open_creates_missing_parent_dirs_for_fresh_db() {
    let tmp = TempDir::new().unwrap();
    let db = tmp.path().join("a").join("b").join("nested.db");
    let storage = Storage::open(&db);
    assert!(
        storage.is_ok(),
        "open must create parent dirs and succeed (is_err={})",
        storage.is_err()
    );
    assert!(db.exists(), "nested DB file must be created");
}

/// Corrupt file: a path whose contents are garbage (not a `SQLite` header) must
/// produce an `Err`, not a panic. `SQLite` detects the bad magic / malformed
/// schema during open or first migration query.
#[test]
fn open_corrupt_file_returns_err_not_panic() {
    let tmp = TempDir::new().unwrap();
    let db = tmp.path().join("corrupt.db");
    // Write a non-empty garbage blob that is NOT a valid SQLite file. The
    // 16-byte SQLite magic header is "SQLite format 3\0"; this is deliberately
    // different and followed by junk so header validation fails.
    fs::write(
        &db,
        b"this is definitely not a sqlite database file \x00\x01\x02\x03 junk",
    )
    .unwrap();

    let result = Storage::open(&db);
    assert!(
        result.is_err(),
        "opening a corrupt SQLite file must return Err, got Ok"
    );
}

/// Truncated/partial header: a file containing only a partial `SQLite`-looking
/// prefix must also error rather than open into an undefined state.
#[test]
fn open_partial_header_file_returns_err() {
    let tmp = TempDir::new().unwrap();
    let db = tmp.path().join("partial.db");
    // Looks almost like the magic but is truncated and padded with garbage,
    // so the page structure is invalid.
    fs::write(&db, b"SQLite format 3\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF").unwrap();

    let result = Storage::open(&db);
    assert!(
        result.is_err(),
        "opening a truncated/invalid SQLite file must return Err"
    );
}

/// Directory-in-the-way: if the target DB path is itself an existing
/// directory, `SQLite` cannot open it as a file. `open` must return `Err`, not
/// panic. (We do NOT test "missing parent dir" because `open` is documented to
/// create parent dirs; that is asserted positively above.)
#[test]
fn open_path_that_is_a_directory_returns_err() {
    let tmp = TempDir::new().unwrap();
    let db = tmp.path().join("a_dir_not_a_file.db");
    fs::create_dir(&db).unwrap();
    assert!(db.is_dir(), "precondition: path is a directory");

    let result = Storage::open(&db);
    assert!(
        result.is_err(),
        "opening a path that is a directory must return Err, not panic"
    );
}

/// Empty file: a zero-byte file at the path is a valid (empty) `SQLite`
/// database to which migrations can be applied. This pins the "old/empty DB
/// migrates" contract: open must succeed and produce a usable schema.
#[test]
fn open_empty_file_migrates_successfully() {
    let tmp = TempDir::new().unwrap();
    let db = tmp.path().join("empty.db");
    fs::write(&db, b"").unwrap();
    assert_eq!(fs::metadata(&db).unwrap().len(), 0, "precondition: empty");

    let result = Storage::open(&db);
    assert!(
        result.is_ok(),
        "an empty (zero-byte) file is a valid empty SQLite DB and must migrate (is_err={})",
        result.is_err()
    );
}
