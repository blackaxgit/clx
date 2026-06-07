//! Behavior tests for the v8→v9 purge migration (Issue 1, AC1.5/AC1.6).
//!
//! Public boundary: `Storage::open(&Path)` runs all pending migrations,
//! including `migrate_to_v9`, which purges secret-bearing and malformed
//! `learned_rules` rows of ANY source while preserving well-formed rules
//! (including legit `*`/`/` wildcard/path patterns).
//!
//! Strategy: seed a raw `SQLite` database stamped at schema version 8 (the
//! `learned_rules` table from v1 plus a `schema_version` of 8), insert a mix of
//! offending and legitimate rows, then open it via the normal `Storage::open`
//! path so ONLY `migrate_to_v9` runs. Assert the offending rows are gone, the
//! legit rows remain, the recorded schema version is 9, and a second open is a
//! no-op.
//!
//! Hermetic: the DB lives under a per-test `TempDir`; no real `~/.clx`.

use clx_core::storage::Storage;
use rusqlite::Connection;
use std::path::Path;
use tempfile::TempDir;

/// Seed a raw v8 database with the `learned_rules` schema and a set of
/// `(pattern, source)` rows, stamping the recorded schema version to 8 so that
/// opening it via `Storage::open` runs only `migrate_to_v9`.
fn seed_v8_with_rules(path: &Path, rows: &[(&str, &str)]) {
    let conn = Connection::open(path).expect("open raw db");
    conn.execute_batch(
        "CREATE TABLE schema_version (version INTEGER PRIMARY KEY);
         CREATE TABLE learned_rules (
             id INTEGER PRIMARY KEY AUTOINCREMENT,
             pattern TEXT NOT NULL UNIQUE,
             rule_type TEXT NOT NULL,
             learned_at TEXT NOT NULL,
             source TEXT NOT NULL,
             confirmation_count INTEGER DEFAULT 0,
             denial_count INTEGER DEFAULT 0,
             project_path TEXT
         );",
    )
    .expect("create v8 schema");

    for (pattern, source) in rows {
        conn.execute(
            "INSERT INTO learned_rules (pattern, rule_type, learned_at, source) \
             VALUES (?1, 'Allow', datetime('now'), ?2)",
            [pattern, source],
        )
        .expect("seed learned rule");
    }

    conn.execute("INSERT INTO schema_version (version) VALUES (8)", [])
        .expect("stamp schema version 8");
    // Drop the connection (close) so Storage::open gets a clean handle.
    drop(conn);
}

/// Collect the surviving `learned_rules` patterns from an opened storage.
fn surviving_patterns(storage: &Storage) -> Vec<String> {
    let conn = storage.connection();
    let mut stmt = conn
        .prepare("SELECT pattern FROM learned_rules ORDER BY pattern")
        .expect("prepare select");
    let rows = stmt
        .query_map([], |r| r.get::<_, String>(0))
        .expect("query");
    rows.map(|r| r.expect("row")).collect()
}

/// AC1.5/AC1.6: the v9 purge deletes secret-bearing and malformed rows of any
/// source, preserves well-formed rules (including a legit wildcard), records
/// schema version 9, and is idempotent on a second open.
#[test]
fn v9_purges_secret_and_malformed_rules_preserves_legit() {
    let tmp = TempDir::new().unwrap();
    let db = tmp.path().join("v8.db");

    // (a) secret row, (b) malformed (compound metachar) row, (c) legit literal,
    // (d) legit wildcard. The secret row is seeded as a manual `cli` source to
    // prove purge ignores source.
    seed_v8_with_rules(
        &db,
        &[
            ("Bash(SSHPASS=hunter2pass ssh host:*)", "cli"),
            ("Bash(true;:*)", "user_decision"),
            ("Bash(make build)", "user_decision"),
            ("Bash(npm run build*)", "user_decision"),
        ],
    );

    let storage = Storage::open(&db).expect("open runs migrate_to_v9");

    // Recorded schema version is the schema_version TABLE value, now 9.
    assert_eq!(
        storage.schema_version().expect("schema version"),
        9,
        "v9 migration must stamp the schema_version table to 9"
    );

    let survivors = surviving_patterns(&storage);
    assert_eq!(
        survivors,
        vec![
            "Bash(make build)".to_string(),
            "Bash(npm run build*)".to_string(),
        ],
        "only the legit literal and wildcard rules must survive; \
         secret + malformed rows must be purged regardless of source"
    );

    // Idempotent: a second open (close + reopen) does not delete the survivors
    // and stays at v9.
    drop(storage);
    let reopened = Storage::open(&db).expect("second open is a no-op");
    assert_eq!(
        reopened.schema_version().expect("schema version"),
        9,
        "second open must remain at schema version 9"
    );
    assert_eq!(
        surviving_patterns(&reopened),
        vec![
            "Bash(make build)".to_string(),
            "Bash(npm run build*)".to_string(),
        ],
        "second open must not delete the surviving legit rules"
    );
}

/// A clean v8 database with no offending rows must lose nothing during the v9
/// purge (idempotent / no false positives on well-formed rules).
#[test]
fn v9_no_op_on_clean_database() {
    let tmp = TempDir::new().unwrap();
    let db = tmp.path().join("clean_v8.db");

    seed_v8_with_rules(
        &db,
        &[
            ("Bash(make build)", "user_decision"),
            ("FileEdit(*/src/*)", "user_decision"),
        ],
    );

    let storage = Storage::open(&db).expect("open runs migrate_to_v9");
    assert_eq!(storage.schema_version().expect("schema version"), 9);
    assert_eq!(
        surviving_patterns(&storage),
        vec![
            "Bash(make build)".to_string(),
            "FileEdit(*/src/*)".to_string(),
        ],
        "a clean DB must keep all well-formed rules"
    );
}
