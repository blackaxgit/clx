//! Schema migrations for CLX storage
//!
//! Handles database schema versioning and incremental migrations.

use tracing::info;

use super::Storage;

/// Current schema version for migrations
pub(super) const SCHEMA_VERSION: i32 = 5;

impl Storage {
    /// Configure `SQLite` pragmas for optimal performance
    pub(super) fn configure_pragmas(&self) -> crate::Result<()> {
        // Allow up to 5s for write lock contention in multi-session scenarios.
        self.conn.busy_timeout(std::time::Duration::from_secs(5))?;
        self.conn.execute_batch(
            "
            PRAGMA journal_mode = WAL;
            PRAGMA foreign_keys = ON;
            PRAGMA synchronous = NORMAL;
            ",
        )?;
        tracing::debug!("Configured SQLite pragmas");
        Ok(())
    }

    /// Run schema migrations
    pub(super) fn run_migrations(&self) -> crate::Result<()> {
        // Create schema_version table if not exists
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS schema_version (
                version INTEGER PRIMARY KEY
            )",
            [],
        )?;

        let current_version: i32 = self
            .conn
            .query_row(
                "SELECT COALESCE(MAX(version), 0) FROM schema_version",
                [],
                |row| row.get(0),
            )
            .unwrap_or(0);

        if current_version < SCHEMA_VERSION {
            info!(
                "Running migrations from version {} to {}",
                current_version, SCHEMA_VERSION
            );

            if current_version < 1 {
                self.migrate_to_v1()?;
            }

            if current_version < 2 {
                self.migrate_to_v2()?;
            }

            if current_version < 3 {
                self.migrate_to_v3()?;
            }

            if current_version < 4 {
                self.migrate_to_v4()?;
            }

            if current_version < 5 {
                self.migrate_to_v5()?;
            }

            self.conn.execute(
                "INSERT OR REPLACE INTO schema_version (version) VALUES (?1)",
                [SCHEMA_VERSION],
            )?;
        }

        Ok(())
    }

    /// Check if a column exists in a table
    ///
    /// Table name is validated against a whitelist to prevent SQL injection,
    /// since `SQLite` pragma queries cannot use parameterized table names.
    pub(super) fn column_exists(&self, table: &str, column: &str) -> bool {
        const VALID_TABLES: &[&str] = &[
            "sessions",
            "snapshots",
            "events",
            "audit_log",
            "learned_rules",
            "analytics",
            "snapshots_fts",
            "validation_cache",
        ];
        if !VALID_TABLES.contains(&table) {
            return false;
        }

        self.conn
            .query_row(
                &format!("SELECT COUNT(*) FROM pragma_table_info('{table}') WHERE name = ?1"),
                [column],
                |row| row.get::<_, i64>(0).map(|c| c > 0),
            )
            .unwrap_or(false)
    }

    /// Migrate to schema version 1
    pub(super) fn migrate_to_v1(&self) -> crate::Result<()> {
        self.conn.execute_batch(
            "
            -- Sessions table
            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                project_path TEXT NOT NULL,
                transcript_path TEXT,
                started_at TEXT NOT NULL,
                ended_at TEXT,
                source TEXT NOT NULL DEFAULT 'startup',
                message_count INTEGER DEFAULT 0,
                command_count INTEGER DEFAULT 0,
                input_tokens INTEGER DEFAULT 0,
                output_tokens INTEGER DEFAULT 0,
                status TEXT DEFAULT 'active'
            );

            CREATE INDEX IF NOT EXISTS idx_sessions_status ON sessions(status);
            CREATE INDEX IF NOT EXISTS idx_sessions_project ON sessions(project_path);

            -- Snapshots table
            CREATE TABLE IF NOT EXISTS snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                created_at TEXT NOT NULL,
                trigger TEXT NOT NULL,
                summary TEXT,
                key_facts TEXT,
                todos TEXT,
                message_count INTEGER,
                input_tokens INTEGER,
                output_tokens INTEGER,
                FOREIGN KEY (session_id) REFERENCES sessions(id)
            );

            CREATE INDEX IF NOT EXISTS idx_snapshots_session ON snapshots(session_id);

            -- Events table
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                tool_name TEXT,
                tool_use_id TEXT,
                tool_input TEXT,
                tool_output TEXT,
                FOREIGN KEY (session_id) REFERENCES sessions(id)
            );

            CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id);
            CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);

            -- Audit log table
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                command TEXT NOT NULL,
                working_dir TEXT,
                layer TEXT NOT NULL,
                decision TEXT NOT NULL,
                risk_score INTEGER,
                reasoning TEXT,
                user_decision TEXT,
                FOREIGN KEY (session_id) REFERENCES sessions(id)
            );

            CREATE INDEX IF NOT EXISTS idx_audit_session ON audit_log(session_id);
            CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);

            -- Learned rules table
            CREATE TABLE IF NOT EXISTS learned_rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pattern TEXT NOT NULL UNIQUE,
                rule_type TEXT NOT NULL,
                learned_at TEXT NOT NULL,
                source TEXT NOT NULL,
                confirmation_count INTEGER DEFAULT 0,
                denial_count INTEGER DEFAULT 0,
                project_path TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_rules_pattern ON learned_rules(pattern);
            CREATE INDEX IF NOT EXISTS idx_rules_project ON learned_rules(project_path);

            -- Analytics table
            -- Note: project_path uses empty string '' for global metrics to enable proper UNIQUE constraint
            CREATE TABLE IF NOT EXISTS analytics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                date TEXT NOT NULL,
                project_path TEXT NOT NULL DEFAULT '',
                metric_name TEXT NOT NULL,
                metric_value INTEGER NOT NULL,
                UNIQUE(date, project_path, metric_name)
            );

            CREATE INDEX IF NOT EXISTS idx_analytics_date ON analytics(date);
            CREATE INDEX IF NOT EXISTS idx_analytics_metric ON analytics(metric_name);
            ",
        )?;

        info!("Completed migration to schema version 1");
        Ok(())
    }

    /// Migrate to schema version 2 - add token tracking columns
    ///
    /// Wrapped in a transaction so partial failures roll back cleanly.
    pub(super) fn migrate_to_v2(&self) -> crate::Result<()> {
        let tx = self.conn.unchecked_transaction()?;

        let columns = [
            ("sessions", "input_tokens", "INTEGER DEFAULT 0"),
            ("sessions", "output_tokens", "INTEGER DEFAULT 0"),
            ("snapshots", "input_tokens", "INTEGER"),
            ("snapshots", "output_tokens", "INTEGER"),
        ];

        for (table, column, col_type) in &columns {
            if !self.column_exists(table, column) {
                alter_table_add_column(&self.conn, table, column, col_type)?;
            }
        }

        tx.commit()?;
        info!("Completed migration to schema version 2 (token tracking)");
        Ok(())
    }

    /// Migrate to schema version 3 - add FTS5 full-text search index
    ///
    /// Wrapped in a transaction so partial failures roll back cleanly.
    pub(super) fn migrate_to_v3(&self) -> crate::Result<()> {
        let tx = self.conn.unchecked_transaction()?;

        self.conn.execute_batch(
            "
            -- FTS5 virtual table for full-text search on snapshots
            CREATE VIRTUAL TABLE IF NOT EXISTS snapshots_fts USING fts5(
                summary,
                key_facts,
                todos,
                content='snapshots',
                content_rowid='id'
            );

            -- Triggers to keep FTS index in sync with snapshots table
            CREATE TRIGGER IF NOT EXISTS snapshots_ai AFTER INSERT ON snapshots BEGIN
                INSERT INTO snapshots_fts(rowid, summary, key_facts, todos)
                VALUES (new.id, new.summary, new.key_facts, new.todos);
            END;

            CREATE TRIGGER IF NOT EXISTS snapshots_ad AFTER DELETE ON snapshots BEGIN
                INSERT INTO snapshots_fts(snapshots_fts, rowid, summary, key_facts, todos)
                VALUES ('delete', old.id, old.summary, old.key_facts, old.todos);
            END;

            CREATE TRIGGER IF NOT EXISTS snapshots_au AFTER UPDATE ON snapshots BEGIN
                INSERT INTO snapshots_fts(snapshots_fts, rowid, summary, key_facts, todos)
                VALUES ('delete', old.id, old.summary, old.key_facts, old.todos);
                INSERT INTO snapshots_fts(rowid, summary, key_facts, todos)
                VALUES (new.id, new.summary, new.key_facts, new.todos);
            END;

            -- Backfill existing snapshots into FTS index
            INSERT INTO snapshots_fts(rowid, summary, key_facts, todos)
            SELECT id, summary, key_facts, todos FROM snapshots;
            ",
        )?;

        tx.commit()?;
        info!("Completed migration to schema version 3 (FTS5 full-text search)");
        Ok(())
    }

    /// Migrate to schema version 4 - add validation decision cache
    ///
    /// Wrapped in a transaction so partial failures roll back cleanly.
    pub(super) fn migrate_to_v4(&self) -> crate::Result<()> {
        let tx = self.conn.unchecked_transaction()?;

        self.conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS validation_cache (
                cache_key TEXT PRIMARY KEY,
                decision TEXT NOT NULL,
                reason TEXT,
                risk_score INTEGER,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                expires_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_validation_cache_expires
                ON validation_cache(expires_at);",
        )?;

        tx.commit()?;
        info!("Completed migration to schema version 4 (validation cache)");
        Ok(())
    }

    /// Migrate to schema version 5 - track embedding model identity per snapshot row.
    ///
    /// Pre-existing rows receive the sentinel `'<unknown-pre-migration>'` so that
    /// `EmbeddingStore::current_model()` can filter them out and avoid false mismatch
    /// errors on databases that pre-date this migration.
    pub(super) fn migrate_to_v5(&self) -> crate::Result<()> {
        let tx = self.conn.unchecked_transaction()?;

        if !self.column_exists("snapshots", "embedding_model") {
            alter_table_add_column(
                &self.conn,
                "snapshots",
                "embedding_model",
                "TEXT NOT NULL DEFAULT '<unknown-pre-migration>'",
            )?;
        }

        tx.commit()?;
        info!("Completed migration to schema version 5 (embedding model identity)");
        Ok(())
    }
}

/// Valid table names for `ALTER TABLE` migrations.
///
/// Validated at runtime to prevent SQL injection if migration code
/// is ever refactored to accept dynamic table names.
const VALID_MIGRATION_TABLES: &[&str] = &[
    "sessions",
    "snapshots",
    "events",
    "audit_log",
    "learned_rules",
    "analytics",
    "embeddings",
    "context_snapshots",
    "validation_cache",
];

/// Add a column to a table, validating table name against a whitelist.
///
/// Column names are also validated to contain only alphanumeric characters
/// and underscores to prevent injection.
fn alter_table_add_column(
    conn: &rusqlite::Connection,
    table: &str,
    column: &str,
    col_type: &str,
) -> crate::Result<()> {
    assert!(
        VALID_MIGRATION_TABLES.contains(&table),
        "Unknown table in migration: {table}"
    );
    assert!(
        column
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_'),
        "Invalid column name in migration: {column}"
    );
    conn.execute(
        &format!("ALTER TABLE {table} ADD COLUMN {column} {col_type}"),
        [],
    )?;
    Ok(())
}
