//! Validation decision cache operations.
//!
//! Provides persistent caching for LLM policy decisions in `SQLite`,
//! enabling cross-process decision reuse between short-lived hook invocations.

use rusqlite::params;
use tracing::debug;

use super::Storage;

/// A cached validation decision retrieved from the database.
#[derive(Debug, Clone)]
pub struct CachedDecision {
    /// The policy decision string ("allow", "deny", "ask")
    pub decision: String,
    /// Optional reason for the decision
    pub reason: Option<String>,
    /// Optional risk score (1-10)
    pub risk_score: Option<i64>,
}

impl Storage {
    /// Look up a cached validation decision by cache key.
    ///
    /// Returns `None` if not found or expired.
    pub fn get_cached_decision(&self, cache_key: &str) -> crate::Result<Option<CachedDecision>> {
        let mut stmt = self.conn.prepare(
            "SELECT decision, reason, risk_score FROM validation_cache
             WHERE cache_key = ?1 AND expires_at > datetime('now')",
        )?;

        let result = stmt.query_row(params![cache_key], |row| {
            Ok(CachedDecision {
                decision: row.get(0)?,
                reason: row.get(1)?,
                risk_score: row.get(2)?,
            })
        });

        match result {
            Ok(cached) => {
                debug!("Validation cache hit for key: {}", cache_key);
                Ok(Some(cached))
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Store a validation decision with TTL.
    ///
    /// Uses `INSERT OR REPLACE` so repeated evaluations update the cache entry.
    pub fn cache_decision(
        &self,
        cache_key: &str,
        decision: &str,
        reason: Option<&str>,
        risk_score: Option<i64>,
        ttl_secs: i64,
    ) -> crate::Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO validation_cache
             (cache_key, decision, reason, risk_score, created_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, datetime('now'), datetime('now', '+' || ?5 || ' seconds'))",
            params![cache_key, decision, reason, risk_score, ttl_secs],
        )?;
        debug!(
            "Cached validation decision for key: {} (ttl: {}s)",
            cache_key, ttl_secs
        );
        Ok(())
    }

    /// Remove expired cache entries.
    ///
    /// Returns the number of entries deleted.
    pub fn cleanup_expired_cache(&self) -> crate::Result<usize> {
        let deleted = self.conn.execute(
            "DELETE FROM validation_cache WHERE expires_at < datetime('now')",
            [],
        )?;
        if deleted > 0 {
            debug!("Cleaned up {} expired cache entries", deleted);
        }
        Ok(deleted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_storage() -> Storage {
        Storage::open_in_memory().expect("Failed to create in-memory storage")
    }

    #[test]
    fn test_cache_miss_returns_none() {
        let storage = create_test_storage();
        let result = storage.get_cached_decision("nonexistent_key").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_cache_hit_returns_decision() {
        let storage = create_test_storage();
        storage
            .cache_decision("key1", "allow", None, None, 3600)
            .unwrap();

        let cached = storage
            .get_cached_decision("key1")
            .unwrap()
            .expect("expected a cached decision");

        assert_eq!(cached.decision, "allow");
        assert!(cached.reason.is_none());
        assert!(cached.risk_score.is_none());
    }

    #[test]
    fn test_cache_with_reason_and_risk_score() {
        let storage = create_test_storage();
        storage
            .cache_decision("key2", "ask", Some("suspicious pattern"), Some(7), 3600)
            .unwrap();

        let cached = storage
            .get_cached_decision("key2")
            .unwrap()
            .expect("expected a cached decision");

        assert_eq!(cached.decision, "ask");
        assert_eq!(cached.reason.as_deref(), Some("suspicious pattern"));
        assert_eq!(cached.risk_score, Some(7));
    }

    #[test]
    fn test_cache_expired_returns_none() {
        let storage = create_test_storage();
        // Insert directly with an already-past expires_at since negative TTL
        // causes NULL in SQLite's datetime arithmetic.
        storage
            .conn
            .execute(
                "INSERT INTO validation_cache
                 (cache_key, decision, reason, risk_score, created_at, expires_at)
                 VALUES ('expired_key', 'allow', NULL, NULL, datetime('now'), datetime('now', '-1 seconds'))",
                [],
            )
            .unwrap();

        let result = storage.get_cached_decision("expired_key").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_cache_upsert_replaces() {
        let storage = create_test_storage();
        storage
            .cache_decision("dup_key", "allow", Some("first"), Some(2), 3600)
            .unwrap();
        storage
            .cache_decision("dup_key", "deny", Some("second"), Some(9), 3600)
            .unwrap();

        let cached = storage
            .get_cached_decision("dup_key")
            .unwrap()
            .expect("expected a cached decision");

        assert_eq!(cached.decision, "deny");
        assert_eq!(cached.reason.as_deref(), Some("second"));
        assert_eq!(cached.risk_score, Some(9));
    }

    #[test]
    fn test_cleanup_expired_removes_old_entries() {
        let storage = create_test_storage();

        // Insert one expired entry via raw SQL and one valid entry (TTL=3600)
        storage
            .conn
            .execute(
                "INSERT INTO validation_cache
                 (cache_key, decision, reason, risk_score, created_at, expires_at)
                 VALUES ('old_key', 'allow', NULL, NULL, datetime('now'), datetime('now', '-1 seconds'))",
                [],
            )
            .unwrap();
        storage
            .cache_decision("fresh_key", "allow", None, None, 3600)
            .unwrap();

        let deleted = storage.cleanup_expired_cache().unwrap();
        assert_eq!(deleted, 1);

        // Expired entry should be gone
        assert!(storage.get_cached_decision("old_key").unwrap().is_none());

        // Valid entry should remain
        assert!(storage
            .get_cached_decision("fresh_key")
            .unwrap()
            .is_some());
    }

    #[test]
    fn test_cache_deny_not_cached_pattern() {
        // The storage layer does not enforce "don't cache deny" policy.
        // That policy is enforced by the caller. Verify storage stores and
        // retrieves deny decisions without issue.
        let storage = create_test_storage();
        storage
            .cache_decision("deny_key", "deny", Some("blocked"), Some(10), 3600)
            .unwrap();

        let cached = storage
            .get_cached_decision("deny_key")
            .unwrap()
            .expect("expected a cached decision");

        assert_eq!(cached.decision, "deny");
        assert_eq!(cached.reason.as_deref(), Some("blocked"));
        assert_eq!(cached.risk_score, Some(10));
    }
}
