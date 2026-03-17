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
