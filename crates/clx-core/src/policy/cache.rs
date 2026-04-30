//! Validation cache for LLM policy decisions.

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use super::types::PolicyDecision;

/// Cache entry for LLM validation results
#[derive(Debug, Clone)]
struct CacheEntry {
    decision: PolicyDecision,
    created_at: Instant,
}

impl CacheEntry {
    fn new(decision: PolicyDecision) -> Self {
        Self {
            decision,
            created_at: Instant::now(),
        }
    }

    fn is_expired(&self, ttl: Duration) -> bool {
        self.created_at.elapsed() > ttl
    }
}

/// Default maximum number of entries in the validation cache.
const DEFAULT_MAX_CACHE_ENTRIES: usize = 10_000;

/// Cache for LLM validation results
#[derive(Debug)]
pub struct ValidationCache {
    entries: Mutex<HashMap<String, CacheEntry>>,
    pub(crate) ttl: Duration,
    access_count: AtomicU64,
    /// Maximum number of entries before oldest are evicted
    pub(crate) max_entries: usize,
}

impl Default for ValidationCache {
    fn default() -> Self {
        Self::new()
    }
}

impl ValidationCache {
    /// Create a new empty cache
    #[must_use]
    pub fn new() -> Self {
        Self::with_ttl(Duration::from_mins(5))
    }

    /// Create a cache with a custom TTL
    #[must_use]
    pub fn with_ttl(ttl: Duration) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            ttl,
            access_count: AtomicU64::new(0),
            max_entries: DEFAULT_MAX_CACHE_ENTRIES,
        }
    }

    /// Set the maximum number of cache entries.
    ///
    /// When the cache exceeds this limit, the oldest entries (by creation time)
    /// are evicted to make room.
    #[must_use]
    pub fn with_max_entries(mut self, max_entries: usize) -> Self {
        self.max_entries = max_entries;
        self
    }

    /// Get a cached decision if it exists and is not expired
    pub fn get(&self, cache_key: &str) -> Option<PolicyDecision> {
        let mut entries = self.entries.lock().ok()?;

        // Periodic cleanup: every 100 accesses
        self.access_count.fetch_add(1, Ordering::Relaxed);
        if self
            .access_count
            .load(Ordering::Relaxed)
            .is_multiple_of(100)
        {
            entries.retain(|_, entry| !entry.is_expired(self.ttl));
        }

        if let Some(entry) = entries.get(cache_key) {
            if entry.is_expired(self.ttl) {
                entries.remove(cache_key);
                None
            } else {
                Some(entry.decision.clone())
            }
        } else {
            None
        }
    }

    /// Store a decision in the cache
    ///
    /// If the cache exceeds `max_entries` after insertion, the oldest entries
    /// (by creation time) are evicted to bring it back within the limit.
    pub fn insert(&self, cache_key: String, decision: PolicyDecision) {
        if let Ok(mut entries) = self.entries.lock() {
            entries.insert(cache_key, CacheEntry::new(decision));

            // Evict oldest entries if over capacity
            if entries.len() > self.max_entries {
                let mut items: Vec<(String, Instant)> = entries
                    .iter()
                    .map(|(k, v)| (k.clone(), v.created_at))
                    .collect();
                items.sort_by_key(|(_, created)| *created);
                let to_remove = entries.len() - self.max_entries;
                for (key, _) in items.iter().take(to_remove) {
                    entries.remove(key);
                }
            }
        }
    }

    /// Remove expired entries from the cache
    pub fn cleanup_expired(&self) {
        if let Ok(mut entries) = self.entries.lock() {
            entries.retain(|_, entry| !entry.is_expired(self.ttl));
        }
    }

    /// Get the number of cached entries
    pub fn len(&self) -> usize {
        self.entries.lock().map_or(0, |e| e.len())
    }

    /// Check if the cache is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Clear all cached entries
    pub fn clear(&self) {
        if let Ok(mut entries) = self.entries.lock() {
            entries.clear();
        }
    }
}

/// Compute a cache key from command and working directory.
///
/// Uses full string concatenation instead of hashing to eliminate
/// collision risk from non-cryptographic hash functions.
#[must_use]
pub fn compute_cache_key(command: &str, working_dir: &str) -> String {
    format!("{working_dir}:{command}")
}
