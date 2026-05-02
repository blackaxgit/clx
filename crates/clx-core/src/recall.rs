//! Recall engine for hybrid semantic + FTS5 search across snapshots.
//!
//! Shared logic used by both the MCP `clx_recall` tool and the
//! `UserPromptSubmit` hook for auto-context recall.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use crate::embeddings::EmbeddingStore;
use crate::llm::LlmClient;
use crate::storage::Storage;

/// A single recall search result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecallHit {
    /// Database snapshot ID.
    pub snapshot_id: i64,
    /// Session that produced this snapshot.
    pub session_id: String,
    /// ISO-8601 timestamp of when the snapshot was created.
    pub created_at: String,
    /// Human-readable summary (if available).
    pub summary: Option<String>,
    /// Extracted key facts (if available).
    pub key_facts: Option<String>,
    /// Relevance score (0.0-1.0, higher is better).
    /// Stored as f64 for JSON serialisation (`serde_json` widens f32).
    pub score: f64,
    /// How this hit was discovered.
    pub search_type: RecallSearchType,
}

/// How a recall hit was found.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RecallSearchType {
    /// Embedding-based vector similarity search.
    Semantic,
    /// `SQLite` FTS5 full-text search.
    Fts5,
    /// Weighted combination of semantic + FTS5.
    Hybrid,
    /// Substring fallback search.
    Text,
}

/// Configuration for a recall query.
#[derive(Debug, Clone)]
pub struct RecallQueryConfig {
    /// Maximum number of results to return.
    pub max_results: usize,
    /// Minimum relevance score (f32 to match `EmbeddingStore` distances).
    pub similarity_threshold: f32,
    /// Fall back to FTS5 when semantic search is unavailable.
    pub fallback_to_fts: bool,
    /// Include key facts in results.
    pub include_key_facts: bool,
}

/// Engine that performs hybrid search across stored snapshots.
pub struct RecallEngine<'a> {
    storage: &'a Storage,
    ollama: Option<&'a LlmClient>,
    embedding_store: Option<&'a EmbeddingStore>,
    /// The model identifier (`"<provider>:<model>"`) that the current config
    /// would use for new embeddings.  When `Some`, mismatch detection is
    /// active: `check_model_mismatch` returns the stored vs. configured pair
    /// when they differ.
    configured_model_ident: Option<String>,
    /// The bare embedding model / deployment name to pass to the backend
    /// when generating the query embedding. Required for backends that do
    /// not have a baked-in default model (e.g., `AzureOpenAIBackend`). Optional because
    /// Ollama tolerates `None` by falling back to its configured default.
    embedding_model: Option<String>,
}

impl<'a> RecallEngine<'a> {
    /// Create a new recall engine.
    #[must_use]
    pub fn new(
        storage: &'a Storage,
        ollama: Option<&'a LlmClient>,
        embedding_store: Option<&'a EmbeddingStore>,
    ) -> Self {
        Self {
            storage,
            ollama,
            embedding_store,
            configured_model_ident: None,
            embedding_model: None,
        }
    }

    /// Attach the bare embedding model / deployment name. Required for
    /// Azure-routed embeddings (Azure backend errors with
    /// `DeploymentNotFound` when called with `None`); Ollama tolerates
    /// missing model and falls back to its config default.
    #[must_use]
    pub fn with_embedding_model(mut self, model: impl Into<String>) -> Self {
        self.embedding_model = Some(model.into());
        self
    }

    /// Attach the configured embedding model identifier so that mismatch
    /// detection works.  The identifier should be `"<provider>:<model>"`.
    #[must_use]
    pub fn with_model_ident(mut self, ident: impl Into<String>) -> Self {
        self.configured_model_ident = Some(ident.into());
        self
    }

    /// Check whether the stored model identifier differs from the configured one.
    ///
    /// Returns `Some((stored, configured))` when a mismatch is detected.
    /// Returns `None` when:
    /// - no embedding store is attached,
    /// - `configured_model_ident` was not set,
    /// - the database is empty / all rows carry the pre-migration sentinel, or
    /// - the identifiers match.
    #[must_use]
    pub fn check_model_mismatch(&self) -> Option<(String, String)> {
        let configured = self.configured_model_ident.as_deref()?;
        let emb_store = self.embedding_store?;
        let stored = emb_store.current_model().ok().flatten()?;
        if stored == configured {
            None
        } else {
            Some((stored, configured.to_string()))
        }
    }

    /// Run hybrid search: FTS5 first (fast), then semantic if available.
    ///
    /// FTS5 runs first because it completes in <10ms, guaranteeing baseline
    /// results even if the Ollama embedding call consumes most of the timeout.
    pub async fn query(&self, query: &str, config: &RecallQueryConfig) -> Vec<RecallHit> {
        let mut fts_hits = Vec::new();
        let mut semantic_hits = Vec::new();

        // FTS5 first — always fast (<10ms), provides baseline results
        if config.fallback_to_fts {
            fts_hits = self.try_fts(query, config);
        }

        // Then try semantic search (may be slow due to Ollama embedding)
        if let (Some(ollama), Some(emb_store)) = (self.ollama, self.embedding_store)
            && emb_store.is_vector_search_enabled()
        {
            semantic_hits = self.try_semantic(query, ollama, emb_store, config).await;
        }

        // If FTS5 was skipped and semantic found nothing, try FTS5 as last resort
        if !config.fallback_to_fts && semantic_hits.is_empty() {
            fts_hits = self.try_fts(query, config);
        }

        hybrid_merge(semantic_hits, fts_hits, config.max_results)
    }

    /// Attempt embedding-based semantic search.
    ///
    /// Returns an empty vec on any error (logged as warning).
    async fn try_semantic(
        &self,
        query: &str,
        ollama: &LlmClient,
        emb_store: &EmbeddingStore,
        config: &RecallQueryConfig,
    ) -> Vec<RecallHit> {
        // Generate embedding for the query. Pass the configured embedding
        // model so backends without a baked-in default (Azure) work.
        let embedding = match ollama.embed(query, self.embedding_model.as_deref()).await {
            Ok(emb) => emb,
            Err(e) => {
                warn!("Recall semantic embedding failed: {e}");
                return Vec::new();
            }
        };

        debug!(
            "Generated recall query embedding with {} dimensions",
            embedding.len()
        );

        // Fetch extra candidates for filtering
        let fetch_limit = config.max_results * 2;
        let similar = match emb_store.find_similar(&embedding, fetch_limit) {
            Ok(results) => results,
            Err(e) => {
                warn!("Recall vector search failed: {e}");
                return Vec::new();
            }
        };

        if similar.is_empty() {
            debug!("No similar embeddings found for recall");
            return Vec::new();
        }

        debug!("Found {} similar embeddings for recall", similar.len());

        // Convert threshold to distance: higher threshold => lower max distance
        let max_distance = distance_from_threshold(config.similarity_threshold);

        let mut hits = Vec::new();
        for (snapshot_id, distance) in similar {
            if distance > max_distance {
                debug!(
                    "Skipping snapshot {snapshot_id} with distance {distance} (above max {max_distance})"
                );
                continue;
            }

            match self.storage.get_snapshot(snapshot_id) {
                Ok(Some(snapshot)) => {
                    let score = f64::from(score_from_distance(distance));
                    hits.push(RecallHit {
                        snapshot_id,
                        session_id: snapshot.session_id.to_string(),
                        created_at: snapshot.created_at.to_rfc3339(),
                        summary: snapshot.summary,
                        key_facts: snapshot.key_facts,
                        score,
                        search_type: RecallSearchType::Semantic,
                    });
                }
                Ok(None) => {
                    debug!("Snapshot {snapshot_id} not found in storage");
                }
                Err(e) => {
                    debug!("Error fetching snapshot {snapshot_id}: {e}");
                }
            }
        }

        hits
    }

    /// Attempt FTS5 search with substring fallback.
    fn try_fts(&self, query: &str, config: &RecallQueryConfig) -> Vec<RecallHit> {
        let fetch_limit = config.max_results * 2;

        // Try FTS5 first
        match self.storage.search_snapshots_fts(query, fetch_limit) {
            Ok(fts_results) if !fts_results.is_empty() => {
                debug!("FTS5 recall returned {} results", fts_results.len());
                return fts_results
                    .into_iter()
                    .filter_map(|(snapshot, bm25_score)| {
                        let snapshot_id = snapshot.id?;
                        Some(RecallHit {
                            snapshot_id,
                            session_id: snapshot.session_id.to_string(),
                            created_at: snapshot.created_at.to_rfc3339(),
                            summary: snapshot.summary,
                            key_facts: snapshot.key_facts,
                            score: bm25_score,
                            search_type: RecallSearchType::Fts5,
                        })
                    })
                    .collect();
            }
            Ok(_) => {
                debug!("FTS5 recall returned no results, trying substring fallback");
            }
            Err(e) => {
                warn!("FTS5 recall failed, trying substring fallback: {e}");
            }
        }

        // Substring fallback
        self.try_substring_fallback(query, fetch_limit)
    }

    /// Fallback substring search across active sessions.
    fn try_substring_fallback(&self, query: &str, limit: usize) -> Vec<RecallHit> {
        let query_lower = query.chars().take(500).collect::<String>().to_lowercase();
        let mut hits = Vec::new();

        let sessions = match self.storage.list_active_sessions() {
            Ok(s) => s,
            Err(e) => {
                warn!("Failed to list sessions for substring recall: {e}");
                return Vec::new();
            }
        };

        for session in sessions.iter().take(limit.max(5)) {
            if let Ok(snapshots) = self.storage.get_snapshots_by_session(session.id.as_str()) {
                for snapshot in snapshots.iter().take(3) {
                    let matches_summary = snapshot
                        .summary
                        .as_ref()
                        .is_some_and(|s| s.to_lowercase().contains(&query_lower));
                    let matches_facts = snapshot
                        .key_facts
                        .as_ref()
                        .is_some_and(|s| s.to_lowercase().contains(&query_lower));

                    if (matches_summary || matches_facts)
                        && let Some(snapshot_id) = snapshot.id
                    {
                        hits.push(RecallHit {
                            snapshot_id,
                            session_id: snapshot.session_id.to_string(),
                            created_at: snapshot.created_at.to_rfc3339(),
                            summary: snapshot.summary.clone(),
                            key_facts: snapshot.key_facts.clone(),
                            score: 0.5, // Default relevance for substring matches
                            search_type: RecallSearchType::Text,
                        });
                    }

                    if hits.len() >= limit {
                        return hits;
                    }
                }
            }
        }

        hits
    }
}

/// Convert a similarity threshold (0.0-1.0) to a distance ceiling.
///
/// Higher threshold means stricter matching (lower max distance).
/// Formula: `(1.0 - threshold) * 2.0`
fn distance_from_threshold(threshold: f32) -> f32 {
    (1.0 - threshold) * 2.0
}

/// Convert a vector distance to a relevance score (0.0-1.0).
///
/// Lower distance = higher score.
fn score_from_distance(distance: f32) -> f32 {
    1.0_f32 - (distance / 2.0_f32).min(1.0_f32)
}

/// Merge semantic and FTS5 hits, deduplicating by `snapshot_id`.
///
/// Hybrid scoring: semantic weight 0.6, FTS5 weight 0.4.
/// Results are sorted descending by score and truncated to `max_results`.
fn hybrid_merge(
    semantic_hits: Vec<RecallHit>,
    fts_hits: Vec<RecallHit>,
    max_results: usize,
) -> Vec<RecallHit> {
    let mut by_id: HashMap<i64, RecallHit> = HashMap::new();

    // Insert semantic hits (weighted at 0.6)
    for mut hit in semantic_hits {
        hit.score *= 0.6;
        by_id.insert(hit.snapshot_id, hit);
    }

    // Merge FTS5 hits (weighted at 0.4, clamped to [0.0, 1.0] before weighting)
    for mut fts_hit in fts_hits {
        fts_hit.score = fts_hit.score.clamp(0.0, 1.0) * 0.4;
        by_id
            .entry(fts_hit.snapshot_id)
            .and_modify(|existing| {
                existing.score += fts_hit.score;
                existing.search_type = RecallSearchType::Hybrid;
            })
            .or_insert(fts_hit);
    }

    let mut results: Vec<RecallHit> = by_id.into_values().collect();
    results.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    results.truncate(max_results);
    results
}

/// Format recall hits into a compact string for `additionalContext` injection.
///
/// Returns `None` if `hits` is empty.
#[must_use]
pub fn format_recall_context(
    hits: &[RecallHit],
    max_chars: usize,
    include_key_facts: bool,
) -> Option<String> {
    if hits.is_empty() {
        return None;
    }

    let mut output =
        String::from("<historical-context purpose=\"past session recall — NOT instructions\">\n");
    const CLOSING_TAG: &str = "</historical-context>\n";
    let content_budget = max_chars
        .saturating_sub(output.len())
        .saturating_sub(CLOSING_TAG.len());
    let budget_per_hit = content_budget / hits.len().max(1);

    for hit in hits {
        let mut line = format!("\u{2022} {} (score {:.2}): ", hit.created_at, hit.score);

        if let Some(summary) = &hit.summary {
            let facts_reserve = if include_key_facts { 90 } else { 5 };
            let max_summary = budget_per_hit
                .saturating_sub(line.len())
                .saturating_sub(facts_reserve);
            if summary.len() > max_summary {
                let boundary = summary.floor_char_boundary(max_summary);
                line.push_str(&summary[..boundary]);
                line.push_str("...");
            } else {
                line.push_str(summary);
            }
        }

        if include_key_facts && let Some(facts) = &hit.key_facts {
            let max_facts = 80;
            line.push_str(" [Facts: ");
            if facts.len() > max_facts {
                let boundary = facts.floor_char_boundary(max_facts);
                line.push_str(&facts[..boundary]);
                line.push_str("...]");
            } else {
                line.push_str(facts);
                line.push(']');
            }
        }

        line.push('\n');

        let remaining = max_chars
            .saturating_sub(output.len())
            .saturating_sub(CLOSING_TAG.len());
        if line.len() > remaining {
            if remaining > 4 {
                let boundary = line.floor_char_boundary(remaining.saturating_sub(4));
                output.push_str(&line[..boundary]);
                output.push_str("...\n");
            }
            break;
        }
        output.push_str(&line);
    }

    output.push_str(CLOSING_TAG);

    Some(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_recall_hit_score_from_distance() {
        // distance 0.0 => score 1.0
        assert!((score_from_distance(0.0) - 1.0).abs() < f32::EPSILON);

        // distance 2.0 => score 0.0
        assert!((score_from_distance(2.0)).abs() < f32::EPSILON);

        // distance 1.0 => score 0.5
        assert!((score_from_distance(1.0) - 0.5).abs() < f32::EPSILON);

        // distance > 2.0 clamped to score 0.0
        assert!((score_from_distance(3.0)).abs() < f32::EPSILON);
    }

    #[test]
    fn test_distance_from_threshold() {
        // threshold 0.0 => max distance 2.0
        assert!((distance_from_threshold(0.0) - 2.0).abs() < f32::EPSILON);

        // threshold 1.0 => max distance 0.0
        assert!((distance_from_threshold(1.0)).abs() < f32::EPSILON);

        // threshold 0.35 => max distance 1.3
        assert!((distance_from_threshold(0.35) - 1.3).abs() < 0.001);
    }

    #[test]
    fn test_hybrid_merge_dedup_by_snapshot_id() {
        let sem = vec![make_hit(1, 0.9, RecallSearchType::Semantic)];
        let fts = vec![make_hit(1, 0.8, RecallSearchType::Fts5)];

        let merged = hybrid_merge(sem, fts, 10);
        assert_eq!(merged.len(), 1, "duplicate snapshot_id should be merged");
        assert_eq!(merged[0].search_type, RecallSearchType::Hybrid);
        // 0.9 * 0.6 + 0.8 * 0.4 = 0.54 + 0.32 = 0.86
        let expected = 0.9 * 0.6 + 0.8 * 0.4;
        assert!(
            (merged[0].score - expected).abs() < 1e-10,
            "deduped hybrid score should be sem*0.6 + fts*0.4, got {}",
            merged[0].score
        );
    }

    #[test]
    fn test_hybrid_merge_weights() {
        let sem = vec![make_hit(1, 0.9, RecallSearchType::Semantic)];
        let fts = vec![make_hit(1, 0.8, RecallSearchType::Fts5)];

        let merged = hybrid_merge(sem, fts, 10);
        // 0.9 * 0.6 + 0.8 * 0.4 = 0.54 + 0.32 = 0.86
        let expected = 0.9 * 0.6 + 0.8 * 0.4;
        assert!(
            (merged[0].score - expected).abs() < 1e-10,
            "hybrid score should be sem*0.6 + fts*0.4, got {}",
            merged[0].score
        );
    }

    #[test]
    fn test_hybrid_merge_single_source_weighting() {
        // Semantic-only hits should be weighted at 0.6
        let sem = vec![make_hit(1, 0.9, RecallSearchType::Semantic)];
        let merged_sem = hybrid_merge(sem, Vec::new(), 10);
        let expected_sem = 0.9 * 0.6;
        assert!(
            (merged_sem[0].score - expected_sem).abs() < 1e-10,
            "semantic-only score should be 0.9*0.6={expected_sem}, got {}",
            merged_sem[0].score
        );

        // FTS-only hits should be weighted at 0.4
        let fts = vec![make_hit(2, 0.8, RecallSearchType::Fts5)];
        let merged_fts = hybrid_merge(Vec::new(), fts, 10);
        let expected_fts = 0.8 * 0.4;
        assert!(
            (merged_fts[0].score - expected_fts).abs() < 1e-10,
            "fts-only score should be 0.8*0.4={expected_fts}, got {}",
            merged_fts[0].score
        );

        // FTS scores > 1.0 should be clamped before weighting
        let fts_high = vec![make_hit(3, 1.5, RecallSearchType::Fts5)];
        let merged_clamped = hybrid_merge(Vec::new(), fts_high, 10);
        let expected_clamped = 1.0 * 0.4; // clamped to 1.0 then * 0.4
        assert!(
            (merged_clamped[0].score - expected_clamped).abs() < 1e-10,
            "clamped fts score should be 1.0*0.4={expected_clamped}, got {}",
            merged_clamped[0].score
        );
    }

    #[test]
    fn test_hybrid_merge_sorts_descending() {
        let sem = vec![
            make_hit(1, 0.5, RecallSearchType::Semantic),
            make_hit(2, 0.9, RecallSearchType::Semantic),
            make_hit(3, 0.7, RecallSearchType::Semantic),
        ];
        let fts = Vec::new();

        let merged = hybrid_merge(sem, fts, 10);
        // After 0.6 weighting: id2=0.54, id3=0.42, id1=0.30
        assert_eq!(merged[0].snapshot_id, 2);
        assert_eq!(merged[1].snapshot_id, 3);
        assert_eq!(merged[2].snapshot_id, 1);
    }

    #[test]
    fn test_hybrid_merge_takes_top_k() {
        let sem = vec![
            make_hit(1, 0.9, RecallSearchType::Semantic),
            make_hit(2, 0.8, RecallSearchType::Semantic),
            make_hit(3, 0.7, RecallSearchType::Semantic),
        ];

        let merged = hybrid_merge(sem, Vec::new(), 2);
        assert_eq!(merged.len(), 2);
        assert_eq!(merged[0].snapshot_id, 1);
        assert_eq!(merged[1].snapshot_id, 2);
    }

    #[test]
    fn test_format_context_under_budget() {
        let hits = vec![
            make_hit(1, 0.9, RecallSearchType::Semantic),
            make_hit(2, 0.8, RecallSearchType::Fts5),
        ];

        let max_chars = 500;
        let result = format_recall_context(&hits, max_chars, true);
        assert!(result.is_some());
        let text = result.unwrap();
        assert!(
            text.len() <= max_chars,
            "output {} chars exceeds budget {max_chars}",
            text.len()
        );
        assert!(text.starts_with("<historical-context "));
    }

    #[test]
    fn test_format_context_empty_returns_none() {
        let result = format_recall_context(&[], 1000, true);
        assert!(result.is_none());
    }

    #[test]
    fn test_format_context_multibyte_no_panic() {
        let mut hit = make_hit(1, 0.9, RecallSearchType::Semantic);
        hit.summary = Some("日本語テスト文字列の概要".to_string());
        hit.key_facts = Some("重要な事実：データベースの設計".to_string());
        let result = format_recall_context(&[hit], 100, true);
        assert!(result.is_some());
    }

    #[test]
    fn test_format_context_respects_budget_with_long_summary() {
        let mut hit = make_hit(1, 0.9, RecallSearchType::Semantic);
        hit.summary = Some("A".repeat(2000));
        let result = format_recall_context(&[hit], 200, false);
        let text = result.unwrap();
        assert!(
            text.len() <= 200,
            "output {} exceeded budget 200",
            text.len()
        );
    }

    #[test]
    fn test_format_context_excludes_facts_when_disabled() {
        let mut hit = make_hit(1, 0.9, RecallSearchType::Semantic);
        hit.key_facts = Some("Important fact data".to_string());

        let with_facts = format_recall_context(&[hit.clone()], 2000, true).unwrap();
        let without_facts = format_recall_context(&[hit], 2000, false).unwrap();

        assert!(
            with_facts.contains("[Facts:"),
            "should include facts when enabled"
        );
        assert!(
            !without_facts.contains("[Facts:"),
            "should exclude facts when disabled"
        );
    }

    // --- RecallEngine integration tests ---

    /// Helper to create in-memory storage populated with a session and snapshot.
    fn setup_test_storage(summary: &str, key_facts: &str) -> (crate::storage::Storage, i64) {
        use crate::types::{Session, SessionId, Snapshot, SnapshotTrigger};

        let storage = crate::storage::Storage::open_in_memory().unwrap();

        let session = Session::new(
            SessionId::new("test-session-1"),
            "/tmp/test-project".to_string(),
        );
        storage.create_session(&session).unwrap();

        let mut snapshot = Snapshot::new(SessionId::new("test-session-1"), SnapshotTrigger::Auto);
        snapshot.summary = Some(summary.to_string());
        snapshot.key_facts = Some(key_facts.to_string());

        let snapshot_id = storage.create_snapshot(&snapshot).unwrap();
        (storage, snapshot_id)
    }

    #[tokio::test]
    async fn test_recall_engine_fts_query() {
        let (storage, _snapshot_id) =
            setup_test_storage("Implemented authentication module", "auth, JWT, tokens");

        let engine = RecallEngine::new(&storage, None, None);
        let config = RecallQueryConfig {
            max_results: 5,
            similarity_threshold: 0.35,
            fallback_to_fts: true,
            include_key_facts: true,
        };

        let hits = engine.query("authentication", &config).await;
        assert!(
            !hits.is_empty(),
            "FTS query for 'authentication' should find the snapshot"
        );
        assert_eq!(hits[0].session_id, "test-session-1");
        assert!(
            hits[0].search_type == RecallSearchType::Fts5
                || hits[0].search_type == RecallSearchType::Text,
            "hit should come from FTS or text search, got {:?}",
            hits[0].search_type,
        );
    }

    #[tokio::test]
    async fn test_recall_engine_query_no_results() {
        let (storage, _) = setup_test_storage("Database migration completed", "postgres, schema");

        let engine = RecallEngine::new(&storage, None, None);
        let config = RecallQueryConfig {
            max_results: 5,
            similarity_threshold: 0.35,
            fallback_to_fts: true,
            include_key_facts: true,
        };

        let hits = engine.query("xyzzy_nonexistent_topic_qqq", &config).await;
        assert!(
            hits.is_empty(),
            "query for gibberish should return no results, got {} hits",
            hits.len()
        );
    }

    #[tokio::test]
    async fn test_recall_engine_fallback_path() {
        // When fallback_to_fts=false and no semantic store is available,
        // the engine should still try FTS as a last resort (lines 105-107).
        let (storage, _) = setup_test_storage(
            "Configured Redis caching layer",
            "redis, cache, performance",
        );

        let engine = RecallEngine::new(&storage, None, None);
        let config = RecallQueryConfig {
            max_results: 5,
            similarity_threshold: 0.35,
            fallback_to_fts: false,
            include_key_facts: true,
        };

        // semantic_hits will be empty (no ollama/embedding_store),
        // so the code at line 105-107 should trigger FTS as last resort
        let hits = engine.query("Redis", &config).await;
        assert!(
            !hits.is_empty(),
            "fallback path should still find results via FTS last-resort"
        );
    }

    // --- T38: RecallEngine path tests ---

    #[tokio::test]
    async fn test_t38_semantic_path_with_mock_ollama() {
        // Arrange: seed storage with a snapshot, then mock Ollama to return an
        // embedding so that the semantic path in try_semantic() executes.
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let (storage, snapshot_id) = setup_test_storage(
            "Rust async runtime tokio integration",
            "tokio, async, runtime",
        );

        // Ensure sqlite-vec is registered for this test process.
        crate::init_sqlite_vec();

        let emb_store = crate::embeddings::EmbeddingStore::open_in_memory().unwrap();

        // Store the embedding for the seeded snapshot so find_similar can
        // return it when queried.
        let stored_emb = vec![1.0f32; crate::embeddings::DEFAULT_EMBEDDING_DIM];
        emb_store.store_embedding(snapshot_id, stored_emb).unwrap();

        // Mock Ollama: return the same embedding vector for any /api/embeddings
        // request so the query embedding matches the stored one exactly.
        let mock_embedding_json = {
            let values = vec!["1.0"; crate::embeddings::DEFAULT_EMBEDDING_DIM];
            format!("{{\"embedding\":[{}]}}", values.join(","))
        };
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/embeddings"))
            .respond_with(
                ResponseTemplate::new(200).set_body_raw(mock_embedding_json, "application/json"),
            )
            .mount(&server)
            .await;

        let ollama_config = crate::config::OllamaConfig {
            host: server.uri(),
            max_retries: 0,
            ..crate::config::OllamaConfig::default()
        };
        let ollama = crate::llm::LlmClient::Ollama(
            crate::llm::OllamaBackend::new(ollama_config)
                .expect("failed to create OllamaBackend for test"),
        );

        let engine = RecallEngine::new(&storage, Some(&ollama), Some(&emb_store));
        let config = RecallQueryConfig {
            max_results: 5,
            similarity_threshold: 0.0, // accept all distances
            fallback_to_fts: false,
            include_key_facts: true,
        };

        // Act
        let hits = engine.query("tokio async", &config).await;

        // Assert: at least one semantic hit should be returned
        assert!(
            !hits.is_empty(),
            "semantic path should return results when Ollama mock returns a matching embedding"
        );
        assert!(
            hits.iter().any(|h| h.snapshot_id == snapshot_id),
            "results should include the seeded snapshot_id={snapshot_id}"
        );
    }

    #[tokio::test]
    async fn test_t38_substring_fallback_when_no_ollama() {
        // Arrange: seed storage with a recognisable summary; provide no Ollama
        // client so the semantic path is skipped and the substring fallback runs.
        let (storage, _) = setup_test_storage(
            "continuous integration pipeline configuration",
            "CI, pipeline, yaml",
        );

        let engine = RecallEngine::new(&storage, None, None);
        let config = RecallQueryConfig {
            max_results: 5,
            similarity_threshold: 0.35,
            fallback_to_fts: true,
            include_key_facts: false,
        };

        // Act — "pipeline" appears in the seeded summary
        let hits = engine.query("pipeline", &config).await;

        // Assert: substring/FTS fallback must find the seeded snapshot
        assert!(
            !hits.is_empty(),
            "substring/FTS fallback should return results when query matches stored summary"
        );
        assert!(
            hits.iter().any(|h| {
                h.search_type == RecallSearchType::Fts5 || h.search_type == RecallSearchType::Text
            }),
            "hits should come from FTS5 or text search, got: {:?}",
            hits.iter().map(|h| h.search_type).collect::<Vec<_>>()
        );
    }

    #[tokio::test]
    async fn test_t38_empty_storage_returns_empty() {
        // Arrange: completely empty in-memory storage (no sessions, no snapshots)
        let storage = crate::storage::Storage::open_in_memory().unwrap();

        let engine = RecallEngine::new(&storage, None, None);
        let config = RecallQueryConfig {
            max_results: 10,
            similarity_threshold: 0.35,
            fallback_to_fts: true,
            include_key_facts: false,
        };

        // Act
        let hits = engine.query("anything", &config).await;

        // Assert
        assert!(
            hits.is_empty(),
            "query against empty storage must return an empty result set"
        );
    }

    #[tokio::test]
    async fn test_t38_no_match_returns_empty() {
        // Arrange: seed storage with content that will NOT match the query term
        let (storage, _) = setup_test_storage(
            "GraphQL schema design and resolver patterns",
            "graphql, schema, resolver",
        );

        let engine = RecallEngine::new(&storage, None, None);
        let config = RecallQueryConfig {
            max_results: 10,
            similarity_threshold: 0.35,
            fallback_to_fts: true,
            include_key_facts: false,
        };

        // Act — this term does not appear anywhere in the seeded data
        let hits = engine.query("xyzzy_no_match_qqqqqq", &config).await;

        // Assert
        assert!(
            hits.is_empty(),
            "query with a non-matching term must return an empty result set, got {} hits",
            hits.len()
        );
    }

    /// Helper to construct a test `RecallHit`.
    fn make_hit(snapshot_id: i64, score: f64, search_type: RecallSearchType) -> RecallHit {
        RecallHit {
            snapshot_id,
            session_id: format!("session-{snapshot_id}"),
            created_at: "2026-01-01T00:00:00+00:00".to_string(),
            summary: Some(format!("Summary for snapshot {snapshot_id}")),
            key_facts: Some(format!("Facts for snapshot {snapshot_id}")),
            score,
            search_type,
        }
    }

    /// Regression for the 0.7.1 bug: `auto_recall` passed `None` for the
    /// embeddings model, which Azure rejects with `DeploymentNotFound`.
    /// 0.7.2 plumbs the configured model through `with_embedding_model`.
    /// This test asserts the builder stores the model so `try_semantic`
    /// will pass it to the backend.
    #[test]
    fn embedding_model_builder_persists_value() {
        let storage = Storage::open_in_memory().unwrap();
        let engine =
            RecallEngine::new(&storage, None, None).with_embedding_model("text-embedding-3-small");
        assert_eq!(
            engine.embedding_model.as_deref(),
            Some("text-embedding-3-small")
        );
    }

    #[test]
    fn embedding_model_default_is_none_for_back_compat() {
        let storage = Storage::open_in_memory().unwrap();
        let engine = RecallEngine::new(&storage, None, None);
        assert!(
            engine.embedding_model.is_none(),
            "default must be None so existing callers keep relying on Ollama's baked-in default"
        );
    }
}
