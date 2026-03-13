//! Recall engine for hybrid semantic + FTS5 search across snapshots.
//!
//! Shared logic used by both the MCP `clx_recall` tool and the
//! `UserPromptSubmit` hook for auto-context recall.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use crate::embeddings::EmbeddingStore;
use crate::ollama::OllamaClient;
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
    ollama: Option<&'a OllamaClient>,
    embedding_store: Option<&'a EmbeddingStore>,
}

impl<'a> RecallEngine<'a> {
    /// Create a new recall engine.
    #[must_use]
    pub fn new(
        storage: &'a Storage,
        ollama: Option<&'a OllamaClient>,
        embedding_store: Option<&'a EmbeddingStore>,
    ) -> Self {
        Self {
            storage,
            ollama,
            embedding_store,
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
        ollama: &OllamaClient,
        emb_store: &EmbeddingStore,
        config: &RecallQueryConfig,
    ) -> Vec<RecallHit> {
        // Generate embedding for the query
        let embedding = match ollama.embed(query, None).await {
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
        let query_lower = query.to_lowercase();
        let mut hits = Vec::new();

        let sessions = match self.storage.list_active_sessions() {
            Ok(s) => s,
            Err(e) => {
                warn!("Failed to list sessions for substring recall: {e}");
                return Vec::new();
            }
        };

        for session in sessions.iter().take(5) {
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

    let mut output = String::from("[Relevant past context]:\n");
    let budget_per_hit = max_chars.saturating_sub(output.len()) / hits.len();

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

        if include_key_facts
            && let Some(facts) = &hit.key_facts
        {
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

        let remaining = max_chars.saturating_sub(output.len());
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
        assert!(text.starts_with("[Relevant past context]:"));
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
}
