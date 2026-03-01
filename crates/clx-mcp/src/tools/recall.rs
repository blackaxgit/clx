//! `clx_recall` tool — Semantic search for relevant context.

use serde_json::{Value, json};
use std::collections::HashMap;
use std::time::Duration;
use tracing::{debug, error, warn};

use clx_core::embeddings::EmbeddingStore;
use clx_core::ollama::OllamaClient;
use clx_core::types::Snapshot;

use crate::server::{
    EMBEDDING_TIMEOUT_MS, MAX_SEMANTIC_RESULTS, McpServer, SEMANTIC_DISTANCE_THRESHOLD,
    SearchResult,
};
use crate::validation::{MAX_QUERY_LEN, validate_string_param};

impl McpServer {
    /// `clx_recall` - Semantic search for relevant context
    ///
    /// Search strategy:
    /// 1. Try embedding-based semantic search if Ollama and sqlite-vec are available
    /// 2. Perform FTS5/text-based search as supplement or fallback
    /// 3. Hybrid merge: semantic weight 0.6, FTS5 weight 0.4
    /// 4. Deduplicate by `snapshot_id`, keeping highest combined score
    pub(crate) fn tool_recall(&self, args: &Value) -> Result<Value, (i32, String)> {
        let query = validate_string_param(args, "query", MAX_QUERY_LEN)?;

        debug!("Recall query: {}", query);

        // Collect results keyed by snapshot_id for hybrid merging
        // Each entry: (snapshot_id -> (entry, semantic_score, text_score))
        type ScoredEntry = (HashMap<String, Value>, Option<f64>, Option<f64>);
        let mut scored_results: HashMap<i64, ScoredEntry> = HashMap::new();
        // Results without snapshot_id (cannot be merged)
        let mut unkeyed_results: Vec<HashMap<String, Value>> = Vec::new();
        let mut used_semantic_search = false;

        // Try semantic search first if embedding infrastructure is available
        if let (Some(ollama), Some(embedding_store)) = (&self.ollama_client, &self.embedding_store)
            && embedding_store.is_vector_search_enabled()
        {
            match self.try_semantic_search(&query, ollama, embedding_store) {
                Ok(semantic_results) => {
                    if !semantic_results.is_empty() {
                        used_semantic_search = true;
                        debug!(
                            "Semantic search returned {} results",
                            semantic_results.len()
                        );
                        for (entry, snapshot_id) in semantic_results {
                            let score = entry
                                .get("relevance_score")
                                .and_then(serde_json::Value::as_f64)
                                .unwrap_or(0.5);

                            if let Some(id) = snapshot_id {
                                scored_results
                                    .entry(id)
                                    .and_modify(|(_, sem, _)| *sem = Some(score))
                                    .or_insert((entry.clone(), Some(score), None));
                            } else {
                                unkeyed_results.push(entry);
                            }
                        }
                    }
                }
                Err(e) => {
                    warn!("Semantic search failed, falling back to text search: {}", e);
                }
            }
        }

        // Also perform text-based search (FTS5 or substring fallback)
        let text_results = self.text_based_search(&query);

        for (entry, snapshot_id) in text_results {
            let score = entry
                .get("relevance_score")
                .and_then(serde_json::Value::as_f64)
                .unwrap_or(0.5);

            if let Some(id) = snapshot_id {
                scored_results
                    .entry(id)
                    .and_modify(|(_, _, txt)| *txt = Some(score))
                    .or_insert((entry.clone(), None, Some(score)));
            } else {
                unkeyed_results.push(entry);
            }
        }

        // Compute hybrid scores and build final result list
        let mut final_results: Vec<(f64, HashMap<String, Value>)> = Vec::new();

        for (_snapshot_id, (mut entry, semantic_score, text_score)) in scored_results {
            // Determine the original text search type before mutating the entry
            let original_search_type = entry
                .get("search_type")
                .and_then(|v| v.as_str())
                .unwrap_or("fts5")
                .to_string();

            let (combined_score, search_type) = match (semantic_score, text_score) {
                (Some(sem), Some(txt)) => {
                    // Hybrid: weighted combination
                    let combined = sem * 0.6 + txt * 0.4;
                    (combined, "hybrid".to_string())
                }
                (Some(sem), None) => (sem, "semantic".to_string()),
                (None, Some(txt)) => (txt, original_search_type),
                (None, None) => (0.5, "text".to_string()),
            };

            entry.insert("relevance_score".to_string(), json!(combined_score));
            entry.insert("search_type".to_string(), json!(search_type));
            final_results.push((combined_score, entry));
        }

        // Add unkeyed results with their original scores
        for entry in unkeyed_results {
            let score = entry
                .get("relevance_score")
                .and_then(serde_json::Value::as_f64)
                .unwrap_or(0.5);
            final_results.push((score, entry));
        }

        // Sort by score descending (highest relevance first)
        final_results.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));

        let results: Vec<HashMap<String, Value>> =
            final_results.into_iter().map(|(_, entry)| entry).collect();

        // Build response text
        let response_text = if results.is_empty() {
            format!("No relevant context found for query: {query}")
        } else {
            let search_method = if used_semantic_search {
                "semantic + fts5 (hybrid)"
            } else {
                "fts5"
            };
            let header = format!(
                "Found {} results (search method: {})\n\n",
                results.len(),
                search_method
            );
            header + &serde_json::to_string_pretty(&results).unwrap_or_else(|_| "[]".to_string())
        };

        Ok(json!({
            "content": [{
                "type": "text",
                "text": response_text
            }]
        }))
    }

    /// Attempt semantic search using embeddings
    ///
    /// Returns a vector of (result entry, optional `snapshot_id`) tuples
    pub(crate) fn try_semantic_search(
        &self,
        query: &str,
        ollama: &OllamaClient,
        embedding_store: &EmbeddingStore,
    ) -> std::result::Result<Vec<SearchResult>, String> {
        // Generate embedding for the query with timeout
        let query_embedding = self.runtime.block_on(async {
            tokio::time::timeout(
                Duration::from_millis(EMBEDDING_TIMEOUT_MS),
                ollama.embed(query, None),
            )
            .await
        });

        let query_embedding = match query_embedding {
            Ok(Ok(embedding)) => embedding,
            Ok(Err(e)) => {
                return Err(format!("Ollama embedding error: {e}"));
            }
            Err(_) => {
                return Err(format!(
                    "Embedding generation timed out after {EMBEDDING_TIMEOUT_MS}ms"
                ));
            }
        };

        debug!(
            "Generated query embedding with {} dimensions",
            query_embedding.len()
        );

        // Search for similar embeddings
        let similar = embedding_store
            .find_similar(&query_embedding, MAX_SEMANTIC_RESULTS)
            .map_err(|e| format!("Vector search error: {e}"))?;

        if similar.is_empty() {
            debug!("No similar embeddings found");
            return Ok(Vec::new());
        }

        debug!("Found {} similar embeddings", similar.len());

        // Fetch snapshot details for each result
        let mut results = Vec::new();
        for (snapshot_id, distance) in similar {
            // Filter out low-relevance results
            if distance > SEMANTIC_DISTANCE_THRESHOLD {
                debug!(
                    "Skipping snapshot {} with distance {} (above threshold {})",
                    snapshot_id, distance, SEMANTIC_DISTANCE_THRESHOLD
                );
                continue;
            }

            match self.storage.get_snapshot(snapshot_id) {
                Ok(Some(snapshot)) => {
                    let mut entry = HashMap::new();
                    entry.insert("session_id".to_string(), json!(snapshot.session_id));
                    entry.insert(
                        "created_at".to_string(),
                        json!(snapshot.created_at.to_rfc3339()),
                    );
                    entry.insert(
                        "relevance_score".to_string(),
                        json!(1.0 - (distance / 2.0).min(1.0)),
                    );
                    entry.insert("search_type".to_string(), json!("semantic"));

                    if let Some(summary) = &snapshot.summary {
                        entry.insert("summary".to_string(), json!(summary));
                    }
                    if let Some(facts) = &snapshot.key_facts {
                        entry.insert("key_facts".to_string(), json!(facts));
                    }
                    results.push((entry, Some(snapshot_id)));
                }
                Ok(None) => {
                    debug!("Snapshot {} not found in storage", snapshot_id);
                }
                Err(e) => {
                    debug!("Error fetching snapshot {}: {}", snapshot_id, e);
                }
            }
        }

        Ok(results)
    }

    /// Perform text-based search across snapshots
    ///
    /// Tries FTS5 full-text search first for BM25-ranked results.
    /// Falls back to substring matching for pre-v3 databases or when FTS5 fails.
    ///
    /// Returns a vector of (result entry, optional `snapshot_id`) tuples
    pub(crate) fn text_based_search(&self, query: &str) -> Vec<SearchResult> {
        // Try FTS5 search first
        match self.storage.search_snapshots_fts(query, 10) {
            Ok(fts_results) if !fts_results.is_empty() => {
                debug!("FTS5 search returned {} results", fts_results.len());
                return fts_results
                    .into_iter()
                    .map(|(snapshot, score)| {
                        let snapshot_id = snapshot.id;
                        let mut entry = HashMap::new();
                        entry.insert("session_id".to_string(), json!(snapshot.session_id));
                        entry.insert(
                            "created_at".to_string(),
                            json!(snapshot.created_at.to_rfc3339()),
                        );
                        entry.insert("relevance_score".to_string(), json!(score));
                        entry.insert("search_type".to_string(), json!("fts5"));

                        if let Some(summary) = &snapshot.summary {
                            entry.insert("summary".to_string(), json!(summary));
                        }
                        if let Some(facts) = &snapshot.key_facts {
                            entry.insert("key_facts".to_string(), json!(facts));
                        }
                        (entry, snapshot_id)
                    })
                    .collect();
            }
            Ok(_) => {
                debug!("FTS5 search returned no results, falling back to substring search");
            }
            Err(e) => {
                warn!(
                    "FTS5 search failed, falling back to substring search: {}",
                    e
                );
            }
        }

        // Fallback: substring-based search for pre-v3 databases
        self.text_based_search_fallback(query)
    }

    /// Fallback substring-based search for pre-v3 databases
    pub(crate) fn text_based_search_fallback(&self, query: &str) -> Vec<SearchResult> {
        let mut results = Vec::new();
        let query_lower = query.to_lowercase();

        // Search current session first
        if let Some(session_id) = &self.session_id {
            match self.storage.get_snapshots_by_session(session_id.as_str()) {
                Ok(snapshots) => {
                    for snapshot in snapshots.iter().take(5) {
                        if let Some(entry) = self.match_snapshot_text(snapshot, &query_lower) {
                            results.push((entry, snapshot.id));
                        }
                    }
                }
                Err(e) => {
                    error!("Failed to get snapshots: {}", e);
                }
            }
        }

        // Search across all active sessions
        match self.storage.list_active_sessions() {
            Ok(sessions) => {
                for session in sessions.iter().take(3) {
                    if let Ok(snapshots) =
                        self.storage.get_snapshots_by_session(session.id.as_str())
                    {
                        for snapshot in snapshots.iter().take(3) {
                            if let Some(entry) = self.match_snapshot_text(snapshot, &query_lower) {
                                results.push((entry, snapshot.id));
                            }
                        }
                    }
                }
            }
            Err(e) => {
                error!("Failed to list sessions: {}", e);
            }
        }

        results
    }

    /// Check if a snapshot matches the query text and build result entry
    #[allow(clippy::unused_self)] // Will use self for configurable matching
    pub(crate) fn match_snapshot_text(
        &self,
        snapshot: &Snapshot,
        query_lower: &str,
    ) -> Option<HashMap<String, Value>> {
        let matches_summary = snapshot
            .summary
            .as_ref()
            .is_some_and(|s| s.to_lowercase().contains(query_lower));
        let matches_facts = snapshot
            .key_facts
            .as_ref()
            .is_some_and(|s| s.to_lowercase().contains(query_lower));

        if matches_summary || matches_facts {
            let mut entry = HashMap::new();
            entry.insert("session_id".to_string(), json!(snapshot.session_id));
            entry.insert(
                "created_at".to_string(),
                json!(snapshot.created_at.to_rfc3339()),
            );
            entry.insert("search_type".to_string(), json!("text"));

            if let Some(summary) = &snapshot.summary {
                entry.insert("summary".to_string(), json!(summary));
            }
            if let Some(facts) = &snapshot.key_facts {
                entry.insert("key_facts".to_string(), json!(facts));
            }
            Some(entry)
        } else {
            None
        }
    }
}
