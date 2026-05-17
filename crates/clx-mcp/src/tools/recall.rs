//! `clx_recall` tool - Semantic search for relevant context.
//!
//! Delegates to `RecallEngine` for hybrid semantic + FTS5 search,
//! then formats results as verbose JSON for the MCP protocol.

use std::collections::HashMap;

use serde_json::{Value, json};
use tracing::debug;

use clx_core::config::Config;
use clx_core::recall::{LlmQueryEmbedder, RecallEngine, RecallQueryConfig, RecallSearchType};
use clx_core::storage::StorageSnapshotRepo;

use crate::server::{MAX_SEMANTIC_RESULTS, McpServer, SEMANTIC_DISTANCE_THRESHOLD};
use crate::validation::{MAX_QUERY_LEN, validate_string_param};

impl McpServer {
    /// `clx_recall` - Semantic search for relevant context
    ///
    /// Search strategy (via `RecallEngine`):
    /// 1. Try embedding-based semantic search if Ollama and sqlite-vec are available
    /// 2. Perform FTS5/text-based search as supplement or fallback
    /// 3. Hybrid merge: semantic weight 0.6, FTS5 weight 0.4
    /// 4. Deduplicate by `snapshot_id`, keeping highest combined score
    pub(crate) fn tool_recall(&self, args: &Value) -> Result<Value, (i32, String)> {
        let query = validate_string_param(args, "query", MAX_QUERY_LEN)?;

        debug!("Recall query: {}", query);

        let auto_recall = Config::load().unwrap_or_default().auto_recall;
        let reranker = auto_recall
            .reranker_enabled
            .then(|| clx_core::recall::FastembedReranker::new(clx_core::paths::model_cache_dir()));

        // Build domain ports (Hexagonal Architecture, 0.8.0). Infrastructure
        // types are confined to the adapters.
        let repo = StorageSnapshotRepo::new(&self.storage, self.embedding_store.as_ref());
        let embedder = self
            .ollama_client
            .as_ref()
            .map(|client| LlmQueryEmbedder::new(client, Some(self.embed_model.as_str())));

        let mut engine = RecallEngine::new(&repo);
        if let Some(ref e) = embedder {
            engine = engine.with_embedder(e);
        }
        if let Some(reranker) = reranker.as_ref() {
            engine = engine.with_reranker(reranker);
        }

        // MCP recall uses a more permissive threshold (0.25) than auto-recall (0.35)
        // because it is user-invoked and benefits from broader results.
        let config = RecallQueryConfig {
            max_results: MAX_SEMANTIC_RESULTS,
            similarity_threshold: 1.0 - (SEMANTIC_DISTANCE_THRESHOLD / 2.0),
            fallback_to_fts: true,
            include_key_facts: auto_recall.include_key_facts,
            rrf_enabled: auto_recall.rrf_enabled,
            rrf_k: auto_recall.rrf_k,
            time_decay_half_life_days: auto_recall.time_decay_half_life_days,
            percentile_gate: query_percentile_gate(auto_recall.percentile_gate),
            reranker_enabled: auto_recall.reranker_enabled,
            reranker_timeout_ms: auto_recall.reranker_timeout_ms,
            ..Default::default()
        };

        let hits = self.runtime.block_on(engine.query(&query, &config));

        let has_semantic = hits.iter().any(|h| {
            matches!(
                h.search_type,
                RecallSearchType::Semantic | RecallSearchType::Hybrid
            )
        });

        // Convert RecallHits to the existing verbose JSON format
        let results: Vec<HashMap<String, Value>> = hits
            .into_iter()
            .map(|hit| {
                let mut entry = HashMap::new();
                entry.insert("session_id".to_string(), json!(hit.session_id));
                entry.insert("created_at".to_string(), json!(hit.created_at));
                entry.insert("relevance_score".to_string(), json!(hit.score));
                entry.insert(
                    "search_type".to_string(),
                    json!(match hit.search_type {
                        RecallSearchType::Semantic => "semantic",
                        RecallSearchType::Fts5 => "fts5",
                        RecallSearchType::Hybrid => "hybrid",
                        RecallSearchType::Text => "text",
                    }),
                );

                if let Some(summary) = &hit.summary {
                    entry.insert("summary".to_string(), json!(summary));
                }
                if let Some(facts) = &hit.key_facts {
                    entry.insert("key_facts".to_string(), json!(facts));
                }
                entry
            })
            .collect();

        // Build response text
        let response_text = if results.is_empty() {
            format!("No relevant context found for query: {query}")
        } else {
            let search_method = if has_semantic {
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
        let response_text = clx_core::redaction::redact_secrets(&response_text);

        Ok(json!({
            "content": [{
                "type": "text",
                "text": response_text
            }]
        }))
    }
}

fn query_percentile_gate(value: f64) -> u32 {
    if !value.is_finite() || value <= 0.0 {
        0
    } else {
        (value.clamp(0.0, 1.0) * 100.0).round() as u32
    }
}
