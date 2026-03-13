//! `clx_recall` tool — Semantic search for relevant context.
//!
//! Delegates to `RecallEngine` for hybrid semantic + FTS5 search,
//! then formats results as verbose JSON for the MCP protocol.

use std::collections::HashMap;

use serde_json::{Value, json};
use tracing::debug;

use clx_core::recall::{RecallEngine, RecallQueryConfig, RecallSearchType};

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

        let engine = RecallEngine::new(
            &self.storage,
            self.ollama_client.as_ref(),
            self.embedding_store.as_ref(),
        );

        let config = RecallQueryConfig {
            max_results: MAX_SEMANTIC_RESULTS,
            similarity_threshold: 1.0 - (SEMANTIC_DISTANCE_THRESHOLD / 2.0),
            fallback_to_fts: true,
            include_key_facts: true,
        };

        let hits = self.runtime.block_on(engine.query(&query, &config));

        let has_semantic = hits
            .iter()
            .any(|h| matches!(h.search_type, RecallSearchType::Semantic | RecallSearchType::Hybrid));

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

        Ok(json!({
            "content": [{
                "type": "text",
                "text": response_text
            }]
        }))
    }
}
