//! Recall command: search context database for past interactions.
//!
//! ## Seam (0.8.1, campaign v2 Stream 1)
//!
//! The embedding step is driven through the existing [`QueryEmbedder`] port
//! so an offline test can substitute the I/O boundary (a wiremock-backed
//! `LlmQueryEmbedder` via config-in-sandbox) without a `#[cfg(test)]`
//! constructor hack. The similarity step calls `EmbeddingStore::find_similar`
//! directly and `storage` is opened lazily only at the snapshot-hydration
//! sites — *exactly* as the pre-refactor raw path did (it is NOT the
//! `RecallEngine` RRF/decay/percentile pipeline that `clx-mcp` uses).
//!
//! [`recall_via_ports`] performs the same two operations the old raw path
//! did — `QueryEmbedder::embed_query` (was `ollama.embed`) then
//! `EmbeddingStore::find_similar` — so the observable CLI output (stdout for
//! `--json` and human, exit codes, and *when* `Storage::open_default` is
//! reached) is byte-identical to the pre-refactor behaviour. This is a seam
//! refactor for testability, not a behaviour change.

use anyhow::{Context, Result};
use colored::Colorize;

use clx_core::config::{Capability, Config};
use clx_core::embeddings::EmbeddingStore;
use clx_core::recall::{LlmQueryEmbedder, QueryEmbedder};
use clx_core::redaction::redact_secrets;
use clx_core::storage::Storage;

use crate::Cli;
use crate::types::{RecallOutput, RecallResult, truncate_str};

/// Number of nearest snapshots the recall search returns. Preserved
/// verbatim from the pre-refactor `emb_store.find_similar(&emb, 5)`.
const RECALL_LIMIT: usize = 5;

/// Embedding + similarity core, with the embed step behind the
/// [`QueryEmbedder`] port so an offline fake (or a wiremock-backed
/// `LlmQueryEmbedder`) can substitute the I/O boundary without a
/// `#[cfg(test)]` constructor hack.
///
/// Returns the `(snapshot_id, distance)` pairs ordered by ascending
/// distance, identical in shape and content to the pre-refactor
/// `ollama.embed(...)` then `emb_store.find_similar(...)` chain. An `Err`
/// here corresponds to the pre-refactor `ollama.embed(...)` error arm
/// (reached *before* any `Storage::open_default`, matching the old code).
async fn recall_via_ports(
    embedder: &dyn QueryEmbedder,
    emb_store: &EmbeddingStore,
    query: &str,
    limit: usize,
) -> Result<Vec<(i64, f32)>> {
    let query_embedding = embedder
        .embed_query(query)
        .await
        .context("embedding generation failed")?;
    let similar = emb_store
        .find_similar(&query_embedding, limit)
        .context("similarity search failed")?;
    Ok(similar)
}

/// Search context database
pub async fn cmd_recall(cli: &Cli, query: &str) -> Result<()> {
    // Get database path
    let db_path = clx_core::paths::database_path();

    // Try to open embedding store
    let Ok(emb_store) = Storage::create_embedding_store(&db_path) else {
        if cli.json {
            let output = RecallOutput {
                query: query.to_string(),
                results: vec![],
            };
            println!("{}", serde_json::to_string_pretty(&output)?);
        } else {
            println!(
                "{}",
                "Database not initialized. Run 'clx install' first.".yellow()
            );
        }
        return Ok(());
    };

    // Load config and create LLM client for embeddings
    let config = Config::load().context("Failed to load configuration")?;
    let embed_model = config
        .capability_route(Capability::Embeddings)
        .map(|r| r.model.clone())
        .unwrap_or_default();
    let Ok(ollama) = config.create_llm_client(Capability::Embeddings) else {
        if cli.json {
            let output = RecallOutput {
                query: query.to_string(),
                results: vec![],
            };
            println!("{}", serde_json::to_string_pretty(&output)?);
        } else {
            println!("{}", "Context Recall".cyan().bold());
            println!("{}", "=".repeat(50));
            println!();
            println!("{}  {}", "Query:".bold(), query);
            println!();
            println!("{}", "Could not generate embedding for query.".yellow());
            println!("Ollama is not configured. Run 'clx install' and ensure Ollama is running.");
        }
        return Ok(());
    };

    // Build the embedding port (Hexagonal boundary): production wires the
    // `LlmQueryEmbedder` adapter over `Config::create_llm_client`; an offline
    // test substitutes a wiremock-backed embedder via config-in-sandbox.
    // `storage` is intentionally NOT opened here — the pre-refactor code
    // opened it lazily only at the hydration sites, so opening it earlier
    // would change which error surfaces when embed also fails.
    let embed_model_opt = if embed_model.is_empty() {
        None
    } else {
        Some(embed_model.as_str())
    };
    let embedder = LlmQueryEmbedder::new(&ollama, embed_model_opt);

    // Spinner for the human path (suppressed for --json).
    let spinner = if cli.json {
        None
    } else {
        let sp = indicatif::ProgressBar::new_spinner();
        sp.set_message("Searching context database...");
        sp.enable_steady_tick(std::time::Duration::from_millis(100));
        Some(sp)
    };

    // Port-driven embed + similarity. An Err here is the embed-error arm,
    // observably identical to the pre-refactor `ollama.embed` failure.
    let similar = match recall_via_ports(&embedder, &emb_store, query, RECALL_LIMIT).await {
        Ok(similar) => similar,
        Err(e) => {
            if let Some(sp) = &spinner {
                sp.finish_and_clear();
            }
            if cli.json {
                let output = RecallOutput {
                    query: query.to_string(),
                    results: vec![],
                };
                println!("{}", serde_json::to_string_pretty(&output)?);
            } else {
                println!("{}", "Context Recall".cyan().bold());
                println!("{}", "=".repeat(50));
                println!();
                println!("{}  {}", "Query:".bold(), query);
                println!();
                println!("{}", "Could not generate embedding for query.".yellow());
                println!("Make sure Ollama is running: ollama serve");
                // Sink wrap (B6-1): redact LlmError Display before printing to stdout.
                println!("Error: {}", redact_secrets(&e.to_string()));
            }
            return Ok(());
        }
    };

    if let Some(sp) = spinner {
        sp.finish_and_clear();
    }

    if cli.json {
        // Open storage lazily here (pre-refactor parity: the old JSON path
        // opened it only at this point, after a successful embed+search).
        let storage = Storage::open_default()?;
        let mut results = Vec::new();
        for (snapshot_id, distance) in &similar {
            if let Ok(Some(snapshot)) = storage.get_snapshot(*snapshot_id) {
                // Combine snapshot fields into content with truncation to bound allocations
                let summary = truncate_str(snapshot.summary.as_deref().unwrap_or(""), 2000);
                let key_facts = truncate_str(snapshot.key_facts.as_deref().unwrap_or(""), 2000);
                let todos = truncate_str(snapshot.todos.as_deref().unwrap_or(""), 1000);
                let content = format!("Summary: {summary}\nKey Facts: {key_facts}\nTODOs: {todos}");
                results.push(RecallResult {
                    session_id: snapshot.session_id.to_string(),
                    content,
                    timestamp: snapshot.created_at.to_rfc3339(),
                    distance: *distance,
                });
            }
        }
        let output = RecallOutput {
            query: query.to_string(),
            results,
        };
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!("{}", "Context Recall".cyan().bold());
        println!("{}", "=".repeat(50));
        println!();
        println!("{}  {}", "Query:".bold(), query);
        println!();

        if similar.is_empty() {
            let embedding_count = emb_store.count_embeddings().unwrap_or(0);
            println!("{}", "No matching context found.".dimmed());
            println!();
            if embedding_count == 0 {
                println!("No embeddings stored yet.");
                println!("Embeddings are created during PreCompact hooks when context is saved.");
                println!("Run: clx embed-backfill to generate embeddings for existing snapshots.");
            } else {
                println!("({embedding_count} embeddings in database, but none matched your query)");
            }
        } else {
            // Open storage lazily here (pre-refactor parity: the old human
            // path opened it only inside the non-empty branch, never on the
            // "no matching context" path).
            let storage = Storage::open_default()?;
            for (i, (snapshot_id, distance)) in similar.iter().enumerate() {
                // Lower distance = more similar
                println!(
                    "{}",
                    format!(
                        "{}. Snapshot #{} (distance: {:.2})",
                        i + 1,
                        snapshot_id,
                        distance
                    )
                    .cyan()
                );
                if let Ok(Some(snapshot)) = storage.get_snapshot(*snapshot_id) {
                    println!("   Session: {}", snapshot.session_id);
                    println!(
                        "   Time: {}",
                        snapshot.created_at.format("%Y-%m-%d %H:%M:%S")
                    );
                    if let Some(summary) = &snapshot.summary {
                        println!("   {}", "Summary:".bold());
                        for line in summary.lines().take(3) {
                            println!("     {}", line.dimmed());
                        }
                    }
                    if let Some(facts) = &snapshot.key_facts {
                        println!("   {}", "Key Facts:".bold());
                        for line in facts.lines().take(3) {
                            println!("     {}", line.dimmed());
                        }
                    }
                }
                println!();
            }
        }
    }

    Ok(())
}
