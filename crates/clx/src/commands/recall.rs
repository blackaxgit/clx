//! Recall command: search context database for past interactions.

use anyhow::{Context, Result};
use colored::Colorize;

use clx_core::config::{Capability, Config};
use clx_core::storage::Storage;

use crate::Cli;
use crate::types::{RecallOutput, RecallResult, truncate_str};

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
    let ollama = match config.create_llm_client(Capability::Embeddings) {
        Ok(client) => client,
        Err(_) => {
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
                println!(
                    "Ollama is not configured. Run 'clx install' and ensure Ollama is running."
                );
            }
            return Ok(());
        }
    };

    // Generate embedding for the query
    let spinner = if cli.json {
        None
    } else {
        let sp = indicatif::ProgressBar::new_spinner();
        sp.set_message("Searching context database...");
        sp.enable_steady_tick(std::time::Duration::from_millis(100));
        Some(sp)
    };

    let query_embedding = match ollama.embed(query, Some(&embed_model)).await {
        Ok(emb) => emb,
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
                println!("Error: {e}");
            }
            return Ok(());
        }
    };

    // Search for similar snapshots
    let similar = emb_store.find_similar(&query_embedding, 5)?;

    if let Some(sp) = spinner {
        sp.finish_and_clear();
    }

    if cli.json {
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
