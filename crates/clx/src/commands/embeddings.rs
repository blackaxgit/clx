//! Embeddings commands: status, rebuild, and backfill.

use anyhow::{Context, Result};
use clap::Subcommand;
use colored::Colorize;
use std::io::{self, Write};

use clx_core::config::{Capability, Config, OllamaConfig};
use clx_core::storage::Storage;

use crate::Cli;

#[derive(Debug, Subcommand)]
pub enum EmbeddingsAction {
    /// Show embedding model info and status
    Status,
    /// Rebuild all embeddings with current model
    Rebuild {
        /// Dry run - show what would change without modifying
        #[arg(long)]
        dry_run: bool,
    },
}

/// Manage embeddings: status, rebuild
pub async fn cmd_embeddings(cli: &Cli, action: &EmbeddingsAction) -> Result<()> {
    let config = Config::load().context("Failed to load configuration")?;
    let db_path = clx_core::paths::database_path();

    let ollama_defaults = OllamaConfig::default();
    let ollama_cfg = config.ollama.as_ref().unwrap_or(&ollama_defaults);

    match action {
        EmbeddingsAction::Status => {
            let emb_store =
                Storage::create_embedding_store_with_dimension(&db_path, ollama_cfg.embedding_dim)
                    .context("Failed to open embedding store. Run 'clx install' first.")?;

            let model = &ollama_cfg.embedding_model;
            let dim = ollama_cfg.embedding_dim;
            let vec_enabled = emb_store.is_vector_search_enabled();
            let count = emb_store.count_embeddings().unwrap_or(0);
            let needs_migration = emb_store.needs_dimension_migration(dim);

            if cli.json {
                println!(
                    "{}",
                    serde_json::json!({
                        "model": model,
                        "dimension": dim,
                        "vector_search_enabled": vec_enabled,
                        "stored_embeddings": count,
                        "needs_migration": needs_migration,
                    })
                );
            } else {
                println!("{}", "Embedding Status".cyan().bold());
                println!("{}", "=".repeat(50));
                println!();
                println!("  Model:              {}", model.green());
                println!("  Dimension:          {dim}");
                println!(
                    "  Vector search:      {}",
                    "enabled (statically linked)".green()
                );
                println!("  Stored embeddings:  {count}");
                if needs_migration {
                    println!();
                    println!(
                        "  {}",
                        "Migration needed: table dimension differs from configured dimension."
                            .yellow()
                    );
                    println!("  Run {} to rebuild.", "clx embeddings rebuild".cyan());
                } else {
                    println!("  Migration needed:   {}", "no".green());
                }
            }
        }
        EmbeddingsAction::Rebuild { dry_run } => {
            let mut emb_store =
                Storage::create_embedding_store_with_dimension(&db_path, ollama_cfg.embedding_dim)
                    .context("Failed to open embedding store. Run 'clx install' first.")?;

            // Get all snapshots to regenerate
            let storage = Storage::open_default().context("Failed to open database")?;
            let snapshots = storage.list_all_snapshots()?;

            let dim = ollama_cfg.embedding_dim;
            let needs_migration = emb_store.needs_dimension_migration(dim);
            let existing_count = emb_store.count_embeddings().unwrap_or(0);

            if *dry_run {
                if cli.json {
                    println!(
                        "{}",
                        serde_json::json!({
                            "dry_run": true,
                            "model": ollama_cfg.embedding_model,
                            "target_dimension": dim,
                            "needs_dimension_migration": needs_migration,
                            "existing_embeddings": existing_count,
                            "total_snapshots": snapshots.len(),
                            "would_regenerate": snapshots.len(),
                        })
                    );
                } else {
                    println!("{}", "Embedding Rebuild (dry run)".cyan().bold());
                    println!("{}", "=".repeat(50));
                    println!();
                    println!(
                        "  Model:                {}",
                        ollama_cfg.embedding_model.green()
                    );
                    println!("  Target dimension:     {dim}");
                    println!(
                        "  Dimension migration:  {}",
                        if needs_migration {
                            "yes".yellow().to_string()
                        } else {
                            "no".green().to_string()
                        }
                    );
                    println!("  Existing embeddings:  {existing_count}");
                    println!("  Total snapshots:      {}", snapshots.len());
                    println!("  Would regenerate:     {}", snapshots.len());
                    println!();
                    println!("{}", "Run without --dry-run to perform rebuild.".yellow());
                }
                return Ok(());
            }

            // Actual rebuild
            if !cli.json {
                println!("{}", "Embedding Rebuild".cyan().bold());
                println!("{}", "=".repeat(50));
                println!();
            }

            // Step 1: Rebuild table with new dimension
            if needs_migration {
                if !cli.json {
                    println!("  Rebuilding table with {dim} dimensions...");
                }
                emb_store
                    .rebuild_table(dim)
                    .context("Failed to rebuild embedding table")?;
                if !cli.json {
                    println!("  {}", "Table rebuilt.".green());
                }
            } else {
                // Even without dimension change, drop and recreate for clean rebuild
                if !cli.json {
                    println!("  Dropping and recreating embedding table...");
                }
                emb_store
                    .rebuild_table(dim)
                    .context("Failed to rebuild embedding table")?;
                if !cli.json {
                    println!("  {}", "Table recreated.".green());
                }
            }

            // Step 2: Create LLM client and regenerate embeddings
            let embed_model = config
                .capability_route(Capability::Embeddings)
                .map(|r| r.model.clone())
                .unwrap_or_else(|_| ollama_cfg.embedding_model.clone());
            let ollama = config
                .create_llm_client(Capability::Embeddings)
                .context("Failed to create LLM client")?;

            if !ollama.is_available().await {
                if cli.json {
                    println!(
                        "{}",
                        serde_json::json!({
                            "error": "Ollama not available",
                            "hint": "Make sure Ollama is running: ollama serve",
                            "table_rebuilt": true,
                            "embeddings_generated": 0
                        })
                    );
                } else {
                    println!();
                    println!("{}", "Ollama not available.".yellow());
                    println!("Table was rebuilt but embeddings could not be regenerated.");
                    println!("Make sure Ollama is running and then run: clx embed-backfill");
                }
                return Ok(());
            }

            let total = snapshots.len();
            let mut processed = 0usize;
            let mut skipped = 0usize;
            let mut errors = 0usize;

            for (i, snapshot) in snapshots.iter().enumerate() {
                let snapshot_id = snapshot.id.unwrap_or(0);

                let text = format!(
                    "{}\n{}\n{}",
                    snapshot.summary.as_deref().unwrap_or(""),
                    snapshot.key_facts.as_deref().unwrap_or(""),
                    snapshot.todos.as_deref().unwrap_or("")
                );

                if text.trim().is_empty() {
                    skipped += 1;
                    continue;
                }

                if !cli.json {
                    print!(
                        "\r  Processing [{}/{}] snapshot {}... ",
                        i + 1,
                        total,
                        snapshot_id
                    );
                    io::stdout().flush()?;
                }

                match ollama.embed(&text, Some(&embed_model)).await {
                    Ok(embedding) => {
                        if let Err(e) = emb_store.store_embedding(snapshot_id, embedding) {
                            if !cli.json {
                                println!("{}", format!("Error: {e}").red());
                            }
                            errors += 1;
                        } else {
                            processed += 1;
                        }
                    }
                    Err(e) => {
                        if !cli.json {
                            println!("{}", format!("Error: {e}").red());
                        }
                        errors += 1;
                    }
                }
            }

            if cli.json {
                println!(
                    "{}",
                    serde_json::json!({
                        "total_snapshots": total,
                        "processed": processed,
                        "skipped": skipped,
                        "errors": errors,
                        "dimension": dim,
                        "model": ollama_cfg.embedding_model,
                    })
                );
            } else {
                println!();
                println!();
                println!("{}", "Summary:".bold());
                println!("  Total snapshots:  {total}");
                println!("  Processed:        {processed}");
                println!("  Skipped (empty):  {skipped}");
                if errors > 0 {
                    println!("  Errors:           {errors}");
                }
                println!("  Dimension:        {dim}");
                println!("  Model:            {}", ollama_cfg.embedding_model);
            }
        }
    }

    Ok(())
}

/// Generate embeddings for existing snapshots
pub async fn cmd_embed_backfill(cli: &Cli, dry_run: bool) -> Result<()> {
    // Get database path
    let db_path = clx_core::paths::database_path();

    // Open embedding store
    let emb_store = Storage::create_embedding_store(&db_path)
        .context("Failed to open embedding store. Run 'clx install' first.")?;

    // Load config and create LLM client for embeddings
    let config = Config::load().context("Failed to load configuration")?;
    let backfill_defaults = OllamaConfig::default();
    let backfill_cfg = config.ollama.as_ref().unwrap_or(&backfill_defaults);
    let embed_model = config
        .capability_route(Capability::Embeddings)
        .map(|r| r.model.clone())
        .unwrap_or_else(|_| backfill_cfg.embedding_model.clone());
    let ollama = match config.create_llm_client(Capability::Embeddings) {
        Ok(client) => client,
        Err(e) => {
            if cli.json {
                println!(
                    "{}",
                    serde_json::json!({
                        "error": format!("Failed to create LLM client: {}", e),
                        "hint": "Check LLM configuration"
                    })
                );
            } else {
                println!("{}", format!("Failed to create LLM client: {e}").red());
            }
            return Ok(());
        }
    };

    // Check if Ollama is available
    if !ollama.is_available().await {
        if cli.json {
            println!(
                "{}",
                serde_json::json!({
                    "error": "Ollama not available",
                    "hint": "Make sure Ollama is running: ollama serve"
                })
            );
        } else {
            println!("{}", "Ollama not available.".yellow());
            println!("Make sure Ollama is running: ollama serve");
        }
        return Ok(());
    }

    // Get all snapshots
    let storage = Storage::open_default().context("Failed to open database")?;
    let snapshots = storage.list_all_snapshots()?;

    if !cli.json {
        println!("{}", "Embedding Backfill".cyan().bold());
        println!("{}", "=".repeat(50));
        println!();
        println!("Found {} snapshots", snapshots.len());
    }

    let mut processed = 0;
    let mut skipped = 0;
    let mut errors = 0;

    for snapshot in &snapshots {
        let snapshot_id = snapshot.id.unwrap_or(0);

        // Check if embedding already exists
        if emb_store.has_embedding(snapshot_id)? {
            skipped += 1;
            continue;
        }

        // Create text to embed from snapshot content
        let text = format!(
            "{}\n{}\n{}",
            snapshot.summary.as_deref().unwrap_or(""),
            snapshot.key_facts.as_deref().unwrap_or(""),
            snapshot.todos.as_deref().unwrap_or("")
        );

        if text.trim().is_empty() {
            skipped += 1;
            continue;
        }

        if !cli.json && !dry_run {
            print!("  Processing snapshot {snapshot_id}... ");
            io::stdout().flush()?;
        }

        if dry_run {
            if !cli.json {
                println!(
                    "  Would process snapshot {} ({} chars)",
                    snapshot_id,
                    text.len()
                );
            }
            processed += 1;
        } else {
            // Generate embedding
            match ollama.embed(&text, Some(&embed_model)).await {
                Ok(embedding) => {
                    // Store embedding
                    if let Err(e) = emb_store.store_embedding(snapshot_id, embedding) {
                        if !cli.json {
                            println!("{}", format!("Error: {e}").red());
                        }
                        errors += 1;
                    } else {
                        if !cli.json {
                            println!("{}", "OK".green());
                        }
                        processed += 1;
                    }
                }
                Err(e) => {
                    if !cli.json {
                        println!("{}", format!("Error: {e}").red());
                    }
                    errors += 1;
                }
            }
        }
    }

    if cli.json {
        println!(
            "{}",
            serde_json::json!({
                "total": snapshots.len(),
                "processed": processed,
                "skipped": skipped,
                "errors": errors,
                "dry_run": dry_run
            })
        );
    } else {
        println!();
        println!("{}", "Summary:".bold());
        println!("  Total snapshots: {}", snapshots.len());
        println!("  Processed: {processed}");
        println!("  Skipped (already have embedding): {skipped}");
        if errors > 0 {
            println!("  Errors: {errors}");
        }
        if dry_run {
            println!();
            println!(
                "{}",
                "This was a dry run. Run without --dry-run to generate embeddings.".yellow()
            );
        }
    }

    Ok(())
}
