//! Embeddings commands: status, rebuild, and backfill.

use anyhow::{Context, Result};
use clap::Subcommand;
use colored::Colorize;
use std::io::{self, Write};

use clx_core::config::{Capability, Config, OllamaConfig};
use clx_core::storage::Storage;

use crate::Cli;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Format the `model_ident` tag written into every embedding row.
fn make_model_ident(provider: &str, model: &str) -> String {
    format!("{provider}:{model}")
}

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

            // Resolve provider + model before anything else so dry-run can show them.
            // Fall back to legacy ollama defaults when no routing section is present.
            let (embed_model, provider_name) = match config.capability_route(Capability::Embeddings)
            {
                Ok(r) => (r.model.clone(), r.provider.clone()),
                Err(_) => (
                    ollama_cfg.embedding_model.clone(),
                    "ollama-local".to_owned(),
                ),
            };
            let model_ident = make_model_ident(&provider_name, &embed_model);

            // Snapshot list comes from the embedding store itself (uses its connection).
            let snapshots = emb_store
                .iter_snapshots_for_rebuild()
                .context("Failed to read snapshots")?;

            let dim = ollama_cfg.embedding_dim;
            let needs_migration = emb_store.needs_dimension_migration(dim);
            let existing_count = emb_store.count_embeddings().unwrap_or(0);

            if *dry_run {
                if cli.json {
                    println!(
                        "{}",
                        serde_json::json!({
                            "dry_run": true,
                            "provider": provider_name,
                            "model": embed_model,
                            "model_ident": model_ident,
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
                    println!("  Provider:             {}", provider_name.green());
                    println!("  Model:                {}", embed_model.green());
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

            // Step 2: Check provider availability before doing any work.
            let client = match config.create_llm_client(Capability::Embeddings) {
                Ok(c) => c,
                Err(e) => {
                    if cli.json {
                        println!(
                            "{}",
                            serde_json::json!({
                                "error": format!("Failed to create LLM client: {e}"),
                                "provider": provider_name,
                                "table_rebuilt": true,
                                "embeddings_generated": 0
                            })
                        );
                    } else {
                        println!();
                        println!(
                            "{}",
                            format!("Failed to create LLM client for '{provider_name}': {e}")
                                .yellow()
                        );
                        println!("Table was rebuilt but embeddings could not be regenerated.");
                    }
                    return Ok(());
                }
            };

            if !client.is_available().await {
                if cli.json {
                    println!(
                        "{}",
                        serde_json::json!({
                            "error": format!("Provider '{}' is not available", provider_name),
                            "provider": provider_name,
                            "table_rebuilt": true,
                            "embeddings_generated": 0
                        })
                    );
                } else {
                    println!();
                    println!(
                        "{}",
                        format!("Provider '{provider_name}' is not available.").yellow()
                    );
                    println!("Table was rebuilt but embeddings could not be regenerated.");
                    println!("Check the provider configuration and then run: clx embed-backfill");
                }
                return Ok(());
            }

            // Step 3: Re-read snapshots after table rebuild (connection is the same store).
            let snapshots = emb_store
                .iter_snapshots_for_rebuild()
                .context("Failed to read snapshots after table rebuild")?;

            let total = snapshots.len();
            let mut processed = 0usize;
            let mut skipped = 0usize;
            let mut errors = 0usize;

            for (i, (snapshot_id, text)) in snapshots.iter().enumerate() {
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

                match client.embed(text, Some(&embed_model)).await {
                    Ok(embedding) => {
                        if let Err(e) =
                            emb_store.store_with_model(*snapshot_id, embedding, &model_ident)
                        {
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
                        "provider": provider_name,
                        "model": embed_model,
                        "model_ident": model_ident,
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
                println!("  Provider:         {provider_name}");
                println!("  Model:            {embed_model}");
            }
        }
    }

    Ok(())
}

/// Generate embeddings for existing snapshots that do not yet have one.
pub async fn cmd_embed_backfill(cli: &Cli, dry_run: bool) -> Result<()> {
    let db_path = clx_core::paths::database_path();

    // Open embedding store
    let emb_store = Storage::create_embedding_store(&db_path)
        .context("Failed to open embedding store. Run 'clx install' first.")?;

    // Load config and resolve provider/model.
    let config = Config::load().context("Failed to load configuration")?;
    let backfill_defaults = OllamaConfig::default();
    let backfill_cfg = config.ollama.as_ref().unwrap_or(&backfill_defaults);
    let (embed_model, provider_name) = match config.capability_route(Capability::Embeddings) {
        Ok(r) => (r.model.clone(), r.provider.clone()),
        Err(_) => (
            backfill_cfg.embedding_model.clone(),
            "ollama-local".to_owned(),
        ),
    };
    let model_ident = make_model_ident(&provider_name, &embed_model);

    let client = match config.create_llm_client(Capability::Embeddings) {
        Ok(c) => c,
        Err(e) => {
            if cli.json {
                println!(
                    "{}",
                    serde_json::json!({
                        "error": format!("Failed to create LLM client: {e}"),
                        "hint": "Check LLM configuration"
                    })
                );
            } else {
                println!("{}", format!("Failed to create LLM client: {e}").red());
            }
            return Ok(());
        }
    };

    // Check provider availability.
    if !client.is_available().await {
        if cli.json {
            println!(
                "{}",
                serde_json::json!({
                    "error": format!("Provider '{}' is not available", provider_name),
                    "provider": provider_name,
                    "hint": "Check provider configuration"
                })
            );
        } else {
            println!(
                "{}",
                format!("Provider '{provider_name}' is not available.").yellow()
            );
            println!("Check provider configuration before running backfill.");
        }
        return Ok(());
    }

    // Get all snapshots via the embedding store's own connection.
    let all_snapshots = emb_store
        .iter_snapshots_for_rebuild()
        .context("Failed to read snapshots")?;

    if !cli.json {
        println!("{}", "Embedding Backfill".cyan().bold());
        println!("{}", "=".repeat(50));
        println!();
        println!("Found {} snapshots", all_snapshots.len());
    }

    let mut processed = 0usize;
    let mut skipped = 0usize;
    let mut errors = 0usize;

    for (snapshot_id, text) in &all_snapshots {
        // Skip snapshots that already have an embedding.
        if emb_store.has_embedding(*snapshot_id)? {
            skipped += 1;
            continue;
        }

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
            match client.embed(text, Some(&embed_model)).await {
                Ok(embedding) => {
                    if let Err(e) =
                        emb_store.store_with_model(*snapshot_id, embedding, &model_ident)
                    {
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
                "total": all_snapshots.len(),
                "processed": processed,
                "skipped": skipped,
                "errors": errors,
                "provider": provider_name,
                "model": embed_model,
                "dry_run": dry_run
            })
        );
    } else {
        println!();
        println!("{}", "Summary:".bold());
        println!("  Total snapshots: {}", all_snapshots.len());
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
