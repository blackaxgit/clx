//! Embeddings commands: status, rebuild, and backfill.

use anyhow::{Context, Result};
use clap::Subcommand;
use colored::Colorize;
use std::io::{self, Write};

use clx_core::config::{Capability, Config, OllamaConfig};
use clx_core::embeddings::EmbeddingStore;
use clx_core::llm::{LlmBackend, LlmClient, LlmError};
use clx_core::storage::Storage;

use crate::Cli;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Format the `model_ident` tag written into every embedding row.
fn make_model_ident(provider: &str, model: &str) -> String {
    format!("{provider}:{model}")
}

// ---------------------------------------------------------------------------
// Embed-client seam
// ---------------------------------------------------------------------------

/// Thin adapter closing the existing [`LlmBackend`] trait over the concrete
/// [`LlmClient`] enum (which exposes the same surface via inherent methods but
/// does not itself implement the trait). This keeps the extracted loop bodies
/// generic over `LlmBackend` so an offline fake can be substituted in tests
/// without changing the trait's public signature or the production type.
struct LlmClientAdapter<'a>(&'a LlmClient);

impl LlmBackend for LlmClientAdapter<'_> {
    async fn generate(&self, prompt: &str, model: Option<&str>) -> Result<String, LlmError> {
        self.0.generate(prompt, model).await
    }
    async fn embed(&self, text: &str, model: Option<&str>) -> Result<Vec<f32>, LlmError> {
        self.0.embed(text, model).await
    }
    async fn is_available(&self) -> bool {
        self.0.is_available().await
    }
}

/// Outcome counts from the rebuild embed loop. Pure data so callers (and
/// tests) assert observable behavior, not implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct RebuildCounts {
    pub processed: usize,
    pub skipped: usize,
    pub errors: usize,
}

/// Outcome counts from the backfill embed loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct BackfillCounts {
    pub processed: usize,
    pub skipped: usize,
    pub errors: usize,
}

/// Pure per-snapshot rebuild embed loop, generic over the embed-client trait
/// surface. Mirrors the prior inline loop exactly: empty text is skipped,
/// `embed` errors and `store_with_model` errors both count as errors, and
/// progress is printed only in non-JSON mode.
pub(crate) async fn rebuild_embeddings<E: LlmBackend>(
    emb_store: &EmbeddingStore,
    snapshots: &[(i64, String)],
    client: &E,
    embed_model: &str,
    model_ident: &str,
    json: bool,
) -> Result<RebuildCounts> {
    let total = snapshots.len();
    let mut counts = RebuildCounts::default();

    for (i, (snapshot_id, text)) in snapshots.iter().enumerate() {
        if text.trim().is_empty() {
            counts.skipped += 1;
            continue;
        }

        if !json {
            print!(
                "\r  Processing [{}/{}] snapshot {}... ",
                i + 1,
                total,
                snapshot_id
            );
            io::stdout().flush()?;
        }

        match client.embed(text, Some(embed_model)).await {
            Ok(embedding) => {
                if let Err(e) = emb_store.store_with_model(*snapshot_id, embedding, model_ident) {
                    if !json {
                        println!("{}", format!("Error: {e}").red());
                    }
                    counts.errors += 1;
                } else {
                    counts.processed += 1;
                }
            }
            Err(e) => {
                if !json {
                    println!("{}", format!("Error: {e}").red());
                }
                counts.errors += 1;
            }
        }
    }

    Ok(counts)
}

/// Pure per-snapshot backfill embed loop, generic over the embed-client trait
/// surface. Mirrors the prior inline loop exactly: already-embedded snapshots
/// and empty text are skipped, the dry-run branch only counts and prints, and
/// `embed`/`store_with_model` errors count as errors.
pub(crate) async fn backfill_embeddings<E: LlmBackend>(
    emb_store: &EmbeddingStore,
    snapshots: &[(i64, String)],
    client: &E,
    embed_model: &str,
    model_ident: &str,
    json: bool,
    dry_run: bool,
) -> Result<BackfillCounts> {
    let mut counts = BackfillCounts::default();

    for (snapshot_id, text) in snapshots {
        // Skip snapshots that already have an embedding.
        if emb_store.has_embedding(*snapshot_id)? {
            counts.skipped += 1;
            continue;
        }

        if text.trim().is_empty() {
            counts.skipped += 1;
            continue;
        }

        if !json && !dry_run {
            print!("  Processing snapshot {snapshot_id}... ");
            io::stdout().flush()?;
        }

        if dry_run {
            if !json {
                println!(
                    "  Would process snapshot {} ({} chars)",
                    snapshot_id,
                    text.len()
                );
            }
            counts.processed += 1;
        } else {
            match client.embed(text, Some(embed_model)).await {
                Ok(embedding) => {
                    if let Err(e) = emb_store.store_with_model(*snapshot_id, embedding, model_ident)
                    {
                        if !json {
                            println!("{}", format!("Error: {e}").red());
                        }
                        counts.errors += 1;
                    } else {
                        if !json {
                            println!("{}", "OK".green());
                        }
                        counts.processed += 1;
                    }
                }
                Err(e) => {
                    if !json {
                        println!("{}", format!("Error: {e}").red());
                    }
                    counts.errors += 1;
                }
            }
        }
    }

    Ok(counts)
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
            let RebuildCounts {
                processed,
                skipped,
                errors,
            } = rebuild_embeddings(
                &emb_store,
                &snapshots,
                &LlmClientAdapter(&client),
                &embed_model,
                &model_ident,
                cli.json,
            )
            .await?;

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

    let BackfillCounts {
        processed,
        skipped,
        errors,
    } = backfill_embeddings(
        &emb_store,
        &all_snapshots,
        &LlmClientAdapter(&client),
        &embed_model,
        &model_ident,
        cli.json,
        dry_run,
    )
    .await?;

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
