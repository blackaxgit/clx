//! Embeddings commands: status, rebuild, and backfill.

use anyhow::{Context, Result};
use clap::Subcommand;
use colored::Colorize;
use std::io::{self, Write};

use clx_core::config::{Capability, Config, OllamaConfig, effective_embedding_dimension};
use clx_core::embeddings::EmbeddingStore;
use clx_core::llm::{LlmBackend, LlmClient, LlmError};
use clx_core::redaction::redact_secrets;
use clx_core::storage::Storage;

use crate::Cli;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Format the `model_ident` tag written into every embedding row.
fn make_model_ident(provider: &str, model: &str) -> String {
    format!("{provider}:{model}")
}

/// Pure decision for `clx embeddings status` display + migration verdict.
///
/// Inputs:
/// * `stored_model` - the per-snapshot producing-model ident actually in the
///   index (`None` for an empty index or pre-migration sentinel rows).
/// * `configured_model` - the active route's model name, used only as the
///   display fallback when nothing is stored yet.
/// * `dim_migration` - whether the table dimension differs from configured.
/// * `model_migration` - whether the stored model differs from the active route.
///
/// Returns `(display_model, needs_migration)` where `display_model` is the
/// STORED model when known (Finding #4: never the config model when a stored
/// model exists), and `needs_migration` is the OR of dimension and model drift.
fn status_display(
    stored_model: Option<&str>,
    configured_model: &str,
    dim_migration: bool,
    model_migration: bool,
) -> (String, bool) {
    let display_model = stored_model.unwrap_or(configured_model).to_owned();
    (display_model, dim_migration || model_migration)
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
                        // Sink wrap (B6-1): storage errors are not LlmErrors but may
                        // echo path/connection strings; redact defensively.
                        println!(
                            "{}",
                            format!("Error: {}", redact_secrets(&e.to_string())).red()
                        );
                    }
                    counts.errors += 1;
                } else {
                    counts.processed += 1;
                }
            }
            Err(e) => {
                if !json {
                    // Sink wrap (B6-1): LlmError Display may contain tenant URLs.
                    println!(
                        "{}",
                        format!("Error: {}", redact_secrets(&e.to_string())).red()
                    );
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
                            // Sink wrap (B6-1): redact before printing to stdout.
                            println!(
                                "{}",
                                format!("Error: {}", redact_secrets(&e.to_string())).red()
                            );
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
                        // Sink wrap (B6-1): LlmError Display may contain tenant URLs.
                        println!(
                            "{}",
                            format!("Error: {}", redact_secrets(&e.to_string())).red()
                        );
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
            // Resolve the active embeddings route (provider + model) the same
            // way rebuild/backfill do, falling back to legacy ollama defaults
            // when no routing section is present. The configured model is what
            // the active route WILL use; the stored model is what produced the
            // vectors currently in the index. The route also carries the
            // effective dimension so the store opens — and migration is judged
            // — at the dimension the active route actually uses (Issue 6).
            let (configured_model, provider_name, dim) =
                match config.capability_route(Capability::Embeddings) {
                    Ok(r) => {
                        let dim = effective_embedding_dimension(r, ollama_cfg.embedding_dim);
                        (r.model.clone(), r.provider.clone(), dim)
                    }
                    Err(_) => (
                        ollama_cfg.embedding_model.clone(),
                        "ollama-local".to_owned(),
                        ollama_cfg.embedding_dim,
                    ),
                };
            let active_ident = make_model_ident(&provider_name, &configured_model);

            let emb_store = Storage::create_embedding_store_with_dimension(&db_path, dim)
                .context("Failed to open embedding store. Run 'clx install' first.")?;

            let vec_enabled = emb_store.is_vector_search_enabled();
            let count = emb_store.count_embeddings().unwrap_or(0);

            // The model actually stored in the index (per-snapshot provenance).
            // `None` means an empty index or only pre-migration sentinel rows.
            let stored_model = emb_store
                .current_model()
                .context("Failed to read stored embedding model")?;

            // Migration is needed when EITHER the table dimension differs from
            // the configured dimension OR the stored producing-model differs
            // from the active route (a same-dimension provider/model swap).
            let dim_migration = emb_store.needs_dimension_migration(dim);
            let model_migration = emb_store
                .needs_model_migration(&active_ident)
                .context("Failed to compare stored embedding model")?;

            // Display the STORED model when known; otherwise surface the
            // configured model so the field is never blank. `needs_migration`
            // is the OR of dimension drift and model drift.
            let (display_model, needs_migration) = status_display(
                stored_model.as_deref(),
                &configured_model,
                dim_migration,
                model_migration,
            );

            if cli.json {
                println!(
                    "{}",
                    serde_json::json!({
                        "model": display_model.as_str(),
                        "stored_model": stored_model,
                        "configured_model": active_ident,
                        "dimension": dim,
                        "vector_search_enabled": vec_enabled,
                        "stored_embeddings": count,
                        "needs_migration": needs_migration,
                        "needs_dimension_migration": dim_migration,
                        "needs_model_migration": model_migration,
                    })
                );
            } else {
                println!("{}", "Embedding Status".cyan().bold());
                println!("{}", "=".repeat(50));
                println!();
                println!("  Model (stored):     {}", display_model.green());
                if stored_model.as_deref().is_some_and(|s| s != active_ident) {
                    println!("  Model (configured): {}", active_ident.yellow());
                }
                println!("  Dimension:          {dim}");
                println!(
                    "  Vector search:      {}",
                    "enabled (statically linked)".green()
                );
                println!("  Stored embeddings:  {count}");
                if needs_migration {
                    println!();
                    if dim_migration {
                        println!(
                            "  {}",
                            "Migration needed: table dimension differs from configured dimension."
                                .yellow()
                        );
                    }
                    if model_migration {
                        println!(
                            "  {}",
                            "Migration needed: stored model differs from the active embeddings route."
                                .yellow()
                        );
                    }
                    println!("  Run {} to rebuild.", "clx embeddings rebuild".cyan());
                } else {
                    println!("  Migration needed:   {}", "no".green());
                }
            }
        }
        EmbeddingsAction::Rebuild { dry_run } => {
            // Resolve provider + model + effective dimension before anything
            // else so dry-run can show them and the store opens / rebuilds at
            // the route-derived dimension (Issue 6). Fall back to legacy ollama
            // defaults when no routing section is present.
            let (embed_model, provider_name, dim) =
                match config.capability_route(Capability::Embeddings) {
                    Ok(r) => {
                        let dim = effective_embedding_dimension(r, ollama_cfg.embedding_dim);
                        (r.model.clone(), r.provider.clone(), dim)
                    }
                    Err(_) => (
                        ollama_cfg.embedding_model.clone(),
                        "ollama-local".to_owned(),
                        ollama_cfg.embedding_dim,
                    ),
                };
            let model_ident = make_model_ident(&provider_name, &embed_model);

            let mut emb_store = Storage::create_embedding_store_with_dimension(&db_path, dim)
                .context("Failed to open embedding store. Run 'clx install' first.")?;

            // Snapshot list comes from the embedding store itself (uses its connection).
            let snapshots = emb_store
                .iter_snapshots_for_rebuild()
                .context("Failed to read snapshots")?;

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
                    // Sink wrap (B6-1): LlmError Display may contain tenant URLs or
                    // connection strings; redact before printing or embedding in JSON.
                    let safe_err = redact_secrets(&e.to_string());
                    if cli.json {
                        println!(
                            "{}",
                            serde_json::json!({
                                "error": format!("Failed to create LLM client: {safe_err}"),
                                "provider": provider_name,
                                "table_rebuilt": true,
                                "embeddings_generated": 0
                            })
                        );
                    } else {
                        println!();
                        println!(
                            "{}",
                            format!(
                                "Failed to create LLM client for '{provider_name}': {safe_err}"
                            )
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

    // Load config and resolve provider/model + effective dimension first, so the
    // store opens at the route-derived dimension — consistent with status and
    // rebuild (Issue 6).
    let config = Config::load().context("Failed to load configuration")?;
    let backfill_defaults = OllamaConfig::default();
    let backfill_cfg = config.ollama.as_ref().unwrap_or(&backfill_defaults);
    let (embed_model, provider_name, dim) = match config.capability_route(Capability::Embeddings) {
        Ok(r) => {
            let dim = effective_embedding_dimension(r, backfill_cfg.embedding_dim);
            (r.model.clone(), r.provider.clone(), dim)
        }
        Err(_) => (
            backfill_cfg.embedding_model.clone(),
            "ollama-local".to_owned(),
            backfill_cfg.embedding_dim,
        ),
    };
    let model_ident = make_model_ident(&provider_name, &embed_model);

    // Open embedding store at the effective dimension.
    let emb_store = Storage::create_embedding_store_with_dimension(&db_path, dim)
        .context("Failed to open embedding store. Run 'clx install' first.")?;

    let client = match config.create_llm_client(Capability::Embeddings) {
        Ok(c) => c,
        Err(e) => {
            // Sink wrap (B6-1): redact LlmError Display before printing or JSON.
            let safe_err = redact_secrets(&e.to_string());
            if cli.json {
                println!(
                    "{}",
                    serde_json::json!({
                        "error": format!("Failed to create LLM client: {safe_err}"),
                        "hint": "Check LLM configuration"
                    })
                );
            } else {
                println!(
                    "{}",
                    format!("Failed to create LLM client: {safe_err}").red()
                );
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

#[cfg(test)]
mod status_tests {
    //! Finding #4: `clx embeddings status` must display the STORED model (not
    //! the config model) and must flag migration on a same-dimension
    //! provider/model swap. These tests exercise the pure decision
    //! [`status_display`] used by the Status branch. The store-level migration
    //! logic (`needs_model_migration`) is tested over an in-memory `SQLite`
    //! index in `clx_core::embeddings`; here we pin the command-layer mapping
    //! from (stored, configured, dim-drift, model-drift) to (display, verdict)
    //! with no config/network/keychain.

    use super::{make_model_ident, status_display};

    /// 4-tuple #1 (the bug): stored qwen3, active Azure text-embedding-3-small
    /// at the SAME dim -> dim drift false, model drift true -> migration NEEDED,
    /// and the displayed model is the STORED qwen3, not the configured Azure.
    #[test]
    fn same_dim_provider_swap_needs_migration_and_shows_stored() {
        let stored_ident = make_model_ident("ollama-local", "qwen3-embedding:0.6b");
        // Same dim => dim_migration = false. Model differs => model_migration = true.
        let (display, needs) = status_display(
            Some(&stored_ident),
            "text-embedding-3-small", // configured (active route) model
            false,                    // dim_migration
            true,                     // model_migration (qwen3 != azure)
        );
        assert!(
            needs,
            "status must report migration NEEDED on a same-dim swap"
        );
        assert_eq!(
            display, stored_ident,
            "status must display the STORED model, not the configured one"
        );
    }

    /// 4-tuple #2: stored == active -> no migration; displayed model is stored.
    #[test]
    fn stored_equals_active_no_migration() {
        let ident = make_model_ident("azure-prod", "text-embedding-3-small");
        let (display, needs) = status_display(Some(&ident), "text-embedding-3-small", false, false);
        assert!(
            !needs,
            "matching stored and active route must NOT need migration"
        );
        assert_eq!(
            display, ident,
            "display must be the stored (== active) model"
        );
    }

    /// 4-tuple #3: dimension change -> migration (existing behavior preserved),
    /// display remains the stored model.
    #[test]
    fn dimension_change_needs_migration() {
        let ident = make_model_ident("ollama-local", "qwen3-embedding:0.6b");
        // Dim differs, model unchanged: dim drift carries the verdict.
        let (display, needs) = status_display(Some(&ident), "qwen3-embedding:0.6b", true, false);
        assert!(needs, "dimension change must report migration NEEDED");
        assert_eq!(display, ident, "display must remain the stored model");
    }

    /// Empty index: nothing stored -> no false migration, display falls back
    /// to the configured model so the field is never blank.
    #[test]
    fn empty_index_uses_configured_model_no_migration() {
        let (display, needs) = status_display(None, "text-embedding-3-small", false, false);
        assert!(!needs, "empty index must not raise a false migration alarm");
        assert_eq!(
            display, "text-embedding-3-small",
            "with nothing stored, display falls back to the configured model"
        );
    }
}
