//! Config command: view or manage configuration.

use anyhow::{Context, Result};
use clap::Subcommand;
use colored::Colorize;
use std::env;
use std::io::{self, Write};
use std::process::Command;

use clx_core::config::Config;

use crate::Cli;

#[derive(Subcommand)]
pub enum ConfigAction {
    /// Open configuration file in editor
    Edit,

    /// Reset configuration to defaults
    Reset,

    /// Rewrite ~/.clx/config.yaml from the legacy `ollama:` block to the new providers/llm schema.
    Migrate,
}

/// Configuration management
pub async fn cmd_config(cli: &Cli, action: Option<&ConfigAction>) -> Result<()> {
    match action {
        None => {
            // Show current config as YAML
            let config = Config::load().context("Failed to load configuration")?;

            if cli.json {
                println!("{}", serde_json::to_string_pretty(&config)?);
            } else {
                let yaml = serde_yml::to_string(&config)?;
                println!("{}", "Current Configuration".cyan().bold());
                println!("{}", "=".repeat(50));
                println!();
                println!("{yaml}");
            }
        }
        Some(ConfigAction::Edit) => {
            let config_path = Config::config_file_path()?;

            // Ensure config file exists with defaults
            if !config_path.exists() {
                let config = Config::default();
                let yaml = serde_yml::to_string(&config)?;
                if let Some(parent) = config_path.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                std::fs::write(&config_path, yaml)?;
                if !cli.json {
                    println!(
                        "Created default config at: {}",
                        config_path.display().to_string().green()
                    );
                }
            }

            // Open in editor
            let editor = env::var("EDITOR")
                .or_else(|_| env::var("VISUAL"))
                .unwrap_or_else(|_| "vim".to_string());

            if cli.json {
                println!(
                    "{}",
                    serde_json::json!({
                        "action": "edit",
                        "path": config_path.display().to_string(),
                        "editor": editor
                    })
                );
            } else {
                println!(
                    "Opening {} with {}...",
                    config_path.display().to_string().cyan(),
                    editor.yellow()
                );
            }

            let status = Command::new(&editor)
                .arg(&config_path)
                .status()
                .context("Failed to open editor")?;

            if !status.success() {
                anyhow::bail!("Editor exited with non-zero status");
            }
        }
        Some(ConfigAction::Migrate) => {
            migrate(cli)?;
        }
        Some(ConfigAction::Reset) => {
            let config_path = Config::config_file_path()?;

            if !cli.json {
                print!(
                    "{} Reset configuration to defaults? [y/N] ",
                    "Warning:".yellow().bold()
                );
                io::stdout().flush()?;

                let mut input = String::new();
                io::stdin().read_line(&mut input)?;

                if !input.trim().eq_ignore_ascii_case("y") {
                    println!("Cancelled.");
                    return Ok(());
                }
            }

            // Write default config
            let config = Config::default();
            let yaml = serde_yml::to_string(&config)?;
            if let Some(parent) = config_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&config_path, yaml)?;

            if cli.json {
                println!(
                    "{}",
                    serde_json::json!({
                        "action": "reset",
                        "path": config_path.display().to_string(),
                        "success": true
                    })
                );
            } else {
                println!("{}", "Configuration reset to defaults.".green());
            }
        }
    }

    Ok(())
}

/// Migrate `~/.clx/config.yaml` from the legacy `ollama:` block to the new
/// `providers:` / `llm:` schema.
///
/// Steps:
/// 1. Read and parse the raw YAML file.
/// 2. Bail if the file already uses the new schema OR has no legacy block.
/// 3. Call `translate_legacy_in_place()`, clear `ollama`, write a `.bak` backup,
///    then atomically replace the original file via a temp-file rename.
fn migrate(cli: &Cli) -> Result<()> {
    let config_path = Config::config_file_path().context("Failed to resolve config path")?;

    if !config_path.exists() {
        anyhow::bail!(
            "config file not found at {}; nothing to migrate",
            config_path.display()
        );
    }

    // Parse the raw file (no env-var overrides — we want the on-disk shape).
    let raw = std::fs::read_to_string(&config_path)
        .with_context(|| format!("Failed to read {}", config_path.display()))?;
    let mut cfg: Config = serde_yml::from_str(&raw)
        .with_context(|| format!("Failed to parse {}", config_path.display()))?;

    // Guard: already new schema.
    if !cfg.providers.is_empty() || cfg.llm.is_some() {
        anyhow::bail!("config already uses the new schema; nothing to migrate");
    }

    // Guard: nothing legacy to migrate.
    if cfg.ollama.is_none() {
        anyhow::bail!(
            "config has neither legacy 'ollama:' block nor new sections; nothing to migrate"
        );
    }

    // Translate legacy → new schema in memory.
    cfg.translate_legacy_in_place();
    // Drop the legacy block so it is absent from the written file.
    cfg.ollama = None;

    // Write backup.
    let bak_path = config_path.with_extension("yaml.bak");
    std::fs::copy(&config_path, &bak_path)
        .with_context(|| format!("Failed to write backup to {}", bak_path.display()))?;

    // Serialize and atomically replace the config file.
    let new_yaml = serde_yml::to_string(&cfg).context("Failed to serialize updated config")?;
    let tmp_path = config_path.with_extension("yaml.tmp");
    std::fs::write(&tmp_path, &new_yaml)
        .with_context(|| format!("Failed to write temp file {}", tmp_path.display()))?;
    std::fs::rename(&tmp_path, &config_path)
        .with_context(|| format!("Failed to rename temp file to {}", config_path.display()))?;

    if cli.json {
        println!(
            "{}",
            serde_json::json!({
                "action": "migrate",
                "config": config_path.display().to_string(),
                "backup": bak_path.display().to_string(),
                "success": true
            })
        );
    } else {
        println!(
            "migrated config; backup at {}",
            bak_path.display().to_string().cyan()
        );
    }

    Ok(())
}
