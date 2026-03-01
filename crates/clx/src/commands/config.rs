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
