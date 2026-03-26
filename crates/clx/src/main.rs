//! CLX CLI Binary
//!
//! Command-line interface for managing CLX configuration and state.
//!
//! Commands:
//! - recall <query>: Search context DB, show results
//! - config: Show current config as YAML
//! - config edit: Open config in $EDITOR
//! - config reset: Reset config to defaults
//! - rules list: Show all rules (builtin + learned + custom)
//! - rules allow <pattern>: Add pattern to whitelist
//! - rules deny <pattern>: Add pattern to blacklist
//! - rules reset: Clear learned rules
//! - credentials set <key> <value>: Store credential in keychain
//! - credentials get <key>: Retrieve credential
//! - credentials list: List stored credentials
//! - credentials delete <key>: Delete credential
//! - dashboard: Interactive TUI dashboard (status, sessions, audit, stats)
//! - install: Install CLX integration
//! - uninstall: Remove CLX integration
//! - version: Show version info

mod commands;
mod dashboard;
mod types;

use anyhow::Result;
use clap::{CommandFactory, Parser, Subcommand};
use colored::Colorize;
use std::io;
use std::process;
use tracing_subscriber::EnvFilter;

use commands::{ConfigAction, CredentialsAction, EmbeddingsAction, RulesAction};

/// CLX - Claude Code Extension
#[derive(Parser)]
#[command(name = "clx")]
#[command(author, version, about = "CLX - Claude Code Extension CLI")]
#[command(
    long_about = "Command-line interface for managing CLX configuration, rules, and context."
)]
pub struct Cli {
    /// Enable verbose output
    #[arg(short, long, global = true)]
    pub verbose: bool,

    /// Output in JSON format for programmatic use
    #[arg(long, global = true)]
    pub json: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Search context database for past interactions
    Recall {
        /// Search query
        query: String,
    },

    /// View or manage configuration
    Config {
        #[command(subcommand)]
        action: Option<ConfigAction>,
    },

    /// Manage command validation rules
    Rules {
        #[command(subcommand)]
        action: RulesAction,
    },

    /// Install CLX integration into Claude Code
    Install,

    /// Remove CLX integration from Claude Code
    Uninstall {
        /// Also remove ~/.clx/ directory and all data
        #[arg(long)]
        purge: bool,
    },

    /// Show version information
    Version,

    /// Manage credentials stored in the system keychain
    Credentials {
        #[command(subcommand)]
        action: CredentialsAction,
    },

    /// Generate embeddings for existing snapshots (backfill)
    EmbedBackfill {
        /// Only show what would be done, don't generate embeddings
        #[arg(long)]
        dry_run: bool,
    },

    /// Generate shell completions for the specified shell
    Completions {
        /// Shell type (bash, zsh, fish, elvish, powershell)
        #[arg(value_enum)]
        shell: clap_complete::Shell,
    },

    /// Manage embeddings (status, rebuild for model migration)
    Embeddings {
        #[command(subcommand)]
        action: EmbeddingsAction,
    },

    /// Check CLX system health
    Health {
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Interactive TUI dashboard
    Dashboard {
        /// Filter by last N days
        #[arg(long, short, default_value = "7")]
        days: u32,
        /// Refresh interval in seconds
        #[arg(long, default_value = "2")]
        refresh: u64,
    },
}

#[tokio::main]
async fn main() {
    clx_core::init_sqlite_vec();

    let cli = Cli::parse();

    // Initialize tracing (only if not JSON mode)
    if !cli.json {
        let filter = if cli.verbose { "debug" } else { "warn" };
        tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| filter.into()))
            .init();
    }

    let result = run_command(&cli).await;

    match result {
        Ok(()) => process::exit(0),
        Err(e) => {
            if cli.json {
                let error_json = serde_json::json!({
                    "error": e.to_string()
                });
                eprintln!("{}", serde_json::to_string_pretty(&error_json).unwrap());
            } else {
                eprintln!("{}: {}", "Error".red().bold(), e);
            }
            process::exit(1);
        }
    }
}

async fn run_command(cli: &Cli) -> Result<()> {
    match &cli.command {
        Some(Commands::Recall { query }) => commands::cmd_recall(cli, query).await,
        Some(Commands::Config { action }) => commands::cmd_config(cli, action.as_ref()).await,
        Some(Commands::Rules { action }) => commands::cmd_rules(cli, action).await,
        Some(Commands::Install) => commands::cmd_install(cli).await,
        Some(Commands::Uninstall { purge }) => commands::cmd_uninstall(cli, *purge).await,
        Some(Commands::Version) => commands::cmd_version(cli),
        Some(Commands::Credentials { action }) => commands::cmd_credentials(cli, action),
        Some(Commands::EmbedBackfill { dry_run }) => {
            commands::cmd_embed_backfill(cli, *dry_run).await
        }
        Some(Commands::Completions { shell }) => {
            clap_complete::generate(*shell, &mut Cli::command(), "clx", &mut io::stdout());
            Ok(())
        }
        Some(Commands::Embeddings { action }) => commands::cmd_embeddings(cli, action).await,
        Some(Commands::Health { json }) => commands::health::cmd_health(*json || cli.json).await,
        Some(Commands::Dashboard { days, refresh }) => dashboard::run_dashboard(*days, *refresh)
            .map_err(|e| anyhow::anyhow!("Dashboard error: {e}")),
        None => commands::cmd_default(cli),
    }
}
