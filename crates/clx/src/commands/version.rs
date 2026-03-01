//! Version and default commands.

use anyhow::Result;
use colored::Colorize;

use crate::Cli;

/// Show version information
#[allow(clippy::unnecessary_wraps)] // Returns Result for consistent command handler interface
pub fn cmd_version(cli: &Cli) -> Result<()> {
    if cli.json {
        println!(
            "{}",
            serde_json::json!({
                "version": clx_core::VERSION,
                "name": "clx",
                "description": "Claude Code Extension"
            })
        );
    } else {
        println!(
            "{} {} - Claude Code Extension",
            "clx".cyan().bold(),
            format!("v{}", clx_core::VERSION).yellow()
        );
        println!();
        println!("A command validation and context persistence layer for Claude Code.");
        println!();
        println!("  Config: {}", clx_core::paths::clx_dir().display());
        println!("  License: MIT");
    }

    Ok(())
}

/// Default command when no subcommand is provided
#[allow(clippy::unnecessary_wraps)] // Returns Result for consistent command handler interface
pub fn cmd_default(cli: &Cli) -> Result<()> {
    if cli.json {
        println!(
            "{}",
            serde_json::json!({
                "version": clx_core::VERSION,
                "hint": "Run 'clx --help' for usage information"
            })
        );
    } else {
        println!(
            "{} {}",
            "CLX".cyan().bold(),
            format!("v{}", clx_core::VERSION).dimmed()
        );
        println!();
        println!("A command validation and context persistence layer for Claude Code.");
        println!();
        println!("{}:", "Quick Start".yellow().bold());
        println!("  clx dashboard   Interactive TUI dashboard");
        println!("  clx config      View current configuration");
        println!("  clx rules list  List all validation rules");
        println!();
        println!("Run {} for all available commands.", "'clx --help'".cyan());
    }

    Ok(())
}
