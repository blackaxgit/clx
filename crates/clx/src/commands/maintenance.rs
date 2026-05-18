//! `clx maintenance` subcommand — retention sweeps.
//!
//! Applies the configured retention windows to long-lived tables
//! (`tool_events`, `audit_log`). The sweep is non-destructive on
//! `days = 0` (the corresponding table is skipped).
//!
//! Layering: orchestration only. Pure deletion semantics live in
//! `clx-core::storage::*::cleanup_old_*`.

use anyhow::Result;
use clap::Subcommand;
use clx_core::config::Config;
use clx_core::storage::Storage;
use colored::Colorize;

use crate::Cli;

#[derive(Subcommand, Clone)]
pub enum MaintenanceAction {
    /// Apply retention windows to long-lived tables (`tool_events`, `audit_log`).
    Trim {
        /// Override `retention.tool_events_days` (days). 0 disables sweep.
        #[arg(long)]
        tool_events_days: Option<u32>,
        /// Override audit log retention (days). 0 disables sweep.
        #[arg(long)]
        audit_days: Option<u32>,
        /// Show what would be removed without deleting.
        #[arg(long)]
        dry_run: bool,
    },
}

/// Entry point for `clx maintenance ...`.
pub async fn cmd_maintenance(cli: &Cli, action: &MaintenanceAction) -> Result<()> {
    match action {
        MaintenanceAction::Trim {
            tool_events_days,
            audit_days,
            dry_run,
        } => trim(cli, *tool_events_days, *audit_days, *dry_run),
    }
}

fn trim(
    cli: &Cli,
    tool_events_days: Option<u32>,
    audit_days: Option<u32>,
    dry_run: bool,
) -> Result<()> {
    let config = Config::load().unwrap_or_default();
    let storage = Storage::open_default()?;

    let te_days = tool_events_days.unwrap_or(config.retention.tool_events_days);
    // Audit days default is 90 if user did not set anything explicit.
    let au_days = audit_days.unwrap_or(90);

    if dry_run {
        let te_count: i64 = storage
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM tool_events \
                 WHERE created_at < datetime('now', '-' || ?1 || ' seconds')",
                [i64::from(te_days) * 86400],
                |row| row.get(0),
            )
            .unwrap_or(0);
        if cli.json {
            println!(
                "{}",
                serde_json::json!({
                    "dry_run": true,
                    "tool_events_days": te_days,
                    "audit_days": au_days,
                    "tool_events_would_delete": te_count,
                })
            );
        } else {
            println!("{} (dry-run)", "clx maintenance trim".bold());
            println!("  tool_events older than {te_days}d: {te_count} row(s)");
            println!("  audit_log  older than {au_days}d: (count not estimated in dry-run)");
        }
        return Ok(());
    }

    let te_deleted = storage.cleanup_old_tool_events(te_days)?;
    let au_deleted = if au_days == 0 {
        0
    } else {
        storage.cleanup_old_audit_logs(au_days)?
    };

    if cli.json {
        println!(
            "{}",
            serde_json::json!({
                "tool_events_deleted": te_deleted,
                "audit_log_deleted": au_deleted,
                "tool_events_days": te_days,
                "audit_days": au_days,
            })
        );
    } else {
        println!("{}", "clx maintenance trim".bold());
        println!(
            "  tool_events (>{te_days}d): {} row(s) removed",
            te_deleted.to_string().yellow()
        );
        println!(
            "  audit_log  (>{au_days}d): {} row(s) removed",
            au_deleted.to_string().yellow()
        );
    }
    Ok(())
}
