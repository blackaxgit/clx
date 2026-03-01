//! Rules command: manage command validation rules.

use anyhow::{Context, Result};
use clap::Subcommand;
use colored::Colorize;
use std::env;
use std::io::{self, Write};

use clx_core::policy::{PolicyEngine, RuleSource};
use clx_core::storage::Storage;
use clx_core::types::{LearnedRule, RuleType};

use crate::Cli;
use crate::types::{LearnedRuleInfo, RuleInfo, RulesOutput};

#[derive(Subcommand)]
pub enum RulesAction {
    /// List all rules (builtin, learned, and custom)
    List,

    /// Add a pattern to the whitelist (allow)
    Allow {
        /// Pattern to allow (e.g., "npm test*", "cargo build")
        pattern: String,

        /// Make this a global rule (default is project-specific)
        #[arg(long)]
        global: bool,
    },

    /// Add a pattern to the blacklist (deny)
    Deny {
        /// Pattern to deny (e.g., "rm -rf /*")
        pattern: String,

        /// Make this a global rule (default is project-specific)
        #[arg(long)]
        global: bool,
    },

    /// Clear all learned rules
    Reset {
        /// Also clear manually added rules
        #[arg(long)]
        all: bool,
    },
}

/// Rules management
pub async fn cmd_rules(cli: &Cli, action: &RulesAction) -> Result<()> {
    match action {
        RulesAction::List => {
            let engine = PolicyEngine::new();

            // Separate rules by source
            let mut builtin_whitelist: Vec<RuleInfo> = vec![];
            let mut builtin_blacklist: Vec<RuleInfo> = vec![];
            let mut config_whitelist: Vec<RuleInfo> = vec![];
            let mut config_blacklist: Vec<RuleInfo> = vec![];

            for rule in engine.whitelist_rules() {
                let info = RuleInfo {
                    pattern: rule.pattern.clone(),
                    description: rule.description.clone(),
                };
                match rule.source {
                    RuleSource::Builtin => builtin_whitelist.push(info),
                    RuleSource::Config => config_whitelist.push(info),
                    _ => {}
                }
            }

            for rule in engine.blacklist_rules() {
                let info = RuleInfo {
                    pattern: rule.pattern.clone(),
                    description: rule.description.clone(),
                };
                match rule.source {
                    RuleSource::Builtin => builtin_blacklist.push(info),
                    RuleSource::Config => config_blacklist.push(info),
                    _ => {}
                }
            }

            // Get learned rules from database
            let learned: Vec<LearnedRuleInfo> = Storage::open_default()
                .ok()
                .and_then(|s| s.get_rules().ok())
                .unwrap_or_default()
                .into_iter()
                .map(|r| LearnedRuleInfo {
                    pattern: r.pattern,
                    rule_type: r.rule_type.as_str().to_string(),
                    confirmation_count: r.confirmation_count,
                    denial_count: r.denial_count,
                    project_path: r.project_path,
                })
                .collect();

            if cli.json {
                let output = RulesOutput {
                    builtin_whitelist,
                    builtin_blacklist,
                    learned,
                    config_whitelist,
                    config_blacklist,
                };
                println!("{}", serde_json::to_string_pretty(&output)?);
            } else {
                println!("{}", "Policy Rules".cyan().bold());
                println!("{}", "=".repeat(60));
                println!();

                // Builtin Whitelist
                println!(
                    "{} ({})",
                    "Builtin Whitelist".green().bold(),
                    builtin_whitelist.len()
                );
                println!("{}", "-".repeat(40));
                for rule in &builtin_whitelist {
                    println!("  {} {}", "+".green(), rule.pattern);
                }
                println!();

                // Builtin Blacklist
                println!(
                    "{} ({})",
                    "Builtin Blacklist".red().bold(),
                    builtin_blacklist.len()
                );
                println!("{}", "-".repeat(40));
                for rule in &builtin_blacklist {
                    println!(
                        "  {} {} {}",
                        "-".red(),
                        rule.pattern,
                        rule.description
                            .as_ref()
                            .map(|d| format!("({d})").dimmed().to_string())
                            .unwrap_or_default()
                    );
                }
                println!();

                // Config rules (if any)
                if !config_whitelist.is_empty() || !config_blacklist.is_empty() {
                    println!("{}", "Custom Rules (from config)".yellow().bold());
                    println!("{}", "-".repeat(40));
                    for rule in &config_whitelist {
                        println!("  {} {}", "+".green(), rule.pattern);
                    }
                    for rule in &config_blacklist {
                        println!("  {} {}", "-".red(), rule.pattern);
                    }
                    println!();
                }

                // Learned rules
                println!("{} ({})", "Learned Rules".cyan().bold(), learned.len());
                println!("{}", "-".repeat(40));
                if learned.is_empty() {
                    println!("  {}", "No learned rules yet.".dimmed());
                } else {
                    for rule in &learned {
                        let type_indicator = if rule.rule_type == "allow" {
                            "+".green()
                        } else {
                            "-".red()
                        };
                        let scope = rule
                            .project_path
                            .as_ref()
                            .map_or_else(|| "[global]".to_string(), |p| format!("[{p}]"));
                        println!(
                            "  {} {} {} (confirmed: {}, denied: {})",
                            type_indicator,
                            rule.pattern,
                            scope.dimmed(),
                            rule.confirmation_count,
                            rule.denial_count
                        );
                    }
                }
            }
        }

        RulesAction::Allow { pattern, global } => {
            let storage = Storage::open_default().context("Failed to open database")?;

            let mut rule = LearnedRule::new(pattern.clone(), RuleType::Allow, "cli".to_string());

            if !*global {
                // Use current directory as project path
                if let Ok(cwd) = env::current_dir() {
                    rule.project_path = Some(cwd.display().to_string());
                }
            }

            storage.add_rule(&rule)?;

            if cli.json {
                println!(
                    "{}",
                    serde_json::json!({
                        "action": "allow",
                        "pattern": pattern,
                        "global": global,
                        "success": true
                    })
                );
            } else {
                println!(
                    "{} Added whitelist rule: {}",
                    "Success:".green().bold(),
                    pattern.cyan()
                );
                if !*global {
                    println!(
                        "  Scope: {}",
                        rule.project_path.unwrap_or_else(|| "global".to_string())
                    );
                }
            }
        }

        RulesAction::Deny { pattern, global } => {
            let storage = Storage::open_default().context("Failed to open database")?;

            let mut rule = LearnedRule::new(pattern.clone(), RuleType::Deny, "cli".to_string());

            if !*global && let Ok(cwd) = env::current_dir() {
                rule.project_path = Some(cwd.display().to_string());
            }

            storage.add_rule(&rule)?;

            if cli.json {
                println!(
                    "{}",
                    serde_json::json!({
                        "action": "deny",
                        "pattern": pattern,
                        "global": global,
                        "success": true
                    })
                );
            } else {
                println!(
                    "{} Added blacklist rule: {}",
                    "Success:".green().bold(),
                    pattern.red()
                );
                if !*global {
                    println!(
                        "  Scope: {}",
                        rule.project_path.unwrap_or_else(|| "global".to_string())
                    );
                }
            }
        }

        RulesAction::Reset { all } => {
            let storage = Storage::open_default().context("Failed to open database")?;

            if !cli.json {
                let msg = if *all {
                    "This will delete ALL learned rules (including manually added ones)."
                } else {
                    "This will delete all automatically learned rules."
                };
                print!("{} {} Continue? [y/N] ", "Warning:".yellow().bold(), msg);
                io::stdout().flush()?;

                let mut input = String::new();
                io::stdin().read_line(&mut input)?;

                if !input.trim().eq_ignore_ascii_case("y") {
                    println!("Cancelled.");
                    return Ok(());
                }
            }

            // Get all rules and delete them
            let rules = storage.get_rules()?;
            let mut deleted_count = 0;

            for rule in rules {
                // If not --all, only delete rules with source "user_decision" or similar
                // For simplicity, we delete all rules when --all, otherwise just user_decision
                if *all || rule.source == "user_decision" {
                    storage.delete_rule(&rule.pattern)?;
                    deleted_count += 1;
                }
            }

            if cli.json {
                println!(
                    "{}",
                    serde_json::json!({
                        "action": "reset",
                        "all": all,
                        "deleted_count": deleted_count,
                        "success": true
                    })
                );
            } else {
                println!(
                    "{} Deleted {} learned rules.",
                    "Success:".green().bold(),
                    deleted_count
                );
            }
        }
    }

    Ok(())
}
