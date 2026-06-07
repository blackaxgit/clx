//! Rules command: manage command validation rules.

use anyhow::{Context, Result};
use clap::Subcommand;
use colored::Colorize;
use std::env;
use std::io::{self, Write};

use clx_core::policy::{PolicyEngine, RuleSource};
use clx_core::redaction::redact_secrets;
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

    /// Clear learned rules.
    ///
    /// By default (`--learned-only`) only auto-learned rules
    /// (`source="user_decision"`) are removed; explicit user `--global` allows
    /// are preserved. `--all` drops every learned rule.
    Reset {
        /// Drop ALL learned rules, including manually added ones.
        #[arg(long)]
        all: bool,

        /// Only clear auto-learned rules (the default; preserves explicit allows).
        #[arg(long)]
        learned_only: bool,
    },

    /// Export user rules to a versioned JSON envelope.
    Export {
        /// Destination file path.
        file: String,
    },

    /// Import user rules from a versioned JSON envelope (re-validates each entry).
    Import {
        /// Source file path.
        file: String,
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

        RulesAction::Reset { all, learned_only } => {
            // Scope is explicit: `--all` drops everything; otherwise (default,
            // including the explicit `--learned-only`) only auto-learned
            // `source="user_decision"` rows are removed so explicit user
            // `--global` allows survive. `--learned-only` is accepted for
            // clarity but is a no-op relative to the default.
            let _ = learned_only;
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

        RulesAction::Export { file } => {
            cmd_rules_export(cli, file)?;
        }

        RulesAction::Import { file } => {
            cmd_rules_import(cli, file)?;
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Export / Import (Issue 10)
// ---------------------------------------------------------------------------

/// Current export envelope version. Imports of a higher version are rejected
/// with a clear message; this version is forward-compatible only within v1.
const RULES_ENVELOPE_VERSION: u32 = 1;

/// One rule entry in the export/import JSON envelope.
#[derive(serde::Serialize, serde::Deserialize)]
struct ExportedRule {
    pattern: String,
    rule_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    project_path: Option<String>,
}

/// Versioned export envelope: `{"version":1,"rules":[...]}`.
#[derive(serde::Serialize, serde::Deserialize)]
struct RulesEnvelope {
    version: u32,
    rules: Vec<ExportedRule>,
}

/// Export USER rules (global, learned/user-decision and manual) to a versioned
/// JSON envelope. Global rules are those with no `project_path`.
fn cmd_rules_export(cli: &Cli, file: &str) -> Result<()> {
    let storage = Storage::open_default().context("Failed to open database")?;
    let rules = storage.get_rules().context("Failed to read rules")?;

    let exported: Vec<ExportedRule> = rules
        .into_iter()
        .filter(|r| r.project_path.is_none())
        .map(|r| ExportedRule {
            pattern: r.pattern,
            rule_type: r.rule_type.as_str().to_owned(),
            project_path: r.project_path,
        })
        .collect();

    let count = exported.len();
    let envelope = RulesEnvelope {
        version: RULES_ENVELOPE_VERSION,
        rules: exported,
    };

    let json = serde_json::to_string_pretty(&envelope).context("Failed to serialize envelope")?;
    std::fs::write(file, json).with_context(|| format!("Failed to write {file}"))?;

    if cli.json {
        println!(
            "{}",
            serde_json::json!({
                "action": "export",
                "file": file,
                "exported": count,
                "version": RULES_ENVELOPE_VERSION,
                "success": true
            })
        );
    } else {
        println!(
            "{} Exported {} rules to {}",
            "Success:".green().bold(),
            count,
            file.cyan()
        );
    }
    Ok(())
}

/// Import USER rules from a versioned JSON envelope. Each rule is re-validated
/// through the shared secret + malformed-pattern gates (Issue 1); secret-bearing
/// or malformed entries are rejected (warned, redacted) and the valid ones
/// inserted. Malformed JSON / unknown future versions error cleanly with no
/// partial writes.
fn cmd_rules_import(cli: &Cli, file: &str) -> Result<()> {
    use clx_core::learned_pattern::{is_well_formed_pattern, pattern_contains_secret};

    let raw = std::fs::read_to_string(file).with_context(|| format!("Failed to read {file}"))?;

    // Parse the whole envelope FIRST so malformed JSON fails before any write.
    let envelope: RulesEnvelope =
        serde_json::from_str(&raw).context("Failed to parse rules envelope (malformed JSON)")?;

    if envelope.version > RULES_ENVELOPE_VERSION {
        anyhow::bail!(
            "unsupported rules envelope version {} (this build supports up to {})",
            envelope.version,
            RULES_ENVELOPE_VERSION
        );
    }

    let storage = Storage::open_default().context("Failed to open database")?;

    let mut imported = 0usize;
    let mut rejected = 0usize;

    for entry in envelope.rules {
        // Reject secret-bearing or malformed patterns. `is_well_formed_pattern`
        // ALLOWS `*`/`/`, so legitimate wildcard/path rules import fine.
        if pattern_contains_secret(&entry.pattern) || !is_well_formed_pattern(&entry.pattern) {
            rejected += 1;
            // Redact the pattern before logging so a secret-bearing entry never
            // reaches logs verbatim.
            tracing::warn!(
                pattern = %redact_secrets(&entry.pattern),
                "rejected rule on import (secret or malformed pattern)"
            );
            continue;
        }

        // Strictly parse the rule type: an unknown/unsupported value (e.g.
        // "graylist" or a typo) must be REJECTED, never silently defaulted to
        // an allow rule (fail-open). Only "allow"/"deny" are accepted.
        let Ok(rule_type) = entry.rule_type.parse::<RuleType>() else {
            rejected += 1;
            tracing::warn!(
                rule_type = %entry.rule_type,
                pattern = %redact_secrets(&entry.pattern),
                "rejected rule on import (unknown rule type)"
            );
            continue;
        };
        let mut rule = LearnedRule::new(entry.pattern, rule_type, "import".to_owned());
        rule.project_path = entry.project_path;
        storage
            .add_rule(&rule)
            .context("Failed to insert imported rule")?;
        imported += 1;
    }

    if cli.json {
        println!(
            "{}",
            serde_json::json!({
                "action": "import",
                "file": file,
                "imported": imported,
                "rejected": rejected,
                "success": true
            })
        );
    } else {
        println!(
            "{} Imported {} rules ({} rejected) from {}",
            "Success:".green().bold(),
            imported,
            rejected,
            file.cyan()
        );
    }
    Ok(())
}
