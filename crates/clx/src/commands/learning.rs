//! Learning command: inspect, report on, and manage opt-in learning-mode events.
//!
//! Learning mode (off by default) records every `PreToolUse` decision plus its
//! rationale into the `learning_events` table. This command reads that table:
//! it prints counts (`report`), lists redacted rows (`list`), serializes them
//! (`export --json`), and clears them (`clear --yes`). It is observe-only and
//! suggestion-only: `report` may suggest `clx rules allow Bash(<pattern>)`
//! for repeated diverged asks, but never applies anything automatically.

use anyhow::{Context, Result};
use clap::Subcommand;
use colored::Colorize;

use clx_core::config::Config;
use clx_core::learned_pattern::{is_never_auto_whitelist, pattern_contains_secret};
use clx_core::storage::{LearningFilter, Storage};
use clx_core::types::{EffectiveConfig, LearningEvent};

use crate::Cli;

/// Minimum number of diverged asks for the same command before a rule
/// suggestion is emitted.
const SUGGESTION_THRESHOLD: i64 = 3;

/// Default row cap for `learning list`.
const DEFAULT_LIST_LIMIT: usize = 50;

#[derive(Subcommand)]
pub enum LearningAction {
    /// Print decision/divergence/kind counts plus deterministic suggestions.
    Report,

    /// List recorded (already-redacted) learning events.
    List {
        /// Only show rows with this decision (`allow`/`ask`/`deny`).
        #[arg(long)]
        decision: Option<String>,

        /// Only show diverged rows.
        #[arg(long)]
        diverged: bool,

        /// Maximum number of rows to show (most recent first).
        #[arg(long, default_value_t = DEFAULT_LIST_LIMIT)]
        limit: usize,
    },

    /// Export the (already-redacted) learning events as JSON to stdout.
    Export {
        /// Emit JSON (currently the only supported format; accepted for clarity).
        #[arg(long)]
        json: bool,
    },

    /// Delete ALL learning events. Refuses unless `--yes` is given.
    Clear {
        /// Confirm the destructive clear.
        #[arg(long)]
        yes: bool,
    },
}

/// Learning-mode inspection and management.
pub fn cmd_learning(cli: &Cli, action: &LearningAction) -> Result<()> {
    match action {
        LearningAction::Report => cmd_report(cli),
        LearningAction::List {
            decision,
            diverged,
            limit,
        } => cmd_list(cli, decision.as_deref(), *diverged, *limit),
        LearningAction::Export { json } => cmd_export(cli, *json),
        LearningAction::Clear { yes } => cmd_clear(cli, *yes),
    }
}

/// Compute the current effective-config fingerprint the same way the capture
/// path does: load the config, project the six decision-relevant fields into an
/// [`EffectiveConfig`], and hash it.
fn current_fingerprint() -> Result<String> {
    let config = Config::load().context("Failed to load config")?;
    Ok(effective_config(&config).fingerprint())
}

/// Project the loaded config's validator subtree into the six-field
/// [`EffectiveConfig`] snapshot. Mirrors the capture-side snapshot so the CLI
/// aggregates over rows written under the same effective policy.
fn effective_config(config: &Config) -> EffectiveConfig {
    let v = &config.validator;
    EffectiveConfig {
        default_decision: v.default_decision.as_str().to_string(),
        prompt_sensitivity: serde_token(&v.prompt_sensitivity),
        auto_allow_reads: v.auto_allow_reads,
        layer0_enabled: v.layer0_enabled,
        layer1_enabled: v.layer1_enabled,
        on_validator_unavailable: serde_token(&v.on_validator_unavailable),
    }
}

/// Render a `#[serde(rename_all = "lowercase")]` unit enum to its serialized
/// token (e.g. `Standard` -> `"standard"`). Falls back to an empty string only
/// if serialization unexpectedly fails (never for these fixed enums).
fn serde_token<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_default()
}

/// Whether `command` is a shell-compound (multiple commands chained). Compound
/// commands are never suggested as a single allow pattern.
fn is_compound(command: &str) -> bool {
    command.contains("&&")
        || command.contains("||")
        || command.contains(';')
        || command.contains('|')
}

/// Normalize a captured (already-redacted) command into a rule pattern. The
/// command is used verbatim (trimmed); divergence aggregation already groups by
/// the stored command string.
fn normalize_pattern(command: &str) -> String {
    command.trim().to_string()
}

fn cmd_report(cli: &Cli) -> Result<()> {
    let Ok(storage) = Storage::open_default() else {
        // No DB yet (learning never ran): report an empty store rather than error.
        return empty_report(cli);
    };

    let rows = storage
        .list_learning_events(&LearningFilter::default())
        .context("Failed to read learning events")?;

    // Tally counts.
    let total = rows.len();
    let mut allow = 0usize;
    let mut ask = 0usize;
    let mut deny = 0usize;
    let mut diverged_true = 0usize;
    let mut diverged_false = 0usize;
    let mut error_kind = 0usize;
    let mut degraded_kind = 0usize;

    for r in &rows {
        match r.decision.as_str() {
            "allow" => allow += 1,
            "ask" => ask += 1,
            "deny" => deny += 1,
            _ => {}
        }
        if r.diverged {
            diverged_true += 1;
        } else {
            diverged_false += 1;
        }
        match r.kind {
            clx_core::types::LearningKind::Error => error_kind += 1,
            clx_core::types::LearningKind::Degraded => degraded_kind += 1,
            clx_core::types::LearningKind::Decision => {}
        }
    }

    // Build suggestions.
    let fingerprint = current_fingerprint().unwrap_or_default();
    let aggregates = if fingerprint.is_empty() {
        Vec::new()
    } else {
        storage
            .learning_pattern_aggregates(&fingerprint)
            .unwrap_or_default()
    };

    let mut rule_suggestions: Vec<String> = Vec::new();
    for (command, count) in &aggregates {
        if *count < SUGGESTION_THRESHOLD {
            continue;
        }
        let pattern = normalize_pattern(command);
        if is_never_auto_whitelist(command)
            || pattern_contains_secret(&pattern)
            || is_compound(command)
        {
            continue;
        }
        rule_suggestions.push(format!(
            "Suggestion: {count} diverged asks for '{command}' \u{2192} consider: clx rules allow Bash({pattern})"
        ));
    }

    // L1-unavailable / validator-unavailable error suggestion. The hook records the
    // four validator-unavailable arms with kind=Error/Degraded regardless of how the
    // decision finally resolved (allow/ask/deny), so kind is the authoritative signal
    // here — more robust than matching the divergence-reason text (which is absent when
    // an unavailable arm resolves to allow).
    let l1_unavailable = error_kind + degraded_kind;

    if cli.json {
        let out = serde_json::json!({
            "total": total,
            "by_decision": { "allow": allow, "ask": ask, "deny": deny },
            "by_diverged": { "true": diverged_true, "false": diverged_false },
            "by_kind": { "error": error_kind, "degraded": degraded_kind },
            "suggestions": rule_suggestions,
            "validator_unavailable_events": l1_unavailable,
        });
        println!("{}", serde_json::to_string_pretty(&out)?);
        return Ok(());
    }

    println!("{}", "Learning Report".cyan().bold());
    println!("{}", "=".repeat(60));
    println!("Total events: {total}");
    println!();
    println!("{}", "By decision".bold());
    println!("  allow: {allow}");
    println!("  ask:   {ask}");
    println!("  deny:  {deny}");
    println!();
    println!("{}", "By divergence".bold());
    println!("  diverged:     {diverged_true}");
    println!("  not diverged: {diverged_false}");
    println!();
    println!("{}", "By kind".bold());
    println!("  error:    {error_kind}");
    println!("  degraded: {degraded_kind}");
    println!();
    println!("{}", "Suggestions".green().bold());
    println!("{}", "-".repeat(40));
    if rule_suggestions.is_empty() && l1_unavailable == 0 {
        println!("  {}", "No suggestions.".dimmed());
    } else {
        for s in &rule_suggestions {
            println!("  {s}");
        }
        if l1_unavailable > 0 {
            println!(
                "  {l1_unavailable} validator-unavailable events \u{2192} check your provider / validator.on_validator_unavailable"
            );
        }
    }

    Ok(())
}

/// Emit an all-zero report (used when no DB exists yet).
fn empty_report(cli: &Cli) -> Result<()> {
    if cli.json {
        let out = serde_json::json!({
            "total": 0,
            "by_decision": { "allow": 0, "ask": 0, "deny": 0 },
            "by_diverged": { "true": 0, "false": 0 },
            "by_kind": { "error": 0, "degraded": 0 },
            "suggestions": [],
            "validator_unavailable_events": 0,
        });
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else {
        println!("{}", "Learning Report".cyan().bold());
        println!("{}", "=".repeat(60));
        println!("Total events: 0");
        println!("  {}", "No learning events recorded.".dimmed());
    }
    Ok(())
}

fn cmd_list(cli: &Cli, decision: Option<&str>, diverged: bool, limit: usize) -> Result<()> {
    let rows = load_rows(
        decision.map(str::to_owned),
        if diverged { Some(true) } else { None },
        Some(limit),
    )?;

    if cli.json {
        println!("{}", serde_json::to_string_pretty(&rows)?);
        return Ok(());
    }

    if rows.is_empty() {
        println!("{}", "No learning events.".dimmed());
        return Ok(());
    }

    println!(
        "{:<20} {:<10} {:<7} {:<9} {:<9} {}",
        "TS".bold(),
        "TOOL".bold(),
        "DEC".bold(),
        "LAYER".bold(),
        "DIVERGED".bold(),
        "COMMAND".bold()
    );
    println!("{}", "-".repeat(80));
    for r in &rows {
        let command = r.command.as_deref().unwrap_or("");
        let reason = if r.reason.is_empty() {
            String::new()
        } else {
            format!(" \u{2014} {}", r.reason)
        };
        println!(
            "{:<20} {:<10} {:<7} {:<9} {:<9} {}{}",
            truncate(&r.ts, 19),
            truncate(&r.tool, 10),
            truncate(&r.decision, 7),
            truncate(&r.layer, 9),
            r.diverged,
            command,
            reason.dimmed()
        );
    }

    Ok(())
}

fn cmd_export(cli: &Cli, json: bool) -> Result<()> {
    // `--json` and the global `--json` both select JSON; it is the only format.
    let _ = json || cli.json;
    let rows = load_rows(None, None, None)?;
    println!("{}", serde_json::to_string_pretty(&rows)?);
    Ok(())
}

fn cmd_clear(cli: &Cli, yes: bool) -> Result<()> {
    if !yes {
        if cli.json {
            println!(
                "{}",
                serde_json::json!({
                    "action": "clear",
                    "success": false,
                    "error": "refused: pass --yes to confirm clearing all learning events",
                })
            );
        } else {
            println!(
                "{} Refusing to clear learning events without {}.",
                "Warning:".yellow().bold(),
                "--yes".cyan()
            );
        }
        return Ok(());
    }

    let storage = Storage::open_default().context("Failed to open database")?;
    let removed = storage
        .clear_learning_events()
        .context("Failed to clear learning events")?;

    if cli.json {
        println!(
            "{}",
            serde_json::json!({
                "action": "clear",
                "cleared": removed,
                "success": true,
            })
        );
    } else {
        println!("{} Cleared {removed} events", "Success:".green().bold());
    }
    Ok(())
}

/// Load rows through `list_learning_events`, returning an empty vec when the DB
/// does not exist yet (read commands never error on a missing store).
fn load_rows(
    decision: Option<String>,
    diverged: Option<bool>,
    limit: Option<usize>,
) -> Result<Vec<LearningEvent>> {
    let Ok(storage) = Storage::open_default() else {
        return Ok(Vec::new());
    };
    let filter = LearningFilter {
        decision,
        diverged,
        limit,
    };
    storage
        .list_learning_events(&filter)
        .context("Failed to read learning events")
}

/// Truncate a string to `n` chars (byte-safe for ASCII timestamps/tokens).
fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        s.chars().take(n).collect()
    }
}
