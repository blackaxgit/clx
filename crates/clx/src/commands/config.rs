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

    /// Read a single config value by dotted key (e.g. `validator.default_decision`).
    Get {
        /// Dotted key path into the raw global config (e.g. `context.embedding_model`).
        key: String,
    },

    /// Set a single config value by dotted key, then validate (global config only).
    Set {
        /// Dotted key path into the raw global config (e.g. `validator.default_decision`).
        key: String,

        /// Value to assign. Parsed as bool/int/float when possible, else string.
        value: String,
    },
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
        Some(ConfigAction::Get { key }) => {
            config_get(cli, key)?;
        }
        Some(ConfigAction::Set { key, value }) => {
            config_set(cli, key, value)?;
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

// ---------------------------------------------------------------------------
// `config get` / `config set` (Issue 8)
// ---------------------------------------------------------------------------

/// Walk a dotted key path through a raw YAML mapping and return the leaf node.
///
/// Returns `None` when any intermediate segment is missing or is not a mapping.
fn yaml_get<'a>(root: &'a serde_yml::Value, key: &str) -> Option<&'a serde_yml::Value> {
    let mut cur = root;
    for seg in key.split('.') {
        let map = cur.as_mapping()?;
        cur = map.get(serde_yml::Value::String(seg.to_owned()))?;
    }
    Some(cur)
}

/// Format a scalar YAML leaf for display. Refuses non-scalar leaves (maps /
/// sequences) so `get` never prints a structured subtree as if it were a value.
fn yaml_scalar_to_string(v: &serde_yml::Value) -> Option<String> {
    match v {
        serde_yml::Value::String(s) => Some(s.clone()),
        serde_yml::Value::Bool(b) => Some(b.to_string()),
        serde_yml::Value::Number(n) => Some(n.to_string()),
        serde_yml::Value::Null => Some("null".to_owned()),
        _ => None,
    }
}

/// Parse a CLI string value into the most specific YAML scalar: bool, then
/// integer, then float, falling back to a string (Q8-a). `Config::load`
/// validation is the safety net for an unexpected type.
fn parse_value(value: &str) -> serde_yml::Value {
    if let Ok(b) = value.parse::<bool>() {
        return serde_yml::Value::Bool(b);
    }
    if let Ok(i) = value.parse::<i64>() {
        return serde_yml::Value::Number(i.into());
    }
    if let Ok(f) = value.parse::<f64>() {
        return serde_yml::Value::Number(serde_yml::Number::from(f));
    }
    serde_yml::Value::String(value.to_owned())
}

/// Walk/create the dotted path in `root`, creating intermediate mappings, and
/// assign `leaf` at the final segment.
fn yaml_set(root: &mut serde_yml::Value, key: &str, leaf: serde_yml::Value) -> Result<()> {
    // Ensure the root itself is a mapping (an empty/Null document becomes one).
    if !root.is_mapping() {
        *root = serde_yml::Value::Mapping(serde_yml::Mapping::new());
    }

    let segments: Vec<&str> = key.split('.').collect();
    let mut cur = root;
    for seg in &segments[..segments.len() - 1] {
        let map = cur
            .as_mapping_mut()
            .context("config path traverses a non-mapping node")?;
        let entry = map
            .entry(serde_yml::Value::String((*seg).to_owned()))
            .or_insert_with(|| serde_yml::Value::Mapping(serde_yml::Mapping::new()));
        // If an existing intermediate is not a mapping, replace it with one so
        // the dotted path can be created.
        if !entry.is_mapping() {
            *entry = serde_yml::Value::Mapping(serde_yml::Mapping::new());
        }
        cur = entry;
    }

    let last = segments[segments.len() - 1];
    let map = cur
        .as_mapping_mut()
        .context("config path traverses a non-mapping node")?;
    map.insert(serde_yml::Value::String(last.to_owned()), leaf);
    Ok(())
}

/// `clx config get <key>`: read the RAW global config file (no env/project
/// contamination, no legacy translation) and print the scalar leaf at `key`.
fn config_get(cli: &Cli, key: &str) -> Result<()> {
    let config_path = Config::config_file_path().context("Failed to resolve config path")?;

    let raw = std::fs::read_to_string(&config_path).with_context(|| {
        format!(
            "Failed to read config file {}; key not found",
            config_path.display()
        )
    })?;

    let root: serde_yml::Value =
        serde_yml::from_str(&raw).context("Failed to parse config file as YAML")?;

    let leaf = yaml_get(&root, key).with_context(|| format!("key not found: {key}"))?;
    let value = yaml_scalar_to_string(leaf)
        .with_context(|| format!("key '{key}' is not a scalar value"))?;

    if cli.json {
        println!("{}", serde_json::json!({ "key": key, "value": value }));
    } else {
        println!("{value}");
    }
    Ok(())
}

/// `clx config set <key> <value>`: walk/create the dotted path in the RAW global
/// config, write it back (GLOBAL file only), then validate via
/// `Config::load_from_file_only` (global-only, no env/project contamination).
/// On validation failure, restore the exact original bytes and error.
fn config_set(cli: &Cli, key: &str, value: &str) -> Result<()> {
    let config_path = Config::config_file_path().context("Failed to resolve config path")?;

    // Capture the original bytes (if the file exists) so we can restore on
    // validation failure. A missing file starts from an empty mapping.
    let original: Option<String> = match std::fs::read_to_string(&config_path) {
        Ok(s) => Some(s),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => {
            return Err(e).with_context(|| format!("Failed to read {}", config_path.display()));
        }
    };

    let mut root: serde_yml::Value = match &original {
        Some(s) if !s.trim().is_empty() => {
            serde_yml::from_str(s).context("Failed to parse config file as YAML")?
        }
        _ => serde_yml::Value::Mapping(serde_yml::Mapping::new()),
    };

    yaml_set(&mut root, key, parse_value(value))?;

    let new_yaml = serde_yml::to_string(&root).context("Failed to serialize updated config")?;
    if let Some(parent) = config_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&config_path, &new_yaml)
        .with_context(|| format!("Failed to write {}", config_path.display()))?;

    // Validate the GLOBAL file in isolation (no env/project layering).
    if let Err(e) = Config::load_from_file_only() {
        // Restore the exact original bytes (or remove the file we created).
        match &original {
            Some(bytes) => {
                std::fs::write(&config_path, bytes).with_context(|| {
                    format!(
                        "Failed to restore original config {}",
                        config_path.display()
                    )
                })?;
            }
            None => {
                let _ = std::fs::remove_file(&config_path);
            }
        }
        anyhow::bail!("invalid value for '{key}': {e}; config left unchanged");
    }

    if cli.json {
        println!(
            "{}",
            serde_json::json!({
                "action": "set",
                "key": key,
                "value": value,
                "success": true
            })
        );
    } else {
        println!("{} {} = {}", "Set:".green().bold(), key.cyan(), value);
    }
    Ok(())
}
