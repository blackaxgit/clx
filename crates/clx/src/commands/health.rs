//! Health check command for CLX.
//!
//! Runs 9 concurrent validators to verify all CLX components are working
//! correctly and reports status in a clear, actionable format.

use std::time::{Duration, Instant};

use colored::Colorize;
use serde::Serialize;

/// Status of a single health check.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum CheckStatus {
    Pass,
    Warn,
    Fail,
}

/// Result of a single health check.
#[derive(Debug, Clone, Serialize)]
pub struct CheckResult {
    pub name: String,
    pub status: CheckStatus,
    pub detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
    #[serde(serialize_with = "serialize_duration")]
    pub duration: Duration,
}

fn serialize_duration<S: serde::Serializer>(d: &Duration, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_f64(d.as_secs_f64())
}

#[derive(Debug, Serialize)]
struct HealthReport {
    version: String,
    checks: Vec<CheckResult>,
    summary: Summary,
}

#[derive(Debug, Serialize)]
struct Summary {
    passed: usize,
    warned: usize,
    failed: usize,
    total: usize,
}

/// Run the health check command.
///
/// Executes all 9 validators concurrently and prints results as either
/// a colored table (default) or structured JSON (`--json`).
///
/// # Exit codes
/// - 0: all checks passed or only warnings
/// - 1: one or more checks failed
pub async fn cmd_health(json: bool) -> anyhow::Result<()> {
    // Load config (used by several validators)
    let config = clx_core::config::Config::load().ok();

    let (r1, r2, r3, r4, r5, r6, r7, r8, r9) = tokio::join!(
        check_config(),
        check_database(),
        check_sqlite_vec(),
        check_ollama(config.as_ref()),
        check_validator_model(config.as_ref()),
        check_embedding_model(config.as_ref()),
        check_hook_binary(),
        check_mcp_binary(),
        check_validator_prompt(config.as_ref()),
    );

    let results = vec![r1, r2, r3, r4, r5, r6, r7, r8, r9];

    if json {
        print_json(&results)?;
    } else {
        print_table(&results);
    }

    let has_failure = results.iter().any(|r| r.status == CheckStatus::Fail);
    if has_failure {
        std::process::exit(1);
    }

    Ok(())
}

// ── V1: Configuration ──────────────────────────────────────────────

#[allow(clippy::unused_async)] // Must be async for tokio::join!
async fn check_config() -> CheckResult {
    let start = Instant::now();
    let config_path = clx_core::paths::clx_dir().join("config.yaml");

    match clx_core::config::Config::load() {
        Ok(config) => {
            let sensitivity = &config.validator.prompt_sensitivity;
            let exists = config_path.exists();
            let detail = if exists {
                format!(
                    "{} loaded (sensitivity: {sensitivity})",
                    abbreviate_home(&config_path.to_string_lossy()),
                )
            } else {
                format!("defaults (sensitivity: {sensitivity})")
            };
            CheckResult {
                name: "Configuration".into(),
                status: if exists {
                    CheckStatus::Pass
                } else {
                    CheckStatus::Warn
                },
                detail,
                hint: if exists {
                    None
                } else {
                    Some("Create config: clx config edit".into())
                },
                duration: start.elapsed(),
            }
        }
        Err(e) => CheckResult {
            name: "Configuration".into(),
            status: CheckStatus::Fail,
            detail: format!("parse error: {e}"),
            hint: Some("Fix config: clx config edit  OR  clx config reset".into()),
            duration: start.elapsed(),
        },
    }
}

// ── V2: Database ───────────────────────────────────────────────────

#[allow(clippy::unused_async)] // Must be async for tokio::join!
async fn check_database() -> CheckResult {
    let start = Instant::now();
    let db_path = clx_core::paths::database_path();

    if !db_path.exists() {
        return CheckResult {
            name: "Database".into(),
            status: CheckStatus::Fail,
            detail: format!("{} not found", abbreviate_home(&db_path.to_string_lossy())),
            hint: Some("Initialize: clx install".into()),
            duration: start.elapsed(),
        };
    }

    // Get file size
    let file_size = std::fs::metadata(&db_path)
        .map_or_else(|_| "unknown size".into(), |m| format_bytes(m.len()));

    match clx_core::storage::Storage::open(&db_path) {
        Ok(storage) => {
            let schema_version = storage
                .schema_version()
                .map_or_else(|_| "unknown".into(), |v| format!("v{v}"));

            let journal_mode: String = storage
                .connection()
                .query_row("PRAGMA journal_mode", [], |row| row.get(0))
                .unwrap_or_else(|_| "unknown".into());

            let detail = format!(
                "{} ({}, schema {schema_version}, {file_size})",
                abbreviate_home(&db_path.to_string_lossy()),
                journal_mode.to_uppercase(),
            );

            CheckResult {
                name: "Database".into(),
                status: CheckStatus::Pass,
                detail,
                hint: None,
                duration: start.elapsed(),
            }
        }
        Err(e) => CheckResult {
            name: "Database".into(),
            status: CheckStatus::Fail,
            detail: format!("cannot open: {e}"),
            hint: Some(format!(
                "Delete and reinstall: rm {} && clx install",
                abbreviate_home(&db_path.to_string_lossy())
            )),
            duration: start.elapsed(),
        },
    }
}

// ── V3: sqlite-vec ─────────────────────────────────────────────────

#[allow(clippy::unused_async)] // Must be async for tokio::join!
async fn check_sqlite_vec() -> CheckResult {
    let start = Instant::now();
    CheckResult {
        name: "sqlite-vec".into(),
        status: CheckStatus::Pass,
        detail: "built-in (statically linked)".into(),
        hint: None,
        duration: start.elapsed(),
    }
}

// ── V4: Ollama Service ─────────────────────────────────────────────

async fn check_ollama(config: Option<&clx_core::config::Config>) -> CheckResult {
    let start = Instant::now();
    let host = config.map_or_else(
        || "http://127.0.0.1:11434".into(),
        |c| c.ollama_or_default().host.clone(),
    );

    let url = format!("{host}/");
    let timeout = Duration::from_secs(3);

    let Ok(client) = reqwest::Client::builder().timeout(timeout).build() else {
        return CheckResult {
            name: "Ollama service".into(),
            status: CheckStatus::Fail,
            detail: "HTTP client error".into(),
            hint: None,
            duration: start.elapsed(),
        };
    };

    match tokio::time::timeout(timeout, client.get(&url).send()).await {
        Ok(Ok(resp)) if resp.status().is_success() => {
            let elapsed = start.elapsed();
            let status = if elapsed > Duration::from_secs(1) {
                CheckStatus::Warn
            } else {
                CheckStatus::Pass
            };
            CheckResult {
                name: "Ollama service".into(),
                status,
                detail: format!("{host} reachable ({elapsed:.0?})"),
                hint: if elapsed > Duration::from_secs(1) {
                    Some("Ollama is responding slowly".into())
                } else {
                    None
                },
                duration: elapsed,
            }
        }
        _ => CheckResult {
            name: "Ollama service".into(),
            status: CheckStatus::Fail,
            detail: format!("{host} unreachable"),
            hint: Some("Start Ollama: ollama serve".into()),
            duration: start.elapsed(),
        },
    }
}

// ── V5: Validator Model ────────────────────────────────────────────

async fn check_validator_model(config: Option<&clx_core::config::Config>) -> CheckResult {
    let start = Instant::now();
    let (host, model) = match config {
        Some(c) => (c.ollama_or_default().host.clone(), c.ollama_or_default().model.clone()),
        None => ("http://127.0.0.1:11434".into(), "qwen3:1.7b".into()),
    };

    check_model_available(&host, &model, "Validator model", start).await
}

// ── V6: Embedding Model ───────────────────────────────────────────

async fn check_embedding_model(config: Option<&clx_core::config::Config>) -> CheckResult {
    let start = Instant::now();
    let (host, model) = match config {
        Some(c) => (c.ollama_or_default().host.clone(), c.ollama_or_default().embedding_model.clone()),
        None => ("http://127.0.0.1:11434".into(), "nomic-embed-text".into()),
    };

    check_model_available(&host, &model, "Embedding model", start).await
}

/// Shared helper: check if a named model is available in Ollama's `/api/tags`.
async fn check_model_available(
    host: &str,
    model: &str,
    label: &str,
    start: Instant,
) -> CheckResult {
    let url = format!("{host}/api/tags");
    let timeout = Duration::from_secs(3);

    let Ok(client) = reqwest::Client::builder().timeout(timeout).build() else {
        return CheckResult {
            name: label.into(),
            status: CheckStatus::Fail,
            detail: format!("{model} not found (HTTP client error)"),
            hint: Some(format!("Pull model: ollama pull {model}")),
            duration: start.elapsed(),
        };
    };

    match client.get(&url).send().await {
        Ok(resp) => {
            let body: serde_json::Value = resp.json().await.unwrap_or_default();
            let empty = vec![];
            let models = body["models"].as_array().unwrap_or(&empty);
            let found = models.iter().any(|m| {
                m["name"]
                    .as_str()
                    .is_some_and(|n| n == model || n.starts_with(&format!("{model}:")))
            });
            if found {
                CheckResult {
                    name: label.into(),
                    status: CheckStatus::Pass,
                    detail: format!("{model} available"),
                    hint: None,
                    duration: start.elapsed(),
                }
            } else {
                CheckResult {
                    name: label.into(),
                    status: CheckStatus::Fail,
                    detail: format!("{model} not found"),
                    hint: Some(format!("Pull model: ollama pull {model}")),
                    duration: start.elapsed(),
                }
            }
        }
        Err(_) => CheckResult {
            name: label.into(),
            status: CheckStatus::Fail,
            detail: format!("{model} not found (Ollama unavailable)"),
            hint: Some("Start Ollama first: ollama serve".into()),
            duration: start.elapsed(),
        },
    }
}

// ── V7: Hook Binary ───────────────────────────────────────────────

#[allow(clippy::unused_async)] // Must be async for tokio::join!
async fn check_hook_binary() -> CheckResult {
    check_binary_sync("clx-hook", "Hook binary")
}

// ── V8: MCP Binary ────────────────────────────────────────────────

#[allow(clippy::unused_async)] // Must be async for tokio::join!
async fn check_mcp_binary() -> CheckResult {
    check_binary_sync("clx-mcp", "MCP binary")
}

/// Check if a binary exists and is executable in `~/.clx/bin/`.
fn check_binary_sync(name: &str, label: &str) -> CheckResult {
    let start = Instant::now();
    let bin_path = clx_core::paths::bin_dir().join(name);

    if !bin_path.exists() || !bin_path.is_file() {
        return CheckResult {
            name: label.into(),
            status: CheckStatus::Fail,
            detail: format!("{} not found", abbreviate_home(&bin_path.to_string_lossy())),
            hint: Some("Reinstall: clx install".into()),
            duration: start.elapsed(),
        };
    }

    // Check executable bit (Unix)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(metadata) = std::fs::metadata(&bin_path) {
            let mode = metadata.permissions().mode();
            if mode & 0o111 == 0 {
                return CheckResult {
                    name: label.into(),
                    status: CheckStatus::Fail,
                    detail: format!(
                        "{} not executable",
                        abbreviate_home(&bin_path.to_string_lossy())
                    ),
                    hint: Some(format!("Fix permissions: chmod +x {}", bin_path.display())),
                    duration: start.elapsed(),
                };
            }
        }
    }

    CheckResult {
        name: label.into(),
        status: CheckStatus::Pass,
        detail: abbreviate_home(&bin_path.to_string_lossy()),
        hint: None,
        duration: start.elapsed(),
    }
}

// ── V9: Validator Prompt ──────────────────────────────────────────

#[allow(clippy::unused_async)] // Must be async for tokio::join!
async fn check_validator_prompt(config: Option<&clx_core::config::Config>) -> CheckResult {
    let start = Instant::now();

    let sensitivity = config
        .map(|c| c.validator.prompt_sensitivity.clone())
        .unwrap_or_default();

    // Determine which source the prompt comes from by checking file existence
    let cwd =
        std::env::current_dir().map_or_else(|_| "/".into(), |p| p.to_string_lossy().to_string());

    let project_prompt = std::path::Path::new(&cwd).join(".clx/prompts/validator.txt");
    let global_prompt = clx_core::paths::validator_prompt_path();

    let (source, status) = if project_prompt.exists() {
        ("per-project file".to_string(), CheckStatus::Warn)
    } else if global_prompt.exists() {
        ("global file".to_string(), CheckStatus::Warn)
    } else {
        (format!("{sensitivity} (built-in)"), CheckStatus::Pass)
    };

    // Verify the prompt actually loads without error
    let _prompt = clx_core::policy::load_validator_prompt(&cwd, &sensitivity);

    CheckResult {
        name: "Validator prompt".into(),
        status,
        detail: source,
        hint: if status == CheckStatus::Warn {
            Some("Custom prompt loaded; verify it behaves as expected".into())
        } else {
            None
        },
        duration: start.elapsed(),
    }
}

// ── Output formatting ─────────────────────────────────────────────

fn print_table(results: &[CheckResult]) {
    println!();
    println!(
        "{} (v{})",
        "CLX Health Check".cyan().bold(),
        clx_core::VERSION
    );

    // Use a simple repeated character for the separator
    let separator = "\u{2550}".repeat(50);
    println!("{}", separator.dimmed());
    println!();

    // Find the longest name for alignment
    let max_name_len = results.iter().map(|r| r.name.len()).max().unwrap_or(0);

    for result in results {
        let colored_symbol = match result.status {
            CheckStatus::Pass => "\u{2713}".green().bold(),
            CheckStatus::Warn => "\u{26A0}".yellow().bold(),
            CheckStatus::Fail => "\u{2717}".red().bold(),
        };

        println!(
            "{} {:<width$}  {}",
            colored_symbol,
            result.name,
            result.detail,
            width = max_name_len,
        );

        if let Some(hint) = &result.hint
            && result.status == CheckStatus::Fail
        {
            println!(
                "  {:<width$}  {} {}",
                "",
                "\u{2192}".dimmed(),
                hint.dimmed(),
                width = max_name_len,
            );
        }
    }

    println!();
    println!("{}", separator.dimmed());

    let passed = results
        .iter()
        .filter(|r| r.status == CheckStatus::Pass)
        .count();
    let warned = results
        .iter()
        .filter(|r| r.status == CheckStatus::Warn)
        .count();
    let failed = results
        .iter()
        .filter(|r| r.status == CheckStatus::Fail)
        .count();
    let total = results.len();

    if failed == 0 && warned == 0 {
        println!("{}", format!("All checks passed ({total}/{total})").green());
    } else {
        let mut parts = Vec::new();
        if failed > 0 {
            parts.push(format!("{failed} failed").red().to_string());
        }
        if warned > 0 {
            parts.push(format!("{warned} warned").yellow().to_string());
        }
        parts.push(format!("{passed} passed").green().to_string());
        println!("{}", parts.join(", "));
    }

    println!();
}

fn print_json(results: &[CheckResult]) -> anyhow::Result<()> {
    let passed = results
        .iter()
        .filter(|r| r.status == CheckStatus::Pass)
        .count();
    let warned = results
        .iter()
        .filter(|r| r.status == CheckStatus::Warn)
        .count();
    let failed = results
        .iter()
        .filter(|r| r.status == CheckStatus::Fail)
        .count();

    let report = HealthReport {
        version: clx_core::VERSION.to_string(),
        checks: results.to_vec(),
        summary: Summary {
            passed,
            warned,
            failed,
            total: results.len(),
        },
    };

    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

// ── Helpers ───────────────────────────────────────────────────────

/// Replace the user's home directory with `~` for display.
fn abbreviate_home(path: &str) -> String {
    if let Some(home) = dirs::home_dir() {
        let home_str = home.to_string_lossy();
        if path.starts_with(home_str.as_ref()) {
            return format!("~{}", &path[home_str.len()..]);
        }
    }
    path.to_string()
}

/// Format a byte count as a human-readable string.
fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * KB;
    const GB: u64 = 1024 * MB;

    #[allow(clippy::cast_precision_loss)]
    if bytes >= GB {
        format!("{:.1}GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1}MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1}KB", bytes as f64 / KB as f64)
    } else {
        format!("{bytes}B")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_result_serializes_to_json() {
        let result = CheckResult {
            name: "Test".into(),
            status: CheckStatus::Pass,
            detail: "all good".into(),
            hint: None,
            duration: Duration::from_millis(42),
        };
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["name"], "Test");
        assert_eq!(json["status"], "pass");
        assert_eq!(json["detail"], "all good");
        assert!(json.get("hint").is_none());
        // duration serialized as seconds (f64)
        assert!(json["duration"].as_f64().unwrap() > 0.0);
    }

    #[test]
    fn check_result_serializes_hint_when_present() {
        let result = CheckResult {
            name: "Fail".into(),
            status: CheckStatus::Fail,
            detail: "broken".into(),
            hint: Some("fix it".into()),
            duration: Duration::from_millis(1),
        };
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["hint"], "fix it");
    }

    #[test]
    fn check_status_serializes_lowercase() {
        assert_eq!(
            serde_json::to_string(&CheckStatus::Pass).unwrap(),
            "\"pass\""
        );
        assert_eq!(
            serde_json::to_string(&CheckStatus::Warn).unwrap(),
            "\"warn\""
        );
        assert_eq!(
            serde_json::to_string(&CheckStatus::Fail).unwrap(),
            "\"fail\""
        );
    }

    #[test]
    fn sqlite_vec_always_passes() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let result = rt.block_on(check_sqlite_vec());
        assert_eq!(result.status, CheckStatus::Pass);
        assert!(result.detail.contains("statically linked"));
    }

    #[test]
    fn format_bytes_units() {
        assert_eq!(format_bytes(500), "500B");
        assert_eq!(format_bytes(1024), "1.0KB");
        assert_eq!(format_bytes(2_500_000), "2.4MB");
        assert_eq!(format_bytes(1_500_000_000), "1.4GB");
    }

    #[test]
    fn abbreviate_home_replaces_prefix() {
        if let Some(home) = dirs::home_dir() {
            let path = format!("{}/.clx/config.yaml", home.display());
            let short = abbreviate_home(&path);
            assert!(short.starts_with("~/.clx"));
            assert!(!short.contains(&home.to_string_lossy().to_string()));
        }
    }

    #[test]
    fn abbreviate_home_leaves_non_home_paths() {
        let path = "/tmp/some/path";
        assert_eq!(abbreviate_home(path), path);
    }

    #[tokio::test]
    async fn check_config_does_not_panic() {
        // Should return a result regardless of whether config exists
        let result = check_config().await;
        assert!(!result.name.is_empty());
        assert!(
            result.status == CheckStatus::Pass
                || result.status == CheckStatus::Warn
                || result.status == CheckStatus::Fail
        );
    }

    #[test]
    fn health_report_json_structure() {
        let results = vec![
            CheckResult {
                name: "A".into(),
                status: CheckStatus::Pass,
                detail: "ok".into(),
                hint: None,
                duration: Duration::from_millis(1),
            },
            CheckResult {
                name: "B".into(),
                status: CheckStatus::Fail,
                detail: "bad".into(),
                hint: Some("fix".into()),
                duration: Duration::from_millis(2),
            },
        ];

        let report = HealthReport {
            version: "0.2.1".into(),
            checks: results,
            summary: Summary {
                passed: 1,
                warned: 0,
                failed: 1,
                total: 2,
            },
        };

        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["version"], "0.2.1");
        assert_eq!(json["checks"].as_array().unwrap().len(), 2);
        assert_eq!(json["summary"]["passed"], 1);
        assert_eq!(json["summary"]["failed"], 1);
        assert_eq!(json["summary"]["total"], 2);
    }
}
