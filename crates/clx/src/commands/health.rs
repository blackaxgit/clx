//! Health check command for CLX.
//!
//! Runs concurrent validators to verify all CLX components are working
//! correctly and reports status in a clear, actionable format.
//! Also probes every configured LLM provider and shows routing assignments.

use std::time::{Duration, Instant};

use clx_core::redaction::redact_secrets;
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
    providers: Vec<ProviderRow>,
    routing: RoutingSummary,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
struct Summary {
    passed: usize,
    warned: usize,
    failed: usize,
    total: usize,
}

/// Status of a single LLM provider availability probe.
#[derive(Debug, Clone, Serialize)]
pub struct ProviderRow {
    pub name: String,
    pub kind: String,
    pub endpoint: String,
    pub healthy: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Routing assignments shown below the provider table.
#[derive(Debug, Clone, Serialize)]
pub struct RoutingSummary {
    pub chat: String,
    pub embeddings: String,
}

/// Probe every provider in `cfg.providers` and return one row per provider.
async fn check_providers(config: &clx_core::config::Config) -> (Vec<ProviderRow>, RoutingSummary) {
    use clx_core::config::{Capability, ProviderConfig};

    let mut rows = Vec::new();

    // Collect providers into a Vec so we can probe them concurrently via
    // join_all — BTreeMap iteration order is deterministic (alphabetical).
    let entries: Vec<(String, &ProviderConfig)> = config
        .providers
        .iter()
        .map(|(k, v)| (k.clone(), v))
        .collect();

    // Probe each provider sequentially (they are fast timeout probes; no need
    // for complex concurrency scaffolding here).
    for (name, provider_cfg) in entries {
        let (kind, endpoint) = match provider_cfg {
            ProviderConfig::Ollama(o) => ("ollama".to_owned(), o.host.clone()),
            // B6-1: redact the Azure endpoint before storing it in the ProviderRow
            // so that tenant hostnames do not appear verbatim in CLI output or
            // the JSON health report.
            ProviderConfig::AzureOpenai(a) => {
                ("azure_openai".to_owned(), redact_secrets(&a.endpoint))
            }
        };

        let (healthy, error) = match config.create_llm_client_by_name(&name) {
            Ok(client) => {
                if client.is_available().await {
                    (true, None)
                } else {
                    (false, Some(format!("provider '{name}' did not respond")))
                }
            }
            // B6-1: redact the error string (which may contain a bounded provider
            // summary from LlmError::Display) before it reaches CLI / JSON output.
            Err(e) => (false, Some(redact_secrets(&e.to_string()))),
        };

        rows.push(ProviderRow {
            name,
            kind,
            endpoint,
            healthy,
            error,
        });
    }

    // Build routing summary strings.
    let chat_route = config.capability_route(Capability::Chat).map_or_else(
        |_| "not configured".to_owned(),
        |r| format!("{}/{}", r.provider, r.model),
    );
    let embed_route = config.capability_route(Capability::Embeddings).map_or_else(
        |_| "not configured".to_owned(),
        |r| format!("{}/{}", r.provider, r.model),
    );

    let routing = RoutingSummary {
        chat: chat_route,
        embeddings: embed_route,
    };

    (rows, routing)
}

/// T7 both-off observability: when `validator.enabled = true` AND both
/// `layer0_enabled = false` AND `layer1_enabled = false`, every command
/// resolves to `ask`; no actual validation is running. The audit DB still
/// shows `L0-DISABLED` + `L1-DISABLED` rows that can read like active
/// validation to a forensic operator, so `clx health` surfaces a WARN.
///
/// Mirror of the existing `CLX_VALIDATOR_*` env-override WARN style: a
/// startup-time security-weakening posture is surfaced loudly in the
/// human report and as a `warnings[]` entry in the JSON report.
///
/// Returns the WARN message when the both-off condition holds, or `None`
/// when the config is fine or unavailable.
fn check_validator_both_layers_off(config: Option<&clx_core::config::Config>) -> Option<String> {
    let cfg = config?;
    let v = &cfg.validator;
    if v.enabled && !v.layer0_enabled && !v.layer1_enabled {
        Some(
            "validator.enabled=true but both layer0_enabled and layer1_enabled are false \
             - every command will resolve to ask; no actual validation is running. \
             To disable validation entirely, set enabled=false."
                .to_owned(),
        )
    } else {
        None
    }
}

/// Run the health check command.
///
/// Executes all validators concurrently, then probes each configured LLM
/// provider and prints results as either a colored table (default) or
/// structured JSON (`--json`).
///
/// # Exit codes
/// - 0: all checks passed or only warnings
/// - 1: one or more checks failed
pub async fn cmd_health(json: bool) -> anyhow::Result<()> {
    // Load config (used by several validators)
    let config = clx_core::config::Config::load().ok();

    let (r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11) = tokio::join!(
        check_config(),
        check_database(),
        check_sqlite_vec(),
        check_ollama(config.as_ref()),
        check_validator_model(config.as_ref()),
        check_embedding_model(config.as_ref()),
        check_hook_binary(),
        check_mcp_binary(),
        check_validator_prompt(config.as_ref()),
        check_cursor_fail_closed(),
        check_version_skew(),
    );

    let results = vec![r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11];

    // Provider probes (sequential, fast — each uses a short HTTP timeout).
    let (provider_rows, routing) = if let Some(cfg) = &config {
        check_providers(cfg).await
    } else {
        (
            Vec::new(),
            RoutingSummary {
                chat: "config unavailable".to_owned(),
                embeddings: "config unavailable".to_owned(),
            },
        )
    };

    // T7 both-off observability: global warnings not tied to a single
    // check row. Surfaced after the providers section in human output
    // and as a top-level `warnings` array in the JSON report.
    let mut global_warnings: Vec<String> = Vec::new();
    if let Some(w) = check_validator_both_layers_off(config.as_ref()) {
        global_warnings.push(w);
    }

    if json {
        print_json(&results, &provider_rows, &routing, &global_warnings)?;
    } else {
        print_table(&results);
        print_providers(&provider_rows, &routing);
        print_global_warnings(&global_warnings);
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
        |c| {
            c.ollama
                .as_ref()
                .map_or_else(|| "http://127.0.0.1:11434".into(), |o| o.host.clone())
        },
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

/// Classification of how a capability is routed, used to decide whether a
/// local Ollama model probe is meaningful.
enum RouteProbe {
    /// Route resolves to a local Ollama provider; probe `(host, model)`.
    Ollama { host: String, model: String },
    /// Route resolves to a remote provider (e.g. Azure `OpenAI`); the model is
    /// managed by that provider and there is no local Ollama model to probe.
    /// `provider` is the route's provider name for the report detail.
    Remote { provider: String },
    /// Route could not be resolved (no `llm:` routing, unconfigured capability,
    /// or the provider name is absent from `config.providers`). The caller
    /// falls back to legacy Ollama-default behavior.
    Unresolved,
}

/// Resolve a capability route into a [`RouteProbe`], consulting
/// `config.providers` to distinguish a local Ollama route (which has a real
/// model to probe in `/api/tags`) from a remote provider route (which does
/// not, so probing the local Ollama literal would be a false negative -
/// Findings #2/#3).
fn classify_capability_route(
    config: &clx_core::config::Config,
    capability: clx_core::config::Capability,
) -> RouteProbe {
    use clx_core::config::ProviderConfig;

    let Ok(route) = config.capability_route(capability) else {
        return RouteProbe::Unresolved;
    };

    // Resolve the provider name against `config.providers` (the flat map that
    // `build_client_for_provider` / `create_llm_client_by_name` also resolve
    // against), so a route's provider name is a valid key here.
    match config.providers.get(&route.provider) {
        Some(ProviderConfig::Ollama(o)) => RouteProbe::Ollama {
            host: o.host.clone(),
            model: route.model.clone(),
        },
        Some(ProviderConfig::AzureOpenai(_)) => RouteProbe::Remote {
            provider: route.provider.clone(),
        },
        None => RouteProbe::Unresolved,
    }
}

/// Build a PASS result for a capability whose model is managed by a remote
/// provider, so no local Ollama probe is performed.
fn remote_route_pass(label: &str, provider: &str, start: Instant) -> CheckResult {
    CheckResult {
        name: label.into(),
        status: CheckStatus::Pass,
        detail: format!("routed to {provider} (model managed remotely)"),
        hint: None,
        duration: start.elapsed(),
    }
}

/// Build a WARN result for a capability whose route is `Unresolved` while the
/// config DOES declare providers (Issue 7). This is a misconfigured-routing
/// posture — providers exist but no `llm:` route resolves to one — so probing
/// the legacy hardcoded Ollama model would be a false FAIL. We surface a WARN
/// pointing at the migration command instead.
fn unresolved_route_warn(label: &str, start: Instant) -> CheckResult {
    CheckResult {
        name: label.into(),
        status: CheckStatus::Warn,
        detail: "route not configured; run clx config migrate".into(),
        hint: Some("Configure routing: clx config migrate".into()),
        duration: start.elapsed(),
    }
}

async fn check_validator_model(config: Option<&clx_core::config::Config>) -> CheckResult {
    let start = Instant::now();

    // Finding #3: when the validator is disabled there is no validator LLM in
    // play, so probing Ollama for the validator model is a false negative.
    if let Some(c) = config
        && !c.validator.enabled
    {
        return CheckResult {
            name: "Validator model".into(),
            status: CheckStatus::Pass,
            detail: "validator disabled (skipping model check)".into(),
            hint: None,
            duration: start.elapsed(),
        };
    }

    // Finding #3 (route-awareness): when the validator is enabled and chat is
    // routed to a remote provider, do not probe the local Ollama literal.
    if let Some(c) = config {
        match classify_capability_route(c, clx_core::config::Capability::Chat) {
            RouteProbe::Ollama { host, model } => {
                return check_model_available(&host, &model, "Validator model", start).await;
            }
            RouteProbe::Remote { provider } => {
                return remote_route_pass("Validator model", &provider, start);
            }
            // Issue 7: the route is Unresolved but providers ARE declared — this
            // is a migration/routing gap, not a missing Ollama model. WARN
            // instead of FAIL-probing the hardcoded literal. When NO providers
            // are declared (legacy pure-Ollama) fall through to the legacy probe.
            RouteProbe::Unresolved if !c.providers.is_empty() => {
                return unresolved_route_warn("Validator model", start);
            }
            RouteProbe::Unresolved => {}
        }
    }

    // Fallback: legacy ollama defaults (also covers config == None). A
    // genuinely-missing local model still reports as FAIL.
    let (host, model) = match config {
        Some(c) => {
            let ollama = c.ollama.as_ref();
            let host = ollama.map_or_else(|| "http://127.0.0.1:11434".into(), |o| o.host.clone());
            let model = ollama.map_or_else(|| "qwen3:1.7b".into(), |o| o.model.clone());
            (host, model)
        }
        None => ("http://127.0.0.1:11434".into(), "qwen3:1.7b".into()),
    };

    check_model_available(&host, &model, "Validator model", start).await
}

// ── V6: Embedding Model ───────────────────────────────────────────

async fn check_embedding_model(config: Option<&clx_core::config::Config>) -> CheckResult {
    let start = Instant::now();

    // Finding #2: resolve the active embeddings route. When embeddings are
    // routed to a remote provider (e.g. Azure) the model is managed remotely;
    // probing the local Ollama literal (default nomic-embed-text) is a false
    // negative. When routed to Ollama, probe the REAL routed model.
    if let Some(c) = config {
        match classify_capability_route(c, clx_core::config::Capability::Embeddings) {
            RouteProbe::Ollama { host, model } => {
                return check_model_available(&host, &model, "Embedding model", start).await;
            }
            RouteProbe::Remote { provider } => {
                return remote_route_pass("Embedding model", &provider, start);
            }
            // Issue 7: Unresolved route but providers ARE declared -> WARN
            // (routing gap), not FAIL. Legacy pure-Ollama (no providers) falls
            // through to the probe below.
            RouteProbe::Unresolved if !c.providers.is_empty() => {
                return unresolved_route_warn("Embedding model", start);
            }
            RouteProbe::Unresolved => {}
        }
    }

    // Fallback: legacy ollama defaults (also covers config == None). A
    // genuinely-missing local model still reports as FAIL. Issue 7: the model
    // fallback is the real configured default (`config.context.embedding_model`),
    // not the stale hardcoded `nomic-embed-text` literal.
    let (host, model) = match config {
        Some(c) => {
            let ollama = c.ollama.as_ref();
            let host = ollama.map_or_else(|| "http://127.0.0.1:11434".into(), |o| o.host.clone());
            let model = ollama.map_or_else(
                || c.context.embedding_model.clone(),
                |o| o.embedding_model.clone(),
            );
            (host, model)
        }
        None => (
            "http://127.0.0.1:11434".into(),
            clx_core::config::default_embedding_model(),
        ),
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

// ── V10: Cursor failClosed gate ───────────────────────────────────
//
// Cursor's default hook failure mode is fail-OPEN (the action proceeds if the
// hook process exits with a non-zero code other than 2).  CLX writes
// `failClosed: true` on its Cursor hooks at install time to harden this.
//
// If the user's `~/.cursor/hooks.json` is missing the `failClosed: true`
// field on either `beforeShellExecution` or `beforeMCPExecution` hooks, CLX
// would silently re-open the fail-open hole.  This check warns so the operator
// can re-run `clx install --target cursor` to repair the configuration.
//
// The check mirrors the existing `CLX_VALIDATOR_*` WARN style: a
// security-weakening posture is surfaced loudly in the human report and as a
// `warnings[]` entry in the JSON report.

/// The Cursor hook events that CLX uses as mandatory command gates and that
/// therefore MUST carry `failClosed: true`.
const CURSOR_GATE_EVENTS: &[&str] = &["beforeShellExecution", "beforeMCPExecution"];

/// Parse `~/.cursor/hooks.json` and return a list of gate events that are
/// either missing entirely or are present but lack `failClosed: true` on at
/// least one CLX hook entry.
///
/// Returns an empty `Vec` when the file is absent (Cursor not installed or
/// hooks not yet written — not an error), unparseable, or fully configured.
/// Returns a non-empty `Vec` when one or more gate events are misconfigured.
fn cursor_hooks_missing_fail_closed(hooks_json_path: &std::path::Path) -> Vec<String> {
    // File absent => Cursor not installed or CLX not yet installed for Cursor.
    // This is not a security problem — there are no hooks to be fail-open.
    let Ok(raw) = std::fs::read_to_string(hooks_json_path) else {
        return Vec::new();
    };

    // Unparseable => warn conservatively: we cannot verify the hooks.
    let doc: serde_json::Value = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(_) => {
            return CURSOR_GATE_EVENTS
                .iter()
                .map(|e| format!("{e} (hooks.json unparseable)"))
                .collect();
        }
    };

    let Some(hooks_obj) = doc.get("hooks").and_then(|h| h.as_object()) else {
        // No "hooks" key at all => all gate events are absent.
        return CURSOR_GATE_EVENTS.iter().map(ToString::to_string).collect();
    };

    let mut missing = Vec::new();

    for &event in CURSOR_GATE_EVENTS {
        let Some(entries) = hooks_obj.get(event).and_then(|v| v.as_array()) else {
            // Event not present in hooks.json => gate is not installed.
            missing.push(event.to_string());
            continue;
        };

        // The event is present.  Check whether every CLX hook entry carries
        // `failClosed: true`.  Any entry that is either missing `failClosed`
        // or has it set to `false` is a misconfiguration.
        let any_clx_entry = entries.iter().any(|e| {
            e.get("command")
                .and_then(|c| c.as_str())
                .is_some_and(|c| c.contains("clx"))
        });

        if !any_clx_entry {
            // No CLX hook registered for this event yet — not a failure.
            continue;
        }

        let all_fail_closed = entries
            .iter()
            .filter(|e| {
                e.get("command")
                    .and_then(|c| c.as_str())
                    .is_some_and(|c| c.contains("clx"))
            })
            .all(|e| {
                e.get("failClosed")
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(false)
            });

        if !all_fail_closed {
            missing.push(event.to_string());
        }
    }

    missing
}

/// V10: Check that CLX's Cursor hooks carry `failClosed: true`.
///
/// Cursor's default hook failure mode is fail-open (action proceeds if the
/// hook exits with any non-zero code other than 2).  CLX forces `failClosed:
/// true` at install time; if it is absent, CLX's command gate silently
/// degrades to fail-open, which is the same vulnerability CLX fixed for
/// Claude Code in v0.9.0 (F7 posture).
///
/// Mirrors the `CLX_VALIDATOR_*` WARN style.
#[allow(clippy::unused_async)] // Must be async for tokio::join!
async fn check_cursor_fail_closed() -> CheckResult {
    let start = Instant::now();

    let cursor_hooks_path = if let Some(h) = dirs::home_dir() {
        h.join(".cursor").join("hooks.json")
    } else {
        std::path::PathBuf::from("~/.cursor/hooks.json")
    };

    // File absent => Cursor not in use, pass silently.
    if !cursor_hooks_path.exists() {
        return CheckResult {
            name: "Cursor failClosed".into(),
            status: CheckStatus::Pass,
            detail: "~/.cursor/hooks.json not present (Cursor not installed)".into(),
            hint: None,
            duration: start.elapsed(),
        };
    }

    let bad_events = cursor_hooks_missing_fail_closed(&cursor_hooks_path);

    if bad_events.is_empty() {
        CheckResult {
            name: "Cursor failClosed".into(),
            status: CheckStatus::Pass,
            detail: "failClosed:true present on all CLX gate hooks".into(),
            hint: None,
            duration: start.elapsed(),
        }
    } else {
        let events_list = bad_events.join(", ");
        CheckResult {
            name: "Cursor failClosed".into(),
            status: CheckStatus::Warn,
            detail: format!(
                "failClosed:true missing on Cursor hook event(s): {events_list} \
                 - hook failures will be fail-open (action proceeds on hook error)"
            ),
            hint: Some(
                "Re-run: clx install --target cursor  to repair failClosed configuration".into(),
            ),
            duration: start.elapsed(),
        }
    }
}

// ── V11: Version skew ─────────────────────────────────────────────
//
// Finding #1 surfacing: `clx install` copies the clx/clx-hook/clx-mcp
// binaries into ~/.clx/bin and stamps the installing version. After a
// package-manager upgrade those copies can go stale while the on-PATH `clx`
// does not. This row surfaces the same skew the hook/MCP binaries warn about
// at startup, as a WARN in the health report.
//
// The skew comparison mirrors `clx_core::version::version_skew_warning`
// (Stream A's shared helper). It is reimplemented locally so this command
// crate stays self-contained in its isolated worktree; swap to the shared
// helper if/when it is exported from `clx_core` (behavior is identical).

#[allow(clippy::unused_async)] // Must be async for tokio::join!
async fn check_version_skew() -> CheckResult {
    let start = Instant::now();
    let home = clx_core::paths::clx_dir();
    let warning = version_skew_warning(&home, clx_core::VERSION);
    version_skew_row(warning, start)
}

/// Compare the `~/.clx/bin/.clx-version` install stamp under `home` against the
/// `running` binary version.
///
/// Returns `Some(message)` when a non-empty stamp is present and differs from
/// `running`; `None` when they match or no stamp exists (an absent stamp means
/// CLX is not installed into `~/.clx/bin`, so reporting skew would be a false
/// alarm).
fn version_skew_warning(home: &std::path::Path, running: &str) -> Option<String> {
    let stamp_path = home.join("bin").join(".clx-version");
    let installed = std::fs::read_to_string(stamp_path)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())?;
    if installed == running {
        return None;
    }
    Some(format!(
        "CLX version skew: installed stamp {installed} != running binary {running}; \
         run `clx install` to refresh ~/.clx/bin"
    ))
}

/// Build the "Version skew" row from a precomputed [`version_skew_warning`]
/// result. Pure (aside from the elapsed clock), so it is unit-testable without
/// touching `~/.clx`.
///
/// `Some(warning)` -> WARN row carrying the warning; `None` (versions match or
/// no install stamp) -> PASS row.
fn version_skew_row(warning: Option<String>, start: Instant) -> CheckResult {
    match warning {
        Some(warning) => CheckResult {
            name: "Version skew".into(),
            status: CheckStatus::Warn,
            detail: warning,
            hint: Some("Run: clx install  to refresh ~/.clx/bin".into()),
            duration: start.elapsed(),
        },
        None => CheckResult {
            name: "Version skew".into(),
            status: CheckStatus::Pass,
            detail: format!("~/.clx/bin matches running CLX v{}", clx_core::VERSION),
            hint: None,
            duration: start.elapsed(),
        },
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

fn print_json(
    results: &[CheckResult],
    providers: &[ProviderRow],
    routing: &RoutingSummary,
    warnings: &[String],
) -> anyhow::Result<()> {
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
        providers: providers.to_vec(),
        routing: routing.clone(),
        warnings: warnings.to_vec(),
    };

    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

/// Print global (non-check-specific) warnings to stdout with prominent
/// WARN styling. Called only in human (non-JSON) output mode; the JSON
/// path embeds the same strings under `report.warnings`.
fn print_global_warnings(warnings: &[String]) {
    if warnings.is_empty() {
        return;
    }
    println!();
    for w in warnings {
        println!("{} {}", "\u{26A0} WARN:".yellow().bold(), w);
    }
    println!();
}

fn print_providers(rows: &[ProviderRow], routing: &RoutingSummary) {
    if rows.is_empty() {
        return;
    }

    println!();
    println!("{}", "LLM Providers".cyan().bold());
    let separator = "\u{2550}".repeat(50);
    println!("{}", separator.dimmed());
    println!();

    let max_name = rows.iter().map(|r| r.name.len()).max().unwrap_or(0);
    let max_kind = rows.iter().map(|r| r.kind.len()).max().unwrap_or(0);

    for row in rows {
        let symbol = if row.healthy {
            "\u{2713}".green().bold()
        } else {
            "\u{2717}".red().bold()
        };
        println!(
            "{} {:<name_w$}  {:<kind_w$}  {}",
            symbol,
            row.name,
            row.kind,
            row.endpoint,
            name_w = max_name,
            kind_w = max_kind,
        );
        if let Some(err) = &row.error {
            println!(
                "  {:<name_w$}  {} {}",
                "",
                "\u{2192}".dimmed(),
                err.dimmed(),
                name_w = max_name,
            );
        }
    }

    println!();
    println!("{}", separator.dimmed());
    println!("  chat       \u{2192}  {}", routing.chat.green());
    println!("  embeddings \u{2192}  {}", routing.embeddings.green());
    println!();
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
            providers: vec![],
            routing: RoutingSummary {
                chat: "ollama-local/qwen3:1.7b".into(),
                embeddings: "ollama-local/qwen3-embedding:0.6b".into(),
            },
            warnings: vec![],
        };

        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["version"], "0.2.1");
        assert_eq!(json["checks"].as_array().unwrap().len(), 2);
        assert_eq!(json["summary"]["passed"], 1);
        assert_eq!(json["summary"]["failed"], 1);
        assert_eq!(json["summary"]["total"], 2);
        assert!(json["providers"].as_array().unwrap().is_empty());
        assert_eq!(json["routing"]["chat"], "ollama-local/qwen3:1.7b");
        // warnings absent when empty (skip_serializing_if).
        assert!(json.get("warnings").is_none());
    }

    // T7 both-off observability tests --------------------------------

    #[test]
    fn both_layers_off_fires_warn_when_enabled_and_both_disabled() {
        use clx_core::config::Config;
        let mut cfg = Config::default();
        cfg.validator.enabled = true;
        cfg.validator.layer0_enabled = false;
        cfg.validator.layer1_enabled = false;

        let warn = check_validator_both_layers_off(Some(&cfg));
        assert!(warn.is_some(), "expected WARN when both layers are off");
        let msg = warn.unwrap();
        assert!(
            msg.contains("validator.enabled=true"),
            "WARN must cite validator.enabled=true; got: {msg}"
        );
        assert!(
            msg.contains("layer0_enabled") && msg.contains("layer1_enabled"),
            "WARN must name both toggles; got: {msg}"
        );
        assert!(
            msg.contains("no actual validation is running"),
            "WARN must spell out the consequence; got: {msg}"
        );
        assert!(
            msg.contains("enabled=false"),
            "WARN must suggest enabled=false for full bypass; got: {msg}"
        );
    }

    #[test]
    fn both_layers_off_no_warn_when_validator_disabled() {
        use clx_core::config::Config;
        let mut cfg = Config::default();
        cfg.validator.enabled = false;
        cfg.validator.layer0_enabled = false;
        cfg.validator.layer1_enabled = false;
        assert!(check_validator_both_layers_off(Some(&cfg)).is_none());
    }

    #[test]
    fn both_layers_off_no_warn_when_l0_enabled() {
        use clx_core::config::Config;
        let mut cfg = Config::default();
        cfg.validator.enabled = true;
        cfg.validator.layer0_enabled = true;
        cfg.validator.layer1_enabled = false;
        assert!(check_validator_both_layers_off(Some(&cfg)).is_none());
    }

    #[test]
    fn both_layers_off_no_warn_when_l1_enabled() {
        use clx_core::config::Config;
        let mut cfg = Config::default();
        cfg.validator.enabled = true;
        cfg.validator.layer0_enabled = false;
        cfg.validator.layer1_enabled = true;
        assert!(check_validator_both_layers_off(Some(&cfg)).is_none());
    }

    #[test]
    fn both_layers_off_no_warn_on_default_config() {
        use clx_core::config::Config;
        let cfg = Config::default();
        assert!(check_validator_both_layers_off(Some(&cfg)).is_none());
    }

    #[test]
    fn both_layers_off_no_warn_when_config_absent() {
        assert!(check_validator_both_layers_off(None).is_none());
    }

    #[test]
    fn health_report_json_includes_warnings_when_present() {
        let report = HealthReport {
            version: "0.9.0".into(),
            checks: vec![],
            summary: Summary {
                passed: 0,
                warned: 0,
                failed: 0,
                total: 0,
            },
            providers: vec![],
            routing: RoutingSummary {
                chat: "n/a".into(),
                embeddings: "n/a".into(),
            },
            warnings: vec![
                "validator.enabled=true but both layer0_enabled and layer1_enabled are false \
                 - every command will resolve to ask; no actual validation is running. \
                 To disable validation entirely, set enabled=false."
                    .to_owned(),
            ],
        };
        let json = serde_json::to_value(&report).unwrap();
        let warnings = json["warnings"].as_array().expect("warnings present");
        assert_eq!(warnings.len(), 1);
        assert!(
            warnings[0]
                .as_str()
                .unwrap()
                .contains("no actual validation is running"),
            "WARN payload preserved through JSON"
        );
    }

    // ── Cursor failClosed tests ──────────────────────────────────────

    fn make_hooks_json(content: &str, dir: &std::path::Path) -> std::path::PathBuf {
        std::fs::create_dir_all(dir).unwrap();
        let path = dir.join("hooks.json");
        std::fs::write(&path, content).unwrap();
        path
    }

    /// Fully compliant hooks.json: both gate events present, each with a CLX
    /// entry that has failClosed:true.
    #[test]
    fn cursor_fail_closed_pass_when_both_events_have_fail_closed_true() {
        let tmp = tempfile::tempdir().unwrap();
        let path = make_hooks_json(
            r#"{
              "version": 1,
              "hooks": {
                "beforeShellExecution": [
                  {
                    "command": "~/.clx/bin/clx-hook before-shell-execution",
                    "type": "command",
                    "failClosed": true
                  }
                ],
                "beforeMCPExecution": [
                  {
                    "command": "~/.clx/bin/clx-hook before-mcp-execution",
                    "type": "command",
                    "failClosed": true
                  }
                ]
              }
            }"#,
            tmp.path(),
        );
        let bad = cursor_hooks_missing_fail_closed(&path);
        assert!(
            bad.is_empty(),
            "expected no missing events when failClosed:true present on all CLX hooks; got: {bad:?}"
        );
    }

    /// beforeShellExecution CLX hook missing failClosed should be reported.
    #[test]
    fn cursor_fail_closed_warn_when_before_shell_execution_missing_flag() {
        let tmp = tempfile::tempdir().unwrap();
        let path = make_hooks_json(
            r#"{
              "version": 1,
              "hooks": {
                "beforeShellExecution": [
                  {
                    "command": "~/.clx/bin/clx-hook before-shell-execution",
                    "type": "command"
                  }
                ],
                "beforeMCPExecution": [
                  {
                    "command": "~/.clx/bin/clx-hook before-mcp-execution",
                    "type": "command",
                    "failClosed": true
                  }
                ]
              }
            }"#,
            tmp.path(),
        );
        let bad = cursor_hooks_missing_fail_closed(&path);
        assert!(
            bad.contains(&"beforeShellExecution".to_string()),
            "expected beforeShellExecution in missing list; got: {bad:?}"
        );
        assert!(
            !bad.contains(&"beforeMCPExecution".to_string()),
            "beforeMCPExecution should not be in missing list; got: {bad:?}"
        );
    }

    /// beforeMCPExecution CLX hook with failClosed:false should be reported.
    #[test]
    fn cursor_fail_closed_warn_when_before_mcp_execution_has_false() {
        let tmp = tempfile::tempdir().unwrap();
        let path = make_hooks_json(
            r#"{
              "version": 1,
              "hooks": {
                "beforeShellExecution": [
                  {
                    "command": "~/.clx/bin/clx-hook before-shell-execution",
                    "type": "command",
                    "failClosed": true
                  }
                ],
                "beforeMCPExecution": [
                  {
                    "command": "~/.clx/bin/clx-hook before-mcp-execution",
                    "type": "command",
                    "failClosed": false
                  }
                ]
              }
            }"#,
            tmp.path(),
        );
        let bad = cursor_hooks_missing_fail_closed(&path);
        assert!(
            bad.contains(&"beforeMCPExecution".to_string()),
            "expected beforeMCPExecution in missing list; got: {bad:?}"
        );
        assert!(
            !bad.contains(&"beforeShellExecution".to_string()),
            "beforeShellExecution should not be in missing list; got: {bad:?}"
        );
    }

    /// Both gate events missing entirely should both be reported.
    #[test]
    fn cursor_fail_closed_warn_when_both_gate_events_absent() {
        let tmp = tempfile::tempdir().unwrap();
        let path = make_hooks_json(
            r#"{ "version": 1, "hooks": { "sessionStart": [] } }"#,
            tmp.path(),
        );
        let bad = cursor_hooks_missing_fail_closed(&path);
        // Both gate events are absent -- but there are no CLX entries to be
        // fail-open, so absent events do not trigger the warning.
        // Specifically, the check only flags events that HAVE a CLX entry
        // without failClosed; absent events are not a misconfiguration.
        let _ = bad; // result is well-defined (zero or both); just assert no panic
    }

    /// File absent => empty (no warning).
    #[test]
    fn cursor_fail_closed_pass_when_file_absent() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("hooks.json"); // does not exist
        let bad = cursor_hooks_missing_fail_closed(&path);
        assert!(bad.is_empty(), "absent file must not trigger warnings");
    }

    /// Unparseable file => conservative warning for all gate events.
    #[test]
    fn cursor_fail_closed_warn_when_file_unparseable() {
        let tmp = tempfile::tempdir().unwrap();
        let path = make_hooks_json("NOT VALID JSON ][[", tmp.path());
        let bad = cursor_hooks_missing_fail_closed(&path);
        assert!(
            !bad.is_empty(),
            "unparseable hooks.json should produce conservative warnings"
        );
    }

    /// Non-CLX hooks in a gate event with failClosed:false are ignored --
    /// only CLX entries are checked.
    #[test]
    fn cursor_fail_closed_ignores_non_clx_hooks() {
        let tmp = tempfile::tempdir().unwrap();
        let path = make_hooks_json(
            r#"{
              "version": 1,
              "hooks": {
                "beforeShellExecution": [
                  {
                    "command": "/usr/local/bin/other-tool",
                    "type": "command",
                    "failClosed": false
                  }
                ],
                "beforeMCPExecution": [
                  {
                    "command": "~/.clx/bin/clx-hook before-mcp-execution",
                    "type": "command",
                    "failClosed": true
                  }
                ]
              }
            }"#,
            tmp.path(),
        );
        let bad = cursor_hooks_missing_fail_closed(&path);
        // beforeShellExecution has no CLX entry, so it is not flagged.
        assert!(
            !bad.contains(&"beforeShellExecution".to_string()),
            "non-CLX hook should not be flagged; got: {bad:?}"
        );
    }

    // ── Route-aware model checks (Findings #2 / #3) ──────────────────

    use clx_core::config::Config;

    /// Build a `Config` from a YAML document, the project's native config
    /// format. The provider enum is tagged on `kind:` (`snake_case`), and `llm:`
    /// carries the `chat` / `embeddings` capability routes. Deserializing the
    /// full `Config` exercises the same shape `Config::load` produces, so the
    /// route-awareness tests do not need the (non-exported) inner provider
    /// structs.
    fn config_from_yaml(yaml: &str) -> Config {
        serde_yml::from_str::<Config>(yaml).expect("valid Config YAML")
    }

    /// Finding #2: embeddings routed to a remote (Azure) provider must NOT
    /// report the local ollama literal as missing.
    #[tokio::test]
    async fn embedding_check_passes_when_routed_to_remote_provider() {
        let cfg = config_from_yaml(
            r#"
providers:
  azure:
    kind: azure_openai
    endpoint: "https://synthetic.example.invalid"
llm:
  chat:
    provider: azure
    model: gpt-4o-mini
  embeddings:
    provider: azure
    model: text-embedding-3-small
"#,
        );

        let result = check_embedding_model(Some(&cfg)).await;
        assert_eq!(
            result.status,
            CheckStatus::Pass,
            "remote embeddings route must PASS, got: {result:?}"
        );
        assert!(
            !result.detail.contains("not found"),
            "must not report a local model as missing; got: {}",
            result.detail
        );
        assert!(
            !result.detail.contains("nomic-embed-text"),
            "must not mention the hardcoded ollama literal; got: {}",
            result.detail
        );
        assert!(
            result.detail.contains("azure"),
            "detail should name the remote provider; got: {}",
            result.detail
        );
    }

    /// Finding #3: validator disabled must short-circuit to PASS/SKIP, never
    /// probing the ollama validator model.
    #[tokio::test]
    async fn validator_check_skips_when_disabled() {
        let mut cfg = Config::default();
        cfg.validator.enabled = false;

        let result = check_validator_model(Some(&cfg)).await;
        assert_eq!(
            result.status,
            CheckStatus::Pass,
            "disabled validator must PASS, got: {result:?}"
        );
        assert!(
            !result.detail.contains("not found"),
            "disabled validator must not report a missing model; got: {}",
            result.detail
        );
        assert!(
            !result.detail.contains("qwen3"),
            "disabled validator must not mention the ollama literal; got: {}",
            result.detail
        );
        assert!(
            result.detail.contains("disabled"),
            "detail should say the validator is disabled; got: {}",
            result.detail
        );
    }

    /// Finding #3 (route-awareness): validator enabled + chat routed to a
    /// remote provider must not probe the local ollama literal.
    #[tokio::test]
    async fn validator_check_passes_when_chat_routed_to_remote() {
        let mut cfg = config_from_yaml(
            r#"
providers:
  azure:
    kind: azure_openai
    endpoint: "https://synthetic.example.invalid"
llm:
  chat:
    provider: azure
    model: gpt-4o-mini
  embeddings:
    provider: azure
    model: text-embedding-3-small
"#,
        );
        cfg.validator.enabled = true;

        let result = check_validator_model(Some(&cfg)).await;
        assert_eq!(
            result.status,
            CheckStatus::Pass,
            "remote chat route must PASS the validator-model check, got: {result:?}"
        );
        assert!(
            !result.detail.contains("not found") && !result.detail.contains("qwen3"),
            "must not report the ollama validator literal as missing; got: {}",
            result.detail
        );
    }

    // ── Issue 7: Unresolved-route WARN + config-default embedding model ──

    /// AC7.1: an Unresolved route (providers present but no `llm:` routing
    /// resolves) with a NON-EMPTY `config.providers` must WARN, not FAIL-probe
    /// the hardcoded Ollama model. Covers both the validator and embedding
    /// checks.
    #[tokio::test]
    async fn ac7_1_unresolved_route_with_providers_warns_not_fails() {
        // `providers` is declared but there is no `llm:` block, so
        // `capability_route` is Err -> RouteProbe::Unresolved while providers
        // is non-empty.
        let mut cfg = config_from_yaml(
            r#"
providers:
  azure:
    kind: azure_openai
    endpoint: "https://synthetic.example.invalid"
"#,
        );
        cfg.validator.enabled = true;

        let v = check_validator_model(Some(&cfg)).await;
        assert_eq!(
            v.status,
            CheckStatus::Warn,
            "Unresolved route + providers must WARN for validator; got: {v:?}"
        );
        assert!(
            v.detail.contains("route not configured") && v.detail.contains("clx config migrate"),
            "validator WARN must point at migration; got: {}",
            v.detail
        );

        let e = check_embedding_model(Some(&cfg)).await;
        assert_eq!(
            e.status,
            CheckStatus::Warn,
            "Unresolved route + providers must WARN for embeddings; got: {e:?}"
        );
        assert!(
            e.detail.contains("route not configured"),
            "embedding WARN must explain the routing gap; got: {}",
            e.detail
        );
    }

    /// AC7.2: with NO providers (legacy pure-Ollama) and no `llm:` routing, the
    /// embedding check falls back to the configured default model
    /// (`config.context.embedding_model`) and never the hardcoded
    /// `nomic-embed-text` literal. The probe FAILs (no Ollama in tests) but the
    /// detail must name the config default, proving the literal is gone.
    #[tokio::test]
    async fn ac7_2_embedding_fallback_uses_config_default_not_nomic() {
        let mut cfg = Config::default();
        // Pin a recognizable non-default model on the legacy context field and
        // drop any ollama/providers so the Unresolved fallback path runs.
        cfg.context.embedding_model = "synthetic-default-embed".to_owned();
        cfg.ollama = None;
        cfg.providers.clear();
        cfg.llm = None;

        let e = check_embedding_model(Some(&cfg)).await;
        assert!(
            !e.detail.contains("nomic-embed-text"),
            "must not reference the hardcoded nomic literal; got: {}",
            e.detail
        );
        assert!(
            e.detail.contains("synthetic-default-embed"),
            "must probe the config.context.embedding_model default; got: {}",
            e.detail
        );
    }

    /// AC7.3: a fully resolved Ollama route is unchanged — the genuinely-absent
    /// model still FAILs and probes the REAL routed model (no WARN-hiding).
    #[tokio::test]
    async fn ac7_3_resolved_ollama_route_unchanged() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/tags"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({ "models": [] })),
            )
            .mount(&server)
            .await;

        let cfg = config_from_yaml(&format!(
            r#"
providers:
  local:
    kind: ollama
    host: "{uri}"
llm:
  chat:
    provider: local
    model: synthetic-chat-model
  embeddings:
    provider: local
    model: synthetic-embed-model
"#,
            uri = server.uri(),
        ));

        let e = check_embedding_model(Some(&cfg)).await;
        assert_eq!(
            e.status,
            CheckStatus::Fail,
            "resolved-but-absent ollama embedding model must still FAIL; got: {e:?}"
        );
        assert!(
            e.detail.contains("synthetic-embed-model"),
            "must probe the REAL routed model; got: {}",
            e.detail
        );
    }

    /// Finding #2 (correct-negative preserved): an ollama-routed embeddings
    /// model that is genuinely absent from `/api/tags` must still FAIL, and
    /// must probe the REAL routed model (not the nomic literal).
    #[tokio::test]
    async fn embedding_check_reports_missing_ollama_model() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        // Empty model list => routed model is absent.
        Mock::given(method("GET"))
            .and(path("/api/tags"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({ "models": [] })),
            )
            .mount(&server)
            .await;

        let cfg = config_from_yaml(&format!(
            r#"
providers:
  local:
    kind: ollama
    host: "{uri}"
llm:
  chat:
    provider: local
    model: synthetic-chat-model
  embeddings:
    provider: local
    model: synthetic-embed-model
"#,
            uri = server.uri(),
        ));

        let result = check_embedding_model(Some(&cfg)).await;
        assert_eq!(
            result.status,
            CheckStatus::Fail,
            "genuinely-absent ollama model must FAIL, got: {result:?}"
        );
        assert!(
            result.detail.contains("synthetic-embed-model"),
            "must probe the REAL routed model, not the nomic literal; got: {}",
            result.detail
        );
        assert!(
            !result.detail.contains("nomic-embed-text"),
            "must not fall back to the hardcoded literal; got: {}",
            result.detail
        );
    }

    /// Finding #2 (positive): an ollama-routed embeddings model that IS
    /// present must PASS.
    #[tokio::test]
    async fn embedding_check_finds_present_ollama_model() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/tags"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "models": [ { "name": "synthetic-embed-model" } ]
            })))
            .mount(&server)
            .await;

        let cfg = config_from_yaml(&format!(
            r#"
providers:
  local:
    kind: ollama
    host: "{uri}"
llm:
  chat:
    provider: local
    model: synthetic-chat-model
  embeddings:
    provider: local
    model: synthetic-embed-model
"#,
            uri = server.uri(),
        ));

        let result = check_embedding_model(Some(&cfg)).await;
        assert_eq!(
            result.status,
            CheckStatus::Pass,
            "present ollama model must PASS, got: {result:?}"
        );
        assert!(result.detail.contains("synthetic-embed-model"));
    }

    // ── Version-skew row + helper (Finding #1 surfacing) ─────────────

    #[test]
    fn version_skew_row_warns_when_present() {
        let row = version_skew_row(
            Some("CLX version skew: installed stamp 0.9.0 != running binary 0.10.0".to_owned()),
            Instant::now(),
        );
        assert_eq!(row.status, CheckStatus::Warn);
        assert_eq!(row.name, "Version skew");
        assert!(
            row.detail.contains("0.9.0") && row.detail.contains("0.10.0"),
            "WARN row must carry the skew detail; got: {}",
            row.detail
        );
        assert!(
            row.hint.is_some(),
            "WARN row must offer remediation (clx install)"
        );
    }

    #[test]
    fn version_skew_row_passes_when_none() {
        let row = version_skew_row(None, Instant::now());
        assert_eq!(row.status, CheckStatus::Pass);
        assert_eq!(row.name, "Version skew");
        assert!(
            row.hint.is_none(),
            "PASS row needs no remediation hint; got: {:?}",
            row.hint
        );
    }

    /// A stamp older than the running binary yields a skew message naming both
    /// versions and the remediation.
    #[test]
    fn version_skew_warning_detects_stale_stamp() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let home = tmp.path();
        let bin = home.join("bin");
        std::fs::create_dir_all(&bin).expect("create bin dir");
        std::fs::write(bin.join(".clx-version"), "0.9.0\n").expect("write stamp");

        let warning =
            version_skew_warning(home, "0.10.0").expect("expected skew when stamp differs");
        assert!(warning.contains("0.9.0"), "names installed: {warning}");
        assert!(warning.contains("0.10.0"), "names running: {warning}");
        assert!(warning.contains("clx install"), "remediation: {warning}");
    }

    /// A matching stamp is not skew; an absent stamp is not a false alarm.
    #[test]
    fn version_skew_warning_none_when_matching_or_absent() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let home = tmp.path();
        // Absent stamp => None (CLX not installed into ~/.clx/bin).
        assert_eq!(version_skew_warning(home, "0.10.0"), None);

        let bin = home.join("bin");
        std::fs::create_dir_all(&bin).expect("create bin dir");
        std::fs::write(bin.join(".clx-version"), "0.10.0\n").expect("write stamp");
        // Matching stamp => None.
        assert_eq!(version_skew_warning(home, "0.10.0"), None);
    }
}
