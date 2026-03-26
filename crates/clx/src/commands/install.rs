//! Install/uninstall commands and all installation helpers.

use anyhow::{Context, Result};
use colored::Colorize;
use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::Command;

use clx_core::config::Config;
use clx_core::storage::Storage;

use crate::Cli;

/// Default docker-compose.yml embedded from scripts/docker-compose.yml
const DOCKER_COMPOSE_YML: &str = include_str!("../../../../scripts/docker-compose.yml");

/// CLX section to inject into CLAUDE.md
const CLX_CLAUDE_MD_SECTION: &str = r#"
# CLX Integration [STRICT]

**[SCOPE: ALL AGENTS]**

CLX (Claude Code Enhancement Layer) provides MCP tools for context persistence across sessions.

## Available CLX Tools (MANDATORY knowledge)

| Tool | Purpose | When to Use |
|------|---------|-------------|
| `clx_recall` | Search past sessions | When user references earlier work, previous decisions, or past context |
| `clx_remember` | Save important info | When discovering key decisions, user preferences, or important context |
| `clx_rules` | Refresh project rules | After long sessions to re-inject CLAUDE.md rules |
| `clx_checkpoint` | Create manual snapshot | Before major refactoring or risky changes |

## Usage Guidelines [IMPORTANT]

1. **Proactive recall**: When user mentions "we discussed", "earlier", "before", or references past work - use `clx_recall`
2. **Save discoveries**: When user states preferences or makes important decisions - use `clx_remember`
3. **Long sessions**: If context feels stale or rules seem forgotten - use `clx_rules`
4. **Before big changes**: Create checkpoint before major refactoring

## Example Queries

```
clx_recall "authentication implementation"
clx_recall "user preferences for error handling"
clx_remember "User prefers functional style over OOP"
```

## Compact Instructions
When compacting context, preserve:
- CLX tools: clx_recall, clx_remember, clx_rules, clx_checkpoint
- Delegation pattern: Use Task tool to delegate to specialized agents
- Agent selection: Check agent descriptions before selecting. Maximize parallelization.
- Security: Never commit secrets. Validate inputs at boundaries.
"#;

/// Marker to identify CLX section in CLAUDE.md
const CLX_SECTION_MARKER: &str = "# CLX Integration";

/// Inject CLX section into CLAUDE.md if not already present
fn inject_clx_to_claude_md(claude_md_path: &std::path::Path) -> Result<bool> {
    let content = if claude_md_path.exists() {
        fs::read_to_string(claude_md_path)?
    } else {
        String::new()
    };

    // Check if CLX section already exists
    if content.contains(CLX_SECTION_MARKER) {
        return Ok(false); // Already present
    }

    // Append CLX section
    let new_content = if content.is_empty() {
        CLX_CLAUDE_MD_SECTION.trim_start().to_string()
    } else {
        format!("{}\n{}", content.trim_end(), CLX_CLAUDE_MD_SECTION)
    };

    fs::write(claude_md_path, new_content)?;
    Ok(true) // Injected
}

/// Get the path to the currently running executable
fn current_exe_dir() -> Result<PathBuf> {
    let exe = env::current_exe().context("Could not determine current executable path")?;
    exe.parent()
        .map(std::path::Path::to_path_buf)
        .ok_or_else(|| anyhow::anyhow!("Could not determine executable directory"))
}

/// Find the built binary path (supports both development and installed scenarios)
fn find_binary(name: &str) -> Result<PathBuf> {
    // First, check if the binary is next to the current executable
    if let Ok(exe_dir) = current_exe_dir() {
        let binary_path = exe_dir.join(name);
        if binary_path.exists() {
            return Ok(binary_path);
        }
    }

    // For development: check the target/debug or target/release directory
    if let Ok(exe) = env::current_exe() {
        // exe might be in target/debug/clx, we want target/debug/clx-hook
        if let Some(parent) = exe.parent() {
            let binary_path = parent.join(name);
            if binary_path.exists() {
                return Ok(binary_path);
            }
        }
    }

    // Check if it's in PATH
    if let Ok(output) = Command::new("which").arg(name).output()
        && output.status.success()
    {
        let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !path.is_empty() {
            return Ok(PathBuf::from(path));
        }
    }

    anyhow::bail!("Could not find binary: {name}")
}

/// Copy a binary to the destination, or create a symlink in development mode
fn install_binary(src: &PathBuf, dest: &PathBuf) -> Result<()> {
    // Remove existing file/symlink if present
    if dest.exists() || dest.is_symlink() {
        fs::remove_file(dest)?;
    }

    // Copy the binary
    fs::copy(src, dest).context(format!(
        "Failed to copy {} to {}",
        src.display(),
        dest.display()
    ))?;

    // Make it executable on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(dest)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(dest, perms)?;
    }

    Ok(())
}

/// Read and parse ~/.claude/settings.json
fn read_claude_settings(settings_path: &PathBuf) -> Result<serde_json::Value> {
    if settings_path.exists() {
        let content = fs::read_to_string(settings_path)?;
        Ok(serde_json::from_str(&content)?)
    } else {
        // Return empty object if file doesn't exist
        Ok(serde_json::json!({}))
    }
}

/// Write ~/.claude/settings.json with backup
fn write_claude_settings(settings_path: &PathBuf, settings: &serde_json::Value) -> Result<()> {
    // Create backup if file exists
    if settings_path.exists() {
        let backup_path = settings_path.with_extension("json.backup");
        fs::copy(settings_path, &backup_path)?;
    }

    // Ensure parent directory exists
    if let Some(parent) = settings_path.parent() {
        fs::create_dir_all(parent)?;
    }

    // Write the new settings
    let content = serde_json::to_string_pretty(settings)?;
    fs::write(settings_path, content)?;

    Ok(())
}

/// Get the hooks configuration to add to settings.json
fn get_hooks_config() -> serde_json::Value {
    serde_json::json!({
        "PreToolUse": [{
            "hooks": [{"type": "command", "command": "~/.clx/bin/clx-hook pre-tool-use"}],
            "matcher": "Bash|Write|Edit"
        }],
        "PostToolUse": [{
            "hooks": [{"type": "command", "command": "~/.clx/bin/clx-hook post-tool-use"}],
            "matcher": "Bash|Write|Edit"
        }],
        "PreCompact": [{
            "hooks": [{"type": "command", "command": "~/.clx/bin/clx-hook pre-compact"}]
        }],
        "SessionStart": [{
            "hooks": [{"type": "command", "command": "~/.clx/bin/clx-hook session-start"}]
        }],
        "SessionEnd": [{
            "hooks": [{"type": "command", "command": "~/.clx/bin/clx-hook session-end"}]
        }],
        "SubagentStart": [{
            "hooks": [{"type": "command", "command": "~/.clx/bin/clx-hook subagent-start"}],
            "matcher": "*"
        }],
        "UserPromptSubmit": [{
            "hooks": [{"type": "command", "command": "~/.clx/bin/clx-hook user-prompt-submit"}],
            "matcher": "*"
        }]
    })
}

/// Get the MCP server configuration to add to settings.json
fn get_mcp_config() -> serde_json::Value {
    serde_json::json!({
        "clx": {
            "command": "~/.clx/bin/clx-mcp",
            "args": []
        }
    })
}

/// Check if Homebrew is available.
fn has_homebrew() -> bool {
    Command::new("which")
        .arg("brew")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Install Ollama via Homebrew.
fn install_ollama_brew() -> Result<()> {
    let status = Command::new("brew")
        .args(["install", "ollama"])
        .status()
        .context("Failed to run brew install ollama")?;
    if !status.success() {
        anyhow::bail!("brew install ollama exited with {status}");
    }
    Ok(())
}

/// Start Ollama server in the background and wait until it's reachable.
async fn start_ollama_server() -> Result<()> {
    // Launch `ollama serve` as a background process
    Command::new("ollama")
        .arg("serve")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .context("Failed to start ollama serve")?;

    // Wait up to 10 seconds for the server to become reachable
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(2))
        .build()?;

    for _ in 0..20 {
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        if client.get("http://127.0.0.1:11434/").send().await.is_ok() {
            return Ok(());
        }
    }

    anyhow::bail!("Ollama server did not start within 10 seconds")
}

/// Ollama prerequisite check status
struct OllamaStatus {
    binary_installed: bool,
    server_running: bool,
    missing_models: Vec<String>,
}

/// Check Ollama prerequisites
async fn check_ollama_prerequisites() -> OllamaStatus {
    // Check if ollama binary exists
    let binary_installed = std::process::Command::new("which")
        .arg("ollama")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    let all_models = vec![
        clx_core::config::default_ollama_model(),
        clx_core::config::default_embedding_model(),
    ];

    if !binary_installed {
        return OllamaStatus {
            binary_installed: false,
            server_running: false,
            missing_models: all_models,
        };
    }

    // Check if server is running by trying to connect
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(2))
        .build()
        .unwrap();

    let server_running = client
        .get("http://127.0.0.1:11434/api/tags")
        .send()
        .await
        .is_ok();

    if !server_running {
        return OllamaStatus {
            binary_installed: true,
            server_running: false,
            missing_models: all_models,
        };
    }

    // Check for required models
    let required_models = all_models;
    let mut missing_models = Vec::new();

    if let Ok(response) = client.get("http://127.0.0.1:11434/api/tags").send().await {
        if let Ok(json) = response.json::<serde_json::Value>().await {
            let installed: Vec<String> = json
                .get("models")
                .and_then(|m| m.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|m| m.get("name").and_then(|n| n.as_str()))
                        .map(std::string::ToString::to_string)
                        .collect()
                })
                .unwrap_or_default();

            for model in &required_models {
                // Check if any installed model starts with the required model name
                let found = installed.iter().any(|m| m.starts_with(model.as_str()));
                if !found {
                    missing_models.push(model.clone());
                }
            }
        } else {
            missing_models = required_models.clone();
        }
    } else {
        missing_models = required_models.clone();
    }

    OllamaStatus {
        binary_installed: true,
        server_running: true,
        missing_models,
    }
}

/// Pull an Ollama model via the API.
async fn pull_ollama_model(model: &str) -> Result<()> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(600))
        .build()?;

    let resp = client
        .post("http://127.0.0.1:11434/api/pull")
        .json(&serde_json::json!({ "name": model, "stream": false }))
        .send()
        .await
        .context(format!("Failed to connect to Ollama to pull {model}"))?;

    if !resp.status().is_success() {
        anyhow::bail!("Ollama returned status {} for model {}", resp.status(), model);
    }

    // Wait for the pull to complete (non-streaming mode returns when done)
    let body: serde_json::Value = resp.json().await.unwrap_or_default();
    if let Some(error) = body.get("error").and_then(|e| e.as_str()) {
        anyhow::bail!("Ollama error pulling {model}: {error}");
    }

    Ok(())
}

/// Install CLX integration
pub async fn cmd_install(cli: &Cli) -> Result<()> {
    let home = dirs::home_dir().context("Could not determine home directory")?;
    let clx_dir = clx_core::paths::clx_dir();
    let claude_dir = home.join(".claude");
    let settings_path = claude_dir.join("settings.json");

    let mut installed_items: Vec<String> = Vec::new();
    let mut errors: Vec<String> = Vec::new();

    if !cli.json {
        println!("{}", "CLX Installation".cyan().bold());
        println!("{}", "=".repeat(50));
        println!();
    }

    // Step 0: Check Ollama prerequisites
    let ollama_status = if cli.json {
        check_ollama_prerequisites().await
    } else {
        let spinner = indicatif::ProgressBar::new_spinner();
        spinner.set_message("Checking Ollama availability...");
        spinner.enable_steady_tick(std::time::Duration::from_millis(100));
        let status = check_ollama_prerequisites().await;
        spinner.finish_and_clear();
        status
    };
    if !cli.json {
        println!("{}", "Prerequisites".cyan().bold());
        println!("{}", "-".repeat(30));

        // Check Ollama binary
        if ollama_status.binary_installed {
            println!("  {} Ollama installed", "✓".green());
        } else {
            println!("  {} Ollama not found", "✗".red());
            println!("    Install from: {}", "https://ollama.ai".cyan());
        }

        // Check Ollama running
        if ollama_status.server_running {
            println!("  {} Ollama server running", "✓".green());
        } else if ollama_status.binary_installed {
            println!("  {} Ollama server not running", "!".yellow());
            println!("    Start with: {}", "ollama serve".cyan());
        }

        // Check models
        if !ollama_status.missing_models.is_empty() {
            println!("  {} Missing models:", "!".yellow());
            for model in &ollama_status.missing_models {
                println!(
                    "    - {} (run: {})",
                    model,
                    format!("ollama pull {model}").cyan()
                );
            }
        } else if ollama_status.server_running {
            println!("  {} Required models available", "✓".green());
        }

        println!();
    }

    // Auto-install Ollama if missing and Homebrew is available
    let mut ollama_status = ollama_status;
    if !ollama_status.binary_installed {
        if has_homebrew() {
            if !cli.json {
                println!("{}", "Ollama Installation".cyan().bold());
                println!("{}", "-".repeat(30));

                let spinner = indicatif::ProgressBar::new_spinner();
                spinner.set_message("Installing Ollama via Homebrew...");
                spinner.enable_steady_tick(std::time::Duration::from_millis(100));

                match install_ollama_brew() {
                    Ok(()) => {
                        spinner.finish_and_clear();
                        println!("  {} Ollama installed via Homebrew", "+".green());
                        ollama_status.binary_installed = true;
                        installed_items.push("ollama (brew)".to_string());
                    }
                    Err(e) => {
                        spinner.finish_and_clear();
                        println!("  {} Failed to install Ollama: {}", "!".red(), e);
                    }
                }
            } else if install_ollama_brew().is_ok() {
                ollama_status.binary_installed = true;
                installed_items.push("ollama (brew)".to_string());
            }
        } else if !cli.json {
            println!(
                "{}",
                "Ollama is required for L1 validation and embeddings.".yellow()
            );
            println!(
                "  Install from: {} or {}",
                "brew install ollama".cyan(),
                "https://ollama.com".cyan()
            );
            println!();
        }
    }

    // Auto-start Ollama server if binary is installed but not running
    if ollama_status.binary_installed && !ollama_status.server_running {
        if !cli.json {
            let spinner = indicatif::ProgressBar::new_spinner();
            spinner.set_message("Starting Ollama server...");
            spinner.enable_steady_tick(std::time::Duration::from_millis(100));

            match start_ollama_server().await {
                Ok(()) => {
                    spinner.finish_and_clear();
                    println!("  {} Ollama server started", "+".green());
                    ollama_status.server_running = true;

                    // Re-check models now that server is running
                    let fresh = check_ollama_prerequisites().await;
                    ollama_status.missing_models = fresh.missing_models;
                }
                Err(e) => {
                    spinner.finish_and_clear();
                    println!("  {} Failed to start Ollama: {}", "!".yellow(), e);
                }
            }
        } else if start_ollama_server().await.is_ok() {
            ollama_status.server_running = true;
            let fresh = check_ollama_prerequisites().await;
            ollama_status.missing_models = fresh.missing_models;
        }

        if !cli.json {
            println!();
        }
    }

    // Auto-pull missing models if Ollama is running
    let mut pulled_models: Vec<String> = Vec::new();
    if ollama_status.server_running && !ollama_status.missing_models.is_empty() {
        if !cli.json {
            println!();
            println!("{}", "Model Installation".cyan().bold());
            println!("{}", "-".repeat(30));
        }

        for model in &ollama_status.missing_models {
            if !cli.json {
                let spinner = indicatif::ProgressBar::new_spinner();
                spinner.set_message(format!("Pulling {model}..."));
                spinner.enable_steady_tick(std::time::Duration::from_millis(100));

                match pull_ollama_model(model).await {
                    Ok(()) => {
                        spinner.finish_and_clear();
                        println!("  {} Pulled {}", "+".green(), model);
                        pulled_models.push(model.clone());
                    }
                    Err(e) => {
                        spinner.finish_and_clear();
                        println!("  {} Failed to pull {}: {}", "!".yellow(), model, e);
                    }
                }
            } else if let Ok(()) = pull_ollama_model(model).await {
                pulled_models.push(model.clone());
            }
        }
    }

    // Store warnings for JSON output
    let mut warnings: Vec<String> = Vec::new();
    if !ollama_status.binary_installed {
        warnings.push("Ollama not installed - L1 validation disabled".to_string());
    } else if !ollama_status.server_running {
        warnings.push("Ollama server not running - could not pull models".to_string());
    }
    // Only warn about models that weren't successfully pulled
    for model in &ollama_status.missing_models {
        if !pulled_models.contains(model) {
            warnings.push(format!("Missing model: {model}"));
        }
    }

    // Step 1: Create directory structure
    let docker_dir = clx_dir.join("docker");
    let dirs_to_create = [
        clx_dir.clone(),
        clx_core::paths::bin_dir(),
        clx_core::paths::data_dir(),
        clx_core::paths::logs_dir(),
        clx_core::paths::rules_dir(),
        clx_core::paths::prompts_dir(),
        clx_core::paths::learned_dir(),
        docker_dir.clone(),
    ];

    for dir in &dirs_to_create {
        if !dir.exists() {
            fs::create_dir_all(dir)?;
            if !cli.json {
                println!("  {} Created {}", "+".green(), dir.display());
            }
            installed_items.push(format!("directory: {}", dir.display()));
        } else if !cli.json {
            println!("  {} Exists  {}", "*".dimmed(), dir.display());
        }
    }

    // Write default docker-compose.yml if not present
    let compose_path = docker_dir.join("docker-compose.yml");
    if !compose_path.exists() {
        fs::write(&compose_path, DOCKER_COMPOSE_YML)?;
        if !cli.json {
            println!("  {} Created {}", "+".green(), compose_path.display());
        }
        installed_items.push("docker-compose.yml".to_string());
    } else if !cli.json {
        println!("  {} Exists  {}", "*".dimmed(), compose_path.display());
    }

    // Set restrictive permissions on ~/.clx/ root directory (owner-only access)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&clx_dir, fs::Permissions::from_mode(0o700))?;
    }

    // Step 2: Write default config.yaml if not exists
    let config_path = clx_dir.join("config.yaml");
    if !config_path.exists() {
        let config = Config::default();
        let yaml = serde_yml::to_string(&config)?;
        fs::write(&config_path, yaml)?;
        if !cli.json {
            println!("  {} Created {}", "+".green(), config_path.display());
        }
        installed_items.push("config.yaml".to_string());
    } else if !cli.json {
        println!("  {} Exists  {}", "*".dimmed(), config_path.display());
    }

    // Step 3: Write default rules/default.yaml
    clx_core::policy::ensure_default_rules_file()?;
    let rules_path = clx_core::paths::default_rules_path();
    if !cli.json {
        if rules_path.exists() {
            println!("  {} Exists  {}", "*".dimmed(), rules_path.display());
        } else {
            println!("  {} Created {}", "+".green(), rules_path.display());
            installed_items.push("rules/default.yaml".to_string());
        }
    }

    // Step 4: Write prompt templates + active validator.txt
    let prompts_dir = clx_core::paths::prompts_dir();
    let prompt_templates: &[(&str, &str)] = &[
        ("validator-standard.txt", clx_core::policy::PROMPT_STANDARD),
        ("validator-high.txt", clx_core::policy::PROMPT_HIGH),
        ("validator-low.txt", clx_core::policy::PROMPT_LOW),
    ];
    for &(filename, content) in prompt_templates {
        let path = prompts_dir.join(filename);
        if !path.exists() {
            fs::write(&path, content)?;
            if !cli.json {
                println!("  {} Created {}", "+".green(), path.display());
            }
            installed_items.push(format!("prompts/{filename}"));
        } else if !cli.json {
            println!("  {} Exists  {}", "*".dimmed(), path.display());
        }
    }
    // Write active validator.txt (standard by default) if not present
    let validator_prompt_path = clx_core::paths::validator_prompt_path();
    if !validator_prompt_path.exists() {
        fs::write(&validator_prompt_path, clx_core::policy::PROMPT_STANDARD)?;
        if !cli.json {
            println!(
                "  {} Created {}",
                "+".green(),
                validator_prompt_path.display()
            );
        }
        installed_items.push("prompts/validator.txt".to_string());
    } else if !cli.json {
        println!(
            "  {} Exists  {}",
            "*".dimmed(),
            validator_prompt_path.display()
        );
    }

    // Step 5: Copy/link binaries to ~/.clx/bin/
    let bin_dir = clx_core::paths::bin_dir();
    let binaries = ["clx", "clx-hook", "clx-mcp"];

    for binary_name in &binaries {
        match find_binary(binary_name) {
            Ok(src_path) => {
                let dest_path = bin_dir.join(binary_name);
                match install_binary(&src_path, &dest_path) {
                    Ok(()) => {
                        if !cli.json {
                            println!("  {} Installed {}", "+".green(), dest_path.display());
                        }
                        installed_items.push(format!("binary: {binary_name}"));
                    }
                    Err(e) => {
                        if !cli.json {
                            println!("  {} Failed to install {}: {}", "!".red(), binary_name, e);
                        }
                        errors.push(format!("Failed to install {binary_name}: {e}"));
                    }
                }
            }
            Err(e) => {
                if !cli.json {
                    println!("  {} Could not find {}: {}", "!".yellow(), binary_name, e);
                }
                errors.push(format!("Could not find {binary_name}: {e}"));
            }
        }
    }

    // Step 6: Initialize SQLite database
    if !cli.json {
        println!();
        println!("{}", "Database".cyan().bold());
        println!("{}", "-".repeat(30));
    }

    match Storage::open_default() {
        Ok(_) => {
            if !cli.json {
                println!("  {} Database initialized", "+".green());
            }
            installed_items.push("database".to_string());
        }
        Err(e) => {
            if !cli.json {
                println!("  {} Database error: {}", "!".red(), e);
            }
            errors.push(format!("Database error: {e}"));
        }
    }

    // Step 7: Configure ~/.claude/settings.json
    if !cli.json {
        println!();
        println!("{}", "Claude Code Integration".cyan().bold());
        println!("{}", "-".repeat(30));
    }

    // Ensure ~/.claude/ directory exists
    if !claude_dir.exists() {
        fs::create_dir_all(&claude_dir)?;
        if !cli.json {
            println!("  {} Created {}", "+".green(), claude_dir.display());
        }
    }

    // Read existing settings
    let mut settings = read_claude_settings(&settings_path)?;

    // Add hooks configuration
    let hooks_config = get_hooks_config();
    settings["hooks"] = hooks_config;
    if !cli.json {
        println!(
            "  {} Configured hooks (PreToolUse, PostToolUse, PreCompact, SessionStart, SessionEnd, SubagentStart, UserPromptSubmit)",
            "+".green()
        );
    }
    installed_items.push("hooks configuration".to_string());

    // Add MCP server configuration
    let mcp_config = get_mcp_config();
    if settings.get("mcpServers").is_none() {
        settings["mcpServers"] = serde_json::json!({});
    }
    if let Some(mcp_servers) = settings.get_mut("mcpServers")
        && let Some(obj) = mcp_servers.as_object_mut()
    {
        obj.insert("clx".to_string(), mcp_config["clx"].clone());
    }
    if !cli.json {
        println!("  {} Configured MCP server (clx)", "+".green());
    }
    installed_items.push("mcp server configuration".to_string());

    // Write updated settings
    write_claude_settings(&settings_path, &settings)?;
    if !cli.json {
        println!("  {} Updated {}", "+".green(), settings_path.display());
    }

    // Step 8: Inject CLX section into CLAUDE.md
    let claude_md_path = claude_dir.join("CLAUDE.md");
    if !cli.json {
        println!();
        println!("{}", "CLAUDE.md Integration".cyan().bold());
        println!("{}", "-".repeat(30));
    }

    match inject_clx_to_claude_md(&claude_md_path) {
        Ok(true) => {
            if !cli.json {
                println!(
                    "  {} Added CLX tools section to {}",
                    "+".green(),
                    claude_md_path.display()
                );
            }
            installed_items.push("CLAUDE.md CLX section".to_string());
        }
        Ok(false) => {
            if !cli.json {
                println!(
                    "  {} CLX section already present in {}",
                    "*".dimmed(),
                    claude_md_path.display()
                );
            }
        }
        Err(e) => {
            if !cli.json {
                println!("  {} Failed to update CLAUDE.md: {}", "!".yellow(), e);
            }
            warnings.push(format!("Could not update CLAUDE.md: {e}"));
        }
    }

    // Output summary
    if cli.json {
        let output = serde_json::json!({
            "action": "install",
            "success": errors.is_empty(),
            "installed": installed_items,
            "errors": errors,
            "warnings": warnings,
            "ollama": {
                "installed": ollama_status.binary_installed,
                "running": ollama_status.server_running,
                "missing_models": ollama_status.missing_models,
                "pulled_models": pulled_models
            },
            "paths": {
                "clx_dir": clx_dir.display().to_string(),
                "config": config_path.display().to_string(),
                "settings": settings_path.display().to_string(),
                "claude_md": claude_md_path.display().to_string()
            }
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!();
        if errors.is_empty() {
            println!("{}", "Installation Complete".green().bold());
            println!("{}", "=".repeat(50));
            println!();
            println!("CLX has been installed successfully.");
            println!();
            println!("{}:", "Configured".cyan());
            println!(
                "  - Hooks: PreToolUse, PostToolUse, PreCompact, SessionStart, SessionEnd, SubagentStart, UserPromptSubmit"
            );
            println!("  - MCP Server: clx (clx_recall, clx_remember, etc.)");
            println!("  - CLAUDE.md: CLX tools documentation injected");
            println!();
            println!("{}:", "Paths".cyan());
            println!("  - CLX directory: {}", clx_dir.display());
            println!("  - Config file: {}", config_path.display());
            println!("  - Claude settings: {}", settings_path.display());
            println!("  - CLAUDE.md: {}", claude_md_path.display());
            println!();
            println!("{}:", "Next Steps".yellow());
            println!("  1. Restart Claude Code to load the new configuration");
            println!("  2. Run 'clx dashboard' to verify installation");
            println!("  3. Run 'clx config' to view/edit configuration");
        } else {
            println!("{}", "Installation Completed with Warnings".yellow().bold());
            println!("{}", "=".repeat(50));
            println!();
            println!("Some components could not be installed:");
            for err in &errors {
                println!("  {} {}", "!".red(), err);
            }
            println!();
            println!("The installation may still work. Try:");
            println!("  1. Build all binaries: cargo build --release");
            println!("  2. Re-run: clx install");
        }
    }

    Ok(())
}

/// Remove CLX hooks from settings.json
fn remove_clx_from_settings(settings: &mut serde_json::Value) -> (bool, bool) {
    let mut hooks_removed = false;
    let mut mcp_removed = false;

    // Remove hooks
    if settings.get("hooks").is_some() {
        settings.as_object_mut().unwrap().remove("hooks");
        hooks_removed = true;
    }

    // Remove clx from mcpServers
    if let Some(mcp_servers) = settings.get_mut("mcpServers")
        && let Some(obj) = mcp_servers.as_object_mut()
    {
        if obj.remove("clx").is_some() {
            mcp_removed = true;
        }
        // If mcpServers is now empty, remove it
        if obj.is_empty() {
            settings.as_object_mut().unwrap().remove("mcpServers");
        }
    }

    (hooks_removed, mcp_removed)
}

/// Uninstall CLX integration
pub async fn cmd_uninstall(cli: &Cli, purge: bool) -> Result<()> {
    let home = dirs::home_dir().context("Could not determine home directory")?;
    let clx_dir = clx_core::paths::clx_dir();
    let claude_dir = home.join(".claude");
    let settings_path = claude_dir.join("settings.json");

    let mut removed_items: Vec<String> = Vec::new();

    if !cli.json {
        println!("{}", "CLX Uninstallation".cyan().bold());
        println!("{}", "=".repeat(50));
        println!();
    }

    // Step 1: Remove hooks and MCP server from settings.json
    if settings_path.exists() {
        if !cli.json {
            println!("{}", "Claude Code Configuration".cyan().bold());
            println!("{}", "-".repeat(30));
        }

        let mut settings = read_claude_settings(&settings_path)?;
        let (hooks_removed, mcp_removed) = remove_clx_from_settings(&mut settings);

        if hooks_removed {
            if !cli.json {
                println!("  {} Removed hooks configuration", "-".red());
            }
            removed_items.push("hooks configuration".to_string());
        }

        if mcp_removed {
            if !cli.json {
                println!("  {} Removed MCP server (clx)", "-".red());
            }
            removed_items.push("mcp server configuration".to_string());
        }

        if hooks_removed || mcp_removed {
            write_claude_settings(&settings_path, &settings)?;
            if !cli.json {
                println!("  {} Updated {}", "+".green(), settings_path.display());
            }
        } else if !cli.json {
            println!(
                "  {} No CLX configuration found in settings.json",
                "*".dimmed()
            );
        }
    } else if !cli.json {
        println!(
            "  {} settings.json not found, nothing to remove",
            "*".dimmed()
        );
    }

    // Step 2: Optionally remove ~/.clx/ directory
    if purge {
        if !cli.json {
            println!();
            println!("{}", "Data Removal".cyan().bold());
            println!("{}", "-".repeat(30));
        }

        if clx_dir.exists() {
            // In non-JSON mode, confirm deletion
            if cli.json {
                // In JSON mode, just delete without prompting
                fs::remove_dir_all(&clx_dir)?;
                removed_items.push(format!("directory: {}", clx_dir.display()));
            } else {
                print!(
                    "{} This will permanently delete {} and all data. Continue? [y/N] ",
                    "Warning:".red().bold(),
                    clx_dir.display()
                );
                io::stdout().flush()?;

                let mut input = String::new();
                io::stdin().read_line(&mut input)?;

                if input.trim().eq_ignore_ascii_case("y") {
                    fs::remove_dir_all(&clx_dir)?;
                    println!("  {} Removed {}", "-".red(), clx_dir.display());
                    removed_items.push(format!("directory: {}", clx_dir.display()));
                } else {
                    println!("Cancelled. {} was not deleted.", clx_dir.display());
                }
            }
        } else if !cli.json {
            println!("  {} {} does not exist", "*".dimmed(), clx_dir.display());
        }
    } else if !cli.json {
        println!();
        println!(
            "{}",
            "Note: ~/.clx/ directory was preserved. Use --purge to remove it.".dimmed()
        );
    }

    // Output summary
    if cli.json {
        let output = serde_json::json!({
            "action": "uninstall",
            "success": true,
            "purge": purge,
            "removed": removed_items,
            "paths": {
                "clx_dir": clx_dir.display().to_string(),
                "clx_dir_exists": clx_dir.exists(),
                "settings": settings_path.display().to_string()
            }
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!();
        println!("{}", "Uninstallation Complete".green().bold());
        println!("{}", "=".repeat(50));
        println!();

        if removed_items.is_empty() {
            println!("No CLX configuration was found to remove.");
        } else {
            println!("Removed:");
            for item in &removed_items {
                println!("  - {item}");
            }
        }

        if !purge && clx_dir.exists() {
            println!();
            println!("{}:", "Preserved".cyan());
            println!("  - {} (contains config, data, logs)", clx_dir.display());
            println!();
            println!("To completely remove CLX including all data:");
            println!("  clx uninstall --purge");
        }

        println!();
        println!("Restart Claude Code to apply changes.");
    }

    Ok(())
}
