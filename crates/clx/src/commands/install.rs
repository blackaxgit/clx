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
use crate::codex;
use crate::cursor;

/// Which host(s) `clx install` / `clx uninstall` should act on.
///
/// `Auto` (the default) installs into every host CLX can detect on the machine
/// (Claude is always treated as present); `All` acts on all three
/// unconditionally; the single-host variants target exactly one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum InstallTarget {
    /// Claude Code only (`~/.claude`).
    Claude,
    /// Codex CLI only (`~/.codex`).
    Codex,
    /// Cursor IDE only (`~/.cursor` + repo-local rule).
    Cursor,
    /// All three hosts, unconditionally.
    All,
    /// Every detected host (default). Claude is always included.
    Auto,
}

impl InstallTarget {
    /// Whether Claude should be acted on for this target. Claude is the CLX
    /// baseline host, so `Auto`/`All` always include it.
    fn wants_claude(self) -> bool {
        matches!(self, Self::Claude | Self::All | Self::Auto)
    }

    /// Whether Codex should be acted on. `All` forces it; `Auto` gates on
    /// detection (resolved by the caller); `Codex` selects it explicitly.
    fn wants_codex(self, detected: bool) -> bool {
        match self {
            Self::Codex | Self::All => true,
            Self::Auto => detected,
            _ => false,
        }
    }

    /// Whether Cursor should be acted on. Same gating logic as Codex.
    fn wants_cursor(self, detected: bool) -> bool {
        match self {
            Self::Cursor | Self::All => true,
            Self::Auto => detected,
            _ => false,
        }
    }
}

/// Strip a marker-delimited section (`# CLX Integration`-style H1 through the
/// next top-level `# ` heading or EOF) from a markdown file. Used by D8
/// uninstall for `CLAUDE.md`, `AGENTS.md`, and `AGENTS.override.md`.
///
/// Returns `Ok(true)` if the file existed, contained the marker, and was
/// rewritten without it. A file without the marker (or missing) is a clean
/// no-op returning `Ok(false)`. The marker is matched only at the start of a
/// line so it is never confused with an inline mention.
fn remove_clx_section_from_file(path: &std::path::Path, marker: &str) -> Result<bool> {
    let Ok(content) = fs::read_to_string(path) else {
        return Ok(false);
    };
    let stripped = strip_marker_section(&content, marker);
    if stripped == content {
        return Ok(false);
    }
    fs::write(path, stripped).context("rewrite file after stripping CLX section")?;
    Ok(true)
}

/// Pure string transform behind [`remove_clx_section_from_file`]: drop the
/// block beginning at a line equal to `marker` (an H1 heading) up to but not
/// including the next line that starts a new top-level `# ` heading (or EOF).
fn strip_marker_section(content: &str, marker: &str) -> String {
    let lines: Vec<&str> = content.lines().collect();
    // The CLX heading may carry a trailing tag (e.g. `# CLX Integration
    // [STRICT]`), so accept either the bare marker or the marker followed by a
    // bracketed tag. R2-F5: do NOT match a user's own heading like
    // `# CLX Integration Guide` (remainder does not start with `[`), which the
    // old `starts_with` over-deleted.
    let is_marker = |l: &str| {
        let t = l.trim_end();
        t == marker
            || t.strip_prefix(marker)
                .is_some_and(|rest| rest.trim_start().starts_with('['))
    };
    let Some(start) = lines.iter().position(|l| is_marker(l)) else {
        return content.to_string();
    };
    // Find the next top-level H1 after the marker (a line starting with "# "
    // that is not the marker itself).
    let mut end = lines.len();
    for (i, line) in lines.iter().enumerate().skip(start + 1) {
        if line.starts_with("# ") {
            end = i;
            break;
        }
    }
    let mut kept: Vec<&str> = Vec::new();
    kept.extend_from_slice(&lines[..start]);
    kept.extend_from_slice(&lines[end..]);
    // Re-join, trimming trailing blank lines that the removed section left
    // behind, and preserve a single trailing newline if the original had one.
    let mut out = kept.join("\n");
    while out.ends_with('\n') || out.ends_with(' ') {
        out.pop();
    }
    if !out.is_empty() {
        out.push('\n');
    }
    out
}

/// Default docker-compose.yml embedded from scripts/docker-compose.yml
const DOCKER_COMPOSE_YML: &str = include_str!("../../../../scripts/docker-compose.yml");

/// CLX-managed Claude Code skills, embedded so a non-plugin (cargo/manual)
/// install is self-contained. Each entry is (skill directory name, SKILL.md
/// contents). Installed to `~/.claude/skills/<name>/SKILL.md`, the personal
/// skills location documented at <https://code.claude.com/docs/en/skills>
/// ("Where skills live": Personal -> `~/.claude/skills/<skill-name>/SKILL.md`).
const CLX_SKILLS: &[(&str, &str)] = &[
    (
        "clx-recall",
        include_str!("../../../../plugin/.claude-plugin/skills/clx-recall/SKILL.md"),
    ),
    (
        "clx-remember",
        include_str!("../../../../plugin/.claude-plugin/skills/clx-remember/SKILL.md"),
    ),
    (
        "clx-checkpoint",
        include_str!("../../../../plugin/.claude-plugin/skills/clx-checkpoint/SKILL.md"),
    ),
    (
        "clx-rules",
        include_str!("../../../../plugin/.claude-plugin/skills/clx-rules/SKILL.md"),
    ),
    (
        "clx-resume",
        include_str!("../../../../plugin/.claude-plugin/skills/clx-resume/SKILL.md"),
    ),
    (
        "clx-doctor",
        include_str!("../../../../plugin/.claude-plugin/skills/clx-doctor/SKILL.md"),
    ),
];

/// Name of the version-stamp file written into `~/.clx/bin/`.
const VERSION_STAMP_FILE: &str = ".clx-version";

/// The workspace version this binary was built from.
const CLX_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Result of comparing the running binary version to the on-disk stamp.
#[derive(Debug, PartialEq, Eq)]
enum VersionStampStatus {
    /// No stamp file present (fresh install or pre-0.8.0 layout).
    Absent,
    /// Stamp matches the running binary version.
    Match,
    /// Stamp differs from the running binary version (stale binary risk).
    Mismatch { stamped: String, running: String },
}

/// Pure comparison of an optional on-disk stamp against the running version.
fn version_stamp_status(stamp: Option<&str>, running: &str) -> VersionStampStatus {
    match stamp {
        None => VersionStampStatus::Absent,
        Some(s) if s.trim() == running => VersionStampStatus::Match,
        Some(s) => VersionStampStatus::Mismatch {
            stamped: s.trim().to_string(),
            running: running.to_string(),
        },
    }
}

/// Read the version stamp from `~/.clx/bin/.clx-version`, if present.
fn read_version_stamp(bin_dir: &std::path::Path) -> Option<String> {
    let path = bin_dir.join(VERSION_STAMP_FILE);
    fs::read_to_string(path).ok()
}

/// Write the running version into `~/.clx/bin/.clx-version` (idempotent).
fn write_version_stamp(bin_dir: &std::path::Path) -> Result<()> {
    let path = bin_dir.join(VERSION_STAMP_FILE);
    fs::write(path, format!("{CLX_VERSION}\n")).context("Failed to write version stamp")?;
    Ok(())
}

/// Resolve the personal Claude Code skills directory for a skill name.
/// Per <https://code.claude.com/docs/en/skills> personal skills live at
/// `~/.claude/skills/<skill-name>/`.
fn skill_dir(claude_dir: &std::path::Path, skill_name: &str) -> PathBuf {
    claude_dir.join("skills").join(skill_name)
}

/// Install (or refresh) the embedded CLX skills into the personal skills
/// location. CLX owns these files, so this overwrites `SKILL.md` on every
/// run (idempotent, mirrors the binary-install policy).
fn install_skills(claude_dir: &std::path::Path) -> Result<Vec<String>> {
    let mut installed = Vec::new();
    for (name, contents) in CLX_SKILLS {
        let dir = skill_dir(claude_dir, name);
        fs::create_dir_all(&dir).context(format!("Failed to create skill dir for {name}"))?;
        let skill_md = dir.join("SKILL.md");
        fs::write(&skill_md, contents).context(format!("Failed to write SKILL.md for {name}"))?;
        installed.push((*name).to_string());
    }
    Ok(installed)
}

/// Remove CLX-installed skills. Only deletes a skill directory when it
/// contains nothing other than the `SKILL.md` we wrote, so user-authored
/// files in a same-named directory are never destroyed.
fn uninstall_skills(claude_dir: &std::path::Path) -> Vec<String> {
    let mut removed = Vec::new();
    for (name, _) in CLX_SKILLS {
        let dir = skill_dir(claude_dir, name);
        if !dir.exists() {
            continue;
        }
        let skill_md = dir.join("SKILL.md");
        if !skill_md.exists() {
            continue;
        }
        // Only reclaim the directory if SKILL.md is the sole entry.
        let only_skill_md = fs::read_dir(&dir).is_ok_and(|rd| {
            let entries: Vec<_> = rd.flatten().collect();
            entries.len() == 1 && entries[0].file_name().to_string_lossy() == "SKILL.md"
        });
        if only_skill_md {
            if fs::remove_dir_all(&dir).is_ok() {
                removed.push((*name).to_string());
            }
        } else if fs::remove_file(&skill_md).is_ok() {
            // User added extra files; remove only our SKILL.md.
            removed.push((*name).to_string());
        }
    }
    removed
}

/// Additively merge missing top-level default keys into an existing
/// config.yaml WITHOUT clobbering any user-set values. Returns the list of
/// top-level keys that were added (empty if none / not a mapping).
fn merge_missing_config_keys(
    existing_yaml: &str,
    default_yaml: &str,
) -> Result<(String, Vec<String>)> {
    let existing: serde_yml::Value =
        serde_yml::from_str(existing_yaml).context("Existing config.yaml is not valid YAML")?;
    let defaults: serde_yml::Value =
        serde_yml::from_str(default_yaml).context("Default config is not valid YAML")?;

    let (serde_yml::Value::Mapping(mut existing_map), serde_yml::Value::Mapping(default_map)) =
        (existing.clone(), defaults)
    else {
        // Not a mapping (empty or scalar) -> leave untouched, no-op.
        return Ok((existing_yaml.to_string(), Vec::new()));
    };

    let mut added = Vec::new();
    for (k, v) in &default_map {
        if !existing_map.contains_key(k) {
            existing_map.insert(k.clone(), v.clone());
            if let serde_yml::Value::String(name) = k {
                added.push(name.clone());
            }
        }
    }

    if added.is_empty() {
        return Ok((existing_yaml.to_string(), Vec::new()));
    }

    let merged = serde_yml::to_string(&serde_yml::Value::Mapping(existing_map))
        .context("Failed to re-serialize merged config")?;
    Ok((merged, added))
}

/// CLX section to inject into CLAUDE.md
const CLX_CLAUDE_MD_SECTION: &str = r#"
# CLX Integration [STRICT]

**[SCOPE: ALL AGENTS]**

CLX (Coding-Agent Extension Layer) provides MCP tools for context persistence across sessions.

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
        }],
        "Stop": [{
            "hooks": [{"type": "command", "command": "~/.clx/bin/clx-hook stop"}]
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
        .is_ok_and(|o| o.status.success())
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
        .is_ok_and(|o| o.status.success());

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
        .timeout(std::time::Duration::from_mins(10))
        .build()?;

    let resp = client
        .post("http://127.0.0.1:11434/api/pull")
        .json(&serde_json::json!({ "name": model, "stream": false }))
        .send()
        .await
        .context(format!("Failed to connect to Ollama to pull {model}"))?;

    if !resp.status().is_success() {
        anyhow::bail!(
            "Ollama returned status {} for model {}",
            resp.status(),
            model
        );
    }

    // Wait for the pull to complete (non-streaming mode returns when done)
    let body: serde_json::Value = resp.json().await.unwrap_or_default();
    if let Some(error) = body.get("error").and_then(|e| e.as_str()) {
        anyhow::bail!("Ollama error pulling {model}: {error}");
    }

    Ok(())
}

/// Write the Codex host artifacts (`~/.codex/hooks.json`, `config.toml`
/// `[mcp_servers.clx]`, and the AGENTS.md CLX section). Failures are recorded
/// as warnings, never fatal, so a partial host install does not abort the rest.
fn install_codex_host(
    cli: &Cli,
    home: &std::path::Path,
    installed_items: &mut Vec<String>,
    warnings: &mut Vec<String>,
) {
    if !cli.json {
        println!();
        println!("{}", "Codex Integration".cyan().bold());
        println!("{}", "-".repeat(30));
    }

    match codex::write_codex_hooks(home) {
        Ok(_) => {
            if !cli.json {
                println!(
                    "  {} Configured {}",
                    "+".green(),
                    codex::hooks_json_path(home).display()
                );
            }
            installed_items.push("codex hooks.json".to_string());
        }
        Err(e) => warnings.push(format!("Could not write Codex hooks.json: {e}")),
    }

    match codex::write_codex_mcp(home) {
        Ok(_) => {
            if !cli.json {
                println!(
                    "  {} Configured MCP server (clx) in {}",
                    "+".green(),
                    codex::config_toml_path(home).display()
                );
            }
            installed_items.push("codex config.toml [mcp_servers.clx]".to_string());
        }
        Err(e) => warnings.push(format!("Could not write Codex config.toml: {e}")),
    }

    match codex::inject_codex_agents_md(home) {
        Ok(codex::AgentsInjectOutcome::Injected) => {
            if !cli.json {
                println!(
                    "  {} Added CLX section to {}",
                    "+".green(),
                    codex::agents_md_path(home).display()
                );
            }
            installed_items.push("codex AGENTS.md CLX section".to_string());
        }
        Ok(codex::AgentsInjectOutcome::OverrideFallback) => {
            if !cli.json {
                println!(
                    "  {} AGENTS.md near 32 KiB cap; wrote {}",
                    "!".yellow(),
                    codex::agents_override_md_path(home).display()
                );
            }
            installed_items.push("codex AGENTS.override.md CLX section".to_string());
        }
        Ok(codex::AgentsInjectOutcome::AlreadyPresent) => {
            if !cli.json {
                println!(
                    "  {} CLX section already present in {}",
                    "*".dimmed(),
                    codex::agents_md_path(home).display()
                );
            }
        }
        Err(e) => warnings.push(format!("Could not update Codex AGENTS.md: {e}")),
    }
}

/// Write the Cursor host artifacts (`~/.cursor/mcp.json`, `~/.cursor/hooks.json`
/// with `failClosed:true`, and - when `write_repo_rule` is set - the repo-local
/// `.cursor/rules/clx.mdc`). The rule is project-scoped (Cursor has no global
/// instructions file) and is written into the current working directory; it is
/// only emitted on an explicit Cursor target (`--target cursor`/`all`), never
/// under `auto`, so a plain `clx install` never drops a file into the user's
/// cwd. Failures are warnings.
fn install_cursor_host(
    cli: &Cli,
    home: &std::path::Path,
    write_repo_rule: bool,
    installed_items: &mut Vec<String>,
    warnings: &mut Vec<String>,
) {
    if !cli.json {
        println!();
        println!("{}", "Cursor Integration".cyan().bold());
        println!("{}", "-".repeat(30));
    }

    match cursor::write_cursor_mcp(home) {
        Ok(_) => {
            if !cli.json {
                println!(
                    "  {} Configured MCP server (clx) in {}",
                    "+".green(),
                    cursor::mcp_json_path(home).display()
                );
            }
            installed_items.push("cursor mcp.json".to_string());
        }
        Err(e) => warnings.push(format!("Could not write Cursor mcp.json: {e}")),
    }

    match cursor::write_cursor_hooks(home) {
        Ok(_) => {
            if !cli.json {
                println!(
                    "  {} Configured {} (failClosed)",
                    "+".green(),
                    cursor::hooks_json_path(home).display()
                );
            }
            installed_items.push("cursor hooks.json".to_string());
        }
        Err(e) => warnings.push(format!("Could not write Cursor hooks.json: {e}")),
    }

    // Project-scoped rule: written into the current repo (cwd), only on an
    // explicit Cursor target so `auto` never touches the user's cwd.
    if write_repo_rule {
        match env::current_dir() {
            Ok(repo) => match cursor::write_cursor_rule(&repo) {
                Ok(_) => {
                    if !cli.json {
                        println!(
                            "  {} Wrote {}",
                            "+".green(),
                            cursor::rule_mdc_path(&repo).display()
                        );
                    }
                    installed_items.push("cursor .cursor/rules/clx.mdc".to_string());
                }
                Err(e) => warnings.push(format!("Could not write Cursor rule: {e}")),
            },
            Err(e) => warnings.push(format!("Could not resolve repo for Cursor rule: {e}")),
        }
    } else if !cli.json {
        println!(
            "  {} Skipped repo-local .cursor/rules/clx.mdc (run `clx install --target cursor` in a repo to add it)",
            "*".dimmed()
        );
    }
}

/// Install CLX integration
pub async fn cmd_install(cli: &Cli, target: InstallTarget) -> Result<()> {
    let home = dirs::home_dir().context("Could not determine home directory")?;
    let clx_dir = clx_core::paths::clx_dir();
    let claude_dir = home.join(".claude");
    let settings_path = claude_dir.join("settings.json");

    let mut installed_items: Vec<String> = Vec::new();
    let mut errors: Vec<String> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();

    if !cli.json {
        println!("{}", "CLX Installation".cyan().bold());
        println!("{}", "=".repeat(50));
        println!();
    }

    // GAP-3: warn early if a stale binary set is shadowing the running CLX.
    let bin_dir_check = clx_core::paths::bin_dir();
    if let VersionStampStatus::Mismatch { stamped, running } =
        version_stamp_status(read_version_stamp(&bin_dir_check).as_deref(), CLX_VERSION)
    {
        let msg = format!(
            "Version skew: ~/.clx/bin was installed by CLX {stamped} but you are \
             running CLX {running}. Re-running install will refresh the binaries."
        );
        if cli.json {
            warnings.push(msg);
        } else {
            println!("  {} {}", "!".yellow(), msg);
            println!();
        }
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
    if config_path.exists() {
        // GAP-5: additively merge any missing top-level default keys into the
        // existing config.yaml without clobbering user values.
        match (
            fs::read_to_string(&config_path),
            serde_yml::to_string(&Config::default()),
        ) {
            (Ok(existing), Ok(default_yaml)) => {
                match merge_missing_config_keys(&existing, &default_yaml) {
                    Ok((merged, added)) if !added.is_empty() => {
                        if fs::write(&config_path, merged).is_ok() {
                            if !cli.json {
                                println!(
                                    "  {} Added missing config keys ({}) to {}",
                                    "+".green(),
                                    added.join(", "),
                                    config_path.display()
                                );
                            }
                            installed_items.push(format!("config.yaml keys: {}", added.join(", ")));
                        }
                    }
                    Ok(_) => {
                        if !cli.json {
                            println!("  {} Exists  {}", "*".dimmed(), config_path.display());
                        }
                    }
                    Err(e) => {
                        warnings.push(format!("Could not merge config.yaml keys: {e}"));
                        if !cli.json {
                            println!(
                                "  {} Exists  {} (key merge skipped: {})",
                                "*".dimmed(),
                                config_path.display(),
                                e
                            );
                        }
                    }
                }
            }
            _ => {
                if !cli.json {
                    println!("  {} Exists  {}", "*".dimmed(), config_path.display());
                }
            }
        }
    } else {
        let config = Config::default();
        let yaml = serde_yml::to_string(&config)?;
        fs::write(&config_path, yaml)?;
        if !cli.json {
            println!("  {} Created {}", "+".green(), config_path.display());
        }
        installed_items.push("config.yaml".to_string());
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

    // GAP-3: stamp the installed workspace version so future runs can detect
    // a stale binary set shadowing a newer CLX.
    match write_version_stamp(&bin_dir) {
        Ok(()) => {
            if !cli.json {
                println!(
                    "  {} Stamped version {} ({})",
                    "+".green(),
                    CLX_VERSION,
                    bin_dir.join(VERSION_STAMP_FILE).display()
                );
            }
            installed_items.push(format!("version stamp: {CLX_VERSION}"));
        }
        Err(e) => {
            warnings.push(format!("Could not write version stamp: {e}"));
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

    let claude_md_path = claude_dir.join("CLAUDE.md");

    // Step 7: Configure ~/.claude (Claude Code host). Gated on the target so
    // `--target codex`/`cursor` skip Claude wiring; `auto`/`all`/`claude`
    // include it. The body below is byte-identical to the pre-P3 Claude path.
    if target.wants_claude() {
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
                "  {} Configured hooks (PreToolUse, PostToolUse, PreCompact, SessionStart, SessionEnd, SubagentStart, UserPromptSubmit, Stop)",
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

        // GAP-2: install the 6 CLX skills into the personal skills location so a
        // non-plugin (cargo/manual) install is self-contained.
        match install_skills(&claude_dir) {
            Ok(skill_names) => {
                if !cli.json {
                    println!(
                        "  {} Installed {} skills to {}",
                        "+".green(),
                        skill_names.len(),
                        claude_dir.join("skills").display()
                    );
                }
                installed_items.push(format!("skills: {}", skill_names.join(", ")));
            }
            Err(e) => {
                if !cli.json {
                    println!("  {} Failed to install skills: {}", "!".yellow(), e);
                }
                warnings.push(format!("Could not install skills: {e}"));
            }
        }

        // Step 8: Inject CLX section into CLAUDE.md
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
    }

    // Step 9: Codex host integration (~/.codex). Written when the target asks
    // for Codex (explicit, `all`, or `auto` with a detected `codex` binary).
    let codex_detected = codex::detect_codex().installed;
    if target.wants_codex(codex_detected) {
        install_codex_host(cli, &home, &mut installed_items, &mut warnings);
    }

    // Step 10: Cursor host integration (~/.cursor + repo-local rule). The
    // repo-local rule is only written on an explicit Cursor target so a plain
    // `clx install` (auto) never drops a file into the user's cwd.
    let cursor_detected = cursor::detect_cursor().installed;
    if target.wants_cursor(cursor_detected) {
        let write_repo_rule = matches!(target, InstallTarget::Cursor | InstallTarget::All);
        install_cursor_host(
            cli,
            &home,
            write_repo_rule,
            &mut installed_items,
            &mut warnings,
        );
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
                "  - Hooks: PreToolUse, PostToolUse, PreCompact, SessionStart, SessionEnd, SubagentStart, UserPromptSubmit, Stop"
            );
            println!("  - MCP Server: clx (clx_recall, clx_remember, etc.)");
            println!(
                "  - Skills: clx-recall, clx-remember, clx-checkpoint, clx-rules, clx-resume, clx-doctor"
            );
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
            println!();
            println!(
                "  macOS keychain trust is auto-handled when CLX stores a credential; \
                 run 'clx keychain-trust' once to repair items from older CLX versions."
            );
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

/// D8 Codex cleanup: remove `~/.codex/hooks.json` (CLX-managed),
/// `[mcp_servers.clx]` from `config.toml`, and the CLX section from both
/// `AGENTS.md` and `AGENTS.override.md`. All steps are best-effort.
fn uninstall_codex_host(cli: &Cli, home: &std::path::Path, removed_items: &mut Vec<String>) {
    if !cli.json {
        println!();
        println!("{}", "Codex Configuration".cyan().bold());
        println!("{}", "-".repeat(30));
    }
    let mut any = false;
    if codex::remove_codex_hooks(home).unwrap_or(false) {
        any = true;
        removed_items.push("codex hooks.json".to_string());
    }
    if codex::remove_codex_mcp(home).unwrap_or(false) {
        any = true;
        removed_items.push("codex config.toml [mcp_servers.clx]".to_string());
    }
    for path in [
        codex::agents_md_path(home),
        codex::agents_override_md_path(home),
    ] {
        if remove_clx_section_from_file(&path, codex::CLX_SECTION_MARKER).unwrap_or(false) {
            any = true;
            removed_items.push(format!("codex CLX section: {}", path.display()));
        }
    }
    if !any && !cli.json {
        println!("  {} No CLX Codex configuration found", "*".dimmed());
    } else if any && !cli.json {
        println!("  {} Removed CLX Codex artifacts", "-".red());
    }
}

/// D8 Cursor cleanup: remove `mcpServers.clx` from `~/.cursor/mcp.json`, the
/// CLX-managed `~/.cursor/hooks.json`, and the repo-local
/// `.cursor/rules/clx.mdc`. Best-effort.
fn uninstall_cursor_host(cli: &Cli, home: &std::path::Path, removed_items: &mut Vec<String>) {
    if !cli.json {
        println!();
        println!("{}", "Cursor Configuration".cyan().bold());
        println!("{}", "-".repeat(30));
    }
    let mut any = false;
    if cursor::remove_cursor_mcp(home).unwrap_or(false) {
        any = true;
        removed_items.push("cursor mcp.json".to_string());
    }
    if cursor::remove_cursor_hooks(home).unwrap_or(false) {
        any = true;
        removed_items.push("cursor hooks.json".to_string());
    }
    if let Ok(repo) = env::current_dir()
        && cursor::remove_cursor_rule(&repo).unwrap_or(false)
    {
        any = true;
        removed_items.push("cursor .cursor/rules/clx.mdc".to_string());
    }
    if !any && !cli.json {
        println!("  {} No CLX Cursor configuration found", "*".dimmed());
    } else if any && !cli.json {
        println!("  {} Removed CLX Cursor artifacts", "-".red());
    }
}

/// Uninstall CLX integration
pub async fn cmd_uninstall(cli: &Cli, purge: bool, target: InstallTarget) -> Result<()> {
    let home = dirs::home_dir().context("Could not determine home directory")?;
    let clx_dir = clx_core::paths::clx_dir();
    let claude_dir = home.join(".claude");
    let settings_path = claude_dir.join("settings.json");

    let mut removed_items: Vec<String> = Vec::new();

    // Uninstall removes whatever a host might have; `auto`/`all` clean every
    // host so a switch of install target never strands artifacts. The
    // single-host variants scope the cleanup.
    let do_claude = target.wants_claude();
    let do_codex = matches!(
        target,
        InstallTarget::Codex | InstallTarget::All | InstallTarget::Auto
    );
    let do_cursor = matches!(
        target,
        InstallTarget::Cursor | InstallTarget::All | InstallTarget::Auto
    );

    if !cli.json {
        println!("{}", "CLX Uninstallation".cyan().bold());
        println!("{}", "=".repeat(50));
        println!();
    }

    // Step 1: Remove hooks and MCP server from settings.json
    if do_claude && settings_path.exists() {
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
    } else if do_claude && !cli.json {
        println!(
            "  {} settings.json not found, nothing to remove",
            "*".dimmed()
        );
    }

    // Step 1b: Remove CLX-installed skills (symmetric with install GAP-2).
    // Never touches user-authored files: only our SKILL.md / empty dirs.
    if do_claude {
        let removed_skills = uninstall_skills(&claude_dir);
        if removed_skills.is_empty() {
            if !cli.json {
                println!("  {} No CLX skills found to remove", "*".dimmed());
            }
        } else {
            if !cli.json {
                println!(
                    "  {} Removed {} CLX skills",
                    "-".red(),
                    removed_skills.len()
                );
            }
            removed_items.push(format!("skills: {}", removed_skills.join(", ")));
        }

        // D8: strip the CLX section from ~/.claude/CLAUDE.md (marker-to-next-H1).
        let claude_md = claude_dir.join("CLAUDE.md");
        match remove_clx_section_from_file(&claude_md, CLX_SECTION_MARKER) {
            Ok(true) => {
                if !cli.json {
                    println!(
                        "  {} Removed CLX section from {}",
                        "-".red(),
                        claude_md.display()
                    );
                }
                removed_items.push("CLAUDE.md CLX section".to_string());
            }
            Ok(false) => {}
            Err(e) => {
                if !cli.json {
                    println!("  {} Could not update CLAUDE.md: {}", "!".yellow(), e);
                }
            }
        }
    }

    // Step 1c-codex: D8 Codex cleanup (~/.codex hooks.json, config.toml MCP,
    // AGENTS.md + AGENTS.override.md CLX section).
    if do_codex {
        uninstall_codex_host(cli, &home, &mut removed_items);
    }

    // Step 1c-cursor: D8 Cursor cleanup (~/.cursor mcp.json + hooks.json, and
    // the repo-local .cursor/rules/clx.mdc).
    if do_cursor {
        uninstall_cursor_host(cli, &home, &mut removed_items);
    }

    // Step 1c: Remove the version stamp (symmetric with install GAP-3).
    let stamp_path = clx_core::paths::bin_dir().join(VERSION_STAMP_FILE);
    if stamp_path.exists() && fs::remove_file(&stamp_path).is_ok() {
        if !cli.json {
            println!("  {} Removed version stamp", "-".red());
        }
        removed_items.push("version stamp".to_string());
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

#[cfg(test)]
mod tests {
    use super::*;

    // GAP-1: get_hooks_config must register all 8 events including "Stop".
    #[test]
    fn hooks_config_includes_all_eight_events_with_stop() {
        let cfg = get_hooks_config();
        let obj = cfg.as_object().expect("hooks config is an object");
        let expected = [
            "PreToolUse",
            "PostToolUse",
            "PreCompact",
            "SessionStart",
            "SessionEnd",
            "SubagentStart",
            "UserPromptSubmit",
            "Stop",
        ];
        for ev in expected {
            assert!(obj.contains_key(ev), "missing hook event: {ev}");
        }
        assert_eq!(obj.len(), expected.len(), "unexpected extra hook events");
    }

    #[test]
    fn stop_hook_uses_clx_hook_command() {
        let cfg = get_hooks_config();
        let cmd = cfg["Stop"][0]["hooks"][0]["command"]
            .as_str()
            .expect("Stop command is a string");
        assert_eq!(cmd, "~/.clx/bin/clx-hook stop");
        // Stop is a session-level event: no tool matcher, mirroring PreCompact.
        assert!(cfg["Stop"][0].get("matcher").is_none());
    }

    // GAP-2: skill destination resolver and 6 embedded skills.
    #[test]
    fn skill_dir_resolves_personal_skills_path() {
        let claude = std::path::Path::new("/home/u/.claude");
        let p = skill_dir(claude, "clx-recall");
        assert_eq!(p, std::path::Path::new("/home/u/.claude/skills/clx-recall"));
    }

    #[test]
    fn six_skills_embedded_with_nonempty_content() {
        assert_eq!(CLX_SKILLS.len(), 6);
        let names: Vec<&str> = CLX_SKILLS.iter().map(|(n, _)| *n).collect();
        for expected in [
            "clx-recall",
            "clx-remember",
            "clx-checkpoint",
            "clx-rules",
            "clx-resume",
            "clx-doctor",
        ] {
            assert!(names.contains(&expected), "missing skill: {expected}");
        }
        for (name, content) in CLX_SKILLS {
            assert!(!content.trim().is_empty(), "{name} SKILL.md is empty");
        }
    }

    #[test]
    fn install_then_uninstall_skills_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let claude = tmp.path();

        let installed = install_skills(claude).unwrap();
        assert_eq!(installed.len(), 6);
        for (name, _) in CLX_SKILLS {
            assert!(skill_dir(claude, name).join("SKILL.md").exists());
        }

        // Idempotent: re-running install does not error or duplicate.
        let again = install_skills(claude).unwrap();
        assert_eq!(again.len(), 6);

        let removed = uninstall_skills(claude);
        assert_eq!(removed.len(), 6);
        for (name, _) in CLX_SKILLS {
            assert!(!skill_dir(claude, name).exists());
        }

        // Uninstall when nothing is installed is a clean no-op.
        assert!(uninstall_skills(claude).is_empty());
    }

    #[test]
    fn uninstall_skills_preserves_user_authored_files() {
        let tmp = tempfile::tempdir().unwrap();
        let claude = tmp.path();
        install_skills(claude).unwrap();

        // User drops an extra file into a CLX skill dir.
        let recall = skill_dir(claude, "clx-recall");
        let user_file = recall.join("user-notes.md");
        fs::write(&user_file, "my notes").unwrap();

        uninstall_skills(claude);
        // The user's file survives; only our SKILL.md was removed.
        assert!(user_file.exists());
        assert!(!recall.join("SKILL.md").exists());
    }

    // GAP-3: version-stamp comparison and file I/O.
    #[test]
    fn version_stamp_status_detects_states() {
        assert_eq!(
            version_stamp_status(None, "0.8.0"),
            VersionStampStatus::Absent
        );
        assert_eq!(
            version_stamp_status(Some("0.8.0\n"), "0.8.0"),
            VersionStampStatus::Match
        );
        match version_stamp_status(Some("0.7.2"), "0.8.0") {
            VersionStampStatus::Mismatch { stamped, running } => {
                assert_eq!(stamped, "0.7.2");
                assert_eq!(running, "0.8.0");
            }
            other => panic!("expected mismatch, got {other:?}"),
        }
    }

    #[test]
    fn version_stamp_write_then_read_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(read_version_stamp(tmp.path()).is_none());
        write_version_stamp(tmp.path()).unwrap();
        let stamp = read_version_stamp(tmp.path()).expect("stamp present");
        assert_eq!(
            version_stamp_status(Some(&stamp), CLX_VERSION),
            VersionStampStatus::Match
        );
    }

    // GAP-5: additive config-key merge must never clobber user values.
    #[test]
    fn merge_adds_only_missing_keys_and_preserves_user_values() {
        let existing = "alpha: user_value\n";
        let defaults = "alpha: default_value\nbeta: 42\n";
        let (merged, added) = merge_missing_config_keys(existing, defaults).unwrap();
        assert_eq!(added, vec!["beta".to_string()]);
        let v: serde_yml::Value = serde_yml::from_str(&merged).unwrap();
        assert_eq!(v["alpha"].as_str(), Some("user_value"));
        assert_eq!(v["beta"].as_i64(), Some(42));
    }

    #[test]
    fn merge_is_noop_when_nothing_missing() {
        let existing = "alpha: x\nbeta: y\n";
        let defaults = "alpha: 1\nbeta: 2\n";
        let (merged, added) = merge_missing_config_keys(existing, defaults).unwrap();
        assert!(added.is_empty());
        assert_eq!(merged, existing);
    }

    #[test]
    fn merge_handles_empty_existing_config_as_noop() {
        // serde_yml parses "" as Null (not a mapping) -> leave untouched.
        let (merged, added) = merge_missing_config_keys("", "alpha: 1\n").unwrap();
        assert!(added.is_empty());
        assert_eq!(merged, "");
    }

    // D8: strip_marker_section drops the marker H1 through the next H1.
    #[test]
    fn strip_section_removes_marker_block_keeps_surrounding() {
        let content = "# User Rules\n\nkeep me\n\n# CLX Integration\n\nclx body\nmore clx\n\n# After\n\ntail\n";
        let out = strip_marker_section(content, CLX_SECTION_MARKER);
        assert!(out.contains("# User Rules"));
        assert!(out.contains("keep me"));
        assert!(out.contains("# After"));
        assert!(out.contains("tail"));
        assert!(!out.contains("# CLX Integration"));
        assert!(!out.contains("clx body"));
    }

    #[test]
    fn strip_section_at_eof_removes_to_end() {
        let content = "# Head\n\nbody\n\n# CLX Integration\n\nclx tail\n";
        let out = strip_marker_section(content, CLX_SECTION_MARKER);
        assert!(out.contains("# Head"));
        assert!(out.contains("body"));
        assert!(!out.contains("CLX Integration"));
        assert!(!out.contains("clx tail"));
    }

    #[test]
    fn strip_section_noop_without_marker() {
        let content = "# Only\n\nno clx here\n";
        let out = strip_marker_section(content, CLX_SECTION_MARKER);
        assert_eq!(out, content);
    }

    #[test]
    fn strip_section_ignores_inline_mention() {
        // A line that merely mentions the marker text inline is not an H1.
        let content = "# Head\n\nsee # CLX Integration notes\n";
        let out = strip_marker_section(content, CLX_SECTION_MARKER);
        assert_eq!(out, content);
    }

    #[test]
    fn remove_section_from_file_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("CLAUDE.md");
        fs::write(&path, "# A\n\nkeep\n\n# CLX Integration\n\nclx\n").unwrap();
        assert!(remove_clx_section_from_file(&path, CLX_SECTION_MARKER).unwrap());
        let out = fs::read_to_string(&path).unwrap();
        assert!(out.contains("# A"));
        assert!(!out.contains("CLX Integration"));
        // Idempotent: second call is a no-op.
        assert!(!remove_clx_section_from_file(&path, CLX_SECTION_MARKER).unwrap());
    }

    #[test]
    fn remove_section_missing_file_is_noop() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("absent.md");
        assert!(!remove_clx_section_from_file(&path, CLX_SECTION_MARKER).unwrap());
    }

    // Target gating truth table.
    #[test]
    fn target_gating_matrix() {
        assert!(InstallTarget::Claude.wants_claude());
        assert!(InstallTarget::Auto.wants_claude());
        assert!(InstallTarget::All.wants_claude());
        assert!(!InstallTarget::Codex.wants_claude());
        assert!(!InstallTarget::Cursor.wants_claude());

        // Codex: explicit/all always; auto only when detected.
        assert!(InstallTarget::Codex.wants_codex(false));
        assert!(InstallTarget::All.wants_codex(false));
        assert!(InstallTarget::Auto.wants_codex(true));
        assert!(!InstallTarget::Auto.wants_codex(false));
        assert!(!InstallTarget::Claude.wants_codex(true));

        // Cursor: same shape.
        assert!(InstallTarget::Cursor.wants_cursor(false));
        assert!(InstallTarget::All.wants_cursor(false));
        assert!(InstallTarget::Auto.wants_cursor(true));
        assert!(!InstallTarget::Auto.wants_cursor(false));
    }
}
