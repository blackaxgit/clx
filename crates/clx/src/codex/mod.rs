//! Codex CLI install/uninstall artifact writers (P3).
//!
//! This module is the install-time counterpart to `clx-hook`'s `CodexHost`.
//! It is intentionally standalone (the `CodexHost` capability methods are
//! `pub(crate)` to `clx-hook`), and writes the three Codex integration
//! artifacts resolved by P0:
//!
//! - `~/.codex/hooks.json` - per-event `clx-hook` command entries (P0 F3).
//! - `~/.codex/config.toml` `[mcp_servers.clx]` - stdio MCP registration.
//! - `~/.codex/AGENTS.md` - the CLX instructions section (32 KiB cap, with
//!   an `AGENTS.override.md` fallback at 30 KiB; P0 F2 caveat documented in
//!   the section body).
//!
//! Detection (`detect_codex`) shells out to `codex --version`; install never
//! requires Codex to be present (the writers only touch `~/.codex`), but
//! `--target codex`/`auto` use detection to decide whether to write.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result};

/// Marker that identifies the CLX section in `AGENTS.md` (shared with the D8
/// uninstall stripper; matches the H1 heading text minus the leading `# `).
pub const CLX_SECTION_MARKER: &str = "# CLX Integration";

/// Hard cap on `AGENTS.md` size Codex will read before truncating (P0/plan
/// §3). If injecting the CLX section would push the file past this, CLX falls
/// back to writing `AGENTS.override.md`.
pub const AGENTS_MD_CAP_BYTES: usize = 32 * 1024;

/// Conservative fallback threshold (plan §3): if the post-injection size would
/// exceed this, write the override file instead of risking truncation.
pub const AGENTS_MD_FALLBACK_BYTES: usize = 30 * 1024;

/// The CLX instructions section injected into `~/.codex/AGENTS.md`.
///
/// The F2 caveat ("command gating applies to interactive Codex, not
/// `codex exec`") is stated verbatim so users reading AGENTS.md understand the
/// scope of CLX's Codex command-validation.
pub const CLX_AGENTS_MD_SECTION: &str = r#"
# CLX Integration

CLX (Coding-Agent Extension Layer) provides MCP tools for context persistence
and command validation across Codex sessions.

## Available CLX Tools

| Tool | Purpose |
|------|---------|
| `clx_recall` | Search past sessions for prior work, decisions, context |
| `clx_remember` | Save important decisions, preferences, or context |
| `clx_rules` | Refresh project rules (AGENTS.md) |
| `clx_checkpoint` | Create a manual snapshot before risky changes |

## Caveat: command gating scope

CLX command gating applies to interactive Codex, not `codex exec`. Codex hooks
fire in interactive `codex` sessions; they do not fire in `codex exec`
(headless/automation) mode in current Codex builds. MCP tools and these
AGENTS.md instructions are unaffected and work in both modes. Codex does not
support an interactive "ask" decision, so a CLX `ask` verdict is mapped to a
fail-closed deny - re-run the command if it was intended.
"#;

/// Result of probing the local Codex CLI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodexInfo {
    /// Whether a `codex` binary was found and answered `--version`.
    pub installed: bool,
    /// The reported version string, if any (`codex --version` stdout).
    pub version: Option<String>,
}

/// The `~/.codex` config directory under the given home.
#[must_use]
pub fn codex_dir(home: &Path) -> PathBuf {
    home.join(".codex")
}

/// `~/.codex/hooks.json`.
#[must_use]
pub fn hooks_json_path(home: &Path) -> PathBuf {
    codex_dir(home).join("hooks.json")
}

/// `~/.codex/config.toml`.
#[must_use]
pub fn config_toml_path(home: &Path) -> PathBuf {
    codex_dir(home).join("config.toml")
}

/// `~/.codex/AGENTS.md`.
#[must_use]
pub fn agents_md_path(home: &Path) -> PathBuf {
    codex_dir(home).join("AGENTS.md")
}

/// `~/.codex/AGENTS.override.md` (the oversize fallback).
#[must_use]
pub fn agents_override_md_path(home: &Path) -> PathBuf {
    codex_dir(home).join("AGENTS.override.md")
}

/// Detect a local Codex CLI by running `codex --version`.
///
/// Never fails: a missing binary yields `installed: false`. The version string
/// is the trimmed first line of stdout (Codex prints e.g. `codex-cli 0.135.0`).
#[must_use]
pub fn detect_codex() -> CodexInfo {
    match Command::new("codex").arg("--version").output() {
        Ok(out) if out.status.success() => {
            let version = String::from_utf8_lossy(&out.stdout)
                .lines()
                .next()
                .map(|l| l.trim().to_string())
                .filter(|s| !s.is_empty());
            CodexInfo {
                installed: true,
                version,
            }
        }
        _ => CodexInfo {
            installed: false,
            version: None,
        },
    }
}

/// The CLX hooks.json content for Codex (P0 F3 shape).
///
/// Registers a `clx-hook` command per supported event. `PreToolUse` /
/// `PostToolUse` carry the `Bash` matcher (the command-gating surface);
/// lifecycle events carry none. `timeout` and `statusMessage` match the
/// documented Codex hook object fields.
#[must_use]
pub fn codex_hooks_value() -> serde_json::Value {
    let bash_entry = |sub: &str| {
        serde_json::json!({
            "matcher": "Bash",
            "hooks": [{
                "type": "command",
                "command": format!("~/.clx/bin/clx-hook {sub}"),
                "timeout": 30,
                "statusMessage": "CLX validating command"
            }]
        })
    };
    let lifecycle_entry = |sub: &str| {
        serde_json::json!({
            "hooks": [{
                "type": "command",
                "command": format!("~/.clx/bin/clx-hook {sub}"),
                "timeout": 30
            }]
        })
    };
    serde_json::json!({
        "hooks": {
            "PreToolUse": [bash_entry("pre-tool-use")],
            "PostToolUse": [bash_entry("post-tool-use")],
            "PermissionRequest": [lifecycle_entry("permission-request")],
            "SessionStart": [lifecycle_entry("session-start")],
            "SessionEnd": [lifecycle_entry("session-end")],
            "UserPromptSubmit": [lifecycle_entry("user-prompt-submit")],
            "Stop": [lifecycle_entry("stop")],
            "PreCompact": [lifecycle_entry("pre-compact")]
        }
    })
}

/// Write `~/.codex/hooks.json` (idempotent: overwrites CLX-managed file).
///
/// Returns `true` if the file was created or its contents changed.
pub fn write_codex_hooks(home: &Path) -> Result<bool> {
    let path = hooks_json_path(home);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).context("create ~/.codex")?;
    }
    let desired =
        serde_json::to_string_pretty(&codex_hooks_value()).context("serialize Codex hooks.json")?;
    let changed = match fs::read_to_string(&path) {
        Ok(existing) => existing != desired,
        Err(_) => true,
    };
    if changed {
        fs::write(&path, &desired).context("write ~/.codex/hooks.json")?;
    }
    Ok(changed)
}

/// Merge the `[mcp_servers.clx]` block into `~/.codex/config.toml`, preserving
/// all other keys. Returns `true` if the file was created or changed.
///
/// Shape (plan §3): `command = "~/.clx/bin/clx-mcp"`, plus an `env` table
/// carrying `CLX_INSTRUCTIONS_FILE` (the AGENTS.md path) and a `CLX_SESSION_ID`
/// placeholder (Codex provides the session id in the hook envelope, but the
/// MCP server reads it from the environment when present).
pub fn write_codex_mcp(home: &Path) -> Result<bool> {
    let path = config_toml_path(home);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).context("create ~/.codex")?;
    }

    let existing = fs::read_to_string(&path).unwrap_or_default();
    let mut doc: toml::Value = if existing.trim().is_empty() {
        toml::Value::Table(toml::map::Map::new())
    } else {
        toml::from_str(&existing).context("parse existing ~/.codex/config.toml")?
    };

    let agents_md = agents_md_path(home);
    let mut clx_table = toml::map::Map::new();
    clx_table.insert(
        "command".to_string(),
        toml::Value::String("~/.clx/bin/clx-mcp".to_string()),
    );
    clx_table.insert("args".to_string(), toml::Value::Array(Vec::new()));
    let mut env_table = toml::map::Map::new();
    env_table.insert(
        "CLX_INSTRUCTIONS_FILE".to_string(),
        toml::Value::String(agents_md.display().to_string()),
    );
    env_table.insert(
        "CLX_SESSION_ID".to_string(),
        toml::Value::String(String::new()),
    );
    clx_table.insert("env".to_string(), toml::Value::Table(env_table));

    let table = doc
        .as_table_mut()
        .context("~/.codex/config.toml top level is not a table")?;
    let mcp_servers = table
        .entry("mcp_servers".to_string())
        .or_insert_with(|| toml::Value::Table(toml::map::Map::new()));
    let mcp_table = mcp_servers
        .as_table_mut()
        .context("[mcp_servers] is not a table")?;
    mcp_table.insert("clx".to_string(), toml::Value::Table(clx_table));

    let desired = toml::to_string_pretty(&doc).context("serialize ~/.codex/config.toml")?;
    let changed = existing != desired;
    if changed {
        fs::write(&path, &desired).context("write ~/.codex/config.toml")?;
    }
    Ok(changed)
}

/// Outcome of the AGENTS.md injection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentsInjectOutcome {
    /// CLX section newly written into `AGENTS.md`.
    Injected,
    /// Section already present; nothing changed.
    AlreadyPresent,
    /// File would exceed the cap, so the section was written to
    /// `AGENTS.override.md` instead.
    OverrideFallback,
}

/// Inject the CLX section into `~/.codex/AGENTS.md`, falling back to
/// `AGENTS.override.md` when the combined size would risk Codex's 32 KiB cap.
///
/// Idempotent: if either file already contains the CLX marker, returns
/// `AlreadyPresent` without writing.
pub fn inject_codex_agents_md(home: &Path) -> Result<AgentsInjectOutcome> {
    let main_path = agents_md_path(home);
    let override_path = agents_override_md_path(home);
    if let Some(parent) = main_path.parent() {
        fs::create_dir_all(parent).context("create ~/.codex")?;
    }

    let main_content = fs::read_to_string(&main_path).unwrap_or_default();
    let override_content = fs::read_to_string(&override_path).unwrap_or_default();

    // Idempotency: marker present in either file means already installed.
    if main_content.contains(CLX_SECTION_MARKER) || override_content.contains(CLX_SECTION_MARKER) {
        return Ok(AgentsInjectOutcome::AlreadyPresent);
    }

    let section = CLX_AGENTS_MD_SECTION;
    let combined = if main_content.is_empty() {
        section.trim_start().to_string()
    } else {
        format!("{}\n{}", main_content.trim_end(), section)
    };

    // Fall back to the override file once the combined size crosses the
    // conservative threshold; never let it approach the hard 32 KiB cap that
    // Codex truncates at. The effective trigger is the smaller of the two.
    let fallback_at = AGENTS_MD_FALLBACK_BYTES.min(AGENTS_MD_CAP_BYTES);
    if combined.len() > fallback_at {
        // Oversize: write the section into the override file instead.
        let override_new = if override_content.is_empty() {
            section.trim_start().to_string()
        } else {
            format!("{}\n{}", override_content.trim_end(), section)
        };
        fs::write(&override_path, override_new).context("write ~/.codex/AGENTS.override.md")?;
        return Ok(AgentsInjectOutcome::OverrideFallback);
    }

    fs::write(&main_path, combined).context("write ~/.codex/AGENTS.md")?;
    Ok(AgentsInjectOutcome::Injected)
}

/// Remove the CLX `[mcp_servers.clx]` block from `~/.codex/config.toml`.
/// Returns `true` if anything was removed. Leaves all other keys untouched and
/// drops an emptied `[mcp_servers]` table.
pub fn remove_codex_mcp(home: &Path) -> Result<bool> {
    let path = config_toml_path(home);
    let Ok(existing) = fs::read_to_string(&path) else {
        return Ok(false);
    };
    if existing.trim().is_empty() {
        return Ok(false);
    }
    let mut doc: toml::Value =
        toml::from_str(&existing).context("parse ~/.codex/config.toml for uninstall")?;
    let Some(table) = doc.as_table_mut() else {
        return Ok(false);
    };
    let mut removed = false;
    if let Some(mcp_servers) = table.get_mut("mcp_servers")
        && let Some(mcp_table) = mcp_servers.as_table_mut()
    {
        if mcp_table.remove("clx").is_some() {
            removed = true;
        }
        if mcp_table.is_empty() {
            table.remove("mcp_servers");
        }
    }
    if removed {
        let serialized =
            toml::to_string_pretty(&doc).context("re-serialize ~/.codex/config.toml")?;
        fs::write(&path, serialized).context("write ~/.codex/config.toml")?;
    }
    Ok(removed)
}

/// Remove `~/.codex/hooks.json` if it is a CLX-managed file. Returns `true` if
/// removed. Conservatively only deletes when the file references `clx-hook`.
pub fn remove_codex_hooks(home: &Path) -> Result<bool> {
    let path = hooks_json_path(home);
    let Ok(content) = fs::read_to_string(&path) else {
        return Ok(false);
    };
    if content.contains("clx-hook") {
        fs::remove_file(&path).context("remove ~/.codex/hooks.json")?;
        return Ok(true);
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_resolve_under_codex_dir() {
        let home = Path::new("/home/u");
        assert_eq!(
            hooks_json_path(home),
            Path::new("/home/u/.codex/hooks.json")
        );
        assert_eq!(
            config_toml_path(home),
            Path::new("/home/u/.codex/config.toml")
        );
        assert_eq!(agents_md_path(home), Path::new("/home/u/.codex/AGENTS.md"));
        assert_eq!(
            agents_override_md_path(home),
            Path::new("/home/u/.codex/AGENTS.override.md")
        );
    }

    #[test]
    fn hooks_value_has_pre_tool_use_with_bash_matcher() {
        let v = codex_hooks_value();
        let hooks = v["hooks"].as_object().expect("hooks object");
        assert!(hooks.contains_key("PreToolUse"));
        assert_eq!(v["hooks"]["PreToolUse"][0]["matcher"], "Bash");
        assert_eq!(
            v["hooks"]["PreToolUse"][0]["hooks"][0]["command"],
            "~/.clx/bin/clx-hook pre-tool-use"
        );
        // Lifecycle event carries no matcher.
        assert!(v["hooks"]["SessionStart"][0].get("matcher").is_none());
    }

    #[test]
    fn write_hooks_is_idempotent() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        assert!(write_codex_hooks(home).unwrap());
        assert!(hooks_json_path(home).exists());
        // Second run: no change.
        assert!(!write_codex_hooks(home).unwrap());
    }

    #[test]
    fn write_mcp_creates_and_preserves_other_keys() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        // Seed an unrelated key.
        fs::create_dir_all(codex_dir(home)).unwrap();
        fs::write(config_toml_path(home), "model = \"gpt-5.4\"\n").unwrap();

        assert!(write_codex_mcp(home).unwrap());
        let doc: toml::Value =
            toml::from_str(&fs::read_to_string(config_toml_path(home)).unwrap()).unwrap();
        // Unrelated key preserved.
        assert_eq!(doc["model"].as_str(), Some("gpt-5.4"));
        // CLX block present.
        assert_eq!(
            doc["mcp_servers"]["clx"]["command"].as_str(),
            Some("~/.clx/bin/clx-mcp")
        );
        assert!(
            doc["mcp_servers"]["clx"]["env"]["CLX_INSTRUCTIONS_FILE"]
                .as_str()
                .unwrap()
                .ends_with("AGENTS.md")
        );

        // Idempotent.
        assert!(!write_codex_mcp(home).unwrap());
    }

    #[test]
    fn inject_agents_md_then_idempotent() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        assert_eq!(
            inject_codex_agents_md(home).unwrap(),
            AgentsInjectOutcome::Injected
        );
        let content = fs::read_to_string(agents_md_path(home)).unwrap();
        assert!(content.contains(CLX_SECTION_MARKER));
        assert!(content.contains("codex exec"));
        // Idempotent second run.
        assert_eq!(
            inject_codex_agents_md(home).unwrap(),
            AgentsInjectOutcome::AlreadyPresent
        );
    }

    #[test]
    fn inject_agents_md_falls_back_to_override_when_oversize() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        fs::create_dir_all(codex_dir(home)).unwrap();
        // Seed a near-cap AGENTS.md.
        let filler = "x".repeat(AGENTS_MD_FALLBACK_BYTES + 100);
        fs::write(agents_md_path(home), &filler).unwrap();

        assert_eq!(
            inject_codex_agents_md(home).unwrap(),
            AgentsInjectOutcome::OverrideFallback
        );
        // Main file untouched (still no marker), override carries the section.
        assert!(
            !fs::read_to_string(agents_md_path(home))
                .unwrap()
                .contains(CLX_SECTION_MARKER)
        );
        assert!(
            fs::read_to_string(agents_override_md_path(home))
                .unwrap()
                .contains(CLX_SECTION_MARKER)
        );
    }

    #[test]
    fn remove_mcp_removes_clx_and_preserves_rest() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        fs::create_dir_all(codex_dir(home)).unwrap();
        fs::write(config_toml_path(home), "model = \"gpt\"\n").unwrap();
        write_codex_mcp(home).unwrap();

        assert!(remove_codex_mcp(home).unwrap());
        let doc: toml::Value =
            toml::from_str(&fs::read_to_string(config_toml_path(home)).unwrap()).unwrap();
        assert!(doc.get("mcp_servers").is_none());
        assert_eq!(doc["model"].as_str(), Some("gpt"));
        // Removing again is a clean no-op.
        assert!(!remove_codex_mcp(home).unwrap());
    }

    #[test]
    fn remove_hooks_only_deletes_clx_managed() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        write_codex_hooks(home).unwrap();
        assert!(remove_codex_hooks(home).unwrap());
        assert!(!hooks_json_path(home).exists());

        // A non-CLX hooks.json is preserved.
        fs::create_dir_all(codex_dir(home)).unwrap();
        fs::write(hooks_json_path(home), "{\"hooks\":{}}").unwrap();
        assert!(!remove_codex_hooks(home).unwrap());
        assert!(hooks_json_path(home).exists());
    }

    #[test]
    fn detect_codex_never_panics() {
        // Whatever the local environment, detection returns a value.
        let _ = detect_codex();
    }
}
