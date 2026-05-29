//! Cursor IDE install/uninstall artifact writers (P3).
//!
//! Standalone install-time counterpart to `clx-hook`'s `CursorHost`. Writes
//! the three Cursor integration artifacts (research doc + plan §3):
//!
//! - `~/.cursor/mcp.json` `mcpServers.clx` - stdio MCP registration
//!   (~identical to Claude's shape).
//! - `~/.cursor/hooks.json` - `version: 1` with `beforeShellExecution` and
//!   `beforeMCPExecution` gates, each `failClosed: true` (closes Cursor's
//!   fail-open default), plus the observe-only lifecycle events.
//! - `<repo>/.cursor/rules/clx.mdc` - project-scoped instructions with
//!   frontmatter `alwaysApply: true` (Cursor has no global instructions file).
//!
//! Command gating in Cursor is GUI-only (the `cursor-agent` CLI runs no
//! hooks); that scope limitation is documented for the user, not enforced
//! here.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result};

/// The CLX rule body written to `<repo>/.cursor/rules/clx.mdc`. The frontmatter
/// `alwaysApply: true` makes Cursor include it in every chat session.
pub const CLX_MDC: &str = r"---
description: CLX context-persistence and command-validation rules
alwaysApply: true
---
# CLX Integration

CLX (Coding-Agent Extension Layer) provides MCP tools for context persistence
and command validation across Cursor sessions.

## Available CLX Tools

- `clx_recall` - search past sessions for prior work, decisions, context
- `clx_remember` - save important decisions, preferences, or context
- `clx_rules` - refresh project rules
- `clx_checkpoint` - create a manual snapshot before risky changes

## Caveat: command gating is GUI-only

CLX command validation in Cursor runs through the IDE Agent hooks
(`beforeShellExecution`) with fail-closed enabled. The `cursor-agent` CLI does
not run hooks today, so terminal command gating is unavailable there. MCP tools
and these rules apply in both the GUI and the CLI.
";

/// Result of probing the local Cursor CLI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CursorInfo {
    /// Whether a `cursor-agent` (or `cursor`) binary answered `--version`.
    pub installed: bool,
    /// The reported version string, if any.
    pub version: Option<String>,
}

/// The `~/.cursor` config directory under the given home.
#[must_use]
pub fn cursor_dir(home: &Path) -> PathBuf {
    home.join(".cursor")
}

/// `~/.cursor/mcp.json`.
#[must_use]
pub fn mcp_json_path(home: &Path) -> PathBuf {
    cursor_dir(home).join("mcp.json")
}

/// `~/.cursor/hooks.json`.
#[must_use]
pub fn hooks_json_path(home: &Path) -> PathBuf {
    cursor_dir(home).join("hooks.json")
}

/// `<repo>/.cursor/rules/clx.mdc` (project-scoped instructions).
#[must_use]
pub fn rule_mdc_path(repo: &Path) -> PathBuf {
    repo.join(".cursor").join("rules").join("clx.mdc")
}

/// Detect a local Cursor by probing `cursor-agent --version`, then `cursor`.
/// Never fails: absence yields `installed: false`.
#[must_use]
pub fn detect_cursor() -> CursorInfo {
    for bin in ["cursor-agent", "cursor"] {
        if let Ok(out) = Command::new(bin).arg("--version").output()
            && out.status.success()
        {
            let version = String::from_utf8_lossy(&out.stdout)
                .lines()
                .next()
                .map(|l| l.trim().to_string())
                .filter(|s| !s.is_empty());
            return CursorInfo {
                installed: true,
                version,
            };
        }
    }
    CursorInfo {
        installed: false,
        version: None,
    }
}

/// The CLX `mcpServers.clx` block for Cursor (research §3.3). Shape mirrors
/// Claude's stdio MCP registration.
#[must_use]
pub fn cursor_mcp_entry() -> serde_json::Value {
    serde_json::json!({
        "command": "~/.clx/bin/clx-mcp",
        "args": [],
        "env": { "CLX_SESSION_ID": "" }
    })
}

/// The CLX hooks.json content for Cursor (research §2.4, §2.6).
///
/// `version: 1`; `beforeShellExecution` and `beforeMCPExecution` are the
/// command/MCP gates with `failClosed: true` (closes Cursor's fail-open
/// default, F7); lifecycle events are observe-only and carry no `failClosed`.
#[must_use]
pub fn cursor_hooks_value() -> serde_json::Value {
    let gate = |sub: &str| {
        serde_json::json!({
            "command": format!("~/.clx/bin/clx-hook {sub}"),
            "type": "command",
            "timeout": 30,
            "failClosed": true
        })
    };
    let observe = |sub: &str| {
        serde_json::json!({
            "command": format!("~/.clx/bin/clx-hook {sub}"),
            "type": "command",
            "timeout": 30
        })
    };
    serde_json::json!({
        "version": 1,
        "hooks": {
            "beforeShellExecution": [gate("pre-tool-use")],
            "beforeMCPExecution": [gate("pre-tool-use")],
            "afterShellExecution": [observe("post-tool-use")],
            "sessionStart": [observe("session-start")],
            "sessionEnd": [observe("session-end")],
            "stop": [observe("stop")]
        }
    })
}

/// Merge `mcpServers.clx` into `~/.cursor/mcp.json`, preserving other servers.
/// Returns `true` if created or changed.
pub fn write_cursor_mcp(home: &Path) -> Result<bool> {
    let path = mcp_json_path(home);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).context("create ~/.cursor")?;
    }
    let mut doc: serde_json::Value = match fs::read_to_string(&path) {
        Ok(s) if !s.trim().is_empty() => {
            serde_json::from_str(&s).context("parse existing ~/.cursor/mcp.json")?
        }
        _ => serde_json::json!({}),
    };
    if doc.get("mcpServers").is_none() {
        doc["mcpServers"] = serde_json::json!({});
    }
    let before = doc.clone();
    if let Some(servers) = doc.get_mut("mcpServers").and_then(|m| m.as_object_mut()) {
        servers.insert("clx".to_string(), cursor_mcp_entry());
    }
    let changed = doc != before || !path.exists();
    if changed {
        let pretty = serde_json::to_string_pretty(&doc).context("serialize ~/.cursor/mcp.json")?;
        fs::write(&path, pretty).context("write ~/.cursor/mcp.json")?;
    }
    Ok(changed)
}

/// Write `~/.cursor/hooks.json` (idempotent; overwrites CLX-managed file).
/// Returns `true` if created or changed.
pub fn write_cursor_hooks(home: &Path) -> Result<bool> {
    let path = hooks_json_path(home);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).context("create ~/.cursor")?;
    }
    let desired = serde_json::to_string_pretty(&cursor_hooks_value())
        .context("serialize Cursor hooks.json")?;
    let changed = match fs::read_to_string(&path) {
        Ok(existing) => existing != desired,
        Err(_) => true,
    };
    if changed {
        fs::write(&path, &desired).context("write ~/.cursor/hooks.json")?;
    }
    Ok(changed)
}

/// Write `<repo>/.cursor/rules/clx.mdc` (idempotent). Returns `true` if created
/// or changed.
pub fn write_cursor_rule(repo: &Path) -> Result<bool> {
    let path = rule_mdc_path(repo);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).context("create <repo>/.cursor/rules")?;
    }
    let changed = match fs::read_to_string(&path) {
        Ok(existing) => existing != CLX_MDC,
        Err(_) => true,
    };
    if changed {
        fs::write(&path, CLX_MDC).context("write <repo>/.cursor/rules/clx.mdc")?;
    }
    Ok(changed)
}

/// Remove `mcpServers.clx` from `~/.cursor/mcp.json`. Returns `true` if removed.
/// Drops an emptied `mcpServers` object.
pub fn remove_cursor_mcp(home: &Path) -> Result<bool> {
    let path = mcp_json_path(home);
    let Ok(content) = fs::read_to_string(&path) else {
        return Ok(false);
    };
    if content.trim().is_empty() {
        return Ok(false);
    }
    let mut doc: serde_json::Value =
        serde_json::from_str(&content).context("parse ~/.cursor/mcp.json for uninstall")?;
    let mut removed = false;
    if let Some(servers) = doc.get_mut("mcpServers").and_then(|m| m.as_object_mut()) {
        if servers.remove("clx").is_some() {
            removed = true;
        }
        if servers.is_empty()
            && let Some(obj) = doc.as_object_mut()
        {
            obj.remove("mcpServers");
        }
    }
    if removed {
        let pretty = serde_json::to_string_pretty(&doc).context("serialize ~/.cursor/mcp.json")?;
        fs::write(&path, pretty).context("write ~/.cursor/mcp.json")?;
    }
    Ok(removed)
}

/// Remove `~/.cursor/hooks.json` if CLX-managed (references `clx-hook`).
/// Returns `true` if removed.
pub fn remove_cursor_hooks(home: &Path) -> Result<bool> {
    let path = hooks_json_path(home);
    let Ok(content) = fs::read_to_string(&path) else {
        return Ok(false);
    };
    if content.contains("clx-hook") {
        fs::remove_file(&path).context("remove ~/.cursor/hooks.json")?;
        return Ok(true);
    }
    Ok(false)
}

/// Delete `<repo>/.cursor/rules/clx.mdc` (D8). Returns `true` if removed.
pub fn remove_cursor_rule(repo: &Path) -> Result<bool> {
    let path = rule_mdc_path(repo);
    if path.exists() {
        fs::remove_file(&path).context("remove <repo>/.cursor/rules/clx.mdc")?;
        return Ok(true);
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_resolve() {
        let home = Path::new("/home/u");
        assert_eq!(mcp_json_path(home), Path::new("/home/u/.cursor/mcp.json"));
        assert_eq!(
            hooks_json_path(home),
            Path::new("/home/u/.cursor/hooks.json")
        );
        let repo = Path::new("/repo");
        assert_eq!(
            rule_mdc_path(repo),
            Path::new("/repo/.cursor/rules/clx.mdc")
        );
    }

    #[test]
    fn hooks_value_has_failclosed_gates() {
        let v = cursor_hooks_value();
        assert_eq!(v["version"], 1);
        assert_eq!(v["hooks"]["beforeShellExecution"][0]["failClosed"], true);
        assert_eq!(v["hooks"]["beforeMCPExecution"][0]["failClosed"], true);
        // Observe-only events do NOT set failClosed.
        assert!(v["hooks"]["sessionStart"][0].get("failClosed").is_none());
    }

    #[test]
    fn write_mcp_creates_and_preserves_other_servers() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        fs::create_dir_all(cursor_dir(home)).unwrap();
        fs::write(
            mcp_json_path(home),
            "{\"mcpServers\":{\"other\":{\"command\":\"x\"}}}",
        )
        .unwrap();

        assert!(write_cursor_mcp(home).unwrap());
        let doc: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(mcp_json_path(home)).unwrap()).unwrap();
        assert_eq!(doc["mcpServers"]["other"]["command"], "x");
        assert_eq!(doc["mcpServers"]["clx"]["command"], "~/.clx/bin/clx-mcp");
        // Idempotent.
        assert!(!write_cursor_mcp(home).unwrap());
    }

    #[test]
    fn write_hooks_idempotent() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        assert!(write_cursor_hooks(home).unwrap());
        assert!(hooks_json_path(home).exists());
        assert!(!write_cursor_hooks(home).unwrap());
    }

    #[test]
    fn write_rule_idempotent_and_always_apply() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path();
        assert!(write_cursor_rule(repo).unwrap());
        let body = fs::read_to_string(rule_mdc_path(repo)).unwrap();
        assert!(body.contains("alwaysApply: true"));
        assert!(body.contains("# CLX Integration"));
        assert!(!write_cursor_rule(repo).unwrap());
    }

    #[test]
    fn remove_mcp_removes_clx_only() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        fs::create_dir_all(cursor_dir(home)).unwrap();
        fs::write(
            mcp_json_path(home),
            "{\"mcpServers\":{\"other\":{\"command\":\"x\"}}}",
        )
        .unwrap();
        write_cursor_mcp(home).unwrap();

        assert!(remove_cursor_mcp(home).unwrap());
        let doc: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(mcp_json_path(home)).unwrap()).unwrap();
        assert!(doc["mcpServers"].get("clx").is_none());
        assert_eq!(doc["mcpServers"]["other"]["command"], "x");
        assert!(!remove_cursor_mcp(home).unwrap());
    }

    #[test]
    fn remove_rule_deletes_file() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path();
        write_cursor_rule(repo).unwrap();
        assert!(remove_cursor_rule(repo).unwrap());
        assert!(!rule_mdc_path(repo).exists());
        // No-op when absent.
        assert!(!remove_cursor_rule(repo).unwrap());
    }

    #[test]
    fn detect_cursor_never_panics() {
        let _ = detect_cursor();
    }
}
