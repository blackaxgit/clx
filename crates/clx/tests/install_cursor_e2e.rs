//! P3 e2e: `clx install --target cursor` and uninstall (D8), plus the
//! Claude-path-unchanged regression and missing-host-fails-clean checks.
//!
//! Isolation: HOME + XDG + cwd redirected into a fresh `tempfile::TempDir`.
//! The real `~/.cursor`, `~/.claude`, `~/.codex` are never touched.

use assert_cmd::Command;
use tempfile::TempDir;

fn clx(tmp: &TempDir) -> Command {
    let mut cmd = Command::cargo_bin("clx").expect("clx binary");
    cmd.env("HOME", tmp.path())
        .env("XDG_DATA_HOME", tmp.path().join("xdg-data"))
        .env("XDG_CONFIG_HOME", tmp.path().join("xdg-config"))
        .env("CLX_LOG", "error")
        .current_dir(tmp.path());
    cmd
}

fn tmp() -> TempDir {
    tempfile::tempdir().expect("tempdir")
}

fn read(t: &TempDir, rel: &str) -> Option<String> {
    std::fs::read_to_string(t.path().join(rel)).ok()
}

#[test]
fn install_target_cursor_writes_mcp_hooks_and_rule() {
    let t = tmp();
    clx(&t)
        .args(["--json", "install", "--target", "cursor"])
        .assert()
        .success();

    // mcp.json has mcpServers.clx.
    let mcp = read(&t, ".cursor/mcp.json").expect("cursor mcp.json written");
    let mv: serde_json::Value = serde_json::from_str(&mcp).unwrap();
    assert_eq!(mv["mcpServers"]["clx"]["command"], "~/.clx/bin/clx-mcp");

    // hooks.json has failClosed:true on the shell + MCP gates.
    let hooks = read(&t, ".cursor/hooks.json").expect("cursor hooks.json written");
    let hv: serde_json::Value = serde_json::from_str(&hooks).unwrap();
    assert_eq!(hv["version"], 1);
    assert_eq!(hv["hooks"]["beforeShellExecution"][0]["failClosed"], true);
    assert_eq!(hv["hooks"]["beforeMCPExecution"][0]["failClosed"], true);

    // Repo-local rule with alwaysApply:true.
    let mdc = read(&t, ".cursor/rules/clx.mdc").expect("cursor rule written");
    assert!(mdc.contains("alwaysApply: true"));
    assert!(mdc.contains("# CLX Integration"));

    // Codex untouched for --target cursor.
    assert!(read(&t, ".codex/hooks.json").is_none());
}

#[test]
fn install_target_cursor_idempotent() {
    let t = tmp();
    clx(&t)
        .args(["--json", "install", "--target", "cursor"])
        .assert()
        .success();
    let first_mcp = read(&t, ".cursor/mcp.json").unwrap();
    clx(&t)
        .args(["--json", "install", "--target", "cursor"])
        .assert()
        .success();
    assert_eq!(first_mcp, read(&t, ".cursor/mcp.json").unwrap());
}

#[test]
fn uninstall_target_cursor_removes_mcp_hooks_and_rule() {
    let t = tmp();
    clx(&t)
        .args(["--json", "install", "--target", "cursor"])
        .assert()
        .success();
    clx(&t)
        .args(["--json", "uninstall", "--target", "cursor"])
        .assert()
        .success();

    assert!(read(&t, ".cursor/hooks.json").is_none());
    assert!(read(&t, ".cursor/rules/clx.mdc").is_none());
    if let Some(mcp) = read(&t, ".cursor/mcp.json") {
        let mv: serde_json::Value = serde_json::from_str(&mcp).unwrap();
        assert!(mv.get("mcpServers").is_none() || mv["mcpServers"].get("clx").is_none());
    }
}

#[test]
fn missing_host_target_fails_clean_no_panic() {
    // --target cursor with no Cursor binary still succeeds (writers only touch
    // ~/.cursor); the command must not panic or error.
    let t = tmp();
    clx(&t)
        .args(["--json", "install", "--target", "cursor"])
        .assert()
        .success();
    // Uninstall with nothing installed for a host is a clean no-op.
    let t2 = tmp();
    clx(&t2)
        .args(["--json", "uninstall", "--target", "cursor"])
        .assert()
        .success();
}

#[test]
fn claude_install_path_unchanged_target_claude() {
    // Regression: --target claude must wire ~/.claude exactly as the pre-P3
    // default install did - hooks (8 events) + mcpServers.clx + CLAUDE.md.
    let t = tmp();
    clx(&t)
        .args(["--json", "install", "--target", "claude"])
        .assert()
        .success();

    let s = read(&t, ".claude/settings.json").expect("claude settings written");
    let sv: serde_json::Value = serde_json::from_str(&s).unwrap();
    let hooks = sv["hooks"].as_object().expect("hooks object");
    for ev in [
        "PreToolUse",
        "PostToolUse",
        "PreCompact",
        "SessionStart",
        "SessionEnd",
        "SubagentStart",
        "UserPromptSubmit",
        "Stop",
    ] {
        assert!(hooks.contains_key(ev), "missing Claude hook: {ev}");
    }
    assert_eq!(sv["mcpServers"]["clx"]["command"], "~/.clx/bin/clx-mcp");
    let claude_md = read(&t, ".claude/CLAUDE.md").expect("CLAUDE.md written");
    assert!(claude_md.contains("# CLX Integration"));

    // --target claude must NOT touch Codex or Cursor.
    assert!(read(&t, ".codex/hooks.json").is_none());
    assert!(read(&t, ".cursor/mcp.json").is_none());
}

#[test]
fn uninstall_target_claude_strips_claude_md_section() {
    // D8: uninstall removes the CLX section from ~/.claude/CLAUDE.md.
    let t = tmp();
    clx(&t)
        .args(["--json", "install", "--target", "claude"])
        .assert()
        .success();
    assert!(
        read(&t, ".claude/CLAUDE.md")
            .unwrap()
            .contains("# CLX Integration")
    );

    clx(&t)
        .args(["--json", "uninstall", "--target", "claude"])
        .assert()
        .success();
    // CLAUDE.md may be gone or present-without-section; either way no marker.
    if let Some(md) = read(&t, ".claude/CLAUDE.md") {
        assert!(!md.contains("# CLX Integration"));
    }
}
