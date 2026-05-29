//! P3 e2e: `clx install --target codex` / `all` and uninstall (D8).
//!
//! Isolation: HOME + XDG redirected into a fresh `tempfile::TempDir`, so all
//! host artifacts land in throwaway space. The real `~/.codex`, `~/.claude`,
//! and `~/.cursor` are never touched. No network, no model download (the
//! install Ollama steps are best-effort and tolerate absence).

use assert_cmd::Command;
use tempfile::TempDir;

/// A `clx` command with HOME + XDG fully isolated to `tmp`. `current_dir` is
/// also redirected so the Cursor repo-local rule (when `all`) lands in tmp.
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
fn install_target_codex_writes_hooks_config_and_agents_md() {
    let t = tmp();
    clx(&t)
        .args(["--json", "install", "--target", "codex"])
        .assert()
        .success();

    // hooks.json present with the clx-hook PreToolUse Bash gate.
    let hooks = read(&t, ".codex/hooks.json").expect("codex hooks.json written");
    let hv: serde_json::Value = serde_json::from_str(&hooks).unwrap();
    assert_eq!(hv["hooks"]["PreToolUse"][0]["matcher"], "Bash");
    assert!(
        hv["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
            .as_str()
            .unwrap()
            .contains("clx-hook pre-tool-use")
    );

    // config.toml has [mcp_servers.clx].
    let cfg = read(&t, ".codex/config.toml").expect("codex config.toml written");
    let cv: toml::Value = toml::from_str(&cfg).unwrap();
    assert_eq!(
        cv["mcp_servers"]["clx"]["command"].as_str(),
        Some("~/.clx/bin/clx-mcp")
    );

    // AGENTS.md carries the CLX section + the F2 caveat.
    let agents = read(&t, ".codex/AGENTS.md").expect("codex AGENTS.md written");
    assert!(agents.contains("# CLX Integration"));
    assert!(agents.contains("codex exec"));

    // Claude should NOT be wired for --target codex.
    assert!(
        read(&t, ".claude/settings.json").is_none() || {
            let s = read(&t, ".claude/settings.json").unwrap();
            let sv: serde_json::Value = serde_json::from_str(&s).unwrap();
            sv.get("hooks").is_none()
        }
    );
}

#[test]
fn install_target_codex_is_idempotent() {
    let t = tmp();
    clx(&t)
        .args(["--json", "install", "--target", "codex"])
        .assert()
        .success();
    let first = read(&t, ".codex/config.toml").unwrap();

    // Second run must not duplicate or corrupt.
    clx(&t)
        .args(["--json", "install", "--target", "codex"])
        .assert()
        .success();
    let second = read(&t, ".codex/config.toml").unwrap();
    assert_eq!(first, second);

    // AGENTS.md still has exactly one CLX section.
    let agents = read(&t, ".codex/AGENTS.md").unwrap();
    assert_eq!(agents.matches("# CLX Integration").count(), 1);
}

#[test]
fn install_target_all_writes_codex_and_cursor_and_claude() {
    let t = tmp();
    clx(&t)
        .args(["--json", "install", "--target", "all"])
        .assert()
        .success();

    // Codex.
    assert!(read(&t, ".codex/hooks.json").is_some());
    assert!(read(&t, ".codex/config.toml").is_some());
    assert!(read(&t, ".codex/AGENTS.md").is_some());
    // Cursor.
    assert!(read(&t, ".cursor/mcp.json").is_some());
    assert!(read(&t, ".cursor/hooks.json").is_some());
    assert!(read(&t, ".cursor/rules/clx.mdc").is_some());
    // Claude.
    let s = read(&t, ".claude/settings.json").expect("claude settings written");
    let sv: serde_json::Value = serde_json::from_str(&s).unwrap();
    assert!(sv["hooks"].is_object());
}

#[test]
fn uninstall_target_all_removes_codex_section_and_config() {
    let t = tmp();
    clx(&t)
        .args(["--json", "install", "--target", "all"])
        .assert()
        .success();
    clx(&t)
        .args(["--json", "uninstall", "--target", "all"])
        .assert()
        .success();

    // hooks.json removed.
    assert!(read(&t, ".codex/hooks.json").is_none());
    // config.toml no longer has the clx MCP block.
    if let Some(cfg) = read(&t, ".codex/config.toml") {
        let cv: toml::Value = toml::from_str(&cfg).unwrap();
        assert!(cv.get("mcp_servers").is_none());
    }
    // AGENTS.md CLX section stripped.
    if let Some(agents) = read(&t, ".codex/AGENTS.md") {
        assert!(!agents.contains("# CLX Integration"));
    }
}

#[test]
fn install_target_codex_does_not_panic_when_no_codex_binary() {
    // Detection may say "not installed", but --target codex installs anyway
    // (the writers only touch ~/.codex). The command must succeed cleanly.
    let t = tmp();
    clx(&t)
        .args(["--json", "install", "--target", "codex"])
        .assert()
        .success();
}
