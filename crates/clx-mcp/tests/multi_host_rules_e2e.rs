//! Multi-host `get_project_rules` integration tests for the clx-mcp binary.
//!
//! These tests exercise the `clx_rules` tool's `get_project_rules` action as a
//! subprocess over JSON-RPC, verifying the multi-host behavior introduced for
//! v0.10.0:
//!
//! - Both `~/.claude/CLAUDE.md` (Claude) and `~/.codex/AGENTS.md` (Codex) are
//!   globbed and each present file is returned with a provenance label.
//! - `CLX_INSTRUCTIONS_FILE` overrides the glob list when it points at an
//!   existing file.
//! - When no instruction file exists, a "no rules found" message names the
//!   checked paths.
//!
//! Hermetic: each test uses a fresh tempdir as `$HOME`, `CLX_DB_PATH=:memory:`,
//! and runs the child with `current_dir` set to that home so the in-home path
//! guard passes. No real home directory or shared state is touched.

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

/// Spawn clx-mcp with a synthetic `$HOME`, optional `CLX_INSTRUCTIONS_FILE`,
/// and an in-memory DB. The child's working directory is set to `home` so the
/// `get_project_rules` in-home path guard admits the lookup. Returns stdout.
fn run_mcp_with_home(home: &Path, instructions_file: Option<&Path>, input: &str) -> String {
    let binary = env!("CARGO_BIN_EXE_clx-mcp");

    let mut cmd = Command::new(binary);
    cmd.env("CLX_DB_PATH", ":memory:")
        .env("HOME", home)
        .current_dir(home)
        // Ensure no ambient override leaks in from the test runner's env.
        .env_remove("CLX_INSTRUCTIONS_FILE")
        .env_remove("CLX_SESSION_ID")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    if let Some(file) = instructions_file {
        cmd.env("CLX_INSTRUCTIONS_FILE", file);
    }

    let mut child = cmd.spawn().expect("Failed to spawn clx-mcp binary");

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(input.as_bytes()).unwrap();
    }

    let output = child
        .wait_with_output()
        .expect("Failed to wait for clx-mcp");
    String::from_utf8_lossy(&output.stdout).to_string()
}

/// Build the JSON-RPC input for a `get_project_rules` call (after initialize).
fn get_project_rules_input() -> String {
    [
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"clx_rules","arguments":{"action":"get_project_rules"}}}"#,
    ]
    .join("\n")
        + "\n"
}

/// Extract the `result.content[0].text` from the `get_project_rules` response.
fn extract_rules_text(stdout: &str) -> String {
    let lines: Vec<&str> = stdout.lines().collect();
    assert!(
        lines.len() >= 2,
        "Expected initialize + tool-call responses, got {}: {:?}",
        lines.len(),
        lines
    );
    // Find the response with id == 2 (the tools/call).
    let call_resp = lines
        .iter()
        .map(|l| serde_json::from_str::<serde_json::Value>(l.trim()).expect("valid JSON-RPC line"))
        .find(|v| v["id"] == 2)
        .expect("response with id 2");
    assert!(
        call_resp.get("error").is_none(),
        "get_project_rules should not error: {call_resp}"
    );
    call_resp["result"]["content"][0]["text"]
        .as_str()
        .expect("content text")
        .to_string()
}

#[test]
fn get_project_rules_returns_both_claude_and_codex_with_provenance() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let home = tmp.path();

    // Synthetic Claude global file.
    let claude_dir = home.join(".claude");
    std::fs::create_dir_all(&claude_dir).expect("create .claude");
    std::fs::write(
        claude_dir.join("CLAUDE.md"),
        "# Claude Rules [CRITICAL]\nClaude rule alpha is in effect.\n",
    )
    .expect("write CLAUDE.md");

    // Synthetic Codex global file.
    let codex_dir = home.join(".codex");
    std::fs::create_dir_all(&codex_dir).expect("create .codex");
    std::fs::write(
        codex_dir.join("AGENTS.md"),
        "# Codex Rules [STRICT]\nCodex rule beta is in effect.\n",
    )
    .expect("write AGENTS.md");

    let text = extract_rules_text(&run_mcp_with_home(home, None, &get_project_rules_input()));

    assert!(
        text.contains("[from CLAUDE.md]"),
        "expected CLAUDE.md provenance label, got: {text}"
    );
    assert!(
        text.contains("Claude rule alpha"),
        "expected CLAUDE.md content, got: {text}"
    );
    assert!(
        text.contains("[from AGENTS.md]"),
        "expected AGENTS.md provenance label, got: {text}"
    );
    assert!(
        text.contains("Codex rule beta"),
        "expected AGENTS.md content, got: {text}"
    );
}

#[test]
fn get_project_rules_no_files_returns_no_rules_message_naming_paths() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let home = tmp.path();
    // No .claude/.codex files created.

    let text = extract_rules_text(&run_mcp_with_home(home, None, &get_project_rules_input()));

    assert!(
        text.contains("No rules found"),
        "expected no-rules message, got: {text}"
    );
    // Both checked global paths must be named.
    assert!(
        text.contains("CLAUDE.md"),
        "no-rules message must name the CLAUDE.md path, got: {text}"
    );
    assert!(
        text.contains("AGENTS.md"),
        "no-rules message must name the AGENTS.md path, got: {text}"
    );
}

#[test]
fn get_project_rules_honors_instructions_file_override() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let home = tmp.path();

    // A normal Claude file exists, but the override must take precedence.
    let claude_dir = home.join(".claude");
    std::fs::create_dir_all(&claude_dir).expect("create .claude");
    std::fs::write(
        claude_dir.join("CLAUDE.md"),
        "# Claude Rules [CRITICAL]\nClaude rule that must be shadowed.\n",
    )
    .expect("write CLAUDE.md");

    // The override file lives under home (so the path guard is satisfied) but
    // carries a distinct name and content.
    let override_file = home.join("CUSTOM_RULES.md");
    std::fs::write(
        &override_file,
        "# Override Rules [MANDATORY]\nOverride rule gamma is authoritative.\n",
    )
    .expect("write override file");

    let text = extract_rules_text(&run_mcp_with_home(
        home,
        Some(&override_file),
        &get_project_rules_input(),
    ));

    assert!(
        text.contains("[from CUSTOM_RULES.md]"),
        "expected override provenance label, got: {text}"
    );
    assert!(
        text.contains("Override rule gamma"),
        "expected override content, got: {text}"
    );
    // The override is exclusive: the shadowed Claude file must not appear.
    assert!(
        !text.contains("Claude rule that must be shadowed"),
        "override must shadow the glob list, got: {text}"
    );
    assert!(
        !text.contains("[from CLAUDE.md]"),
        "override must not also surface CLAUDE.md, got: {text}"
    );
}
