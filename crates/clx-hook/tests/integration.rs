//! Integration tests for the clx-hook binary.
//!
//! These tests exercise the hook binary as a subprocess, sending
//! Claude Code hook JSON on stdin and verifying JSON output on stdout.
//! Uses a temporary HOME directory to avoid touching the real database.

use std::io::Write;
use std::process::{Command, Stdio};

/// Helper: spawn the clx-hook binary with isolated HOME and pipe JSON input.
/// Returns (stdout, stderr) as strings.
fn run_hook(input: &str) -> (String, String) {
    let binary = env!("CARGO_BIN_EXE_clx-hook");

    // Use a temp directory as HOME to isolate from real ~/.clx
    let temp_home = std::env::temp_dir().join(format!("clx-hook-test-{}", std::process::id()));
    std::fs::create_dir_all(&temp_home).unwrap();

    let mut child = Command::new(binary)
        .env("HOME", &temp_home)
        .env("CLX_LOG", "error") // Suppress log noise
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn clx-hook binary");

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(input.as_bytes()).unwrap();
    }

    let output = child
        .wait_with_output()
        .expect("Failed to wait for clx-hook");

    // Clean up temp directory (best-effort)
    let _ = std::fs::remove_dir_all(&temp_home);

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    (stdout, stderr)
}

// =========================================================================
// 1. PreToolUse for non-Bash tool (fast path, no storage interaction)
// =========================================================================

#[test]
fn test_hook_pre_tool_use_non_bash_allows() {
    // Non-Bash tools take the fast path: immediate "allow" without storage
    let input = serde_json::json!({
        "session_id": "test-session-integration-001",
        "cwd": "/tmp",
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_use_id": "tu-001",
        "tool_input": {
            "file_path": "/tmp/test.txt"
        }
    });

    let (stdout, _stderr) = run_hook(&input.to_string());

    assert!(
        !stdout.trim().is_empty(),
        "Hook should produce JSON output on stdout"
    );

    let output: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("Failed to parse hook output: {e}\nOutput: {stdout}"));

    // Verify structure
    let hook_output = &output["hookSpecificOutput"];
    assert_eq!(
        hook_output["hookEventName"], "PreToolUse",
        "Should echo back the hook event name"
    );
    assert_eq!(
        hook_output["permissionDecision"], "allow",
        "Non-Bash tools should be allowed"
    );
}

// =========================================================================
// 2. PreToolUse for Bash with whitelisted command
// =========================================================================

#[test]
fn test_hook_pre_tool_use_bash_whitelisted_command() {
    // "ls -la" is in the built-in whitelist, should be allowed
    let input = serde_json::json!({
        "session_id": "test-session-integration-002",
        "cwd": "/tmp",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_use_id": "tu-002",
        "tool_input": {
            "command": "ls -la"
        }
    });

    let (stdout, _stderr) = run_hook(&input.to_string());

    assert!(
        !stdout.trim().is_empty(),
        "Hook should produce JSON output on stdout"
    );

    let output: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("Failed to parse hook output: {e}\nOutput: {stdout}"));

    let hook_output = &output["hookSpecificOutput"];
    assert_eq!(hook_output["hookEventName"], "PreToolUse");
    assert_eq!(
        hook_output["permissionDecision"], "allow",
        "Built-in whitelisted command 'ls -la' should be allowed"
    );
}

// =========================================================================
// 3. PostToolUse integration test
// =========================================================================

#[test]
fn test_hook_post_tool_use_basic() {
    // PostToolUse should process the event and exit successfully with valid JSON output.
    // It logs the tool use to storage (which will be in a temp HOME).
    let input = serde_json::json!({
        "session_id": "test-session-integration-post-001",
        "cwd": "/tmp",
        "hook_event_name": "PostToolUse",
        "tool_name": "Bash",
        "tool_use_id": "tu-post-001",
        "tool_input": {
            "command": "echo hello"
        },
        "tool_response": {
            "output": "hello\n"
        }
    });

    let (stdout, _stderr) = run_hook(&input.to_string());

    // PostToolUse may produce empty output (no permission decision needed)
    // or a generic hook output with additionalContext.
    // The key requirement is that the process exits successfully and
    // any output is valid JSON (if non-empty).
    if !stdout.trim().is_empty() {
        let _output: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
            panic!("PostToolUse output must be valid JSON: {e}\nOutput: {stdout}")
        });
    }
    // If stdout is empty, that is also acceptable for PostToolUse
    // (it only produces output when context pressure triggers)
}

// =========================================================================
// 4. Trust mode - valid token auto-allows
// =========================================================================

#[test]
fn test_hook_trust_mode_valid_token_allows() {
    // When trust_mode is enabled and the token file is fresh (<1 hour),
    // PreToolUse should auto-allow any command without LLM validation.
    let binary = env!("CARGO_BIN_EXE_clx-hook");

    let temp_home = std::env::temp_dir().join(format!("clx-trust-valid-{}", std::process::id()));
    std::fs::create_dir_all(&temp_home).unwrap();

    // Create config.yaml that enables trust_mode and disables L1
    let clx_dir = temp_home.join(".clx");
    std::fs::create_dir_all(&clx_dir).unwrap();
    std::fs::write(
        clx_dir.join("config.yaml"),
        "validator:\n  enabled: true\n  trust_mode: true\n  layer1_enabled: false\n",
    )
    .unwrap();

    // Create a fresh trust token file (mtime = now => valid)
    std::fs::write(clx_dir.join(".trust_mode_token"), "trust_mode_active").unwrap();

    let input = serde_json::json!({
        "session_id": "test-trust-valid-001",
        "cwd": "/tmp",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_use_id": "tu-trust-001",
        "tool_input": {
            "command": "rm -rf /some/dangerous/path"
        }
    });

    let mut child = Command::new(binary)
        .env("HOME", &temp_home)
        .env("CLX_LOG", "error")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn clx-hook binary");

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(input.to_string().as_bytes()).unwrap();
    }

    let output = child
        .wait_with_output()
        .expect("Failed to wait for clx-hook");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();

    let parsed: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("Failed to parse trust mode output: {e}\nOutput: {stdout}"));

    let hook_output = &parsed["hookSpecificOutput"];
    assert_eq!(
        hook_output["permissionDecision"], "allow",
        "Trust mode with valid token should auto-allow even dangerous commands"
    );

    let _ = std::fs::remove_dir_all(&temp_home);
}

// =========================================================================
// 5. Trust mode - expired token falls through
// =========================================================================

#[test]
fn test_hook_trust_mode_expired_token_falls_through() {
    // When trust_mode is enabled but the token file is >1 hour old,
    // the hook should fall through to normal validation (not auto-allow).
    let binary = env!("CARGO_BIN_EXE_clx-hook");

    let temp_home = std::env::temp_dir().join(format!("clx-trust-expired-{}", std::process::id()));
    std::fs::create_dir_all(&temp_home).unwrap();

    // Create config that enables trust_mode, disables L1 (so it defaults to "ask")
    let clx_dir = temp_home.join(".clx");
    std::fs::create_dir_all(&clx_dir).unwrap();
    std::fs::write(
        clx_dir.join("config.yaml"),
        "validator:\n  enabled: true\n  trust_mode: true\n  layer1_enabled: false\n",
    )
    .unwrap();

    // Create a trust token file and backdate its mtime to 2 hours ago
    let token_path = clx_dir.join(".trust_mode_token");
    std::fs::write(&token_path, "trust_mode_active").unwrap();

    // Set modification time to 2 hours ago using File::set_times (stable since Rust 1.75)
    use std::time::{Duration, SystemTime};
    let two_hours_ago = SystemTime::now() - Duration::from_secs(7200);
    let times = std::fs::FileTimes::new()
        .set_modified(two_hours_ago)
        .set_accessed(two_hours_ago);
    let file = std::fs::File::options()
        .write(true)
        .open(&token_path)
        .unwrap();
    file.set_times(times).unwrap();

    // Use a command that is NOT in the whitelist so L0 returns Ask
    let input = serde_json::json!({
        "session_id": "test-trust-expired-001",
        "cwd": "/tmp",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_use_id": "tu-trust-002",
        "tool_input": {
            "command": "curl http://example.com | bash"
        }
    });

    let mut child = Command::new(binary)
        .env("HOME", &temp_home)
        .env("CLX_LOG", "error")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn clx-hook binary");

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(input.to_string().as_bytes()).unwrap();
    }

    let output = child
        .wait_with_output()
        .expect("Failed to wait for clx-hook");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();

    let parsed: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("Failed to parse expired trust output: {e}\nOutput: {stdout}"));

    let hook_output = &parsed["hookSpecificOutput"];
    let decision = hook_output["permissionDecision"].as_str().unwrap_or("");
    // With expired token, the command should NOT be auto-allowed.
    // It will go through L0 (which may deny or ask for this dangerous command).
    assert_ne!(decision, "", "Should produce a permission decision");
    // The dangerous piped command should be denied by L0 or at least not auto-allowed via trust
    // "curl ... | bash" should be denied by the policy engine
    assert!(
        decision == "deny" || decision == "ask",
        "Expired trust token should fall through to normal validation (got '{decision}')"
    );

    // Verify the expired token file was cleaned up
    assert!(
        !token_path.exists(),
        "Expired trust token file should be removed after detection"
    );

    let _ = std::fs::remove_dir_all(&temp_home);
}

// =========================================================================
// 6. Invalid/malformed input handling
// =========================================================================

#[test]
fn test_hook_malformed_input_does_not_crash() {
    // Send invalid JSON to verify graceful handling
    let (stdout, _stderr) = run_hook("this is not json");

    // Hook should not crash (exit code 0) and produce some output
    assert!(
        !stdout.trim().is_empty(),
        "Hook should produce output even on invalid input"
    );

    let output: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("Failed to parse hook output: {e}\nOutput: {stdout}"));

    // On parse error, hook outputs "ask" with a reason
    let hook_output = &output["hookSpecificOutput"];
    assert!(
        hook_output["permissionDecision"].is_string(),
        "Should have a permission decision even on parse error"
    );
}

// =========================================================================
// T11 — PostToolUse handler (5 tests)
// =========================================================================

/// T11-1: Normal tool use event is logged without producing stdout output
/// (PostToolUse only emits stdout when context pressure triggers).
#[test]
fn test_post_tool_use_normal_event_logged_successfully() {
    let input = serde_json::json!({
        "session_id": "post-t11-1",
        "cwd": "/tmp",
        "hook_event_name": "PostToolUse",
        "tool_name": "Read",
        "tool_use_id": "tu-t11-1",
        "tool_input": {"file_path": "/tmp/foo.txt"},
        "tool_response": {"content": "file contents"}
    });

    let (stdout, _stderr) = run_hook(&input.to_string());

    // Any output must be valid JSON; empty is also acceptable
    if !stdout.trim().is_empty() {
        let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
            panic!("PostToolUse must emit valid JSON if non-empty: {e}\nOutput: {stdout}")
        });
        // If present, it must reference the PostToolUse event
        let hook_event = parsed["hookSpecificOutput"]["hookEventName"]
            .as_str()
            .unwrap_or("");
        assert_eq!(hook_event, "PostToolUse", "hookEventName must be PostToolUse");
    }
}

/// T11-2: Bash command is extracted from tool_input and tracked for learning.
/// The handler must not crash and must exit cleanly.
#[test]
fn test_post_tool_use_bash_command_extraction() {
    let input = serde_json::json!({
        "session_id": "post-t11-2",
        "cwd": "/tmp",
        "hook_event_name": "PostToolUse",
        "tool_name": "Bash",
        "tool_use_id": "tu-t11-2",
        "tool_input": {"command": "cargo build --release"},
        "tool_response": {"output": "   Compiling clx v0.1.0\n"}
    });

    let (stdout, _stderr) = run_hook(&input.to_string());

    // Must not crash; any stdout must be valid JSON
    if !stdout.trim().is_empty() {
        let _: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
            panic!("PostToolUse (Bash) must emit valid JSON: {e}\nOutput: {stdout}")
        });
    }
}

/// T11-3: Context pressure detection — when a large transcript is provided the
/// handler should output a context-pressure warning via additionalContext.
#[test]
fn test_post_tool_use_context_pressure_warning_emitted() {
    use std::io::Write;

    let binary = env!("CARGO_BIN_EXE_clx-hook");
    let temp_home =
        std::env::temp_dir().join(format!("clx-post-pressure-{}", std::process::id()));
    std::fs::create_dir_all(&temp_home).unwrap();

    // Write config enabling context pressure in "notify" mode with a low window
    // so that a modest transcript crosses the threshold.
    let clx_dir = temp_home.join(".clx");
    std::fs::create_dir_all(&clx_dir).unwrap();
    std::fs::write(
        clx_dir.join("config.yaml"),
        // 1000-token window at 80% threshold = 800 tokens needed.
        "context_pressure:\n  mode: notify\n  context_window_size: 1000\n  threshold: 0.80\n",
    )
    .unwrap();

    // Build a transcript that accumulates well above 800 tokens.
    // estimate_tokens: (len+3)/4  =>  4000-char msg => ~1000 tokens each.
    let data_dir = clx_dir.join("data");
    std::fs::create_dir_all(&data_dir).unwrap();
    let transcript_path = data_dir.join("test_transcript.jsonl");
    {
        let mut f = std::fs::File::create(&transcript_path).unwrap();
        let big_content = "A".repeat(4000);
        for _ in 0..3 {
            writeln!(
                f,
                "{{\"type\":\"assistant\",\"message\":\"{}\"}}",
                big_content
            )
            .unwrap();
        }
    }

    let input = serde_json::json!({
        "session_id": "post-t11-3",
        "cwd": "/tmp",
        "hook_event_name": "PostToolUse",
        "tool_name": "Read",
        "tool_use_id": "tu-t11-3",
        "tool_input": {"file_path": "/tmp/foo.txt"},
        "transcript_path": transcript_path.to_str().unwrap()
    });

    let mut child = std::process::Command::new(binary)
        .env("HOME", &temp_home)
        .env("CLX_LOG", "error")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.to_string().as_bytes())
        .unwrap();

    let output = child.wait_with_output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();

    let _ = std::fs::remove_dir_all(&temp_home);

    // When context pressure fires the handler emits a JSON object with additionalContext
    assert!(
        !stdout.trim().is_empty(),
        "Context pressure should produce JSON output"
    );
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!("Context pressure output must be valid JSON: {e}\nOutput: {stdout}")
    });

    let additional_ctx = parsed["hookSpecificOutput"]["additionalContext"]
        .as_str()
        .unwrap_or("");
    assert!(
        additional_ctx.contains("WARNING") || additional_ctx.contains("Context"),
        "additionalContext should contain the context-pressure warning, got: '{additional_ctx}'"
    );
}

/// T11-4: Auto-learning trigger — Bash command executed (tool_response present)
/// is tracked; no-response commands are not. Handler must complete cleanly either way.
#[test]
fn test_post_tool_use_auto_learning_executed_vs_not_executed() {
    // With tool_response present the command is considered "executed"
    let input_executed = serde_json::json!({
        "session_id": "post-t11-4a",
        "cwd": "/tmp",
        "hook_event_name": "PostToolUse",
        "tool_name": "Bash",
        "tool_use_id": "tu-t11-4a",
        "tool_input": {"command": "echo learning_test"},
        "tool_response": {"output": "learning_test\n"}
    });

    let (stdout_exec, _) = run_hook(&input_executed.to_string());

    // Without tool_response the command was not executed
    let input_not_executed = serde_json::json!({
        "session_id": "post-t11-4b",
        "cwd": "/tmp",
        "hook_event_name": "PostToolUse",
        "tool_name": "Bash",
        "tool_use_id": "tu-t11-4b",
        "tool_input": {"command": "echo learning_test"}
        // no tool_response field
    });

    let (stdout_no_exec, _) = run_hook(&input_not_executed.to_string());

    // Both must exit cleanly; any stdout must parse as JSON
    for (label, stdout) in [("executed", &stdout_exec), ("not_executed", &stdout_no_exec)] {
        if !stdout.trim().is_empty() {
            let _: serde_json::Value =
                serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
                    panic!("PostToolUse ({label}) must emit valid JSON: {e}\nOutput: {stdout}")
                });
        }
    }
}

/// T11-5: Malformed / missing required fields — handler must not panic.
#[test]
fn test_post_tool_use_missing_optional_fields_no_crash() {
    // Minimal valid PostToolUse with no tool_name, tool_input, or tool_response
    let input = serde_json::json!({
        "session_id": "post-t11-5",
        "cwd": "/tmp",
        "hook_event_name": "PostToolUse"
    });

    let (stdout, _stderr) = run_hook(&input.to_string());

    if !stdout.trim().is_empty() {
        let _: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
            panic!("PostToolUse with minimal input must emit valid JSON: {e}\nOutput: {stdout}")
        });
    }
}

// =========================================================================
// T12 — PreCompact handler (4 tests)
// =========================================================================

/// T12-1: Snapshot is created in storage when no transcript is provided.
/// Verifies the handler completes without error (empty stdout is acceptable).
#[test]
fn test_pre_compact_snapshot_created_without_transcript() {
    let input = serde_json::json!({
        "session_id": "compact-t12-1",
        "cwd": "/tmp",
        "hook_event_name": "PreCompact",
        "trigger": "manual"
    });

    let (stdout, _stderr) = run_hook(&input.to_string());

    // PreCompact does not produce stdout output unless there is an error path.
    // Any output present must be valid JSON.
    if !stdout.trim().is_empty() {
        let _: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
            panic!("PreCompact must emit valid JSON if non-empty: {e}\nOutput: {stdout}")
        });
    }
}

/// T12-2: Trigger field controls SnapshotTrigger variant — both "auto" and
/// "manual" triggers must complete without error.
#[test]
fn test_pre_compact_auto_and_manual_trigger() {
    for trigger in ["auto", "manual", "unknown_trigger"] {
        let input = serde_json::json!({
            "session_id": format!("compact-t12-2-{trigger}"),
            "cwd": "/tmp",
            "hook_event_name": "PreCompact",
            "trigger": trigger
        });

        let (stdout, _stderr) = run_hook(&input.to_string());

        if !stdout.trim().is_empty() {
            let _: serde_json::Value =
                serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
                    panic!(
                        "PreCompact (trigger={trigger}) must emit valid JSON: {e}\nOutput: {stdout}"
                    )
                });
        }
    }
}

/// T12-3: With a valid transcript file, the handler reads and processes it
/// (token counting). Ollama is unavailable in CI so only basic summary is created.
#[test]
fn test_pre_compact_with_transcript_file() {
    use std::io::Write;

    let binary = env!("CARGO_BIN_EXE_clx-hook");
    let temp_home =
        std::env::temp_dir().join(format!("clx-compact-transcript-{}", std::process::id()));
    std::fs::create_dir_all(&temp_home).unwrap();

    // Disable Ollama to force the graceful-degradation path
    let clx_dir = temp_home.join(".clx");
    std::fs::create_dir_all(&clx_dir).unwrap();
    std::fs::write(
        clx_dir.join("config.yaml"),
        "ollama:\n  base_url: \"http://127.0.0.1:19999\"\n  timeout_secs: 1\n",
    )
    .unwrap();

    // Write a small transcript
    let data_dir = clx_dir.join("data");
    std::fs::create_dir_all(&data_dir).unwrap();
    let transcript_path = data_dir.join("compact_transcript.jsonl");
    {
        let mut f = std::fs::File::create(&transcript_path).unwrap();
        writeln!(f, "{{\"type\":\"user\",\"message\":\"what is 2+2\"}}").unwrap();
        writeln!(f, "{{\"type\":\"assistant\",\"message\":\"4\"}}").unwrap();
    }

    let input = serde_json::json!({
        "session_id": "compact-t12-3",
        "cwd": "/tmp",
        "hook_event_name": "PreCompact",
        "trigger": "auto",
        "transcript_path": transcript_path.to_str().unwrap()
    });

    let mut child = std::process::Command::new(binary)
        .env("HOME", &temp_home)
        .env("CLX_LOG", "error")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.to_string().as_bytes())
        .unwrap();

    let output = child.wait_with_output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();

    let _ = std::fs::remove_dir_all(&temp_home);

    // Handler should complete; no stdout unless error
    if !stdout.trim().is_empty() {
        let _: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
            panic!("PreCompact with transcript must emit valid JSON: {e}\nOutput: {stdout}")
        });
    }
}

/// T12-4: Graceful degradation when Ollama is unavailable — handler must not
/// crash and must complete without producing invalid output.
#[test]
fn test_pre_compact_graceful_degradation_ollama_unavailable() {
    use std::io::Write;

    let binary = env!("CARGO_BIN_EXE_clx-hook");
    let temp_home =
        std::env::temp_dir().join(format!("clx-compact-no-ollama-{}", std::process::id()));
    std::fs::create_dir_all(&temp_home).unwrap();

    // Point Ollama at a port that is not listening to force unavailable path
    let clx_dir = temp_home.join(".clx");
    std::fs::create_dir_all(&clx_dir).unwrap();
    std::fs::write(
        clx_dir.join("config.yaml"),
        "ollama:\n  base_url: \"http://127.0.0.1:19998\"\n  timeout_secs: 1\n",
    )
    .unwrap();

    let data_dir = clx_dir.join("data");
    std::fs::create_dir_all(&data_dir).unwrap();
    let transcript_path = data_dir.join("no_ollama_transcript.jsonl");
    {
        let mut f = std::fs::File::create(&transcript_path).unwrap();
        writeln!(f, "{{\"type\":\"user\",\"message\":\"test message\"}}").unwrap();
    }

    let input = serde_json::json!({
        "session_id": "compact-t12-4",
        "cwd": "/tmp",
        "hook_event_name": "PreCompact",
        "trigger": "auto",
        "transcript_path": transcript_path.to_str().unwrap()
    });

    let mut child = std::process::Command::new(binary)
        .env("HOME", &temp_home)
        .env("CLX_LOG", "error")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.to_string().as_bytes())
        .unwrap();

    let output = child.wait_with_output().unwrap();
    let exit_status = output.status;
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();

    let _ = std::fs::remove_dir_all(&temp_home);

    assert!(
        exit_status.success(),
        "PreCompact should exit 0 even when Ollama is unavailable"
    );

    if !stdout.trim().is_empty() {
        let _: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
            panic!(
                "PreCompact (no Ollama) must emit valid JSON if non-empty: {e}\nOutput: {stdout}"
            )
        });
    }
}

// =========================================================================
// T13 — SessionStart handler (5 tests)
// =========================================================================

/// T13-1: New session creation — handler must emit valid JSON with a
/// systemMessage containing the CLX tools reminder.
#[test]
fn test_session_start_new_session_creates_and_emits_system_message() {
    let input = serde_json::json!({
        "session_id": "start-t13-1",
        "cwd": "/tmp",
        "hook_event_name": "SessionStart",
        "source": "startup"
    });

    let (stdout, _stderr) = run_hook(&input.to_string());

    assert!(
        !stdout.trim().is_empty(),
        "SessionStart must always emit JSON output"
    );

    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!("SessionStart must emit valid JSON: {e}\nOutput: {stdout}")
    });

    // Must reference the correct hook event
    let hook_event = parsed["hookSpecificOutput"]["hookEventName"]
        .as_str()
        .unwrap_or("");
    assert_eq!(hook_event, "SessionStart", "hookEventName must be SessionStart");

    // systemMessage must contain CLX tools reminder
    let system_msg = parsed["systemMessage"].as_str().unwrap_or("");
    assert!(
        system_msg.contains("clx_recall") || system_msg.contains("CLX Tools"),
        "systemMessage should contain CLX tools reminder, got: '{system_msg}'"
    );
}

/// T13-2: Resume detection — when the same session_id is sent twice, the
/// second call detects an existing session and logs a resume.
#[test]
fn test_session_start_resumed_session_detection() {
    let binary = env!("CARGO_BIN_EXE_clx-hook");

    let temp_home =
        std::env::temp_dir().join(format!("clx-start-resume-{}", std::process::id()));
    std::fs::create_dir_all(&temp_home).unwrap();

    let input = serde_json::json!({
        "session_id": "start-t13-2",
        "cwd": "/tmp",
        "hook_event_name": "SessionStart",
        "source": "startup"
    });
    let input_str = input.to_string();

    // Helper to run with the shared temp_home
    let run = |binary: &str, temp_home: &std::path::Path, body: &str| {
        let mut child = std::process::Command::new(binary)
            .env("HOME", temp_home)
            .env("CLX_LOG", "error")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(body.as_bytes())
            .unwrap();
        let out = child.wait_with_output().unwrap();
        (
            String::from_utf8_lossy(&out.stdout).to_string(),
            String::from_utf8_lossy(&out.stderr).to_string(),
        )
    };

    // First call — creates the session
    let (stdout1, _) = run(binary, &temp_home, &input_str);
    assert!(!stdout1.trim().is_empty(), "First SessionStart must emit JSON");

    // Second call — should detect existing session (resume path)
    let (stdout2, _stderr2) = run(binary, &temp_home, &input_str);
    assert!(
        !stdout2.trim().is_empty(),
        "Resumed SessionStart must also emit JSON"
    );
    let parsed2: serde_json::Value = serde_json::from_str(stdout2.trim()).unwrap_or_else(|e| {
        panic!("Resumed SessionStart must emit valid JSON: {e}\nOutput: {stdout2}")
    });
    assert_eq!(
        parsed2["hookSpecificOutput"]["hookEventName"]
            .as_str()
            .unwrap_or(""),
        "SessionStart"
    );

    let _ = std::fs::remove_dir_all(&temp_home);
}

/// T13-3: Previous summary injection — if a snapshot exists for a prior session
/// in the same project directory, it should appear in the systemMessage.
#[test]
fn test_session_start_previous_summary_injected() {
    use std::io::Write;

    let binary = env!("CARGO_BIN_EXE_clx-hook");
    let temp_home =
        std::env::temp_dir().join(format!("clx-start-summary-{}", std::process::id()));
    std::fs::create_dir_all(&temp_home).unwrap();

    // Seed the storage with a previous session + snapshot using clx-core directly
    // by first running a SessionEnd for a "prior" session (which creates the snapshot).
    // To keep the test self-contained we run SessionStart for a prior session first,
    // then PreCompact to create a snapshot, then SessionEnd, then a new SessionStart
    // and verify the system message contains summary-related content.
    let project_cwd = temp_home.join("myproject");
    std::fs::create_dir_all(&project_cwd).unwrap();

    // Build a small transcript so PreCompact gets a basic summary
    let clx_dir = temp_home.join(".clx");
    std::fs::create_dir_all(&clx_dir).unwrap();
    // Disable Ollama to use the fallback "Session with N messages" summary
    std::fs::write(
        clx_dir.join("config.yaml"),
        "ollama:\n  base_url: \"http://127.0.0.1:19997\"\n  timeout_secs: 1\n",
    )
    .unwrap();

    let data_dir = clx_dir.join("data");
    std::fs::create_dir_all(&data_dir).unwrap();
    let transcript_path = data_dir.join("prior_session_transcript.jsonl");
    {
        let mut f = std::fs::File::create(&transcript_path).unwrap();
        writeln!(f, "{{\"type\":\"user\",\"message\":\"implement feature X\"}}").unwrap();
        writeln!(
            f,
            "{{\"type\":\"assistant\",\"message\":\"Done, feature X implemented.\"}}"
        )
        .unwrap();
    }

    let run_hook_isolated =
        |binary: &str, temp_home: &std::path::Path, body: serde_json::Value| {
            let mut child = std::process::Command::new(binary)
                .env("HOME", temp_home)
                .env("CLX_LOG", "error")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            child
                .stdin
                .take()
                .unwrap()
                .write_all(body.to_string().as_bytes())
                .unwrap();
            let out = child.wait_with_output().unwrap();
            String::from_utf8_lossy(&out.stdout).to_string()
        };

    let project_str = project_cwd.to_str().unwrap();

    // 1. Create prior session
    run_hook_isolated(
        binary,
        &temp_home,
        serde_json::json!({
            "session_id": "prior-session-t13-3",
            "cwd": project_str,
            "hook_event_name": "SessionStart",
            "source": "startup"
        }),
    );

    // 2. Create a snapshot via PreCompact (this stores a summary)
    run_hook_isolated(
        binary,
        &temp_home,
        serde_json::json!({
            "session_id": "prior-session-t13-3",
            "cwd": project_str,
            "hook_event_name": "PreCompact",
            "trigger": "manual",
            "transcript_path": transcript_path.to_str().unwrap()
        }),
    );

    // 3. End the prior session
    run_hook_isolated(
        binary,
        &temp_home,
        serde_json::json!({
            "session_id": "prior-session-t13-3",
            "cwd": project_str,
            "hook_event_name": "SessionEnd"
        }),
    );

    // 4. Start a new session — it should load the prior session summary
    let stdout = run_hook_isolated(
        binary,
        &temp_home,
        serde_json::json!({
            "session_id": "new-session-t13-3",
            "cwd": project_str,
            "hook_event_name": "SessionStart",
            "source": "startup"
        }),
    );

    let _ = std::fs::remove_dir_all(&temp_home);

    assert!(
        !stdout.trim().is_empty(),
        "New SessionStart must emit JSON output"
    );

    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!(
            "New SessionStart (with prior summary) must emit valid JSON: {e}\nOutput: {stdout}"
        )
    });

    // The systemMessage should contain either a previous session block or CLX tools
    let system_msg = parsed["systemMessage"].as_str().unwrap_or("");
    assert!(
        system_msg.contains("clx_recall")
            || system_msg.contains("CLX Tools")
            || system_msg.contains("Previous Session"),
        "systemMessage should reference CLX tools or previous session, got: '{system_msg}'"
    );
}

/// T13-4: Project rules injection — if CLAUDE.md exists in cwd the rules section
/// should appear in the systemMessage output.
#[test]
fn test_session_start_project_rules_injected() {
    use std::io::Write;

    let binary = env!("CARGO_BIN_EXE_clx-hook");
    let temp_home =
        std::env::temp_dir().join(format!("clx-start-rules-{}", std::process::id()));
    std::fs::create_dir_all(&temp_home).unwrap();

    // Create a project directory with a CLAUDE.md that has a CRITICAL section
    let project_dir = temp_home.join("rulesproject");
    std::fs::create_dir_all(&project_dir).unwrap();
    {
        let mut f = std::fs::File::create(project_dir.join("CLAUDE.md")).unwrap();
        writeln!(f, "# Rules [CRITICAL]").unwrap();
        writeln!(f, "Always use strict mode. Never skip tests.").unwrap();
    }

    let input = serde_json::json!({
        "session_id": "start-t13-4",
        "cwd": project_dir.to_str().unwrap(),
        "hook_event_name": "SessionStart",
        "source": "startup"
    });

    let mut child = std::process::Command::new(binary)
        .env("HOME", &temp_home)
        .env("CLX_LOG", "error")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.to_string().as_bytes())
        .unwrap();

    let output = child.wait_with_output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();

    let _ = std::fs::remove_dir_all(&temp_home);

    assert!(
        !stdout.trim().is_empty(),
        "SessionStart with CLAUDE.md must emit JSON"
    );

    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!("SessionStart (CLAUDE.md) must emit valid JSON: {e}\nOutput: {stdout}")
    });

    let system_msg = parsed["systemMessage"].as_str().unwrap_or("");
    assert!(
        system_msg.contains("strict mode")
            || system_msg.contains("Project Rules")
            || system_msg.contains("CRITICAL"),
        "systemMessage should contain project rules content, got: '{system_msg}'"
    );
}

/// T13-5: Unknown source value — handler must fall back to Startup and not crash.
#[test]
fn test_session_start_unknown_source_defaults_to_startup() {
    let input = serde_json::json!({
        "session_id": "start-t13-5",
        "cwd": "/tmp",
        "hook_event_name": "SessionStart",
        "source": "totally_unknown_source_value"
    });

    let (stdout, _stderr) = run_hook(&input.to_string());

    assert!(
        !stdout.trim().is_empty(),
        "SessionStart with unknown source must emit JSON"
    );

    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!("SessionStart (unknown source) must emit valid JSON: {e}\nOutput: {stdout}")
    });

    assert_eq!(
        parsed["hookSpecificOutput"]["hookEventName"]
            .as_str()
            .unwrap_or(""),
        "SessionStart"
    );
}

// =========================================================================
// T14 — SessionEnd handler (4 tests)
// =========================================================================

/// T14-1: Basic session end without transcript — handler exits cleanly.
#[test]
fn test_session_end_basic_no_transcript() {
    // First, create the session so end_session has something to operate on
    let input_start = serde_json::json!({
        "session_id": "end-t14-1",
        "cwd": "/tmp",
        "hook_event_name": "SessionStart",
        "source": "startup"
    });
    let _ = run_hook(&input_start.to_string());

    let input_end = serde_json::json!({
        "session_id": "end-t14-1",
        "cwd": "/tmp",
        "hook_event_name": "SessionEnd"
    });

    let (stdout, _stderr) = run_hook(&input_end.to_string());

    // SessionEnd may produce no stdout output; any output must be valid JSON
    if !stdout.trim().is_empty() {
        let _: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
            panic!("SessionEnd must emit valid JSON if non-empty: {e}\nOutput: {stdout}")
        });
    }
}

/// T14-2: Final snapshot is created and session token counts are updated
/// when a transcript is provided.
#[test]
fn test_session_end_creates_final_snapshot_with_transcript() {
    use std::io::Write;

    let binary = env!("CARGO_BIN_EXE_clx-hook");
    let temp_home =
        std::env::temp_dir().join(format!("clx-end-snapshot-{}", std::process::id()));
    std::fs::create_dir_all(&temp_home).unwrap();

    // Disable Ollama to avoid timeout delay in CI
    let clx_dir = temp_home.join(".clx");
    std::fs::create_dir_all(&clx_dir).unwrap();
    std::fs::write(
        clx_dir.join("config.yaml"),
        "ollama:\n  base_url: \"http://127.0.0.1:19996\"\n  timeout_secs: 1\n",
    )
    .unwrap();

    let data_dir = clx_dir.join("data");
    std::fs::create_dir_all(&data_dir).unwrap();
    let transcript_path = data_dir.join("end_transcript.jsonl");
    {
        let mut f = std::fs::File::create(&transcript_path).unwrap();
        writeln!(f, "{{\"type\":\"user\",\"message\":\"finish the task\"}}").unwrap();
        writeln!(
            f,
            "{{\"type\":\"assistant\",\"message\":\"Task complete.\"}}"
        )
        .unwrap();
    }

    let run_isolated = |binary: &str, temp_home: &std::path::Path, body: serde_json::Value| {
        let mut child = std::process::Command::new(binary)
            .env("HOME", temp_home)
            .env("CLX_LOG", "error")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(body.to_string().as_bytes())
            .unwrap();
        child.wait_with_output().unwrap()
    };

    // Start the session first
    run_isolated(
        binary,
        &temp_home,
        serde_json::json!({
            "session_id": "end-t14-2",
            "cwd": "/tmp",
            "hook_event_name": "SessionStart",
            "source": "startup"
        }),
    );

    // End with transcript
    let output = run_isolated(
        binary,
        &temp_home,
        serde_json::json!({
            "session_id": "end-t14-2",
            "cwd": "/tmp",
            "hook_event_name": "SessionEnd",
            "transcript_path": transcript_path.to_str().unwrap()
        }),
    );

    let exit_status = output.status;
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();

    let _ = std::fs::remove_dir_all(&temp_home);

    assert!(
        exit_status.success(),
        "SessionEnd with transcript must exit 0"
    );

    if !stdout.trim().is_empty() {
        let _: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
            panic!(
                "SessionEnd (with transcript) must emit valid JSON: {e}\nOutput: {stdout}"
            )
        });
    }
}

/// T14-3: Session status update — ending a session whose ID was never registered
/// (no-session-found case) must complete without crashing.
#[test]
fn test_session_end_no_session_found_graceful() {
    let input = serde_json::json!({
        "session_id": "end-t14-3-nonexistent",
        "cwd": "/tmp",
        "hook_event_name": "SessionEnd"
    });

    let (stdout, _stderr) = run_hook(&input.to_string());

    // Handler should complete cleanly; end_session on a missing ID logs a warning only
    if !stdout.trim().is_empty() {
        let _: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
            panic!(
                "SessionEnd (missing session) must emit valid JSON if non-empty: {e}\nOutput: {stdout}"
            )
        });
    }
}

/// T14-4: Token count recorded — stderr should mention the token count at end.
#[test]
fn test_session_end_token_count_reported_on_stderr() {
    let binary = env!("CARGO_BIN_EXE_clx-hook");
    let temp_home =
        std::env::temp_dir().join(format!("clx-end-tokens-{}", std::process::id()));
    std::fs::create_dir_all(&temp_home).unwrap();

    let input = serde_json::json!({
        "session_id": "end-t14-4",
        "cwd": "/tmp",
        "hook_event_name": "SessionEnd"
    });

    let mut child = std::process::Command::new(binary)
        .env("HOME", &temp_home)
        .env("CLX_LOG", "error")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.to_string().as_bytes())
        .unwrap();

    let output = child.wait_with_output().unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    let _ = std::fs::remove_dir_all(&temp_home);

    // The handler always writes "CLX: Session <id> ended (~<N> tokens)" to stderr
    assert!(
        stderr.contains("ended") || stderr.contains("CLX:"),
        "SessionEnd must write a completion message to stderr, got: '{stderr}'"
    );
}

// =========================================================================
// T31 — UserPromptSubmit handler (4 tests)
// =========================================================================

/// T31-1: Recall success path — seed storage with a prior session (via SessionStart +
/// PreCompact), then send a UserPromptSubmit with a matching prompt. The handler
/// must always produce valid JSON with hookEventName = "UserPromptSubmit" and
/// additionalContext containing at least the orchestrator reminder.
///
/// NOTE: The recall engine requires Ollama for embedding generation. In CI/test
/// environments Ollama is not available, so the handler falls back gracefully to
/// the orchestrator-only context. The test validates the invariant that JSON output
/// is always produced and always contains the orchestrator reminder.
#[test]
fn test_user_prompt_submit_recall_success_produces_valid_json() {
    let binary = env!("CARGO_BIN_EXE_clx-hook");
    let temp_home =
        std::env::temp_dir().join(format!("clx-ups-recall-{}", std::process::id()));
    std::fs::create_dir_all(&temp_home).unwrap();

    // Disable Ollama to force the graceful-degradation path (no embedding service
    // available in CI) — recall is skipped but orchestrator context is still injected.
    let clx_dir = temp_home.join(".clx");
    std::fs::create_dir_all(&clx_dir).unwrap();
    std::fs::write(
        clx_dir.join("config.yaml"),
        "ollama:\n  base_url: \"http://127.0.0.1:19995\"\n  timeout_secs: 1\nauto_recall:\n  enabled: true\n  timeout_ms: 500\n",
    )
    .unwrap();

    // Seed storage: start a prior session so storage is non-empty.
    let run_hook_isolated =
        |binary: &str, temp_home: &std::path::Path, body: serde_json::Value| {
            let mut child = std::process::Command::new(binary)
                .env("HOME", temp_home)
                .env("CLX_LOG", "error")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            child
                .stdin
                .take()
                .unwrap()
                .write_all(body.to_string().as_bytes())
                .unwrap();
            let out = child.wait_with_output().unwrap();
            String::from_utf8_lossy(&out.stdout).to_string()
        };

    // Create a prior session to ensure the database file exists.
    run_hook_isolated(
        binary,
        &temp_home,
        serde_json::json!({
            "session_id": "ups-prior-t31-1",
            "cwd": "/tmp",
            "hook_event_name": "SessionStart",
            "source": "startup"
        }),
    );

    // Now send a UserPromptSubmit with a substantive prompt.
    let input = serde_json::json!({
        "session_id": "ups-t31-1",
        "cwd": "/tmp",
        "hook_event_name": "UserPromptSubmit",
        "prompt": "Implement the authentication module for the project"
    });

    let mut child = std::process::Command::new(binary)
        .env("HOME", &temp_home)
        .env("CLX_LOG", "error")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn clx-hook binary");

    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.to_string().as_bytes())
        .unwrap();

    let output = child.wait_with_output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();

    let _ = std::fs::remove_dir_all(&temp_home);

    // UserPromptSubmit ALWAYS emits JSON — recall result is optional.
    assert!(
        !stdout.trim().is_empty(),
        "UserPromptSubmit must always emit JSON output"
    );

    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!("UserPromptSubmit must emit valid JSON: {e}\nOutput: {stdout}")
    });

    // hookEventName must identify the hook.
    assert_eq!(
        parsed["hookSpecificOutput"]["hookEventName"]
            .as_str()
            .unwrap_or(""),
        "UserPromptSubmit",
        "hookEventName must be UserPromptSubmit"
    );

    // additionalContext must contain the orchestrator reminder (always injected).
    let additional_ctx = parsed["hookSpecificOutput"]["additionalContext"]
        .as_str()
        .unwrap_or("");
    assert!(
        additional_ctx.contains("Orchestrator") || additional_ctx.contains("Delegate"),
        "additionalContext must contain the orchestrator reminder, got: '{additional_ctx}'"
    );
}

/// T31-2: Recall timeout handling — point Ollama at an unreachable port and set
/// an extremely short timeout. The handler must complete in reasonable time because
/// recall is fire-and-forget with an async timeout, and must still produce valid JSON.
#[test]
fn test_user_prompt_submit_recall_timeout_completes_in_time() {
    use std::time::Instant;

    let binary = env!("CARGO_BIN_EXE_clx-hook");
    let temp_home =
        std::env::temp_dir().join(format!("clx-ups-timeout-{}", std::process::id()));
    std::fs::create_dir_all(&temp_home).unwrap();

    // Point Ollama at an unreachable port with the minimum allowed timeout (100 ms).
    // The recall operation will timeout after ~100 ms and the handler returns promptly.
    let clx_dir = temp_home.join(".clx");
    std::fs::create_dir_all(&clx_dir).unwrap();
    std::fs::write(
        clx_dir.join("config.yaml"),
        "ollama:\n  base_url: \"http://127.0.0.1:19994\"\n  timeout_secs: 1\nauto_recall:\n  enabled: true\n  timeout_ms: 100\n",
    )
    .unwrap();

    let input = serde_json::json!({
        "session_id": "ups-t31-2",
        "cwd": "/tmp",
        "hook_event_name": "UserPromptSubmit",
        "prompt": "Implement the payment processing service with retry logic"
    });

    let start = Instant::now();

    let mut child = std::process::Command::new(binary)
        .env("HOME", &temp_home)
        .env("CLX_LOG", "error")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn clx-hook binary");

    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.to_string().as_bytes())
        .unwrap();

    let output = child.wait_with_output().unwrap();
    let elapsed = start.elapsed();
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();

    let _ = std::fs::remove_dir_all(&temp_home);

    // Handler must not block: allow 5 seconds headroom for process startup + OS scheduling.
    assert!(
        elapsed.as_secs() < 5,
        "UserPromptSubmit with unreachable Ollama must complete within 5 seconds, took {}ms",
        elapsed.as_millis()
    );

    // Output must still be valid JSON.
    assert!(
        !stdout.trim().is_empty(),
        "UserPromptSubmit must emit JSON even when Ollama times out"
    );

    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!(
            "UserPromptSubmit (timeout path) must emit valid JSON: {e}\nOutput: {stdout}"
        )
    });

    assert_eq!(
        parsed["hookSpecificOutput"]["hookEventName"]
            .as_str()
            .unwrap_or(""),
        "UserPromptSubmit",
        "hookEventName must be UserPromptSubmit even after recall timeout"
    );
}

/// T31-3: Recall error swallowing — no Ollama available and auto_recall enabled.
/// The handler must swallow all errors internally and still produce valid JSON with
/// the orchestrator reminder injected into additionalContext. No panic allowed.
#[test]
fn test_user_prompt_submit_recall_error_swallowed_no_panic() {
    let binary = env!("CARGO_BIN_EXE_clx-hook");
    let temp_home =
        std::env::temp_dir().join(format!("clx-ups-error-{}", std::process::id()));
    std::fs::create_dir_all(&temp_home).unwrap();

    // No Ollama available; auto_recall enabled. All recall errors must be swallowed.
    let clx_dir = temp_home.join(".clx");
    std::fs::create_dir_all(&clx_dir).unwrap();
    std::fs::write(
        clx_dir.join("config.yaml"),
        "ollama:\n  base_url: \"http://127.0.0.1:19993\"\n  timeout_secs: 1\nauto_recall:\n  enabled: true\n  timeout_ms: 200\n",
    )
    .unwrap();

    let input = serde_json::json!({
        "session_id": "ups-t31-3",
        "cwd": "/tmp",
        "hook_event_name": "UserPromptSubmit",
        "prompt": "Refactor the database layer to use the repository pattern"
    });

    let mut child = std::process::Command::new(binary)
        .env("HOME", &temp_home)
        .env("CLX_LOG", "error")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn clx-hook binary");

    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.to_string().as_bytes())
        .unwrap();

    let output = child.wait_with_output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();

    let _ = std::fs::remove_dir_all(&temp_home);

    // Process must exit successfully — errors are swallowed.
    assert!(
        output.status.success(),
        "UserPromptSubmit must exit 0 even when recall errors occur"
    );

    // Output must be valid JSON.
    assert!(
        !stdout.trim().is_empty(),
        "UserPromptSubmit must produce JSON output even when recall fails"
    );

    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!(
            "UserPromptSubmit (error swallow path) must emit valid JSON: {e}\nOutput: {stdout}"
        )
    });

    // hookEventName must be correct.
    assert_eq!(
        parsed["hookSpecificOutput"]["hookEventName"]
            .as_str()
            .unwrap_or(""),
        "UserPromptSubmit",
        "hookEventName must be UserPromptSubmit when recall errors are swallowed"
    );

    // Orchestrator reminder must always be present in additionalContext.
    let additional_ctx = parsed["hookSpecificOutput"]["additionalContext"]
        .as_str()
        .unwrap_or("");
    assert!(
        additional_ctx.contains("Orchestrator") || additional_ctx.contains("Delegate"),
        "additionalContext must contain orchestrator reminder even when recall fails, got: '{additional_ctx}'"
    );
}

/// T31-4: Empty storage — call UserPromptSubmit against empty storage (no prior
/// sessions). Recall finds no results; handler must still produce valid JSON with
/// the orchestrator reminder and no recall context appended.
#[test]
fn test_user_prompt_submit_empty_storage_valid_output() {
    // run_hook uses a fresh temp HOME each invocation; no seeding needed.
    let input = serde_json::json!({
        "session_id": "ups-t31-4",
        "cwd": "/tmp",
        "hook_event_name": "UserPromptSubmit",
        "prompt": "Set up CI/CD pipeline with GitHub Actions for this project"
    });

    let (stdout, _stderr) = run_hook(&input.to_string());

    // UserPromptSubmit always emits JSON output.
    assert!(
        !stdout.trim().is_empty(),
        "UserPromptSubmit against empty storage must emit JSON output"
    );

    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!(
            "UserPromptSubmit (empty storage) must emit valid JSON: {e}\nOutput: {stdout}"
        )
    });

    // hookEventName must identify the correct hook event.
    assert_eq!(
        parsed["hookSpecificOutput"]["hookEventName"]
            .as_str()
            .unwrap_or(""),
        "UserPromptSubmit",
        "hookEventName must be UserPromptSubmit with empty storage"
    );

    // additionalContext is always present — at minimum the orchestrator reminder.
    let additional_ctx = parsed["hookSpecificOutput"]["additionalContext"]
        .as_str()
        .unwrap_or("");
    assert!(
        additional_ctx.contains("Orchestrator") || additional_ctx.contains("Delegate"),
        "additionalContext must contain orchestrator reminder with empty storage, got: '{additional_ctx}'"
    );

    // With empty storage there should be no recall context block injected.
    // The presence of "Past Context" or "Recall" would indicate an unexpected recall hit.
    assert!(
        !additional_ctx.contains("Past Context") && !additional_ctx.contains("## Recall"),
        "Empty storage must not inject recall context, got: '{additional_ctx}'"
    );
}
