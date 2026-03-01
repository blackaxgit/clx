//! Integration tests for the clx-mcp binary.
//!
//! These tests exercise the MCP server as a subprocess, sending JSON-RPC
//! messages over stdin and verifying JSON-RPC responses on stdout.
//! Uses `CLX_DB_PATH=:memory:` to avoid filesystem side effects.

use std::io::Write;
use std::process::{Command, Stdio};

/// Helper: spawn the clx-mcp binary with in-memory DB and pipe JSON-RPC input.
/// Returns (stdout, stderr) as strings.
fn run_mcp_server(input: &str) -> (String, String) {
    let binary = env!("CARGO_BIN_EXE_clx-mcp");

    let mut child = Command::new(binary)
        .env("CLX_DB_PATH", ":memory:")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn clx-mcp binary");

    // Write input and close stdin so the server exits on EOF
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(input.as_bytes()).unwrap();
        // stdin is dropped here, closing the pipe
    }

    let output = child
        .wait_with_output()
        .expect("Failed to wait for clx-mcp");

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    (stdout, stderr)
}

/// Parse a single JSON-RPC response line from stdout.
fn parse_response(line: &str) -> serde_json::Value {
    serde_json::from_str(line.trim())
        .unwrap_or_else(|e| panic!("Failed to parse JSON-RPC response: {e}\nLine: {line}"))
}

// =========================================================================
// 1. Protocol round-trip: initialize -> tools/list
// =========================================================================

#[test]
fn test_mcp_initialize_and_tools_list() {
    // Send initialize followed by tools/list, then EOF
    let input = concat!(
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
        "\n",
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#,
        "\n",
    );

    let (stdout, _stderr) = run_mcp_server(input);

    let lines: Vec<&str> = stdout.lines().collect();
    assert!(
        lines.len() >= 2,
        "Expected at least 2 response lines, got {}: {:?}",
        lines.len(),
        lines
    );

    // Verify initialize response
    let init_resp = parse_response(lines[0]);
    assert_eq!(init_resp["jsonrpc"], "2.0");
    assert_eq!(init_resp["id"], 1);
    assert!(
        init_resp.get("result").is_some(),
        "Initialize should have result"
    );
    assert!(init_resp["result"]["protocolVersion"].is_string());
    assert_eq!(init_resp["result"]["serverInfo"]["name"], "clx-mcp");

    // Verify tools/list response
    let tools_resp = parse_response(lines[1]);
    assert_eq!(tools_resp["jsonrpc"], "2.0");
    assert_eq!(tools_resp["id"], 2);
    assert!(
        tools_resp.get("result").is_some(),
        "tools/list should have result"
    );

    let tools = tools_resp["result"]["tools"]
        .as_array()
        .expect("tools should be an array");
    assert_eq!(tools.len(), 7, "Expected 7 MCP tools");

    let tool_names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
    assert!(tool_names.contains(&"clx_recall"));
    assert!(tool_names.contains(&"clx_remember"));
    assert!(tool_names.contains(&"clx_checkpoint"));
    assert!(tool_names.contains(&"clx_rules"));
    assert!(tool_names.contains(&"clx_session_info"));
    assert!(tool_names.contains(&"clx_credentials"));
    assert!(tool_names.contains(&"clx_stats"));
}

// =========================================================================
// 2. Tool execution: tools/call for clx_session_info
// =========================================================================

#[test]
fn test_mcp_tool_call_session_info() {
    let input = concat!(
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
        "\n",
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"clx_session_info","arguments":{}}}"#,
        "\n",
    );

    let (stdout, _stderr) = run_mcp_server(input);

    let lines: Vec<&str> = stdout.lines().collect();
    assert!(
        lines.len() >= 2,
        "Expected at least 2 response lines, got {}: {:?}",
        lines.len(),
        lines
    );

    // Skip initialize response (line 0), check session_info response
    let call_resp = parse_response(lines[1]);
    assert_eq!(call_resp["jsonrpc"], "2.0");
    assert_eq!(call_resp["id"], 2);
    assert!(
        call_resp.get("result").is_some(),
        "tools/call should have result, got: {call_resp}"
    );
    assert!(call_resp.get("error").is_none(), "Should not have error");

    // Result should contain content array with text
    let content = call_resp["result"]["content"]
        .as_array()
        .expect("result should have content array");
    assert!(!content.is_empty(), "Content should not be empty");
    assert_eq!(content[0]["type"], "text");

    let text = content[0]["text"].as_str().unwrap();
    // The text is JSON-stringified session info
    let info: serde_json::Value =
        serde_json::from_str(text).expect("Session info text should be valid JSON");
    assert!(info.get("db_path").is_some(), "Should include db_path");
    assert!(
        info.get("session_id").is_some(),
        "Should include session_id"
    );
}

// =========================================================================
// 3. Error handling: unknown method
// =========================================================================

#[test]
fn test_mcp_unknown_method_returns_error() {
    let input = concat!(
        r#"{"jsonrpc":"2.0","id":1,"method":"unknown/method","params":{}}"#,
        "\n",
    );

    let (stdout, _stderr) = run_mcp_server(input);

    let lines: Vec<&str> = stdout.lines().collect();
    assert!(!lines.is_empty(), "Should get at least 1 response line");

    let resp = parse_response(lines[0]);
    assert_eq!(resp["jsonrpc"], "2.0");
    assert!(resp.get("error").is_some(), "Should have error");
    assert_eq!(resp["error"]["code"], -32601); // METHOD_NOT_FOUND
}
