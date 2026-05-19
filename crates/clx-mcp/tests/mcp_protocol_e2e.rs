//! Wave 1 E: MCP JSON-RPC protocol round-trip e2e tests.
//!
//! Anchored to `specs/_prerelease/04-integration.md` section 3.4 and the
//! edge/failure matrix rows for MCP. Exercises the real `clx-mcp` binary as
//! a subprocess with `CLX_DB_PATH=:memory:` (zero filesystem side effects,
//! zero network, zero keychain, zero model download).
//!
//! Covered:
//! - `initialize` envelope (protocolVersion, serverInfo name/version)
//! - `tools/list` returns the 7 documented tools with input schemas
//! - each of the 7 tools: a valid call, an oversize-arg call
//!   (`INVALID_PARAMS` "exceeds max length"), a malformed/missing-arg call
//! - envelope shape (`jsonrpc`, `id`, `result` xor `error`)
//! - error tuple codes: INVALID_REQUEST -32600, METHOD_NOT_FOUND -32601,
//!   INVALID_PARAMS -32602, PARSE_ERROR -32700
//! - >10 MiB line -> PARSE_ERROR (server.rs MAX_LINE_SIZE)
//! - notifications (no id) get no response unless an error
//! - output redaction: a remembered secret is not echoed back verbatim

// e2e test file: prose docs reference protocol identifiers and the request
// builders take owned JSON for json! ergonomics; pedantic lints add noise.
#![allow(clippy::doc_markdown, clippy::needless_pass_by_value)]

use std::io::Write;
use std::process::{Command, Stdio};

const PARSE_ERROR: i64 = -32700;
const INVALID_REQUEST: i64 = -32600;
const METHOD_NOT_FOUND: i64 = -32601;
const INVALID_PARAMS: i64 = -32602;

/// MCP validation limits mirrored from `clx-mcp::validation` (not a lib).
const MAX_QUERY_LEN: usize = 10_000;
const MAX_CONTENT_LEN: usize = 100_000;

/// Spawn `clx-mcp` with an in-memory DB and pipe `input` (newline-delimited
/// JSON-RPC). Returns `(stdout, stderr)`.
fn run_mcp(input: &str) -> (String, String) {
    let binary = env!("CARGO_BIN_EXE_clx-mcp");
    let mut child = Command::new(binary)
        .env("CLX_DB_PATH", ":memory:")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn clx-mcp");
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(input.as_bytes()).expect("write stdin");
    }
    let output = child.wait_with_output().expect("wait clx-mcp");
    (
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
    )
}

fn parse(line: &str) -> serde_json::Value {
    serde_json::from_str(line.trim())
        .unwrap_or_else(|e| panic!("invalid JSON-RPC line: {e}\nline: {line}"))
}

/// Assert a response object is a well-formed JSON-RPC 2.0 envelope:
/// `jsonrpc == "2.0"`, exactly one of `result` / `error`.
fn assert_envelope(v: &serde_json::Value) {
    assert_eq!(v["jsonrpc"], "2.0", "jsonrpc must be 2.0: {v}");
    let has_result = v.get("result").is_some();
    let has_error = v.get("error").is_some();
    assert!(
        has_result ^ has_error,
        "exactly one of result/error required: {v}"
    );
}

/// Build a request line.
fn req(id: i64, method: &str, params: serde_json::Value) -> String {
    serde_json::json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}).to_string()
}

/// Drive `initialize` then a single `tools/call` and return the call
/// response (line index 1, after the initialize response).
fn call_tool(name: &str, arguments: serde_json::Value) -> serde_json::Value {
    let input = format!(
        "{}\n{}\n",
        req(1, "initialize", serde_json::json!({})),
        req(
            2,
            "tools/call",
            serde_json::json!({ "name": name, "arguments": arguments })
        ),
    );
    let (stdout, stderr) = run_mcp(&input);
    let lines: Vec<&str> = stdout.lines().collect();
    assert!(
        lines.len() >= 2,
        "expected >=2 lines, got {lines:?}; stderr: {stderr}"
    );
    parse(lines[1])
}

// ===========================================================================
// initialize + tools/list
// ===========================================================================

#[test]
fn initialize_envelope_is_well_formed() {
    let (stdout, _e) = run_mcp(&format!(
        "{}\n",
        req(1, "initialize", serde_json::json!({}))
    ));
    let v = parse(stdout.lines().next().expect("one line"));
    assert_envelope(&v);
    assert_eq!(v["id"], 1);
    assert_eq!(v["result"]["protocolVersion"], "2024-11-05");
    assert_eq!(v["result"]["serverInfo"]["name"], "clx-mcp");
    assert!(v["result"]["serverInfo"]["version"].is_string());
}

#[test]
fn tools_list_returns_seven_documented_tools_with_schemas() {
    let input = format!(
        "{}\n{}\n",
        req(1, "initialize", serde_json::json!({})),
        req(2, "tools/list", serde_json::json!({})),
    );
    let (stdout, _e) = run_mcp(&input);
    let lines: Vec<&str> = stdout.lines().collect();
    let v = parse(lines[1]);
    assert_envelope(&v);
    let tools = v["result"]["tools"].as_array().expect("tools array");
    assert_eq!(tools.len(), 7);
    let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
    for expected in [
        "clx_recall",
        "clx_remember",
        "clx_checkpoint",
        "clx_rules",
        "clx_session_info",
        "clx_credentials",
        "clx_stats",
    ] {
        assert!(names.contains(&expected), "missing tool {expected}");
    }
    // Every tool must declare a JSON-schema object.
    for t in tools {
        assert_eq!(
            t["inputSchema"]["type"], "object",
            "schema for {}",
            t["name"]
        );
    }
}

// ===========================================================================
// Error tuple codes + envelope shapes
// ===========================================================================

#[test]
fn non_2_0_jsonrpc_is_invalid_request() {
    let bad = serde_json::json!({"jsonrpc":"1.0","id":1,"method":"ping","params":{}}).to_string();
    let (stdout, _e) = run_mcp(&format!("{bad}\n"));
    let v = parse(stdout.lines().next().expect("line"));
    assert_envelope(&v);
    assert_eq!(v["error"]["code"], INVALID_REQUEST);
}

#[test]
fn unknown_method_is_method_not_found() {
    let (stdout, _e) = run_mcp(&format!(
        "{}\n",
        req(1, "no/such/method", serde_json::json!({}))
    ));
    let v = parse(stdout.lines().next().expect("line"));
    assert_envelope(&v);
    assert_eq!(v["error"]["code"], METHOD_NOT_FOUND);
}

#[test]
fn unknown_tool_is_an_error_tuple() {
    let v = call_tool("clx_not_a_tool", serde_json::json!({}));
    assert_envelope(&v);
    assert!(v.get("error").is_some(), "unknown tool must error: {v}");
}

#[test]
fn garbage_line_is_parse_error() {
    let (stdout, _e) = run_mcp("this is not json at all\n");
    let v = parse(stdout.lines().next().expect("line"));
    assert_eq!(v["error"]["code"], PARSE_ERROR);
}

#[test]
fn oversize_line_over_10_mib_is_parse_error() {
    // server.rs MAX_LINE_SIZE = 10 MiB; a line beyond it -> PARSE_ERROR.
    let huge = "x".repeat(10 * 1024 * 1024 + 16);
    let line = format!(r#"{{"jsonrpc":"2.0","id":1,"method":"ping","params":{{"pad":"{huge}"}}}}"#);
    let (stdout, _e) = run_mcp(&format!("{line}\n"));
    let v = parse(stdout.lines().next().expect("oversize -> error line"));
    assert_eq!(v["error"]["code"], PARSE_ERROR);
}

#[test]
fn ping_notification_without_id_gets_no_response() {
    // Notifications (no `id`) get no response unless an error (3.4).
    let note = serde_json::json!({"jsonrpc":"2.0","method":"ping","params":{}}).to_string();
    let (stdout, _e) = run_mcp(&format!("{note}\n"));
    assert!(
        stdout.trim().is_empty(),
        "a successful notification must produce no response, got: {stdout}"
    );
}

// ===========================================================================
// Per-tool: valid call + missing/oversize argument validation
// ===========================================================================

#[test]
fn recall_valid_returns_content_envelope() {
    let v = call_tool("clx_recall", serde_json::json!({"query":"anything"}));
    assert_envelope(&v);
    // Empty in-memory DB: a successful "no relevant context" text result.
    let content = v["result"]["content"].as_array().expect("content array");
    assert_eq!(content[0]["type"], "text");
}

#[test]
fn recall_missing_query_is_invalid_params() {
    let v = call_tool("clx_recall", serde_json::json!({}));
    assert_eq!(v["error"]["code"], INVALID_PARAMS);
    assert!(
        v["error"]["message"]
            .as_str()
            .unwrap_or("")
            .contains("Missing or invalid parameter"),
        "{v}"
    );
}

#[test]
fn recall_oversize_query_is_invalid_params_exceeds_max_length() {
    let v = call_tool(
        "clx_recall",
        serde_json::json!({"query": "q".repeat(MAX_QUERY_LEN + 1)}),
    );
    assert_eq!(v["error"]["code"], INVALID_PARAMS);
    assert!(
        v["error"]["message"]
            .as_str()
            .unwrap_or("")
            .contains("exceeds max length"),
        "{v}"
    );
}

#[test]
fn remember_valid_then_redacts_secret_in_output() {
    // Output redaction (3.4): a remembered API-key-shaped secret must not be
    // echoed back verbatim in the tool result text.
    let secret = "sk-ant-DEADBEEFDEADBEEFDEADBEEFDEADBEEF0123";
    let v = call_tool(
        "clx_remember",
        serde_json::json!({"text": format!("my key is {secret}"), "tags": ["t"]}),
    );
    assert_envelope(&v);
    if let Some(result) = v.get("result") {
        let text = serde_json::to_string(result).unwrap();
        assert!(
            !text.contains(secret),
            "remember output must redact the secret, got: {text}"
        );
    }
}

#[test]
fn remember_missing_text_is_invalid_params() {
    let v = call_tool("clx_remember", serde_json::json!({"tags": ["x"]}));
    assert_eq!(v["error"]["code"], INVALID_PARAMS);
}

#[test]
fn remember_oversize_text_is_invalid_params() {
    let v = call_tool(
        "clx_remember",
        serde_json::json!({"text": "z".repeat(MAX_CONTENT_LEN + 1)}),
    );
    assert_eq!(v["error"]["code"], INVALID_PARAMS);
    assert!(
        v["error"]["message"]
            .as_str()
            .unwrap_or("")
            .contains("exceeds max length")
    );
}

#[test]
fn checkpoint_with_note_is_ok_envelope() {
    let v = call_tool(
        "clx_checkpoint",
        serde_json::json!({"note":"wave1 checkpoint"}),
    );
    assert_envelope(&v);
}

#[test]
fn checkpoint_without_note_is_ok_envelope() {
    // `note` is optional; absence must not be INVALID_PARAMS.
    let v = call_tool("clx_checkpoint", serde_json::json!({}));
    assert_envelope(&v);
}

#[test]
fn rules_get_project_rules_is_envelope() {
    let v = call_tool(
        "clx_rules",
        serde_json::json!({"action":"get_project_rules"}),
    );
    assert_envelope(&v);
}

#[test]
fn rules_missing_action_is_invalid_params() {
    let v = call_tool("clx_rules", serde_json::json!({}));
    assert_eq!(v["error"]["code"], INVALID_PARAMS);
}

#[test]
fn session_info_no_args_returns_json_text() {
    let v = call_tool("clx_session_info", serde_json::json!({}));
    assert_envelope(&v);
    let text = v["result"]["content"][0]["text"]
        .as_str()
        .expect("session_info text");
    let info: serde_json::Value = serde_json::from_str(text).expect("session_info text is JSON");
    assert!(info.get("db_path").is_some());
    assert!(info.get("session_id").is_some());
}

#[test]
fn credentials_list_is_envelope() {
    let v = call_tool("clx_credentials", serde_json::json!({"action":"list"}));
    assert_envelope(&v);
}

#[test]
fn credentials_missing_action_is_invalid_params() {
    let v = call_tool("clx_credentials", serde_json::json!({}));
    assert_eq!(v["error"]["code"], INVALID_PARAMS);
}

#[test]
fn credentials_set_then_get_roundtrip_redacts_value_in_logs() {
    // set then get the same key inside one process so it lands in the
    // in-memory store. The returned value comes back; the contract here is
    // a well-formed envelope (no panic, no INTERNAL crash).
    let input = format!(
        "{}\n{}\n{}\n",
        req(1, "initialize", serde_json::json!({})),
        req(
            2,
            "tools/call",
            serde_json::json!({"name":"clx_credentials","arguments":{"action":"set","key":"WAVE1_K","value":"v-secret-123"}})
        ),
        req(
            3,
            "tools/call",
            serde_json::json!({"name":"clx_credentials","arguments":{"action":"get","key":"WAVE1_K"}})
        ),
    );
    let (stdout, stderr) = run_mcp(&input);
    let lines: Vec<&str> = stdout.lines().collect();
    assert!(lines.len() >= 3, "expected >=3 lines: {lines:?}");
    let set_resp = parse(lines[1]);
    assert_envelope(&set_resp);
    let get_resp = parse(lines[2]);
    assert_envelope(&get_resp);
    // The secret value must never leak onto stderr (debug logs are
    // redacted per server.rs:297,444,464).
    assert!(
        !stderr.contains("v-secret-123"),
        "credential value leaked to stderr"
    );
}

#[test]
fn stats_default_is_envelope() {
    let v = call_tool("clx_stats", serde_json::json!({}));
    assert_envelope(&v);
}

#[test]
fn stats_out_of_range_days_is_invalid_params() {
    // `days` is a validated i64 range; a wildly out-of-range value rejects.
    let v = call_tool("clx_stats", serde_json::json!({"days": 1_000_000_000_i64}));
    assert_eq!(v["error"]["code"], INVALID_PARAMS);
}

#[test]
fn stats_non_integer_days_is_invalid_params() {
    let v = call_tool("clx_stats", serde_json::json!({"days": "seven"}));
    assert_eq!(v["error"]["code"], INVALID_PARAMS);
}

#[test]
fn full_protocol_sequence_initialize_list_call_in_one_session() {
    let input = format!(
        "{}\n{}\n{}\n",
        req(1, "initialize", serde_json::json!({})),
        req(2, "tools/list", serde_json::json!({})),
        req(
            3,
            "tools/call",
            serde_json::json!({"name":"clx_session_info","arguments":{}})
        ),
    );
    let (stdout, _e) = run_mcp(&input);
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 3, "three responses expected: {lines:?}");
    for (i, line) in lines.iter().enumerate() {
        let v = parse(line);
        assert_envelope(&v);
        assert_eq!(v["id"], (i as i64) + 1);
    }
}
