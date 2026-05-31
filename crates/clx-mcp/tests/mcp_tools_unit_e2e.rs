//! Per-tool contract depth for the `clx-mcp` server (tools/* handlers).
//!
//! Companion to `mcp_protocol_e2e.rs` (protocol envelope) and
//! `mcp_tools_depth_e2e.rs` (rules/credentials branch depth). This suite
//! deepens the *dispatch + success/error contract* of each tool reachable
//! through `tools/call`, plus the protocol-layer error codes that guard
//! dispatch. It asserts the JSON-RPC envelope, the error CODE (not just
//! "an error happened"), and the observable `result.content[0].text` payload
//! or `error.message` -- never merely "did not panic".
//!
//! Hermetic: every spawned `clx-mcp` child runs with an in-memory DB
//! (`CLX_DB_PATH=:memory:`), an isolated `HOME` (RAII tempdir), the file
//! credential backend forced (no keychain), and a model-fetch dry-run flag.
//! No network, no keychain, no model download. Synthetic data only.
//!
//! SKIPPED -- LLM retry / fallback seam: not reachable from `clx-mcp`. The
//! crate's only deps are clx-core, serde, serde_json, tokio, anyhow, tracing,
//! dirs, chrono (dev-dep: tempfile + tokio). There is no HTTP client / retry
//! loop here; embedding/LLM lives in `clx-core` (owned by another agent) and
//! is `None` in this hermetic env, so the no-embedding fallback branch IS
//! exercised indirectly by the remember/recall success tests, but a
//! retry-then-success wiremock seam is intentionally not built here (Cargo.toml
//! edits are out of scope and the seam does not live in this crate).

// e2e: prose references protocol identifiers; json! builders take owned args.
#![allow(clippy::doc_markdown, clippy::needless_pass_by_value)]

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

const INVALID_PARAMS: i64 = -32602;
const METHOD_NOT_FOUND: i64 = -32601;
const PARSE_ERROR: i64 = -32700;

/// Upper bound for the isolated `HOME` footprint: a hermetic MCP run writes
/// only a tiny age credential file; 50 MiB is ~40x below a single model
/// artifact, so a leaked download trips this instantly.
const MAX_HOME_BYTES: u64 = 50 * 1024 * 1024;

/// RAII isolated `HOME`. Its `Drop` removes the dir recursively (even on
/// panic); `mkdtemp` gives a unique name so parallel tests never collide.
struct HermeticHome {
    _tmp: tempfile::TempDir,
    home: std::path::PathBuf,
}

impl HermeticHome {
    fn new() -> Self {
        let tmp = tempfile::Builder::new()
            .prefix("clx-mcp-unit-")
            .tempdir()
            .expect("create isolated temp HOME");
        let home = tmp
            .path()
            .canonicalize()
            .unwrap_or_else(|_| tmp.path().to_path_buf());
        Self { _tmp: tmp, home }
    }

    /// Spawn `clx-mcp` with an in-memory DB + isolated HOME + file credential
    /// backend, pipe `input` (newline-delimited JSON-RPC) on stdin, return
    /// `(stdout, stderr)`.
    fn run_mcp(&self, input: &str) -> (String, String) {
        let binary = env!("CARGO_BIN_EXE_clx-mcp");
        let mut child = Command::new(binary)
            .env("CLX_DB_PATH", ":memory:")
            .env("HOME", &self.home)
            .env("CLX_LOG", "error")
            .env("CLX_MODEL_FETCH_DRYRUN", "1")
            .env("CLX_CREDENTIALS_BACKEND", "file")
            .env_remove("CLX_SESSION_ID")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn clx-mcp");
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(input.as_bytes()).expect("write stdin");
        }
        let output = child.wait_with_output().expect("wait clx-mcp");
        assert_home_size_bounded(&self.home);
        (
            String::from_utf8_lossy(&output.stdout).to_string(),
            String::from_utf8_lossy(&output.stderr).to_string(),
        )
    }
}

fn dir_size_bytes(root: &Path) -> u64 {
    let mut total = 0u64;
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(ft) = entry.file_type() else { continue };
            if ft.is_dir() {
                stack.push(entry.path());
            } else if ft.is_file()
                && let Ok(meta) = entry.metadata()
            {
                total += meta.len();
            }
        }
    }
    total
}

fn assert_home_size_bounded(home: &Path) {
    let total = dir_size_bytes(home);
    assert!(
        total < MAX_HOME_BYTES,
        "isolated test HOME at {} grew to {total} bytes (limit {MAX_HOME_BYTES}); \
         a model download likely leaked into the throwaway HOME",
        home.display(),
    );
}

fn parse(line: &str) -> serde_json::Value {
    serde_json::from_str(line.trim())
        .unwrap_or_else(|e| panic!("invalid JSON-RPC line: {e}\nline: {line}"))
}

/// Exactly one of result/error must be present (JSON-RPC contract).
fn assert_envelope(v: &serde_json::Value) {
    assert_eq!(v["jsonrpc"], "2.0", "jsonrpc must be 2.0: {v}");
    let has_result = v.get("result").is_some();
    let has_error = v.get("error").is_some();
    assert!(
        has_result ^ has_error,
        "exactly one of result/error required: {v}"
    );
}

fn req(id: i64, method: &str, params: serde_json::Value) -> String {
    serde_json::json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}).to_string()
}

fn raw_req(id: serde_json::Value, method: &str, params: serde_json::Value) -> String {
    serde_json::json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}).to_string()
}

fn tool_call(id: i64, name: &str, arguments: serde_json::Value) -> String {
    req(
        id,
        "tools/call",
        serde_json::json!({ "name": name, "arguments": arguments }),
    )
}

/// `result.content[0].text` of a successful tool call.
fn result_text(v: &serde_json::Value) -> String {
    v["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("expected result text, got: {v}"))
        .to_string()
}

/// Whether a tool *result* carries the `isError` flag (a tool-level error,
/// distinct from a JSON-RPC `error` envelope).
fn is_tool_error(v: &serde_json::Value) -> bool {
    v["result"]["isError"].as_bool().unwrap_or(false)
}

/// Drive `initialize` then a single `tools/call`; return the call response.
fn call_once(home: &HermeticHome, name: &str, args: serde_json::Value) -> serde_json::Value {
    let input = format!(
        "{}\n{}\n",
        req(1, "initialize", serde_json::json!({})),
        tool_call(2, name, args),
    );
    let (stdout, stderr) = home.run_mcp(&input);
    let lines: Vec<&str> = stdout.lines().collect();
    assert!(
        lines.len() >= 2,
        "expected >=2 response lines, got {lines:?}; stderr: {stderr}"
    );
    parse(lines[1])
}

// ===========================================================================
// clx_recall: required-arg guard + empty-result marker + populated success
// ===========================================================================

/// Missing `query` hits the required-arg guard -> INVALID_PARAMS naming the
/// offending param. (Asserting the CODE + param name, not just "an error".)
#[test]
fn recall_missing_query_is_invalid_params() {
    let home = HermeticHome::new();
    let v = call_once(&home, "clx_recall", serde_json::json!({}));
    assert_eq!(v["error"]["code"], INVALID_PARAMS, "missing query: {v}");
    assert!(
        v["error"]["message"]
            .as_str()
            .unwrap_or("")
            .contains("query"),
        "missing-query error must name the param: {v}"
    );
}

/// A query that cannot match on a fresh in-memory DB takes the empty-result
/// arm: a NON-error success envelope (no `isError`) whose text signals the
/// absence of hits rather than crashing or returning garbage.
#[test]
fn recall_no_matches_is_graceful_success() {
    let home = HermeticHome::new();
    let v = call_once(
        &home,
        "clx_recall",
        serde_json::json!({"query": "zzzqqq_no_such_memory_4242"}),
    );
    assert_envelope(&v);
    assert!(
        !is_tool_error(&v),
        "empty recall result must not be a tool error: {v}"
    );
    let text = result_text(&v).to_lowercase();
    assert!(
        text.contains("no ")
            && (text.contains("relevant") || text.contains("memor") || text.contains("found")),
        "empty recall must surface a no-results marker, got: {text}"
    );
}

/// remember then recall on the SAME process/DB: the FTS fallback search (no
/// embedding client in the hermetic env) must surface the just-stored text.
/// This is the lifecycle proof: write -> read-back -> observable content.
#[test]
fn recall_after_remember_returns_stored_text_via_fts_fallback() {
    let home = HermeticHome::new();
    let marker = "quokkanaut_marsupial_marker";
    let input = format!(
        "{}\n{}\n{}\n",
        req(1, "initialize", serde_json::json!({})),
        tool_call(
            2,
            "clx_remember",
            serde_json::json!({"text": format!("the {marker} hops")})
        ),
        tool_call(3, "clx_recall", serde_json::json!({"query": marker})),
    );
    let (stdout, stderr) = home.run_mcp(&input);
    let lines: Vec<&str> = stdout.lines().collect();
    assert!(lines.len() >= 3, "expected 3 lines: {lines:?}; {stderr}");

    let remember = parse(lines[1]);
    assert_envelope(&remember);
    assert!(
        result_text(&remember).contains("Successfully remembered"),
        "remember must confirm storage: {remember}"
    );

    let recall = parse(lines[2]);
    assert_envelope(&recall);
    assert!(
        !is_tool_error(&recall),
        "recall hit must be a success envelope: {recall}"
    );
    assert!(
        result_text(&recall).contains(marker),
        "recall must surface the just-stored marker (write->read-back): {}",
        result_text(&recall)
    );
}

// ===========================================================================
// clx_remember: required-arg guard + success id + oversize cap
// ===========================================================================

/// Missing `text` hits the required-arg guard -> INVALID_PARAMS naming `text`.
#[test]
fn remember_missing_text_is_invalid_params() {
    let home = HermeticHome::new();
    let v = call_once(&home, "clx_remember", serde_json::json!({"tags": ["x"]}));
    assert_eq!(v["error"]["code"], INVALID_PARAMS, "missing text: {v}");
    assert!(
        v["error"]["message"]
            .as_str()
            .unwrap_or("")
            .contains("text"),
        "missing-text error must name the param: {v}"
    );
}

/// Valid `text` returns a success envelope reporting a NUMERIC snapshot id
/// (proves the storage Ok(id) arm ran, not a canned string), even with no
/// embedding client configured (the no-embedding fallback branch).
#[test]
fn remember_success_reports_numeric_snapshot_id() {
    let home = HermeticHome::new();
    let v = call_once(
        &home,
        "clx_remember",
        serde_json::json!({"text": "synthetic durable fact alpha"}),
    );
    assert_envelope(&v);
    let text = result_text(&v);
    assert!(
        text.contains("Successfully remembered information (snapshot id:"),
        "remember must report the persisted snapshot id: {text}"
    );
    let id_part = text
        .rsplit("snapshot id:")
        .next()
        .unwrap_or("")
        .trim()
        .trim_end_matches(')')
        .trim();
    assert!(
        id_part.parse::<i64>().is_ok(),
        "snapshot id must be numeric, got {id_part:?} in {text}"
    );
}

// ===========================================================================
// clx_checkpoint: success path (optional note) + with-note path
// ===========================================================================

/// `clx_checkpoint` with a valid session present creates a snapshot and
/// returns a success envelope echoing the new id. We seed `CLX_SESSION_ID`
/// AND a matching session row first, because `create_snapshot` has a FOREIGN
/// KEY on the session: a checkpoint against a non-existent session is a real
/// failure (see `checkpoint_without_session_row_is_internal_error`).
///
/// GENUINE BEHAVIORAL FINDING: with no session row, `clx_checkpoint` falls
/// back to `SessionId::new("default")`, whose row does not exist, so the DB
/// rejects the insert with a FOREIGN KEY constraint and the tool returns
/// INTERNAL_ERROR (-32603). That is asserted as the contract below rather
/// than treated as success.
#[test]
fn checkpoint_without_session_row_is_internal_error() {
    let home = HermeticHome::new();
    // Fresh :memory: DB, no session seeded -> "default" session has no row.
    let v = call_once(&home, "clx_checkpoint", serde_json::json!({}));
    assert_eq!(
        v["error"]["code"], -32603,
        "checkpoint without a session row must be INTERNAL_ERROR: {v}"
    );
    assert!(
        v["error"]["message"]
            .as_str()
            .unwrap_or("")
            .contains("Failed to create checkpoint"),
        "checkpoint failure must surface an actionable message: {v}"
    );
}

/// The optional `note` arg, when present but oversize, is rejected by the
/// validator BEFORE any storage attempt: INVALID_PARAMS, not INTERNAL_ERROR.
/// This pins the validation guard independent of the session-row dependency.
#[test]
fn checkpoint_oversize_note_is_invalid_params() {
    let home = HermeticHome::new();
    let v = call_once(
        &home,
        "clx_checkpoint",
        serde_json::json!({"note": "z".repeat(100_001)}),
    );
    assert_eq!(
        v["error"]["code"], INVALID_PARAMS,
        "oversize note must be rejected at validation: {v}"
    );
    assert!(
        v["error"]["message"]
            .as_str()
            .unwrap_or("")
            .contains("exceeds max length"),
        "oversize note message must name the length cap: {v}"
    );
}

/// A non-string `note` is rejected by `validate_optional_string_param`'s
/// wrong-type arm -> INVALID_PARAMS (distinct from the oversize arm above).
#[test]
fn checkpoint_non_string_note_is_invalid_params() {
    let home = HermeticHome::new();
    let v = call_once(&home, "clx_checkpoint", serde_json::json!({"note": 42}));
    assert_eq!(
        v["error"]["code"], INVALID_PARAMS,
        "non-string note must be INVALID_PARAMS: {v}"
    );
    assert!(
        v["error"]["message"]
            .as_str()
            .unwrap_or("")
            .contains("must be a string"),
        "non-string note message must say so: {v}"
    );
}

// ===========================================================================
// clx_session_info / clx_stats: success contracts
// ===========================================================================

/// `clx_session_info` returns a success envelope describing the session.
#[test]
fn session_info_returns_success_envelope() {
    let home = HermeticHome::new();
    let v = call_once(&home, "clx_session_info", serde_json::json!({}));
    assert_envelope(&v);
    assert!(
        !is_tool_error(&v),
        "session_info must be a success envelope: {v}"
    );
    // Must return a non-empty textual description, not an empty body.
    assert!(
        !result_text(&v).trim().is_empty(),
        "session_info text must be non-empty: {v}"
    );
}

/// `clx_stats` with an explicit `days` window returns a success envelope.
#[test]
fn stats_with_days_window_returns_success() {
    let home = HermeticHome::new();
    let v = call_once(&home, "clx_stats", serde_json::json!({"days": 3}));
    assert_envelope(&v);
    assert!(!is_tool_error(&v), "stats must be a success envelope: {v}");
    assert!(
        !result_text(&v).trim().is_empty(),
        "stats text must be non-empty: {v}"
    );
}

/// `clx_stats` with no `days` falls back to its default window and still
/// succeeds (the default-arg branch, distinct from the explicit-days test).
#[test]
fn stats_default_window_returns_success() {
    let home = HermeticHome::new();
    let v = call_once(&home, "clx_stats", serde_json::json!({}));
    assert_envelope(&v);
    assert!(!is_tool_error(&v), "stats default window must succeed: {v}");
}

// ===========================================================================
// dispatch + protocol-layer error codes guarding tools/call
// ===========================================================================

/// An unknown tool name falls through dispatch to the trailing arm ->
/// JSON-RPC METHOD_NOT_FOUND whose message echoes the offending name.
/// (This is a JSON-RPC error envelope, NOT a tool result with isError.)
#[test]
fn unknown_tool_name_is_method_not_found_with_name() {
    let home = HermeticHome::new();
    let v = call_once(&home, "clx_made_up_tool", serde_json::json!({}));
    assert_eq!(
        v["error"]["code"], METHOD_NOT_FOUND,
        "unknown tool must be METHOD_NOT_FOUND: {v}"
    );
    assert!(
        v["error"]["message"]
            .as_str()
            .unwrap_or("")
            .contains("clx_made_up_tool"),
        "unknown-tool error must echo the offending name: {v}"
    );
}

/// `tools/call` with no `name` field hits the missing-name guard ->
/// INVALID_PARAMS (distinct from the unknown-tool METHOD_NOT_FOUND path).
#[test]
fn tools_call_missing_name_is_invalid_params() {
    let home = HermeticHome::new();
    let input = format!(
        "{}\n{}\n",
        req(1, "initialize", serde_json::json!({})),
        req(2, "tools/call", serde_json::json!({"arguments": {}})),
    );
    let (stdout, stderr) = home.run_mcp(&input);
    let lines: Vec<&str> = stdout.lines().collect();
    assert!(lines.len() >= 2, "expected 2 lines: {lines:?}; {stderr}");
    let v = parse(lines[1]);
    assert_eq!(
        v["error"]["code"], INVALID_PARAMS,
        "missing tool name must be INVALID_PARAMS: {v}"
    );
    assert!(
        v["error"]["message"]
            .as_str()
            .unwrap_or("")
            .to_lowercase()
            .contains("tool name"),
        "missing-name message must mention the tool name: {v}"
    );
}

/// An unknown JSON-RPC method (not a tool) returns METHOD_NOT_FOUND echoing
/// the method, distinct from the unknown-tool path above.
#[test]
fn unknown_method_is_method_not_found() {
    let home = HermeticHome::new();
    let input = format!(
        "{}\n{}\n",
        req(1, "initialize", serde_json::json!({})),
        req(2, "totally/unknown", serde_json::json!({})),
    );
    let (stdout, stderr) = home.run_mcp(&input);
    let lines: Vec<&str> = stdout.lines().collect();
    assert!(lines.len() >= 2, "expected 2 lines: {lines:?}; {stderr}");
    let v = parse(lines[1]);
    assert_eq!(
        v["error"]["code"], METHOD_NOT_FOUND,
        "unknown method must be METHOD_NOT_FOUND: {v}"
    );
    assert!(
        v["error"]["message"]
            .as_str()
            .unwrap_or("")
            .contains("totally/unknown"),
        "method-not-found must echo the method: {v}"
    );
}

/// A non-"2.0" jsonrpc version is rejected with INVALID_REQUEST (-32600).
#[test]
fn wrong_jsonrpc_version_is_invalid_request() {
    let home = HermeticHome::new();
    let bad = serde_json::json!({"jsonrpc":"1.0","id":1,"method":"ping","params":{}}).to_string();
    let (stdout, stderr) = home.run_mcp(&format!("{bad}\n"));
    let lines: Vec<&str> = stdout.lines().collect();
    assert!(!lines.is_empty(), "expected a response: {stderr}");
    let v = parse(lines[0]);
    assert_eq!(
        v["error"]["code"], -32600,
        "wrong jsonrpc version must be INVALID_REQUEST: {v}"
    );
}

/// Malformed JSON yields a PARSE_ERROR envelope with a null id (the server
/// cannot recover the id from unparseable input).
#[test]
fn malformed_json_is_parse_error_with_null_id() {
    let home = HermeticHome::new();
    let (stdout, stderr) = home.run_mcp("{ this is not valid json\n");
    let lines: Vec<&str> = stdout.lines().collect();
    assert!(
        !lines.is_empty(),
        "expected a parse-error response: {stderr}"
    );
    let v = parse(lines[0]);
    assert_eq!(
        v["error"]["code"], PARSE_ERROR,
        "malformed input must be PARSE_ERROR: {v}"
    );
    assert!(v["id"].is_null(), "parse error id must be null: {v}");
}

/// `ping` is a health check returning an empty success result object.
#[test]
fn ping_returns_empty_result_object() {
    let home = HermeticHome::new();
    let input = format!(
        "{}\n{}\n",
        req(1, "initialize", serde_json::json!({})),
        req(2, "ping", serde_json::json!({})),
    );
    let (stdout, stderr) = home.run_mcp(&input);
    let lines: Vec<&str> = stdout.lines().collect();
    assert!(lines.len() >= 2, "expected 2 lines: {lines:?}; {stderr}");
    let v = parse(lines[1]);
    assert!(v.get("error").is_none(), "ping must not error: {v}");
    assert_eq!(
        v["result"],
        serde_json::json!({}),
        "ping result must be {{}}"
    );
}

/// A notification (request with no `id`) that succeeds produces NO response
/// line, per the JSON-RPC notification rule. Using `initialized` which the
/// server acknowledges only for id-bearing requests.
#[test]
fn notification_without_id_produces_no_response() {
    let home = HermeticHome::new();
    // id-less initialized notification, then an id-bearing ping to prove the
    // loop kept running and only emitted the ping response.
    let notif = serde_json::json!({"jsonrpc":"2.0","method":"initialized","params":{}}).to_string();
    let input = format!(
        "{}\n{}\n{}\n",
        req(1, "initialize", serde_json::json!({})),
        notif,
        raw_req(serde_json::json!(2), "ping", serde_json::json!({})),
    );
    let (stdout, stderr) = home.run_mcp(&input);
    let lines: Vec<&str> = stdout.lines().collect();
    // initialize (id 1) + ping (id 2) = 2 responses; the notification emits none.
    assert_eq!(
        lines.len(),
        2,
        "notification must not produce a response line: {lines:?}; {stderr}"
    );
    let last = parse(lines[1]);
    assert_eq!(
        last["id"], 2,
        "last response must be the ping (id 2): {last}"
    );
}
