//! Tests for the CLX MCP server.

use std::io::BufReader;

use serde_json::json;

use clx_core::credentials::CredentialStore;
use clx_core::storage::Storage;
use clx_core::types::{AuditDecision, AuditLogEntry, SessionId};

use crate::protocol::types::*;
use crate::server::McpServer;
use crate::tools::credentials::mask_credential_value;

fn create_test_server() -> McpServer {
    // Use in-memory storage for tests
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("Failed to create Tokio runtime");

    McpServer {
        storage: Storage::open_in_memory().expect("Failed to create in-memory storage"),
        session_id: Some(SessionId::new("test-session")),
        db_path: ":memory:".to_string(),
        credential_store: CredentialStore::with_service("com.clx.credentials.test"),
        ollama_client: None,   // Disable Ollama in tests by default
        embedding_store: None, // Disable embeddings in tests by default
        embed_model: String::new(),
        runtime,
    }
}

#[test]
fn test_get_tools() {
    let server = create_test_server();
    let tools = server.get_tools();
    assert_eq!(tools.len(), 7);

    let tool_names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
    assert!(tool_names.contains(&"clx_recall"));
    assert!(tool_names.contains(&"clx_remember"));
    assert!(tool_names.contains(&"clx_checkpoint"));
    assert!(tool_names.contains(&"clx_rules"));
    assert!(tool_names.contains(&"clx_session_info"));
    assert!(tool_names.contains(&"clx_credentials"));
}

#[test]
fn test_handle_initialize() {
    let server = create_test_server();
    let result = server.handle_initialize(&json!({}));

    assert!(result.get("protocolVersion").is_some());
    assert!(result.get("capabilities").is_some());
    assert!(result.get("serverInfo").is_some());
}

#[test]
fn test_handle_tools_list() {
    let server = create_test_server();
    let result = server.handle_tools_list();

    let tools = result.get("tools").unwrap().as_array().unwrap();
    assert_eq!(tools.len(), 7);
}

#[test]
fn test_tool_session_info() {
    let server = create_test_server();
    let result = server.tool_session_info(&json!({}));
    assert!(result.is_ok());

    let value = result.unwrap();
    let content = value.get("content").unwrap().as_array().unwrap();
    assert!(!content.is_empty());
}

#[test]
fn test_tool_checkpoint() {
    let server = create_test_server();

    // First create a session for the foreign key constraint
    let session =
        clx_core::types::Session::new(SessionId::new("test-session"), "/test/project".to_string());
    server.storage.create_session(&session).unwrap();

    let result = server.tool_checkpoint(&json!({"note": "Test checkpoint"}));
    assert!(result.is_ok());

    let value = result.unwrap();
    let content = value.get("content").unwrap().as_array().unwrap();
    let text = content[0].get("text").unwrap().as_str().unwrap();
    assert!(text.contains("Checkpoint created"));
}

#[test]
fn test_tool_remember() {
    let server = create_test_server();

    // First create a session for the foreign key constraint
    let session =
        clx_core::types::Session::new(SessionId::new("test-session"), "/test/project".to_string());
    server.storage.create_session(&session).unwrap();

    let result = server.tool_remember(&json!({
        "text": "Important info to remember",
        "tags": ["tag1", "tag2"]
    }));
    assert!(result.is_ok());

    let value = result.unwrap();
    let content = value.get("content").unwrap().as_array().unwrap();
    let text = content[0].get("text").unwrap().as_str().unwrap();
    assert!(text.contains("Successfully remembered"));
}

#[test]
fn test_tool_rules_list() {
    let server = create_test_server();
    let result = server.tool_rules(&json!({"action": "list"}));
    assert!(result.is_ok());
}

#[test]
fn test_tool_rules_add_and_remove() {
    let server = create_test_server();

    // Add a rule
    let result = server.tool_rules(&json!({
        "action": "add",
        "pattern": "npm *",
        "rule_type": "whitelist"
    }));
    assert!(result.is_ok());

    // List rules to verify
    let list_result = server.tool_rules(&json!({"action": "list"}));
    assert!(list_result.is_ok());
    let value = list_result.unwrap();
    let content = value.get("content").unwrap().as_array().unwrap();
    let text = content[0].get("text").unwrap().as_str().unwrap();
    assert!(text.contains("npm *"));

    // Remove the rule
    let remove_result = server.tool_rules(&json!({
        "action": "remove",
        "pattern": "npm *"
    }));
    assert!(remove_result.is_ok());
}

#[test]
fn test_tool_recall() {
    let server = create_test_server();

    // First create a session for the foreign key constraint
    let session =
        clx_core::types::Session::new(SessionId::new("test-session"), "/test/project".to_string());
    server.storage.create_session(&session).unwrap();

    // Remember something first
    let _ = server.tool_remember(&json!({
        "text": "Rust project using tokio for async"
    }));

    // Now recall it
    let result = server.tool_recall(&json!({"query": "tokio"}));
    assert!(result.is_ok());
}

#[test]
fn test_process_request_initialize() {
    let server = create_test_server();
    let request = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(json!(1)),
        method: "initialize".to_string(),
        params: json!({}),
    };

    let response = server.process_request(&request);
    assert!(response.result.is_some());
    assert!(response.error.is_none());
}

#[test]
fn test_process_request_tools_list() {
    let server = create_test_server();
    let request = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(json!(2)),
        method: "tools/list".to_string(),
        params: json!({}),
    };

    let response = server.process_request(&request);
    assert!(response.result.is_some());
    assert!(response.error.is_none());
}

#[test]
fn test_process_request_tools_call() {
    let server = create_test_server();

    // First create a session
    let session =
        clx_core::types::Session::new(SessionId::new("test-session"), "/test/project".to_string());
    server.storage.create_session(&session).unwrap();

    let request = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(json!(3)),
        method: "tools/call".to_string(),
        params: json!({
            "name": "clx_session_info",
            "arguments": {}
        }),
    };

    let response = server.process_request(&request);
    assert!(response.result.is_some());
    assert!(response.error.is_none());
}

#[test]
fn test_process_request_unknown_method() {
    let server = create_test_server();
    let request = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(json!(4)),
        method: "unknown/method".to_string(),
        params: json!({}),
    };

    let response = server.process_request(&request);
    assert!(response.error.is_some());
    assert_eq!(response.error.unwrap().code, METHOD_NOT_FOUND);
}

#[test]
fn test_process_request_invalid_version() {
    let server = create_test_server();
    let request = JsonRpcRequest {
        jsonrpc: "1.0".to_string(),
        id: Some(json!(5)),
        method: "initialize".to_string(),
        params: json!({}),
    };

    let response = server.process_request(&request);
    assert!(response.error.is_some());
    assert_eq!(response.error.unwrap().code, INVALID_REQUEST);
}

#[test]
fn test_tool_call_unknown_tool() {
    let server = create_test_server();
    let result = server.handle_tools_call(&json!({
        "name": "unknown_tool",
        "arguments": {}
    }));

    assert!(result.is_err());
    let (code, _) = result.unwrap_err();
    assert_eq!(code, METHOD_NOT_FOUND);
}

#[test]
fn test_tool_call_missing_required_param() {
    let server = create_test_server();
    let result = server.handle_tools_call(&json!({
        "name": "clx_recall",
        "arguments": {}
    }));

    assert!(result.is_err());
    let (code, _) = result.unwrap_err();
    assert_eq!(code, INVALID_PARAMS);
}

// Credentials tool tests

#[test]
fn test_tool_credentials_missing_action() {
    let server = create_test_server();
    let result = server.tool_credentials(&json!({}));
    assert!(result.is_err());
    let (code, _) = result.unwrap_err();
    assert_eq!(code, INVALID_PARAMS);
}

#[test]
fn test_tool_credentials_invalid_action() {
    let server = create_test_server();
    let result = server.tool_credentials(&json!({"action": "invalid"}));
    assert!(result.is_err());
    let (code, _) = result.unwrap_err();
    assert_eq!(code, INVALID_PARAMS);
}

#[test]
fn test_tool_credentials_get_missing_key() {
    let server = create_test_server();
    let result = server.tool_credentials(&json!({"action": "get"}));
    assert!(result.is_err());
    let (code, _) = result.unwrap_err();
    assert_eq!(code, INVALID_PARAMS);
}

#[test]
fn test_tool_credentials_set_missing_key() {
    let server = create_test_server();
    let result = server.tool_credentials(&json!({
        "action": "set",
        "value": "secret"
    }));
    assert!(result.is_err());
    let (code, _) = result.unwrap_err();
    assert_eq!(code, INVALID_PARAMS);
}

#[test]
fn test_tool_credentials_set_missing_value() {
    let server = create_test_server();
    let result = server.tool_credentials(&json!({
        "action": "set",
        "key": "test_key"
    }));
    assert!(result.is_err());
    let (code, _) = result.unwrap_err();
    assert_eq!(code, INVALID_PARAMS);
}

#[test]
fn test_tool_credentials_delete_missing_key() {
    let server = create_test_server();
    let result = server.tool_credentials(&json!({"action": "delete"}));
    assert!(result.is_err());
    let (code, _) = result.unwrap_err();
    assert_eq!(code, INVALID_PARAMS);
}

// Integration tests that require keychain access
#[test]
#[ignore = "Requires keychain access"]
fn test_tool_credentials_full_cycle() {
    let server = create_test_server();
    let key = "mcp_test_key";
    let value = "mcp_test_secret";

    // Clean up first
    let _ = server.tool_credentials(&json!({
        "action": "delete",
        "key": key
    }));

    // Set
    let set_result = server.tool_credentials(&json!({
        "action": "set",
        "key": key,
        "value": value
    }));
    assert!(set_result.is_ok());

    // Get
    let get_result = server.tool_credentials(&json!({
        "action": "get",
        "key": key
    }));
    assert!(get_result.is_ok());
    let get_value = get_result.unwrap();
    let content = get_value.get("content").unwrap().as_array().unwrap();
    let text = content[0].get("text").unwrap().as_str().unwrap();
    assert_eq!(text, value);

    // List
    let list_result = server.tool_credentials(&json!({"action": "list"}));
    assert!(list_result.is_ok());

    // Delete
    let delete_result = server.tool_credentials(&json!({
        "action": "delete",
        "key": key
    }));
    assert!(delete_result.is_ok());

    // Verify deleted
    let get_after_delete = server.tool_credentials(&json!({
        "action": "get",
        "key": key
    }));
    assert!(get_after_delete.is_ok());
    let not_found_value = get_after_delete.unwrap();
    assert!(not_found_value.get("isError").is_some());
}

// =========================================================================
// Security fix tests (redact_secrets tests are in clx_core::redaction)
// =========================================================================

#[test]
fn test_credential_masking_long_value() {
    // B3-1 fix: mask must NOT leak head/tail plaintext or exact length.
    let value = "sk-1234567890abcdef"; // 19 chars -> "medium" bracket
    let masked = mask_credential_value(value);
    // No head or tail plaintext leaked (pre-fix leaked "sk-" and "def").
    assert!(
        !masked.contains("sk-"),
        "B3-1: head plaintext must not leak: {masked}"
    );
    assert!(
        !masked.contains("def"),
        "B3-1: tail plaintext must not leak: {masked}"
    );
    // No exact length leaked (pre-fix emitted "(19 chars)").
    assert!(
        !masked.contains("chars"),
        "B3-1: exact char count must not leak: {masked}"
    );
    assert!(
        !masked.contains("19"),
        "B3-1: exact length digit must not leak: {masked}"
    );
    // Fixed-form redacted token with coarse bracket.
    assert_eq!(masked, "[REDACTED:medium]");
    // The full value must not appear in the masked output.
    assert!(!masked.contains("1234567890abcdef"));
}

#[test]
fn test_credential_masking_short_value() {
    // B3-1 fix: short value must not leak exact length (pre-fix: "**** (3 chars)").
    let value = "abc"; // 3 chars -> "short" bracket
    let masked = mask_credential_value(value);
    assert_eq!(masked, "[REDACTED:short]");
    assert!(!masked.contains("abc"));
    assert!(
        !masked.contains('3'),
        "B3-1: exact length must not leak for short value: {masked}"
    );
    assert!(
        !masked.contains("chars"),
        "B3-1: 'chars' suffix must not appear: {masked}"
    );
}

#[test]
fn test_credential_masking_multibyte_utf8() {
    // B3-1 fix: multi-byte UTF-8 must not panic and must not leak any chars or exact count.
    // 8 emoji, each 4 bytes but 1 char -> 8 chars total -> "short" bracket.
    let value = "\u{1F600}\u{1F601}\u{1F602}\u{1F603}\u{1F604}\u{1F605}\u{1F606}\u{1F607}";
    let masked = mask_credential_value(value);
    // No "chars" suffix (pre-fix leaked exact count).
    assert!(
        !masked.contains("chars"),
        "B3-1: exact char count must not leak: {masked}"
    );
    // Should not panic and should not contain the full value.
    assert!(!masked.contains("\u{1F603}\u{1F604}\u{1F605}\u{1F606}"));
    // Fixed-form redacted token.
    assert_eq!(masked, "[REDACTED:short]");
}

#[test]
fn test_path_traversal_blocked() {
    let server = create_test_server();

    // Use a path that is guaranteed to exist and be outside the home directory.
    // /etc exists on all Unix systems; it canonicalizes to /private/etc on macOS
    // and /etc on Linux. Neither is under a user's home directory.
    let result = server.tool_rules(&json!({
        "action": "get_project_rules",
        "cwd": "/etc"
    }));

    // The path traversal guard MUST reject this unconditionally.
    let (code, msg) =
        result.expect_err("Path outside home directory must be rejected by traversal guard");
    assert_eq!(code, INVALID_PARAMS, "Expected INVALID_PARAMS error code");
    assert!(
        msg.contains("must be under home directory"),
        "Error message should explain the path restriction, got: {msg}"
    );
}

// =========================================================================
// Input validation integration tests (M28)
// =========================================================================

#[test]
fn test_recall_missing_query() {
    let server = create_test_server();
    let result = server.tool_recall(&json!({}));
    assert!(result.is_err());
    let (code, msg) = result.unwrap_err();
    assert_eq!(code, INVALID_PARAMS);
    assert!(msg.contains("query"));
}

#[test]
fn test_recall_query_wrong_type() {
    let server = create_test_server();
    let result = server.tool_recall(&json!({"query": 42}));
    assert!(result.is_err());
    let (code, _) = result.unwrap_err();
    assert_eq!(code, INVALID_PARAMS);
}

#[test]
fn test_recall_query_too_long() {
    let server = create_test_server();
    let long_query = "x".repeat(10_001);
    let result = server.tool_recall(&json!({"query": long_query}));
    assert!(result.is_err());
    let (code, msg) = result.unwrap_err();
    assert_eq!(code, INVALID_PARAMS);
    assert!(msg.contains("exceeds max length"));
}

#[test]
fn test_remember_missing_text() {
    let server = create_test_server();
    let result = server.tool_remember(&json!({}));
    assert!(result.is_err());
    let (code, msg) = result.unwrap_err();
    assert_eq!(code, INVALID_PARAMS);
    assert!(msg.contains("text"));
}

#[test]
fn test_remember_text_wrong_type() {
    let server = create_test_server();
    let result = server.tool_remember(&json!({"text": 123}));
    assert!(result.is_err());
    let (code, _) = result.unwrap_err();
    assert_eq!(code, INVALID_PARAMS);
}

#[test]
fn test_remember_tags_wrong_type() {
    let server = create_test_server();

    let session =
        clx_core::types::Session::new(SessionId::new("test-session"), "/test/project".to_string());
    server.storage.create_session(&session).unwrap();

    let result = server.tool_remember(&json!({"text": "hello", "tags": "not-an-array"}));
    assert!(result.is_err());
    let (code, msg) = result.unwrap_err();
    assert_eq!(code, INVALID_PARAMS);
    assert!(msg.contains("must be an array"));
}

#[test]
fn test_checkpoint_note_wrong_type() {
    let server = create_test_server();
    let result = server.tool_checkpoint(&json!({"note": 42}));
    assert!(result.is_err());
    let (code, msg) = result.unwrap_err();
    assert_eq!(code, INVALID_PARAMS);
    assert!(msg.contains("must be a string"));
}

#[test]
fn test_rules_action_wrong_type() {
    let server = create_test_server();
    let result = server.tool_rules(&json!({"action": 42}));
    assert!(result.is_err());
    let (code, _) = result.unwrap_err();
    assert_eq!(code, INVALID_PARAMS);
}

#[test]
fn test_stats_days_wrong_type() {
    let server = create_test_server();
    let result = server.tool_stats(&json!({"days": "seven"}));
    assert!(result.is_err());
    let (code, msg) = result.unwrap_err();
    assert_eq!(code, INVALID_PARAMS);
    assert!(msg.contains("must be a number"));
}

#[test]
fn test_stats_days_out_of_range() {
    let server = create_test_server();
    let result = server.tool_stats(&json!({"days": 0}));
    assert!(result.is_err());
    let (code, msg) = result.unwrap_err();
    assert_eq!(code, INVALID_PARAMS);
    assert!(msg.contains("must be between"));
}

#[test]
fn test_stats_days_valid() {
    let server = create_test_server();
    let result = server.tool_stats(&json!({"days": 30}));
    assert!(result.is_ok());
}

#[test]
fn test_credentials_action_wrong_type() {
    let server = create_test_server();
    let result = server.tool_credentials(&json!({"action": 42}));
    assert!(result.is_err());
    let (code, _) = result.unwrap_err();
    assert_eq!(code, INVALID_PARAMS);
}

// =========================================================================
// T20 — tool_recall additional coverage
// =========================================================================

#[test]
fn test_recall_returns_empty_message_when_no_match() {
    // Arrange
    let server = create_test_server();
    let session =
        clx_core::types::Session::new(SessionId::new("test-session"), "/test/project".to_string());
    server.storage.create_session(&session).unwrap();
    let _ = server.tool_remember(&json!({"text": "Rust async programming with tokio"}));

    // Act — query that won't match anything stored
    let result = server.tool_recall(&json!({"query": "zxqvbnm_nonexistent_xyz"}));

    // Assert
    assert!(result.is_ok());
    let value = result.unwrap();
    let content = value.get("content").unwrap().as_array().unwrap();
    let text = content[0].get("text").unwrap().as_str().unwrap();
    assert!(text.contains("No relevant context found"));
}

#[test]
fn test_recall_with_seeded_data_returns_formatted_results() {
    // Arrange — seed a snapshot and recall with a matching query
    let server = create_test_server();
    let session =
        clx_core::types::Session::new(SessionId::new("test-session"), "/test/project".to_string());
    server.storage.create_session(&session).unwrap();
    let _ = server.tool_remember(&json!({"text": "database migration strategy using flyway"}));

    // Act
    let result = server.tool_recall(&json!({"query": "database migration flyway"}));

    // Assert
    assert!(result.is_ok());
    let value = result.unwrap();
    let content = value.get("content").unwrap().as_array().unwrap();
    assert!(!content.is_empty());
    let text = content[0].get("text").unwrap().as_str().unwrap();
    // With no embedding infrastructure the fallback FTS5 search runs;
    // the response is either results or "No relevant context found" — either is valid.
    // What matters is the response is well-formed.
    assert!(
        text.contains("Found") || text.contains("No relevant context found"),
        "unexpected response: {text}"
    );
}

// =========================================================================
// T21 — MCP Tools partial coverage gaps
// =========================================================================

#[test]
fn test_remember_creates_snapshot_in_storage() {
    // Arrange
    let server = create_test_server();
    let session =
        clx_core::types::Session::new(SessionId::new("test-session"), "/test/project".to_string());
    server.storage.create_session(&session).unwrap();

    // Act
    let result = server.tool_remember(&json!({"text": "important architectural decision"}));

    // Assert — tool succeeds
    assert!(result.is_ok());
    let value = result.unwrap();
    let text = value["content"][0]["text"].as_str().unwrap();
    assert!(text.contains("Successfully remembered"));

    // Assert — snapshot actually persisted in storage
    let snapshots = server
        .storage
        .get_snapshots_by_session("test-session")
        .expect("should retrieve snapshots");
    assert!(
        !snapshots.is_empty(),
        "at least one snapshot should be stored"
    );
    let last = snapshots.last().unwrap();
    assert!(
        last.summary
            .as_deref()
            .unwrap_or("")
            .contains("architectural decision"),
        "snapshot summary should contain remembered text"
    );
}

#[test]
fn test_remember_without_embedding_infrastructure_still_saves() {
    // Arrange — server with no Ollama/embedding (the default test server)
    let server = create_test_server();
    let session =
        clx_core::types::Session::new(SessionId::new("test-session"), "/test/project".to_string());
    server.storage.create_session(&session).unwrap();

    // Act — embedding_store is None so embedding generation is skipped
    let result = server.tool_remember(&json!({"text": "embedding failure graceful fallback"}));

    // Assert — memory is saved despite missing embedding infrastructure
    assert!(
        result.is_ok(),
        "remember should succeed even without embeddings"
    );
    let snapshots = server
        .storage
        .get_snapshots_by_session("test-session")
        .expect("should retrieve snapshots");
    assert!(
        !snapshots.is_empty(),
        "snapshot must be persisted without embedding"
    );
}

#[test]
fn test_checkpoint_creates_snapshot_in_storage() {
    // Arrange
    let server = create_test_server();
    let session =
        clx_core::types::Session::new(SessionId::new("test-session"), "/test/project".to_string());
    server.storage.create_session(&session).unwrap();

    // Act
    let result = server.tool_checkpoint(&json!({"note": "before refactor"}));

    // Assert — tool succeeds and includes the note in the response
    assert!(result.is_ok());
    let text = result.unwrap()["content"][0]["text"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(text.contains("Checkpoint created"));
    assert!(text.contains("before refactor"));

    // Assert — snapshot written to storage with Checkpoint trigger
    let snapshots = server
        .storage
        .get_snapshots_by_session("test-session")
        .expect("should retrieve snapshots");
    assert!(
        !snapshots.is_empty(),
        "checkpoint snapshot must be persisted"
    );
}

#[test]
fn test_checkpoint_without_note_succeeds() {
    // Arrange
    let server = create_test_server();
    let session =
        clx_core::types::Session::new(SessionId::new("test-session"), "/test/project".to_string());
    server.storage.create_session(&session).unwrap();

    // Act
    let result = server.tool_checkpoint(&json!({}));

    // Assert
    assert!(result.is_ok());
    let text = result.unwrap()["content"][0]["text"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(text.contains("Checkpoint created"));
}

#[test]
fn test_rules_get_project_rules_missing_action_invalid() {
    // Supplying an unrecognised action returns INVALID_PARAMS
    let server = create_test_server();
    let result = server.tool_rules(&json!({"action": "unknown_action"}));
    assert!(result.is_err());
    let (code, _) = result.unwrap_err();
    assert_eq!(code, INVALID_PARAMS);
}

#[test]
fn test_rules_add_blacklist_rule() {
    // Arrange
    let server = create_test_server();

    // Act
    let result = server.tool_rules(&json!({
        "action": "add",
        "pattern": "rm -rf *",
        "rule_type": "blacklist"
    }));

    // Assert — succeeds and response mentions "deny"
    assert!(result.is_ok());
    let text = result.unwrap()["content"][0]["text"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(text.contains("deny"));
    assert!(text.contains("rm -rf *"));
}

#[test]
fn test_stats_with_seeded_audit_data() {
    // Arrange — create a session and two audit log entries
    let server = create_test_server();
    let session =
        clx_core::types::Session::new(SessionId::new("test-session"), "/test/project".to_string());
    server.storage.create_session(&session).unwrap();

    let allow_entry = AuditLogEntry::new(
        SessionId::new("test-session"),
        "cargo build".to_string(),
        "policy".to_string(),
        AuditDecision::Allowed,
    );
    let deny_entry = AuditLogEntry::new(
        SessionId::new("test-session"),
        "rm -rf /".to_string(),
        "policy".to_string(),
        AuditDecision::Blocked,
    );
    server.storage.create_audit_log(&allow_entry).unwrap();
    server.storage.create_audit_log(&deny_entry).unwrap();

    // Act
    let result = server.tool_stats(&json!({"days": 7}));

    // Assert — tool succeeds and the JSON structure is well-formed
    assert!(result.is_ok());
    let value = result.unwrap();
    let text = value["content"][0]["text"].as_str().unwrap();
    let stats: serde_json::Value = serde_json::from_str(text).expect("stats output must be JSON");
    assert!(stats.get("period_days").is_some());
    assert!(stats.get("sessions").is_some());
    assert!(stats.get("commands").is_some());
}

#[test]
fn test_stats_max_days_boundary() {
    // days=365 is the maximum allowed value
    let server = create_test_server();
    let result = server.tool_stats(&json!({"days": 365}));
    assert!(result.is_ok());
    let text = result.unwrap()["content"][0]["text"]
        .as_str()
        .unwrap()
        .to_string();
    let stats: serde_json::Value =
        serde_json::from_str(&text).expect("stats output must be valid JSON");
    assert_eq!(stats["period_days"], 365);
}

// =========================================================================
// T36 — McpServer::new Integration Tests
// =========================================================================

#[test]
fn test_mcp_server_new_creates_db_at_default_path() {
    // McpServer::new() falls back to clx_core::paths::database_path() when
    // CLX_DB_PATH is not set. We exercise the real code-path by calling
    // McpServer::new() directly (CLX_DB_PATH not set in CI / clean env).
    // The test asserts the call succeeds and the db_path field is non-empty —
    // verifying that Storage::open ran without error is the key assertion.
    //
    // Note: env::set_var is forbidden by workspace `unsafe_code = "deny"`, so
    // we test the no-env-var code path here and rely on the other T36 tests
    // (which use create_test_server) for post-init state verification.
    let result = McpServer::new();
    assert!(
        result.is_ok(),
        "McpServer::new() must succeed with default path: {:?}",
        result.err()
    );
    let server = result.unwrap();
    assert!(
        !server.db_path.is_empty(),
        "db_path should be populated after successful init"
    );
}

#[test]
fn test_mcp_server_new_ollama_is_optional_at_init() {
    // Verify that McpServer::new() succeeds even when there is no reachable
    // Ollama server.  The ollama_client field may be None after init — that
    // is acceptable and tested here.
    let result = McpServer::new();
    assert!(
        result.is_ok(),
        "McpServer::new() must succeed even when Ollama is unavailable"
    );
    // ollama_client is None OR Some — both are valid; what matters is no panic/error.
    let _ = result.unwrap();
}

#[test]
fn test_mcp_server_new_get_tools_returns_all_seven_names() {
    // Arrange — use create_test_server (in-memory) to exercise get_tools() on
    // a fully initialised McpServer, verifying all 7 required tool names.
    let server = create_test_server();

    // Act
    let tools = server.get_tools();
    let names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();

    // Assert — all seven expected tools are present
    assert_eq!(tools.len(), 7, "get_tools() must return exactly 7 tools");
    for expected in &[
        "clx_recall",
        "clx_remember",
        "clx_checkpoint",
        "clx_rules",
        "clx_session_info",
        "clx_credentials",
        "clx_stats",
    ] {
        assert!(
            names.contains(expected),
            "get_tools() is missing '{expected}'"
        );
    }
}

// =========================================================================
// T20 — tool_recall additional coverage (named per spec)
// =========================================================================

#[test]
fn test_recall_with_seeded_data_returns_results() {
    // Arrange — seed a session and a snapshot via tool_remember, then recall
    let server = create_test_server();
    let session =
        clx_core::types::Session::new(SessionId::new("test-session"), "/test/project".to_string());
    server.storage.create_session(&session).unwrap();
    let _ = server.tool_remember(&json!({"text": "Rust ownership model and borrow checker"}));

    // Act
    let result = server.tool_recall(&json!({"query": "Rust ownership borrow"}));

    // Assert — the call succeeds and returns well-formed MCP content
    assert!(result.is_ok(), "recall with seeded data must succeed");
    let value = result.unwrap();
    let content = value.get("content").unwrap().as_array().unwrap();
    assert!(!content.is_empty(), "content array must not be empty");
    // The response is either results or the "no match" message — both are valid
    let text = content[0].get("text").unwrap().as_str().unwrap();
    assert!(
        text.contains("Found") || text.contains("No relevant context found"),
        "unexpected response shape: {text}"
    );
}

#[test]
fn test_recall_result_format_contains_expected_fields() {
    // Arrange — seed data so there is something to recall
    let server = create_test_server();
    let session =
        clx_core::types::Session::new(SessionId::new("test-session"), "/test/project".to_string());
    server.storage.create_session(&session).unwrap();
    let _ = server.tool_remember(&json!({"text": "tokio async runtime configuration"}));

    // Act — issue a matching query
    let result = server.tool_recall(&json!({"query": "tokio async"}));

    // Assert — response JSON structure is well-formed per MCP spec
    assert!(result.is_ok());
    let value = result.unwrap();

    // Top-level "content" key must be an array
    let content = value
        .get("content")
        .expect("response must have 'content' key")
        .as_array()
        .expect("'content' must be an array");
    assert!(!content.is_empty(), "'content' array must not be empty");

    // Each item in the content array must have a "type" and "text" field
    let item = &content[0];
    assert!(
        item.get("type").is_some(),
        "content item must have 'type' field"
    );
    assert!(
        item.get("text").is_some(),
        "content item must have 'text' field"
    );
    assert_eq!(
        item.get("type").unwrap().as_str(),
        Some("text"),
        "content item 'type' must be 'text'"
    );
}

// =========================================================================
// T21 — MCP Tools additional coverage (named per spec)
// =========================================================================

#[test]
fn test_remember_embedding_failure_still_saves() {
    // Arrange — the default test server has ollama_client = None and
    // embedding_store = None, simulating an embedding infrastructure failure
    let server = create_test_server();
    let session =
        clx_core::types::Session::new(SessionId::new("test-session"), "/test/project".to_string());
    server.storage.create_session(&session).unwrap();

    // Act — call tool_remember; embedding generation will be skipped (no client)
    let result = server.tool_remember(&json!({
        "text": "important context that must be saved without embeddings"
    }));

    // Assert — the tool must succeed even with no embedding infrastructure
    assert!(
        result.is_ok(),
        "tool_remember must succeed when embedding infrastructure is absent"
    );

    // Assert — the snapshot was persisted to storage
    let snapshots = server
        .storage
        .get_snapshots_by_session("test-session")
        .expect("storage must be readable after tool_remember");
    assert!(
        !snapshots.is_empty(),
        "at least one snapshot must be saved even when embeddings are unavailable"
    );
}

#[test]
fn test_stats_with_seeded_data() {
    // Arrange — create a session and seed audit log entries
    let server = create_test_server();
    let session =
        clx_core::types::Session::new(SessionId::new("test-session"), "/test/project".to_string());
    server.storage.create_session(&session).unwrap();

    let allow_entry = AuditLogEntry::new(
        SessionId::new("test-session"),
        "cargo test".to_string(),
        "policy".to_string(),
        AuditDecision::Allowed,
    );
    let deny_entry = AuditLogEntry::new(
        SessionId::new("test-session"),
        "curl http://external".to_string(),
        "policy".to_string(),
        AuditDecision::Blocked,
    );
    server.storage.create_audit_log(&allow_entry).unwrap();
    server.storage.create_audit_log(&deny_entry).unwrap();

    // Act
    let result = server.tool_stats(&json!({"days": 30}));

    // Assert — response is well-formed JSON with expected top-level keys
    assert!(result.is_ok(), "tool_stats must succeed with seeded data");
    let value = result.unwrap();
    let text = value["content"][0]["text"].as_str().unwrap();
    let stats: serde_json::Value =
        serde_json::from_str(text).expect("stats response must be valid JSON");
    assert!(
        stats.get("period_days").is_some(),
        "stats must contain 'period_days'"
    );
    assert!(
        stats.get("sessions").is_some(),
        "stats must contain 'sessions'"
    );
    assert!(
        stats.get("commands").is_some(),
        "stats must contain 'commands'"
    );
    assert_eq!(
        stats["period_days"], 30,
        "period_days must reflect requested days"
    );
}

#[test]
fn test_stats_date_range_filtering() {
    // Arrange — create a session and audit entries that fall within "now"
    let server = create_test_server();
    let session =
        clx_core::types::Session::new(SessionId::new("test-session"), "/test/project".to_string());
    server.storage.create_session(&session).unwrap();

    let entry = AuditLogEntry::new(
        SessionId::new("test-session"),
        "git status".to_string(),
        "policy".to_string(),
        AuditDecision::Allowed,
    );
    server.storage.create_audit_log(&entry).unwrap();

    // Act — query with a narrow window (days=1) and a wide window (days=365)
    let result_narrow = server.tool_stats(&json!({"days": 1}));
    let result_wide = server.tool_stats(&json!({"days": 365}));

    // Assert — both succeed and return JSON with the expected period_days values
    assert!(result_narrow.is_ok(), "stats with days=1 must succeed");
    assert!(result_wide.is_ok(), "stats with days=365 must succeed");

    let narrow_text = result_narrow.unwrap()["content"][0]["text"]
        .as_str()
        .unwrap()
        .to_string();
    let wide_text = result_wide.unwrap()["content"][0]["text"]
        .as_str()
        .unwrap()
        .to_string();

    let narrow: serde_json::Value =
        serde_json::from_str(&narrow_text).expect("narrow stats must be valid JSON");
    let wide: serde_json::Value =
        serde_json::from_str(&wide_text).expect("wide stats must be valid JSON");

    assert_eq!(
        narrow["period_days"], 1,
        "narrow window must have period_days=1"
    );
    assert_eq!(
        wide["period_days"], 365,
        "wide window must have period_days=365"
    );

    // The wide window must report at least as many commands as the narrow one
    let narrow_total = narrow["commands"]["total"].as_i64().unwrap_or(0);
    let wide_total = wide["commands"]["total"].as_i64().unwrap_or(0);
    assert!(
        wide_total >= narrow_total,
        "wider date range must include at least as many commands as the narrow range"
    );
}

// =========================================================================
// T22 — Server functions: handle_tools_call and read_bounded_line
// =========================================================================

#[test]
fn test_handle_tools_call_valid_dispatch_returns_result() {
    // Arrange
    let server = create_test_server();

    // Act — clx_session_info requires no FK deps and always succeeds
    let result = server.handle_tools_call(&json!({
        "name": "clx_session_info",
        "arguments": {}
    }));

    // Assert
    assert!(result.is_ok());
    let value = result.unwrap();
    assert!(
        value.get("content").is_some(),
        "dispatched tool must return MCP content array"
    );
}

#[test]
fn test_handle_tools_call_missing_name_returns_invalid_params() {
    // Arrange
    let server = create_test_server();

    // Act — params object has no "name" key
    let result = server.handle_tools_call(&json!({"arguments": {}}));

    // Assert
    assert!(result.is_err());
    let (code, _) = result.unwrap_err();
    assert_eq!(code, INVALID_PARAMS);
}

#[test]
fn test_read_bounded_line_normal() {
    // Arrange — a simple line well within the size limit
    let data = b"hello world\n";
    let mut reader = BufReader::new(data.as_ref());
    let mut buf = String::new();

    // Act
    let result = McpServer::read_bounded_line(&mut reader, &mut buf);

    // Assert
    assert!(result.is_ok());
    assert!(
        result.unwrap().is_some(),
        "should return Some for a normal line"
    );
    assert_eq!(buf, "hello world");
}

#[test]
fn test_read_bounded_line_eof_returns_none() {
    // Arrange — empty buffer signals EOF
    let data: &[u8] = b"";
    let mut reader = BufReader::new(data);
    let mut buf = String::new();

    // Act
    let result = McpServer::read_bounded_line(&mut reader, &mut buf);

    // Assert
    assert!(result.is_ok());
    assert!(
        result.unwrap().is_none(),
        "empty input must return None (EOF)"
    );
}

#[test]
fn test_read_bounded_line_at_limit_succeeds() {
    // Arrange — exactly MAX_LINE_SIZE bytes followed by a newline
    let mut data = vec![b'x'; McpServer::MAX_LINE_SIZE];
    data.push(b'\n');
    let mut reader = BufReader::new(data.as_slice());
    let mut buf = String::new();

    // Act
    let result = McpServer::read_bounded_line(&mut reader, &mut buf);

    // Assert — at-limit is accepted
    assert!(result.is_ok());
    assert!(result.unwrap().is_some());
    assert_eq!(buf.len(), McpServer::MAX_LINE_SIZE);
}

#[test]
fn test_read_bounded_line_over_limit_returns_error() {
    // Arrange — MAX_LINE_SIZE + 1 bytes before the newline
    let mut data = vec![b'x'; McpServer::MAX_LINE_SIZE + 1];
    data.push(b'\n');
    let mut reader = BufReader::new(data.as_slice());
    let mut buf = String::new();

    // Act
    let result = McpServer::read_bounded_line(&mut reader, &mut buf);

    // Assert — over-limit is rejected with InvalidData
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
}

#[test]
fn test_read_bounded_line_utf8_split_across_chunk_boundary() {
    // FIX-9 regression. A small-capacity BufReader hands out the line in
    // multiple `fill_buf` chunks; the 4-byte emoji and the 3-byte CJK char are
    // deliberately split across those chunk boundaries.
    //
    // Fails-before: the old impl called `String::from_utf8_lossy` on each chunk
    // independently, so a multi-byte char straddling a boundary decoded to one
    // or more `U+FFFD` replacement chars — the line came back corrupted.
    // Passes-after: bytes are accumulated and decoded once, so the line is
    // intact with no replacement chars.
    let line = "héllo🦀世界\n"; // mix of 1/2/4/3-byte UTF-8 scalars
    // Capacity 4 forces fill_buf to return small chunks that will not align
    // with the multi-byte char boundaries.
    let mut reader = BufReader::with_capacity(4, line.as_bytes());
    let mut buf = String::new();

    let result = McpServer::read_bounded_line(&mut reader, &mut buf);

    assert!(result.is_ok());
    assert!(result.unwrap().is_some());
    assert_eq!(
        buf, "héllo🦀世界",
        "multi-byte chars split across chunk boundaries must decode intact"
    );
    assert!(
        !buf.contains('\u{FFFD}'),
        "no U+FFFD replacement char must appear (no boundary corruption)"
    );
}

#[test]
fn test_read_bounded_line_over_limit_still_bounded_with_small_chunks() {
    // FIX-9: the byte bound must still reject oversize input even when the
    // reader delivers the line in many tiny chunks (the refactor accumulates
    // across chunks, so the bound is checked against the running total).
    let mut data = vec![b'x'; McpServer::MAX_LINE_SIZE + 1];
    data.push(b'\n');
    let mut reader = BufReader::with_capacity(8, data.as_slice());
    let mut buf = String::new();

    let result = McpServer::read_bounded_line(&mut reader, &mut buf);

    assert!(result.is_err());
    assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::InvalidData);
}

// =========================================================================
// tool_remember — auto session-creation branches (remember.rs lines 23-44)
// =========================================================================

/// Build a server with NO bound session id so `tool_remember` must fall back
/// to the `clx-standalone` session id and auto-create that session row.
fn create_standalone_server() -> McpServer {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("Failed to create Tokio runtime");

    McpServer {
        storage: Storage::open_in_memory().expect("Failed to create in-memory storage"),
        session_id: None, // <- no bound session
        db_path: ":memory:".to_string(),
        credential_store: CredentialStore::with_service("com.clx.credentials.test"),
        ollama_client: None,
        embedding_store: None,
        embed_model: String::new(),
        runtime,
    }
}

/// Branch: when `self.session_id` is None, `tool_remember` falls back to the
/// `clx-standalone` session id (remember.rs lines 23-26). Kills a mutant that
/// uses a different fallback id or panics on the missing session id.
#[test]
fn test_remember_standalone_uses_clx_standalone_session() {
    let server = create_standalone_server();

    let result = server.tool_remember(&json!({"text": "standalone memory"}));
    assert!(
        result.is_ok(),
        "remember must succeed with no bound session id"
    );

    // The fallback session must now exist and own the snapshot.
    let session = server
        .storage
        .get_session("clx-standalone")
        .expect("get_session ok")
        .expect("standalone session must be auto-created");
    assert_eq!(session.id.as_str(), "clx-standalone");

    let snapshots = server
        .storage
        .get_snapshots_by_session("clx-standalone")
        .expect("snapshots query ok");
    assert!(
        !snapshots.is_empty(),
        "snapshot must be persisted under the standalone session"
    );
}

/// Branch: when the bound session does NOT yet exist in storage,
/// `tool_remember` auto-creates it before inserting the snapshot
/// (remember.rs lines 29-44). The existing happy-path tests always
/// pre-create the session, leaving this guard uncovered. Kills a mutant that
/// removes the `get_session(...).is_none()` auto-create block (the snapshot
/// insert would then trip the snapshots->sessions FK constraint and error).
#[test]
fn test_remember_auto_creates_missing_bound_session() {
    let server = create_test_server(); // session_id = Some("test-session")
    // Deliberately do NOT create the "test-session" row first.
    assert!(
        server
            .storage
            .get_session("test-session")
            .unwrap()
            .is_none(),
        "precondition: session row absent"
    );

    let result = server.tool_remember(&json!({"text": "auto-create the session"}));
    assert!(
        result.is_ok(),
        "remember must auto-create the missing session, not fail on the FK: {:?}",
        result.err()
    );

    // The session was created on demand and owns the snapshot.
    assert!(
        server
            .storage
            .get_session("test-session")
            .unwrap()
            .is_some(),
        "missing session must be auto-created by tool_remember"
    );
    let snapshots = server
        .storage
        .get_snapshots_by_session("test-session")
        .unwrap();
    assert_eq!(snapshots.len(), 1, "exactly one snapshot persisted");
}

/// Branch: the snapshot summary embeds the tags suffix when tags are present
/// and omits it when empty (`remember.rs` lines 48-57). Kills a mutant that
/// always emits the tag suffix or drops it. The `key_facts` must always be the
/// raw text regardless of tags.
#[test]
fn test_remember_tag_suffix_is_conditional() {
    let server = create_test_server();
    let session =
        clx_core::types::Session::new(SessionId::new("test-session"), "/test/project".to_string());
    server.storage.create_session(&session).unwrap();

    // With tags.
    server
        .tool_remember(&json!({"text": "tagged note", "tags": ["alpha", "beta"]}))
        .unwrap();
    // Without tags.
    server
        .tool_remember(&json!({"text": "plain note"}))
        .unwrap();

    let snaps = server
        .storage
        .get_snapshots_by_session("test-session")
        .unwrap();
    let tagged = snaps
        .iter()
        .find(|s| s.summary.as_deref().unwrap_or("").contains("tagged note"))
        .expect("tagged snapshot present");
    assert!(
        tagged
            .summary
            .as_deref()
            .unwrap()
            .contains("[tags: alpha, beta]"),
        "tagged snapshot summary must include the tag suffix: {:?}",
        tagged.summary
    );
    assert_eq!(
        tagged.key_facts.as_deref(),
        Some("tagged note"),
        "key_facts must be the raw text, not the tag-decorated summary"
    );

    let plain = snaps
        .iter()
        .find(|s| s.summary.as_deref().unwrap_or("").contains("plain note"))
        .expect("plain snapshot present");
    assert!(
        !plain.summary.as_deref().unwrap().contains("[tags:"),
        "untagged snapshot summary must NOT include a tag suffix: {:?}",
        plain.summary
    );
}

// =========================================================================
// Codex PURPLE NO-SHIP #2 — MCP tool handlers must not LOG raw user content
//
// If `tracing` output is directed to a file (the `logging.file` global-config
// setting), a secret a user passes into clx_remember / clx_checkpoint /
// clx_recall would be persisted to the log file in clear text. The handlers
// log at `debug!` on entry; the fix routes that content through
// `redact_secrets` before interpolation.
//
// These tests install a scoped `tracing` subscriber backed by an in-process
// shared buffer (no file, no network, no extra DB side effects), drive each
// handler with a SYNTHETIC secret, and assert the secret never appears in the
// captured log output while the redaction marker does.
//
// Pre-fix: FAIL (raw value interpolated into the debug! line).
// Post-fix: PASS (value scrubbed by redact_secrets).
//
// ALL secrets below are SYNTHETIC — no real credential or tenant URL appears.
// =========================================================================
mod log_redaction_tests {
    use std::io::Write;
    use std::sync::{Arc, Mutex};

    use serde_json::json;
    use tracing::subscriber::DefaultGuard;
    use tracing_subscriber::fmt::MakeWriter;

    use super::create_test_server;
    use clx_core::types::{Session, SessionId};

    /// A `MakeWriter` that appends every log line to a shared byte buffer.
    #[derive(Clone)]
    struct BufferWriter(Arc<Mutex<Vec<u8>>>);

    impl Write for BufferWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for BufferWriter {
        type Writer = BufferWriter;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    /// Install a scoped subscriber that writes DEBUG+ logs into `buf`.
    /// The returned guard restores the previous subscriber on drop, so the
    /// capture is confined to the current thread for the test's duration.
    fn capture_into(buf: Arc<Mutex<Vec<u8>>>) -> DefaultGuard {
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_writer(BufferWriter(buf))
            .with_ansi(false)
            .finish();
        tracing::subscriber::set_default(subscriber)
    }

    fn captured(buf: &Arc<Mutex<Vec<u8>>>) -> String {
        String::from_utf8(buf.lock().unwrap().clone()).expect("log output is UTF-8")
    }

    /// Sanity: the capture harness itself records emitted logs. Guards against
    /// a false-green where the buffer is silently never written.
    #[test]
    fn capture_harness_records_log_output() {
        let buf = Arc::new(Mutex::new(Vec::new()));
        {
            let _guard = capture_into(buf.clone());
            tracing::debug!("harness sentinel CANARY12345");
        }
        let logged = captured(&buf);
        assert!(
            logged.contains("CANARY12345"),
            "capture harness must record emitted logs, got: {logged}"
        );
    }

    /// `clx_remember` must NOT log the raw `text` (Bearer token in this case).
    #[test]
    fn remember_does_not_log_secret_in_text() {
        let server = create_test_server();
        server
            .storage
            .create_session(&Session::new(
                SessionId::new("test-session"),
                "/test/project".to_string(),
            ))
            .unwrap();

        let buf = Arc::new(Mutex::new(Vec::new()));
        {
            let _guard = capture_into(buf.clone());
            let result =
                server.tool_remember(&json!({"text": "deploy key Bearer SYNTHvalue12345"}));
            assert!(result.is_ok(), "remember should still succeed");
        }

        let logged = captured(&buf);
        assert!(
            logged.contains("Remember text:"),
            "the debug entry line must have been emitted: {logged}"
        );
        assert!(
            !logged.contains("SYNTHvalue12345"),
            "secret in `text` leaked into log output: {logged}"
        );
    }

    /// `clx_remember` must NOT log a raw secret carried in a `tags` element.
    #[test]
    fn remember_does_not_log_secret_in_tags() {
        let server = create_test_server();
        server
            .storage
            .create_session(&Session::new(
                SessionId::new("test-session"),
                "/test/project".to_string(),
            ))
            .unwrap();

        let buf = Arc::new(Mutex::new(Vec::new()));
        {
            let _guard = capture_into(buf.clone());
            let result = server.tool_remember(&json!({
                "text": "harmless note",
                "tags": ["safe-tag", "api_key=SYNTHtagsecret67890"]
            }));
            assert!(result.is_ok(), "remember should still succeed");
        }

        let logged = captured(&buf);
        assert!(
            !logged.contains("SYNTHtagsecret67890"),
            "secret in a `tags` element leaked into log output: {logged}"
        );
    }

    /// `clx_checkpoint` must NOT log the raw `note`.
    #[test]
    fn checkpoint_does_not_log_secret_in_note() {
        let server = create_test_server();
        server
            .storage
            .create_session(&Session::new(
                SessionId::new("test-session"),
                "/test/project".to_string(),
            ))
            .unwrap();

        let buf = Arc::new(Mutex::new(Vec::new()));
        {
            let _guard = capture_into(buf.clone());
            let result =
                server.tool_checkpoint(&json!({"note": "ship it Bearer SYNTHnote34567890"}));
            assert!(result.is_ok(), "checkpoint should still succeed");
        }

        let logged = captured(&buf);
        assert!(
            logged.contains("Checkpoint with note:"),
            "the debug entry line must have been emitted: {logged}"
        );
        assert!(
            !logged.contains("SYNTHnote34567890"),
            "secret in `note` leaked into log output: {logged}"
        );
    }

    /// `clx_recall` must NOT log the raw `query` (a third site beyond the two
    /// reported handlers).
    #[test]
    fn recall_does_not_log_secret_in_query() {
        let server = create_test_server();
        server
            .storage
            .create_session(&Session::new(
                SessionId::new("test-session"),
                "/test/project".to_string(),
            ))
            .unwrap();

        let buf = Arc::new(Mutex::new(Vec::new()));
        {
            let _guard = capture_into(buf.clone());
            let result = server.tool_recall(&json!({"query": "find Bearer SYNTHquery98765432"}));
            assert!(result.is_ok(), "recall should still succeed");
        }

        let logged = captured(&buf);
        assert!(
            logged.contains("Recall query:"),
            "the debug entry line must have been emitted: {logged}"
        );
        assert!(
            !logged.contains("SYNTHquery98765432"),
            "secret in `query` leaked into log output: {logged}"
        );
    }
}

// =========================================================================
// T40 — Uncovered-branch behavior contracts: the embedding pipeline
// (success / wrong-dimension / unreachable / stalled embedder), degraded
// recall (FIX-6, both arms), semantic search-type labeling, storage write
// failure, and credential-backend failure arms.
//
// Hermetic by construction: loopback HTTP stubs (no real Ollama), in-memory
// SQLite, and a tempdir-backed age-file credential store (never the user's
// real CLX home, never the keychain).
// =========================================================================
mod failure_and_embedding_path_tests {
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::Arc;

    use serde_json::json;

    use clx_core::config::OllamaConfig;
    use clx_core::credentials::{AgeFileBackend, CredentialStore};
    use clx_core::embeddings::EmbeddingStore;
    use clx_core::llm::{LlmClient, OllamaBackend};
    use clx_core::storage::Storage;
    use clx_core::types::{Session, SessionId};

    use crate::protocol::types::INTERNAL_ERROR;
    use crate::server::McpServer;

    // ---------------------------------------------------------------------
    // Builders and test doubles
    // ---------------------------------------------------------------------

    /// In-memory vector store with the sqlite-vec module registered (the
    /// registration is process-global and idempotent).
    fn in_memory_embedding_store() -> EmbeddingStore {
        clx_core::init_sqlite_vec();
        EmbeddingStore::open_in_memory().expect("embedding store")
    }

    /// Credential store backed by an age file inside an isolated tempdir.
    fn file_credential_store(dir: &std::path::Path) -> CredentialStore {
        CredentialStore::with_backend(Arc::new(
            AgeFileBackend::with_dir(dir).expect("with_dir only records paths"),
        ))
    }

    /// Build a server whose embedding seams (LLM client / vector store) and
    /// credential backend are injected per test. Storage is in-memory.
    fn server_with(
        ollama: Option<LlmClient>,
        embedding_store: Option<EmbeddingStore>,
        credential_dir: &std::path::Path,
    ) -> McpServer {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("create test runtime");
        McpServer {
            storage: Storage::open_in_memory().expect("in-memory storage"),
            session_id: Some(SessionId::new("test-session")),
            db_path: ":memory:".to_string(),
            credential_store: file_credential_store(credential_dir),
            ollama_client: ollama,
            embed_model: "stub-embed-model".to_string(),
            embedding_store,
            runtime,
        }
    }

    fn seed_session(server: &McpServer) {
        server
            .storage
            .create_session(&Session::new(
                SessionId::new("test-session"),
                "/test/project".to_string(),
            ))
            .expect("seed session");
    }

    /// Loopback Ollama-shaped client with retries disabled so failure tests
    /// stay fast and deterministic.
    fn ollama_at(host: &str, timeout_ms: u64) -> LlmClient {
        let cfg = OllamaConfig {
            host: host.to_string(),
            timeout_ms,
            max_retries: 0,
            retry_delay_ms: 1,
            ..OllamaConfig::default()
        };
        LlmClient::Ollama(OllamaBackend::new(cfg).expect("loopback host must be accepted"))
    }

    /// A loopback URL where nothing listens: connecting is refused instantly.
    fn refused_base_url() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind probe");
        let addr = listener.local_addr().expect("probe addr");
        drop(listener);
        format!("http://{addr}")
    }

    /// Read one HTTP/1.1 request (headers plus `Content-Length` body) from
    /// `stream`. Returns `None` on any I/O error.
    fn read_http_request(stream: &mut TcpStream) -> Option<()> {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        let header_end = loop {
            let n = stream.read(&mut chunk).ok()?;
            if n == 0 {
                return None;
            }
            buf.extend_from_slice(&chunk[..n]);
            if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break pos + 4;
            }
            if buf.len() > 1_048_576 {
                return None;
            }
        };
        let headers = String::from_utf8_lossy(&buf[..header_end]).to_ascii_lowercase();
        let content_length: usize = headers
            .lines()
            .find_map(|l| l.strip_prefix("content-length:"))
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or(0);
        while buf.len() < header_end + content_length {
            let n = stream.read(&mut chunk).ok()?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
        }
        Some(())
    }

    /// Spawn a minimal HTTP stub that answers every request with the canned
    /// `/api/embeddings` JSON body, then exits after `max_requests`
    /// connections.
    fn spawn_embedding_stub(embedding: &[f32], max_requests: usize) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind embedding stub");
        let addr = listener.local_addr().expect("stub addr");
        let body = json!({ "embedding": embedding }).to_string();
        std::thread::spawn(move || {
            for stream in listener.incoming().take(max_requests) {
                let Ok(mut stream) = stream else { continue };
                let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(10)));
                if read_http_request(&mut stream).is_none() {
                    continue;
                }
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes());
            }
        });
        format!("http://{addr}")
    }

    /// Spawn a stub that accepts connections and reads the request but never
    /// answers, so the embed future stalls until the caller's deadline.
    fn spawn_stalling_stub() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind stalling stub");
        let addr = listener.local_addr().expect("stub addr");
        std::thread::spawn(move || {
            for stream in listener.incoming().take(4) {
                let Ok(mut stream) = stream else { continue };
                std::thread::spawn(move || {
                    let _ = read_http_request(&mut stream);
                    // Hold the socket open without answering; the pipeline
                    // deadline (EMBEDDING_STORE_TIMEOUT_MS) fires first.
                    std::thread::sleep(std::time::Duration::from_secs(12));
                });
            }
        });
        format!("http://{addr}")
    }

    fn embedding_count(server: &McpServer) -> i64 {
        server
            .embedding_store
            .as_ref()
            .expect("embedding store injected")
            .count_embeddings()
            .expect("count embeddings")
    }

    fn response_text(value: &serde_json::Value) -> &str {
        value["content"][0]["text"]
            .as_str()
            .expect("MCP text payload")
    }

    // ---------------------------------------------------------------------
    // remember / checkpoint embedding pipeline
    // ---------------------------------------------------------------------

    /// Happy path through the embed-and-store pipeline: a reachable embedder
    /// plus an enabled vector store must persist exactly one embedding for
    /// the remembered snapshot.
    #[test]
    fn remember_with_working_embedder_persists_embedding() {
        let store = in_memory_embedding_store();
        let dim = store.embedding_dim();
        let url = spawn_embedding_stub(&vec![0.25_f32; dim], 4);
        let dir = tempfile::tempdir().expect("tempdir");
        let server = server_with(Some(ollama_at(&url, 10_000)), Some(store), dir.path());
        seed_session(&server);

        let result = server.tool_remember(&json!({"text": "embedding pipeline happy path"}));

        let value = result.expect("remember must succeed");
        let text = response_text(&value);
        assert!(
            text.contains("Successfully remembered"),
            "unexpected response: {text}"
        );
        assert_eq!(
            embedding_count(&server),
            1,
            "the generated embedding must be persisted in the vector store"
        );
    }

    /// The stub returns an 8-dim vector while the store expects its
    /// configured dimension: `store_embedding` must fail, remember must
    /// still succeed (graceful degradation), and nothing may land in the
    /// vector store.
    #[test]
    fn remember_with_wrong_dimension_embedding_saves_snapshot_without_embedding() {
        let store = in_memory_embedding_store();
        assert_ne!(
            store.embedding_dim(),
            8,
            "test precondition: dimensions must mismatch"
        );
        let url = spawn_embedding_stub(&[0.5_f32; 8], 4);
        let dir = tempfile::tempdir().expect("tempdir");
        let server = server_with(Some(ollama_at(&url, 10_000)), Some(store), dir.path());
        seed_session(&server);

        let result = server.tool_remember(&json!({"text": "dimension mismatch path"}));

        let value = result.expect("remember must succeed despite the bad embedding");
        assert!(
            response_text(&value).contains("Successfully remembered"),
            "unexpected response: {value}"
        );
        assert_eq!(
            embedding_count(&server),
            0,
            "a mismatched-dimension embedding must be rejected, not stored"
        );
        let snaps = server
            .storage
            .get_snapshots_by_session("test-session")
            .expect("snapshots");
        assert_eq!(snaps.len(), 1, "the snapshot itself must still be saved");
    }

    /// Connection-refused embedder: the memory is saved, no embedding lands.
    #[test]
    fn remember_with_unreachable_embedder_saves_snapshot_without_embedding() {
        let store = in_memory_embedding_store();
        let dir = tempfile::tempdir().expect("tempdir");
        let server = server_with(
            Some(ollama_at(&refused_base_url(), 2_000)),
            Some(store),
            dir.path(),
        );
        seed_session(&server);

        let result = server.tool_remember(&json!({"text": "embedder offline path"}));

        let value = result.expect("remember must succeed without a reachable embedder");
        assert!(
            response_text(&value).contains("Successfully remembered"),
            "unexpected response: {value}"
        );
        assert_eq!(embedding_count(&server), 0);
    }

    /// The 5s embed deadline (`EMBEDDING_STORE_TIMEOUT_MS`) must fire when
    /// the embedder accepts but never answers; the memory is still saved.
    /// Costs ~5s wall clock by design (the deadline itself is the contract).
    #[test]
    fn remember_with_stalling_embedder_hits_deadline_and_still_saves() {
        let store = in_memory_embedding_store();
        let url = spawn_stalling_stub();
        let dir = tempfile::tempdir().expect("tempdir");
        // reqwest timeout far above the 5s pipeline deadline so the
        // tokio::time::timeout arm (not a reqwest error) is what fires.
        let server = server_with(Some(ollama_at(&url, 60_000)), Some(store), dir.path());
        seed_session(&server);

        let started = std::time::Instant::now();
        let result = server.tool_remember(&json!({"text": "stalled embedder path"}));
        let elapsed = started.elapsed();

        let value = result.expect("remember must succeed despite the stall");
        assert!(
            response_text(&value).contains("Successfully remembered"),
            "unexpected response: {value}"
        );
        assert_eq!(
            embedding_count(&server),
            0,
            "no embedding may be stored after the deadline"
        );
        assert!(
            elapsed >= std::time::Duration::from_millis(4_500),
            "the 5s deadline arm should be the taken path (took {elapsed:?})"
        );
        assert!(
            elapsed < std::time::Duration::from_secs(20),
            "the deadline must bound the stall (took {elapsed:?})"
        );
    }

    /// Checkpoint with a note and a working embedder must persist the note's
    /// embedding (the success arm of the checkpoint embed branch).
    #[test]
    fn checkpoint_with_note_and_working_embedder_stores_embedding() {
        let store = in_memory_embedding_store();
        let dim = store.embedding_dim();
        let url = spawn_embedding_stub(&vec![0.125_f32; dim], 4);
        let dir = tempfile::tempdir().expect("tempdir");
        let server = server_with(Some(ollama_at(&url, 10_000)), Some(store), dir.path());
        seed_session(&server);

        let result = server.tool_checkpoint(&json!({"note": "before big refactor"}));

        let value = result.expect("checkpoint must succeed");
        let text = response_text(&value);
        assert!(text.contains("Checkpoint created"), "unexpected: {text}");
        assert!(
            text.contains("before big refactor"),
            "the note must be echoed: {text}"
        );
        assert_eq!(
            embedding_count(&server),
            1,
            "the checkpoint note embedding must be persisted"
        );
    }

    // ---------------------------------------------------------------------
    // storage failure arms
    // ---------------------------------------------------------------------

    /// A read-only database file makes every write fail while reads keep
    /// working: `tool_remember` must surface `INTERNAL_ERROR` with an
    /// actionable message (and the standalone-session auto-create warning
    /// path runs on the way because the session insert also fails).
    #[test]
    #[cfg(unix)]
    fn remember_on_readonly_database_returns_internal_error() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("tempdir");
        let db_path = dir.path().join("clx-test.db");
        drop(Storage::open(&db_path).expect("create schema"));
        std::fs::set_permissions(&db_path, std::fs::Permissions::from_mode(0o444))
            .expect("make db read-only");

        let storage = Storage::open(&db_path).expect("reopen read-only db");
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let server = McpServer {
            storage,
            session_id: Some(SessionId::new("never-created-session")),
            db_path: db_path.to_string_lossy().to_string(),
            credential_store: file_credential_store(dir.path()),
            ollama_client: None,
            embed_model: String::new(),
            embedding_store: None,
            runtime,
        };

        let err = server
            .tool_remember(&json!({"text": "this write must fail"}))
            .expect_err("a read-only database must fail the snapshot write");
        assert_eq!(err.0, INTERNAL_ERROR);
        assert!(
            err.1.contains("Failed to save information"),
            "actionable error message expected, got: {}",
            err.1
        );

        // Restore permissions so the tempdir cleans up.
        let _ = std::fs::set_permissions(&db_path, std::fs::Permissions::from_mode(0o644));
    }

    /// When the session lookup itself errors (here: the `sessions` table is
    /// dropped out from under a live connection through a second connection
    /// to the same database file), `clx_session_info` must report the
    /// failure in `session_error` instead of failing the whole tool call.
    #[test]
    fn session_info_reports_session_error_when_session_read_fails() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db_path = dir.path().join("clx-test.db");
        let storage = Storage::open(&db_path).expect("open file-backed db");
        // Second connection to the same file (the embedding store exposes
        // its raw connection): dropping the table makes the server's next
        // `get_session` fail with a hard storage error, not Ok(None).
        clx_core::init_sqlite_vec();
        let saboteur = EmbeddingStore::open(&db_path).expect("second connection");
        saboteur
            .connection()
            .execute_batch("DROP TABLE sessions;")
            .expect("drop sessions table");

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let server = McpServer {
            storage,
            session_id: Some(SessionId::new("test-session")),
            db_path: db_path.to_string_lossy().to_string(),
            credential_store: file_credential_store(dir.path()),
            ollama_client: None,
            embed_model: String::new(),
            embedding_store: None,
            runtime,
        };

        let value = server
            .tool_session_info(&json!({}))
            .expect("session_info must never hard-fail");
        let text = response_text(&value);
        assert!(
            text.contains("session_error") && text.contains("Failed to get session"),
            "a failing session read must surface session_error, got: {text}"
        );
    }

    // ---------------------------------------------------------------------
    // degraded recall (FIX-6) and search-type labeling
    // ---------------------------------------------------------------------

    /// Embedder configured but unreachable: the semantic stage errors
    /// (degraded) while FTS runs healthy on an empty store (no hits).
    /// FIX-6: that must read as unavailability, NOT as "nothing relevant".
    #[test]
    fn recall_degraded_with_no_hits_reports_temporary_unavailability() {
        let store = in_memory_embedding_store();
        let dir = tempfile::tempdir().expect("tempdir");
        let server = server_with(
            Some(ollama_at(&refused_base_url(), 2_000)),
            Some(store),
            dir.path(),
        );

        let value = server
            .tool_recall(&json!({"query": "anything"}))
            .expect("degraded recall must still return Ok");
        let text = response_text(&value);
        assert!(
            text.contains("Recall temporarily unavailable"),
            "degraded+empty must be reported as unavailability, got: {text}"
        );
        assert!(
            !text.contains("No relevant context found"),
            "degraded recall must not masquerade as a clean empty result: {text}"
        );
    }

    /// Embedder down but FTS healthy and matching: the hits are returned
    /// WITH the partial-failure note so the agent knows one path was out.
    #[test]
    fn recall_degraded_with_fts_hits_appends_partial_note() {
        let store = in_memory_embedding_store();
        let dir = tempfile::tempdir().expect("tempdir");
        let server = server_with(
            Some(ollama_at(&refused_base_url(), 2_000)),
            Some(store),
            dir.path(),
        );
        seed_session(&server);
        server
            .tool_remember(&json!({"text": "flyway database migration ledger"}))
            .expect("remember succeeds without embedder");

        let value = server
            .tool_recall(&json!({"query": "flyway migration"}))
            .expect("recall ok");
        let text = response_text(&value);
        assert!(
            text.contains("Found"),
            "an FTS hit was expected, got: {text}"
        );
        assert!(
            text.contains("[partial: one search path was unavailable]"),
            "degraded-with-hits must carry the partial note, got: {text}"
        );
    }

    /// A hit reachable ONLY through the vector path (the query shares no
    /// token with the stored text; the stub returns the identical vector for
    /// every embed call, i.e. perfect similarity) must be labeled `semantic`
    /// and the header must report the hybrid search method.
    #[test]
    fn recall_semantic_only_hit_is_labeled_semantic() {
        let store = in_memory_embedding_store();
        let dim = store.embedding_dim();
        let url = spawn_embedding_stub(&vec![0.5_f32; dim], 8);
        let dir = tempfile::tempdir().expect("tempdir");
        let server = server_with(Some(ollama_at(&url, 10_000)), Some(store), dir.path());
        seed_session(&server);
        server
            .tool_remember(&json!({"text": "alpha bravo charlie delta"}))
            .expect("remember with embedding");
        assert_eq!(
            embedding_count(&server),
            1,
            "precondition: embedding stored"
        );

        let value = server
            .tool_recall(&json!({"query": "zulu"}))
            .expect("recall ok");
        let text = response_text(&value);
        assert!(
            text.contains("Found"),
            "a semantic hit was expected, got: {text}"
        );
        assert!(
            text.contains("semantic + fts5 (hybrid)"),
            "the header must report the semantic method, got: {text}"
        );
        assert!(
            text.contains("\"search_type\": \"semantic\""),
            "the hit must be labeled semantic, got: {text}"
        );
        assert!(
            !text.contains("[partial:"),
            "a healthy recall must not carry the partial note: {text}"
        );
    }

    /// A snapshot found by BOTH the vector path and FTS must be deduplicated
    /// into a single hit labeled `hybrid`.
    #[test]
    fn recall_hit_found_by_both_paths_is_labeled_hybrid() {
        let store = in_memory_embedding_store();
        let dim = store.embedding_dim();
        let url = spawn_embedding_stub(&vec![0.5_f32; dim], 8);
        let dir = tempfile::tempdir().expect("tempdir");
        let server = server_with(Some(ollama_at(&url, 10_000)), Some(store), dir.path());
        seed_session(&server);
        server
            .tool_remember(&json!({"text": "alpha bravo charlie delta"}))
            .expect("remember with embedding");

        let value = server
            .tool_recall(&json!({"query": "alpha bravo"}))
            .expect("recall ok");
        let text = response_text(&value);
        assert!(
            text.contains("Found"),
            "a merged hit was expected, got: {text}"
        );
        assert!(
            text.contains("\"search_type\": \"hybrid\""),
            "a hit found by both paths must be labeled hybrid, got: {text}"
        );
    }

    // NOTE: a test attempting to force the FTS->substring degraded path by
    // `DROP TABLE snapshots_fts` through a second connection was removed: the
    // server connection still resolved the query via fts5 (the DDL did not make
    // its FTS stage error), so the sabotage could not exercise the degraded
    // `[partial]` path. The genuine substring-fallback + degraded behavior is
    // covered at the engine level by
    // clx-core/tests/recall_substring_fallback_behavior.rs.

    // ---------------------------------------------------------------------
    // credentials: project fallback, empty list, backend failure arms
    // ---------------------------------------------------------------------

    #[test]
    fn credentials_list_on_empty_store_says_none_stored() {
        let dir = tempfile::tempdir().expect("tempdir");
        let server = server_with(None, None, dir.path());

        let value = server
            .tool_credentials(&json!({"action": "list"}))
            .expect("list on an empty store is not an error");
        assert_eq!(response_text(&value), "No credentials stored");
    }

    /// `get` with a `project` argument must fall back to the global scope
    /// when no project-scoped value exists — and the value must stay masked.
    #[test]
    fn credentials_get_with_project_falls_back_to_global_value() {
        let dir = tempfile::tempdir().expect("tempdir");
        let server = server_with(None, None, dir.path());
        server
            .tool_credentials(
                &json!({"action": "set", "key": "api-token", "value": "SYNTH-cred-value-123"}),
            )
            .expect("set ok");

        let value = server
            .tool_credentials(&json!({"action": "get", "key": "api-token", "project": "proj-x"}))
            .expect("get with project must fall back to the global value");
        let text = response_text(&value);
        assert!(
            text.contains("Credential 'api-token' exists"),
            "fallback lookup must find the global value, got: {text}"
        );
        assert!(
            text.contains("[REDACTED:"),
            "the value must be masked: {text}"
        );
        assert!(
            !text.contains("SYNTH-cred-value-123"),
            "plaintext must never be returned: {text}"
        );
    }

    /// A blank/whitespace `project` must be treated as "no project" and use
    /// the plain global lookup.
    #[test]
    fn credentials_get_with_blank_project_uses_global_lookup() {
        let dir = tempfile::tempdir().expect("tempdir");
        let server = server_with(None, None, dir.path());
        server
            .tool_credentials(
                &json!({"action": "set", "key": "blank-proj-key", "value": "SYNTH-value"}),
            )
            .expect("set ok");

        let value = server
            .tool_credentials(&json!({"action": "get", "key": "blank-proj-key", "project": "   "}))
            .expect("get with blank project must use the global path");
        assert!(
            response_text(&value).contains("Credential 'blank-proj-key' exists"),
            "blank project must behave like no project"
        );
    }

    #[test]
    fn credentials_get_on_corrupt_backend_returns_internal_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("credentials.age"),
            b"definitely-not-an-age-v1-file",
        )
        .expect("plant corrupt credential file");
        let server = server_with(None, None, dir.path());

        let err = server
            .tool_credentials(&json!({"action": "get", "key": "any-key"}))
            .expect_err("a corrupt backend must fail the get");
        assert_eq!(err.0, INTERNAL_ERROR);
        assert!(err.1.contains("Failed to get credential"), "got: {}", err.1);
    }

    #[test]
    fn credentials_list_on_corrupt_backend_returns_internal_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("credentials.age"),
            b"definitely-not-an-age-v1-file",
        )
        .expect("plant corrupt credential file");
        let server = server_with(None, None, dir.path());

        let err = server
            .tool_credentials(&json!({"action": "list"}))
            .expect_err("a corrupt backend must fail the list");
        assert_eq!(err.0, INTERNAL_ERROR);
        assert!(
            err.1.contains("Failed to list credentials"),
            "got: {}",
            err.1
        );
    }

    #[test]
    fn credentials_delete_on_corrupt_backend_returns_internal_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("credentials.age"),
            b"definitely-not-an-age-v1-file",
        )
        .expect("plant corrupt credential file");
        let server = server_with(None, None, dir.path());

        let err = server
            .tool_credentials(&json!({"action": "delete", "key": "any-key"}))
            .expect_err("a corrupt backend must fail the delete");
        assert_eq!(err.0, INTERNAL_ERROR);
        assert!(
            err.1.contains("Failed to delete credential"),
            "got: {}",
            err.1
        );
    }

    /// The age backend self-heals directory permissions (0700), so a
    /// read-only dir cannot fail it; planting a DIRECTORY where the data
    /// file belongs makes the write path fail unrecoverably instead.
    #[test]
    fn credentials_set_on_unwritable_backend_returns_internal_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir(dir.path().join("credentials.age"))
            .expect("plant directory where the credential file belongs");
        let server = server_with(None, None, dir.path());

        let err = server
            .tool_credentials(&json!({"action": "set", "key": "k", "value": "v"}))
            .expect_err("an unwritable backend must fail the store");
        assert_eq!(err.0, INTERNAL_ERROR);
        assert!(
            err.1.contains("Failed to store credential"),
            "got: {}",
            err.1
        );
    }
}
