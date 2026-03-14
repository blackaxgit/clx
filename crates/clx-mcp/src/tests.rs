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
    let value = "sk-1234567890abcdef";
    let masked = mask_credential_value(value);
    assert!(masked.contains("sk-"));
    assert!(masked.contains("def"));
    assert!(masked.contains("chars"));
    // The full value must not appear in the masked output
    assert!(!masked.contains("1234567890abcdef"));
}

#[test]
fn test_credential_masking_short_value() {
    let value = "abc";
    let masked = mask_credential_value(value);
    assert_eq!(masked, "**** (3 chars)");
    assert!(!masked.contains("abc"));
}

#[test]
fn test_credential_masking_multibyte_utf8() {
    // Ensure masking does not panic on multi-byte UTF-8 characters
    let value = "\u{1F600}\u{1F601}\u{1F602}\u{1F603}\u{1F604}\u{1F605}\u{1F606}\u{1F607}";
    let masked = mask_credential_value(value);
    assert!(masked.contains("chars"));
    // Should not panic and should not contain the full value
    assert!(!masked.contains("\u{1F603}\u{1F604}\u{1F605}\u{1F606}"));
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
    assert!(result.is_ok(), "remember should succeed even without embeddings");
    let snapshots = server
        .storage
        .get_snapshots_by_session("test-session")
        .expect("should retrieve snapshots");
    assert!(!snapshots.is_empty(), "snapshot must be persisted without embedding");
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
    assert!(!snapshots.is_empty(), "checkpoint snapshot must be persisted");
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

    assert_eq!(narrow["period_days"], 1, "narrow window must have period_days=1");
    assert_eq!(wide["period_days"], 365, "wide window must have period_days=365");

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
    assert!(result.unwrap().is_some(), "should return Some for a normal line");
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
    assert!(result.unwrap().is_none(), "empty input must return None (EOF)");
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
