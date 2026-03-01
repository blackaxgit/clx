//! Tests for the CLX MCP server.

use serde_json::json;

use clx_core::credentials::CredentialStore;
use clx_core::storage::Storage;
use clx_core::types::SessionId;

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
