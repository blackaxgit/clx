//! `clx_credentials` tool — Securely manage credentials using the system keychain.

use serde_json::{Value, json};
use tracing::{debug, error, info};

use crate::protocol::types::{INTERNAL_ERROR, INVALID_PARAMS};
use crate::server::McpServer;
use crate::validation::{
    MAX_CONTENT_LEN, MAX_KEY_LEN, validate_optional_string_param, validate_string_param,
};

impl McpServer {
    /// `clx_credentials` - Securely manage credentials
    pub(crate) fn tool_credentials(&self, args: &Value) -> Result<Value, (i32, String)> {
        let action = validate_string_param(args, "action", MAX_KEY_LEN)?;

        match action.as_str() {
            "get" => {
                let key = validate_string_param(args, "key", MAX_KEY_LEN)?;
                let project = validate_optional_string_param(args, "project", MAX_KEY_LEN)?
                    .filter(|s| !s.trim().is_empty());

                debug!(
                    "Getting credential for key: {} (project: {:?})",
                    key, project
                );

                let result = if let Some(ref project) = project {
                    self.credential_store.get_with_fallback(&key, project)
                } else {
                    self.credential_store.get(&key)
                };

                match result {
                    Ok(Some(value)) => {
                        // SECURITY: Never return plaintext credentials in MCP responses.
                        // Mask the value so it cannot be leaked through LLM context.
                        let masked = mask_credential_value(&value);

                        Ok(json!({
                            "content": [{
                                "type": "text",
                                "text": format!(
                                    "Credential '{}' exists. Value (masked): {}\n\nTo use this credential, reference it by key name in your configuration. The actual value is stored securely in the OS keychain.",
                                    key, masked
                                )
                            }]
                        }))
                    }
                    Ok(None) => Ok(json!({
                        "content": [{
                            "type": "text",
                            "text": format!("Credential not found: {}", key)
                        }],
                        "isError": true
                    })),
                    Err(e) => {
                        error!("Failed to get credential: {}", e);
                        Err((INTERNAL_ERROR, format!("Failed to get credential: {e}")))
                    }
                }
            }
            "set" => {
                let key = validate_string_param(args, "key", MAX_KEY_LEN)?;
                let value = validate_string_param(args, "value", MAX_CONTENT_LEN)?;

                // Never log the actual value
                debug!("Storing credential for key: {}", key);

                match self.credential_store.store(&key, &value) {
                    Ok(()) => {
                        info!("Credential stored for key: {}", key);
                        Ok(json!({
                            "content": [{
                                "type": "text",
                                "text": format!(
                                    "Credential '{}' stored successfully.\n\n\
                                     Note: For maximum security, prefer using `clx credentials set KEY VALUE` \
                                     from a terminal instead of this MCP tool, as values passed through MCP \
                                     are visible in Claude Code's transcript.",
                                    key
                                )
                            }]
                        }))
                    }
                    Err(e) => {
                        error!("Failed to store credential: {}", e);
                        Err((INTERNAL_ERROR, format!("Failed to store credential: {e}")))
                    }
                }
            }
            "delete" => {
                let key = validate_string_param(args, "key", MAX_KEY_LEN)?;

                debug!("Deleting credential for key: {}", key);

                match self.credential_store.delete(&key) {
                    Ok(()) => {
                        info!("Credential deleted for key: {}", key);
                        Ok(json!({
                            "content": [{
                                "type": "text",
                                "text": format!("Credential deleted for key: {}", key)
                            }]
                        }))
                    }
                    Err(e) => {
                        error!("Failed to delete credential: {}", e);
                        Err((INTERNAL_ERROR, format!("Failed to delete credential: {e}")))
                    }
                }
            }
            "list" => {
                debug!("Listing credentials");

                match self.credential_store.list() {
                    Ok(keys) => {
                        let response = if keys.is_empty() {
                            "No credentials stored".to_string()
                        } else {
                            serde_json::to_string_pretty(&keys).unwrap_or_else(|_| "[]".to_string())
                        };
                        Ok(json!({
                            "content": [{
                                "type": "text",
                                "text": response
                            }]
                        }))
                    }
                    Err(e) => {
                        error!("Failed to list credentials: {}", e);
                        Err((INTERNAL_ERROR, format!("Failed to list credentials: {e}")))
                    }
                }
            }
            _ => Err((
                INVALID_PARAMS,
                format!("Invalid action: {action}. Must be 'get', 'set', 'delete', or 'list'"),
            )),
        }
    }
}

/// Mask a credential value for safe display without exposing the full secret.
///
/// Uses character-based indexing to avoid panics on multi-byte UTF-8 values.
/// For values longer than 6 chars, shows the first 3 and last 3 characters.
/// For shorter values, fully masks the content.
pub(crate) fn mask_credential_value(value: &str) -> String {
    let char_count = value.chars().count();
    if char_count > 6 {
        let prefix: String = value.chars().take(3).collect();
        let suffix: String = value.chars().skip(char_count - 3).collect();
        format!("{prefix}...{suffix} ({char_count} chars)")
    } else {
        format!("**** ({char_count} chars)")
    }
}
