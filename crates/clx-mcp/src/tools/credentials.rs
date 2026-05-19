//! `clx_credentials` tool - Securely manage credentials in the configured
//! credential backend (an encrypted local file by default, the macOS keychain
//! only when the user has explicitly opted in).

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
                                    "Credential '{}' exists. Value (masked): {}\n\nTo use this credential, reference it by key name in your configuration. The actual value is stored securely in the configured credential backend (an encrypted local file by default, the macOS keychain only if opted in).",
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

/// Mask a credential value for safe display.
///
/// # Security guarantees
///
/// - **No plaintext fragment**: the returned string contains zero characters
///   from the original value (no head, no tail, no interior slice).
/// - **No exact length**: the length is expressed as a coarse bracket
///   (`short`, `medium`, `long`, `very long`) so an observer cannot derive
///   the exact character count and reduce brute-force search space.
///
/// The output is a fixed-form redacted token: `[REDACTED:<bracket>]`.
///
/// # Rationale
///
/// The previous implementation (`prefix...suffix (N chars)`) leaked 6
/// plaintext characters plus the exact character count per `get` call,
/// enabling structured-secret enumeration via prompt injection (B3-1).
pub(crate) fn mask_credential_value(value: &str) -> String {
    let bracket = coarse_length_bracket(value.chars().count());
    format!("[REDACTED:{bracket}]")
}

/// Classify a character count into a coarse length bracket.
///
/// Brackets are intentionally wide to prevent exact-length derivation:
/// - `short`    : 1 – 15 chars   (covers PINs, short tokens)
/// - `medium`   : 16 – 63 chars  (covers API keys, passwords)
/// - `long`     : 64 – 255 chars (covers JWTs, certificates)
/// - `very-long`: 256+ chars     (covers large blobs)
fn coarse_length_bracket(char_count: usize) -> &'static str {
    match char_count {
        0 => "empty",
        1..=15 => "short",
        16..=63 => "medium",
        64..=255 => "long",
        _ => "very-long",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -------------------------------------------------------------------------
    // B3-1 regression: hardened mask leaks no plaintext fragment, no exact length
    // -------------------------------------------------------------------------

    /// GREEN regression for B3-1: the mask must NOT contain any character from
    /// the original value and must NOT expose the exact character count.
    /// Fails on the pre-fix implementation (prefix...suffix (N chars)).
    #[test]
    fn b3_1_mask_leaks_no_plaintext_fragment() {
        // Synthetic structured key that models a low-entropy secret.
        let secret = "AKIA-SYNTHETIC-EXAMPLE-1234-TAIL";
        let masked = mask_credential_value(secret);

        // No head or tail plaintext: the mask must not start with any
        // character sequence from the original value.
        assert!(
            !masked.contains("AKI"),
            "B3-1 regression: mask must not leak head chars; got: {masked}"
        );
        assert!(
            !masked.contains("AIL"),
            "B3-1 regression: mask must not leak tail chars; got: {masked}"
        );
        assert!(
            !masked.contains("ail"),
            "B3-1 regression: mask must not leak tail chars (lower); got: {masked}"
        );

        // No exact length: the mask must not contain the decimal digit string
        // equal to the secret's character count.
        let exact_len = secret.chars().count().to_string();
        assert!(
            !masked.contains(&exact_len),
            "B3-1 regression: mask must not expose exact length ({exact_len}); got: {masked}"
        );

        // The output is the fixed-form token.
        assert!(
            masked.starts_with("[REDACTED:"),
            "mask must be a fixed-form redacted token; got: {masked}"
        );
    }

    /// The synthetic secret from the RED R2 `PoC`: verify the `PoC` assertion is
    /// now inverted (the `PoC` proved the BUG; this proves the FIX).
    #[test]
    fn b3_1_poc_secret_no_longer_leaks() {
        let synthetic = "AKIA-SYNTHETIC-EXAMPLE-1234-TAIL";
        let masked = mask_credential_value(synthetic);

        // Pre-fix: masked.starts_with("AKI") was true — now it must be false.
        assert!(
            !masked.starts_with("AKI"),
            "B3-1 closed: mask must not start with head chars; got: {masked}"
        );
        // Pre-fix: masked.contains("ail (") was true — now it must be false.
        assert!(
            !masked.contains("ail ("),
            "B3-1 closed: mask must not contain tail+length; got: {masked}"
        );
        // Pre-fix: masked.contains("(32 chars)") was true — now it must be false.
        assert!(
            !masked.contains("(32 chars)"),
            "B3-1 closed: mask must not expose exact char count; got: {masked}"
        );
    }

    /// Verify coarse-bracket semantics across boundary values.
    #[test]
    fn coarse_bracket_boundaries() {
        assert_eq!(coarse_length_bracket(0), "empty");
        assert_eq!(coarse_length_bracket(1), "short");
        assert_eq!(coarse_length_bracket(15), "short");
        assert_eq!(coarse_length_bracket(16), "medium");
        assert_eq!(coarse_length_bracket(63), "medium");
        assert_eq!(coarse_length_bracket(64), "long");
        assert_eq!(coarse_length_bracket(255), "long");
        assert_eq!(coarse_length_bracket(256), "very-long");
    }

    /// Two secrets of different lengths within the same bracket must produce
    /// the same masked output (confirming no exact-length leak).
    #[test]
    fn different_lengths_same_bracket_produce_same_output() {
        // Both are "medium" (16–63 chars).
        let a = "a".repeat(20); // 20 chars
        let b = "b".repeat(50); // 50 chars
        assert_eq!(
            mask_credential_value(&a),
            mask_credential_value(&b),
            "different lengths in the same bucket must produce identical masked output"
        );
    }

    /// Short secret (≤ 15 chars) — no plaintext, coarse bracket.
    #[test]
    fn b3_1_short_secret_no_plaintext_no_exact_len() {
        let secret = "abc123"; // 6 chars — was "**** (6 chars)" pre-fix
        let masked = mask_credential_value(secret);

        // Pre-fix: masked == "**** (6 chars)" — leaked exact length 6.
        assert!(
            !masked.contains("(6 chars)"),
            "B3-1 regression: short secret must not leak exact length; got: {masked}"
        );
        // No plaintext chars from the secret.
        for c in ["abc", "123"] {
            assert!(
                !masked.contains(c),
                "mask must not contain plaintext fragment '{c}'; got: {masked}"
            );
        }
        assert_eq!(masked, "[REDACTED:short]");
    }

    /// Empty credential edge case.
    #[test]
    fn empty_credential_masked() {
        assert_eq!(mask_credential_value(""), "[REDACTED:empty]");
    }

    /// Multi-byte UTF-8 value: no panic, no plaintext fragment leaked.
    #[test]
    fn utf8_multibyte_no_plaintext() {
        // 20 Unicode chars (each 3 bytes in UTF-8) — "medium" bracket.
        let secret: String = "日".repeat(20);
        let masked = mask_credential_value(&secret);
        assert_eq!(masked, "[REDACTED:medium]");
        assert!(!masked.contains("日"));
    }
}
