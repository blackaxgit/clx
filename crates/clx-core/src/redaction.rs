//! Shared secret redaction utilities.
//!
//! Provides [`redact_secrets`] which scrubs known secret patterns from text
//! before it is logged, persisted, or displayed. Uses simple prefix-based and
//! keyword-based matching, no regex dependency required.
//!
//! Also provides [`redact_json_value`] which walks a `serde_json::Value`
//! recursively, redacting (a) values whose key matches a sensitive pattern
//! (`api_key`, `password`, `secret`, `token`, `authorization`, `credential`, ...),
//! and (b) string leaves that contain a known secret pattern.

use serde_json::Value;

/// Redact known secret patterns from text before logging.
///
/// Uses simple prefix-based matching (no regex dependency). Catches common API key
/// prefixes, keyword=value patterns for tokens/passwords/secrets, Bearer tokens,
/// and shell `export VAR=value` patterns where VAR contains a sensitive keyword.
#[must_use]
pub fn redact_secrets(text: &str) -> String {
    let mut redacted = text.to_string();

    // -------------------------------------------------------------------------
    // 1. Simple prefix-based redaction (single-pass per prefix)
    // -------------------------------------------------------------------------
    let prefixes = ["sk-", "pk-", "ghp_", "gho_", "xoxb-", "xoxp-"];
    for prefix in &prefixes {
        let replacement = format!("{prefix}***REDACTED***");
        let positions: Vec<usize> = {
            let mut pos = Vec::new();
            let mut search_from = 0;
            while let Some(idx) = redacted[search_from..].find(prefix) {
                pos.push(search_from + idx);
                search_from = search_from + idx + prefix.len();
            }
            pos
        };
        // Apply replacements in reverse to preserve positions
        for &start in positions.iter().rev() {
            let end = redacted[start..]
                .find(|c: char| c.is_whitespace() || c == '"' || c == '\'')
                .map_or(redacted.len(), |i| start + i);
            if end - start > prefix.len() + 4 {
                redacted.replace_range(start..end, &replacement);
            }
        }
    }

    // -------------------------------------------------------------------------
    // 2. Keyword=value redaction (case-insensitive, single-pass per keyword)
    // -------------------------------------------------------------------------
    let keywords = [
        "api_key=",
        "api-key=",
        "token=",
        "password=",
        "secret=",
        "api_key:",
        "api-key:",
        "token:",
        "password:",
        "secret:",
    ];
    for keyword in &keywords {
        let lower = redacted.to_lowercase();
        let kw_lower = keyword.to_lowercase();
        let positions: Vec<usize> = {
            let mut pos = Vec::new();
            let mut search_from = 0;
            while let Some(idx) = lower[search_from..].find(&kw_lower) {
                pos.push(search_from + idx);
                search_from = search_from + idx + keyword.len();
            }
            pos
        };
        for &kw_start in positions.iter().rev() {
            let value_start = kw_start + keyword.len();
            let value_end = redacted[value_start..]
                .find(|c: char| c.is_whitespace() || c == '"' || c == '\'')
                .map_or(redacted.len(), |i| value_start + i);
            let value = &redacted[value_start..value_end];
            // Skip if already redacted by prefix-based pass
            if value_end > value_start && !value.contains("***REDACTED***") {
                redacted.replace_range(value_start..value_end, "***REDACTED***");
            }
        }
    }

    // -------------------------------------------------------------------------
    // 3. Bearer token redaction
    // -------------------------------------------------------------------------
    if let Some(bearer_start) = redacted.find("Bearer ") {
        let token_start = bearer_start + 7;
        if redacted.len() > token_start + 20 {
            let token_end = redacted[token_start..]
                .find(|c: char| c.is_whitespace() || c == '"' || c == '\'')
                .map_or(redacted.len(), |i| token_start + i);
            if token_end - token_start >= 20 {
                redacted.replace_range(token_start..token_end, "***REDACTED***");
            }
        }
    }

    // -------------------------------------------------------------------------
    // 4. Shell export pattern: `export VAR=value` where VAR contains a
    //    sensitive keyword (SECRET, TOKEN, KEY, PASSWORD, CREDENTIAL, API).
    //    Also handles optional quoting: export VAR="value" / export VAR='value'
    // -------------------------------------------------------------------------
    let sensitive_keywords = ["SECRET", "TOKEN", "KEY", "PASSWORD", "CREDENTIAL", "API"];

    // Collect replacement ranges first to avoid mutation-during-scan issues.
    let mut export_replacements: Vec<(usize, usize)> = Vec::new();

    {
        let search = &redacted;
        let mut search_from = 0;
        while let Some(idx) = search[search_from..].find("export ") {
            let abs_idx = search_from + idx;
            let after_export = abs_idx + 7; // length of "export "

            // Skip extra whitespace after "export "
            let var_start =
                if let Some(offset) = search[after_export..].find(|c: char| !c.is_whitespace()) {
                    after_export + offset
                } else {
                    search_from = after_export;
                    continue;
                };

            // Find the '=' that ends the variable name
            let eq_pos = if let Some(offset) = search[var_start..].find('=') {
                var_start + offset
            } else {
                search_from = after_export;
                continue;
            };

            let var_name = &search[var_start..eq_pos];
            let var_upper = var_name.to_uppercase();

            // Check if the variable name contains any sensitive keyword
            let is_sensitive = sensitive_keywords.iter().any(|kw| var_upper.contains(kw));

            if is_sensitive {
                let value_start = eq_pos + 1;
                if value_start < search.len() {
                    let first_char = search.as_bytes().get(value_start).copied();
                    let (val_start, val_end) = match first_char {
                        Some(b'"') => {
                            // Quoted with double-quote — find closing quote
                            let inner_start = value_start + 1;
                            let inner_end = search[inner_start..]
                                .find('"')
                                .map_or(search.len(), |i| inner_start + i);
                            (inner_start, inner_end)
                        }
                        Some(b'\'') => {
                            // Quoted with single-quote — find closing quote
                            let inner_start = value_start + 1;
                            let inner_end = search[inner_start..]
                                .find('\'')
                                .map_or(search.len(), |i| inner_start + i);
                            (inner_start, inner_end)
                        }
                        _ => {
                            // Unquoted — value extends to next whitespace
                            let val_end = search[value_start..]
                                .find(|c: char| c.is_whitespace())
                                .map_or(search.len(), |i| value_start + i);
                            (value_start, val_end)
                        }
                    };

                    if val_end > val_start {
                        let value_slice = &search[val_start..val_end];
                        if !value_slice.contains("***REDACTED***") {
                            export_replacements.push((val_start, val_end));
                        }
                    }
                }
            }

            search_from = eq_pos + 1;
        }
    }

    // Apply export replacements in reverse order to preserve positions
    for &(start, end) in export_replacements.iter().rev() {
        redacted.replace_range(start..end, "***REDACTED***");
    }

    redacted
}

// =============================================================================
// JSON-aware redaction
// =============================================================================

/// Substring patterns (case-insensitive) that mark an object KEY as carrying a
/// secret value. Any key whose lowercased form contains one of these patterns
/// will have its associated value replaced with `"***REDACTED***"`.
///
/// Kept as a `&[&str]` (not regex) so the cost is a handful of `contains()`
/// calls per object key — cheap enough to run in a hot hook path.
const SENSITIVE_KEY_PATTERNS: &[&str] = &[
    "api_key",
    "api-key",
    "apikey",
    "password",
    "passwd",
    "secret",
    "token",
    "authorization",
    "auth_token",
    "auth-token",
    "credential",
    "private_key",
    "private-key",
    "access_key",
    "access-key",
    "session_key",
    "session-key",
    "client_secret",
    "client-secret",
    "bearer",
];

/// Return `true` if `key` looks sensitive under case-insensitive substring
/// matching against [`SENSITIVE_KEY_PATTERNS`].
#[must_use]
fn is_sensitive_key(key: &str) -> bool {
    let lower = key.to_lowercase();
    SENSITIVE_KEY_PATTERNS.iter().any(|p| lower.contains(p))
}

/// Walk a `serde_json::Value` recursively and redact secrets.
///
/// Rules:
/// - `Object`: if a key matches [`is_sensitive_key`], its value is replaced
///   with `"***REDACTED***"` regardless of variant. Otherwise the value is
///   recursed into.
/// - `Array`: each element is recursed into.
/// - `String`: routed through [`redact_secrets`] so inline secrets (e.g.
///   `Bearer ...`, `sk-...`, `export SECRET=...`) are scrubbed.
/// - `Number`, `Bool`, `Null`: passed through unchanged.
///
/// This is a pure function: no IO, no panics, no allocation amplification
/// beyond the size of the input.
#[must_use]
pub fn redact_json_value(v: &Value) -> Value {
    match v {
        Value::Object(map) => {
            let mut out = serde_json::Map::with_capacity(map.len());
            for (k, val) in map {
                if is_sensitive_key(k) {
                    out.insert(k.clone(), Value::String("***REDACTED***".to_string()));
                } else {
                    out.insert(k.clone(), redact_json_value(val));
                }
            }
            Value::Object(out)
        }
        Value::Array(arr) => Value::Array(arr.iter().map(redact_json_value).collect()),
        Value::String(s) => Value::String(redact_secrets(s)),
        other => other.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // Prefix-based redaction
    // =========================================================================

    #[test]
    fn test_redact_secrets_api_key_prefix() {
        let input = "curl -H 'Authorization: sk-abcdefghijklmnopqrstuvwxyz1234567890'";
        let redacted = redact_secrets(input);
        assert!(redacted.contains("sk-***REDACTED***"));
        assert!(!redacted.contains("abcdefghijklmnopqrstuvwxyz"));
    }

    #[test]
    fn test_redact_secrets_github_token() {
        let input = "export GITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij123456";
        let redacted = redact_secrets(input);
        assert!(redacted.contains("ghp_***REDACTED***"));
        assert!(!redacted.contains("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij123456"));
    }

    #[test]
    fn test_redact_secrets_slack_token() {
        let input = "xoxb-FAKE-TOKEN-FOR-TESTING";
        let redacted = redact_secrets(input);
        assert!(redacted.contains("xoxb-***REDACTED***"));
    }

    #[test]
    fn test_redact_secrets_short_prefix_no_redact() {
        // Prefix followed by too few characters should not be redacted
        let input = "sk-abc";
        let redacted = redact_secrets(input);
        assert_eq!(redacted, input);
    }

    // =========================================================================
    // Keyword=value redaction
    // =========================================================================

    #[test]
    fn test_redact_secrets_keyword_value() {
        let input = "api_key=mysecretapikey123 other_flag=safe";
        let redacted = redact_secrets(input);
        assert!(redacted.contains("api_key=***REDACTED***"));
        assert!(!redacted.contains("mysecretapikey123"));
    }

    #[test]
    fn test_redact_secrets_password() {
        let input = "password=hunter2";
        let redacted = redact_secrets(input);
        assert!(redacted.contains("password=***REDACTED***"));
        assert!(!redacted.contains("hunter2"));
    }

    #[test]
    fn test_redact_secrets_keyword_colon() {
        let input = "password:hunter2 token:abc123longvalue";
        let redacted = redact_secrets(input);
        assert!(redacted.contains("password:***REDACTED***"));
        assert!(redacted.contains("token:***REDACTED***"));
    }

    // =========================================================================
    // Bearer token redaction
    // =========================================================================

    #[test]
    fn test_redact_secrets_bearer_token() {
        let input = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
        let redacted = redact_secrets(input);
        assert!(redacted.contains("Bearer ***REDACTED***"));
        assert!(!redacted.contains("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"));
    }

    // =========================================================================
    // No secrets — passthrough
    // =========================================================================

    #[test]
    fn test_redact_secrets_no_secrets() {
        let input = "git status && ls -la";
        let redacted = redact_secrets(input);
        assert_eq!(redacted, input);
    }

    // =========================================================================
    // Export pattern redaction (Issue N7)
    // =========================================================================

    #[test]
    fn test_redact_export_secret_unquoted() {
        let input = "export MY_SECRET=supersecretvalue123";
        let redacted = redact_secrets(input);
        assert!(
            redacted.contains("MY_SECRET=***REDACTED***"),
            "got: {redacted}",
        );
        assert!(!redacted.contains("supersecretvalue123"));
    }

    #[test]
    fn test_redact_export_token_double_quoted() {
        let input = r#"export API_TOKEN="mytokenvalue""#;
        let redacted = redact_secrets(input);
        assert!(redacted.contains("***REDACTED***"), "got: {redacted}");
        assert!(!redacted.contains("mytokenvalue"));
    }

    #[test]
    fn test_redact_export_password_single_quoted() {
        let input = "export DB_PASSWORD='hunter2secret'";
        let redacted = redact_secrets(input);
        assert!(redacted.contains("***REDACTED***"), "got: {redacted}");
        assert!(!redacted.contains("hunter2secret"));
    }

    #[test]
    fn test_redact_export_credential() {
        let input = "export SOME_CREDENTIAL=abc123def456";
        let redacted = redact_secrets(input);
        assert!(redacted.contains("***REDACTED***"), "got: {redacted}");
        assert!(!redacted.contains("abc123def456"));
    }

    #[test]
    fn test_redact_export_api_key() {
        let input = "export MY_API_KEY=myapikey999";
        let redacted = redact_secrets(input);
        assert!(redacted.contains("***REDACTED***"), "got: {redacted}");
        assert!(!redacted.contains("myapikey999"));
    }

    #[test]
    fn test_no_redact_export_safe_var() {
        // PATH does not contain any sensitive keyword
        let input = "export PATH=/usr/local/bin:/usr/bin";
        let redacted = redact_secrets(input);
        assert_eq!(redacted, input);
    }

    #[test]
    fn test_no_redact_export_home() {
        let input = "export HOME=/Users/alice";
        let redacted = redact_secrets(input);
        assert_eq!(redacted, input);
    }

    #[test]
    fn test_redact_multiple_exports() {
        let input = "export SECRET_A=aaa export TOKEN_B=bbb";
        let redacted = redact_secrets(input);
        assert!(!redacted.contains("aaa"), "got: {redacted}");
        assert!(!redacted.contains("bbb"), "got: {redacted}");
    }

    // =========================================================================
    // JSON-aware redaction (Issue 1: JSON-structured secrets bypass)
    // =========================================================================

    use serde_json::json;

    #[test]
    fn test_redact_json_object_sensitive_key() {
        let v = json!({"api_key": "plainsecretvalue", "name": "alice"});
        let r = redact_json_value(&v);
        assert_eq!(r["api_key"], json!("***REDACTED***"));
        assert_eq!(r["name"], json!("alice"));
    }

    #[test]
    fn test_redact_json_case_insensitive_keys() {
        let v = json!({
            "API_KEY": "secret1",
            "Password": "secret2",
            "AuthToken": "secret3",
            "AUTHORIZATION": "Bearer abc"
        });
        let r = redact_json_value(&v);
        assert_eq!(r["API_KEY"], json!("***REDACTED***"));
        assert_eq!(r["Password"], json!("***REDACTED***"));
        assert_eq!(r["AuthToken"], json!("***REDACTED***"));
        assert_eq!(r["AUTHORIZATION"], json!("***REDACTED***"));
    }

    #[test]
    fn test_redact_json_nested_objects() {
        let v = json!({
            "request": {
                "headers": {
                    "authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.x.y"
                },
                "body": {"safe_field": "ok"}
            }
        });
        let r = redact_json_value(&v);
        assert_eq!(r["request"]["headers"]["authorization"], json!("***REDACTED***"));
        assert_eq!(r["request"]["body"]["safe_field"], json!("ok"));
    }

    #[test]
    fn test_redact_json_array_of_objects() {
        let v = json!([
            {"api_key": "sec1", "id": 1},
            {"api_key": "sec2", "id": 2}
        ]);
        let r = redact_json_value(&v);
        assert_eq!(r[0]["api_key"], json!("***REDACTED***"));
        assert_eq!(r[1]["api_key"], json!("***REDACTED***"));
        assert_eq!(r[0]["id"], json!(1));
    }

    #[test]
    fn test_redact_json_string_leaf_contains_secret_pattern() {
        // A plain string value (not under a sensitive key) that itself
        // contains a known secret pattern must still be scrubbed by the
        // string-level pass.
        let v = json!({"log": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.AAA.BBB"});
        let r = redact_json_value(&v);
        let s = r["log"].as_str().unwrap();
        assert!(s.contains("Bearer ***REDACTED***"), "got: {s}");
    }

    #[test]
    fn test_redact_json_empty_object_and_array() {
        assert_eq!(redact_json_value(&json!({})), json!({}));
        assert_eq!(redact_json_value(&json!([])), json!([]));
        assert_eq!(redact_json_value(&json!(null)), json!(null));
    }

    #[test]
    fn test_redact_json_non_string_types_passthrough() {
        let v = json!({"count": 42, "ok": true, "ratio": 1.5, "missing": null});
        let r = redact_json_value(&v);
        assert_eq!(r["count"], json!(42));
        assert_eq!(r["ok"], json!(true));
        assert_eq!(r["ratio"], json!(1.5));
        assert_eq!(r["missing"], json!(null));
    }

    #[test]
    fn test_redact_json_deeply_nested_five_levels() {
        let v = json!({
            "a": {"b": {"c": {"d": {"secret": "deeplyhiddenvalue"}}}}
        });
        let r = redact_json_value(&v);
        assert_eq!(
            r["a"]["b"]["c"]["d"]["secret"],
            json!("***REDACTED***")
        );
    }

    #[test]
    fn test_redact_json_sensitive_key_redacts_non_string_value() {
        // Even if a sensitive key carries an object (e.g. a serialized
        // credential blob), the whole value must be redacted to prevent
        // partial exposure of nested fields.
        let v = json!({"credentials": {"user": "alice", "pass": "hunter2"}});
        let r = redact_json_value(&v);
        assert_eq!(r["credentials"], json!("***REDACTED***"));
    }

    #[test]
    fn test_redact_json_mixed_array_strings_and_objects() {
        let v = json!([
            "plain string",
            "sk-abcdefghijklmnopqrstuvwxyz1234567890",
            {"token": "secrettoken"},
            42
        ]);
        let r = redact_json_value(&v);
        assert_eq!(r[0], json!("plain string"));
        let scrubbed = r[1].as_str().unwrap();
        assert!(scrubbed.contains("sk-***REDACTED***"), "got: {scrubbed}");
        assert_eq!(r[2]["token"], json!("***REDACTED***"));
        assert_eq!(r[3], json!(42));
    }

    #[test]
    fn test_redact_json_preserves_safe_keys() {
        let v = json!({
            "file_path": "/tmp/foo.rs",
            "command": "ls -la",
            "count": 7
        });
        let r = redact_json_value(&v);
        assert_eq!(r, v, "non-sensitive payload must round-trip unchanged");
    }

    #[test]
    fn test_redact_json_partial_match_in_key() {
        // Keys like "github_token", "x-api-key", "client_secret_id" must
        // all be considered sensitive via substring matching.
        let v = json!({
            "github_token": "ghp_xxx",
            "x-api-key": "abc",
            "client_secret_id": "def"
        });
        let r = redact_json_value(&v);
        assert_eq!(r["github_token"], json!("***REDACTED***"));
        assert_eq!(r["x-api-key"], json!("***REDACTED***"));
        assert_eq!(r["client_secret_id"], json!("***REDACTED***"));
    }
}
