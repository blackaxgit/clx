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

/// Host-suffix patterns for Azure/OpenAI tenant endpoints that must be scrubbed
/// from logs and error messages (B6-2). These are provider infrastructure
/// hostnames — not secrets themselves, but are in the same disclosure class as
/// the previously-leaked tenant URL.
///
/// Matched as case-insensitive suffix of the `authority` (host[:port]) component
/// of any URL-like token in the text.
const AZURE_HOST_SUFFIXES: &[&str] = &[
    ".openai.azure.com",
    ".azure-api.net",
    ".cognitiveservices.azure.com",
];

/// Replacement token used when an Azure/OpenAI tenant host is scrubbed.
const AZURE_HOST_REDACTED: &str = "***AZURE-HOST-REDACTED***";

/// Scrub Azure/OpenAI tenant hostnames from `text`.
///
/// Finds URL-like tokens (`https?://`) and replaces the authority component
/// (host[:port]) when it ends with any of the [`AZURE_HOST_SUFFIXES`].
/// Non-matching authorities are left unchanged so that unrelated HTTPS URLs
/// (documentation links, etc.) are not over-redacted.
///
/// Also replaces bare hostname tokens (no scheme) that end with the same
/// suffixes, since Azure error bodies sometimes embed them without a scheme.
#[must_use]
fn redact_azure_hosts(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let lower = text.to_lowercase();
    let mut cursor = 0usize;

    // Pass 1: URL-bearing tokens (`https?://authority/...`).
    // We scan for `https://` or `http://` and then extract the authority.
    while cursor < text.len() {
        // Look for a scheme start.
        let scheme_pos = {
            let mut found = None;
            let search_from = cursor;
            for scheme in &["https://", "http://"] {
                if let Some(idx) = lower[search_from..].find(scheme) {
                    let abs = search_from + idx;
                    found = match found {
                        None => Some((abs, scheme.len())),
                        Some((prev, _)) if abs < prev => Some((abs, scheme.len())),
                        other => other,
                    };
                }
            }
            found
        };

        let Some((scheme_start, scheme_len)) = scheme_pos else {
            // No more URLs — append the rest and stop.
            out.push_str(&text[cursor..]);
            break;
        };

        // Append everything before the scheme.
        out.push_str(&text[cursor..scheme_start]);

        let authority_start = scheme_start + scheme_len;
        // Authority ends at the first `/`, `?`, `#`, space, `"`, `'`, or end.
        let authority_end = text[authority_start..]
            .find(['/', '?', '#', ' ', '"', '\'', '\n', '\r'])
            .map_or(text.len(), |i| authority_start + i);

        let authority = &text[authority_start..authority_end];
        let authority_lower = authority.to_lowercase();

        let is_azure = AZURE_HOST_SUFFIXES
            .iter()
            .any(|suf| authority_lower.ends_with(suf));

        if is_azure {
            // Replace just the authority; keep scheme visible so context is clear.
            out.push_str(&text[scheme_start..authority_start]);
            out.push_str(AZURE_HOST_REDACTED);
        } else {
            // Not an Azure host — keep scheme + authority verbatim.
            out.push_str(&text[scheme_start..authority_end]);
        }

        cursor = authority_end;
    }

    // Pass 2: bare hostname tokens (no scheme prefix) that end with an Azure suffix.
    // Many Azure error bodies embed hostnames like `synthetic-tenant.openai.azure.com`
    // without a leading `https://`. The boundary set must cover all characters that
    // reqwest and the url crate emit in their error strings:
    //   `:` — port separator: `tenant.openai.azure.com:443`
    //   `;` — field terminator: `tenant.openai.azure.com;`
    //   `<` / `>` — XML/HTML: `<tenant.openai.azure.com>`
    //   `=` / `&` / `?` — URL query: `host=tenant.openai.azure.com&port=443`
    //   `\` — Windows path separators in error text
    // T6/B6-2 fix: extend the delimiter set so post-fix punctuation does not
    // prevent the hostname token from being recognised and scrubbed.
    let mut result = String::with_capacity(out.len());
    let mut pos = 0usize;
    let out_bytes = out.as_bytes();
    while pos < out.len() {
        // A word boundary: find the next non-space, non-quote, non-special run.
        // We tokenise on whitespace and a small set of punctuation.
        let token_start = pos;
        let token_end = out[pos..]
            .find([
                ' ', '\t', '\n', '\r', '"', '\'', ',', '}', '{', '[', ']', '(', ')',
                // T6: additional boundaries for reqwest/url error output forms
                ':', ';', '<', '>', '=', '&', '?', '\\',
            ])
            .map_or(out.len(), |i| pos + i);

        if token_start == token_end {
            // Delimiter — emit and advance.
            result.push(out_bytes[pos] as char);
            pos += 1;
            continue;
        }

        let token = &out[token_start..token_end];
        // Skip tokens that already contain the redaction marker (from pass 1).
        if !token.contains("***AZURE-HOST-REDACTED***") {
            let token_lower = token.to_lowercase();
            // Strip a trailing path component if present — check authority portion.
            let authority_part = token_lower.split('/').next().unwrap_or("");
            let is_azure = AZURE_HOST_SUFFIXES
                .iter()
                .any(|suf| authority_part.ends_with(suf));
            if is_azure {
                result.push_str(AZURE_HOST_REDACTED);
                pos = token_end;
                continue;
            }
        }

        result.push_str(token);
        pos = token_end;
    }

    result
}

/// Redact known secret patterns from text before logging.
///
/// Uses simple prefix-based matching (no regex dependency). Catches common API key
/// prefixes, keyword=value patterns for tokens/passwords/secrets, Bearer tokens,
/// shell `export VAR=value` patterns where VAR contains a sensitive keyword, and
/// Azure/OpenAI tenant/endpoint hostnames (B6-2).
#[must_use]
pub fn redact_secrets(text: &str) -> String {
    // Apply Azure host redaction first so that subsequent passes do not
    // accidentally match partial tokens whose URL context has been stripped.
    let text_owned;
    let text: &str = if text.contains("://")
        || AZURE_HOST_SUFFIXES
            .iter()
            .any(|suf| text.to_lowercase().contains(*suf))
    {
        text_owned = redact_azure_hosts(text);
        &text_owned
    } else {
        text
    };
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
    // 3. Bearer / Basic auth token redaction (case-insensitive). Runs BEFORE
    //    the whitespace-tolerant keyword scan so `Authorization: bearer xyz`
    //    has the scheme prefix consumed first; otherwise section 2b would
    //    eat just the `bearer` word and leave the token behind.
    // -------------------------------------------------------------------------
    for scheme in &["bearer", "basic"] {
        // R1-A + PURPLE follow-up: match the scheme WORD then ANY whitespace
        // (space/tab/newline), at EVERY occurrence. The prior `"bearer "`
        // literal-space match missed `Bearer\t...` / `Bearer\n...` and is a
        // no-code-exec leak into logs/audit (Codex PURPLE NO-SHIP).
        let mut from = 0usize;
        loop {
            let lower_search = redacted.to_lowercase();
            let Some(rel) = lower_search.get(from..).and_then(|s| s.find(scheme)) else {
                break;
            };
            let after_kw = from + rel + scheme.len();
            // Require >=1 whitespace after the scheme word so `bearertoken`
            // is not treated as a scheme prefix.
            let mut cursor = after_kw;
            while cursor < redacted.len() && redacted.as_bytes()[cursor].is_ascii_whitespace() {
                cursor += 1;
            }
            if cursor == after_kw {
                from = after_kw;
                continue;
            }
            let token_start = cursor;
            let token_end = redacted[token_start..]
                .find(|c: char| c.is_whitespace() || c == '"' || c == '\'')
                .map_or(redacted.len(), |i| token_start + i);
            if token_end - token_start >= 6
                && !redacted[token_start..token_end].contains("***REDACTED***")
            {
                redacted.replace_range(token_start..token_end, "***REDACTED***");
                from = token_start + "***REDACTED***".len();
            } else {
                from = after_kw;
            }
        }
    }

    // -------------------------------------------------------------------------
    // 2b. Whitespace-tolerant keyword scan (`api_key = sk_test_...`,
    //     `authorization : Bearer ...`). Catches the gap where section 2's
    //     exact `keyword=` literal match misses values with spaces around
    //     the separator. Scheme tokens (`bearer`, `basic`) are skipped so
    //     the actual credential after them stays intact for downstream code.
    // -------------------------------------------------------------------------
    let tolerant_keywords = [
        "api_key",
        "api-key",
        "token",
        "password",
        "secret",
        "authorization",
    ];
    let lower = redacted.to_lowercase();
    let mut tolerant_replacements: Vec<(usize, usize)> = Vec::new();
    for kw in &tolerant_keywords {
        let mut search_from = 0;
        while let Some(idx) = lower[search_from..].find(kw) {
            let abs = search_from + idx;
            let mut cursor = abs + kw.len();
            // Skip whitespace then require `=` or `:`.
            while cursor < redacted.len()
                && redacted.as_bytes()[cursor].is_ascii_whitespace()
                && redacted.as_bytes()[cursor] != b'\n'
            {
                cursor += 1;
            }
            if cursor >= redacted.len()
                || (redacted.as_bytes()[cursor] != b'=' && redacted.as_bytes()[cursor] != b':')
            {
                search_from = abs + kw.len();
                continue;
            }
            cursor += 1; // past separator
            // R1-D: skip newlines too, so `password:\n<secret>` (value on the
            // next line, common in YAML / pretty-printed error bodies) is caught.
            while cursor < redacted.len() && redacted.as_bytes()[cursor].is_ascii_whitespace() {
                cursor += 1;
            }
            // Skip over scheme tokens (`Bearer`, `Basic`) so the actual
            // credential after them is what we redact (handled in section 3
            // above; here we just skip the marker so we don't redact the
            // scheme name instead of the token).
            let value_start_initial = cursor;
            let after_word_end = redacted[value_start_initial..]
                .find(|c: char| c.is_whitespace() || c == '"' || c == '\'')
                .map_or(redacted.len(), |i| value_start_initial + i);
            let first_word = &redacted[value_start_initial..after_word_end];
            let first_word_lower = first_word.to_lowercase();
            if first_word_lower == "bearer" || first_word_lower == "basic" {
                // Scheme already handled above; advance past it.
                search_from = after_word_end;
                continue;
            }
            let value_start = cursor;
            let value_end = after_word_end;
            // R1-B: redact ANY non-empty value after a security keyword. The
            // prior `> value_start + 4` floor let short secrets (PINs, OTPs,
            // short tokens) slip; the strong keyword context justifies it.
            if value_end > value_start
                && !redacted[value_start..value_end].contains("***REDACTED***")
            {
                tolerant_replacements.push((value_start, value_end));
            }
            search_from = value_end;
        }
    }
    for (s, e) in tolerant_replacements.into_iter().rev() {
        redacted.replace_range(s..e, "***REDACTED***");
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

    // Codex PURPLE NO-SHIP regression: scheme followed by tab/newline (not just
    // a literal space) must still redact the token, at EVERY occurrence.
    #[test]
    fn test_redact_secrets_bearer_tab_and_newline_after_scheme() {
        let r = redact_secrets("Authorization:\nBearer\tSECRETVALUE123456");
        assert!(
            !r.contains("SECRETVALUE123456"),
            "tab-after-Bearer must redact: {r}"
        );
        let r2 = redact_secrets("Bearer\nANOTHERSECRET987654");
        assert!(
            !r2.contains("ANOTHERSECRET987654"),
            "newline-after-Bearer must redact: {r2}"
        );
        let r3 = redact_secrets("Bearer firsttoken111111 and Bearer secondtoken222222");
        assert!(
            !r3.contains("firsttoken111111"),
            "first token must redact: {r3}"
        );
        assert!(
            !r3.contains("secondtoken222222"),
            "second token must redact: {r3}"
        );
        let r4 = redact_secrets("Basic\tdXNlcjpwYXNzd29yZA==");
        assert!(
            !r4.contains("dXNlcjpwYXNzd29yZA=="),
            "tab-after-Basic must redact: {r4}"
        );
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
        assert_eq!(
            r["request"]["headers"]["authorization"],
            json!("***REDACTED***")
        );
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
        assert_eq!(r["a"]["b"]["c"]["d"]["secret"], json!("***REDACTED***"));
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

    // -------------------------------------------------------------------------
    // Wave-4c Purple Team regressions (Red Team F1: free-text redaction gaps)
    // -------------------------------------------------------------------------

    #[test]
    fn redacts_keyword_with_whitespace_around_equals() {
        let result = redact_secrets("user said api_key = sk_test_abcdef1234 hello");
        assert!(
            !result.contains("sk_test_abcdef1234"),
            "whitespace-around-= keyword leaked: {result}"
        );
        assert!(result.contains("***REDACTED***"));
    }

    #[test]
    fn redacts_keyword_with_whitespace_around_colon() {
        let result = redact_secrets("authorization : Bearer eyJabcdef1234");
        assert!(
            !result.contains("eyJabcdef1234"),
            "whitespace-around-: keyword leaked: {result}"
        );
    }

    #[test]
    fn redacts_lowercase_bearer_token() {
        let result = redact_secrets("Authorization: bearer eyJabcdefghij1234");
        assert!(
            !result.contains("eyJabcdefghij1234"),
            "lowercase bearer leaked: {result}"
        );
    }

    #[test]
    fn redacts_basic_auth_token() {
        let result = redact_secrets("Authorization: Basic dXNlcjpwd2Q12345");
        assert!(
            !result.contains("dXNlcjpwd2Q12345"),
            "Basic auth credential leaked: {result}"
        );
    }

    // =========================================================================
    // B6-2 regression tests (GREEN G2) — Azure/OpenAI tenant host scrubbing
    //
    // These tests FAIL on pre-fix code (no host pattern in redact_secrets) and
    // PASS after the fix (redact_azure_hosts integrated into redact_secrets).
    //
    // ALL hosts used here are SYNTHETIC — the real leaked tenant URL appears
    // nowhere in this file.
    // =========================================================================

    /// B6-2 regression: `redact_secrets` must scrub a `*.openai.azure.com`
    /// tenant host that appears inside an HTTPS URL in the text.
    #[test]
    fn b6_2_redact_secrets_scrubs_openai_azure_com_host_in_url() {
        let text = r#"{"error":{"message":"Access denied at https://synthetic-tenant.openai.azure.com/openai/deployments/d/chat"}}"#;
        let result = redact_secrets(text);
        assert!(
            !result.contains("synthetic-tenant.openai.azure.com"),
            "B6-2 REGRESSION: *.openai.azure.com host leaked through redact_secrets: {result}"
        );
        assert!(
            result.contains("***AZURE-HOST-REDACTED***"),
            "redacted token must appear in output: {result}"
        );
    }

    /// B6-2 regression: `redact_secrets` must scrub a `*.azure-api.net` host.
    #[test]
    fn b6_2_redact_secrets_scrubs_azure_api_net_host_in_url() {
        let text = "endpoint=https://synthetic-tenant.azure-api.net/v1/chat";
        let result = redact_secrets(text);
        assert!(
            !result.contains("synthetic-tenant.azure-api.net"),
            "B6-2 REGRESSION: *.azure-api.net host leaked through redact_secrets: {result}"
        );
    }

    /// B6-2 regression: `redact_secrets` must scrub a `*.cognitiveservices.azure.com` host.
    #[test]
    fn b6_2_redact_secrets_scrubs_cognitiveservices_host_in_url() {
        let text = "resource at https://synthetic-tenant.cognitiveservices.azure.com/openai";
        let result = redact_secrets(text);
        assert!(
            !result.contains("synthetic-tenant.cognitiveservices.azure.com"),
            "B6-2 REGRESSION: *.cognitiveservices.azure.com host leaked: {result}"
        );
    }

    /// B6-2 regression: `redact_secrets` must scrub a bare hostname (no scheme)
    /// that ends with a known Azure suffix, as Azure error bodies sometimes embed
    /// the host without an `https://` prefix.
    #[test]
    fn b6_2_redact_secrets_scrubs_bare_azure_hostname() {
        let text = "host synthetic-tenant.openai.azure.com returned 401";
        let result = redact_secrets(text);
        assert!(
            !result.contains("synthetic-tenant.openai.azure.com"),
            "B6-2 REGRESSION: bare Azure hostname leaked through redact_secrets: {result}"
        );
    }

    /// B6-2 non-regression: `redact_secrets` must NOT over-redact unrelated HTTPS
    /// URLs (e.g. documentation links, Ollama localhost, non-Azure endpoints).
    #[test]
    fn b6_2_redact_secrets_does_not_over_redact_unrelated_urls() {
        let safe_texts = [
            "see https://docs.example.com/guide for more info",
            "ollama at http://127.0.0.1:11434/api/tags",
            "endpoint https://api.openai.com/v1/chat/completions",
        ];
        for text in &safe_texts {
            let result = redact_secrets(text);
            assert_eq!(
                result, *text,
                "B6-2: safe URL was over-redacted by redact_secrets: input={text:?} output={result:?}"
            );
        }
    }

    /// B6-2 regression: `redact_json_value` must also scrub Azure tenant hosts
    /// embedded in string values (via the `redact_secrets` path it delegates to).
    #[test]
    fn b6_2_redact_json_value_scrubs_azure_host_in_string_leaf() {
        let v = serde_json::json!({
            "log": "error at https://synthetic-tenant.openai.azure.com/openai/deployments/d",
            "safe": "normal text"
        });
        let r = redact_json_value(&v);
        let log_str = r["log"].as_str().unwrap();
        assert!(
            !log_str.contains("synthetic-tenant.openai.azure.com"),
            "B6-2 REGRESSION: Azure host leaked through redact_json_value string leaf: {log_str}"
        );
        assert_eq!(r["safe"], serde_json::json!("normal text"));
    }

    /// B6-2 regression: the `redact_azure_hosts` internal function handles the
    /// exact synthetic body shape used in the RED R2 `PoC` (`b6_2_redact_secrets_leaves_tenant_url_intact`).
    #[test]
    fn b6_2_redact_azure_hosts_handles_poc_body_shape() {
        // Same shape as SYNTH_AZURE_BODY in red_r2_poc.rs — synthetic host only.
        let poc_body = r#"{"error":{"code":"401","message":"Access denied due to invalid subscription key. Make sure to provide a valid key for the resource at https://synthetic-tenant.example-openai.invalid/openai/deployments/synthetic-deploy/chat/completions"}}"#;
        // Note: example-openai.invalid does NOT end with our Azure suffixes, so it
        // is intentionally NOT scrubbed — the PoC uses a non-`.openai.azure.com`
        // domain on purpose (rules of engagement: no real tenant). The B6-2 fix
        // targets the real suffix class; over-redacting `.invalid` TLDs would be
        // wrong. This test documents that contract explicitly.
        let result = redact_secrets(poc_body);
        // The `.invalid` synthetic host is not in our suffix list — that's correct.
        // What matters is that REAL Azure suffixes ARE scrubbed (tested above).
        // This test pins the "no over-redaction of .invalid" contract.
        assert!(
            result.contains("example-openai.invalid"),
            "synthetic .invalid host should NOT be scrubbed (not in Azure suffix list): {result}"
        );
    }

    // =========================================================================
    // T6 regression tests — extended boundary set for bare hostname pass
    //
    // These tests FAIL on pre-fix code (boundary set at redaction.rs:110-112
    // missing `:`, `;`, `<`, `>`, `=`, `&`, `?`, `\`) and PASS after the fix.
    //
    // Counterexamples from the Codex audit:
    //   - `tenant.openai.azure.com:443`    (colon/port suffix)
    //   - `tenant.openai.azure.com;`       (semicolon terminator)
    //   - `host=tenant.openai.azure.com&port=443`  (query-param form)
    //
    // ALL hosts used here are SYNTHETIC.
    // =========================================================================

    /// T6 regression: bare hostname with a `:port` suffix must be redacted.
    ///
    /// reqwest errors from connection failures embed the target as
    /// `tcp connect error: Connection refused (os error 61), url: <URL>` which
    /// after URL parsing can surface as `host:port`. The `:` was previously
    /// not in the Pass-2 boundary set, so `synthetic-tenant.openai.azure.com:443`
    /// was not split and the authority did not match any Azure suffix.
    #[test]
    fn t6_regression_bare_hostname_with_port_is_redacted() {
        let text = "connect error at synthetic-tenant.openai.azure.com:443 failed";
        let result = redact_secrets(text);
        assert!(
            !result.contains("synthetic-tenant.openai.azure.com"),
            "T6 REGRESSION: bare Azure hostname with :port leaked: {result}"
        );
        assert!(
            result.contains("***AZURE-HOST-REDACTED***"),
            "redacted token must appear in output: {result}"
        );
    }

    /// T6 regression: bare hostname with a `;` terminator must be redacted.
    ///
    /// Some HTTP/1.1 error strings and log formats use semicolons as field
    /// separators: `host: synthetic-tenant.openai.azure.com; status: 401`.
    #[test]
    fn t6_regression_bare_hostname_semicolon_terminated_is_redacted() {
        let text = "host: synthetic-tenant.openai.azure.com; status: 401";
        let result = redact_secrets(text);
        assert!(
            !result.contains("synthetic-tenant.openai.azure.com"),
            "T6 REGRESSION: semicolon-terminated Azure hostname leaked: {result}"
        );
    }

    /// T6 regression: hostname in a query-param form `host=<host>&port=443`
    /// must be redacted. The `=` preceding the hostname and `&` following it
    /// were both missing from the old boundary set.
    #[test]
    fn t6_regression_hostname_in_query_param_form_is_redacted() {
        let text = "error: host=synthetic-tenant.openai.azure.com&port=443";
        let result = redact_secrets(text);
        assert!(
            !result.contains("synthetic-tenant.openai.azure.com"),
            "T6 REGRESSION: hostname in query-param form leaked: {result}"
        );
    }

    /// T6 regression: `?` query separator following hostname must split correctly.
    #[test]
    fn t6_regression_hostname_followed_by_query_separator_is_redacted() {
        let text = "url: synthetic-tenant.openai.azure.com?api-version=2024-10-21";
        let result = redact_secrets(text);
        assert!(
            !result.contains("synthetic-tenant.openai.azure.com"),
            "T6 REGRESSION: hostname before ? query separator leaked: {result}"
        );
    }

    /// T6 regression: `<host>` XML/HTML-embedded form must be redacted.
    #[test]
    fn t6_regression_hostname_in_xml_angle_brackets_is_redacted() {
        let text = "resource=<synthetic-tenant.openai.azure.com>";
        let result = redact_secrets(text);
        assert!(
            !result.contains("synthetic-tenant.openai.azure.com"),
            "T6 REGRESSION: hostname in XML angle brackets leaked: {result}"
        );
    }

    /// T6 non-regression: the extended boundary set must not over-redact
    /// safe tokens that happen to contain boundary characters adjacent to
    /// non-Azure hostnames.
    #[test]
    fn t6_does_not_over_redact_safe_hosts_with_ports() {
        // api.openai.com is NOT an Azure suffix — must not be scrubbed.
        let text = "api.openai.com:443 is fine";
        let result = redact_secrets(text);
        assert_eq!(
            result, text,
            "T6: safe non-Azure host with port was over-redacted: {result}"
        );
    }
}
