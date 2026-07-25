//! Utility functions for storage operations
//!
//! Private helpers shared across storage sub-modules.

use chrono::{DateTime, Utc};

/// Convert arbitrary/untrusted user text into a safe FTS5 `MATCH` expression.
///
/// Each whitespace-separated token is wrapped in a double-quoted FTS5 *string*
/// (embedded `"` doubled), so every FTS5 metacharacter inside it — `:` (the
/// column-filter operator), `*`, `^`, `-`, `(`, `)`, `+`, and the operator
/// words `AND`/`OR`/`NOT`/`NEAR` — is treated as a literal search term instead
/// of query syntax. Tokens are combined with implicit AND. This never produces
/// an FTS5 syntax error and, unlike stripping, preserves non-ASCII (CJK/Cyrillic/
/// accented) terms so they still match what the `unicode61` tokenizer indexed.
///
/// Notes on robustness:
/// - Control characters (including NUL) are removed from each token; an embedded
///   NUL truncates the `SQLite` text and can still make FTS5 error.
/// - Tokens with no alphanumeric content (pure punctuation) are skipped, so we
///   never emit an empty `""` phrase (which itself makes FTS5 error).
/// - The whole-query length and term-count caps bound work as a cheap `DoS` guard.
///
/// Returns an empty string when no searchable term remains; the caller
/// (`search_snapshots_fts`) short-circuits on empty.
pub(super) fn sanitize_fts_query(query: &str) -> String {
    const MAX_QUERY_LENGTH: usize = 1000;
    const MAX_TERMS: usize = 20;

    let truncated: String = query.chars().take(MAX_QUERY_LENGTH).collect();

    truncated
        .split_whitespace()
        .filter_map(|token| {
            // Drop control chars (incl. NUL) that can break SQLite text / FTS5.
            let cleaned: String = token.chars().filter(|c| !c.is_control()).collect();
            // Keep only tokens with tokenizable (Unicode-aware) content so pure
            // punctuation does not become an empty `""` phrase.
            if cleaned.chars().any(char::is_alphanumeric) {
                // Wrap as an FTS5 literal string; escape embedded `"` by doubling.
                Some(format!("\"{}\"", cleaned.replace('"', "\"\"")))
            } else {
                None
            }
        })
        .take(MAX_TERMS)
        .collect::<Vec<_>>()
        .join(" ")
}

/// Validate a session ID to prevent path traversal and injection attacks
pub(super) fn validate_session_id(id: &str) -> crate::Result<()> {
    if id.is_empty() {
        return Err(crate::Error::InvalidInput(
            "Session ID cannot be empty".to_string(),
        ));
    }
    if id.starts_with('.') {
        return Err(crate::Error::InvalidInput(
            "Session ID cannot start with '.'".to_string(),
        ));
    }
    if id.len() > 128 {
        return Err(crate::Error::InvalidInput(
            "Session ID too long (max 128)".to_string(),
        ));
    }
    if !id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(crate::Error::InvalidInput(
            "Session ID contains invalid characters".to_string(),
        ));
    }
    if id.contains("..") {
        return Err(crate::Error::InvalidInput(
            "Session ID contains path traversal".to_string(),
        ));
    }
    Ok(())
}

/// Parse an RFC3339 datetime string, falling back to the Unix epoch on error
pub(super) fn parse_datetime(s: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(s).map_or(DateTime::UNIX_EPOCH, |dt| dt.with_timezone(&Utc))
}
