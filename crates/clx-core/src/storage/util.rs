//! Utility functions for storage operations
//!
//! Private helpers shared across storage sub-modules.

use chrono::{DateTime, Utc};

/// Sanitize a user query for FTS5 MATCH syntax
///
/// Strips FTS5 special characters and joins remaining terms with spaces
/// (implicit AND). Returns an empty string if no valid terms remain.
pub(super) fn sanitize_fts_query(query: &str) -> String {
    const MAX_QUERY_LENGTH: usize = 1000;
    const MAX_TERMS: usize = 20;
    const MIN_TERM_LENGTH: usize = 2;
    const MAX_TERM_LENGTH: usize = 50;

    // FTS5 reserved words that could be used as operators
    const FTS5_OPERATORS: &[&str] = &["AND", "OR", "NOT", "NEAR"];

    let truncated: String = query.chars().take(MAX_QUERY_LENGTH).collect();

    truncated
        .split_whitespace()
        .map(|word| {
            word.chars()
                .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
                .collect::<String>()
        })
        .filter(|w| {
            w.len() >= MIN_TERM_LENGTH
                && w.len() <= MAX_TERM_LENGTH
                && !FTS5_OPERATORS.contains(&w.to_uppercase().as_str())
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
    DateTime::parse_from_rfc3339(s)
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or(DateTime::UNIX_EPOCH)
}
