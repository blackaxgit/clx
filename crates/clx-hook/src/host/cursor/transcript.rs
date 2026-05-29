//! Cursor `state.vscdb` `SQLite` transcript parser (best-effort, P0 F7).
//!
//! Cursor (a VS Code fork) persists workbench state in a `SQLite` database
//! `state.vscdb` as a single key-value table `ItemTable(key TEXT, value BLOB)`.
//! Chat history is stored under one of a few JSON-valued keys. The exact key
//! and the JSON shape are NOT pinned by P0 (Cursor hooks are GUI-only and
//! could not be captured headless), so this parser is explicitly best-effort:
//! it returns an empty turn list gracefully whenever the schema does not match
//! rather than erroring (per the F7 fallback contract).
//!
//! ## Schema assumptions (defensive)
//!
//! - The DB is a VS Code `state.vscdb` with table `ItemTable(key, value)`.
//! - Chat lives under one of [`CHAT_KEYS`] (the keys VS Code / Cursor builds
//!   have used for chat panels and prompt history). The first key that exists
//!   and parses wins.
//! - The value is UTF-8 JSON. We accept either an array of
//!   `{role|type, content|text}` message objects, or an object nesting the
//!   same under a `messages` / `tabs[].bubbles` array. Content may itself be
//!   a string or an array of `{text}` parts.
//! - Anything else yields zero turns (graceful empty), never a panic.
//!
//! ## Security
//!
//! The DB path comes from the (untrusted) hook envelope context. The database
//! is opened strictly read-only (`SQLITE_OPEN_READ_ONLY`, no create) so a
//! parser bug cannot mutate Cursor state, and the path is canonicalized and
//! size-capped before opening. Every extracted turn is passed through
//! `redact_secrets` before it leaves this module (P2 rule 5: never trust host
//! redaction).
//!
//! When the real schema is confirmed (P8), tighten [`CHAT_KEYS`] and the JSON
//! matchers; the empty-on-mismatch fallback remains as the safety net.

use std::path::PathBuf;

use clx_core::redaction::redact_secrets;
use clx_core::types::estimate_tokens;
use rusqlite::{Connection, OpenFlags};
use serde::Deserialize;
use tracing::warn;

use crate::transcript::OwnedTurn;

/// Hard ceiling on the `state.vscdb` size we will open (mirrors the JSONL
/// parsers' cap). A real Cursor state DB is a few MiB; 64 MiB is generous.
const MAX_DB_BYTES: u64 = 64 * 1024 * 1024;

/// Candidate `ItemTable` keys under which chat history has been observed in
/// VS Code / Cursor builds. Tried in order; first hit that parses wins.
const CHAT_KEYS: &[&str] = &[
    "workbench.panel.aichat.view.aichat.chatdata",
    "workbench.panel.composerChatViewPane.composerChatData",
    "aiService.prompts",
    "interactive.sessions",
];

/// Canonicalize the DB path and reject missing / non-regular / oversized
/// files. Returns `None` ("no usable transcript") so callers stay non-fatal.
fn safe_db_path(db_path: &str) -> Option<PathBuf> {
    let canonical = std::fs::canonicalize(db_path).ok()?;
    let metadata = std::fs::metadata(&canonical).ok()?;
    if !metadata.file_type().is_file() {
        warn!(
            "cursor state.vscdb '{}' is not a regular file ({:?}); refusing to read",
            canonical.display(),
            metadata.file_type()
        );
        return None;
    }
    if metadata.len() > MAX_DB_BYTES {
        warn!(
            "cursor state.vscdb '{}' is {} bytes (> {} cap); refusing to read",
            canonical.display(),
            metadata.len(),
            MAX_DB_BYTES
        );
        return None;
    }
    Some(canonical)
}

/// A chat message, parsed defensively. Roles/content keys vary across builds.
#[derive(Debug, Deserialize, Default)]
struct ChatMessage {
    role: Option<String>,
    #[serde(rename = "type")]
    msg_type: Option<String>,
    content: Option<Content>,
    text: Option<String>,
}

/// Either a plain string or an array of typed parts.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum Content {
    Text(String),
    Parts(Vec<ContentPart>),
}

#[derive(Debug, Deserialize, Default)]
struct ContentPart {
    text: Option<String>,
}

impl Content {
    fn to_text(&self) -> String {
        match self {
            Content::Text(s) => s.clone(),
            Content::Parts(parts) => parts
                .iter()
                .filter_map(|p| p.text.as_deref())
                .collect::<Vec<_>>()
                .join("\n"),
        }
    }
}

/// Top-level chat blob: either a bare array of messages, or an object that
/// nests them under `messages` or `tabs[].bubbles`.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum ChatBlob {
    Messages(Vec<ChatMessage>),
    Wrapped(WrappedChat),
}

#[derive(Debug, Deserialize, Default)]
struct WrappedChat {
    #[serde(default)]
    messages: Vec<ChatMessage>,
    #[serde(default)]
    tabs: Vec<ChatTab>,
}

#[derive(Debug, Deserialize, Default)]
struct ChatTab {
    #[serde(default)]
    bubbles: Vec<ChatMessage>,
}

/// Normalize a role string to canonical user/assistant, else `None`.
fn normalize_role(role: &str) -> Option<&'static str> {
    match role {
        "user" => Some("user"),
        // Cursor labels model turns variously; treat all as assistant output.
        "assistant" | "ai" | "bot" => Some("assistant"),
        _ => None,
    }
}

/// Convert one parsed [`ChatMessage`] to an `(role, content)` turn, or `None`.
fn turn_from_message(msg: &ChatMessage) -> Option<(&'static str, String)> {
    let role = msg
        .role
        .as_deref()
        .and_then(normalize_role)
        .or_else(|| msg.msg_type.as_deref().and_then(normalize_role))?;
    let content = msg
        .content
        .as_ref()
        .map(Content::to_text)
        .or_else(|| msg.text.clone())
        .unwrap_or_default();
    if content.is_empty() {
        return None;
    }
    Some((role, content))
}

/// Flatten any [`ChatBlob`] variant into an ordered message list.
fn messages_of(blob: ChatBlob) -> Vec<ChatMessage> {
    match blob {
        ChatBlob::Messages(m) => m,
        ChatBlob::Wrapped(w) => {
            if w.messages.is_empty() {
                w.tabs.into_iter().flat_map(|t| t.bubbles).collect()
            } else {
                w.messages
            }
        }
    }
}

/// Read all chat turns from the DB, in document order, with content redacted.
/// Returns an empty Vec on any schema mismatch or read failure.
fn read_all_turns(db_path: &str) -> Vec<OwnedTurn> {
    let Some(path) = safe_db_path(db_path) else {
        return Vec::new();
    };
    // Read-only open: a parser bug can never mutate Cursor's live state.
    let conn = match Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY) {
        Ok(c) => c,
        Err(e) => {
            warn!(
                "cursor state.vscdb open failed: {}",
                redact_secrets(&e.to_string())
            );
            return Vec::new();
        }
    };

    for key in CHAT_KEYS {
        let raw: Option<String> = conn
            .query_row("SELECT value FROM ItemTable WHERE key = ?1", [key], |row| {
                row.get::<_, String>(0)
            })
            .ok();
        let Some(raw) = raw else { continue };
        let Ok(blob) = serde_json::from_str::<ChatBlob>(&raw) else {
            continue;
        };
        let turns: Vec<OwnedTurn> = messages_of(blob)
            .iter()
            .filter_map(turn_from_message)
            .map(|(role, content)| OwnedTurn {
                role: role.to_string(),
                // P2 rule 5: redact every turn; never trust host redaction.
                content: redact_secrets(&content),
            })
            .collect();
        if !turns.is_empty() {
            return turns;
        }
    }
    Vec::new()
}

/// Read the most recent `n` user/assistant turns from a Cursor `state.vscdb`.
///
/// Mirrors `transcript::last_n_turns`: empty Vec on any failure, never panics,
/// chronological order within the trailing window, content redacted.
pub(crate) fn last_n_turns(db_path: &str, n: usize) -> Vec<OwnedTurn> {
    if n == 0 {
        return Vec::new();
    }
    let mut all = read_all_turns(db_path);
    let len = all.len();
    if len > n {
        all.drain(0..len - n);
    }
    all
}

/// Fast token count from a Cursor `state.vscdb` (no LLM, no async).
/// Returns `(input_tokens, output_tokens, message_count)` over redacted text.
pub(crate) fn count_transcript_tokens(db_path: &str) -> (i64, i64, i32) {
    let turns = read_all_turns(db_path);
    let mut input_tokens: i64 = 0;
    let mut output_tokens: i64 = 0;
    for turn in &turns {
        let tokens = estimate_tokens(&turn.content);
        match turn.role.as_str() {
            "user" => input_tokens += tokens,
            "assistant" => output_tokens += tokens,
            _ => {}
        }
    }
    (input_tokens, output_tokens, turns.len() as i32)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a synthetic `state.vscdb` with an `ItemTable(key, value)` row.
    fn fixture_db(key: &str, value_json: &str) -> (tempfile::TempDir, PathBuf) {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("state.vscdb");
        let conn = Connection::open(&path).unwrap();
        conn.execute(
            "CREATE TABLE ItemTable (key TEXT PRIMARY KEY, value BLOB)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO ItemTable (key, value) VALUES (?1, ?2)",
            rusqlite::params![key, value_json],
        )
        .unwrap();
        drop(conn);
        (tmp, path)
    }

    #[test]
    fn parses_bare_message_array() {
        let value = serde_json::json!([
            { "role": "user", "content": "hello cursor" },
            { "role": "assistant", "content": "hi there" }
        ])
        .to_string();
        let (_tmp, path) = fixture_db(CHAT_KEYS[0], &value);
        let turns = last_n_turns(path.to_str().unwrap(), 10);
        assert_eq!(turns.len(), 2);
        assert_eq!(turns[0].role, "user");
        assert_eq!(turns[0].content, "hello cursor");
        assert_eq!(turns[1].role, "assistant");
    }

    #[test]
    fn parses_wrapped_messages_object() {
        let value = serde_json::json!({
            "messages": [
                { "type": "user", "text": "wrapped prompt" },
                { "type": "ai", "content": [{ "text": "wrapped reply" }] }
            ]
        })
        .to_string();
        let (_tmp, path) = fixture_db(CHAT_KEYS[1], &value);
        let turns = last_n_turns(path.to_str().unwrap(), 10);
        assert_eq!(turns.len(), 2);
        assert_eq!(turns[0].content, "wrapped prompt");
        assert_eq!(turns[1].role, "assistant");
        assert_eq!(turns[1].content, "wrapped reply");
    }

    #[test]
    fn parses_tabs_bubbles_shape() {
        let value = serde_json::json!({
            "tabs": [
                { "bubbles": [
                    { "role": "user", "content": "tab one prompt" },
                    { "role": "assistant", "content": "tab one reply" }
                ] }
            ]
        })
        .to_string();
        let (_tmp, path) = fixture_db(CHAT_KEYS[0], &value);
        let turns = last_n_turns(path.to_str().unwrap(), 10);
        assert_eq!(turns.len(), 2);
        assert_eq!(turns[0].content, "tab one prompt");
    }

    #[test]
    fn unknown_key_yields_empty_gracefully() {
        // Value present but under a key CLX does not know -> empty, no panic.
        let value = serde_json::json!([{ "role": "user", "content": "x" }]).to_string();
        let (_tmp, path) = fixture_db("some.unrelated.key", &value);
        assert!(last_n_turns(path.to_str().unwrap(), 10).is_empty());
        assert_eq!(count_transcript_tokens(path.to_str().unwrap()), (0, 0, 0));
    }

    #[test]
    fn malformed_json_value_yields_empty() {
        let (_tmp, path) = fixture_db(CHAT_KEYS[0], "not valid json {");
        assert!(last_n_turns(path.to_str().unwrap(), 10).is_empty());
    }

    #[test]
    fn missing_db_is_empty() {
        let missing = "/nonexistent/clx/cursor/state.vscdb";
        assert!(last_n_turns(missing, 5).is_empty());
        assert_eq!(count_transcript_tokens(missing), (0, 0, 0));
    }

    #[test]
    fn db_without_itemtable_is_empty() {
        // A valid SQLite DB lacking ItemTable must degrade gracefully.
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("state.vscdb");
        let conn = Connection::open(&path).unwrap();
        conn.execute("CREATE TABLE other (x INTEGER)", []).unwrap();
        drop(conn);
        assert!(last_n_turns(path.to_str().unwrap(), 5).is_empty());
    }

    #[test]
    fn last_n_keeps_trailing_window() {
        let value = serde_json::json!([
            { "role": "user", "content": "u1" },
            { "role": "assistant", "content": "a1" },
            { "role": "user", "content": "u2" },
            { "role": "assistant", "content": "a2" }
        ])
        .to_string();
        let (_tmp, path) = fixture_db(CHAT_KEYS[0], &value);
        let turns = last_n_turns(path.to_str().unwrap(), 2);
        assert_eq!(turns.len(), 2);
        assert_eq!(turns[0].content, "u2");
        assert_eq!(turns[1].content, "a2");
    }

    #[test]
    fn token_counts_match_estimate() {
        // "hello world" -> 3 ; "goodbye world" -> 4
        let value = serde_json::json!([
            { "role": "user", "content": "hello world" },
            { "role": "assistant", "content": "goodbye world" }
        ])
        .to_string();
        let (_tmp, path) = fixture_db(CHAT_KEYS[0], &value);
        assert_eq!(count_transcript_tokens(path.to_str().unwrap()), (3, 4, 2));
    }

    #[test]
    fn redaction_applied_to_turn_content() {
        let secret = format!("token {}deadbeefcafef00ddeadbeef", "sk-");
        let value = serde_json::json!([{ "role": "user", "content": secret }]).to_string();
        let (_tmp, path) = fixture_db(CHAT_KEYS[0], &value);
        let turns = last_n_turns(path.to_str().unwrap(), 10);
        assert_eq!(turns.len(), 1);
        assert!(
            turns[0].content.contains("REDACTED"),
            "secret must be redacted, got: {}",
            turns[0].content
        );
        assert!(!turns[0].content.contains("deadbeefcafef00ddeadbeef"));
    }

    #[test]
    fn n_zero_returns_empty() {
        let value = serde_json::json!([{ "role": "user", "content": "x" }]).to_string();
        let (_tmp, path) = fixture_db(CHAT_KEYS[0], &value);
        assert!(last_n_turns(path.to_str().unwrap(), 0).is_empty());
    }

    #[test]
    fn read_only_open_does_not_create_missing_db() {
        // SQLITE_OPEN_READ_ONLY must not create the file when absent.
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("absent.vscdb");
        let _ = last_n_turns(path.to_str().unwrap(), 5);
        assert!(
            !path.exists(),
            "read-only path must never create the DB file"
        );
    }
}
