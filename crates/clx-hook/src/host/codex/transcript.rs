//! Codex rollout-JSONL transcript parser.
//!
//! Codex persists each session as `~/.codex/sessions/rollout-*.jsonl`, a
//! JSON-lines log. This module exposes the same surface the Claude JSONL
//! parser does ([`last_n_turns`], [`count_transcript_tokens`]) so the hook
//! handlers can stay host-agnostic.
//!
//! ## Schema assumptions (defensive)
//!
//! The exact rollout schema is not pinned by P0 (the live capture was
//! interactive-only). The parser is therefore deliberately tolerant:
//!
//! - Each line is an independent JSON object; non-JSON / blank lines are
//!   skipped, never fatal.
//! - A turn is identified by a role-bearing field. We accept, in order: a
//!   `type` field of `user` / `assistant` (Claude-compatible shape); a `role`
//!   field of `user` / `assistant` (chat-message shape); or a nested
//!   `payload` / `message` object carrying either of the above. Any other
//!   `type` / `role` (system, `tool_call`, reasoning, event, ...) is ignored
//!   for turn extraction.
//! - Content is read from the first present of: a string `content`, a
//!   `content` array of `{type:"text"|"input_text"|"output_text", text}`
//!   parts (`OpenAI` Responses shape), a string `text`, or a string `message`.
//! - Token estimation reuses `estimate_tokens` (chars/4) exactly as the
//!   Claude path, so cross-host token math is consistent.
//!
//! If none of these match, the file yields zero turns gracefully rather than
//! erroring. When the real schema is confirmed (P8), tighten the matchers;
//! the tolerant fallback stays as a safety net.
//!
//! ## Security
//!
//! `transcript_path` arrives from the (untrusted) hook envelope. The same
//! hardening the Claude parser applies is replicated here: canonicalize,
//! reject non-regular files (FIFO / device / dir) and anything over the size
//! cap, and bound the reader itself against post-check growth (TOCTOU).
//!
//! Every extracted turn is passed through `redact_secrets` before it leaves
//! this module: host redaction is never trusted (P2 rule 5).

use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::path::PathBuf;

use clx_core::redaction::redact_secrets;
use clx_core::types::estimate_tokens;
use serde::Deserialize;
use tracing::warn;

use crate::transcript::OwnedTurn;

/// Hard ceiling on the rollout file size we will read (mirrors the Claude
/// parser's `MAX_TRANSCRIPT_BYTES`).
const MAX_TRANSCRIPT_BYTES: u64 = 64 * 1024 * 1024;

/// Canonicalize `transcript_path` and reject missing, non-regular, or
/// oversized files. Returns `None` ("no usable transcript") instead of
/// erroring so the Stop/SessionEnd handlers stay non-fatal.
fn safe_transcript_path(transcript_path: &str) -> Option<PathBuf> {
    let canonical = std::fs::canonicalize(transcript_path).ok()?;
    let metadata = std::fs::metadata(&canonical).ok()?;
    if !metadata.file_type().is_file() {
        warn!(
            "codex transcript '{}' is not a regular file ({:?}); refusing to read",
            canonical.display(),
            metadata.file_type()
        );
        return None;
    }
    if metadata.len() > MAX_TRANSCRIPT_BYTES {
        warn!(
            "codex transcript '{}' is {} bytes (> {} cap); refusing to read",
            canonical.display(),
            metadata.len(),
            MAX_TRANSCRIPT_BYTES
        );
        return None;
    }
    Some(canonical)
}

/// One rollout line, parsed defensively. Every field is optional so an
/// unexpected shape degrades to "no turn" rather than a parse error.
#[derive(Debug, Deserialize, Default)]
struct RolloutLine {
    #[serde(rename = "type")]
    line_type: Option<String>,
    role: Option<String>,
    content: Option<Content>,
    text: Option<String>,
    message: Option<NestedMessage>,
    payload: Option<NestedMessage>,
}

/// A nested message object (`payload` / `message`) that itself carries a
/// role + content (Codex sometimes wraps the chat message one level deep).
#[derive(Debug, Deserialize, Default)]
struct NestedMessage {
    #[serde(rename = "type")]
    msg_type: Option<String>,
    role: Option<String>,
    content: Option<Content>,
    text: Option<String>,
}

/// Content is either a plain string or an array of typed parts (the `OpenAI`
/// Responses content shape). `untagged` lets serde pick whichever matches.
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
    /// Flatten to a single owned string (parts joined by newline).
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

/// Normalize a role string to the canonical `user` / `assistant`, or `None`
/// if it is neither (system, tool, reasoning, event, ...).
fn normalize_role(role: &str) -> Option<&'static str> {
    match role {
        "user" => Some("user"),
        "assistant" => Some("assistant"),
        _ => None,
    }
}

/// Extract `(role, content)` from one rollout line, applying the assumption
/// ladder documented at module level. Returns `None` for lines that are not
/// user/assistant turns or that carry no content.
fn turn_from_line(line: &RolloutLine) -> Option<(&'static str, String)> {
    // 1/2: top-level type or role.
    let top_role = line
        .line_type
        .as_deref()
        .and_then(normalize_role)
        .or_else(|| line.role.as_deref().and_then(normalize_role));
    if let Some(role) = top_role {
        let content = line
            .content
            .as_ref()
            .map(Content::to_text)
            .or_else(|| line.text.clone())
            .unwrap_or_default();
        if !content.is_empty() {
            return Some((role, content));
        }
    }

    // 3: nested payload / message object.
    for nested in [line.payload.as_ref(), line.message.as_ref()]
        .into_iter()
        .flatten()
    {
        let role = nested
            .msg_type
            .as_deref()
            .and_then(normalize_role)
            .or_else(|| nested.role.as_deref().and_then(normalize_role));
        if let Some(role) = role {
            let content = nested
                .content
                .as_ref()
                .map(Content::to_text)
                .or_else(|| nested.text.clone())
                .unwrap_or_default();
            if !content.is_empty() {
                return Some((role, content));
            }
        }
    }
    None
}

/// Read the most recent `n` user/assistant turns from a Codex rollout file.
///
/// Mirrors `transcript::last_n_turns`: returns an empty `Vec` when the file
/// is unreadable or has no valid turns; never panics; order is chronological
/// (oldest first within the trailing window). Every turn's content is
/// redacted before return.
pub(crate) fn last_n_turns(transcript_path: &str, n: usize) -> Vec<OwnedTurn> {
    if n == 0 {
        return Vec::new();
    }
    let Some(path) = safe_transcript_path(transcript_path) else {
        return Vec::new();
    };
    let Ok(file) = File::open(&path) else {
        return Vec::new();
    };
    let reader = BufReader::new(file.take(MAX_TRANSCRIPT_BYTES));
    let mut all: Vec<OwnedTurn> = Vec::new();
    for line in reader.lines() {
        let Ok(line) = line else { continue };
        if line.trim().is_empty() {
            continue;
        }
        let Ok(parsed) = serde_json::from_str::<RolloutLine>(&line) else {
            continue;
        };
        if let Some((role, content)) = turn_from_line(&parsed) {
            // P2 rule 5: redact every turn; never trust host redaction.
            all.push(OwnedTurn {
                role: role.to_string(),
                content: redact_secrets(&content),
            });
        }
    }
    let len = all.len();
    if len > n {
        all.drain(0..len - n);
    }
    all
}

/// Fast token count from a Codex rollout file (no LLM, no async).
/// Returns `(input_tokens, output_tokens, message_count)`.
///
/// Mirrors `transcript::count_transcript_tokens`. Token estimates are taken
/// over the redacted content so the count matches what downstream consumers
/// actually see.
pub(crate) fn count_transcript_tokens(transcript_path: &str) -> (i64, i64, i32) {
    let Some(path) = safe_transcript_path(transcript_path) else {
        return (0, 0, 0);
    };
    let Ok(file) = File::open(&path) else {
        return (0, 0, 0);
    };
    let reader = BufReader::new(file.take(MAX_TRANSCRIPT_BYTES));
    let mut input_tokens: i64 = 0;
    let mut output_tokens: i64 = 0;
    let mut message_count: i32 = 0;
    for line in reader.lines() {
        let Ok(line) = line else { continue };
        if line.trim().is_empty() {
            continue;
        }
        let Ok(parsed) = serde_json::from_str::<RolloutLine>(&line) else {
            continue;
        };
        if let Some((role, content)) = turn_from_line(&parsed) {
            let tokens = estimate_tokens(&redact_secrets(&content));
            match role {
                "user" => input_tokens += tokens,
                "assistant" => output_tokens += tokens,
                _ => {}
            }
            message_count += 1;
        }
    }
    (input_tokens, output_tokens, message_count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_rollout(lines: &[&str]) -> (tempfile::TempDir, PathBuf) {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("rollout-2026-05-28T00-00-00-abc.jsonl");
        let mut f = File::create(&path).unwrap();
        for line in lines {
            writeln!(f, "{line}").unwrap();
        }
        drop(f);
        (tmp, path)
    }

    #[test]
    fn parses_type_role_shape() {
        // Claude-compatible `type` discriminator.
        let (_tmp, path) = write_rollout(&[
            r#"{"type":"user","content":"hello codex"}"#,
            r#"{"type":"assistant","content":"hi there"}"#,
        ]);
        let turns = last_n_turns(path.to_str().unwrap(), 10);
        assert_eq!(turns.len(), 2);
        assert_eq!(turns[0].role, "user");
        assert_eq!(turns[0].content, "hello codex");
        assert_eq!(turns[1].role, "assistant");
    }

    #[test]
    fn parses_role_with_content_parts() {
        // OpenAI Responses content-parts shape under a `role` discriminator.
        let (_tmp, path) = write_rollout(&[
            r#"{"role":"user","content":[{"type":"input_text","text":"part one"},{"type":"input_text","text":"part two"}]}"#,
            r#"{"role":"assistant","content":[{"type":"output_text","text":"answer"}]}"#,
        ]);
        let turns = last_n_turns(path.to_str().unwrap(), 10);
        assert_eq!(turns.len(), 2);
        assert_eq!(turns[0].content, "part one\npart two");
        assert_eq!(turns[1].content, "answer");
    }

    #[test]
    fn parses_nested_payload_message() {
        let (_tmp, path) = write_rollout(&[
            r#"{"type":"event","payload":{"role":"user","content":"wrapped prompt"}}"#,
            r#"{"type":"event","message":{"type":"assistant","text":"wrapped reply"}}"#,
        ]);
        let turns = last_n_turns(path.to_str().unwrap(), 10);
        assert_eq!(turns.len(), 2);
        assert_eq!(turns[0].content, "wrapped prompt");
        assert_eq!(turns[1].content, "wrapped reply");
    }

    #[test]
    fn skips_non_turn_lines_gracefully() {
        let (_tmp, path) = write_rollout(&[
            r#"{"type":"session_meta","model":"gpt-5.4-codex"}"#,
            r#"{"type":"reasoning","content":"internal"}"#,
            r#"{"role":"system","content":"system prompt"}"#,
            "not json at all",
            "",
            r#"{"type":"user","content":"the only turn"}"#,
        ]);
        let turns = last_n_turns(path.to_str().unwrap(), 10);
        assert_eq!(turns.len(), 1);
        assert_eq!(turns[0].content, "the only turn");
    }

    #[test]
    fn empty_or_unknown_schema_yields_no_turns() {
        let (_tmp, path) = write_rollout(&[
            r#"{"foo":"bar"}"#,
            r#"{"type":"tool_call","name":"apply_patch"}"#,
        ]);
        assert!(last_n_turns(path.to_str().unwrap(), 10).is_empty());
        assert_eq!(count_transcript_tokens(path.to_str().unwrap()), (0, 0, 0));
    }

    #[test]
    fn last_n_keeps_trailing_window() {
        let (_tmp, path) = write_rollout(&[
            r#"{"type":"user","content":"u1"}"#,
            r#"{"type":"assistant","content":"a1"}"#,
            r#"{"type":"user","content":"u2"}"#,
            r#"{"type":"assistant","content":"a2"}"#,
        ]);
        let turns = last_n_turns(path.to_str().unwrap(), 2);
        assert_eq!(turns.len(), 2);
        assert_eq!(turns[0].content, "u2");
        assert_eq!(turns[1].content, "a2");
    }

    #[test]
    fn n_zero_returns_empty() {
        let (_tmp, path) = write_rollout(&[r#"{"type":"user","content":"x"}"#]);
        assert!(last_n_turns(path.to_str().unwrap(), 0).is_empty());
    }

    #[test]
    fn token_counts_match_estimate() {
        // "hello world" = 11 chars -> (11+3)/4 = 3 ; "goodbye world" = 13 -> 4
        let (_tmp, path) = write_rollout(&[
            r#"{"type":"user","content":"hello world"}"#,
            r#"{"type":"assistant","content":"goodbye world"}"#,
        ]);
        let (i, o, c) = count_transcript_tokens(path.to_str().unwrap());
        assert_eq!((i, o, c), (3, 4, 2));
    }

    #[test]
    fn redaction_applied_to_turn_content() {
        // Synthetic secret (never a real key): the `sk-` prefix must be
        // redacted before the turn leaves this module.
        let secret_line = format!(
            r#"{{"type":"user","content":"my key is {}abcdef0123456789"}}"#,
            "sk-"
        );
        let (_tmp, path) = write_rollout(&[&secret_line]);
        let turns = last_n_turns(path.to_str().unwrap(), 10);
        assert_eq!(turns.len(), 1);
        assert!(
            turns[0].content.contains("REDACTED"),
            "secret must be redacted, got: {}",
            turns[0].content
        );
        assert!(
            !turns[0].content.contains("abcdef0123456789"),
            "raw secret body must not survive redaction"
        );
    }

    #[test]
    fn nonexistent_path_is_empty() {
        let missing = "/nonexistent/clx/codex/does-not-exist.jsonl";
        assert!(last_n_turns(missing, 5).is_empty());
        assert_eq!(count_transcript_tokens(missing), (0, 0, 0));
    }
}
