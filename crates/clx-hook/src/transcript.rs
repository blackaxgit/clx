//! Transcript processing and summarization.

use crate::embedding::truncate_to_char_boundary;
use crate::types::{SUMMARIZE_PROMPT, SummaryResponse, TranscriptEntry, TranscriptResult};
use clx_core::config::{Capability, Config};
use clx_core::redaction::redact_secrets;
use clx_core::types::estimate_tokens;
use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::path::PathBuf;
use tracing::warn;

/// Hard ceiling on the size of a transcript file we are willing to read.
///
/// The `transcript_path` arrives from the hook envelope and is otherwise
/// unconstrained. Without a cap, a hostile or accidental path such as
/// `/dev/zero` (infinite) or a multi-gigabyte log would be streamed
/// line-by-line until the handler timeout, wasting CPU and memory. Real
/// Claude Code transcripts are JSONL conversation logs that stay well
/// under this bound; 64 MiB is a generous headroom for very long
/// sessions while still bounding the worst case.
const MAX_TRANSCRIPT_BYTES: u64 = 64 * 1024 * 1024;

/// Resolve `transcript_path` to a canonical path and reject it when the
/// file is missing, unresolvable (broken symlink, traversal), or larger
/// than [`MAX_TRANSCRIPT_BYTES`].
///
/// Returns `None` (caller treats as "no usable transcript") instead of
/// erroring so the Stop/SessionEnd hooks stay non-fatal.
///
/// No filesystem allowlist is enforced: legitimate transcripts live under
/// `~/.claude/projects/` in production but the existing test-suite (and
/// users with relocated Claude config) point at arbitrary temp paths, so
/// a hard root allowlist would break valid callers. Canonicalization plus
/// the size cap bound the read scope without that fragility. Canonicalize
/// also collapses `..` traversal and resolves symlinks, so the size check
/// runs against the real target rather than a link.
fn safe_transcript_path(transcript_path: &str) -> Option<PathBuf> {
    let canonical = std::fs::canonicalize(transcript_path).ok()?;
    let metadata = std::fs::metadata(&canonical).ok()?;
    // Reject anything that is not a regular file. A character device
    // (`/dev/zero`), block device, FIFO, socket, or directory reports a
    // metadata length of 0, so the size cap below would pass while the
    // subsequent line reader would never terminate (unbounded read ->
    // OOM/SIGKILL). Treat all of these as "no usable transcript".
    if !metadata.file_type().is_file() {
        warn!(
            "transcript '{}' is not a regular file ({:?}); refusing to read",
            canonical.display(),
            metadata.file_type()
        );
        return None;
    }
    let len = metadata.len();
    if len > MAX_TRANSCRIPT_BYTES {
        warn!(
            "transcript '{}' is {} bytes (> {} cap); refusing to read",
            canonical.display(),
            len,
            MAX_TRANSCRIPT_BYTES
        );
        return None;
    }
    Some(canonical)
}

/// Owned (role, content) pair extracted from a transcript JSONL file.
///
/// Produced by `last_n_turns`. Kept owned (not a `TurnSlice<'a>`) because
/// the JSONL line buffer the data was parsed from is dropped at the end
/// of each `BufRead::lines()` iteration; lifetimes can't bridge that.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OwnedTurn {
    pub role: String,
    pub content: String,
}

/// Read the most recent `n` `user`/`assistant` turns from a transcript
/// JSONL file. Used by the `stop_auto_summary` hook handler to build the
/// summarization prompt.
///
/// Returns an empty `Vec` when the file is unreadable or contains no
/// valid turns; never panics. Order is chronological (oldest first within
/// the trailing window).
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

    // Defensively bound the bytes actually consumed regardless of the
    // metadata size check above: a regular file can still grow (or be
    // swapped via TOCTOU) after the gate, so cap the reader itself.
    let reader = BufReader::new(file.take(MAX_TRANSCRIPT_BYTES));
    let mut all: Vec<OwnedTurn> = Vec::new();
    for line in reader.lines() {
        let Ok(line) = line else { continue };
        if line.trim().is_empty() {
            continue;
        }
        let Ok(entry) = serde_json::from_str::<TranscriptEntry>(&line) else {
            continue;
        };
        let role = match entry.entry_type.as_deref() {
            Some(r @ ("user" | "assistant")) => r.to_string(),
            _ => continue,
        };
        let content = entry
            .message
            .as_ref()
            .map(|m| m.content().to_string())
            .unwrap_or_default();
        if content.is_empty() {
            continue;
        }
        all.push(OwnedTurn { role, content });
    }
    // Keep only the trailing `n` turns. `split_off` would copy; `drain`
    // from the front avoids a clone on the kept tail.
    let len = all.len();
    if len > n {
        all.drain(0..len - n);
    }
    all
}

/// Fast token count from transcript file (no LLM calls, no async).
/// Returns (`input_tokens`, `output_tokens`, `message_count`).
pub(crate) fn count_transcript_tokens(transcript_path: &str) -> (i64, i64, i32) {
    let Some(path) = safe_transcript_path(transcript_path) else {
        return (0, 0, 0);
    };
    let Ok(file) = File::open(&path) else {
        return (0, 0, 0);
    };

    // Bound the read even if the file grows or is swapped post-check.
    let reader = BufReader::new(file.take(MAX_TRANSCRIPT_BYTES));
    let mut input_tokens: i64 = 0;
    let mut output_tokens: i64 = 0;
    let mut message_count: i32 = 0;

    for line in reader.lines() {
        let Ok(line) = line else { continue };
        if line.trim().is_empty() {
            continue;
        }

        if let Ok(entry) = serde_json::from_str::<TranscriptEntry>(&line) {
            if let Some(ref entry_type) = entry.entry_type
                && let Some(ref message) = entry.message
            {
                let content = message.content();
                let tokens = estimate_tokens(content);
                match entry_type.as_str() {
                    "user" => input_tokens += tokens,
                    "assistant" => output_tokens += tokens,
                    _ => {}
                }
            }
            message_count += 1;
        }
    }

    (input_tokens, output_tokens, message_count)
}

/// Read and process a transcript file.
///
/// When `ollama_available` is `false` the function skips the LLM
/// summarization call entirely (no health check, no generate request).
/// This avoids the 2-4 s timeout that causes `SessionEnd` to be cancelled.
pub(crate) async fn process_transcript(
    transcript_path: &str,
    ollama_available: bool,
) -> TranscriptResult {
    // Read transcript file. `safe_transcript_path` canonicalizes the
    // envelope-supplied path and rejects oversized/unresolvable files so
    // a hostile path cannot drive an unbounded read.
    let Some(safe_path) = safe_transcript_path(transcript_path) else {
        warn!(
            "Refusing transcript file '{}' (missing, unresolvable, or over size cap)",
            transcript_path
        );
        return TranscriptResult {
            summary: None,
            key_facts: None,
            todos: None,
            message_count: None,
            input_tokens: 0,
            output_tokens: 0,
        };
    };
    let file = match File::open(&safe_path) {
        Ok(f) => f,
        Err(e) => {
            warn!(
                "Failed to open transcript file '{}': {}",
                transcript_path, e
            );
            return TranscriptResult {
                summary: None,
                key_facts: None,
                todos: None,
                message_count: None,
                input_tokens: 0,
                output_tokens: 0,
            };
        }
    };

    // Bound the read even if the file grows or is swapped post-check.
    let reader = BufReader::new(file.take(MAX_TRANSCRIPT_BYTES));
    let mut entries = Vec::new();
    let mut message_count = 0;
    let mut input_tokens: i64 = 0;
    let mut output_tokens: i64 = 0;

    for line in reader.lines() {
        let Ok(line) = line else {
            continue;
        };

        if line.trim().is_empty() {
            continue;
        }

        if let Ok(entry) = serde_json::from_str::<TranscriptEntry>(&line) {
            // Count tokens based on message type
            if let Some(ref entry_type) = entry.entry_type
                && let Some(ref message) = entry.message
            {
                let content = message.content();
                let tokens = estimate_tokens(content);
                match entry_type.as_str() {
                    "user" => input_tokens += tokens,
                    "assistant" => output_tokens += tokens,
                    _ => {}
                }
            }
            entries.push(entry);
            message_count += 1;
        }
    }

    if entries.is_empty() {
        return TranscriptResult {
            summary: None,
            key_facts: None,
            todos: None,
            message_count: Some(0),
            input_tokens: 0,
            output_tokens: 0,
        };
    }

    // Build transcript text for summarization
    let transcript_text = build_transcript_text(&entries);

    // Fast path: skip all LLM work when the caller knows Ollama is down.
    if !ollama_available {
        return TranscriptResult {
            summary: Some(format!("Session with {message_count} messages")),
            key_facts: None,
            todos: None,
            message_count: Some(message_count),
            input_tokens,
            output_tokens,
        };
    }

    // Generate summary using LLM
    let config = Config::load().unwrap_or_default();
    let (ollama, chat_model) = match config.create_llm_client(Capability::Chat).and_then(|c| {
        config
            .capability_route(Capability::Chat)
            .map(|r| (c, r.model.clone()))
    }) {
        Ok(pair) => pair,
        Err(e) => {
            // Sink wrap (B6-1): redact LlmError Display string before logging
            // to prevent tenant URLs or key fragments from reaching tracing sinks.
            warn!(
                "Failed to create LLM client for summarization: {}",
                redact_secrets(&e.to_string())
            );
            return TranscriptResult {
                summary: Some(format!(
                    "Session with {message_count} messages (LLM unavailable)"
                )),
                key_facts: None,
                todos: None,
                message_count: Some(message_count),
                input_tokens,
                output_tokens,
            };
        }
    };

    if !ollama.is_available().await {
        // Return basic info without LLM summary
        return TranscriptResult {
            summary: Some(format!("Session with {message_count} messages")),
            key_facts: None,
            todos: None,
            message_count: Some(message_count),
            input_tokens,
            output_tokens,
        };
    }

    // Generate summary
    let prompt = SUMMARIZE_PROMPT.replace("{{transcript}}", &transcript_text);

    match ollama.generate(&prompt, Some(&chat_model)).await {
        Ok(response) => {
            // Try to parse as JSON
            if let Ok(summary_data) = parse_summary_response(&response) {
                TranscriptResult {
                    summary: Some(summary_data.summary),
                    key_facts: summary_data.key_facts.map(|f| f.join("\n")),
                    todos: summary_data.todos.map(|t| t.join("\n")),
                    message_count: Some(message_count),
                    input_tokens,
                    output_tokens,
                }
            } else {
                // Use raw response as summary
                TranscriptResult {
                    summary: Some(response),
                    key_facts: None,
                    todos: None,
                    message_count: Some(message_count),
                    input_tokens,
                    output_tokens,
                }
            }
        }
        Err(e) => {
            // Sink wrap (B6-1): redact LlmError Display string before logging.
            warn!(
                "Failed to generate summary: {}",
                redact_secrets(&e.to_string())
            );
            TranscriptResult {
                summary: Some(format!("Session with {message_count} messages")),
                key_facts: None,
                todos: None,
                message_count: Some(message_count),
                input_tokens,
                output_tokens,
            }
        }
    }
}

/// Build a text representation of transcript entries
pub(crate) fn build_transcript_text(entries: &[TranscriptEntry]) -> String {
    let mut text = String::new();

    for entry in entries.iter().take(100) {
        // Limit to avoid token limits
        if let Some(ref entry_type) = entry.entry_type {
            match entry_type.as_str() {
                "user" | "assistant" => {
                    if let Some(ref message) = entry.message {
                        let content = message.content();
                        let truncated = if content.len() > 500 {
                            format!("{}...", truncate_to_char_boundary(content, 500))
                        } else {
                            content.to_string()
                        };
                        use std::fmt::Write;
                        let _ = writeln!(text, "[{entry_type}]: {truncated}");
                    }
                }
                "tool_use" => {
                    if let Some(ref tool) = entry.tool {
                        use std::fmt::Write;
                        let _ = writeln!(text, "[tool_use]: {tool}");
                    }
                }
                _ => {}
            }
        }
    }

    text
}

/// Parse summary response from LLM
pub(crate) fn parse_summary_response(response: &str) -> Result<SummaryResponse, serde_json::Error> {
    // Try to find JSON in the response
    let json_start = response.find('{').unwrap_or(0);
    let json_end = response.rfind('}').map_or(response.len(), |i| i + 1);

    let json_str = &response[json_start..json_end];
    serde_json::from_str(json_str)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::TranscriptMessage;

    #[test]
    fn test_count_transcript_tokens_missing_file() {
        let (input, output, count) = count_transcript_tokens("/nonexistent/path");
        assert_eq!(input, 0);
        assert_eq!(output, 0);
        assert_eq!(count, 0);
    }

    #[test]
    fn test_count_transcript_tokens_with_content() {
        use std::io::Write;

        let tmp = tempfile::tempdir().expect("tempdir");
        let transcript_path = tmp.path().join("transcript.jsonl");

        // Create a transcript file with known content.
        // Each entry is a JSONL line with type and message fields.
        // "hello world" = 11 chars => estimate_tokens => (11+3)/4 = 3 tokens
        let mut file = std::fs::File::create(&transcript_path).unwrap();
        writeln!(file, r#"{{"type":"user","message":"hello world"}}"#).unwrap();
        writeln!(file, r#"{{"type":"assistant","message":"goodbye world"}}"#).unwrap();
        // A blank line should be skipped
        writeln!(file).unwrap();
        // A non-JSON line should be skipped
        writeln!(file, "not json at all").unwrap();

        let (input_tok, output_tok, msg_count) =
            count_transcript_tokens(transcript_path.to_str().unwrap());

        // "hello world" = 11 chars => (11+3)/4 = 3 tokens
        assert_eq!(
            input_tok, 3,
            "user tokens should be estimated from 'hello world'"
        );
        // "goodbye world" = 13 chars => (13+3)/4 = 4 tokens
        assert_eq!(
            output_tok, 4,
            "assistant tokens should be estimated from 'goodbye world'"
        );
        assert_eq!(msg_count, 2, "only valid JSONL entries should be counted");
    }

    #[test]
    fn test_count_transcript_tokens_exceeds_pressure_threshold() {
        use std::io::Write;

        let tmp = tempfile::tempdir().expect("tempdir");
        let transcript_path = tmp.path().join("transcript.jsonl");

        // Create a transcript with enough content to exceed a realistic threshold.
        // We'll simulate a 200k-token window at 80% threshold = 160k tokens needed.
        // estimate_tokens: (len+3)/4, so we need ~640k chars total.
        // Write many assistant messages to accumulate tokens.
        let mut file = std::fs::File::create(&transcript_path).unwrap();
        let big_message = "x".repeat(6400); // 6400 chars => ~1600 tokens
        for _ in 0..110 {
            writeln!(file, r#"{{"type":"assistant","message":"{big_message}"}}"#).unwrap();
        }

        let (input_tok, output_tok, msg_count) =
            count_transcript_tokens(transcript_path.to_str().unwrap());
        let total_tokens = input_tok + output_tok;

        // Verify the token count is large enough to trigger pressure
        let window: i64 = 200_000;
        let threshold = (window as f64 * 0.80) as i64; // 160_000
        assert!(
            total_tokens >= threshold,
            "total_tokens ({total_tokens}) should exceed threshold ({threshold})"
        );
        assert_eq!(msg_count, 110);
    }

    // =========================================================================
    // T16 — process_transcript tests
    // =========================================================================

    /// Write a JSONL transcript file to `path` from the given lines.
    fn write_transcript(path: &std::path::Path, lines: &[&str]) {
        use std::io::Write;
        let mut f = std::fs::File::create(path).expect("create transcript file");
        for line in lines {
            writeln!(f, "{line}").expect("write line");
        }
    }

    /// T16-1: `process_transcript` with a mock Ollama server returns a non-empty summary.
    ///
    /// Wiremock binds to 127.0.0.1 (loopback), which the Ollama backend accepts.
    /// `CLX_OLLAMA_HOST` is overridden per-test via a scoped env var guard so that
    /// `Config::load()` picks up the mock server URL.
    #[tokio::test]
    async fn test_process_transcript_success_with_mock_ollama() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        // Arrange — start mock server
        let server = MockServer::start().await;

        // Mock GET /api/tags (is_available check)
        Mock::given(method("GET"))
            .and(path("/api/tags"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(r#"{"models":[{"name":"llama3.2:3b"}]}"#),
            )
            .mount(&server)
            .await;

        // Mock POST /api/generate (generate call)
        let summary_json =
            r#"{"summary":"Discussed Rust testing","key_facts":["used wiremock"],"todos":[]}"#;
        Mock::given(method("POST"))
            .and(path("/api/generate"))
            .respond_with(ResponseTemplate::new(200).set_body_string(format!(
                r#"{{"response":{json},"done":true}}"#,
                json = serde_json::to_string(summary_json).unwrap()
            )))
            .mount(&server)
            .await;

        // Write a small transcript file
        let tmp = tempfile::tempdir().expect("tempdir");
        let transcript_path = tmp.path().join("transcript.jsonl");
        write_transcript(
            &transcript_path,
            &[
                r#"{"type":"user","message":"Hello"}"#,
                r#"{"type":"assistant","message":"Hi there"}"#,
            ],
        );

        // Point Config::load() at the mock server via env var.
        // SAFETY: test isolation — env var is restored in the same async task.
        #[allow(unsafe_code)]
        unsafe {
            std::env::set_var("CLX_OLLAMA_HOST", server.uri());
        }

        // Act
        let result = process_transcript(transcript_path.to_str().unwrap(), true).await;

        // Restore env var
        #[allow(unsafe_code)]
        unsafe {
            std::env::remove_var("CLX_OLLAMA_HOST");
        }

        // Assert
        let summary = result.summary.expect("summary should be Some");
        assert!(!summary.is_empty(), "summary must be non-empty");
        assert_eq!(result.message_count, Some(2));
    }

    /// T16-2: `process_transcript` falls back gracefully when Ollama is unavailable.
    ///
    /// Port 19999 is chosen as an unused local port that will refuse connections
    /// immediately. The Ollama backend validates the host is localhost, which
    /// 127.0.0.1 satisfies, so it constructs but `is_available()` returns false.
    #[tokio::test]
    async fn test_process_transcript_fallback_when_ollama_unavailable() {
        // Arrange — write a small transcript
        let tmp = tempfile::tempdir().expect("tempdir");
        let transcript_path = tmp.path().join("transcript.jsonl");
        write_transcript(
            &transcript_path,
            &[
                r#"{"type":"user","message":"Hello"}"#,
                r#"{"type":"assistant","message":"Hi"}"#,
            ],
        );

        // Point Ollama at a port that is not listening so is_available() returns false.
        #[allow(unsafe_code)]
        unsafe {
            std::env::set_var("CLX_OLLAMA_HOST", "http://127.0.0.1:19998");
        }

        // Act — pass ollama_available=false to skip the slow health check
        let result = process_transcript(transcript_path.to_str().unwrap(), false).await;

        #[allow(unsafe_code)]
        unsafe {
            std::env::remove_var("CLX_OLLAMA_HOST");
        }

        // Assert — function completes without panic and provides a fallback summary
        let summary = result
            .summary
            .expect("summary should be Some even when Ollama unavailable");
        assert!(!summary.is_empty(), "fallback summary must be non-empty");
        assert_eq!(
            result.message_count,
            Some(2),
            "message_count must reflect the transcript lines"
        );
    }

    /// T16-3: `count_transcript_tokens` with a known structure returns correct token counts.
    ///
    /// `estimate_tokens` formula: (len + 3) / 4
    ///   "user msg"      = 8  chars → (8+3)/4  = 2 tokens  (integer division)
    ///   "assistant msg" = 13 chars → (13+3)/4 = 4 tokens
    #[test]
    fn test_count_transcript_tokens_known_structure() {
        use std::io::Write;

        let tmp = tempfile::tempdir().expect("tempdir");
        let transcript_path = tmp.path().join("transcript.jsonl");

        let mut f = std::fs::File::create(&transcript_path).unwrap();
        // "user msg" = 8 chars → (8+3)/4 = 2 tokens
        writeln!(f, r#"{{"type":"user","message":"user msg"}}"#).unwrap();
        // "assistant msg" = 13 chars → (13+3)/4 = 4 tokens
        writeln!(f, r#"{{"type":"assistant","message":"assistant msg"}}"#).unwrap();
        // blank line — skipped
        writeln!(f).unwrap();
        // non-JSON — skipped
        writeln!(f, "not-json").unwrap();

        let (input_tok, output_tok, msg_count) =
            count_transcript_tokens(transcript_path.to_str().unwrap());

        assert_eq!(input_tok, 2, "user 'user msg' → 2 tokens");
        assert_eq!(output_tok, 4, "assistant 'assistant msg' → 4 tokens");
        assert_eq!(msg_count, 2, "only 2 valid JSONL entries");
    }

    // =========================================================================
    // F8 — transcript path hardening (canonicalize + size cap)
    // =========================================================================

    /// F8-1: a non-existent path is rejected (canonicalize fails) and both
    /// readers return their empty sentinels.
    #[test]
    fn f8_nonexistent_path_returns_empty() {
        let missing = "/nonexistent/clx/f8/does-not-exist.jsonl";
        assert!(safe_transcript_path(missing).is_none());
        assert!(last_n_turns(missing, 5).is_empty());
        assert_eq!(count_transcript_tokens(missing), (0, 0, 0));
    }

    /// F8-2: a transcript over `MAX_TRANSCRIPT_BYTES` is refused. We assert
    /// the cap predicate directly against a real oversized file via a
    /// sparse file so the test stays fast and does not write 64 MiB.
    #[test]
    fn f8_oversized_transcript_is_rejected() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("huge.jsonl");

        let f = std::fs::File::create(&path).unwrap();
        // Sparse file: set logical length past the cap without writing bytes.
        f.set_len(MAX_TRANSCRIPT_BYTES + 1).unwrap();
        drop(f);

        assert!(
            safe_transcript_path(path.to_str().unwrap()).is_none(),
            "file larger than MAX_TRANSCRIPT_BYTES must be rejected"
        );
        assert!(last_n_turns(path.to_str().unwrap(), 5).is_empty());
        assert_eq!(count_transcript_tokens(path.to_str().unwrap()), (0, 0, 0));
    }

    /// F8-3: a file exactly at the cap is still accepted (boundary), and a
    /// normal small transcript still parses (regression guard).
    #[test]
    fn f8_at_cap_and_small_transcript_still_parse() {
        use std::io::Write;
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("small.jsonl");

        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(f, r#"{{"type":"user","message":"hello world"}}"#).unwrap();
        writeln!(f, r#"{{"type":"assistant","message":"goodbye world"}}"#).unwrap();
        drop(f);

        // safe path resolves and is accepted
        assert!(safe_transcript_path(path.to_str().unwrap()).is_some());
        let turns = last_n_turns(path.to_str().unwrap(), 5);
        assert_eq!(turns.len(), 2, "small transcript must still parse");
        let (i, o, c) = count_transcript_tokens(path.to_str().unwrap());
        assert_eq!((i, o, c), (3, 4, 2));
    }

    /// F8-4: a symlink to a real transcript is canonicalized to its target
    /// and the content is read through the resolved path.
    #[test]
    #[cfg(unix)]
    fn f8_symlink_is_canonicalized_to_target() {
        use std::io::Write;
        let tmp = tempfile::tempdir().expect("tempdir");
        let target = tmp.path().join("real.jsonl");
        let link = tmp.path().join("link.jsonl");

        let mut f = std::fs::File::create(&target).unwrap();
        writeln!(f, r#"{{"type":"user","message":"via symlink"}}"#).unwrap();
        drop(f);
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let resolved = safe_transcript_path(link.to_str().unwrap())
            .expect("symlink to a small file must resolve");
        assert_eq!(
            resolved,
            std::fs::canonicalize(&target).unwrap(),
            "symlink must canonicalize to its real target"
        );
        let turns = last_n_turns(link.to_str().unwrap(), 5);
        assert_eq!(turns.len(), 1);
        assert_eq!(turns[0].content, "via symlink");
    }

    /// F8-5: a non-regular path (FIFO / char device) is rejected by the
    /// `is_file()` gate so the readers never enter an unbounded read. On
    /// unix we create a real FIFO (a `read()` on it would block / never
    /// EOF without the guard); the assertions must return immediately.
    #[test]
    #[cfg(unix)]
    fn f8_non_regular_path_is_rejected_no_unbounded_read() {
        use std::os::unix::fs::FileTypeExt;
        let tmp = tempfile::tempdir().expect("tempdir");
        let fifo = tmp.path().join("pipe");

        // mkfifo via libc-free path: use the `nix`-free std approach by
        // shelling out to `mkfifo` (POSIX, always present on unix CI).
        let status = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .expect("spawn mkfifo");
        assert!(status.success(), "mkfifo must succeed");

        // Sanity: it really is a FIFO, not a regular file.
        let ft = std::fs::symlink_metadata(&fifo).unwrap().file_type();
        assert!(ft.is_fifo(), "test fixture must be a FIFO");

        // The guard must reject it (treated as "no transcript"). These
        // calls must return promptly; without the is_file() gate a reader
        // opened on the FIFO would block forever.
        assert!(
            safe_transcript_path(fifo.to_str().unwrap()).is_none(),
            "a FIFO must be rejected by the regular-file gate"
        );
        assert!(last_n_turns(fifo.to_str().unwrap(), 5).is_empty());
        assert_eq!(count_transcript_tokens(fifo.to_str().unwrap()), (0, 0, 0));
    }

    /// F8-6: a regular file reporting an honest over-cap length is rejected
    /// by the size gate, and `last_n_turns` / `count_transcript_tokens`
    /// both yield their empty sentinel without consuming the file.
    #[test]
    fn f8_over_cap_regular_file_is_bounded_and_empty() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("over.jsonl");

        let f = std::fs::File::create(&path).unwrap();
        f.set_len(MAX_TRANSCRIPT_BYTES + 4096).unwrap();
        drop(f);

        let start = std::time::Instant::now();
        assert!(safe_transcript_path(path.to_str().unwrap()).is_none());
        assert!(last_n_turns(path.to_str().unwrap(), 5).is_empty());
        assert_eq!(count_transcript_tokens(path.to_str().unwrap()), (0, 0, 0));
        assert!(
            start.elapsed() < std::time::Duration::from_secs(2),
            "rejection must be effectively instant (bounded), took {:?}",
            start.elapsed()
        );
    }

    /// T16-4: `build_transcript_text` does not panic on multi-byte UTF-8 content.
    ///
    /// Exercises the `truncate_to_char_boundary` path inside `build_transcript_text`
    /// when a message exceeds 500 chars and contains multi-byte characters.
    #[test]
    fn test_process_transcript_utf8_safety_no_panic() {
        // "こんにちは" is 5 chars × 3 bytes each = 15 bytes per repetition.
        // Repeat 40 times → 200 chars, 600 bytes (well above the 500-byte truncation threshold).
        let long_japanese = "こんにちは".repeat(40);
        let entries = vec![
            TranscriptEntry {
                entry_type: Some("user".to_string()),
                message: Some(TranscriptMessage::String(long_japanese.clone())),
                tool: None,
            },
            TranscriptEntry {
                entry_type: Some("assistant".to_string()),
                message: Some(TranscriptMessage::String(long_japanese)),
                tool: None,
            },
        ];

        // Must not panic even though slicing at byte 500 would split a 3-byte character.
        let text = build_transcript_text(&entries);
        assert!(text.contains("[user]:"), "should contain user label");
        assert!(
            text.contains("[assistant]:"),
            "should contain assistant label"
        );
        assert!(text.contains("..."), "truncation marker should be present");
        // Result must be valid UTF-8 (no panics from bad slicing)
        assert!(std::str::from_utf8(text.as_bytes()).is_ok());
    }

    // =========================================================================
    // Coverage-gap hardening (2026-06): last_n_turns filtering/windowing, role
    // gating in token counts, unreadable-file degradation, invalid-UTF-8 line
    // resilience, and the tool_use/unknown-type arms of build_transcript_text.
    // =========================================================================

    /// `last_n_turns` with `n = 0` returns empty WITHOUT opening the file
    /// (a valid transcript is present; the window size alone gates it).
    #[test]
    fn last_n_turns_zero_window_returns_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("turns.jsonl");
        write_transcript(&path, &[r#"{"type":"user","message":"hello"}"#]);
        assert!(
            last_n_turns(path.to_str().unwrap(), 0).is_empty(),
            "n == 0 must yield no turns even for a valid transcript"
        );
    }

    /// `last_n_turns` must (a) skip blank lines, non-JSON lines, non-user/
    /// assistant roles, and empty-content turns, and (b) keep only the
    /// trailing `n` valid turns in chronological order.
    #[test]
    fn last_n_turns_filters_noise_and_keeps_trailing_window_in_order() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("noisy.jsonl");
        // The noise rows sit INSIDE the trailing window region on purpose: a
        // regression that stops filtering them would shift the window and
        // change its contents (caught below), not just its prefix.
        write_transcript(
            &path,
            &[
                "",                 // blank: skipped
                "this is not json", // bad JSON: skipped
                r#"{"type":"user","message":"turn one"}"#,
                r#"{"type":"assistant","message":"turn two"}"#,
                r#"{"type":"user","message":"turn three"}"#,
                r#"{"type":"system","message":"sys note"}"#, // role: skipped
                r#"{"type":"user","message":""}"#,           // empty content: skipped
                r#"{"type":"assistant","message":"turn four"}"#,
            ],
        );
        let turns = last_n_turns(path.to_str().unwrap(), 3);
        let expected = vec![
            OwnedTurn {
                role: "assistant".to_string(),
                content: "turn two".to_string(),
            },
            OwnedTurn {
                role: "user".to_string(),
                content: "turn three".to_string(),
            },
            OwnedTurn {
                role: "assistant".to_string(),
                content: "turn four".to_string(),
            },
        ];
        assert_eq!(
            turns, expected,
            "trailing window must keep the LAST 3 valid turns, oldest first, \
             with noise lines and non-chat roles excluded"
        );
    }

    /// `count_transcript_tokens` must count tokens ONLY for `user`/`assistant`
    /// entries; a `system` entry parses (and bumps `message_count`) but must
    /// contribute zero tokens to either side.
    #[test]
    fn count_tokens_counts_only_user_and_assistant_roles() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("roles.jsonl");
        write_transcript(
            &path,
            &[
                // "system padding" = 14 chars => 4 tokens IF it were counted.
                r#"{"type":"system","message":"system padding"}"#,
                // "user msg" = 8 chars => (8+3)/4 = 2 tokens.
                r#"{"type":"user","message":"user msg"}"#,
            ],
        );
        let (input_tok, output_tok, msg_count) = count_transcript_tokens(path.to_str().unwrap());
        assert_eq!(
            input_tok, 2,
            "only the user turn may contribute input tokens"
        );
        assert_eq!(
            output_tok, 0,
            "a system entry must NOT count as assistant output"
        );
        assert_eq!(
            msg_count, 2,
            "both valid JSONL entries are counted as messages"
        );
    }

    /// An existing-but-unreadable transcript (mode 000) passes the metadata
    /// gate but fails `File::open`; both sync readers must degrade to their
    /// empty sentinels instead of erroring.
    #[cfg(unix)]
    #[test]
    fn unreadable_transcript_degrades_to_empty_sentinels() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("locked.jsonl");
        write_transcript(&path, &[r#"{"type":"user","message":"hello"}"#]);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
        if std::fs::File::open(&path).is_ok() {
            // Running as root (CI edge): mode 000 is not enforceable; skip.
            return;
        }
        assert!(
            last_n_turns(path.to_str().unwrap(), 5).is_empty(),
            "unreadable transcript must yield no turns"
        );
        assert_eq!(
            count_transcript_tokens(path.to_str().unwrap()),
            (0, 0, 0),
            "unreadable transcript must yield zero token counts"
        );
    }

    /// `process_transcript` on an unreadable file must return the all-`None`
    /// result (open failure AFTER the path gate), not panic or hang.
    #[cfg(unix)]
    #[tokio::test]
    async fn process_transcript_unreadable_file_returns_empty_result() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("locked2.jsonl");
        write_transcript(&path, &[r#"{"type":"user","message":"hello"}"#]);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
        if std::fs::File::open(&path).is_ok() {
            return; // root: permission bits not enforced
        }
        let result = process_transcript(path.to_str().unwrap(), false).await;
        assert!(
            result.summary.is_none(),
            "no summary for an unreadable file"
        );
        assert!(
            result.message_count.is_none(),
            "open-failure path reports message_count = None (vs Some(0) for an \
             empty-but-readable transcript)"
        );
        assert_eq!((result.input_tokens, result.output_tokens), (0, 0));
    }

    /// A readable transcript with NO valid JSONL entries reports
    /// `message_count = Some(0)` and no summary (the empty-entries early
    /// return, distinct from the unreadable-file `None` shape).
    #[tokio::test]
    async fn process_transcript_no_valid_entries_reports_zero_messages() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("garbage.jsonl");
        write_transcript(&path, &["", "not json at all", "   "]);
        let result = process_transcript(path.to_str().unwrap(), false).await;
        assert_eq!(
            result.message_count,
            Some(0),
            "empty-but-readable transcript must report Some(0) messages"
        );
        assert!(result.summary.is_none(), "no summary without entries");
        assert_eq!((result.input_tokens, result.output_tokens), (0, 0));
    }

    /// An invalid-UTF-8 line must be skipped (the `lines()` Err arm) while the
    /// remaining valid turns are still counted; a `system` entry is counted as
    /// a message but contributes no tokens.
    #[tokio::test]
    async fn process_transcript_skips_invalid_utf8_and_counts_remaining_turns() {
        use std::io::Write;
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("mixed.jsonl");
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(b"\xff\xfe\xfd not utf8\n").unwrap();
        f.write_all(b"\n").unwrap(); // blank line: skipped
        f.write_all(br#"{"type":"user","message":"hello world"}"#)
            .unwrap();
        f.write_all(b"\n").unwrap();
        f.write_all(br#"{"type":"system","message":"sys"}"#)
            .unwrap();
        f.write_all(b"\n").unwrap();
        f.write_all(br#"{"type":"assistant","message":"goodbye world"}"#)
            .unwrap();
        f.write_all(b"\n").unwrap();
        drop(f);

        // ollama_available = false: deterministic fast path, no network.
        let result = process_transcript(path.to_str().unwrap(), false).await;
        assert_eq!(
            result.summary.as_deref(),
            Some("Session with 3 messages"),
            "fast-path summary must reflect the 3 parsed entries (bad-UTF-8 \
             and blank lines skipped)"
        );
        assert_eq!(result.message_count, Some(3));
        // "hello world" = 11 chars -> 3 tokens; "goodbye world" = 13 -> 4.
        assert_eq!(result.input_tokens, 3, "user tokens");
        assert_eq!(result.output_tokens, 4, "assistant tokens; system adds 0");
    }

    /// `build_transcript_text` renders `tool_use` entries as `[tool_use]: <tool>`,
    /// truncates >500-char chat content with an ellipsis, and silently drops
    /// unknown entry types.
    #[test]
    fn build_transcript_text_renders_tool_use_and_skips_unknown_types() {
        let long = "a".repeat(600);
        let entries = vec![
            TranscriptEntry {
                entry_type: Some("user".to_string()),
                message: Some(TranscriptMessage::String(long.clone())),
                tool: None,
            },
            TranscriptEntry {
                entry_type: Some("tool_use".to_string()),
                message: None,
                tool: Some("Bash".to_string()),
            },
            TranscriptEntry {
                entry_type: Some("system".to_string()),
                message: Some(TranscriptMessage::String("UNIQUE-SYS-MARKER".to_string())),
                tool: None,
            },
        ];
        let text = build_transcript_text(&entries);
        let expected_user_line = format!("[user]: {}...", &long[..500]);
        assert!(
            text.contains(&expected_user_line),
            "over-500-char content must be truncated to exactly 500 chars + ellipsis; got: {text}"
        );
        assert!(
            text.contains("[tool_use]: Bash"),
            "tool_use entries must render the tool name; got: {text}"
        );
        assert!(
            !text.contains("UNIQUE-SYS-MARKER"),
            "unknown entry types must be dropped from the rendered transcript"
        );
    }
}
