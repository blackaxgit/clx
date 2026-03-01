//! Transcript processing and summarization.

use crate::embedding::truncate_to_char_boundary;
use crate::types::{SUMMARIZE_PROMPT, SummaryResponse, TranscriptEntry, TranscriptResult};
use clx_core::config::Config;
use clx_core::ollama::OllamaClient;
use clx_core::types::estimate_tokens;
use std::fs::File;
use std::io::{BufRead, BufReader};
use tracing::warn;

/// Fast token count from transcript file (no LLM calls, no async).
/// Returns (`input_tokens`, `output_tokens`, `message_count`).
pub(crate) fn count_transcript_tokens(transcript_path: &str) -> (i64, i64, i32) {
    let Ok(file) = File::open(transcript_path) else {
        return (0, 0, 0);
    };

    let reader = BufReader::new(file);
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

/// Read and process a transcript file
pub(crate) async fn process_transcript(transcript_path: &str) -> TranscriptResult {
    // Read transcript file
    let file = match File::open(transcript_path) {
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

    let reader = BufReader::new(file);
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

    // Generate summary using Ollama
    let config = Config::load().unwrap_or_default();
    let ollama = match OllamaClient::new(config.ollama) {
        Ok(client) => client,
        Err(e) => {
            warn!("Failed to create Ollama client for summarization: {}", e);
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

    match ollama.generate(&prompt, None).await {
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
            warn!("Failed to generate summary: {}", e);
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

        let temp_dir =
            std::env::temp_dir().join(format!("clx-transcript-test-{}", std::process::id()));
        std::fs::create_dir_all(&temp_dir).unwrap();
        let transcript_path = temp_dir.join("transcript.jsonl");

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

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_count_transcript_tokens_exceeds_pressure_threshold() {
        use std::io::Write;

        let temp_dir =
            std::env::temp_dir().join(format!("clx-pressure-test-{}", std::process::id()));
        std::fs::create_dir_all(&temp_dir).unwrap();
        let transcript_path = temp_dir.join("transcript.jsonl");

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

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
