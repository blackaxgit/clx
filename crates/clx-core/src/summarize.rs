//! Pure domain logic for rolling N-turn auto-summarization (Phase 10 / 0.8.0).
//!
//! This module owns the *decision and shaping* of an auto-summary:
//! - Build a deterministic prompt from a span of transcript turns.
//! - Call a provided `LlmClient` to produce an LLM summary, or fall back to
//!   a deterministic template when no client is available or the call
//!   fails.
//! - Truncate to a configured character budget.
//!
//! Layering: this module is intentionally pure with respect to filesystem,
//! HTTP, and storage. It depends only on:
//! - `crate::llm::LlmClient` (a trait-like static-dispatch wrapper),
//! - `crate::config::AutoSummarizeConfig` (typed config),
//! - the standard regex / string library for the template fallback.
//!
//! All I/O (transcript reading, snapshot persistence, hook dispatch) lives
//! in `clx-hook`. Cancellation safety is the caller's responsibility; this
//! module performs at most one LLM call and writes no state.

use std::collections::BTreeSet;
use std::sync::LazyLock;
use std::time::Duration;

use regex::Regex;

use crate::config::{AutoSummarizeConfig, CapabilityRoute};
use crate::llm::LlmClient;

/// One turn from a transcript, narrowed to just role + content.
///
/// Role is a free-form string mirroring the transcript JSONL `type` field
/// (`"user"` | `"assistant"`). Borrowed slices so callers can build a
/// fresh `Vec<TurnSlice<'_>>` without copying transcript bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TurnSlice<'a> {
    /// `"user"` or `"assistant"` (or any future role).
    pub role: &'a str,
    /// Raw turn content. Trimmed lazily by the prompt builder.
    pub content: &'a str,
}

/// Default soft timeout for the LLM call when no override is plumbed.
///
/// Stop hook latency budget: keep this conservative so a hung provider
/// can't block session exit. Callers may wrap `summarize_turns` in
/// `tokio::time::timeout` if they want a tighter ceiling.
pub const DEFAULT_LLM_TIMEOUT: Duration = Duration::from_secs(10);

/// Produce an auto-summary string for a span of transcript turns.
///
/// Strategy:
/// 1. If `turns` is empty, return an empty string immediately.
/// 2. If an `LlmClient` is provided, build the deterministic prompt and
///    request a completion. On success and non-empty body, return the
///    truncated body.
/// 3. On any LLM error, on empty body, or when no client is supplied,
///    return the deterministic template fallback truncated to
///    `cfg.max_summary_chars` chars.
///
/// The function never panics and never propagates an LLM error: failure
/// is converted into the template fallback so the Stop hook can always
/// persist a snapshot row when called.
///
/// # Errors
///
/// Currently infallible from the caller's perspective; the `Result`
/// shape is retained for forward-compat (future variants may want to
/// propagate config-validation errors).
pub async fn summarize_turns(
    turns: &[TurnSlice<'_>],
    cfg: &AutoSummarizeConfig,
    llm: Option<&LlmClient>,
    route: Option<&CapabilityRoute>,
) -> crate::Result<String> {
    if turns.is_empty() {
        return Ok(String::new());
    }

    let prompt = build_prompt(turns, cfg.max_summary_chars);

    if let Some(client) = llm {
        let model = route.map(|r| r.model.as_str());
        match client.generate(&prompt, model).await {
            Ok(s) if !s.trim().is_empty() => {
                return Ok(truncate_chars(s.trim().to_string(), cfg.max_summary_chars));
            }
            Ok(_) | Err(_) => {
                // fall through to deterministic template.
            }
        }
    }

    Ok(deterministic_template_summary(
        &flatten_turns(turns),
        cfg.max_summary_chars,
    ))
}

/// Build the deterministic prompt sent to the summarizer.
///
/// Format is stable; tests pin the prefix and the trailing "TURNS:" header
/// so that regressions in prompt wording surface explicitly.
#[must_use]
pub fn build_prompt(turns: &[TurnSlice<'_>], max_chars: usize) -> String {
    let mut body = String::with_capacity(256 + turns.len() * 64);
    use std::fmt::Write as _;
    let _ = write!(
        body,
        "Summarize the following {n}-turn span into <= {max_chars} chars, \
         focusing on decisions made, files touched, and TODOs:\n\nTURNS:\n",
        n = turns.len(),
    );
    for turn in turns {
        body.push_str("- [");
        body.push_str(turn.role);
        body.push_str("] ");
        // Cap per-turn at 600 chars to keep prompt size bounded even
        // when the transcript span is long-form. Truncation respects
        // char boundaries (not byte slicing) so it's UTF-8 safe.
        body.push_str(&truncate_chars(turn.content.to_string(), 600));
        body.push('\n');
    }
    body
}

/// Deterministic template fallback used when the LLM is unavailable or
/// returns an empty body.
///
/// Output shape: `"Auto-summary (no LLM): <last_user_request> | files: a.rs, b.toml"`.
/// The function:
/// - extracts the last `user` request prefix (first 200 chars, trimmed),
/// - scans every turn for file paths via a conservative regex over
///   common project extensions,
/// - truncates the final result to `max_chars` chars on a UTF-8 boundary.
#[must_use]
pub fn deterministic_template_summary(turns_text: &str, max_chars: usize) -> String {
    let last_user = extract_last_user_request(turns_text);
    let files = extract_file_paths(turns_text);

    let mut out = String::with_capacity(64 + last_user.len() + files.len() * 16);
    out.push_str("Auto-summary (no LLM): ");
    if last_user.is_empty() {
        out.push_str("<no user turn>");
    } else {
        out.push_str(&truncate_chars(last_user, 200));
    }
    if !files.is_empty() {
        out.push_str(" | files: ");
        out.push_str(&files.join(", "));
    }
    truncate_chars(out, max_chars)
}

/// Flatten a slice of turns into a single text blob; used as input to the
/// template fallback's regex-based extraction passes.
fn flatten_turns(turns: &[TurnSlice<'_>]) -> String {
    let mut s = String::with_capacity(turns.len() * 128);
    for t in turns {
        s.push('[');
        s.push_str(t.role);
        s.push_str("] ");
        s.push_str(t.content);
        s.push('\n');
    }
    s
}

/// Conservative file-path matcher: tokens that contain an extension we
/// commonly track in CLX. Avoids the `^|\s` anchor that would miss inline
/// references like `(src/foo.rs)`; keeps a permissive char class so a
/// reasonable subset of paths is captured without grabbing prose.
static FILE_PATH_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"[A-Za-z0-9_./-]+\.(?:rs|toml|md|sql|ya?ml|py|ts|tsx|js|json|sh|txt)")
        .expect("static FILE_PATH_REGEX compiles")
});

/// Last user request matcher (case-insensitive, multiline).
static LAST_USER_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?im)^\[user\]\s*(.+)$").expect("LAST_USER_REGEX compiles"));

fn extract_file_paths(text: &str) -> Vec<String> {
    let mut seen = BTreeSet::new();
    for cap in FILE_PATH_REGEX.find_iter(text) {
        seen.insert(cap.as_str().to_string());
    }
    seen.into_iter().collect()
}

fn extract_last_user_request(text: &str) -> String {
    let mut last = String::new();
    for cap in LAST_USER_REGEX.captures_iter(text) {
        if let Some(m) = cap.get(1) {
            last = m.as_str().trim().to_string();
        }
    }
    last
}

/// Truncate `s` to at most `max_chars` Unicode scalar values without
/// splitting a multi-byte character. Returns the input untouched if it
/// already fits.
#[must_use]
pub fn truncate_chars(s: String, max_chars: usize) -> String {
    if max_chars == 0 {
        return String::new();
    }
    let count = s.chars().count();
    if count <= max_chars {
        return s;
    }
    s.chars().take(max_chars).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn turns_simple() -> Vec<TurnSlice<'static>> {
        vec![
            TurnSlice {
                role: "user",
                content: "Refactor src/foo.rs and add tests in tests/bar.rs",
            },
            TurnSlice {
                role: "assistant",
                content: "Done. Updated src/foo.rs and Cargo.toml.",
            },
        ]
    }

    #[test]
    fn summarize_empty_input_returns_empty_string() {
        let cfg = AutoSummarizeConfig::default();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let out = rt
            .block_on(summarize_turns(&[], &cfg, None, None))
            .expect("infallible");
        assert!(out.is_empty(), "empty turns must produce empty output");
    }

    #[test]
    fn summarize_no_llm_falls_back_to_template() {
        let cfg = AutoSummarizeConfig::default();
        let turns = turns_simple();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let out = rt
            .block_on(summarize_turns(&turns, &cfg, None, None))
            .expect("infallible");
        assert!(out.starts_with("Auto-summary (no LLM):"));
        assert!(
            out.contains("foo.rs"),
            "template fallback must mention extracted file paths; got: {out}"
        );
    }

    #[test]
    fn template_fallback_extracts_file_paths_and_user_request() {
        let blob = "[user] Please refactor src/foo.rs and Cargo.toml\n\
                    [assistant] Done. Edits in src/foo.rs and tests/bar.rs.";
        let out = deterministic_template_summary(blob, 500);
        assert!(out.contains("refactor"), "user request prefix missing: {out}");
        assert!(out.contains("foo.rs"), "should list foo.rs: {out}");
        assert!(out.contains("Cargo.toml"), "should list Cargo.toml: {out}");
    }

    #[test]
    fn template_fallback_truncates_to_max_chars() {
        // 1000 ASCII chars input, max 50 chars output.
        let blob = "[user] ".to_string() + &"x".repeat(1000);
        let out = deterministic_template_summary(&blob, 50);
        assert_eq!(out.chars().count(), 50);
    }

    #[test]
    fn template_fallback_is_utf8_safe_on_multibyte_truncation() {
        // 3 bytes per kanji; deliberately truncate near a boundary.
        let blob = "[user] ".to_string() + &"漢字".repeat(200);
        let out = deterministic_template_summary(&blob, 50);
        // Must not panic; must be valid UTF-8; must respect char ceiling.
        assert!(std::str::from_utf8(out.as_bytes()).is_ok());
        assert!(out.chars().count() <= 50);
    }

    #[test]
    fn template_fallback_handles_empty_input_without_panic() {
        let out = deterministic_template_summary("", 500);
        assert!(out.contains("<no user turn>"), "got: {out}");
    }

    #[test]
    fn truncate_chars_zero_returns_empty() {
        let out = truncate_chars("hello".to_string(), 0);
        assert!(out.is_empty());
    }

    #[test]
    fn truncate_chars_under_limit_is_identity() {
        let out = truncate_chars("abc".to_string(), 10);
        assert_eq!(out, "abc");
    }

    #[test]
    fn truncate_chars_over_limit_cuts_at_char_boundary() {
        let out = truncate_chars("漢字漢字漢字".to_string(), 3);
        assert_eq!(out.chars().count(), 3);
        assert!(std::str::from_utf8(out.as_bytes()).is_ok());
    }

    #[test]
    fn build_prompt_contains_max_chars_directive() {
        let turns = turns_simple();
        let prompt = build_prompt(&turns, 250);
        assert!(
            prompt.contains("<= 250 chars"),
            "prompt must mention char ceiling: {prompt}"
        );
        assert!(prompt.contains("TURNS:"));
        assert!(prompt.contains("[user]"));
        assert!(prompt.contains("[assistant]"));
    }

    #[test]
    fn build_prompt_truncates_per_turn_to_600_chars() {
        let long = "x".repeat(5000);
        let turns = vec![TurnSlice {
            role: "user",
            content: &long,
        }];
        let prompt = build_prompt(&turns, 500);
        // Per-turn body is capped at 600 chars; rest of prompt is < 200 chars
        // of framing, so the whole prompt must be well below 5000 chars.
        assert!(prompt.chars().count() < 1500, "prompt too long: {}", prompt.chars().count());
    }

    #[test]
    fn extract_file_paths_dedupes_and_preserves_order() {
        // BTreeSet-based dedup orders alphabetically; that's documented
        // intent: the template summary is a sorted file list.
        let text = "src/foo.rs and src/foo.rs and src/bar.rs";
        let files = extract_file_paths(text);
        assert_eq!(files, vec!["src/bar.rs", "src/foo.rs"]);
    }

    #[test]
    fn extract_last_user_request_returns_last_match() {
        let blob = "[user] first request\n[assistant] ack\n[user] second request";
        assert_eq!(extract_last_user_request(blob), "second request");
    }

    #[test]
    fn extract_last_user_request_empty_when_none() {
        let blob = "[assistant] hello";
        assert_eq!(extract_last_user_request(blob), "");
    }

    #[test]
    fn summarize_respects_max_summary_chars_with_template() {
        let cfg = AutoSummarizeConfig {
            max_summary_chars: 40,
            ..AutoSummarizeConfig::default()
        };
        let turns = turns_simple();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let out = rt
            .block_on(summarize_turns(&turns, &cfg, None, None))
            .expect("infallible");
        assert!(out.chars().count() <= 40, "output exceeds budget: {out}");
    }
}
