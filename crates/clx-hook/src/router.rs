//! Hook event router.
//!
//! This module owns the orchestration logic that was previously inlined in
//! `main()`. It is intentionally pure with respect to process state: stdin
//! and stdout are abstracted behind generic `Read` / `Write` parameters so
//! tests can drive `handle_event` with in-memory buffers.
//!
//! Layering:
//! - Orchestration: `handle_event` (this file)
//! - Domain: `HookDeps`, `HookExit` (this file)
//! - Infrastructure: handlers under `crate::hooks::*` (re-use `Config::load`
//!   and `Storage::open_default` internally; that plumbing is owned by them
//!   and is not changed in this refactor)
//! - Mapping: `crate::output::*`
//!
//! Known limitation: `output::output_decision` / `output::output_generic`
//! still write to the process stdout via `println!`. The `writer` parameter
//! is currently used only for the parse-error/oversize-input fallback. A
//! follow-up will plumb the writer through `output::*` to make stdout
//! itself injectable.

use std::io::{Read, Write};

use clx_core::config::Config;
use clx_core::redaction::redact_secrets;
use clx_core::storage::Storage;
use tracing::{debug, error, warn};

use crate::hooks::{
    handle_post_tool_use, handle_pre_compact, handle_pre_tool_use, handle_session_end,
    handle_session_start, handle_subagent_start, handle_user_prompt_submit,
};
use crate::output::output_decision;
use crate::types::{HookInput, MAX_INPUT_SIZE};

/// Dependencies the router needs to dispatch a hook event.
///
/// Today the downstream handlers re-load `Config` and `Storage` internally,
/// so `HookDeps` is constructed in `main()` and held by the router but not
/// yet threaded through to every handler. The struct still exists so that
/// (a) we have a single chokepoint where future handler signatures will
/// accept injected deps, and (b) integration tests can build a
/// `HookDeps::for_test()` value without standing up the real filesystem.
pub struct HookDeps {
    /// Loaded CLX config (or default if loading failed).
    pub config: Config,
    /// Open storage handle (default location, or in-memory for tests).
    pub storage: Storage,
}

impl HookDeps {
    /// Build deps using process defaults. Falls back to a default config and
    /// the default sqlite path. Returns `None` if storage cannot be opened.
    pub fn from_process_defaults() -> Option<Self> {
        let config = Config::load().unwrap_or_default();
        let storage = Storage::open_default().ok()?;
        Some(Self { config, storage })
    }

    /// Build deps suitable for tests: default config, in-memory storage.
    #[cfg(any(test, feature = "test-fixtures"))]
    pub fn for_test() -> Self {
        Self {
            config: Config::default(),
            storage: Storage::open_in_memory().expect("in-memory sqlite for test deps"),
        }
    }
}

/// Result of running `handle_event`. The binary maps every variant to
/// `ExitCode::SUCCESS` (Claude Code treats non-zero exit codes as hook
/// failure noise), but tests can match on this to assert behavior.
#[derive(Debug, PartialEq, Eq)]
pub enum HookExit {
    /// Event was handled (or unknown event was allowed). Hook exited cleanly.
    Ok,
    /// Input exceeded `MAX_INPUT_SIZE`; a block decision was emitted.
    InputTooLarge,
    /// Stdin could not be read at all; an allow fallback was emitted.
    ReadError,
    /// JSON parse failed; an "ask" fallback was emitted on stdout.
    ParseError,
    /// A downstream handler returned an error; the hook still exits clean.
    HandlerError,
}

/// Read stdin into a bounded `String`, capping at `MAX_INPUT_SIZE` bytes.
///
/// Returns `Ok(s)` on success, `Err(ReadOutcome::TooLarge)` when the cap is
/// hit, or `Err(ReadOutcome::ReadFailed)` if the underlying reader errors.
pub(crate) fn read_input<R: Read>(reader: R) -> Result<String, ReadOutcome> {
    let mut buf = String::new();
    match reader.take(MAX_INPUT_SIZE).read_to_string(&mut buf) {
        Ok(n) => {
            if n as u64 >= MAX_INPUT_SIZE {
                Err(ReadOutcome::TooLarge)
            } else {
                Ok(buf)
            }
        }
        Err(_) => Err(ReadOutcome::ReadFailed),
    }
}

/// Why `read_input` failed.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ReadOutcome {
    TooLarge,
    ReadFailed,
}

/// Parse a raw JSON string into `HookInput`. Wraps `serde_json::from_str`
/// so the router can compose error handling consistently.
pub(crate) fn parse_input(raw: &str) -> Result<HookInput, serde_json::Error> {
    serde_json::from_str::<HookInput>(raw)
}

/// Run the parsed event through the matching handler. Unknown event names
/// emit the safe "allow" fallback and return `Ok(())`.
pub(crate) async fn dispatch(input: HookInput) -> anyhow::Result<()> {
    match input.hook_event_name.as_str() {
        "PreToolUse" => handle_pre_tool_use(input).await,
        "PostToolUse" => handle_post_tool_use(input).await,
        "PreCompact" => handle_pre_compact(input).await,
        "SessionStart" => handle_session_start(input).await,
        "SessionEnd" => handle_session_end(input).await,
        "SubagentStart" => handle_subagent_start(input).await,
        "UserPromptSubmit" => handle_user_prompt_submit(input).await,
        unknown => {
            warn!("Unknown hook event: {}", unknown);
            output_decision("allow", None, None, None);
            Ok(())
        }
    }
}

/// Run one hook invocation end-to-end.
///
/// Read the JSON envelope from `reader`, parse it, route to the right
/// handler, and surface any output. Process exit code is conveyed via the
/// `HookExit` return value (callers translate it as needed; in `main()`
/// every variant currently maps to `ExitCode::SUCCESS`).
///
/// `writer` is reserved for the fallback paths (oversize input, read
/// failure). Handlers themselves still write through `crate::output::*`,
/// which currently uses `println!` on the process stdout.
pub async fn handle_event<R, W>(reader: R, mut writer: W, _deps: HookDeps) -> HookExit
where
    R: Read,
    W: Write,
{
    let raw = match read_input(reader) {
        Ok(s) => s,
        Err(ReadOutcome::TooLarge) => {
            // Match historical behavior: emit a block decision and exit.
            let output = serde_json::json!({
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "block",
                    "permissionDecisionReason": "Input too large"
                }
            });
            let _ = writeln!(writer, "{output}");
            return HookExit::InputTooLarge;
        }
        Err(ReadOutcome::ReadFailed) => {
            // Historical behavior on read error: fall back to allow.
            output_decision("allow", None, None, None);
            return HookExit::ReadError;
        }
    };

    debug!("Hook input: {}", redact_secrets(&raw));

    let input = match parse_input(&raw) {
        Ok(input) => input,
        Err(e) => {
            error!("Failed to parse hook input: {}", e);
            output_decision(
                "ask",
                Some("CLX: Input parse error, manual confirmation required".to_string()),
                None,
                None,
            );
            return HookExit::ParseError;
        }
    };

    match dispatch(input).await {
        Ok(()) => HookExit::Ok,
        Err(e) => {
            error!("Hook handler error: {}", e);
            HookExit::HandlerError
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pre_tool_use_envelope() -> String {
        serde_json::json!({
            "session_id": "sess-router-001",
            "cwd": "/tmp/test-project",
            "hook_event_name": "PreToolUse",
            "tool_name": "Read",
            "tool_use_id": "tu-router-001",
            "tool_input": { "file_path": "/tmp/test.txt" }
        })
        .to_string()
    }

    #[test]
    fn read_input_happy_path() {
        let bytes = b"{\"hello\":\"world\"}";
        let out = read_input(&bytes[..]).expect("read");
        assert_eq!(out, "{\"hello\":\"world\"}");
    }

    #[test]
    fn read_input_empty_input_is_ok() {
        let bytes: &[u8] = b"";
        let out = read_input(bytes).expect("read");
        assert_eq!(out, "");
    }

    #[test]
    fn read_input_oversize_is_rejected() {
        // 1 byte more than MAX_INPUT_SIZE.
        let big = vec![b'a'; (MAX_INPUT_SIZE as usize) + 1];
        let err = read_input(&big[..]).expect_err("should reject");
        assert_eq!(err, ReadOutcome::TooLarge);
    }

    #[test]
    fn parse_input_malformed_returns_err() {
        let err = parse_input("not json").expect_err("should fail");
        assert!(err.to_string().contains("expected"));
    }

    #[test]
    fn parse_input_missing_required_field_returns_err() {
        let raw = serde_json::json!({"hook_event_name":"PreToolUse"}).to_string();
        let err = parse_input(&raw).expect_err("missing fields");
        // session_id and cwd are required
        let msg = err.to_string();
        assert!(
            msg.contains("session_id") || msg.contains("cwd"),
            "expected missing-field error, got: {msg}"
        );
    }

    #[tokio::test]
    async fn handle_event_oversize_emits_block_to_writer() {
        let big = vec![b'a'; (MAX_INPUT_SIZE as usize) + 1];
        let mut out = Vec::<u8>::new();
        let exit = handle_event(&big[..], &mut out, HookDeps::for_test()).await;
        assert_eq!(exit, HookExit::InputTooLarge);
        let s = String::from_utf8_lossy(&out);
        let parsed: serde_json::Value = serde_json::from_str(s.trim()).expect("valid json");
        assert_eq!(parsed["hookSpecificOutput"]["permissionDecision"], "block");
        assert_eq!(parsed["hookSpecificOutput"]["hookEventName"], "PreToolUse");
    }

    #[tokio::test]
    async fn handle_event_malformed_json_returns_parse_error() {
        let bytes = b"definitely not json";
        let mut out = Vec::<u8>::new();
        let exit = handle_event(&bytes[..], &mut out, HookDeps::for_test()).await;
        assert_eq!(exit, HookExit::ParseError);
    }

    #[tokio::test]
    async fn handle_event_unknown_event_returns_ok_via_dispatch() {
        let raw = serde_json::json!({
            "session_id": "sess-router-unknown",
            "cwd": "/tmp",
            "hook_event_name": "SomeFutureEvent"
        })
        .to_string();
        let mut out = Vec::<u8>::new();
        let exit = handle_event(raw.as_bytes(), &mut out, HookDeps::for_test()).await;
        // dispatch returns Ok for unknown events (after emitting allow on stdout)
        assert_eq!(exit, HookExit::Ok);
    }

    #[tokio::test]
    async fn handle_event_happy_pre_tool_use() {
        let raw = pre_tool_use_envelope();
        let mut out = Vec::<u8>::new();
        let exit = handle_event(raw.as_bytes(), &mut out, HookDeps::for_test()).await;
        // Handlers may return Ok or HandlerError depending on filesystem
        // state in the test environment. Both are acceptable here: this
        // test just ensures handle_event reaches dispatch without panic.
        assert!(
            matches!(exit, HookExit::Ok | HookExit::HandlerError),
            "unexpected exit: {exit:?}"
        );
    }
}
