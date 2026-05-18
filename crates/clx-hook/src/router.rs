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
    handle_session_start, handle_stop_auto_summary, handle_subagent_start,
    handle_user_prompt_submit,
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
    #[must_use]
    pub fn from_process_defaults() -> Option<Self> {
        let config = Config::load().unwrap_or_default();
        let storage = Storage::open_default().ok()?;
        Some(Self { config, storage })
    }

    /// Build deps suitable for tests: default config, in-memory storage.
    #[cfg(test)]
    #[must_use]
    pub fn for_test() -> Self {
        Self {
            config: Config::default(),
            storage: Storage::open_in_memory().expect("in-memory sqlite for test deps"),
        }
    }
}

/// Best-effort provenance verdict for the hook invocation (finding F7).
///
/// Threat model: `clx-hook` reads its JSON envelope from stdin. The
/// documented assumption is "stdin is trusted because Claude Code spawns
/// us". A local same-uid attacker can violate that by piping a fabricated
/// `Stop` / `PostToolUse` envelope to poison CLX memory or audit state.
///
/// Claude Code 2026 does NOT hand hooks an unforgeable token. Per the
/// official hooks docs (code.claude.com/docs/en/hooks, fetched 2026-05-17)
/// the only spawn-time signal is the presence of Claude-Code-set
/// environment variables (`CLAUDE_PROJECT_DIR`, and `CLAUDE_PLUGIN_ROOT`
/// for plugin hooks). These are inherited and therefore forgeable by a
/// same-uid attacker who knows the convention, so this check is genuinely
/// best-effort defense-in-depth, not an authentication boundary.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Provenance {
    /// At least one Claude-Code-set environment variable is present. The
    /// invocation is consistent with a real Claude Code spawn.
    Trusted,
    /// No Claude-Code-set environment variable is present. Provenance could
    /// not be established (spoof attempt, or a legitimate edge case such as
    /// the contract test harness, CI, or a debugger). Caller logs a WARN
    /// and still processes: a false positive that blocks every hook is a
    /// worse outcome than the residual local-attacker risk already
    /// acknowledged in the threat model (fail-safe, not fail-closed).
    Unverified,
}

/// Environment variable names Claude Code 2026 sets on every hook spawn.
/// `CLAUDE_PROJECT_DIR` is set for all command hooks; `CLAUDE_PLUGIN_ROOT`
/// is additionally set for plugin hooks (CLX ships as a plugin). Source:
/// official Claude Code hooks documentation, fetched 2026-05-17.
pub const CLAUDE_PROVENANCE_ENV_VARS: &[&str] = &["CLAUDE_PROJECT_DIR", "CLAUDE_PLUGIN_ROOT"];

/// Pure provenance decision function (Domain layer: no process state).
///
/// Given the values of the known Claude-Code-set environment variables
/// (as `(name, Option<value>)` pairs), decide whether the invocation looks
/// like a real Claude Code spawn. An env var counts as "present" only when
/// it is set AND non-empty, so an attacker cannot satisfy the check by
/// exporting an empty placeholder (and a stray empty export does not give
/// false confidence either). The OS read that produces these pairs lives
/// at the `main()` infrastructure edge.
#[must_use]
pub fn classify_provenance(env_vars: &[(&str, Option<String>)]) -> Provenance {
    let any_present = env_vars
        .iter()
        .any(|(_, value)| value.as_deref().is_some_and(|v| !v.trim().is_empty()));
    if any_present {
        Provenance::Trusted
    } else {
        Provenance::Unverified
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
        "Stop" => handle_stop_auto_summary(input).await,
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
    fn classify_provenance_trusted_when_project_dir_set() {
        let env = [
            ("CLAUDE_PROJECT_DIR", Some("/home/u/proj".to_string())),
            ("CLAUDE_PLUGIN_ROOT", None),
        ];
        assert_eq!(classify_provenance(&env), Provenance::Trusted);
    }

    #[test]
    fn classify_provenance_trusted_when_plugin_root_set() {
        let env = [
            ("CLAUDE_PROJECT_DIR", None),
            ("CLAUDE_PLUGIN_ROOT", Some("/home/u/.claude/p".to_string())),
        ];
        assert_eq!(classify_provenance(&env), Provenance::Trusted);
    }

    #[test]
    fn classify_provenance_unverified_when_none_set() {
        let env = [("CLAUDE_PROJECT_DIR", None), ("CLAUDE_PLUGIN_ROOT", None)];
        assert_eq!(classify_provenance(&env), Provenance::Unverified);
    }

    #[test]
    fn classify_provenance_empty_value_does_not_satisfy_check() {
        // An attacker exporting an empty placeholder must not pass, and a
        // stray empty export must not give false confidence.
        let env = [
            ("CLAUDE_PROJECT_DIR", Some(String::new())),
            ("CLAUDE_PLUGIN_ROOT", Some("   ".to_string())),
        ];
        assert_eq!(classify_provenance(&env), Provenance::Unverified);
    }

    #[test]
    fn classify_provenance_known_env_var_list_is_nonempty() {
        // Guard against an accidental edit that empties the source list,
        // which would make classify_provenance always Unverified.
        assert!(!CLAUDE_PROVENANCE_ENV_VARS.is_empty());
        assert!(CLAUDE_PROVENANCE_ENV_VARS.contains(&"CLAUDE_PROJECT_DIR"));
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

    // =====================================================================
    // Wave 1 E: in-process integration behavior for `handle_event`.
    //
    // These live here (not in `tests/hooks_router_e2e.rs`) because the
    // workspace lint forbids `unsafe` `std::env::set_var`, so an external
    // integration test cannot redirect `HOME` to build real `HookDeps`
    // without touching the real `~/.clx`. `HookDeps::for_test()` is
    // `#[cfg(test)]`-only (in-memory sqlite, zero real-env / network /
    // keychain), so the safe place for the in-memory `Read`/`Write`
    // contract is this in-crate module. Anchored to
    // `specs/_prerelease/04-integration.md` 3.1 + the edge/failure matrix.
    // =====================================================================
    mod wave1_integration_behavior {
        use super::*;

        fn envelope(event: &str, extra: &serde_json::Value) -> String {
            let mut base = serde_json::json!({
                "session_id": "00000000-0000-0000-0000-0000000000ee",
                "cwd": "/tmp/test-project",
                "hook_event_name": event,
            });
            if let (Some(b), Some(e)) = (base.as_object_mut(), extra.as_object()) {
                for (k, v) in e {
                    b.insert(k.clone(), v.clone());
                }
            }
            base.to_string()
        }

        #[tokio::test]
        async fn oversize_writes_block_json_to_injected_writer() {
            let big = vec![b'a'; (MAX_INPUT_SIZE as usize) + 1];
            let mut out = Vec::<u8>::new();
            let exit = handle_event(&big[..], &mut out, HookDeps::for_test()).await;
            assert_eq!(exit, HookExit::InputTooLarge);
            let v: serde_json::Value =
                serde_json::from_str(String::from_utf8_lossy(&out).trim()).expect("block json");
            assert_eq!(v["hookSpecificOutput"]["hookEventName"], "PreToolUse");
            assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "block");
            assert_eq!(
                v["hookSpecificOutput"]["permissionDecisionReason"],
                "Input too large"
            );
        }

        #[tokio::test]
        async fn exactly_at_cap_is_input_too_large() {
            // Documented boundary `n >= MAX_INPUT_SIZE` (router.rs read_input).
            let at_cap = vec![b'a'; MAX_INPUT_SIZE as usize];
            let mut out = Vec::<u8>::new();
            let exit = handle_event(&at_cap[..], &mut out, HookDeps::for_test()).await;
            assert_eq!(exit, HookExit::InputTooLarge);
        }

        #[tokio::test]
        async fn malformed_json_is_parse_error() {
            let mut out = Vec::<u8>::new();
            let exit =
                handle_event(b"not json at all" as &[u8], &mut out, HookDeps::for_test()).await;
            assert_eq!(exit, HookExit::ParseError);
        }

        #[tokio::test]
        async fn empty_stdin_is_parse_error() {
            let mut out = Vec::<u8>::new();
            let exit = handle_event(b"" as &[u8], &mut out, HookDeps::for_test()).await;
            assert_eq!(exit, HookExit::ParseError);
        }

        #[tokio::test]
        async fn missing_required_field_is_parse_error() {
            let raw = serde_json::json!({ "hook_event_name": "PreToolUse" }).to_string();
            let mut out = Vec::<u8>::new();
            let exit = handle_event(raw.as_bytes(), &mut out, HookDeps::for_test()).await;
            assert_eq!(exit, HookExit::ParseError);
        }

        #[tokio::test]
        async fn unknown_event_is_allowed_ok() {
            let raw = envelope("SomeFutureEvent2027", &serde_json::json!({}));
            let mut out = Vec::<u8>::new();
            let exit = handle_event(raw.as_bytes(), &mut out, HookDeps::for_test()).await;
            assert_eq!(exit, HookExit::Ok);
        }

        #[tokio::test]
        async fn all_eight_events_reach_dispatch_without_panic() {
            // 3.2: every registered event dispatches; Stop is synthesized
            // here (I-R2 gap) with a correct `hook_event_name:"Stop"`.
            let cases = [
                (
                    "PreToolUse",
                    serde_json::json!({"tool_name":"Read","tool_use_id":"t","tool_input":{"file_path":"/tmp/x"}}),
                ),
                (
                    "PostToolUse",
                    serde_json::json!({"tool_name":"Read","tool_use_id":"t","tool_input":{"file_path":"/tmp/x"},"tool_response":{"ok":true}}),
                ),
                ("PreCompact", serde_json::json!({"trigger":"auto"})),
                ("SessionStart", serde_json::json!({"source":"startup"})),
                ("SessionEnd", serde_json::json!({})),
                ("SubagentStart", serde_json::json!({"tool_name":"Task"})),
                (
                    "UserPromptSubmit",
                    serde_json::json!({"prompt":"long enough prompt to reach the recall gate"}),
                ),
                ("Stop", serde_json::json!({})),
            ];
            for (event, extra) in cases {
                let raw = envelope(event, &extra);
                let mut out = Vec::<u8>::new();
                let exit = handle_event(raw.as_bytes(), &mut out, HookDeps::for_test()).await;
                assert!(
                    matches!(exit, HookExit::Ok | HookExit::HandlerError),
                    "event {event} should reach dispatch, got {exit:?}"
                );
            }
        }
    }
}
