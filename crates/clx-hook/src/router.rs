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
use clx_core::redaction::{redact_json_value, redact_secrets};
use clx_core::storage::Storage;
use tracing::{debug, error, warn};

use crate::hooks::{
    handle_post_tool_use, handle_pre_compact, handle_pre_tool_use, handle_session_end,
    handle_session_start, handle_stop_auto_summary, handle_subagent_start,
    handle_user_prompt_submit,
};
use crate::host::{Host, detect_host};
use crate::output::output_decision;
use crate::types::{HostNeutralInput, MAX_INPUT_SIZE};

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

/// Parse a raw JSON string into `HostNeutralInput` via the detected host.
///
/// For Claude this is the historical `serde_json::from_str` path (lossless
/// lift); other hosts map their envelope to the host-neutral shape. The
/// returned `serde_json::Error` keeps the existing error-handling contract.
///
/// `handle_event` uses `parse_input_with_host` (it has already detected the
/// host); this convenience wrapper is retained for the parse-error unit tests
/// and as the public single-arg parse entry point.
#[allow(dead_code)]
pub(crate) fn parse_input(raw: &str) -> Result<HostNeutralInput, serde_json::Error> {
    parse_input_with_host(&*detect_host(raw), raw)
}

/// Host-explicit parse, used by `handle_event` (which has already detected
/// the host) and by tests that want a deterministic host.
pub(crate) fn parse_input_with_host(
    host: &dyn Host,
    raw: &str,
) -> Result<HostNeutralInput, serde_json::Error> {
    // `Host::parse_hook_input` returns `anyhow::Error`; the only failure mode
    // for the Claude path is a serde parse error. Re-run the serde parse to
    // surface the typed `serde_json::Error` the callers expect, preserving
    // the historical parse-error behaviour exactly.
    match host.parse_hook_input(raw) {
        Ok(input) => Ok(input),
        Err(_) => serde_json::from_str::<HostNeutralInput>(raw).map(|mut input| {
            input.host = host.host_id();
            input
        }),
    }
}

/// Run the parsed event through the matching handler. Unknown event names
/// emit the safe "allow" fallback and return `Ok(())`.
pub(crate) async fn dispatch(input: HostNeutralInput, host: &dyn Host) -> anyhow::Result<()> {
    match input.hook_event_name.as_str() {
        "PreToolUse" => handle_pre_tool_use(input, host).await,
        "PostToolUse" => handle_post_tool_use(input, host).await,
        "PreCompact" => handle_pre_compact(input, host).await,
        "SessionStart" => handle_session_start(input, host).await,
        "SessionEnd" => handle_session_end(input, host).await,
        "SubagentStart" => handle_subagent_start(input, host).await,
        "UserPromptSubmit" => handle_user_prompt_submit(input, host).await,
        "Stop" => handle_stop_auto_summary(input, host).await,
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

    // B6-4: prefer the structure-aware redactor over free-text redact_secrets.
    // Parsing the envelope as JSON first lets redact_json_value walk the
    // value tree and scrub secrets under structured keys (e.g. "password",
    // "token") that redact_secrets' kv-heuristic misses when the surrounding
    // bytes are JSON punctuation rather than key=value text.
    // If the envelope is not valid JSON (malformed/fragment), fall back to
    // the existing free-text redactor so non-JSON input is still scrubbed.
    // The debug! macro does not evaluate its arguments when the level filter
    // excludes DEBUG, so the double-parse cost is zero in production builds.
    if tracing::enabled!(tracing::Level::DEBUG) {
        let redacted_dbg = serde_json::from_str::<serde_json::Value>(&raw).map_or_else(
            |_| redact_secrets(&raw),
            |v| redact_json_value(&v).to_string(),
        );
        debug!("Hook input: {}", redacted_dbg);
    }

    // Detect the host once, from the raw envelope (env override -> envelope
    // shape -> Claude default). The same instance drives parsing and
    // dispatch, so a single invocation never mixes hosts.
    let host = detect_host(&raw);

    let input = match parse_input_with_host(&*host, &raw) {
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

    match dispatch(input, &*host).await {
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

    // =========================================================================
    // B6-4: debug-log uses redact_json_value on parsed envelope
    // =========================================================================

    /// B6-4: verify that `redact_json_value` redacts a secret under a
    /// structured JSON key that `redact_secrets` (free-text, kv-heuristic)
    /// would miss when the surrounding bytes are JSON punctuation.
    ///
    /// FAIL-BEFORE: `redact_secrets(&raw)` on the raw string misses structured
    /// secrets because the kv-heuristic requires `key=value` or `key: value`
    /// form — a JSON `"password":"sk-secret123"` field has `:` not `=`.
    /// PASS-AFTER: `redact_json_value` walks the parsed tree and scrubs by
    /// key name, catching `"password"` unconditionally.
    #[test]
    fn b6_4_redact_json_value_catches_structured_secret_redact_secrets_misses() {
        use clx_core::redaction::redact_json_value;
        use serde_json::json;

        // Envelope with a secret under a structured key ("password").
        // redact_secrets' kv heuristic looks for `password=value` or
        // `password: value` in free text — JSON punctuation (`"password":"..."`)
        // may or may not be caught by the free-text path. The test uses a
        // value that is NOT a known prefix (like `sk-`) so redact_secrets
        // would not catch it via prefix matching either.
        let secret_value = "hunter2-not-a-prefix";
        let envelope = json!({
            "session_id": "sess-b6-4",
            "cwd": "/tmp",
            "hook_event_name": "PreToolUse",
            "password": secret_value,
            "nested": { "token": secret_value }
        });
        let raw = envelope.to_string();

        // Verify the secret IS present in the raw string (precondition)
        assert!(
            raw.contains(secret_value),
            "precondition: secret must be in raw JSON"
        );

        // redact_json_value path (B6-4 fix): walks the parsed tree
        let redacted_json = redact_json_value(&envelope);
        let redacted_str = redacted_json.to_string();
        assert!(
            !redacted_str.contains(secret_value),
            "B6-4: redact_json_value must scrub secret under 'password' key, got: {redacted_str}"
        );

        // Verify non-secret fields are preserved
        assert!(
            redacted_str.contains("sess-b6-4"),
            "B6-4: non-secret session_id must be preserved"
        );
        assert!(
            redacted_str.contains("PreToolUse"),
            "B6-4: non-secret hook_event_name must be preserved"
        );
    }

    /// B6-4: malformed (non-JSON) input falls back to `redact_secrets` without
    /// panic — the `map_or_else` fallback preserves existing behavior.
    #[test]
    fn b6_4_non_json_input_falls_back_to_redact_secrets_without_panic() {
        use clx_core::redaction::{redact_json_value, redact_secrets};

        let non_json = "not json at all sk-abc123TOKEN456";
        // The fallback path: parse fails → redact_secrets on raw string
        let result = serde_json::from_str::<serde_json::Value>(non_json).map_or_else(
            |_| redact_secrets(non_json),
            |v| redact_json_value(&v).to_string(),
        );

        // Must not contain the sk- token (redact_secrets prefix match)
        assert!(
            !result.contains("sk-abc123TOKEN456"),
            "B6-4 fallback: sk- token must be redacted by redact_secrets fallback"
        );
        // Must contain the non-secret text
        assert!(
            result.contains("not json at all"),
            "B6-4 fallback: non-secret text must be preserved"
        );
    }
}
