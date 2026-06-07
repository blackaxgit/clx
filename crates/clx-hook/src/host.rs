//! Capability-aware host abstraction.
//!
//! CLX began life as a Claude Code extension. v0.10.0 generalises the hook
//! binary to run under multiple agent hosts (Claude Code, the Codex CLI,
//! Cursor). Each host differs in:
//!
//! - the JSON envelope it hands the hook on stdin (`parse_hook_input`),
//! - the JSON response shape it expects on stdout (`write_decision` /
//!   `write_generic`),
//! - how it surfaces a "needs confirmation" verdict (`ask_channel`),
//! - whether command gating works on the CLI or only the GUI
//!   (`gating_scope`),
//! - how the conversation transcript is stored (`transcript_backend`),
//! - the on-disk paths for global instructions and MCP config,
//! - the env vars that signal a genuine spawn (`provenance_env_vars`) and
//!   the session id (`session_id_env_var`),
//! - the tool names used for file mutation (`is_mutator_tool` /
//!   `canonical_tool_name`).
//!
//! The `Host` trait is the single seam through which all host-specific
//! behaviour is routed. `detect_host` chooses the implementation at the
//! orchestration edge; everything downstream speaks only to `&dyn Host`.
//!
//! Layering: this module is Domain/Mapping. It performs no IO except the
//! caller-supplied `Write` in the output methods. Path construction takes an
//! explicit `home: &Path` so callers stay testable.

use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::Result;
use clx_core::policy::PolicyDecision;

use crate::types::HostNeutralInput;

mod claude;
mod codex;
mod cursor;

pub(crate) use claude::ClaudeHost;
pub(crate) use codex::CodexHost;
pub(crate) use cursor::CursorHost;

/// Which agent host this hook invocation is serving.
///
/// `HostNeutralInput` carries this so downstream code can branch without a
/// second detection pass. Defaults to `Claude` (the historical behaviour and
/// the ambiguous-envelope fallback).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Deserialize, serde::Serialize)]
pub enum HostId {
    /// Anthropic Claude Code (the original, default host).
    #[default]
    Claude,
    /// The Codex CLI (`codex`).
    Codex,
    /// Cursor IDE.
    Cursor,
}

/// Where command gating is enforced for a host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatingScope {
    /// Gating applies to CLI invocations (Claude Code, interactive Codex).
    Cli,
    /// Gating applies only inside the GUI (Cursor); the headless CLI has no
    /// command-validation hook surface.
    GuiOnly,
}

/// How a host persists its conversation transcript.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TranscriptBackend {
    /// JSON-lines file referenced by `transcript_path` (Claude, Codex).
    Jsonl,
    /// `SQLite` database (`state.vscdb`) for Cursor.
    Sqlite,
}

/// How a host surfaces CLX's "needs manual confirmation" (`ask`) verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AskChannel {
    /// Claude: emit `permissionDecision: "ask"` inline in the `PreToolUse`
    /// response.
    InlinePermissionDecision,
    /// Cursor: emit a flat `permission: "ask"` field (GUI prompt).
    FlatPermissionField,
    /// Codex: Codex 0.135.0 does NOT support interactive `ask` from hooks
    /// (per P0 finding F1). CLX maps `ask` to a fail-closed `deny` so an
    /// unconfirmed command is blocked rather than silently allowed.
    FailClosedDeny,
}

/// The capability-aware host abstraction. See module docs.
pub(crate) trait Host: Send + Sync {
    /// Which host this implementation serves.
    fn host_id(&self) -> HostId;

    /// Parse the raw stdin envelope into the host-neutral input shape.
    fn parse_hook_input(&self, raw: &str) -> Result<HostNeutralInput>;

    /// Serialize a permission decision (PreToolUse-style) to `w`.
    ///
    /// `event` is the hook event name, `d` the policy decision, `ctx` the
    /// optional `additionalContext`, `sys` the optional `systemMessage`.
    fn write_decision(
        &self,
        w: &mut dyn Write,
        event: &str,
        d: &PolicyDecision,
        ctx: Option<&str>,
        sys: Option<&str>,
    ) -> Result<()>;

    /// Serialize a generic (no permission decision) response to `w`.
    fn write_generic(
        &self,
        w: &mut dyn Write,
        event: &str,
        ctx: Option<&str>,
        sys: Option<&str>,
    ) -> Result<()>;

    /// How this host surfaces an `ask` verdict.
    fn ask_channel(&self) -> AskChannel;

    /// Where command gating is enforced.
    fn gating_scope(&self) -> GatingScope;

    /// How the transcript is stored.
    fn transcript_backend(&self) -> TranscriptBackend;

    /// Absolute path to the host's global instructions file, if it has one.
    /// `home` is the user's home directory. Returns `None` for hosts with no
    /// global instructions file (Cursor uses project-scoped rules only).
    fn global_instructions_path(&self, home: &Path) -> Option<PathBuf>;

    /// Human-readable label for the instructions file
    /// (`CLAUDE.md` / `AGENTS.md` / `.cursor/rules`).
    fn instructions_file_label(&self) -> &'static str;

    /// Env var names that indicate a genuine host spawn (best-effort
    /// provenance, defense-in-depth only). May be empty.
    fn provenance_env_vars(&self) -> &'static [&'static str];

    /// Env var carrying the host's session id, if any. `None` means the id
    /// is taken from the envelope instead of the environment.
    fn session_id_env_var(&self) -> Option<&'static str>;

    /// Absolute path to the host's MCP config file. `home` is the user's
    /// home directory.
    fn mcp_config_target(&self, home: &Path) -> PathBuf;

    /// Whether `tool` is a file-mutating tool for this host.
    fn is_mutator_tool(&self, tool: &str) -> bool;

    /// Map a host-specific tool name to its canonical CLX name.
    fn canonical_tool_name(&self, tool: &str) -> String;
}

/// Env var that forces a specific host, bypassing envelope sniffing. Accepts
/// `claude` / `codex` / `cursor` (case-insensitive). Unknown values are
/// ignored (fall through to envelope detection).
pub const HOST_OVERRIDE_ENV_VAR: &str = "CLX_HOOK_HOST";

/// Env var Claude Code sets in its own spawned processes. When truthy it forces
/// `HostId::Claude` (after the explicit `CLX_HOOK_HOST` override, before the
/// envelope sniff).
pub const CLAUDECODE_ENV_VAR: &str = "CLAUDECODE";

/// Return `true` when an env value is *truthy*: present, non-empty after
/// trimming, and not a falsy literal (`0`, `false`/`FALSE`/`False`).
fn is_truthy_env(value: Option<&str>) -> bool {
    match value {
        Some(v) => {
            let t = v.trim();
            !t.is_empty() && !matches!(t, "0" | "false" | "FALSE" | "False")
        }
        None => false,
    }
}

/// Detect the host for a raw stdin envelope.
///
/// Resolution order (per spec §1):
/// 1. `CLX_HOOK_HOST` env override (`claude`/`codex`/`cursor`).
/// 2. Envelope shape (Codex/Cursor signatures).
/// 3. Claude (the ambiguous-envelope default).
///
/// The env read is the only process-state touch; it lives here at the
/// orchestration edge so the rest of the pipeline is pure.
pub(crate) fn detect_host(raw: &str) -> Box<dyn Host> {
    let override_var = std::env::var(HOST_OVERRIDE_ENV_VAR).ok();
    let claudecode = is_truthy_env(std::env::var(CLAUDECODE_ENV_VAR).ok().as_deref());
    detect_host_with_override(raw, override_var.as_deref(), claudecode)
}

/// Pure host-detection core: takes the explicit override value and the resolved
/// `CLAUDECODE` truthiness so it can be unit-tested without touching the
/// environment.
pub(crate) fn detect_host_with_override(
    raw: &str,
    override_value: Option<&str>,
    claudecode: bool,
) -> Box<dyn Host> {
    match host_id_for(raw, override_value, claudecode) {
        HostId::Claude => Box::new(ClaudeHost),
        HostId::Codex => Box::new(CodexHost),
        HostId::Cursor => Box::new(CursorHost),
    }
}

/// Pure decision: which `HostId` does this envelope + override + `CLAUDECODE`
/// signal resolve to.
///
/// Precedence: explicit `CLX_HOOK_HOST` override > truthy `CLAUDECODE` >
/// envelope `turn_id`/shape sniff > Claude default.
fn host_id_for(raw: &str, override_value: Option<&str>, claudecode: bool) -> HostId {
    if let Some(forced) = override_value.and_then(parse_host_override) {
        return forced;
    }
    if claudecode {
        return HostId::Claude;
    }
    sniff_envelope(raw)
}

/// Parse a `CLX_HOOK_HOST` value. Unknown / empty values yield `None` so the
/// caller falls through to envelope detection.
fn parse_host_override(value: &str) -> Option<HostId> {
    match value.trim().to_ascii_lowercase().as_str() {
        "claude" => Some(HostId::Claude),
        "codex" => Some(HostId::Codex),
        "cursor" => Some(HostId::Cursor),
        _ => None,
    }
}

/// Sniff the host from the envelope shape. Conservative: only positively
/// identified Codex/Cursor envelopes divert; everything else is Claude.
///
/// Codex envelopes carry Codex-specific keys (`turn_id`, `permission_mode`)
/// alongside the shared Claude-style keys (per P0 finding F4). Cursor
/// `beforeShellExecution` envelopes carry a flat `permission` field and the
/// Cursor-specific `hook_event_name` values. Anything we cannot positively
/// classify is treated as Claude (the historical default).
fn sniff_envelope(raw: &str) -> HostId {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(raw) else {
        return HostId::Claude;
    };
    let Some(obj) = value.as_object() else {
        return HostId::Claude;
    };

    // Cursor: GUI-only events that Claude/Codex never emit.
    if let Some(event) = obj
        .get("hook_event_name")
        .and_then(serde_json::Value::as_str)
        && matches!(event, "beforeShellExecution" | "beforeMCPExecution")
    {
        return HostId::Cursor;
    }

    // Codex: envelope carries the Codex-only `turn_id` key. NOTE: do NOT key on
    // `permission_mode` here - Claude Code ALSO emits a top-level `permission_mode`
    // (default/acceptEdits/plan/bypassPermissions), so matching it misclassified
    // every Claude envelope as Codex, turning `ask` verdicts into Codex
    // fail-closed denies (e.g. `git rm --cached` blocked in Claude Code).
    if obj.contains_key("turn_id") {
        return HostId::Codex;
    }

    HostId::Claude
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claude_envelope() -> String {
        serde_json::json!({
            "session_id": "sess-host-001",
            "cwd": "/tmp/project",
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": { "command": "ls" }
        })
        .to_string()
    }

    #[test]
    fn explicit_claude_envelope_resolves_to_claude() {
        assert_eq!(host_id_for(&claude_envelope(), None, false), HostId::Claude);
    }

    /// Regression: a Claude Code envelope carrying a top-level `permission_mode`
    /// (Claude emits default/acceptEdits/plan/bypassPermissions) must STILL
    /// resolve to Claude - not Codex. Pre-fix this matched the Codex heuristic
    /// and turned `ask` verdicts into Codex fail-closed denies (the reported
    /// `git rm -r --cached .claude/` block in Claude Code).
    #[test]
    fn claude_envelope_with_permission_mode_is_not_codex() {
        let env = serde_json::json!({
            "session_id": "sess-pm",
            "cwd": "/tmp/project",
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "permission_mode": "default",
            "tool_input": { "command": "git rm -r --cached .claude/" }
        })
        .to_string();
        assert_eq!(host_id_for(&env, None, false), HostId::Claude);
    }

    /// A genuine Codex envelope (carries `turn_id`) still resolves to Codex.
    #[test]
    fn codex_envelope_via_turn_id_only_resolves_to_codex() {
        let env = serde_json::json!({
            "session_id": "sess-codex2",
            "cwd": "/tmp/project",
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "turn_id": "turn-9",
            "tool_input": { "command": "echo hi" }
        })
        .to_string();
        assert_eq!(host_id_for(&env, None, false), HostId::Codex);
    }

    #[test]
    fn codex_envelope_resolves_to_codex() {
        let env = serde_json::json!({
            "session_id": "sess-codex",
            "cwd": "/tmp",
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "turn_id": "turn-1",
            "permission_mode": "default",
            "tool_input": { "command": "ls" }
        })
        .to_string();
        assert_eq!(host_id_for(&env, None, false), HostId::Codex);
    }

    #[test]
    fn cursor_before_shell_envelope_resolves_to_cursor() {
        let env = serde_json::json!({
            "session_id": "sess-cursor",
            "cwd": "/tmp",
            "hook_event_name": "beforeShellExecution",
            "command": "ls"
        })
        .to_string();
        assert_eq!(host_id_for(&env, None, false), HostId::Cursor);
    }

    #[test]
    fn env_override_forces_codex_even_for_claude_envelope() {
        assert_eq!(
            host_id_for(&claude_envelope(), Some("codex"), false),
            HostId::Codex
        );
    }

    #[test]
    fn env_override_forces_cursor() {
        assert_eq!(
            host_id_for(&claude_envelope(), Some("CURSOR"), false),
            HostId::Cursor
        );
    }

    #[test]
    fn env_override_is_case_insensitive_and_trimmed() {
        assert_eq!(
            host_id_for(&claude_envelope(), Some("  Claude "), false),
            HostId::Claude
        );
    }

    #[test]
    fn unknown_override_falls_through_to_envelope() {
        // Unknown override + Codex envelope => envelope wins (Codex).
        let env = serde_json::json!({
            "session_id": "s",
            "cwd": "/tmp",
            "hook_event_name": "PreToolUse",
            "turn_id": "t"
        })
        .to_string();
        assert_eq!(host_id_for(&env, Some("bogus"), false), HostId::Codex);
    }

    #[test]
    fn ambiguous_envelope_defaults_to_claude() {
        assert_eq!(host_id_for("not json at all", None, false), HostId::Claude);
        assert_eq!(host_id_for("{}", None, false), HostId::Claude);
    }

    #[test]
    fn detect_host_builds_matching_impl() {
        assert_eq!(
            detect_host_with_override(&claude_envelope(), None, false).host_id(),
            HostId::Claude
        );
        assert_eq!(
            detect_host_with_override(&claude_envelope(), Some("codex"), false).host_id(),
            HostId::Codex
        );
        assert_eq!(
            detect_host_with_override(&claude_envelope(), Some("cursor"), false).host_id(),
            HostId::Cursor
        );
    }

    fn codex_turn_id_envelope() -> String {
        serde_json::json!({
            "session_id": "sess-cc",
            "cwd": "/tmp/project",
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "turn_id": "turn-cc",
            "tool_input": { "command": "ls" }
        })
        .to_string()
    }

    /// AC2.1: truthy `CLAUDECODE` + a `turn_id` envelope -> Claude (CLAUDECODE
    /// wins over the envelope sniff).
    #[test]
    fn claudecode_truthy_overrides_turn_id_sniff() {
        assert_eq!(
            host_id_for(&codex_turn_id_envelope(), None, true),
            HostId::Claude
        );
    }

    /// AC2.2: explicit `CLX_HOOK_HOST=codex` still wins over truthy `CLAUDECODE`.
    #[test]
    fn explicit_override_beats_claudecode() {
        assert_eq!(
            host_id_for(&claude_envelope(), Some("codex"), true),
            HostId::Codex
        );
    }

    /// AC2.3: `CLAUDECODE` falsy/unset + a `turn_id` envelope -> Codex
    /// (unchanged sniff behaviour).
    #[test]
    fn claudecode_falsy_keeps_turn_id_sniff() {
        assert_eq!(
            host_id_for(&codex_turn_id_envelope(), None, false),
            HostId::Codex
        );
    }

    /// AC2.4: no envelope signal and no `CLAUDECODE` -> Claude default.
    #[test]
    fn no_signals_defaults_to_claude() {
        assert_eq!(host_id_for("{}", None, false), HostId::Claude);
    }

    /// The truthy-env helper: present + non-empty(trim) + not a falsy literal.
    #[test]
    fn is_truthy_env_matrix() {
        assert!(is_truthy_env(Some("1")));
        assert!(is_truthy_env(Some("true")));
        assert!(is_truthy_env(Some(" yes ")));
        assert!(!is_truthy_env(None));
        assert!(!is_truthy_env(Some("")));
        assert!(!is_truthy_env(Some("   ")));
        assert!(!is_truthy_env(Some("0")));
        assert!(!is_truthy_env(Some("false")));
        assert!(!is_truthy_env(Some("FALSE")));
        assert!(!is_truthy_env(Some("False")));
    }
}
