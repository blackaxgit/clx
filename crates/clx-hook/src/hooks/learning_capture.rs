//! T4 — opt-in "learning mode" CAPTURE for the `PreToolUse` hook.
//!
//! A single best-effort helper, [`capture`], is invoked beside EVERY final
//! decision emit in `pre_tool_use.rs`. It records a [`LearningEvent`] firehose
//! row when (and only when) `validator.learning_mode` is enabled.
//!
//! Hard constraints (02-learning-spec §C1–C5, 04-plan-review):
//!
//! * **Observe-only (C1):** capture is a pure side-effect added next to the
//!   existing emit. It NEVER changes a decision (allow/ask/deny) or control flow.
//! * **Off = zero cost (C2):** the FIRST thing [`capture`] does is a plain bool
//!   gate on `config.validator.learning_mode`. When off it returns before any
//!   `EffectiveConfig` construction, fingerprint, or `Storage` open — so the
//!   off-path makes no DB write and opens no DB solely for capture. The
//!   `CLX_LEARNING_MODE` env override is already folded into the loaded `config`.
//! * **Best-effort (C3):** every storage error is swallowed; a capture failure
//!   never blocks, delays, or alters a decision.
//! * **No secret leakage (C4):** redaction happens inside
//!   `Storage::record_learning_event` (`build_learning_row` choke-point). Callers
//!   pass raw values; the row is redacted before INSERT.

use std::time::Instant;

use clx_core::config::Config;
use clx_core::storage::Storage;
use clx_core::types::{
    DecisionOrigin, EffectiveConfig, LearningEvent, LearningKind, classify_divergence,
};

use crate::audit::host_id_str;
use crate::host::Host;
use crate::types::HostNeutralInput;

/// Map the live `validator` config onto the fixed 6-field [`EffectiveConfig`]
/// snapshot (enum knobs converted to their stable string form).
///
/// `prompt_sensitivity` uses its `Display` impl; `default_decision` uses its
/// `as_str`; `on_validator_unavailable` has neither, so it is mapped here to a
/// stable lowercase label that matches its serde `rename_all = "lowercase"`.
fn effective_config_from(config: &Config) -> EffectiveConfig {
    use clx_core::config::OnValidatorUnavailable;
    let on_unavailable = match config.validator.on_validator_unavailable {
        OnValidatorUnavailable::Ask => "ask",
        OnValidatorUnavailable::Deny => "deny",
        OnValidatorUnavailable::HonorDefault => "honordefault",
    };
    EffectiveConfig {
        default_decision: config.validator.default_decision.as_str().to_string(),
        prompt_sensitivity: config.validator.prompt_sensitivity.to_string(),
        auto_allow_reads: config.validator.auto_allow_reads,
        layer0_enabled: config.validator.layer0_enabled,
        layer1_enabled: config.validator.layer1_enabled,
        on_validator_unavailable: on_unavailable.to_string(),
    }
}

/// Best-effort capture of one final `PreToolUse` decision as a learning event.
///
/// GATE FIRST: returns immediately when `learning_mode` is off (C2: zero cost,
/// no Storage open). Otherwise builds the [`LearningEvent`], computes the
/// divergence and fingerprint, and persists it via the redacting storage
/// choke-point. All storage errors are swallowed (C3); the decision is never
/// affected (C1).
///
/// Argument provenance:
/// * `latency_ms` = `started.elapsed()` (handler entry → this emit site).
/// * `session_id` from `input` when present (`SessionId` is always set in the
///   host-neutral envelope; an empty id is stored as `None`).
/// * `host` id string from the host adapter (`claude`/`codex`/`cursor`).
#[allow(clippy::too_many_arguments)]
pub(crate) fn capture(
    config: &Config,
    host: &dyn Host,
    input: &HostNeutralInput,
    tool: &str,
    decision: &str,
    layer: &str,
    kind: LearningKind,
    origin: DecisionOrigin,
    matched_rule: Option<String>,
    reason: &str,
    command: Option<&str>,
    started: Instant,
) {
    // GATE FIRST (C2): a single bool check before ANY work. When learning mode
    // is off this is the entire cost of capture — no EffectiveConfig, no
    // fingerprint, no Storage open, no DB write.
    if !config.validator.learning_mode {
        return;
    }

    let effective = effective_config_from(config);
    let policy_fingerprint = effective.fingerprint();
    let effective_config = serde_json::to_string(&effective).unwrap_or_default();

    let divergence_reason = classify_divergence(decision, origin);
    let diverged = divergence_reason.is_some();

    let latency_ms = i64::try_from(started.elapsed().as_millis()).unwrap_or(i64::MAX);

    let session_id = {
        let s = input.session_id.as_str();
        if s.is_empty() {
            None
        } else {
            Some(s.to_string())
        }
    };

    let event = LearningEvent {
        ts: chrono::Utc::now().to_rfc3339(),
        session_id,
        tool: tool.to_string(),
        host: host_id_str(host.host_id()).to_string(),
        decision: decision.to_string(),
        layer: layer.to_string(),
        kind,
        matched_rule,
        reason: reason.to_string(),
        command: command.map(str::to_string),
        effective_config,
        diverged,
        divergence_reason,
        latency_ms: Some(latency_ms),
        policy_fingerprint,
    };

    // Best-effort persist (C3): swallow ALL errors. NEVER alter control flow or
    // the decision. Redaction (C4) happens inside record_learning_event.
    if let Ok(storage) = Storage::open_default() {
        let _ = storage.record_learning_event(&event);
    }
}
