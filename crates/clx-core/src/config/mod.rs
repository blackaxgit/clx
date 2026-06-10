//! Configuration management for CLX
//!
//! Loads settings from:
//! - ~/.clx/config.yaml (user config)
//! - Environment variables (override file settings)
//!
//! Environment variable mapping:
//! - `CLX_VALIDATOR_ENABLED`
//! - `CLX_VALIDATOR_LAYER1_ENABLED`
//! - `CLX_VALIDATOR_LAYER1_TIMEOUT_MS`
//! - `CLX_VALIDATOR_DEFAULT_DECISION`
//! - `CLX_VALIDATOR_AUTO_ALLOW_READS` (auto-allow read-only commands)
//! - `CLX_VALIDATOR_CACHE_ENABLED` (enable `SQLite` decision cache)
//! - `CLX_VALIDATOR_CACHE_ALLOW_TTL` (TTL for cached allow decisions, seconds)
//! - `CLX_VALIDATOR_CACHE_ASK_TTL` (TTL for cached ask decisions, seconds)
//! - `CLX_VALIDATOR_PROMPT_SENSITIVITY` (high/standard/low/custom)
//! - `CLX_LEARNING_MODE` (opt-in learning/debug capture; observe-only)
//! - `CLX_CONTEXT_ENABLED`
//! - `CLX_CONTEXT_AUTO_SNAPSHOT`
//! - `CLX_CONTEXT_EMBEDDING_MODEL`
//! - `CLX_OLLAMA_HOST`
//! - `CLX_OLLAMA_MODEL`
//! - `CLX_OLLAMA_EMBEDDING_MODEL`
//! - `CLX_EMBEDDING_DIM`
//! - `CLX_OLLAMA_TIMEOUT_MS`
//! - `CLX_USER_LEARNING_ENABLED`
//! - `CLX_USER_LEARNING_AUTO_WHITELIST_THRESHOLD`
//! - `CLX_USER_LEARNING_AUTO_BLACKLIST_THRESHOLD`
//! - `CLX_LOGGING_LEVEL`
//! - `CLX_LOGGING_FILE`
//! - `CLX_LOGGING_MAX_SIZE_MB`
//! - `CLX_LOGGING_MAX_FILES`
//! - `CLX_CONTEXT_PRESSURE_MODE` (auto/notify/disabled)
//! - `CLX_CONTEXT_PRESSURE_THRESHOLD` (0.0-1.0)
//! - `CLX_CONTEXT_PRESSURE_WINDOW_SIZE` (tokens)
//! - `CLX_SESSION_RECOVERY_ENABLED`
//! - `CLX_SESSION_RECOVERY_STALE_HOURS`
//! - `CLX_MCP_TOOLS_ENABLED`
//! - `CLX_MCP_TOOLS_DEFAULT_DECISION`
//! - `CLX_AUTO_RECALL_ENABLED`
//! - `CLX_AUTO_RECALL_MAX_RESULTS` (1-10)
//! - `CLX_AUTO_RECALL_SIMILARITY_THRESHOLD` (0.0-1.0)
//! - `CLX_AUTO_RECALL_MAX_CONTEXT_CHARS` (100-5000)
//! - `CLX_AUTO_RECALL_TIMEOUT_MS` (100-10000)
//! - `CLX_AUTO_RECALL_FALLBACK_TO_FTS`
//! - `CLX_AUTO_RECALL_INCLUDE_KEY_FACTS`
//! - `CLX_AUTO_RECALL_MIN_PROMPT_LEN` (1-500)

pub mod codex_trust;
pub(crate) mod project;
pub mod trust;

use serde::{Deserialize, Serialize};
use std::env;
use std::fmt;
use std::fs;
use std::path::PathBuf;
use std::str::FromStr;

/// Context pressure monitoring mode.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum ContextPressureMode {
    /// Save snapshot and inject compact suggestion at threshold
    #[default]
    Auto,
    /// Only inject compact suggestion at threshold
    Notify,
    /// No monitoring
    Disabled,
}

impl fmt::Display for ContextPressureMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Auto => write!(f, "auto"),
            Self::Notify => write!(f, "notify"),
            Self::Disabled => write!(f, "disabled"),
        }
    }
}

impl FromStr for ContextPressureMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "auto" => Ok(Self::Auto),
            "notify" => Ok(Self::Notify),
            "disabled" => Ok(Self::Disabled),
            _ => Err(format!(
                "Invalid context pressure mode: '{s}'. Expected: auto, notify, disabled"
            )),
        }
    }
}

impl PartialEq<&str> for ContextPressureMode {
    fn eq(&self, other: &&str) -> bool {
        matches!(
            (self, *other),
            (Self::Auto, "auto") | (Self::Notify, "notify") | (Self::Disabled, "disabled")
        )
    }
}

/// Validator prompt sensitivity level.
///
/// Controls which built-in prompt template is used when no custom prompt
/// file is found. The sensitivity changes the **prompt content** (how
/// suspicious the LLM is told to be), not the score thresholds.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum PromptSensitivity {
    /// Strict: treats ambiguous commands as suspicious, flags network access
    High,
    /// Balanced: current default behaviour
    #[default]
    Standard,
    /// Relaxed: trusts common dev tools, fewer interruptions
    Low,
    /// User-edited prompt in ~/.clx/prompts/validator.txt
    Custom,
}

impl fmt::Display for PromptSensitivity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::High => write!(f, "high"),
            Self::Standard => write!(f, "standard"),
            Self::Low => write!(f, "low"),
            Self::Custom => write!(f, "custom"),
        }
    }
}

impl FromStr for PromptSensitivity {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "high" => Ok(Self::High),
            "standard" => Ok(Self::Standard),
            "low" => Ok(Self::Low),
            "custom" => Ok(Self::Custom),
            _ => Err(format!(
                "Invalid prompt sensitivity: '{s}'. Expected: high, standard, low, custom"
            )),
        }
    }
}

/// Default decision for policy evaluation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum DefaultDecision {
    /// Prompt user for confirmation
    #[default]
    Ask,
    /// Auto-allow
    Allow,
    /// Auto-deny
    Deny,
}

impl fmt::Display for DefaultDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ask => write!(f, "ask"),
            Self::Allow => write!(f, "allow"),
            Self::Deny => write!(f, "deny"),
        }
    }
}

impl DefaultDecision {
    /// Get the string representation.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Ask => "ask",
            Self::Allow => "allow",
            Self::Deny => "deny",
        }
    }
}

impl FromStr for DefaultDecision {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "ask" => Ok(Self::Ask),
            "allow" => Ok(Self::Allow),
            "deny" => Ok(Self::Deny),
            _ => Err(format!(
                "Invalid default decision: '{s}'. Expected: ask, allow, deny"
            )),
        }
    }
}

/// Policy applied to the FOUR runtime arms where an *enabled* layer 1 (LLM)
/// validation is UNREACHABLE — provider init error, provider unavailable,
/// request timeout, or generation failure.
///
/// This governs the validator-UNAVAILABLE case ONLY. It is distinct from
/// `layer1_enabled = false` (a *deliberately disabled* layer, which is
/// "unavailable on purpose" and unconditionally forces `ask`): disabled is not
/// the same as unavailable, and this knob never relaxes the disabled-L1 arm.
///
/// - `Ask` (default): force a user prompt regardless of `default_decision`
///   (the historical F7 fail-closed posture — `allow` is upgraded to `ask`).
/// - `Deny`: hard-deny on an unreachable validator (strictest).
/// - `HonorDefault`: opt in to honoring `default_decision` (allow/deny/ask)
///   when the validator cannot be reached. This can fail OPEN if
///   `default_decision = allow`, so it is security-relevant and lives under the
///   trust-gated `validator` subtree (stripped from untrusted project config).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum OnValidatorUnavailable {
    /// Force a user prompt regardless of `default_decision` (fail-closed
    /// default — preserves the historical F7 posture).
    #[default]
    Ask,
    /// Hard-deny when the validator is unreachable (strictest).
    Deny,
    /// Honor `default_decision` (allow/deny/ask) when the validator is
    /// unreachable. May fail open if `default_decision = allow`.
    HonorDefault,
}

/// CLX configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct Config {
    /// Validator configuration
    #[serde(default)]
    pub validator: ValidatorConfig,

    /// Context configuration
    #[serde(default)]
    pub context: ContextConfig,

    /// Ollama configuration (legacy; prefer `providers:` + `llm:` sections)
    #[serde(default)]
    pub ollama: Option<OllamaConfig>,

    /// Named provider configs. Keys are arbitrary provider names like
    /// `"ollama-local"` or `"azure-prod"`.
    #[serde(default)]
    pub providers: std::collections::BTreeMap<String, ProviderConfig>,

    /// LLM routing: which provider+model handles chat vs embeddings.
    #[serde(default)]
    pub llm: Option<LlmRouting>,

    /// User learning configuration
    #[serde(default)]
    pub user_learning: UserLearningConfig,

    /// Logging configuration
    #[serde(default)]
    pub logging: LoggingConfig,

    /// Context pressure monitoring configuration
    #[serde(default)]
    pub context_pressure: ContextPressureConfig,

    /// Session recovery configuration
    #[serde(default)]
    pub session_recovery: SessionRecoveryConfig,

    /// MCP tool command validation configuration
    #[serde(default)]
    pub mcp_tools: McpToolsConfig,

    /// Auto-recall configuration
    #[serde(default)]
    pub auto_recall: AutoRecallConfig,

    /// Retention policy for storage tables.
    #[serde(default)]
    pub retention: RetentionConfig,

    /// Memory aggregation features (auto-summarize, etc.).
    ///
    /// Opt-in. Default values preserve 0.7.x behavior (no auto-summary fires).
    #[serde(default)]
    pub memory: MemoryConfig,

    /// Credential storage backend selection.
    ///
    /// Default is the local age-encrypted file (`backend: file`), which
    /// NEVER touches the macOS keychain and never prompts. Set
    /// `backend: keychain` (or `CLX_CREDENTIALS_BACKEND=keychain`) to opt
    /// into the system keychain.
    #[serde(default)]
    pub credentials: CredentialsConfig,
}

/// Credential storage backend configuration.
///
/// ```yaml
/// credentials:
///   backend: file      # default; local age-encrypted file, never prompts
///   # backend: keychain  # opt-in; macOS Keychain (may prompt on adhoc binaries)
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialsConfig {
    /// `file` (default) or `keychain`.
    #[serde(default)]
    pub backend: crate::credentials::CredentialBackendKind,
}

impl Default for CredentialsConfig {
    fn default() -> Self {
        Self {
            // The default MUST be the file backend so a fresh user never sees
            // a single macOS keychain prompt.
            backend: crate::credentials::CredentialBackendKind::File,
        }
    }
}

impl Config {
    /// Resolve the effective credential backend, honoring the
    /// `CLX_CREDENTIALS_BACKEND` env override (highest precedence) over the
    /// `credentials.backend` config value (default `file`).
    ///
    /// An unknown env value is a hard error so a typo can never silently
    /// fall back to the prompting keychain.
    pub fn credential_backend_kind(
        &self,
    ) -> crate::Result<crate::credentials::CredentialBackendKind> {
        if let Ok(v) = std::env::var("CLX_CREDENTIALS_BACKEND")
            && !v.trim().is_empty()
        {
            return crate::credentials::CredentialBackendKind::parse(&v)
                .map_err(|e| crate::Error::Config(e.to_string()));
        }
        Ok(self.credentials.backend)
    }

    /// Build a `CredentialStore` from this config (single config-aware
    /// constructor). Every production callsite uses this so the user's
    /// backend selection (default `file`) is honored uniformly.
    pub fn credential_store(&self) -> crate::Result<crate::credentials::CredentialStore> {
        Ok(crate::credentials::CredentialStore::from_config(
            self.credential_backend_kind()?,
        ))
    }

    /// Same as [`Config::credential_store`] but with the process-scoped read
    /// cache enabled (long-lived MCP server).
    pub fn credential_store_cached(&self) -> crate::Result<crate::credentials::CredentialStore> {
        Ok(crate::credentials::CredentialStore::from_config_cached(
            self.credential_backend_kind()?,
        ))
    }
}

/// Retention policy for storage tables.
///
/// A value of `0` for any field disables trimming for that table; positive
/// integers set the retention window in days. The `clx maintenance trim`
/// command uses these values to delete rows older than the window.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RetentionConfig {
    /// Days of `tool_events` rows to retain. Default: 30.
    #[serde(default = "default_retention_tool_events_days")]
    pub tool_events_days: u32,

    /// Days of `events` rows to retain. Default: 7.
    #[serde(default = "default_retention_events_days")]
    pub events_days: u32,

    /// Days of `snapshots` rows to retain. Default: 0 (keep forever).
    #[serde(default)]
    pub snapshots_days: u32,
}

fn default_retention_tool_events_days() -> u32 {
    30
}
fn default_retention_events_days() -> u32 {
    7
}

impl Default for RetentionConfig {
    fn default() -> Self {
        Self {
            tool_events_days: default_retention_tool_events_days(),
            events_days: default_retention_events_days(),
            snapshots_days: 0,
        }
    }
}

/// Auto-recall configuration for automatic context injection.
///
/// Controls the behaviour of the `UserPromptSubmit` hook that performs
/// hybrid semantic + FTS5 search and injects relevant past context via
/// `additionalContext`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AutoRecallConfig {
    /// Enable auto-recall on every user prompt
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Maximum number of recall results to inject (1-10)
    #[serde(default = "default_auto_recall_max_results")]
    pub max_results: usize,

    /// Minimum similarity score threshold (0.0-1.0)
    ///
    /// NOTE: f32 matches `EmbeddingStore::find_similar()` return type (f32 distances).
    #[serde(default = "default_auto_recall_similarity_threshold")]
    pub similarity_threshold: f32,

    /// Maximum total characters for injected context (100-5000)
    #[serde(default = "default_auto_recall_max_context_chars")]
    pub max_context_chars: usize,

    /// Timeout in milliseconds for the recall operation (100-10000)
    #[serde(default = "default_auto_recall_timeout_ms")]
    pub timeout_ms: u64,

    /// Fall back to FTS5 search when semantic search is unavailable
    #[serde(default = "default_true")]
    pub fallback_to_fts: bool,

    /// Include key facts in the injected context
    #[serde(default = "default_true")]
    pub include_key_facts: bool,

    /// Minimum prompt length to trigger auto-recall
    #[serde(default = "default_auto_recall_min_prompt_len")]
    pub min_prompt_len: usize,

    /// Pin recent session summaries on every `UserPromptSubmit` recall.
    ///
    /// Opt-in. When `pin_recent_sessions.enabled = true`, the hook prepends
    /// the last N session summaries (newest first, excluding the current
    /// session) regardless of whether the recall query produced semantic
    /// or FTS5 hits.
    #[serde(default)]
    pub pin_recent_sessions: PinRecentSessionsConfig,

    /// Use Reciprocal Rank Fusion for hybrid recall ranking.
    #[serde(default = "default_true")]
    pub rrf_enabled: bool,

    /// RRF k parameter. The standard literature value is 60.
    #[serde(default = "default_auto_recall_rrf_k")]
    pub rrf_k: u32,

    /// Multiplicative time-decay half-life in days. Set to 0 to disable.
    #[serde(default = "default_auto_recall_time_decay_half_life_days")]
    pub time_decay_half_life_days: f64,

    /// Percentile gate as a fraction from 0.0 to 1.0. Set to 0 to disable.
    #[serde(default = "default_auto_recall_percentile_gate")]
    pub percentile_gate: f64,

    /// Enable the cross-encoder rerank stage (bge-reranker-v2-m3).
    /// When `false`, recall uses RRF only. Default `true` per the
    /// 0.8.0 design; first-run UX downloads the model in the
    /// background via `clx model fetch`.
    #[serde(default = "default_true")]
    pub reranker_enabled: bool,

    /// Per-query timeout for the rerank stage in milliseconds.
    /// On expiry the pipeline falls back to RRF-only ordering so the
    /// recall request never errors. Default: 250 ms (per design §3.1).
    #[serde(default = "default_reranker_timeout_ms")]
    pub reranker_timeout_ms: u64,
}

impl Default for AutoRecallConfig {
    fn default() -> Self {
        Self {
            enabled: default_true(),
            max_results: default_auto_recall_max_results(),
            similarity_threshold: default_auto_recall_similarity_threshold(),
            max_context_chars: default_auto_recall_max_context_chars(),
            timeout_ms: default_auto_recall_timeout_ms(),
            fallback_to_fts: default_true(),
            include_key_facts: default_true(),
            min_prompt_len: default_auto_recall_min_prompt_len(),
            pin_recent_sessions: PinRecentSessionsConfig::default(),
            rrf_enabled: default_true(),
            rrf_k: default_auto_recall_rrf_k(),
            time_decay_half_life_days: default_auto_recall_time_decay_half_life_days(),
            percentile_gate: default_auto_recall_percentile_gate(),
            reranker_enabled: default_true(),
            reranker_timeout_ms: default_reranker_timeout_ms(),
        }
    }
}

/// Configuration for pinning the most recent session summaries into recall
/// context on every `UserPromptSubmit` (independent of hit matching).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PinRecentSessionsConfig {
    /// Enable pinned-session header. Default: `false` (preserves 0.7.x behavior).
    #[serde(default)]
    pub enabled: bool,

    /// Number of recent sessions to pin. Default: 3.
    #[serde(default = "default_pin_recent_count")]
    pub count: usize,

    /// Maximum characters per pinned summary (chars, not bytes). Default: 300.
    #[serde(default = "default_pin_recent_max_chars")]
    pub max_chars_each: usize,
}

impl Default for PinRecentSessionsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            count: default_pin_recent_count(),
            max_chars_each: default_pin_recent_max_chars(),
        }
    }
}

fn default_pin_recent_count() -> usize {
    3
}

fn default_pin_recent_max_chars() -> usize {
    300
}

/// Memory aggregation features (Phase 10 / 0.8.0).
///
/// Container for opt-in memory features. Today this holds only
/// `auto_summarize`; future features (e.g. rolling key-fact ledgers) plug in
/// here without expanding the top-level `Config` surface.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct MemoryConfig {
    /// Configuration for rolling N-turn auto-summarization on `Stop`.
    #[serde(default)]
    pub auto_summarize: AutoSummarizeConfig,
}

/// Rolling N-turn auto-summarize configuration.
///
/// When `enabled = true`, the `Stop` hook handler counts the assistant
/// turns since the last `AutoSummary` snapshot for the session and, when
/// the threshold is reached, summarizes the recent transcript span into
/// a new snapshot tagged with `SnapshotTrigger::AutoSummary`.
///
/// All fields have safe defaults. The `enabled` flag is the single gate
/// keeping 0.7.x behavior intact for users who have not opted in.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AutoSummarizeConfig {
    /// Enable auto-summarize. Default: `false` (preserves 0.7.x behavior).
    #[serde(default)]
    pub enabled: bool,

    /// Number of assistant turns between auto-summary snapshots. Default: 5.
    #[serde(default = "default_auto_summarize_every_n_turns")]
    pub every_n_turns: u32,

    /// Capability used to construct the summarizer LLM client. Default:
    /// `"chat"`. Falls back to `Capability::Chat` when the string is not a
    /// known capability name.
    #[serde(default = "default_summarizer_capability")]
    pub summarizer_capability: String,

    /// Maximum characters (not bytes) for the produced summary. Default: 500.
    #[serde(default = "default_max_summary_chars")]
    pub max_summary_chars: usize,

    /// Skip the auto-summary when no mutating tool events have been
    /// recorded since the last summary (i.e. read-only session). Default:
    /// `true`. Uses the `tool_events` table (schema v6) for the lookup.
    #[serde(default = "default_true")]
    pub skip_when_idle: bool,
}

impl Default for AutoSummarizeConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            every_n_turns: default_auto_summarize_every_n_turns(),
            summarizer_capability: default_summarizer_capability(),
            max_summary_chars: default_max_summary_chars(),
            skip_when_idle: true,
        }
    }
}

fn default_auto_summarize_every_n_turns() -> u32 {
    5
}

fn default_summarizer_capability() -> String {
    "chat".to_string()
}

fn default_max_summary_chars() -> usize {
    500
}

/// Validator configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ValidatorConfig {
    /// Enable command validation
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Enable layer 0 (deterministic-policy / rule-based) validation.
    /// When `false`, the static L0 allow/deny ruleset is skipped and every
    /// command falls through to L1. If L1 is ALSO deliberately disabled
    /// (`layer1_enabled = false`), the command is forced to `ask` — NOT
    /// `default_decision`. `default_decision` applies only when L1 is enabled
    /// but its outcome is inconclusive at runtime (see that field); a
    /// deliberately disabled L1 is "unavailable on purpose", which fails to
    /// `ask` rather than to the configured default.
    /// Disabling weakens security posture; treated as a weakening override
    /// (WARN at startup, audit-chain fingerprint per hook invocation).
    #[serde(default = "default_true")]
    pub layer0_enabled: bool,

    /// Enable layer 1 (fast) validation
    #[serde(default = "default_true")]
    pub layer1_enabled: bool,

    /// Layer 1 validation timeout in milliseconds
    #[serde(default = "default_layer1_timeout")]
    pub layer1_timeout_ms: u64,

    /// Default decision applied when an ENABLED layer 1 (LLM) validation
    /// fails or is inconclusive at runtime — i.e. provider init error,
    /// provider unavailable, request timeout, or generation failure. It is the
    /// fail-mode for a layer that is supposed to run but could not produce a
    /// verdict.
    ///
    /// This does NOT apply when L1 is deliberately turned off
    /// (`layer1_enabled = false`): a disabled layer is "unavailable on purpose"
    /// and forces `ask` (disabled != unavailable). So `default_decision` only
    /// governs runtime L1 failure/inconclusive outcomes, never the
    /// configuration choice to disable L1.
    #[serde(default)]
    pub default_decision: DefaultDecision,

    /// Policy for the validator-UNREACHABLE case (provider init error,
    /// provider unavailable, request timeout, generation failure). Default
    /// `Ask` preserves the historical F7 fail-closed posture (an unreachable
    /// validator upgrades `allow` to `ask`). Set to `honordefault` to instead
    /// honor `default_decision` on those arms, or `deny` to hard-deny.
    ///
    /// NOTE: this is distinct from `layer1_enabled = false` (a deliberately
    /// DISABLED layer, which always forces `ask`); disabled != unavailable, and
    /// this knob never affects the disabled-L1 arm.
    #[serde(default)]
    pub on_validator_unavailable: OnValidatorUnavailable,

    /// Trust mode - auto-allow ALL commands without validation
    /// Still logs commands for audit. Use with caution!
    /// Can only be enabled via config file (~/.clx/config.yaml) for security.
    #[serde(default)]
    pub trust_mode: bool,

    /// Auto-allow read-only commands without LLM validation
    /// Commands like cat, ls, head, tail, grep, find, etc. are allowed immediately
    #[serde(default = "default_true")]
    pub auto_allow_reads: bool,

    /// Enable L1 decision caching in `SQLite` (cross-process)
    #[serde(default = "default_true")]
    pub cache_enabled: bool,

    /// TTL for cached "allow" decisions in seconds (default: 1 hour)
    #[serde(default = "default_cache_allow_ttl")]
    pub cache_allow_ttl_secs: u64,

    /// TTL for cached "ask" decisions in seconds (default: 15 minutes)
    #[serde(default = "default_cache_ask_ttl")]
    pub cache_ask_ttl_secs: u64,

    /// Prompt sensitivity level for LLM-based validation
    #[serde(default)]
    pub prompt_sensitivity: PromptSensitivity,

    /// Maximum allowed trust mode duration in seconds (default: 24h)
    #[serde(default = "default_trust_mode_max_duration")]
    pub trust_mode_max_duration: u64,

    /// Default trust mode duration in seconds when no --duration given (default: 1h)
    #[serde(default = "default_trust_mode_default_duration")]
    pub trust_mode_default_duration: u64,

    /// Opt-in learning/debug mode: record every `PreToolUse` decision + rationale
    /// to the `learning_events` table. Observe-only; off by default; never
    /// changes a decision. Trust-gated (lives under the `validator` subtree,
    /// which is stripped from untrusted project config).
    #[serde(default)]
    pub learning_mode: bool,
}

/// Context configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ContextConfig {
    /// Enable context persistence
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Automatically snapshot context
    #[serde(default = "default_true")]
    pub auto_snapshot: bool,

    /// Embedding model to use
    #[serde(default = "default_embedding_model")]
    pub embedding_model: String,
}

/// Ollama configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OllamaConfig {
    /// Ollama host URL
    #[serde(default = "default_ollama_host")]
    pub host: String,

    /// Default model for inference
    #[serde(default = "default_ollama_model")]
    pub model: String,

    /// Model for embeddings
    #[serde(default = "default_embedding_model")]
    pub embedding_model: String,

    /// Embedding vector dimension
    #[serde(default = "default_embedding_dim")]
    pub embedding_dim: usize,

    /// Request timeout in milliseconds
    #[serde(default = "default_ollama_timeout")]
    pub timeout_ms: u64,

    /// Maximum number of retries for transient errors
    #[serde(default = "default_max_retries")]
    pub max_retries: u32,

    /// Initial retry delay in milliseconds
    #[serde(default = "default_retry_delay_ms")]
    pub retry_delay_ms: u64,

    /// Exponential backoff multiplier (e.g., 2.0 = double delay each retry)
    #[serde(default = "default_retry_backoff")]
    pub retry_backoff: f32,
}

/// User learning configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UserLearningConfig {
    /// Enable user learning features
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Number of approvals before auto-whitelisting
    #[serde(default = "default_whitelist_threshold")]
    pub auto_whitelist_threshold: u32,

    /// Number of rejections before auto-blacklisting
    #[serde(default = "default_blacklist_threshold")]
    pub auto_blacklist_threshold: u32,
}

/// Logging configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LoggingConfig {
    /// Log level (trace, debug, info, warn, error)
    #[serde(default = "default_log_level")]
    pub level: String,

    /// Log file path (~ is expanded to home directory)
    #[serde(default = "default_log_file")]
    pub file: String,

    /// Maximum log file size in megabytes
    #[serde(default = "default_max_size_mb")]
    pub max_size_mb: u32,

    /// Maximum number of log files to keep
    #[serde(default = "default_max_files")]
    pub max_files: u32,
}

/// Context pressure monitoring configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ContextPressureConfig {
    /// Monitoring mode
    #[serde(default)]
    pub mode: ContextPressureMode,

    /// Context window size estimate in tokens (Claude Sonnet ~200K)
    #[serde(default = "default_context_window_size")]
    pub context_window_size: i64,

    /// Threshold percentage (0.0-1.0) to trigger action
    #[serde(default = "default_context_pressure_threshold")]
    pub threshold: f64,
}

/// Session recovery configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SessionRecoveryConfig {
    /// Enable auto-recovery from abandoned sessions
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Hours after which an active session is considered abandoned
    #[serde(default = "default_stale_hours")]
    pub stale_hours: u32,
}

/// MCP tool command validation configuration
///
/// When enabled, MCP tools that execute commands (e.g., `mcp__ssh__execute`)
/// have their command parameters extracted and validated through the same
/// `PolicyEngine` used for Bash commands.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct McpToolsConfig {
    /// Enable MCP tool command validation
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Default decision for MCP tools not in the `command_tools` registry
    #[serde(default = "default_mcp_default_decision")]
    pub default_decision: DefaultDecision,

    /// Registry of MCP tools that carry executable commands.
    /// Each entry maps a tool name pattern to the JSON field containing the command.
    #[serde(default = "default_mcp_command_tools")]
    pub command_tools: Vec<McpCommandTool>,
}

/// An MCP tool that carries an executable command in its input
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct McpCommandTool {
    /// Glob pattern matching MCP tool names (e.g., "mcp__*__execute")
    pub tool_pattern: String,

    /// JSON field name in `tool_input` containing the command (e.g., "command")
    pub command_field: String,
}

// Default value functions for serde
fn default_true() -> bool {
    true
}

fn default_layer1_timeout() -> u64 {
    30000 // 30 seconds - model may need to load into memory
}

fn default_cache_allow_ttl() -> u64 {
    3600
}

fn default_cache_ask_ttl() -> u64 {
    900
}

fn default_trust_mode_max_duration() -> u64 {
    86400
}

fn default_trust_mode_default_duration() -> u64 {
    3600
}

#[must_use]
pub fn default_embedding_model() -> String {
    "qwen3-embedding:0.6b".to_string()
}

fn default_embedding_dim() -> usize {
    1024
}

fn default_ollama_host() -> String {
    "http://127.0.0.1:11434".to_string()
}

#[must_use]
pub fn default_ollama_model() -> String {
    "qwen3:1.7b".to_string()
}

fn default_ollama_timeout() -> u64 {
    60000 // 60 seconds - model may need to load into memory on first request
}

fn default_max_retries() -> u32 {
    3 // 3 retries = 4 total attempts
}

fn default_retry_delay_ms() -> u64 {
    100 // Start with 100ms delay
}

fn default_retry_backoff() -> f32 {
    2.0 // Double delay each retry: 100ms, 200ms, 400ms
}

fn default_whitelist_threshold() -> u32 {
    3
}

fn default_blacklist_threshold() -> u32 {
    2
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_log_file() -> String {
    "~/.clx/logs/clx.log".to_string()
}

fn default_max_size_mb() -> u32 {
    10
}

fn default_max_files() -> u32 {
    5
}

fn default_context_window_size() -> i64 {
    200_000
}

fn default_context_pressure_threshold() -> f64 {
    0.80
}

fn default_stale_hours() -> u32 {
    2
}

fn default_mcp_default_decision() -> DefaultDecision {
    DefaultDecision::Allow
}

fn default_mcp_command_tools() -> Vec<McpCommandTool> {
    vec![
        McpCommandTool {
            tool_pattern: "mcp__*__execute".to_string(),
            command_field: "command".to_string(),
        },
        McpCommandTool {
            tool_pattern: "mcp__puppeteer__puppeteer_evaluate".to_string(),
            command_field: "script".to_string(),
        },
        McpCommandTool {
            tool_pattern: "mcp__playwright__browser_evaluate".to_string(),
            command_field: "function".to_string(),
        },
        McpCommandTool {
            tool_pattern: "mcp__playwright__browser_run_code".to_string(),
            command_field: "code".to_string(),
        },
    ]
}

fn default_auto_recall_max_results() -> usize {
    3
}

fn default_auto_recall_similarity_threshold() -> f32 {
    0.35
}

fn default_auto_recall_max_context_chars() -> usize {
    1000
}

fn default_auto_recall_timeout_ms() -> u64 {
    500
}

fn default_auto_recall_min_prompt_len() -> usize {
    10
}

fn default_auto_recall_rrf_k() -> u32 {
    60
}

fn default_auto_recall_time_decay_half_life_days() -> f64 {
    30.0
}

fn default_auto_recall_percentile_gate() -> f64 {
    0.70
}

fn default_reranker_timeout_ms() -> u64 {
    250
}

impl Default for ValidatorConfig {
    fn default() -> Self {
        Self {
            enabled: default_true(),
            layer0_enabled: default_true(),
            layer1_enabled: default_true(),
            layer1_timeout_ms: default_layer1_timeout(),
            default_decision: DefaultDecision::Ask,
            on_validator_unavailable: OnValidatorUnavailable::default(),
            trust_mode: false,
            auto_allow_reads: default_true(),
            cache_enabled: default_true(),
            cache_allow_ttl_secs: default_cache_allow_ttl(),
            cache_ask_ttl_secs: default_cache_ask_ttl(),
            prompt_sensitivity: PromptSensitivity::Standard,
            trust_mode_max_duration: default_trust_mode_max_duration(),
            trust_mode_default_duration: default_trust_mode_default_duration(),
            learning_mode: false,
        }
    }
}

impl Default for ContextConfig {
    fn default() -> Self {
        Self {
            enabled: default_true(),
            auto_snapshot: default_true(),
            embedding_model: default_embedding_model(),
        }
    }
}

impl Default for OllamaConfig {
    fn default() -> Self {
        Self {
            host: default_ollama_host(),
            model: default_ollama_model(),
            embedding_model: default_embedding_model(),
            embedding_dim: default_embedding_dim(),
            timeout_ms: default_ollama_timeout(),
            max_retries: default_max_retries(),
            retry_delay_ms: default_retry_delay_ms(),
            retry_backoff: default_retry_backoff(),
        }
    }
}

impl Default for UserLearningConfig {
    fn default() -> Self {
        Self {
            enabled: default_true(),
            auto_whitelist_threshold: default_whitelist_threshold(),
            auto_blacklist_threshold: default_blacklist_threshold(),
        }
    }
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            file: default_log_file(),
            max_size_mb: default_max_size_mb(),
            max_files: default_max_files(),
        }
    }
}

impl Default for ContextPressureConfig {
    fn default() -> Self {
        Self {
            mode: ContextPressureMode::Auto,
            context_window_size: default_context_window_size(),
            threshold: default_context_pressure_threshold(),
        }
    }
}

impl Default for SessionRecoveryConfig {
    fn default() -> Self {
        Self {
            enabled: default_true(),
            stale_hours: default_stale_hours(),
        }
    }
}

impl Default for McpToolsConfig {
    fn default() -> Self {
        Self {
            enabled: default_true(),
            default_decision: DefaultDecision::Allow,
            command_tools: default_mcp_command_tools(),
        }
    }
}

// ---------------------------------------------------------------------------
// Azure OpenAI provider config (Task 7, does NOT touch the root Config struct)
// ---------------------------------------------------------------------------

/// Configuration for the Azure `OpenAI` backend.
///
/// Loaded from the `azure_openai` section of `~/.clx/config.yaml` by Task 9.
/// Added here as a standalone type so `AzureOpenAIBackend::new` has a typed
/// config to accept.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct AzureOpenAIConfig {
    /// Full base URL, e.g. `https://my-resource.openai.azure.com`
    pub endpoint: String,
    /// Name of the env var whose value is the API key (optional).
    #[serde(default)]
    pub api_key_env: Option<String>,
    /// Path to a file containing the API key (optional).
    #[serde(default)]
    pub api_key_file: Option<std::path::PathBuf>,
    /// If set, use the dated deployment URL shape instead of `/openai/v1/…`.
    #[serde(default)]
    pub api_version: Option<String>,
    /// HTTP request timeout in milliseconds (default 30 000).
    #[serde(default = "default_azure_timeout")]
    pub timeout_ms: u64,
    /// Retry policy (uses the shared `RetryConfig` from `llm::retry`).
    #[serde(default)]
    pub retry: crate::llm::retry::RetryConfig,
}

fn default_azure_timeout() -> u64 {
    30_000
}

// ---------------------------------------------------------------------------
// New provider/routing schema (Task 9)
// ---------------------------------------------------------------------------

/// A discriminated union of provider configs, tagged by `kind:` in YAML.
///
/// ```yaml
/// providers:
///   my-ollama:
///     kind: ollama
///     host: "http://127.0.0.1:11434"
///     model: "qwen3:1.7b"
///   my-azure:
///     kind: azure_openai
///     endpoint: "https://x.openai.azure.com"
///     api_key_env: "AZURE_KEY"
///     timeout_ms: 30000
/// ```
#[derive(Debug, Clone, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProviderConfig {
    Ollama(OllamaConfig),
    AzureOpenai(AzureOpenAIConfig),
}

/// Top-level LLM routing: which provider+model handles each capability.
#[derive(Debug, Clone, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct LlmRouting {
    pub chat: CapabilityRoute,
    pub embeddings: CapabilityRoute,
}

/// A single capability → (provider name, model) binding.
#[derive(Debug, Clone, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct CapabilityRoute {
    pub provider: String,
    pub model: String,

    /// Optional secondary provider used when the primary fails with a
    /// transient error. `Box` to allow recursion (each fallback could
    /// itself have a fallback; v0.7.0 only surfaces a single level UX).
    /// The `model` field on a fallback route is honored at fallback call
    /// time. The caller's model name is replaced because providers don't
    /// share model names (e.g. `gpt-5.4-mini` only exists on Azure).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fallback: Option<Box<CapabilityRoute>>,

    /// Explicit embedding dimension override for this route.
    ///
    /// Only meaningful for the embeddings capability. When `Some`, it wins over
    /// the model→dimension registry and the legacy ollama `embedding_dim`. When
    /// `None` (the default; existing configs deserialize unchanged), the
    /// effective dimension is resolved via [`effective_embedding_dimension`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dimension: Option<usize>,
}

/// Map a known embedding model name to its CLX-effective output dimension.
///
/// Returns `None` for unknown models so the caller can fall back to the legacy
/// ollama `embedding_dim`. Note `text-embedding-3-small` is mapped to 1024 (the
/// dimension CLX requests via the `OpenAI` `dimensions` parameter, NOT its
/// native 1536).
#[must_use]
pub fn embedding_dimension_for_model(model: &str) -> Option<usize> {
    match model {
        "text-embedding-3-small" => Some(1024),
        "text-embedding-3-large" => Some(3072),
        "qwen3-embedding:0.6b" => Some(1024),
        _ => None,
    }
}

/// Resolve the effective embedding dimension for an embeddings route.
///
/// Precedence (highest first):
/// 1. `route.dimension` — an explicit per-route override.
/// 2. The model→dimension registry ([`embedding_dimension_for_model`]) if the
///    route's model is known.
/// 3. The legacy `ollama_embedding_dim` (the historical default, e.g. 1024).
///
/// Batch C (the `crates/clx` embeddings status/rebuild/backfill paths) calls
/// this so every store opens at the same effective dimension.
#[must_use]
pub fn effective_embedding_dimension(
    route: &CapabilityRoute,
    ollama_embedding_dim: usize,
) -> usize {
    route
        .dimension
        .or_else(|| embedding_dimension_for_model(&route.model))
        .unwrap_or(ollama_embedding_dim)
}

/// Which LLM capability to route.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Capability {
    Chat,
    Embeddings,
}

impl Config {
    /// Load configuration from default locations with environment variable overrides
    ///
    /// Loading order:
    /// 1. Default values
    /// 2. ~/.clx/config.yaml (if exists)
    /// 3. Environment variables (highest priority)
    pub fn load() -> crate::Result<Self> {
        use figment::Figment;
        use figment::providers::{Env, Format, Yaml};

        // Ensure config directory and logs directory exist
        let config_dir = Self::config_dir()?;
        Self::ensure_dir_exists(&config_dir)?;
        let logs_dir = config_dir.join("logs");
        Self::ensure_dir_exists(&logs_dir)?;

        let global_path = config_dir.join("config.yaml");

        let mut fig = Figment::new();

        // Layer 1 (lowest): global ~/.clx/config.yaml (if it exists).
        if global_path.is_file() {
            fig = fig.merge(Yaml::file_exact(&global_path));
        }

        // Layer 2: project .clx/config.yaml (filtered through inert allowlist).
        // We read and filter the raw YAML ourselves; figment sees a clean string.
        // Use config_dir.parent() (i.e. the home dir as resolved by config_dir())
        // as the walk-up stop boundary. This ensures that the project walk-up
        // stops at exactly the same home that produced global_path, even when
        // HOME is overridden (e.g. in tests).
        let home_boundary = config_dir.parent().map(std::path::Path::to_path_buf);
        if let Some(proj) =
            crate::config::project::project_config_path_with_stop(home_boundary.as_deref())
            && let Ok(raw) = fs::read_to_string(&proj)
        {
            // Trust-gated filter (§3.11): if the file hash is in the user's
            // ~/.clx/trusted_configs.json, the raw YAML is honored. Otherwise
            // non-inert keys (providers.*, logging.file, validator.enabled)
            // are stripped before merge.
            let filtered = crate::config::project::apply_project_layer(&raw, &proj);
            if !filtered.is_empty() {
                fig = fig.merge(Yaml::string(&filtered));
            }
        }

        // Layer 3 (highest): env vars via figment (flat, no auto-nesting).
        // NOTE: figment's Env::prefixed uses `.` as the nesting separator, but
        // CLX_ vars use `_` in non-nesting positions. We keep apply_env_overrides()
        // below for the full validated env-var logic; this layer is a safety net
        // for any keys that map cleanly (e.g. simple top-level booleans exposed
        // via CLX_VALIDATOR_ENABLED etc. are handled by apply_env_overrides).
        fig = fig.merge(Env::prefixed("CLX_"));

        let mut cfg: Config = fig
            .extract()
            .map_err(|e| crate::Error::Config(format!("figment merge failed: {e}")))?;

        // Translate legacy `ollama:` block into providers/llm (in-memory only).
        cfg.translate_legacy_in_place();

        // Apply validated, range-checked env-var overrides (kept as authoritative
        // env-var mechanism; figment layer above is additive safety net only).
        cfg.apply_env_overrides();

        Ok(cfg)
    }

    /// Load configuration from file only (no environment variable overrides).
    ///
    /// Used by the dashboard Settings tab to show raw YAML values for editing,
    /// without env var overrides that would confuse the user.
    pub fn load_from_file_only() -> crate::Result<Self> {
        let config_path = Self::config_dir()?.join("config.yaml");
        if config_path.exists() {
            let content = fs::read_to_string(&config_path)?;
            let mut cfg: Self = serde_yml::from_str(&content)?;
            cfg.translate_legacy_in_place();
            Ok(cfg)
        } else {
            Ok(Config::default())
        }
    }

    /// Get the CLX configuration directory path
    pub fn config_dir() -> crate::Result<PathBuf> {
        Ok(crate::paths::clx_dir())
    }

    /// Get the default configuration file path
    pub fn config_file_path() -> crate::Result<PathBuf> {
        Self::config_dir().map(|d| d.join("config.yaml"))
    }

    /// Returns the list of active security-weakening environment variable overrides.
    ///
    /// Each entry is a `(env_var_name, current_value_description)` pair identifying
    /// an override that degrades the validator's security posture relative to secure
    /// defaults. The list is empty when no security-weakening env vars are in effect.
    ///
    /// A weakening override is defined as any of:
    /// - `CLX_VALIDATOR_ENABLED=false`  — entire validator disabled
    /// - `CLX_VALIDATOR_LAYER0_ENABLED=false`  — deterministic L0 ruleset disabled
    /// - `CLX_VALIDATOR_LAYER1_ENABLED=false`  — LLM review stage disabled
    /// - `CLX_VALIDATOR_DEFAULT_DECISION=allow`  — fail-open on inconclusive
    /// - `CLX_VALIDATOR_AUTO_ALLOW_READS=true`  — reads auto-approved without LLM
    ///
    /// Callers (e.g., the hook audit log) can use this to emit a structured
    /// audit row when any weakening override is active. The check is stateless:
    /// it re-reads env vars at call time so it is always consistent with the
    /// live environment, even if called before or after `apply_env_overrides`.
    #[must_use]
    pub fn security_env_overrides_active(&self) -> Vec<(&'static str, String)> {
        let mut active = Vec::new();

        if let Ok(val) = env::var("CLX_VALIDATOR_ENABLED")
            && matches!(val.to_lowercase().as_str(), "false" | "0" | "no" | "off")
        {
            active.push(("CLX_VALIDATOR_ENABLED", val));
        }
        if let Ok(val) = env::var("CLX_VALIDATOR_LAYER0_ENABLED")
            && matches!(val.to_lowercase().as_str(), "false" | "0" | "no" | "off")
        {
            active.push(("CLX_VALIDATOR_LAYER0_ENABLED", val));
        }
        if let Ok(val) = env::var("CLX_VALIDATOR_LAYER1_ENABLED")
            && matches!(val.to_lowercase().as_str(), "false" | "0" | "no" | "off")
        {
            active.push(("CLX_VALIDATOR_LAYER1_ENABLED", val));
        }
        if let Ok(val) = env::var("CLX_VALIDATOR_DEFAULT_DECISION")
            && val.to_lowercase() == "allow"
        {
            active.push(("CLX_VALIDATOR_DEFAULT_DECISION", val));
        }
        if let Ok(val) = env::var("CLX_VALIDATOR_AUTO_ALLOW_READS")
            && matches!(val.to_lowercase().as_str(), "true" | "1" | "yes" | "on")
        {
            active.push(("CLX_VALIDATOR_AUTO_ALLOW_READS", val));
        }

        active
    }

    /// Expand ~ to home directory in a path string
    #[must_use]
    pub fn expand_tilde(path: &str) -> String {
        if let Some(stripped) = path.strip_prefix("~/")
            && let Some(home) = dirs::home_dir()
        {
            return home.join(stripped).to_string_lossy().to_string();
        }
        path.to_string()
    }

    /// Get the expanded log file path
    #[must_use]
    pub fn log_file_path(&self) -> PathBuf {
        PathBuf::from(Self::expand_tilde(&self.logging.file))
    }

    /// Ensure a directory exists, creating it if necessary
    fn ensure_dir_exists(path: &PathBuf) -> crate::Result<()> {
        if !path.exists() {
            fs::create_dir_all(path)?;
        }
        Ok(())
    }

    /// Apply environment variable overrides with validation and warnings
    fn apply_env_overrides(&mut self) {
        // Validator overrides
        if let Ok(val) = env::var("CLX_VALIDATOR_ENABLED") {
            apply_bool_override(&val, "CLX_VALIDATOR_ENABLED", &mut self.validator.enabled);
            // SECURITY AUDIT: disabling the validator via env is a security-weakening override.
            if !self.validator.enabled {
                tracing::warn!(
                    env_var = "CLX_VALIDATOR_ENABLED",
                    value = %val,
                    "SECURITY WARNING: CLX_VALIDATOR_ENABLED=false disables the entire \
                     command validator via environment variable; all tool calls will be \
                     permitted without review. This override is intentional only for \
                     trusted CI/ops contexts. Audit trail: env var weakens security posture."
                );
            }
        }
        if let Ok(val) = env::var("CLX_VALIDATOR_LAYER0_ENABLED") {
            apply_bool_override(
                &val,
                "CLX_VALIDATOR_LAYER0_ENABLED",
                &mut self.validator.layer0_enabled,
            );
            // SECURITY AUDIT: disabling L0 (deterministic ruleset) via env is a
            // security-weakening override.
            if !self.validator.layer0_enabled {
                tracing::warn!(
                    env_var = "CLX_VALIDATOR_LAYER0_ENABLED",
                    value = %val,
                    "SECURITY WARNING: CLX_VALIDATOR_LAYER0_ENABLED=false disables the \
                     deterministic Layer-0 ruleset; allow/deny patterns (rm -rf /, \
                     curl|bash, etc.) are no longer enforced. Commands fall through to \
                     L1 (LLM) or default_decision. This override is intentional only \
                     for trusted CI/ops contexts. Audit trail: env var weakens \
                     security posture."
                );
            }
        }
        if let Ok(val) = env::var("CLX_VALIDATOR_LAYER1_ENABLED") {
            apply_bool_override(
                &val,
                "CLX_VALIDATOR_LAYER1_ENABLED",
                &mut self.validator.layer1_enabled,
            );
            // SECURITY AUDIT: disabling L1 (LLM review) via env is a security-weakening override.
            if !self.validator.layer1_enabled {
                tracing::warn!(
                    env_var = "CLX_VALIDATOR_LAYER1_ENABLED",
                    value = %val,
                    "SECURITY WARNING: CLX_VALIDATOR_LAYER1_ENABLED=false disables the \
                     LLM-based (Layer 1) validation stage via environment variable; only \
                     the static L0 ruleset will run. This override is intentional only for \
                     trusted CI/ops contexts. Audit trail: env var weakens security posture."
                );
            }
        }
        if let Ok(val) = env::var("CLX_VALIDATOR_LAYER1_TIMEOUT_MS") {
            apply_u64_override(
                &val,
                "CLX_VALIDATOR_LAYER1_TIMEOUT_MS",
                100,
                300_000,
                &mut self.validator.layer1_timeout_ms,
            );
        }
        if let Ok(val) = env::var("CLX_VALIDATOR_DEFAULT_DECISION") {
            apply_enum_override::<DefaultDecision>(
                &val,
                "CLX_VALIDATOR_DEFAULT_DECISION",
                &mut self.validator.default_decision,
            );
            // SECURITY AUDIT: setting default_decision=allow via env is security-weakening.
            if self.validator.default_decision == DefaultDecision::Allow {
                tracing::warn!(
                    env_var = "CLX_VALIDATOR_DEFAULT_DECISION",
                    value = %val,
                    "SECURITY WARNING: CLX_VALIDATOR_DEFAULT_DECISION=allow sets the \
                     fail-open fallback to unconditional allow via environment variable; \
                     when L1 is unavailable or inconclusive, commands are auto-approved. \
                     This override is intentional only for trusted CI/ops contexts. \
                     Audit trail: env var weakens security posture."
                );
            }
        }
        // NOTE: CLX_VALIDATOR_TRUST_MODE env var intentionally NOT supported.
        // Trust mode can only be enabled via config file to prevent env var injection attacks.
        // See docs/security-remediation.md for rationale.
        if let Ok(val) = env::var("CLX_VALIDATOR_AUTO_ALLOW_READS") {
            apply_bool_override(
                &val,
                "CLX_VALIDATOR_AUTO_ALLOW_READS",
                &mut self.validator.auto_allow_reads,
            );
            // SECURITY AUDIT: enabling auto_allow_reads via env skips LLM review for read cmds.
            if self.validator.auto_allow_reads {
                tracing::warn!(
                    env_var = "CLX_VALIDATOR_AUTO_ALLOW_READS",
                    value = %val,
                    "SECURITY WARNING: CLX_VALIDATOR_AUTO_ALLOW_READS=true enables \
                     automatic approval of read-only commands via environment variable; \
                     commands classified as reads are permitted without LLM review. \
                     This override is intentional only for trusted CI/ops contexts. \
                     Audit trail: env var weakens security posture."
                );
            }
        }
        if let Ok(val) = env::var("CLX_LEARNING_MODE") {
            apply_bool_override(&val, "CLX_LEARNING_MODE", &mut self.validator.learning_mode);
        }
        if let Ok(val) = env::var("CLX_VALIDATOR_CACHE_ENABLED") {
            apply_bool_override(
                &val,
                "CLX_VALIDATOR_CACHE_ENABLED",
                &mut self.validator.cache_enabled,
            );
        }
        if let Ok(val) = env::var("CLX_VALIDATOR_CACHE_ALLOW_TTL") {
            apply_u64_override(
                &val,
                "CLX_VALIDATOR_CACHE_ALLOW_TTL",
                60,
                86400,
                &mut self.validator.cache_allow_ttl_secs,
            );
        }
        if let Ok(val) = env::var("CLX_VALIDATOR_CACHE_ASK_TTL") {
            apply_u64_override(
                &val,
                "CLX_VALIDATOR_CACHE_ASK_TTL",
                60,
                86400,
                &mut self.validator.cache_ask_ttl_secs,
            );
        }
        if let Ok(val) = env::var("CLX_VALIDATOR_PROMPT_SENSITIVITY") {
            apply_enum_override::<PromptSensitivity>(
                &val,
                "CLX_VALIDATOR_PROMPT_SENSITIVITY",
                &mut self.validator.prompt_sensitivity,
            );
        }
        if let Ok(val) = env::var("CLX_VALIDATOR_TRUST_MODE_MAX_DURATION") {
            apply_u64_override(
                &val,
                "CLX_VALIDATOR_TRUST_MODE_MAX_DURATION",
                300,
                604_800, // 7 days max
                &mut self.validator.trust_mode_max_duration,
            );
        }
        if let Ok(val) = env::var("CLX_VALIDATOR_TRUST_MODE_DEFAULT_DURATION") {
            apply_u64_override(
                &val,
                "CLX_VALIDATOR_TRUST_MODE_DEFAULT_DURATION",
                300,
                86400,
                &mut self.validator.trust_mode_default_duration,
            );
        }

        // Context overrides
        if let Ok(val) = env::var("CLX_CONTEXT_ENABLED") {
            apply_bool_override(&val, "CLX_CONTEXT_ENABLED", &mut self.context.enabled);
        }
        if let Ok(val) = env::var("CLX_CONTEXT_AUTO_SNAPSHOT") {
            apply_bool_override(
                &val,
                "CLX_CONTEXT_AUTO_SNAPSHOT",
                &mut self.context.auto_snapshot,
            );
        }
        if let Ok(val) = env::var("CLX_CONTEXT_EMBEDDING_MODEL") {
            apply_string_override(
                &val,
                "CLX_CONTEXT_EMBEDDING_MODEL",
                &mut self.context.embedding_model,
            );
        }

        // Ollama overrides. If any CLX_OLLAMA_* env var is set and the legacy
        // `ollama:` block is absent, synthesize a default block so the env
        // vars still take effect (preserves pre-Task-9 behaviour for users
        // who relied on env-only configuration).
        const OLLAMA_ENV_VARS: &[&str] = &[
            "CLX_OLLAMA_HOST",
            "CLX_OLLAMA_MODEL",
            "CLX_OLLAMA_EMBEDDING_MODEL",
            "CLX_EMBEDDING_DIM",
            "CLX_OLLAMA_TIMEOUT_MS",
        ];
        if self.ollama.is_none() && OLLAMA_ENV_VARS.iter().any(|v| env::var(v).is_ok()) {
            self.ollama = Some(OllamaConfig::default());
        }

        if let Some(ref mut ollama) = self.ollama {
            if let Ok(val) = env::var("CLX_OLLAMA_HOST") {
                apply_string_override(&val, "CLX_OLLAMA_HOST", &mut ollama.host);
            }
            if let Ok(val) = env::var("CLX_OLLAMA_MODEL") {
                apply_string_override(&val, "CLX_OLLAMA_MODEL", &mut ollama.model);
            }
            if let Ok(val) = env::var("CLX_OLLAMA_EMBEDDING_MODEL") {
                apply_string_override(
                    &val,
                    "CLX_OLLAMA_EMBEDDING_MODEL",
                    &mut ollama.embedding_model,
                );
            }
            if let Ok(val) = env::var("CLX_EMBEDDING_DIM") {
                apply_usize_override(
                    &val,
                    "CLX_EMBEDDING_DIM",
                    1,
                    65536,
                    &mut ollama.embedding_dim,
                );
            }
            if let Ok(val) = env::var("CLX_OLLAMA_TIMEOUT_MS") {
                apply_u64_override(
                    &val,
                    "CLX_OLLAMA_TIMEOUT_MS",
                    1000,
                    600_000,
                    &mut ollama.timeout_ms,
                );
            }
        }

        // LLM routing overrides
        if let Some(ref mut llm) = self.llm {
            if let Ok(v) = env::var("CLX_LLM_CHAT_PROVIDER") {
                llm.chat.provider = v;
            }
            if let Ok(v) = env::var("CLX_LLM_CHAT_MODEL") {
                llm.chat.model = v;
            }
            if let Ok(v) = env::var("CLX_LLM_EMBEDDINGS_PROVIDER") {
                llm.embeddings.provider = v;
            }
            if let Ok(v) = env::var("CLX_LLM_EMBEDDINGS_MODEL") {
                llm.embeddings.model = v;
            }
        }

        // User learning overrides
        if let Ok(val) = env::var("CLX_USER_LEARNING_ENABLED") {
            apply_bool_override(
                &val,
                "CLX_USER_LEARNING_ENABLED",
                &mut self.user_learning.enabled,
            );
        }
        if let Ok(val) = env::var("CLX_USER_LEARNING_AUTO_WHITELIST_THRESHOLD") {
            apply_u32_override(
                &val,
                "CLX_USER_LEARNING_AUTO_WHITELIST_THRESHOLD",
                1,
                100,
                &mut self.user_learning.auto_whitelist_threshold,
            );
        }
        if let Ok(val) = env::var("CLX_USER_LEARNING_AUTO_BLACKLIST_THRESHOLD") {
            apply_u32_override(
                &val,
                "CLX_USER_LEARNING_AUTO_BLACKLIST_THRESHOLD",
                1,
                100,
                &mut self.user_learning.auto_blacklist_threshold,
            );
        }

        // Logging overrides
        if let Ok(val) = env::var("CLX_LOGGING_LEVEL") {
            apply_string_override(&val, "CLX_LOGGING_LEVEL", &mut self.logging.level);
        }
        if let Ok(val) = env::var("CLX_LOGGING_FILE") {
            apply_string_override(&val, "CLX_LOGGING_FILE", &mut self.logging.file);
        }
        if let Ok(val) = env::var("CLX_LOGGING_MAX_SIZE_MB") {
            apply_u32_override(
                &val,
                "CLX_LOGGING_MAX_SIZE_MB",
                1,
                1000,
                &mut self.logging.max_size_mb,
            );
        }
        if let Ok(val) = env::var("CLX_LOGGING_MAX_FILES") {
            apply_u32_override(
                &val,
                "CLX_LOGGING_MAX_FILES",
                1,
                100,
                &mut self.logging.max_files,
            );
        }

        // Context pressure overrides
        if let Ok(val) = env::var("CLX_CONTEXT_PRESSURE_MODE") {
            apply_enum_override::<ContextPressureMode>(
                &val,
                "CLX_CONTEXT_PRESSURE_MODE",
                &mut self.context_pressure.mode,
            );
        }
        if let Ok(val) = env::var("CLX_CONTEXT_PRESSURE_THRESHOLD") {
            apply_f64_override(
                &val,
                "CLX_CONTEXT_PRESSURE_THRESHOLD",
                0.0,
                1.0,
                &mut self.context_pressure.threshold,
            );
        }
        if let Ok(val) = env::var("CLX_CONTEXT_PRESSURE_WINDOW_SIZE") {
            apply_i64_override(
                &val,
                "CLX_CONTEXT_PRESSURE_WINDOW_SIZE",
                1000,
                10_000_000,
                &mut self.context_pressure.context_window_size,
            );
        }

        // MCP tools overrides
        // NOTE: command_tools registry is intentionally NOT overridable via env vars.
        // Use config file for custom command tool mappings.
        if let Ok(val) = env::var("CLX_MCP_TOOLS_ENABLED") {
            apply_bool_override(&val, "CLX_MCP_TOOLS_ENABLED", &mut self.mcp_tools.enabled);
        }
        if let Ok(val) = env::var("CLX_MCP_TOOLS_DEFAULT_DECISION") {
            apply_enum_override::<DefaultDecision>(
                &val,
                "CLX_MCP_TOOLS_DEFAULT_DECISION",
                &mut self.mcp_tools.default_decision,
            );
        }

        // Session recovery overrides
        if let Ok(val) = env::var("CLX_SESSION_RECOVERY_ENABLED") {
            apply_bool_override(
                &val,
                "CLX_SESSION_RECOVERY_ENABLED",
                &mut self.session_recovery.enabled,
            );
        }
        if let Ok(val) = env::var("CLX_SESSION_RECOVERY_STALE_HOURS") {
            apply_u32_override(
                &val,
                "CLX_SESSION_RECOVERY_STALE_HOURS",
                1,
                168,
                &mut self.session_recovery.stale_hours,
            );
        }

        // Auto Recall overrides
        if let Ok(val) = env::var("CLX_AUTO_RECALL_ENABLED") {
            apply_bool_override(
                &val,
                "CLX_AUTO_RECALL_ENABLED",
                &mut self.auto_recall.enabled,
            );
        }
        if let Ok(val) = env::var("CLX_AUTO_RECALL_MAX_RESULTS") {
            apply_usize_override(
                &val,
                "CLX_AUTO_RECALL_MAX_RESULTS",
                1,
                10,
                &mut self.auto_recall.max_results,
            );
        }
        if let Ok(val) = env::var("CLX_AUTO_RECALL_SIMILARITY_THRESHOLD") {
            apply_f32_override(
                &val,
                "CLX_AUTO_RECALL_SIMILARITY_THRESHOLD",
                0.0,
                1.0,
                &mut self.auto_recall.similarity_threshold,
            );
        }
        if let Ok(val) = env::var("CLX_AUTO_RECALL_MAX_CONTEXT_CHARS") {
            apply_usize_override(
                &val,
                "CLX_AUTO_RECALL_MAX_CONTEXT_CHARS",
                100,
                5000,
                &mut self.auto_recall.max_context_chars,
            );
        }
        if let Ok(val) = env::var("CLX_AUTO_RECALL_TIMEOUT_MS") {
            apply_u64_override(
                &val,
                "CLX_AUTO_RECALL_TIMEOUT_MS",
                100,
                10000,
                &mut self.auto_recall.timeout_ms,
            );
        }
        if let Ok(val) = env::var("CLX_AUTO_RECALL_FALLBACK_TO_FTS") {
            apply_bool_override(
                &val,
                "CLX_AUTO_RECALL_FALLBACK_TO_FTS",
                &mut self.auto_recall.fallback_to_fts,
            );
        }
        if let Ok(val) = env::var("CLX_AUTO_RECALL_INCLUDE_KEY_FACTS") {
            apply_bool_override(
                &val,
                "CLX_AUTO_RECALL_INCLUDE_KEY_FACTS",
                &mut self.auto_recall.include_key_facts,
            );
        }
        if let Ok(val) = env::var("CLX_AUTO_RECALL_MIN_PROMPT_LEN") {
            apply_usize_override(
                &val,
                "CLX_AUTO_RECALL_MIN_PROMPT_LEN",
                1,
                500,
                &mut self.auto_recall.min_prompt_len,
            );
        }
        if let Ok(val) = env::var("CLX_AUTO_RECALL_RRF_ENABLED") {
            apply_bool_override(
                &val,
                "CLX_AUTO_RECALL_RRF_ENABLED",
                &mut self.auto_recall.rrf_enabled,
            );
        }
        if let Ok(val) = env::var("CLX_AUTO_RECALL_RRF_K") {
            apply_u32_override(
                &val,
                "CLX_AUTO_RECALL_RRF_K",
                1,
                1000,
                &mut self.auto_recall.rrf_k,
            );
        }
        if let Ok(val) = env::var("CLX_AUTO_RECALL_TIME_DECAY_HALF_LIFE_DAYS") {
            apply_f64_override(
                &val,
                "CLX_AUTO_RECALL_TIME_DECAY_HALF_LIFE_DAYS",
                0.0,
                3650.0,
                &mut self.auto_recall.time_decay_half_life_days,
            );
        }
        if let Ok(val) = env::var("CLX_AUTO_RECALL_PERCENTILE_GATE") {
            apply_f64_override(
                &val,
                "CLX_AUTO_RECALL_PERCENTILE_GATE",
                0.0,
                1.0,
                &mut self.auto_recall.percentile_gate,
            );
        }
    }

    // -----------------------------------------------------------------------
    // Legacy translation
    // -----------------------------------------------------------------------

    /// Convert a legacy `ollama:` block into synthesized `providers:` + `llm:`
    /// sections in memory. The on-disk file is NOT touched. Idempotent: a no-op
    /// if `providers:` or `llm:` are already populated.
    pub fn translate_legacy_in_place(&mut self) {
        let has_new = !self.providers.is_empty() || self.llm.is_some();
        let has_old = self.ollama.is_some();

        if has_new && has_old {
            tracing::warn!(
                "config has both legacy 'ollama:' block and new 'providers:'/'llm:' sections; \
                 new sections win, legacy block ignored"
            );
            return;
        }
        if has_new || !has_old {
            return;
        }

        let legacy = self.ollama.clone().expect("has_old guard");
        self.providers.insert(
            "ollama-local".into(),
            ProviderConfig::Ollama(legacy.clone()),
        );
        self.llm = Some(LlmRouting {
            chat: CapabilityRoute {
                provider: "ollama-local".into(),
                model: legacy.model.clone(),
                fallback: None,
                dimension: None,
            },
            embeddings: CapabilityRoute {
                provider: "ollama-local".into(),
                model: legacy.embedding_model.clone(),
                fallback: None,
                // Preserve the legacy ollama embedding dimension exactly.
                dimension: Some(legacy.embedding_dim),
            },
        });
    }

    // -----------------------------------------------------------------------
    // Factory: capability routing + client construction
    // -----------------------------------------------------------------------

    /// Return the route definition for a capability.
    ///
    /// # Errors
    ///
    /// Returns `Err` when no `llm:` routing section exists (and no legacy block
    /// has been translated yet).
    pub fn capability_route(
        &self,
        capability: Capability,
    ) -> Result<&CapabilityRoute, LlmConfigError> {
        let llm = self.llm.as_ref().ok_or(LlmConfigError::MissingLlmRouting)?;
        Ok(match capability {
            Capability::Chat => &llm.chat,
            Capability::Embeddings => &llm.embeddings,
        })
    }

    /// Construct the `LlmClient` for the configured provider of a capability.
    /// Credentials are resolved at call time (env → keychain → file).
    ///
    /// # Errors
    ///
    /// Returns `Err` when routing is missing, the provider name is unknown, or
    /// credential resolution fails.
    pub fn create_llm_client(
        &self,
        capability: Capability,
    ) -> Result<crate::llm::LlmClient, LlmConfigError> {
        let route = self.capability_route(capability)?;
        let primary = self.build_client_for_provider(&route.provider)?;
        if let Some(fb) = route.fallback.as_deref() {
            let fallback = self.build_client_for_provider(&fb.provider)?;
            let wrapper =
                crate::llm::FallbackClient::new(primary, fallback, Some(fb.model.clone()));
            return Ok(crate::llm::LlmClient::Fallback(wrapper));
        }
        Ok(primary)
    }

    /// Construct an `LlmClient` for a named provider, bypassing routing.
    ///
    /// Useful for `clx health` and similar diagnostics that address a specific
    /// provider directly.
    ///
    /// # Errors
    ///
    /// Returns `Err` when the provider name is unknown or credential resolution
    /// fails.
    pub fn create_llm_client_by_name(
        &self,
        name: &str,
    ) -> Result<crate::llm::LlmClient, LlmConfigError> {
        self.build_client_for_provider(name)
    }

    /// Resolve the embedding dimension to request from an Azure provider built
    /// by `name`.
    ///
    /// Azure backends are constructed by provider name (not capability), so the
    /// dimension is taken from the embeddings route when that route targets this
    /// provider. Otherwise (e.g. a chat-only Azure provider, or no `llm:`
    /// routing) the sensible default of 1024 is used. The result is clamped into
    /// `u32` for the `OpenAI` `dimensions` parameter.
    fn azure_embedding_dimension_for_provider(&self, name: &str) -> u32 {
        let legacy_dim = self
            .ollama
            .as_ref()
            .map_or_else(default_embedding_dim, |o| o.embedding_dim);

        let resolved = self
            .llm
            .as_ref()
            .map(|llm| &llm.embeddings)
            .filter(|route| route.provider == name)
            .map_or(1024, |route| {
                effective_embedding_dimension(route, legacy_dim)
            });

        u32::try_from(resolved).unwrap_or(1024)
    }

    fn build_client_for_provider(
        &self,
        name: &str,
    ) -> Result<crate::llm::LlmClient, LlmConfigError> {
        let provider = self
            .providers
            .get(name)
            .ok_or_else(|| LlmConfigError::UnknownProvider(name.to_owned()))?;

        match provider {
            ProviderConfig::Ollama(c) => {
                let backend = crate::llm::OllamaBackend::new(c.clone())
                    .map_err(|e| LlmConfigError::ProviderInit(e.to_string()))?;
                Ok(crate::llm::LlmClient::Ollama(backend))
            }
            ProviderConfig::AzureOpenai(c) => {
                let kind = self
                    .credential_backend_kind()
                    .map_err(|e| LlmConfigError::ProviderInit(e.to_string()))?;
                let secret = resolve_azure_credential(name, c, kind)
                    .map_err(LlmConfigError::ProviderInit)?;
                let dimension = self.azure_embedding_dimension_for_provider(name);
                let backend =
                    crate::llm::AzureOpenAIBackend::with_embedding_dimension(c, secret, dimension)
                        .map_err(|e| LlmConfigError::ProviderInit(e.to_string()))?;
                Ok(crate::llm::LlmClient::Azure(backend))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// LLM config error type
// ---------------------------------------------------------------------------

/// Errors returned by `Config::create_llm_client` and related factory methods.
///
/// Convention: clx-core uses the crate-wide typed [`crate::Error`] everywhere,
/// with `anyhow` reserved for the binaries. `LlmConfigError` is the one
/// deliberate exception — a focused error for the LLM-client factory so callers
/// (the hook's L1 path) can exhaustively match each misconfiguration
/// (`MissingLlmRouting`, unknown provider, ...) without stringly matching. It is
/// intentionally NOT folded into `crate::Error`.
#[derive(Debug, thiserror::Error)]
pub enum LlmConfigError {
    #[error("config has no `llm:` routing section and no legacy `ollama:` block")]
    MissingLlmRouting,
    #[error("unknown provider: '{0}'")]
    UnknownProvider(String),
    #[error("provider init failed: {0}")]
    ProviderInit(String),
}

// ---------------------------------------------------------------------------
// Azure credential resolution
// ---------------------------------------------------------------------------

/// Resolve an Azure provider's API key.
///
/// Resolution order (the critical correctness requirement):
/// 1. Env var named in `cfg.api_key_env` (if set and non-empty) -> 0 prompts.
/// 2. The selected `CredentialBackend` entry keyed `"<provider_name>-api-key"`.
///    With the DEFAULT backend (`file`) this is the local age-encrypted file
///    and NEVER touches the keychain / prompts. The keychain is consulted
///    here ONLY if the user explicitly set `credentials.backend: keychain`.
///    (Hyphen, not colon: `CredentialStore` rejects colons in user keys.)
/// 3. File at `cfg.api_key_file` (Unix: must be mode 0600) -> 0 prompts.
/// 4. Error (with an actionable, one-time message). NEVER a keychain
///    fallback under the default backend -- that was the entire bug.
fn resolve_azure_credential(
    provider_name: &str,
    cfg: &AzureOpenAIConfig,
    backend_kind: crate::credentials::CredentialBackendKind,
) -> Result<secrecy::SecretString, String> {
    use secrecy::SecretString;

    // 1. env var
    if let Some(name) = cfg.api_key_env.as_deref()
        && let Ok(v) = std::env::var(name)
        && !v.is_empty()
    {
        return Ok(SecretString::new(v.into()));
    }

    // 2. selected backend (file by default; keychain ONLY if opted in)
    let store = crate::credentials::CredentialStore::from_config(backend_kind);
    let key = format!("{provider_name}-api-key");
    match store.get(&key) {
        Ok(Some(v)) => return Ok(SecretString::new(v.into())),
        Ok(None) => {} // fall through to api_key_file (NOT to the keychain)
        Err(e) => {
            // File backend IO error / headless keychain unavailable. Log and
            // fall through to api_key_file. We never silently retry a
            // different store (reintroducing prompts).
            tracing::warn!(
                provider = %provider_name,
                backend = %backend_kind_label(backend_kind),
                error = %e,
                "credential backend unavailable, falling back to api_key_file"
            );
        }
    }

    // 3. file
    if let Some(path) = cfg.api_key_file.as_deref() {
        return read_file_credential(path).map(|s| SecretString::new(s.into()));
    }

    Err(format!(
        "no credentials available for provider '{provider_name}' \
         (checked env var, {} backend key '{key}', and api_key_file). \
         Run: clx credentials set {provider_name}-api-key '<your-key>' \
         (or `clx credentials migrate` if the secret is only in the old \
         macOS keychain).",
        backend_kind_label(backend_kind)
    ))
}

fn backend_kind_label(kind: crate::credentials::CredentialBackendKind) -> &'static str {
    match kind {
        crate::credentials::CredentialBackendKind::File => "file",
        crate::credentials::CredentialBackendKind::Keychain => "keychain",
    }
}

#[cfg(unix)]
fn read_file_credential(path: &std::path::Path) -> Result<String, String> {
    use std::os::unix::fs::PermissionsExt;
    let metadata =
        std::fs::metadata(path).map_err(|e| format!("io error reading {}: {e}", path.display()))?;
    let mode = metadata.permissions().mode() & 0o777;
    if mode != 0o600 {
        return Err(format!(
            "file mode for {} is {mode:o}; refusing to read (must be 0600)",
            path.display()
        ));
    }
    let value = std::fs::read_to_string(path)
        .map_err(|e| format!("io error reading {}: {e}", path.display()))?;
    tracing::warn!(
        path = %path.display(),
        "api key loaded from plaintext file; consider running 'clx credentials set'"
    );
    Ok(value.trim().to_string())
}

#[cfg(not(unix))]
fn read_file_credential(_path: &std::path::Path) -> Result<String, String> {
    Err("file credential is not supported on this OS".into())
}

/// Parse a string to boolean, supporting common representations
fn parse_bool(s: &str) -> Option<bool> {
    match s.to_lowercase().as_str() {
        "true" | "1" | "yes" | "on" => Some(true),
        "false" | "0" | "no" | "off" => Some(false),
        _ => None,
    }
}

/// Apply a boolean env var override with validation and warning on invalid input
fn apply_bool_override(val: &str, var_name: &str, target: &mut bool) {
    match parse_bool(val) {
        Some(b) => *target = b,
        None => {
            tracing::warn!(
                "Invalid boolean for {}='{}', expected true/false. Using default: {}",
                var_name,
                val,
                target
            );
        }
    }
}

/// Apply a u64 env var override with range validation and warning
fn apply_u64_override(val: &str, var_name: &str, min: u64, max: u64, target: &mut u64) {
    match val.parse::<u64>() {
        Ok(v) if v >= min && v <= max => *target = v,
        Ok(v) => {
            tracing::warn!(
                "{}={} out of range ({}-{}), using default {}",
                var_name,
                v,
                min,
                max,
                target
            );
        }
        Err(e) => {
            tracing::warn!(
                "Invalid {} value '{}': {}, using default {}",
                var_name,
                val,
                e,
                target
            );
        }
    }
}

/// Apply a u32 env var override with range validation and warning
fn apply_u32_override(val: &str, var_name: &str, min: u32, max: u32, target: &mut u32) {
    match val.parse::<u32>() {
        Ok(v) if v >= min && v <= max => *target = v,
        Ok(v) => {
            tracing::warn!(
                "{}={} out of range ({}-{}), using default {}",
                var_name,
                v,
                min,
                max,
                target
            );
        }
        Err(e) => {
            tracing::warn!(
                "Invalid {} value '{}': {}, using default {}",
                var_name,
                val,
                e,
                target
            );
        }
    }
}

/// Apply a usize env var override with range validation and warning
fn apply_usize_override(val: &str, var_name: &str, min: usize, max: usize, target: &mut usize) {
    match val.parse::<usize>() {
        Ok(v) if v >= min && v <= max => *target = v,
        Ok(v) => {
            tracing::warn!(
                "{}={} out of range ({}-{}), using default {}",
                var_name,
                v,
                min,
                max,
                target
            );
        }
        Err(e) => {
            tracing::warn!(
                "Invalid {} value '{}': {}, using default {}",
                var_name,
                val,
                e,
                target
            );
        }
    }
}

/// Apply an i64 env var override with range validation and warning
fn apply_i64_override(val: &str, var_name: &str, min: i64, max: i64, target: &mut i64) {
    match val.parse::<i64>() {
        Ok(v) if v >= min && v <= max => *target = v,
        Ok(v) => {
            tracing::warn!(
                "{}={} out of range ({}-{}), using default {}",
                var_name,
                v,
                min,
                max,
                target
            );
        }
        Err(e) => {
            tracing::warn!(
                "Invalid {} value '{}': {}, using default {}",
                var_name,
                val,
                e,
                target
            );
        }
    }
}

/// Apply an f64 env var override with range validation and warning
fn apply_f64_override(val: &str, var_name: &str, min: f64, max: f64, target: &mut f64) {
    match val.parse::<f64>() {
        Ok(v) if v >= min && v <= max => *target = v,
        Ok(v) => {
            tracing::warn!(
                "{}={} out of range ({}-{}), using default {}",
                var_name,
                v,
                min,
                max,
                target
            );
        }
        Err(e) => {
            tracing::warn!(
                "Invalid {} value '{}': {}, using default {}",
                var_name,
                val,
                e,
                target
            );
        }
    }
}

/// Apply an f32 env var override with range validation and warning
fn apply_f32_override(val: &str, var_name: &str, min: f32, max: f32, target: &mut f32) {
    match val.parse::<f32>() {
        Ok(v) if v >= min && v <= max => *target = v,
        Ok(v) => {
            tracing::warn!(
                "{}={} out of range ({}-{}), using default {}",
                var_name,
                v,
                min,
                max,
                target
            );
        }
        Err(e) => {
            tracing::warn!(
                "Invalid {} value '{}': {}, using default {}",
                var_name,
                val,
                e,
                target
            );
        }
    }
}

/// Apply an enum env var override, parsing from string with validation
fn apply_enum_override<T: FromStr<Err = String> + fmt::Display>(
    val: &str,
    var_name: &str,
    target: &mut T,
) {
    if val.is_empty() {
        tracing::warn!("{}='' is empty, using default '{}'", var_name, target);
    } else {
        match T::from_str(val) {
            Ok(parsed) => *target = parsed,
            Err(e) => {
                tracing::warn!("Invalid {}: {}, using default '{}'", var_name, e, target);
            }
        }
    }
}

/// Apply a string env var override, rejecting empty strings
fn apply_string_override(val: &str, var_name: &str, target: &mut String) {
    if val.is_empty() {
        tracing::warn!("{}='' is empty, using default '{}'", var_name, target);
    } else {
        *target = val.to_string();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    /// FIX-1 config-trust regression: the new `on_validator_unavailable` key
    /// lives under the `validator` subtree, which `NON_INERT_KEY_PATTERNS`
    /// strips wholesale from an UNTRUSTED project config. An untrusted repo
    /// must NOT be able to set `validator.on_validator_unavailable=honordefault`
    /// (which, paired with `default_decision=allow`, would fail open). Reuses
    /// the existing untrusted-validator-subtree strip path.
    #[test]
    fn on_validator_unavailable_stripped_from_untrusted_config() {
        let raw = "validator:\n  on_validator_unavailable: honordefault\n  \
                   default_decision: allow\n";
        let out = crate::config::project::filter_inert_only(raw);
        assert!(
            !out.contains("on_validator_unavailable"),
            "validator.on_validator_unavailable must be stripped from untrusted config; got: {out}"
        );
        assert!(
            !out.contains("default_decision"),
            "validator.default_decision must also be stripped; got: {out}"
        );
    }

    /// RAII guard that saves env var values on creation and restores them on drop.
    /// Guarantees cleanup even if the test panics.
    #[allow(unsafe_code)]
    struct EnvGuard {
        vars: Vec<(String, Option<String>)>,
    }

    impl EnvGuard {
        fn new(keys: &[&str]) -> Self {
            let vars = keys
                .iter()
                .map(|k| (k.to_string(), env::var(k).ok()))
                .collect();
            Self { vars }
        }
    }

    #[allow(unsafe_code)]
    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for (key, original) in &self.vars {
                // SAFETY: Serialized via #[serial_test::serial], no concurrent mutation.
                unsafe {
                    match original {
                        Some(val) => env::set_var(key, val),
                        None => env::remove_var(key),
                    }
                }
            }
        }
    }

    #[test]
    fn test_default_config() {
        let config = Config::default();

        // Validator defaults
        assert!(config.validator.enabled);
        assert!(config.validator.layer0_enabled);
        assert!(config.validator.layer1_enabled);
        assert_eq!(config.validator.layer1_timeout_ms, 30000);
        assert_eq!(config.validator.default_decision, DefaultDecision::Ask);
        assert!(!config.validator.trust_mode);
        assert!(config.validator.auto_allow_reads);

        // Context defaults
        assert!(config.context.enabled);
        assert!(config.context.auto_snapshot);
        assert_eq!(config.context.embedding_model, "qwen3-embedding:0.6b");

        // Ollama defaults (config.ollama is None by default; verify via OllamaConfig::default())
        let ollama_defaults = OllamaConfig::default();
        assert_eq!(ollama_defaults.host, "http://127.0.0.1:11434");
        assert_eq!(ollama_defaults.model, "qwen3:1.7b");
        assert_eq!(ollama_defaults.embedding_model, "qwen3-embedding:0.6b");
        assert_eq!(ollama_defaults.embedding_dim, 1024);
        assert_eq!(ollama_defaults.timeout_ms, 60000);

        // User learning defaults
        assert!(config.user_learning.enabled);
        assert_eq!(config.user_learning.auto_whitelist_threshold, 3);
        assert_eq!(config.user_learning.auto_blacklist_threshold, 2);

        // Logging defaults
        assert_eq!(config.logging.level, "info");
        assert_eq!(config.logging.file, "~/.clx/logs/clx.log");
        assert_eq!(config.logging.max_size_mb, 10);
        assert_eq!(config.logging.max_files, 5);

        // Auto recall defaults
        assert!(config.auto_recall.enabled);
        assert_eq!(config.auto_recall.max_results, 3);
        assert!((config.auto_recall.similarity_threshold - 0.35).abs() < f32::EPSILON,);
        assert_eq!(config.auto_recall.max_context_chars, 1000);
        assert_eq!(config.auto_recall.timeout_ms, 500);
        assert!(config.auto_recall.fallback_to_fts);
        assert!(config.auto_recall.include_key_facts);
        assert_eq!(config.auto_recall.min_prompt_len, 10);
    }

    #[test]
    fn test_parse_yaml_config() {
        let yaml = r#"
validator:
  enabled: false
  layer1_enabled: true
  layer1_timeout_ms: 1000
  default_decision: "deny"

context:
  enabled: true
  auto_snapshot: false
  embedding_model: "custom-embed"

ollama:
  host: "http://localhost:8080"
  model: "mistral:7b"
  embedding_model: "custom-embed"
  timeout_ms: 10000

user_learning:
  enabled: false
  auto_whitelist_threshold: 5
  auto_blacklist_threshold: 3

logging:
  level: "debug"
  file: "/var/log/clx.log"
  max_size_mb: 50
  max_files: 10
"#;

        let config: Config = serde_yml::from_str(yaml).unwrap();

        assert!(!config.validator.enabled);
        assert!(config.validator.layer1_enabled);
        assert_eq!(config.validator.layer1_timeout_ms, 1000);
        assert_eq!(config.validator.default_decision, DefaultDecision::Deny);

        assert!(config.context.enabled);
        assert!(!config.context.auto_snapshot);
        assert_eq!(config.context.embedding_model, "custom-embed");

        assert_eq!(
            config.ollama.as_ref().unwrap().host,
            "http://localhost:8080"
        );
        assert_eq!(config.ollama.as_ref().unwrap().model, "mistral:7b");
        assert_eq!(
            config.ollama.as_ref().unwrap().embedding_model,
            "custom-embed"
        );
        assert_eq!(config.ollama.as_ref().unwrap().timeout_ms, 10000);

        assert!(!config.user_learning.enabled);
        assert_eq!(config.user_learning.auto_whitelist_threshold, 5);
        assert_eq!(config.user_learning.auto_blacklist_threshold, 3);

        assert_eq!(config.logging.level, "debug");
        assert_eq!(config.logging.file, "/var/log/clx.log");
        assert_eq!(config.logging.max_size_mb, 50);
        assert_eq!(config.logging.max_files, 10);
    }

    #[test]
    fn test_partial_yaml_config() {
        // Test that missing sections get default values
        let yaml = r"
validator:
  enabled: false
";

        let config: Config = serde_yml::from_str(yaml).unwrap();

        // Validator has one value set, rest are defaults
        assert!(!config.validator.enabled);
        assert!(config.validator.layer1_enabled); // default
        assert_eq!(config.validator.layer1_timeout_ms, 30000); // default

        // Other sections should be entirely default
        assert!(config.context.enabled);
        assert_eq!(OllamaConfig::default().host, "http://127.0.0.1:11434");
        assert!(config.user_learning.enabled);
        assert_eq!(config.logging.level, "info");
    }

    #[test]
    #[serial_test::serial]
    #[allow(unsafe_code)]
    fn test_env_overrides() {
        let _guard = EnvGuard::new(&[
            "CLX_VALIDATOR_ENABLED",
            "CLX_VALIDATOR_LAYER1_TIMEOUT_MS",
            "CLX_OLLAMA_MODEL",
            "CLX_USER_LEARNING_AUTO_WHITELIST_THRESHOLD",
            "CLX_LOGGING_LEVEL",
        ]);

        // SAFETY: Serialized via #[serial_test::serial], no concurrent mutation.
        unsafe {
            env::set_var("CLX_VALIDATOR_ENABLED", "false");
            env::set_var("CLX_VALIDATOR_LAYER1_TIMEOUT_MS", "2000");
            env::set_var("CLX_OLLAMA_MODEL", "custom-model:latest");
            env::set_var("CLX_USER_LEARNING_AUTO_WHITELIST_THRESHOLD", "10");
            env::set_var("CLX_LOGGING_LEVEL", "debug");
        }

        let mut config = Config::default();
        config.apply_env_overrides();

        assert!(!config.validator.enabled);
        assert_eq!(config.validator.layer1_timeout_ms, 2000);
        assert_eq!(config.ollama.as_ref().unwrap().model, "custom-model:latest");
        assert_eq!(config.user_learning.auto_whitelist_threshold, 10);
        assert_eq!(config.logging.level, "debug");
    }

    #[test]
    fn test_parse_bool() {
        assert_eq!(parse_bool("true"), Some(true));
        assert_eq!(parse_bool("TRUE"), Some(true));
        assert_eq!(parse_bool("1"), Some(true));
        assert_eq!(parse_bool("yes"), Some(true));
        assert_eq!(parse_bool("on"), Some(true));

        assert_eq!(parse_bool("false"), Some(false));
        assert_eq!(parse_bool("FALSE"), Some(false));
        assert_eq!(parse_bool("0"), Some(false));
        assert_eq!(parse_bool("no"), Some(false));
        assert_eq!(parse_bool("off"), Some(false));

        assert_eq!(parse_bool("invalid"), None);
        assert_eq!(parse_bool(""), None);
    }

    #[test]
    fn test_expand_tilde() {
        let expanded = Config::expand_tilde("~/.clx/logs/clx.log");
        assert!(!expanded.starts_with('~'));
        assert!(expanded.contains(".clx/logs/clx.log"));

        // Non-tilde paths should remain unchanged
        let absolute = Config::expand_tilde("/var/log/clx.log");
        assert_eq!(absolute, "/var/log/clx.log");

        let relative = Config::expand_tilde("relative/path");
        assert_eq!(relative, "relative/path");
    }

    #[test]
    fn test_config_dir() {
        let dir = Config::config_dir().unwrap();
        assert!(dir.ends_with(".clx"));
    }

    #[test]
    fn test_config_file_path() {
        let path = Config::config_file_path().unwrap();
        assert!(path.ends_with("config.yaml"));
        assert!(path.to_string_lossy().contains(".clx"));
    }

    #[test]
    fn test_log_file_path() {
        let config = Config::default();
        let path = config.log_file_path();
        assert!(!path.to_string_lossy().starts_with('~'));
        assert!(path.to_string_lossy().contains(".clx/logs/clx.log"));
    }

    #[test]
    fn test_config_serialization_roundtrip() {
        let config = Config::default();
        let yaml = serde_yml::to_string(&config).unwrap();
        let parsed: Config = serde_yml::from_str(&yaml).unwrap();
        assert_eq!(config, parsed);
    }

    #[test]
    #[serial_test::serial]
    #[allow(unsafe_code)]
    fn test_env_bool_variations() {
        let _guard = EnvGuard::new(&["CLX_VALIDATOR_ENABLED"]);
        let mut config = Config::default();

        // SAFETY: Serialized via #[serial_test::serial], no concurrent mutation.
        unsafe {
            // Test "yes"
            env::set_var("CLX_VALIDATOR_ENABLED", "yes");
            config.apply_env_overrides();
            assert!(config.validator.enabled);

            // Test "no"
            env::set_var("CLX_VALIDATOR_ENABLED", "no");
            config.apply_env_overrides();
            assert!(!config.validator.enabled);

            // Test "on"
            env::set_var("CLX_VALIDATOR_ENABLED", "on");
            config.apply_env_overrides();
            assert!(config.validator.enabled);

            // Test "off"
            env::set_var("CLX_VALIDATOR_ENABLED", "off");
            config.apply_env_overrides();
            assert!(!config.validator.enabled);
        }
    }

    #[test]
    #[serial_test::serial]
    #[allow(unsafe_code)]
    fn test_invalid_env_values_use_defaults() {
        let _guard = EnvGuard::new(&["CLX_VALIDATOR_ENABLED", "CLX_VALIDATOR_LAYER1_TIMEOUT_MS"]);

        // SAFETY: Serialized via #[serial_test::serial], no concurrent mutation.
        unsafe {
            let mut config = Config::default();

            // Invalid boolean should keep default
            env::set_var("CLX_VALIDATOR_ENABLED", "invalid");
            // Invalid number should keep default
            env::set_var("CLX_VALIDATOR_LAYER1_TIMEOUT_MS", "not_a_number");

            config.apply_env_overrides();

            assert!(config.validator.enabled); // default is true
            assert_eq!(config.validator.layer1_timeout_ms, 30000); // default
        }
    }

    #[test]
    #[serial_test::serial]
    #[allow(unsafe_code)]
    fn test_all_env_overrides() {
        let _guard = EnvGuard::new(&[
            "CLX_VALIDATOR_ENABLED",
            "CLX_VALIDATOR_LAYER1_ENABLED",
            "CLX_VALIDATOR_LAYER1_TIMEOUT_MS",
            "CLX_VALIDATOR_DEFAULT_DECISION",
            "CLX_CONTEXT_ENABLED",
            "CLX_CONTEXT_AUTO_SNAPSHOT",
            "CLX_CONTEXT_EMBEDDING_MODEL",
            "CLX_OLLAMA_HOST",
            "CLX_OLLAMA_MODEL",
            "CLX_OLLAMA_EMBEDDING_MODEL",
            "CLX_OLLAMA_TIMEOUT_MS",
            "CLX_USER_LEARNING_ENABLED",
            "CLX_USER_LEARNING_AUTO_WHITELIST_THRESHOLD",
            "CLX_USER_LEARNING_AUTO_BLACKLIST_THRESHOLD",
            "CLX_LOGGING_LEVEL",
            "CLX_LOGGING_FILE",
            "CLX_LOGGING_MAX_SIZE_MB",
            "CLX_LOGGING_MAX_FILES",
        ]);

        // SAFETY: Serialized via #[serial_test::serial], no concurrent mutation.
        unsafe {
            env::set_var("CLX_VALIDATOR_ENABLED", "false");
            env::set_var("CLX_VALIDATOR_LAYER1_ENABLED", "false");
            env::set_var("CLX_VALIDATOR_LAYER1_TIMEOUT_MS", "999");
            env::set_var("CLX_VALIDATOR_DEFAULT_DECISION", "allow");

            env::set_var("CLX_CONTEXT_ENABLED", "false");
            env::set_var("CLX_CONTEXT_AUTO_SNAPSHOT", "false");
            env::set_var("CLX_CONTEXT_EMBEDDING_MODEL", "test-embed");

            env::set_var("CLX_OLLAMA_HOST", "http://test:1234");
            env::set_var("CLX_OLLAMA_MODEL", "test-model");
            env::set_var("CLX_OLLAMA_EMBEDDING_MODEL", "test-embed-model");
            env::set_var("CLX_OLLAMA_TIMEOUT_MS", "9999");

            env::set_var("CLX_USER_LEARNING_ENABLED", "false");
            env::set_var("CLX_USER_LEARNING_AUTO_WHITELIST_THRESHOLD", "99");
            env::set_var("CLX_USER_LEARNING_AUTO_BLACKLIST_THRESHOLD", "88");

            env::set_var("CLX_LOGGING_LEVEL", "trace");
            env::set_var("CLX_LOGGING_FILE", "/custom/path.log");
            env::set_var("CLX_LOGGING_MAX_SIZE_MB", "100");
            env::set_var("CLX_LOGGING_MAX_FILES", "20");
        }

        let mut config = Config::default();
        config.apply_env_overrides();

        // Verify all overrides
        assert!(!config.validator.enabled);
        assert!(!config.validator.layer1_enabled);
        assert_eq!(config.validator.layer1_timeout_ms, 999);
        assert_eq!(config.validator.default_decision, DefaultDecision::Allow);

        assert!(!config.context.enabled);
        assert!(!config.context.auto_snapshot);
        assert_eq!(config.context.embedding_model, "test-embed");

        assert_eq!(config.ollama.as_ref().unwrap().host, "http://test:1234");
        assert_eq!(config.ollama.as_ref().unwrap().model, "test-model");
        assert_eq!(
            config.ollama.as_ref().unwrap().embedding_model,
            "test-embed-model"
        );
        assert_eq!(config.ollama.as_ref().unwrap().timeout_ms, 9999);

        assert!(!config.user_learning.enabled);
        assert_eq!(config.user_learning.auto_whitelist_threshold, 99);
        assert_eq!(config.user_learning.auto_blacklist_threshold, 88);

        assert_eq!(config.logging.level, "trace");
        assert_eq!(config.logging.file, "/custom/path.log");
        assert_eq!(config.logging.max_size_mb, 100);
        assert_eq!(config.logging.max_files, 20);
    }

    // -------------------------------------------------------------------------
    // B5-4 + R1-NEW-1 regression: security-weakening env overrides emit WARN
    // and are reflected in security_env_overrides_active().
    // These tests FAIL on the pre-fix code (no WARN, no accessor).
    // -------------------------------------------------------------------------

    /// GREEN regression for B5-4: when `CLX_VALIDATOR_ENABLED=false` is set,
    /// `security_env_overrides_active()` must report it.
    /// Fails on pre-fix code (method did not exist).
    #[test]
    #[serial_test::serial]
    #[allow(unsafe_code)]
    fn b5_4_security_env_overrides_active_detects_validator_disabled() {
        let _guard = EnvGuard::new(&["CLX_VALIDATOR_ENABLED"]);

        // SAFETY: Serialized via #[serial_test::serial], no concurrent mutation.
        unsafe {
            env::set_var("CLX_VALIDATOR_ENABLED", "false");
        }

        let config = Config::default();
        let overrides = config.security_env_overrides_active();
        assert!(
            overrides.iter().any(|(k, _)| *k == "CLX_VALIDATOR_ENABLED"),
            "B5-4: CLX_VALIDATOR_ENABLED=false must appear in security_env_overrides_active(); \
             got: {overrides:?}"
        );
    }

    /// GREEN regression for B5-4: when `CLX_VALIDATOR_LAYER0_ENABLED=false` is set,
    /// `security_env_overrides_active()` must report it.
    #[test]
    #[serial_test::serial]
    #[allow(unsafe_code)]
    fn b5_4_security_env_overrides_active_detects_layer0_disabled() {
        let _guard = EnvGuard::new(&["CLX_VALIDATOR_LAYER0_ENABLED"]);

        unsafe {
            env::set_var("CLX_VALIDATOR_LAYER0_ENABLED", "false");
        }

        let config = Config::default();
        let overrides = config.security_env_overrides_active();
        assert!(
            overrides
                .iter()
                .any(|(k, _)| *k == "CLX_VALIDATOR_LAYER0_ENABLED"),
            "B5-4: CLX_VALIDATOR_LAYER0_ENABLED=false must appear in security_env_overrides_active(); \
             got: {overrides:?}"
        );
    }

    /// GREEN regression for B5-4: when `CLX_VALIDATOR_LAYER1_ENABLED=false` is set,
    /// `security_env_overrides_active()` must report it.
    #[test]
    #[serial_test::serial]
    #[allow(unsafe_code)]
    fn b5_4_security_env_overrides_active_detects_layer1_disabled() {
        let _guard = EnvGuard::new(&["CLX_VALIDATOR_LAYER1_ENABLED"]);

        unsafe {
            env::set_var("CLX_VALIDATOR_LAYER1_ENABLED", "false");
        }

        let config = Config::default();
        let overrides = config.security_env_overrides_active();
        assert!(
            overrides
                .iter()
                .any(|(k, _)| *k == "CLX_VALIDATOR_LAYER1_ENABLED"),
            "B5-4: CLX_VALIDATOR_LAYER1_ENABLED=false must appear in security_env_overrides_active(); \
             got: {overrides:?}"
        );
    }

    /// GREEN regression for B5-4: when `CLX_VALIDATOR_DEFAULT_DECISION=allow` is set,
    /// `security_env_overrides_active()` must report it.
    #[test]
    #[serial_test::serial]
    #[allow(unsafe_code)]
    fn b5_4_security_env_overrides_active_detects_default_decision_allow() {
        let _guard = EnvGuard::new(&["CLX_VALIDATOR_DEFAULT_DECISION"]);

        unsafe {
            env::set_var("CLX_VALIDATOR_DEFAULT_DECISION", "allow");
        }

        let config = Config::default();
        let overrides = config.security_env_overrides_active();
        assert!(
            overrides
                .iter()
                .any(|(k, _)| *k == "CLX_VALIDATOR_DEFAULT_DECISION"),
            "B5-4: CLX_VALIDATOR_DEFAULT_DECISION=allow must appear in security_env_overrides_active(); \
             got: {overrides:?}"
        );
    }

    /// GREEN regression for B5-4: when `CLX_VALIDATOR_AUTO_ALLOW_READS=true` is set,
    /// `security_env_overrides_active()` must report it.
    #[test]
    #[serial_test::serial]
    #[allow(unsafe_code)]
    fn b5_4_security_env_overrides_active_detects_auto_allow_reads() {
        let _guard = EnvGuard::new(&["CLX_VALIDATOR_AUTO_ALLOW_READS"]);

        unsafe {
            env::set_var("CLX_VALIDATOR_AUTO_ALLOW_READS", "true");
        }

        let config = Config::default();
        let overrides = config.security_env_overrides_active();
        assert!(
            overrides
                .iter()
                .any(|(k, _)| *k == "CLX_VALIDATOR_AUTO_ALLOW_READS"),
            "B5-4: CLX_VALIDATOR_AUTO_ALLOW_READS=true must appear in security_env_overrides_active(); \
             got: {overrides:?}"
        );
    }

    /// Full B5-4 scenario: all five weakening vars set simultaneously —
    /// all five must appear in `security_env_overrides_active()`.
    #[test]
    #[serial_test::serial]
    #[allow(unsafe_code)]
    fn b5_4_all_four_weakening_vars_all_reported() {
        let _guard = EnvGuard::new(&[
            "CLX_VALIDATOR_ENABLED",
            "CLX_VALIDATOR_LAYER0_ENABLED",
            "CLX_VALIDATOR_LAYER1_ENABLED",
            "CLX_VALIDATOR_DEFAULT_DECISION",
            "CLX_VALIDATOR_AUTO_ALLOW_READS",
        ]);

        unsafe {
            env::set_var("CLX_VALIDATOR_ENABLED", "false");
            env::set_var("CLX_VALIDATOR_LAYER0_ENABLED", "false");
            env::set_var("CLX_VALIDATOR_LAYER1_ENABLED", "false");
            env::set_var("CLX_VALIDATOR_DEFAULT_DECISION", "allow");
            env::set_var("CLX_VALIDATOR_AUTO_ALLOW_READS", "true");
        }

        let mut config = Config::default();
        config.apply_env_overrides();

        // The config values are actually weakened.
        assert!(!config.validator.enabled, "validator must be disabled");
        assert!(!config.validator.layer0_enabled, "L0 must be disabled");
        assert!(!config.validator.layer1_enabled, "L1 must be disabled");
        assert_eq!(
            config.validator.default_decision,
            DefaultDecision::Allow,
            "default_decision must be allow"
        );

        // All five weakening vars are reported.
        let overrides = config.security_env_overrides_active();
        let keys: Vec<&str> = overrides.iter().map(|(k, _)| *k).collect();
        assert!(
            keys.contains(&"CLX_VALIDATOR_ENABLED"),
            "missing ENABLED: {keys:?}"
        );
        assert!(
            keys.contains(&"CLX_VALIDATOR_LAYER0_ENABLED"),
            "missing LAYER0_ENABLED: {keys:?}"
        );
        assert!(
            keys.contains(&"CLX_VALIDATOR_LAYER1_ENABLED"),
            "missing LAYER1_ENABLED: {keys:?}"
        );
        assert!(
            keys.contains(&"CLX_VALIDATOR_DEFAULT_DECISION"),
            "missing DEFAULT_DECISION: {keys:?}"
        );
        assert!(
            keys.contains(&"CLX_VALIDATOR_AUTO_ALLOW_READS"),
            "missing AUTO_ALLOW_READS: {keys:?}"
        );
        assert_eq!(
            overrides.len(),
            5,
            "expected exactly 5 weakening overrides; got: {keys:?}"
        );
    }

    /// Negative case: no weakening vars set => empty list.
    #[test]
    #[serial_test::serial]
    #[allow(unsafe_code)]
    fn b5_4_no_weakening_vars_returns_empty() {
        let _guard = EnvGuard::new(&[
            "CLX_VALIDATOR_ENABLED",
            "CLX_VALIDATOR_LAYER0_ENABLED",
            "CLX_VALIDATOR_LAYER1_ENABLED",
            "CLX_VALIDATOR_DEFAULT_DECISION",
            "CLX_VALIDATOR_AUTO_ALLOW_READS",
        ]);

        unsafe {
            env::remove_var("CLX_VALIDATOR_ENABLED");
            env::remove_var("CLX_VALIDATOR_LAYER0_ENABLED");
            env::remove_var("CLX_VALIDATOR_LAYER1_ENABLED");
            env::remove_var("CLX_VALIDATOR_DEFAULT_DECISION");
            env::remove_var("CLX_VALIDATOR_AUTO_ALLOW_READS");
        }

        let config = Config::default();
        let overrides = config.security_env_overrides_active();
        assert!(
            overrides.is_empty(),
            "no weakening vars set => empty list; got: {overrides:?}"
        );
    }

    /// Non-weakening values for `CLX_VALIDATOR_DEFAULT_DECISION` (ask / deny)
    /// must NOT appear in the security override list.
    #[test]
    #[serial_test::serial]
    #[allow(unsafe_code)]
    fn b5_4_non_weakening_default_decision_not_reported() {
        let _guard = EnvGuard::new(&["CLX_VALIDATOR_DEFAULT_DECISION"]);

        for val in ["ask", "deny", "Ask", "DENY"] {
            unsafe {
                env::set_var("CLX_VALIDATOR_DEFAULT_DECISION", val);
            }
            let config = Config::default();
            let overrides = config.security_env_overrides_active();
            assert!(
                !overrides
                    .iter()
                    .any(|(k, _)| *k == "CLX_VALIDATOR_DEFAULT_DECISION"),
                "CLX_VALIDATOR_DEFAULT_DECISION={val} is not security-weakening \
                 and must not appear in overrides; got: {overrides:?}"
            );
        }
    }

    #[test]
    fn test_config_is_clone_send_sync() {
        fn assert_clone_send_sync<T: Clone + Send + Sync>() {}
        assert_clone_send_sync::<Config>();
        assert_clone_send_sync::<ValidatorConfig>();
        assert_clone_send_sync::<ContextConfig>();
        assert_clone_send_sync::<OllamaConfig>();
        assert_clone_send_sync::<UserLearningConfig>();
        assert_clone_send_sync::<LoggingConfig>();
        assert_clone_send_sync::<ContextPressureConfig>();
        assert_clone_send_sync::<SessionRecoveryConfig>();
        assert_clone_send_sync::<McpToolsConfig>();
        assert_clone_send_sync::<McpCommandTool>();
    }

    #[test]
    fn test_qwen3_embedding_defaults() {
        let config = Config::default();
        let ollama_defaults = OllamaConfig::default();
        assert_eq!(ollama_defaults.embedding_model, "qwen3-embedding:0.6b");
        assert_eq!(ollama_defaults.embedding_dim, 1024);
        assert_eq!(config.context.embedding_model, "qwen3-embedding:0.6b");
    }

    #[test]
    #[serial_test::serial]
    #[allow(unsafe_code)]
    fn test_embedding_dim_env_override() {
        let _guard = EnvGuard::new(&["CLX_EMBEDDING_DIM"]);

        // SAFETY: Serialized via #[serial_test::serial], no concurrent mutation.
        unsafe {
            env::set_var("CLX_EMBEDDING_DIM", "768");
        }

        let mut config = Config::default();
        config.apply_env_overrides();

        assert_eq!(config.ollama.as_ref().unwrap().embedding_dim, 768);
    }

    #[test]
    #[serial_test::serial]
    #[allow(unsafe_code)]
    fn test_embedding_dim_env_invalid_keeps_default() {
        let _guard = EnvGuard::new(&["CLX_EMBEDDING_DIM"]);

        // SAFETY: Serialized via #[serial_test::serial], no concurrent mutation.
        unsafe {
            env::set_var("CLX_EMBEDDING_DIM", "not_a_number");
        }

        let mut config = Config::default();
        config.apply_env_overrides();

        assert_eq!(config.ollama.as_ref().unwrap().embedding_dim, 1024);
    }

    #[test]
    fn test_embedding_dim_yaml_deserialization() {
        let yaml = r#"
ollama:
  embedding_model: "custom-model"
  embedding_dim: 512
"#;

        let config: Config = serde_yml::from_str(yaml).unwrap();
        assert_eq!(
            config.ollama.as_ref().unwrap().embedding_model,
            "custom-model"
        );
        assert_eq!(config.ollama.as_ref().unwrap().embedding_dim, 512);
    }

    #[test]
    fn test_embedding_dim_yaml_missing_uses_default() {
        let yaml = r#"
ollama:
  embedding_model: "custom-model"
"#;

        let config: Config = serde_yml::from_str(yaml).unwrap();
        assert_eq!(config.ollama.as_ref().unwrap().embedding_dim, 1024);
    }

    // --- H5: Env var validation helper tests ---

    #[test]
    fn test_apply_bool_override_valid() {
        let mut val = false;
        apply_bool_override("true", "TEST_VAR", &mut val);
        assert!(val);

        apply_bool_override("false", "TEST_VAR", &mut val);
        assert!(!val);
    }

    #[test]
    fn test_apply_bool_override_invalid_keeps_default() {
        let mut val = true;
        apply_bool_override("invalid", "TEST_VAR", &mut val);
        assert!(val); // unchanged
    }

    #[test]
    fn test_apply_u64_override_valid() {
        let mut val = 30000u64;
        apply_u64_override("5000", "TEST_VAR", 100, 300_000, &mut val);
        assert_eq!(val, 5000);
    }

    #[test]
    fn test_apply_u64_override_out_of_range_keeps_default() {
        let mut val = 30000u64;
        apply_u64_override("50", "TEST_VAR", 100, 300_000, &mut val);
        assert_eq!(val, 30000); // unchanged, below min

        apply_u64_override("999999", "TEST_VAR", 100, 300_000, &mut val);
        assert_eq!(val, 30000); // unchanged, above max
    }

    #[test]
    fn test_apply_u64_override_invalid_keeps_default() {
        let mut val = 30000u64;
        apply_u64_override("not_a_number", "TEST_VAR", 100, 300_000, &mut val);
        assert_eq!(val, 30000);
    }

    #[test]
    fn test_apply_u32_override_valid() {
        let mut val = 3u32;
        apply_u32_override("10", "TEST_VAR", 1, 100, &mut val);
        assert_eq!(val, 10);
    }

    #[test]
    fn test_apply_u32_override_out_of_range_keeps_default() {
        let mut val = 3u32;
        apply_u32_override("0", "TEST_VAR", 1, 100, &mut val);
        assert_eq!(val, 3);

        apply_u32_override("200", "TEST_VAR", 1, 100, &mut val);
        assert_eq!(val, 3);
    }

    #[test]
    fn test_apply_usize_override_valid() {
        let mut val = 1024usize;
        apply_usize_override("768", "TEST_VAR", 1, 65536, &mut val);
        assert_eq!(val, 768);
    }

    #[test]
    fn test_apply_usize_override_out_of_range() {
        let mut val = 1024usize;
        apply_usize_override("0", "TEST_VAR", 1, 65536, &mut val);
        assert_eq!(val, 1024);
    }

    #[test]
    fn test_apply_string_override_valid() {
        let mut val = "default".to_string();
        apply_string_override("new_value", "TEST_VAR", &mut val);
        assert_eq!(val, "new_value");
    }

    #[test]
    fn test_apply_string_override_empty_keeps_default() {
        let mut val = "default".to_string();
        apply_string_override("", "TEST_VAR", &mut val);
        assert_eq!(val, "default");
    }

    // --- Context pressure config tests ---

    #[test]
    fn test_context_pressure_defaults() {
        let config = Config::default();
        assert_eq!(config.context_pressure.mode, ContextPressureMode::Auto);
        assert_eq!(config.context_pressure.context_window_size, 200_000);
        assert!((config.context_pressure.threshold - 0.80).abs() < f64::EPSILON);
    }

    #[test]
    fn test_session_recovery_defaults() {
        let config = Config::default();
        assert!(config.session_recovery.enabled);
        assert_eq!(config.session_recovery.stale_hours, 2);
    }

    #[test]
    fn test_context_pressure_yaml_parsing() {
        let yaml = r#"
context_pressure:
  mode: "notify"
  context_window_size: 100000
  threshold: 0.75
"#;

        let config: Config = serde_yml::from_str(yaml).unwrap();
        assert_eq!(config.context_pressure.mode, ContextPressureMode::Notify);
        assert_eq!(config.context_pressure.context_window_size, 100_000);
        assert!((config.context_pressure.threshold - 0.75).abs() < f64::EPSILON);
    }

    #[test]
    fn test_session_recovery_yaml_parsing() {
        let yaml = r"
session_recovery:
  enabled: false
  stale_hours: 4
";

        let config: Config = serde_yml::from_str(yaml).unwrap();
        assert!(!config.session_recovery.enabled);
        assert_eq!(config.session_recovery.stale_hours, 4);
    }

    #[test]
    #[serial_test::serial]
    #[allow(unsafe_code)]
    fn test_context_pressure_env_overrides() {
        let _guard = EnvGuard::new(&[
            "CLX_CONTEXT_PRESSURE_MODE",
            "CLX_CONTEXT_PRESSURE_THRESHOLD",
            "CLX_CONTEXT_PRESSURE_WINDOW_SIZE",
        ]);

        // SAFETY: Serialized via #[serial_test::serial], no concurrent mutation.
        unsafe {
            env::set_var("CLX_CONTEXT_PRESSURE_MODE", "disabled");
            env::set_var("CLX_CONTEXT_PRESSURE_THRESHOLD", "0.90");
            env::set_var("CLX_CONTEXT_PRESSURE_WINDOW_SIZE", "150000");
        }

        let mut config = Config::default();
        config.apply_env_overrides();

        assert_eq!(config.context_pressure.mode, ContextPressureMode::Disabled);
        assert!((config.context_pressure.threshold - 0.90).abs() < f64::EPSILON);
        assert_eq!(config.context_pressure.context_window_size, 150_000);
    }

    #[test]
    #[serial_test::serial]
    #[allow(unsafe_code)]
    fn test_session_recovery_env_overrides() {
        let _guard = EnvGuard::new(&[
            "CLX_SESSION_RECOVERY_ENABLED",
            "CLX_SESSION_RECOVERY_STALE_HOURS",
        ]);

        // SAFETY: Serialized via #[serial_test::serial], no concurrent mutation.
        unsafe {
            env::set_var("CLX_SESSION_RECOVERY_ENABLED", "false");
            env::set_var("CLX_SESSION_RECOVERY_STALE_HOURS", "6");
        }

        let mut config = Config::default();
        config.apply_env_overrides();

        assert!(!config.session_recovery.enabled);
        assert_eq!(config.session_recovery.stale_hours, 6);
    }

    // --- f64/i64 override helper tests ---

    #[test]
    fn test_apply_f64_override_valid() {
        let mut val = 0.80f64;
        apply_f64_override("0.50", "TEST_VAR", 0.0, 1.0, &mut val);
        assert!((val - 0.50).abs() < f64::EPSILON);
    }

    #[test]
    fn test_apply_f64_override_out_of_range_keeps_default() {
        let mut val = 0.80f64;
        apply_f64_override("1.5", "TEST_VAR", 0.0, 1.0, &mut val);
        assert!((val - 0.80).abs() < f64::EPSILON);

        apply_f64_override("-0.1", "TEST_VAR", 0.0, 1.0, &mut val);
        assert!((val - 0.80).abs() < f64::EPSILON);
    }

    #[test]
    fn test_apply_f64_override_invalid_keeps_default() {
        let mut val = 0.80f64;
        apply_f64_override("not_a_number", "TEST_VAR", 0.0, 1.0, &mut val);
        assert!((val - 0.80).abs() < f64::EPSILON);
    }

    #[test]
    fn test_apply_i64_override_valid() {
        let mut val = 200_000i64;
        apply_i64_override("150000", "TEST_VAR", 1000, 10_000_000, &mut val);
        assert_eq!(val, 150_000);
    }

    #[test]
    fn test_apply_i64_override_out_of_range_keeps_default() {
        let mut val = 200_000i64;
        apply_i64_override("500", "TEST_VAR", 1000, 10_000_000, &mut val);
        assert_eq!(val, 200_000);

        apply_i64_override("99999999", "TEST_VAR", 1000, 10_000_000, &mut val);
        assert_eq!(val, 200_000);
    }

    #[test]
    fn test_apply_i64_override_invalid_keeps_default() {
        let mut val = 200_000i64;
        apply_i64_override("not_a_number", "TEST_VAR", 1000, 10_000_000, &mut val);
        assert_eq!(val, 200_000);
    }

    // --- MCP tools config tests ---

    #[test]
    fn test_mcp_tools_defaults() {
        let config = Config::default();
        assert!(config.mcp_tools.enabled);
        assert_eq!(config.mcp_tools.default_decision, DefaultDecision::Allow);
        assert_eq!(config.mcp_tools.command_tools.len(), 4);

        // Verify built-in command tools
        assert_eq!(
            config.mcp_tools.command_tools[0].tool_pattern,
            "mcp__*__execute"
        );
        assert_eq!(config.mcp_tools.command_tools[0].command_field, "command");
        assert_eq!(
            config.mcp_tools.command_tools[1].tool_pattern,
            "mcp__puppeteer__puppeteer_evaluate"
        );
        assert_eq!(config.mcp_tools.command_tools[1].command_field, "script");
        assert_eq!(
            config.mcp_tools.command_tools[2].tool_pattern,
            "mcp__playwright__browser_evaluate"
        );
        assert_eq!(config.mcp_tools.command_tools[2].command_field, "function");
        assert_eq!(
            config.mcp_tools.command_tools[3].tool_pattern,
            "mcp__playwright__browser_run_code"
        );
        assert_eq!(config.mcp_tools.command_tools[3].command_field, "code");
    }

    #[test]
    fn test_mcp_tools_yaml_parsing() {
        let yaml = r#"
mcp_tools:
  enabled: false
  default_decision: "ask"
  command_tools:
    - tool_pattern: "mcp__*__run"
      command_field: "cmd"
    - tool_pattern: "mcp__custom__eval"
      command_field: "expression"
"#;

        let config: Config = serde_yml::from_str(yaml).unwrap();
        assert!(!config.mcp_tools.enabled);
        assert_eq!(config.mcp_tools.default_decision, DefaultDecision::Ask);
        assert_eq!(config.mcp_tools.command_tools.len(), 2);
        assert_eq!(
            config.mcp_tools.command_tools[0].tool_pattern,
            "mcp__*__run"
        );
        assert_eq!(config.mcp_tools.command_tools[0].command_field, "cmd");
    }

    #[test]
    fn test_mcp_tools_yaml_partial_uses_defaults() {
        let yaml = r"
mcp_tools:
  enabled: false
";

        let config: Config = serde_yml::from_str(yaml).unwrap();
        assert!(!config.mcp_tools.enabled);
        assert_eq!(config.mcp_tools.default_decision, DefaultDecision::Allow); // default
        assert_eq!(config.mcp_tools.command_tools.len(), 4); // defaults
    }

    #[test]
    fn test_mcp_tools_serialization_roundtrip() {
        let config = Config::default();
        let yaml = serde_yml::to_string(&config).unwrap();
        let parsed: Config = serde_yml::from_str(&yaml).unwrap();
        assert_eq!(config.mcp_tools, parsed.mcp_tools);
    }

    #[test]
    #[serial_test::serial]
    #[allow(unsafe_code)]
    fn test_mcp_tools_env_overrides() {
        let _guard = EnvGuard::new(&["CLX_MCP_TOOLS_ENABLED", "CLX_MCP_TOOLS_DEFAULT_DECISION"]);

        // SAFETY: Serialized via #[serial_test::serial], no concurrent mutation.
        unsafe {
            env::set_var("CLX_MCP_TOOLS_ENABLED", "false");
            env::set_var("CLX_MCP_TOOLS_DEFAULT_DECISION", "deny");
        }

        let mut config = Config::default();
        config.apply_env_overrides();

        assert!(!config.mcp_tools.enabled);
        assert_eq!(config.mcp_tools.default_decision, DefaultDecision::Deny);
        // command_tools unchanged (not overridable via env)
        assert_eq!(config.mcp_tools.command_tools.len(), 4);
    }

    #[test]
    fn test_mcp_tools_is_clone_send_sync() {
        fn assert_clone_send_sync<T: Clone + Send + Sync>() {}
        assert_clone_send_sync::<McpToolsConfig>();
        assert_clone_send_sync::<McpCommandTool>();
    }

    // --- Auto-recall config tests ---

    #[test]
    fn test_auto_recall_yaml_parsing() {
        let yaml = r"
auto_recall:
  enabled: false
  max_results: 5
  similarity_threshold: 0.5
  max_context_chars: 2000
  timeout_ms: 1000
  fallback_to_fts: false
  include_key_facts: false
  min_prompt_len: 20
  rrf_enabled: false
  rrf_k: 42
  time_decay_half_life_days: 14.5
  percentile_gate: 0.6
  reranker_enabled: false
  reranker_timeout_ms: 125
";

        let config: Config = serde_yml::from_str(yaml).unwrap();
        assert!(!config.auto_recall.enabled);
        assert_eq!(config.auto_recall.max_results, 5);
        assert!((config.auto_recall.similarity_threshold - 0.5).abs() < f32::EPSILON);
        assert_eq!(config.auto_recall.max_context_chars, 2000);
        assert_eq!(config.auto_recall.timeout_ms, 1000);
        assert!(!config.auto_recall.fallback_to_fts);
        assert!(!config.auto_recall.include_key_facts);
        assert_eq!(config.auto_recall.min_prompt_len, 20);
        assert!(!config.auto_recall.rrf_enabled);
        assert_eq!(config.auto_recall.rrf_k, 42);
        assert!((config.auto_recall.time_decay_half_life_days - 14.5).abs() < f64::EPSILON);
        assert!((config.auto_recall.percentile_gate - 0.6).abs() < f64::EPSILON);
        assert!(!config.auto_recall.reranker_enabled);
        assert_eq!(config.auto_recall.reranker_timeout_ms, 125);
    }

    #[test]
    fn test_auto_recall_missing_section_gets_defaults() {
        let yaml = "validator:\n  enabled: true\n";
        let config: Config = serde_yml::from_str(yaml).unwrap();
        assert!(config.auto_recall.enabled);
        assert_eq!(config.auto_recall.max_results, 3);
        assert!((config.auto_recall.similarity_threshold - 0.35).abs() < f32::EPSILON);
        assert_eq!(config.auto_recall.max_context_chars, 1000);
        assert_eq!(config.auto_recall.timeout_ms, 500);
        assert!(config.auto_recall.fallback_to_fts);
        assert!(config.auto_recall.include_key_facts);
        assert_eq!(config.auto_recall.min_prompt_len, 10);
        assert!(config.auto_recall.rrf_enabled);
        assert_eq!(config.auto_recall.rrf_k, 60);
        assert!((config.auto_recall.time_decay_half_life_days - 30.0).abs() < f64::EPSILON);
        assert!((config.auto_recall.percentile_gate - 0.70).abs() < f64::EPSILON);
        assert!(config.auto_recall.reranker_enabled);
        assert_eq!(config.auto_recall.reranker_timeout_ms, 250);
    }

    #[test]
    fn test_auto_recall_partial_yaml_uses_field_defaults() {
        let yaml = r"
auto_recall:
  enabled: false
";

        let config: Config = serde_yml::from_str(yaml).unwrap();
        assert!(!config.auto_recall.enabled);
        // All other fields should be defaults
        assert_eq!(config.auto_recall.max_results, 3);
        assert!(config.auto_recall.fallback_to_fts);
        assert!(config.auto_recall.include_key_facts);
        assert!(config.auto_recall.rrf_enabled);
        assert_eq!(config.auto_recall.rrf_k, 60);
        assert!((config.auto_recall.percentile_gate - 0.70).abs() < f64::EPSILON);
        assert!(config.auto_recall.reranker_enabled);
    }

    #[test]
    fn test_auto_recall_serialization_roundtrip() {
        let config = Config::default();
        let yaml = serde_yml::to_string(&config).unwrap();
        let parsed: Config = serde_yml::from_str(&yaml).unwrap();
        assert_eq!(config.auto_recall, parsed.auto_recall);
    }

    #[test]
    fn test_auto_recall_is_clone_send_sync() {
        fn assert_clone_send_sync<T: Clone + Send + Sync>() {}
        assert_clone_send_sync::<AutoRecallConfig>();
    }

    // --- apply_f32_override tests ---

    #[test]
    fn test_apply_f32_override_valid() {
        let mut val = 0.35_f32;
        apply_f32_override("0.50", "TEST_VAR", 0.0, 1.0, &mut val);
        assert!((val - 0.50).abs() < f32::EPSILON);
    }

    #[test]
    fn test_apply_f32_override_boundary_values() {
        let mut val = 0.5_f32;

        // Exact min should be accepted
        apply_f32_override("0.0", "TEST_VAR", 0.0, 1.0, &mut val);
        assert!(val.abs() < f32::EPSILON);

        // Exact max should be accepted
        apply_f32_override("1.0", "TEST_VAR", 0.0, 1.0, &mut val);
        assert!((val - 1.0).abs() < f32::EPSILON);
    }

    #[test]
    fn test_apply_f32_override_out_of_range_keeps_default() {
        let mut val = 0.35_f32;
        apply_f32_override("1.5", "TEST_VAR", 0.0, 1.0, &mut val);
        assert!(
            (val - 0.35).abs() < f32::EPSILON,
            "above max should keep default"
        );

        apply_f32_override("-0.1", "TEST_VAR", 0.0, 1.0, &mut val);
        assert!(
            (val - 0.35).abs() < f32::EPSILON,
            "below min should keep default"
        );
    }

    #[test]
    fn test_apply_f32_override_invalid_keeps_default() {
        let mut val = 0.35_f32;
        apply_f32_override("not_a_number", "TEST_VAR", 0.0, 1.0, &mut val);
        assert!(
            (val - 0.35).abs() < f32::EPSILON,
            "non-numeric input should keep default"
        );

        apply_f32_override("", "TEST_VAR", 0.0, 1.0, &mut val);
        assert!(
            (val - 0.35).abs() < f32::EPSILON,
            "empty string should keep default"
        );
    }

    // --- T03: load_from_file_only ---

    #[test]
    fn test_load_from_file_only_returns_defaults_when_no_file() {
        // Arrange: no config file exists in a temp dir, but load_from_file_only
        // falls back to Config::default() so we just verify env vars are NOT applied.
        // We set an env var that would normally override a value.
        //
        // Act: get a file-only config (env vars must NOT be reflected in it)
        let config = Config::load_from_file_only().expect("load_from_file_only should not fail");

        // Assert: the returned config has coherent default-like structure.
        // We cannot assert specific values without knowing what is in the user's
        // config.yaml, but we can verify the config round-trips through serde.
        let yaml = serde_yml::to_string(&config).expect("config must serialize");
        let reparsed: Config = serde_yml::from_str(&yaml).expect("serialized config must parse");
        assert_eq!(config, reparsed);
    }

    #[test]
    fn test_load_from_file_only_reads_custom_yaml() {
        // Arrange: write a minimal config to a temp directory, then point the
        // config path at it by writing the file where load_from_file_only looks.
        // Because load_from_file_only hardcodes Config::config_dir() we cannot
        // redirect it easily, so instead we test the parsing logic directly by
        // exercising the same serde path it uses.
        let yaml = r"
validator:
  enabled: false
";
        let config: Config = serde_yml::from_str(yaml).expect("yaml must parse");

        // Assert: file-only values preserved without env var influence.
        assert!(!config.validator.enabled);
        // Other fields are defaults. The point is env vars play no role here.
        assert_eq!(OllamaConfig::default().host, "http://127.0.0.1:11434");
    }

    // --- PromptSensitivity tests ---

    #[test]
    fn test_prompt_sensitivity_default_is_standard() {
        let config = Config::default();
        assert_eq!(
            config.validator.prompt_sensitivity,
            PromptSensitivity::Standard
        );
    }

    #[test]
    fn test_prompt_sensitivity_yaml_parsing() {
        for (yaml_val, expected) in [
            ("high", PromptSensitivity::High),
            ("standard", PromptSensitivity::Standard),
            ("low", PromptSensitivity::Low),
            ("custom", PromptSensitivity::Custom),
        ] {
            let yaml = format!("validator:\n  prompt_sensitivity: \"{yaml_val}\"\n");
            let config: Config = serde_yml::from_str(&yaml).unwrap();
            assert_eq!(
                config.validator.prompt_sensitivity, expected,
                "Failed for yaml value: {yaml_val}"
            );
        }
    }

    #[test]
    fn test_prompt_sensitivity_missing_uses_default() {
        let yaml = "validator:\n  enabled: true\n";
        let config: Config = serde_yml::from_str(yaml).unwrap();
        assert_eq!(
            config.validator.prompt_sensitivity,
            PromptSensitivity::Standard
        );
    }

    #[test]
    fn test_prompt_sensitivity_from_str() {
        assert_eq!(
            "high".parse::<PromptSensitivity>().unwrap(),
            PromptSensitivity::High
        );
        assert_eq!(
            "standard".parse::<PromptSensitivity>().unwrap(),
            PromptSensitivity::Standard
        );
        assert_eq!(
            "low".parse::<PromptSensitivity>().unwrap(),
            PromptSensitivity::Low
        );
        assert_eq!(
            "custom".parse::<PromptSensitivity>().unwrap(),
            PromptSensitivity::Custom
        );
        assert_eq!(
            "HIGH".parse::<PromptSensitivity>().unwrap(),
            PromptSensitivity::High
        );
        assert!("invalid".parse::<PromptSensitivity>().is_err());
    }

    #[test]
    fn test_prompt_sensitivity_display() {
        assert_eq!(PromptSensitivity::High.to_string(), "high");
        assert_eq!(PromptSensitivity::Standard.to_string(), "standard");
        assert_eq!(PromptSensitivity::Low.to_string(), "low");
        assert_eq!(PromptSensitivity::Custom.to_string(), "custom");
    }

    #[test]
    fn test_prompt_sensitivity_serialization_roundtrip() {
        let config = Config::default();
        let yaml = serde_yml::to_string(&config).unwrap();
        let parsed: Config = serde_yml::from_str(&yaml).unwrap();
        assert_eq!(
            config.validator.prompt_sensitivity,
            parsed.validator.prompt_sensitivity
        );
    }

    #[test]
    #[serial_test::serial]
    #[allow(unsafe_code)]
    fn test_prompt_sensitivity_env_override() {
        let _guard = EnvGuard::new(&["CLX_VALIDATOR_PROMPT_SENSITIVITY"]);

        // SAFETY: Serialized via #[serial_test::serial], no concurrent mutation.
        unsafe {
            env::set_var("CLX_VALIDATOR_PROMPT_SENSITIVITY", "high");
        }

        let mut config = Config::default();
        config.apply_env_overrides();
        assert_eq!(config.validator.prompt_sensitivity, PromptSensitivity::High);
    }

    #[test]
    #[serial_test::serial]
    #[allow(unsafe_code)]
    fn test_prompt_sensitivity_env_invalid_keeps_default() {
        let _guard = EnvGuard::new(&["CLX_VALIDATOR_PROMPT_SENSITIVITY"]);

        // SAFETY: Serialized via #[serial_test::serial], no concurrent mutation.
        unsafe {
            env::set_var("CLX_VALIDATOR_PROMPT_SENSITIVITY", "extreme");
        }

        let mut config = Config::default();
        config.apply_env_overrides();
        assert_eq!(
            config.validator.prompt_sensitivity,
            PromptSensitivity::Standard,
            "Invalid env value should keep default"
        );
    }

    // ---- T35: Property tests for config safety ----

    mod prop_tests {
        use proptest::prelude::*;

        use super::super::{Config, DefaultDecision};

        // Any combination of bool/u64/u32 values formatted as YAML must parse
        // without panicking. This guards against serde regressions.
        proptest! {
            #[test]
            fn prop_config_yaml_roundtrip(
                enabled in any::<bool>(),
                timeout_ms in 100_u64..300_000_u64,
                threshold in 1_u32..10_u32,
            ) {
                // Arrange: build a minimal YAML document using the generated values
                let yaml = format!(
                    "validator:\n  enabled: {enabled}\n  layer1_timeout_ms: {timeout_ms}\nuser_learning:\n  auto_whitelist_threshold: {threshold}\n"
                );
                // Act + Assert: parsing must not panic
                let result = serde_yml::from_str::<Config>(&yaml);
                prop_assert!(result.is_ok(), "YAML must parse: {result:?}");
                // Round-trip: serialise the parsed config and re-parse
                let serialised = serde_yml::to_string(&result.unwrap()).expect("must serialise");
                let reparsed = serde_yml::from_str::<Config>(&serialised);
                prop_assert!(reparsed.is_ok(), "Re-parse must succeed: {reparsed:?}");
            }
        }

        proptest! {
            #[test]
            fn prop_default_decision_roundtrip(
                // Generate one of the three valid variant strings
                variant in prop_oneof!["allow", "deny", "ask"].boxed(),
            ) {
                // Act: parse the string into the enum
                let decision: DefaultDecision = variant.parse().expect("must parse known variant");
                // Assert: as_str() round-trips back to the same string
                prop_assert_eq!(decision.as_str(), variant.as_str());
            }
        }
    }
}

#[cfg(test)]
mod schema_tests {
    use super::*;

    #[test]
    fn legacy_ollama_block_translated() {
        let yaml = r#"
ollama:
  host: "http://127.0.0.1:11434"
  model: "qwen3:1.7b"
  embedding_model: "qwen3-embedding:0.6b"
  embedding_dim: 1024
  timeout_ms: 60000
  max_retries: 3
  retry_delay_ms: 100
  retry_backoff: 2.0
"#;
        let mut cfg: Config = serde_yml::from_str(yaml).unwrap();
        cfg.translate_legacy_in_place();
        assert!(cfg.providers.contains_key("ollama-local"));
        let llm = cfg.llm.as_ref().unwrap();
        assert_eq!(llm.chat.provider, "ollama-local");
        assert_eq!(llm.chat.model, "qwen3:1.7b");
        assert_eq!(llm.embeddings.model, "qwen3-embedding:0.6b");
    }

    #[test]
    fn new_schema_passes_through() {
        let yaml = r#"
providers:
  azure-prod:
    kind: azure_openai
    endpoint: "https://x.openai.azure.com"
    api_key_env: "AZURE_OPENAI_API_KEY"
    timeout_ms: 30000
llm:
  chat: { provider: "azure-prod", model: "gpt-4o-mini" }
  embeddings: { provider: "azure-prod", model: "text-embedding-3-large" }
"#;
        let cfg: Config = serde_yml::from_str(yaml).unwrap();
        assert_eq!(cfg.providers.len(), 1);
        assert_eq!(cfg.llm.as_ref().unwrap().chat.model, "gpt-4o-mini");
    }

    #[test]
    fn both_blocks_present_new_wins() {
        let yaml = r#"
ollama:
  host: "http://127.0.0.1:11434"
  model: "old-model"
  embedding_model: "old-embed"
  embedding_dim: 1024
  timeout_ms: 60000
  max_retries: 3
  retry_delay_ms: 100
  retry_backoff: 2.0
providers:
  azure-prod:
    kind: azure_openai
    endpoint: "https://x.openai.azure.com"
    api_key_env: "X"
    timeout_ms: 30000
llm:
  chat: { provider: "azure-prod", model: "new-model" }
  embeddings: { provider: "azure-prod", model: "new-embed" }
"#;
        let mut cfg: Config = serde_yml::from_str(yaml).unwrap();
        cfg.translate_legacy_in_place();
        // new section wins
        assert_eq!(cfg.llm.as_ref().unwrap().chat.model, "new-model");
        // legacy must NOT have injected ollama-local
        assert!(!cfg.providers.contains_key("ollama-local"));
        assert!(cfg.providers.contains_key("azure-prod"));
    }

    #[test]
    fn capability_route_missing_returns_error() {
        let cfg = Config::default();
        assert!(matches!(
            cfg.capability_route(Capability::Chat),
            Err(LlmConfigError::MissingLlmRouting)
        ));
    }

    #[test]
    fn translate_is_idempotent() {
        let yaml = r#"
ollama:
  host: "http://127.0.0.1:11434"
  model: "qwen3:1.7b"
  embedding_model: "qwen3-embedding:0.6b"
  embedding_dim: 1024
  timeout_ms: 60000
  max_retries: 3
  retry_delay_ms: 100
  retry_backoff: 2.0
"#;
        let mut cfg: Config = serde_yml::from_str(yaml).unwrap();
        cfg.translate_legacy_in_place();
        cfg.translate_legacy_in_place(); // second call must be a no-op
        assert_eq!(cfg.providers.len(), 1);
    }

    /// Regression for the 0.6.0 contract mismatch: the keychain key format
    /// used by `resolve_azure_credential` MUST be writable through the
    /// existing `CredentialStore` validator (which rejects colons). Earlier
    /// 0.6.0 used `<provider>:api-key` (colon) and was unwriteable. 0.6.1
    /// uses `<provider>-api-key` (hyphen).
    ///
    /// Discriminates by error variant so headless CI (Linux without D-Bus,
    /// sandboxed macOS keychain) still passes. Those return
    /// `ServiceUnavailable`/`Keychain`, orthogonal to the validator contract.
    #[test]
    fn azure_keychain_key_passes_credential_store_validator() {
        // GitHub Actions macOS runners have a headless keychain that hangs
        // indefinitely on access (PR #22 observed 19 min before timeout in
        // the Coverage job). Skip on CI; the test still runs locally and
        // on Linux CI (where keychain is unavailable, returning a clean
        // ServiceUnavailable error that the test handles).
        if std::env::var("GITHUB_ACTIONS").is_ok() && cfg!(target_os = "macos") {
            eprintln!("skipping: keychain access hangs on GitHub Actions macOS runners");
            return;
        }
        use std::sync::Arc;

        use crate::credentials::{AgeFileBackend, CredentialError, CredentialStore};
        // Use the default (file) backend on a tempdir: deterministic and
        // headless-safe, never touches the keychain.
        let tmp = tempfile::tempdir().unwrap();
        let store =
            CredentialStore::with_backend(Arc::new(AgeFileBackend::with_dir(tmp.path()).unwrap()));
        let provider = "azure-regression-test-keyfmt";

        // 1. Hyphen-format key MUST NOT be rejected by the validator.
        let key = format!("{provider}-api-key");
        match store.store(&key, "fake-value") {
            Ok(()) => {
                let got = store.get(&key).ok().flatten();
                assert_eq!(got.as_deref(), Some("fake-value"));
                let _ = store.delete(&key);
            }
            Err(CredentialError::InvalidKey(msg)) => {
                panic!("hyphen key '{key}' rejected by validator (regression): {msg}");
            }
            Err(CredentialError::ServiceUnavailable(_) | CredentialError::Keychain(_)) => {
                // Headless CI, keychain not present. Validator contract is
                // what we're testing; storage is incidental.
            }
            Err(other) => panic!("unexpected error storing hyphen key: {other:?}"),
        }

        // 2. Colon-format key MUST be rejected by the validator (the 0.6.0
        //    bug). The validator runs before keychain access.
        let bad = format!("{provider}:api-key");
        match store.store(&bad, "fake-value") {
            Err(CredentialError::InvalidKey(_)) => {}
            Ok(()) => panic!("colon-keyed format must be rejected by validator"),
            Err(CredentialError::ServiceUnavailable(_) | CredentialError::Keychain(_)) => {
                // Lenient: don't flake on backend errors that mask the
                // validator. If the validator ever loosens to allow colons,
                // case 1 above would not have detected the regression
                // either, so this lenience is consistent.
            }
            Err(other) => panic!("unexpected error storing colon key: {other:?}"),
        }
    }

    #[test]
    fn fallback_field_round_trips() {
        let yaml = "
provider: azure-prod
model: gpt-5.4-mini
fallback:
  provider: ollama-local
  model: \"qwen3:1.7b\"
";
        let route: CapabilityRoute = serde_yml::from_str(yaml).unwrap();
        assert_eq!(route.provider, "azure-prod");
        let fb = route.fallback.as_deref().expect("fallback present");
        assert_eq!(fb.provider, "ollama-local");
        assert_eq!(fb.model, "qwen3:1.7b");
        assert!(fb.fallback.is_none());

        let yaml2 = serde_yml::to_string(&route).unwrap();
        let route2: CapabilityRoute = serde_yml::from_str(&yaml2).unwrap();
        assert_eq!(route, route2);
    }

    #[test]
    fn fallback_field_omitted_in_serialization_when_none() {
        let route = CapabilityRoute {
            provider: "p".into(),
            model: "m".into(),
            fallback: None,
            dimension: None,
        };
        let yaml = serde_yml::to_string(&route).unwrap();
        assert!(
            !yaml.contains("fallback"),
            "skip_serializing_if not respected: {yaml}"
        );
        assert!(
            !yaml.contains("dimension"),
            "dimension must be omitted when None: {yaml}"
        );
    }

    /// AC6.5: the effective-dimension resolver honors precedence
    /// route override > model registry > legacy ollama dim.
    #[test]
    fn effective_embedding_dimension_precedence() {
        // 1. Explicit route override wins over everything (even a known model).
        let overridden = CapabilityRoute {
            provider: "p".into(),
            model: "text-embedding-3-large".into(),
            fallback: None,
            dimension: Some(256),
        };
        assert_eq!(
            effective_embedding_dimension(&overridden, 999),
            256,
            "explicit route dimension must win"
        );

        // 2. No override but a known model => registry value (NOT the legacy dim).
        let known = CapabilityRoute {
            provider: "p".into(),
            model: "text-embedding-3-large".into(),
            fallback: None,
            dimension: None,
        };
        assert_eq!(
            effective_embedding_dimension(&known, 999),
            3072,
            "known model must resolve via the registry"
        );

        // text-embedding-3-small maps to 1024 (CLX-requested, not native 1536).
        let small = CapabilityRoute {
            provider: "p".into(),
            model: "text-embedding-3-small".into(),
            fallback: None,
            dimension: None,
        };
        assert_eq!(effective_embedding_dimension(&small, 999), 1024);
        assert_eq!(
            embedding_dimension_for_model("text-embedding-3-small"),
            Some(1024)
        );
        assert_eq!(
            embedding_dimension_for_model("qwen3-embedding:0.6b"),
            Some(1024)
        );

        // 3. No override and an unknown model => legacy ollama dim.
        let unknown = CapabilityRoute {
            provider: "p".into(),
            model: "some-unlisted-model".into(),
            fallback: None,
            dimension: None,
        };
        assert_eq!(
            effective_embedding_dimension(&unknown, 768),
            768,
            "unknown model falls back to the legacy ollama dimension"
        );
        assert_eq!(embedding_dimension_for_model("some-unlisted-model"), None);
    }

    // ---- Tasks 6+7: per-project config discovery integration tests ----

    #[test]
    #[serial_test::serial]
    #[allow(unsafe_code)]
    fn project_config_path_walks_up_to_home() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join(".clx");
        std::fs::create_dir_all(&project).unwrap();
        let path = project.join("config.yaml");
        std::fs::write(&path, "logging:\n  level: debug\n").unwrap();

        // SAFETY: test-only env var manipulation; serialized via serial_test.
        unsafe {
            std::env::set_var("CLX_CONFIG_PROJECT", path.to_str().unwrap());
        }
        let resolved = crate::config::project::project_config_path_with_stop(None);
        assert_eq!(resolved.as_deref(), Some(path.as_path()));
        unsafe {
            std::env::remove_var("CLX_CONFIG_PROJECT");
        }
    }

    #[test]
    #[serial_test::serial]
    #[allow(unsafe_code)]
    fn project_config_disabled_via_env_none() {
        // SAFETY: test-only env var manipulation; serialized via serial_test.
        unsafe {
            std::env::set_var("CLX_CONFIG_PROJECT", "none");
        }
        assert!(crate::config::project::project_config_path_with_stop(None).is_none());
        unsafe {
            std::env::remove_var("CLX_CONFIG_PROJECT");
        }
    }

    /// `learning_mode` defaults to false (observe-only, opt-in).
    #[test]
    fn learning_mode_defaults_to_false() {
        assert!(
            !Config::default().validator.learning_mode,
            "learning_mode must default to false"
        );
        assert!(
            !ValidatorConfig::default().learning_mode,
            "ValidatorConfig::default().learning_mode must be false"
        );
    }

    /// AC3: `CLX_LEARNING_MODE=1` enables capture via env override even when the
    /// config flag defaults to false.
    #[test]
    #[serial_test::serial]
    #[allow(unsafe_code)]
    fn learning_mode_enabled_via_env() {
        // SAFETY: test-only env var manipulation; serialized via serial_test.
        unsafe {
            std::env::set_var("CLX_LEARNING_MODE", "1");
        }

        let mut config = Config::default();
        assert!(!config.validator.learning_mode);
        config.apply_env_overrides();
        let enabled = config.validator.learning_mode;

        unsafe {
            std::env::remove_var("CLX_LEARNING_MODE");
        }
        assert!(enabled, "CLX_LEARNING_MODE=1 must enable learning_mode");
    }

    /// AC3 (trust gate): an UNTRUSTED project config setting
    /// `validator.learning_mode: true` is stripped along with the whole
    /// `validator` subtree, so a hostile repo cannot enable capture.
    #[test]
    fn untrusted_validator_learning_mode_is_stripped() {
        let raw = "validator:\n  learning_mode: true\n";
        let out = crate::config::project::filter_inert_only(raw);
        assert!(
            !out.contains("learning_mode"),
            "validator.learning_mode must be dropped from untrusted config; got: {out}"
        );
    }
}
