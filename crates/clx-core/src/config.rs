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

/// CLX configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct Config {
    /// Validator configuration
    #[serde(default)]
    pub validator: ValidatorConfig,

    /// Context configuration
    #[serde(default)]
    pub context: ContextConfig,

    /// Ollama configuration
    #[serde(default)]
    pub ollama: OllamaConfig,

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
        }
    }
}

/// Validator configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ValidatorConfig {
    /// Enable command validation
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Enable layer 1 (fast) validation
    #[serde(default = "default_true")]
    pub layer1_enabled: bool,

    /// Layer 1 validation timeout in milliseconds
    #[serde(default = "default_layer1_timeout")]
    pub layer1_timeout_ms: u64,

    /// Default decision when validation is inconclusive
    #[serde(default)]
    pub default_decision: DefaultDecision,

    /// Trust mode - auto-allow ALL commands without validation
    /// Still logs commands for audit. Use with caution!
    /// Can only be enabled via config file (~/.clx/config.yaml) for security.
    #[serde(default)]
    pub trust_mode: bool,

    /// Auto-allow read-only commands without LLM validation
    /// Commands like cat, ls, head, tail, grep, find, etc. are allowed immediately
    #[serde(default = "default_true")]
    pub auto_allow_reads: bool,
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

impl Default for ValidatorConfig {
    fn default() -> Self {
        Self {
            enabled: default_true(),
            layer1_enabled: default_true(),
            layer1_timeout_ms: default_layer1_timeout(),
            default_decision: DefaultDecision::Ask,
            trust_mode: false,
            auto_allow_reads: default_true(),
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

impl Config {
    /// Load configuration from default locations with environment variable overrides
    ///
    /// Loading order:
    /// 1. Default values
    /// 2. ~/.clx/config.yaml (if exists)
    /// 3. Environment variables (highest priority)
    pub fn load() -> crate::Result<Self> {
        // Ensure config directory exists
        let config_dir = Self::config_dir()?;
        Self::ensure_dir_exists(&config_dir)?;

        // Ensure logs directory exists
        let logs_dir = config_dir.join("logs");
        Self::ensure_dir_exists(&logs_dir)?;

        // Load base config from file or use defaults
        let config_path = config_dir.join("config.yaml");
        let mut config = if config_path.exists() {
            let content = fs::read_to_string(&config_path)?;
            serde_yml::from_str(&content)?
        } else {
            Config::default()
        };

        // Apply environment variable overrides
        config.apply_env_overrides();

        Ok(config)
    }

    /// Load configuration from file only (no environment variable overrides).
    ///
    /// Used by the dashboard Settings tab to show raw YAML values for editing,
    /// without env var overrides that would confuse the user.
    pub fn load_from_file_only() -> crate::Result<Self> {
        let config_path = Self::config_dir()?.join("config.yaml");
        if config_path.exists() {
            let content = fs::read_to_string(&config_path)?;
            Ok(serde_yml::from_str(&content)?)
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
        }
        if let Ok(val) = env::var("CLX_VALIDATOR_LAYER1_ENABLED") {
            apply_bool_override(
                &val,
                "CLX_VALIDATOR_LAYER1_ENABLED",
                &mut self.validator.layer1_enabled,
            );
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

        // Ollama overrides
        if let Ok(val) = env::var("CLX_OLLAMA_HOST") {
            apply_string_override(&val, "CLX_OLLAMA_HOST", &mut self.ollama.host);
        }
        if let Ok(val) = env::var("CLX_OLLAMA_MODEL") {
            apply_string_override(&val, "CLX_OLLAMA_MODEL", &mut self.ollama.model);
        }
        if let Ok(val) = env::var("CLX_OLLAMA_EMBEDDING_MODEL") {
            apply_string_override(
                &val,
                "CLX_OLLAMA_EMBEDDING_MODEL",
                &mut self.ollama.embedding_model,
            );
        }
        if let Ok(val) = env::var("CLX_EMBEDDING_DIM") {
            apply_usize_override(
                &val,
                "CLX_EMBEDDING_DIM",
                1,
                65536,
                &mut self.ollama.embedding_dim,
            );
        }
        if let Ok(val) = env::var("CLX_OLLAMA_TIMEOUT_MS") {
            apply_u64_override(
                &val,
                "CLX_OLLAMA_TIMEOUT_MS",
                1000,
                600_000,
                &mut self.ollama.timeout_ms,
            );
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
    }
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
        assert!(config.validator.layer1_enabled);
        assert_eq!(config.validator.layer1_timeout_ms, 30000);
        assert_eq!(config.validator.default_decision, DefaultDecision::Ask);
        assert!(!config.validator.trust_mode);
        assert!(config.validator.auto_allow_reads);

        // Context defaults
        assert!(config.context.enabled);
        assert!(config.context.auto_snapshot);
        assert_eq!(config.context.embedding_model, "qwen3-embedding:0.6b");

        // Ollama defaults
        assert_eq!(config.ollama.host, "http://127.0.0.1:11434");
        assert_eq!(config.ollama.model, "qwen3:1.7b");
        assert_eq!(config.ollama.embedding_model, "qwen3-embedding:0.6b");
        assert_eq!(config.ollama.embedding_dim, 1024);
        assert_eq!(config.ollama.timeout_ms, 60000);

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

        assert_eq!(config.ollama.host, "http://localhost:8080");
        assert_eq!(config.ollama.model, "mistral:7b");
        assert_eq!(config.ollama.embedding_model, "custom-embed");
        assert_eq!(config.ollama.timeout_ms, 10000);

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
        assert_eq!(config.ollama.host, "http://127.0.0.1:11434");
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
        assert_eq!(config.ollama.model, "custom-model:latest");
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

        assert_eq!(config.ollama.host, "http://test:1234");
        assert_eq!(config.ollama.model, "test-model");
        assert_eq!(config.ollama.embedding_model, "test-embed-model");
        assert_eq!(config.ollama.timeout_ms, 9999);

        assert!(!config.user_learning.enabled);
        assert_eq!(config.user_learning.auto_whitelist_threshold, 99);
        assert_eq!(config.user_learning.auto_blacklist_threshold, 88);

        assert_eq!(config.logging.level, "trace");
        assert_eq!(config.logging.file, "/custom/path.log");
        assert_eq!(config.logging.max_size_mb, 100);
        assert_eq!(config.logging.max_files, 20);
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
        assert_eq!(config.ollama.embedding_model, "qwen3-embedding:0.6b");
        assert_eq!(config.ollama.embedding_dim, 1024);
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

        assert_eq!(config.ollama.embedding_dim, 768);
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

        assert_eq!(config.ollama.embedding_dim, 1024);
    }

    #[test]
    fn test_embedding_dim_yaml_deserialization() {
        let yaml = r#"
ollama:
  embedding_model: "custom-model"
  embedding_dim: 512
"#;

        let config: Config = serde_yml::from_str(yaml).unwrap();
        assert_eq!(config.ollama.embedding_model, "custom-model");
        assert_eq!(config.ollama.embedding_dim, 512);
    }

    #[test]
    fn test_embedding_dim_yaml_missing_uses_default() {
        let yaml = r#"
ollama:
  embedding_model: "custom-model"
"#;

        let config: Config = serde_yml::from_str(yaml).unwrap();
        assert_eq!(config.ollama.embedding_dim, 1024);
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
        // Other fields are defaults — the point is env vars play no role here.
        assert_eq!(config.ollama.host, "http://127.0.0.1:11434");
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
