//! Shared type definitions for CLX
//!
//! Domain types for sessions, snapshots, events, audit logs, and learned rules.

use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::str::FromStr;

/// A validated session identifier.
///
/// Wraps a `String` to provide type safety at API boundaries.
/// Validation is performed at the storage layer (`validate_session_id`),
/// not in the constructor, so `SessionId::new` is suitable for trusted
/// sources such as database reads and internal construction.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SessionId(String);

impl SessionId {
    /// Create a new `SessionId` from a string, without validation.
    /// Use this for trusted sources (database reads, internal construction).
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Get the underlying string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume and return the inner String.
    #[must_use]
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl AsRef<str> for SessionId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for SessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl From<String> for SessionId {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for SessionId {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl rusqlite::types::FromSql for SessionId {
    fn column_result(value: rusqlite::types::ValueRef<'_>) -> rusqlite::types::FromSqlResult<Self> {
        let s = String::column_result(value)?;
        Ok(SessionId(s))
    }
}

impl rusqlite::types::ToSql for SessionId {
    fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput<'_>> {
        self.0.to_sql()
    }
}

/// Trust mode token stored at `~/.clx/.trust_mode_token`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustToken {
    /// When trust mode was enabled (UTC ISO 8601)
    pub enabled_at: String,
    /// When trust mode expires (UTC ISO 8601)
    pub expires_at: String,
    /// Duration in seconds
    pub duration_secs: u64,
    /// Optional session ID restriction
    pub session_id: Option<String>,
    /// How trust mode was enabled
    pub enabled_by: String,
}

/// Command execution request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandRequest {
    /// The command to execute
    pub command: String,

    /// Working directory
    pub cwd: Option<String>,

    /// Environment variables
    pub env: Option<HashMap<String, String>>,

    /// Session ID for context
    pub session_id: Option<SessionId>,
}

/// Command execution response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandResponse {
    /// Whether the command was allowed
    pub allowed: bool,

    /// If blocked, the reason
    pub block_reason: Option<String>,

    /// Validated/modified command (if any)
    pub validated_command: Option<String>,

    /// Additional context to inject
    pub context: Option<serde_json::Value>,
}

/// Session status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum SessionStatus {
    #[default]
    Active,
    Ended,
    Abandoned,
}

impl SessionStatus {
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Ended => "ended",
            Self::Abandoned => "abandoned",
        }
    }

    #[must_use]
    pub fn parse(s: &str) -> Self {
        s.parse().unwrap_or_default()
    }
}

impl FromStr for SessionStatus {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "active" => Ok(Self::Active),
            "ended" => Ok(Self::Ended),
            "abandoned" => Ok(Self::Abandoned),
            _ => Err(format!("Unknown session status: '{s}'")),
        }
    }
}

/// Session source (how the session was started)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum SessionSource {
    #[default]
    Startup,
    Resume,
    Manual,
}

impl SessionSource {
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Startup => "startup",
            Self::Resume => "resume",
            Self::Manual => "manual",
        }
    }

    #[must_use]
    pub fn parse(s: &str) -> Self {
        s.parse().unwrap_or_default()
    }
}

impl FromStr for SessionSource {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "startup" => Ok(Self::Startup),
            "resume" => Ok(Self::Resume),
            "manual" => Ok(Self::Manual),
            _ => Err(format!("Unknown session source: '{s}'")),
        }
    }
}

/// Session information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    /// Unique session ID
    pub id: SessionId,

    /// Project path this session is associated with
    pub project_path: String,

    /// Path to transcript file (if any)
    pub transcript_path: Option<String>,

    /// When the session was created
    pub started_at: DateTime<Utc>,

    /// When the session ended (if ended)
    pub ended_at: Option<DateTime<Utc>>,

    /// How the session was started
    pub source: SessionSource,

    /// Number of messages in the session
    pub message_count: i32,

    /// Number of commands executed
    pub command_count: i32,

    /// Estimated input tokens (user messages)
    pub input_tokens: i64,

    /// Estimated output tokens (assistant messages)
    pub output_tokens: i64,

    /// Session status
    pub status: SessionStatus,
}

impl Session {
    /// Create a new session with default values
    #[must_use]
    pub fn new(id: SessionId, project_path: String) -> Self {
        Self {
            id,
            project_path,
            transcript_path: None,
            started_at: Utc::now(),
            ended_at: None,
            source: SessionSource::Startup,
            message_count: 0,
            command_count: 0,
            input_tokens: 0,
            output_tokens: 0,
            status: SessionStatus::Active,
        }
    }
}

/// Estimate tokens from text (~4 characters = 1 token)
///
/// Uses saturating arithmetic to prevent overflow when converting from
/// `usize` (string length) to `i64`.
#[must_use]
pub fn estimate_tokens(text: &str) -> i64 {
    // Simple estimation: ~4 characters per token on average
    // This is a rough approximation that works reasonably well for English text
    let len = text.len();
    let len_i64 = i64::try_from(len).unwrap_or(i64::MAX);
    len_i64.saturating_add(3) / 4
}

/// Claude Sonnet input price per million tokens (as of 2026-02).
/// Update when Anthropic changes pricing: <https://docs.anthropic.com/en/docs/about-claude/pricing>
pub const INPUT_PRICE_PER_MTOK: f64 = 3.0;

/// Claude Sonnet output price per million tokens (as of 2026-02).
/// Update when Anthropic changes pricing: <https://docs.anthropic.com/en/docs/about-claude/pricing>
pub const OUTPUT_PRICE_PER_MTOK: f64 = 15.0;

/// Estimate cost based on token counts using configured pricing constants.
#[must_use]
pub fn estimate_cost(input_tokens: i64, output_tokens: i64) -> f64 {
    let input_cost = (input_tokens as f64 / 1_000_000.0) * INPUT_PRICE_PER_MTOK;
    let output_cost = (output_tokens as f64 / 1_000_000.0) * OUTPUT_PRICE_PER_MTOK;
    input_cost + output_cost
}

/// Snapshot trigger type
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum SnapshotTrigger {
    Manual,
    #[default]
    Auto,
    Checkpoint,
    Resume,
    ContextPressure,
}

impl SnapshotTrigger {
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Manual => "manual",
            Self::Auto => "auto",
            Self::Checkpoint => "checkpoint",
            Self::Resume => "resume",
            Self::ContextPressure => "context_pressure",
        }
    }

    #[must_use]
    pub fn parse(s: &str) -> Self {
        s.parse().unwrap_or_default()
    }
}

impl FromStr for SnapshotTrigger {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "manual" => Ok(Self::Manual),
            "auto" => Ok(Self::Auto),
            "checkpoint" => Ok(Self::Checkpoint),
            "resume" => Ok(Self::Resume),
            "context_pressure" => Ok(Self::ContextPressure),
            _ => Err(format!("Unknown snapshot trigger: '{s}'")),
        }
    }
}

/// A session snapshot capturing context at a point in time
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    /// Snapshot ID (auto-generated)
    pub id: Option<i64>,

    /// Session this snapshot belongs to
    pub session_id: SessionId,

    /// When the snapshot was created
    pub created_at: DateTime<Utc>,

    /// What triggered this snapshot
    pub trigger: SnapshotTrigger,

    /// Summary of the session state
    pub summary: Option<String>,

    /// Key facts extracted from the session
    pub key_facts: Option<String>,

    /// Pending TODOs
    pub todos: Option<String>,

    /// Message count at snapshot time
    pub message_count: Option<i32>,

    /// Estimated input tokens at snapshot time
    pub input_tokens: Option<i64>,

    /// Estimated output tokens at snapshot time
    pub output_tokens: Option<i64>,
}

impl Snapshot {
    /// Create a new snapshot
    #[must_use]
    pub fn new(session_id: SessionId, trigger: SnapshotTrigger) -> Self {
        Self {
            id: None,
            session_id,
            created_at: Utc::now(),
            trigger,
            summary: None,
            key_facts: None,
            todos: None,
            message_count: None,
            input_tokens: None,
            output_tokens: None,
        }
    }
}

/// Event type for session events
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    ToolUse,
    ToolResult,
    #[default]
    Message,
    Command,
    Error,
}

impl EventType {
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ToolUse => "tool_use",
            Self::ToolResult => "tool_result",
            Self::Message => "message",
            Self::Command => "command",
            Self::Error => "error",
        }
    }

    #[must_use]
    pub fn parse(s: &str) -> Self {
        s.parse().unwrap_or_default()
    }
}

impl FromStr for EventType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "tool_use" => Ok(Self::ToolUse),
            "tool_result" => Ok(Self::ToolResult),
            "message" => Ok(Self::Message),
            "command" => Ok(Self::Command),
            "error" => Ok(Self::Error),
            _ => Err(format!("Unknown event type: '{s}'")),
        }
    }
}

/// A session event (tool use, message, etc.)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    /// Event ID (auto-generated)
    pub id: Option<i64>,

    /// Session this event belongs to
    pub session_id: SessionId,

    /// When the event occurred
    pub timestamp: DateTime<Utc>,

    /// Type of event
    pub event_type: EventType,

    /// Tool name (if applicable)
    pub tool_name: Option<String>,

    /// Tool use ID (if applicable)
    pub tool_use_id: Option<String>,

    /// Tool input (JSON string)
    pub tool_input: Option<String>,

    /// Tool output (JSON string)
    pub tool_output: Option<String>,
}

impl Event {
    /// Create a new event
    #[must_use]
    pub fn new(session_id: SessionId, event_type: EventType) -> Self {
        Self {
            id: None,
            session_id,
            timestamp: Utc::now(),
            event_type,
            tool_name: None,
            tool_use_id: None,
            tool_input: None,
            tool_output: None,
        }
    }
}

/// Audit decision type
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum AuditDecision {
    #[default]
    Allowed,
    Blocked,
    Prompted,
}

impl AuditDecision {
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Allowed => "allowed",
            Self::Blocked => "blocked",
            Self::Prompted => "prompted",
        }
    }

    #[must_use]
    pub fn parse(s: &str) -> Self {
        s.parse().unwrap_or_default()
    }
}

impl FromStr for AuditDecision {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "allowed" => Ok(Self::Allowed),
            "blocked" => Ok(Self::Blocked),
            "prompted" => Ok(Self::Prompted),
            _ => Err(format!("Unknown audit decision: '{s}'")),
        }
    }
}

/// User decision on a prompted command
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum UserDecision {
    #[default]
    Approved,
    Denied,
    ApprovedAlways,
    DeniedAlways,
}

impl UserDecision {
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Approved => "approved",
            Self::Denied => "denied",
            Self::ApprovedAlways => "approved_always",
            Self::DeniedAlways => "denied_always",
        }
    }

    #[must_use]
    pub fn parse(s: &str) -> Self {
        s.parse().unwrap_or_default()
    }
}

impl FromStr for UserDecision {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "approved" => Ok(Self::Approved),
            "denied" => Ok(Self::Denied),
            "approved_always" => Ok(Self::ApprovedAlways),
            "denied_always" => Ok(Self::DeniedAlways),
            _ => Err(format!("Unknown user decision: '{s}'")),
        }
    }
}

/// An audit log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogEntry {
    /// Entry ID (auto-generated)
    pub id: Option<i64>,

    /// Session this entry belongs to
    pub session_id: SessionId,

    /// When the audit occurred
    pub timestamp: DateTime<Utc>,

    /// The command that was audited
    pub command: String,

    /// Working directory
    pub working_dir: Option<String>,

    /// Policy layer that made the decision
    pub layer: String,

    /// The decision made
    pub decision: AuditDecision,

    /// Risk score (0-100)
    pub risk_score: Option<i32>,

    /// Reasoning for the decision
    pub reasoning: Option<String>,

    /// User's decision (if prompted)
    pub user_decision: Option<UserDecision>,
}

impl AuditLogEntry {
    /// Create a new audit log entry
    #[must_use]
    pub fn new(
        session_id: SessionId,
        command: String,
        layer: String,
        decision: AuditDecision,
    ) -> Self {
        Self {
            id: None,
            session_id,
            timestamp: Utc::now(),
            command,
            working_dir: None,
            layer,
            decision,
            risk_score: None,
            reasoning: None,
            user_decision: None,
        }
    }
}

/// Learned rule type
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum RuleType {
    #[default]
    Allow,
    Deny,
}

impl RuleType {
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
        }
    }

    #[must_use]
    pub fn parse(s: &str) -> Self {
        s.parse().unwrap_or_default()
    }
}

impl FromStr for RuleType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "allow" => Ok(Self::Allow),
            "deny" => Ok(Self::Deny),
            _ => Err(format!("Unknown rule type: '{s}'")),
        }
    }
}

/// A learned rule from user decisions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LearnedRule {
    /// Rule ID (auto-generated)
    pub id: Option<i64>,

    /// Pattern to match (glob or regex)
    pub pattern: String,

    /// Type of rule
    pub rule_type: RuleType,

    /// When the rule was learned
    pub learned_at: DateTime<Utc>,

    /// Source of the rule (e.g., "`user_decision`")
    pub source: String,

    /// Number of times confirmed
    pub confirmation_count: i32,

    /// Number of times denied
    pub denial_count: i32,

    /// Project path this rule applies to (None for global)
    pub project_path: Option<String>,
}

impl LearnedRule {
    /// Create a new learned rule
    #[must_use]
    pub fn new(pattern: String, rule_type: RuleType, source: String) -> Self {
        Self {
            id: None,
            pattern,
            rule_type,
            learned_at: Utc::now(),
            source,
            confirmation_count: 0,
            denial_count: 0,
            project_path: None,
        }
    }
}

/// An analytics metric entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalyticsEntry {
    /// Entry ID (auto-generated)
    pub id: Option<i64>,

    /// Date of the metric
    pub date: NaiveDate,

    /// Project path (None for global)
    pub project_path: Option<String>,

    /// Metric name
    pub metric_name: String,

    /// Metric value
    pub metric_value: i64,
}

impl AnalyticsEntry {
    /// Create a new analytics entry
    #[must_use]
    pub fn new(date: NaiveDate, metric_name: String, metric_value: i64) -> Self {
        Self {
            id: None,
            date,
            project_path: None,
            metric_name,
            metric_value,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- M3: Token estimation overflow tests ---

    #[test]
    fn test_estimate_tokens_empty() {
        assert_eq!(estimate_tokens(""), 0);
    }

    #[test]
    fn test_estimate_tokens_short_text() {
        // "hello" = 5 chars -> (5+3)/4 = 2
        assert_eq!(estimate_tokens("hello"), 2);
    }

    #[test]
    fn test_estimate_tokens_exact_multiple() {
        // 8 chars -> (8+3)/4 = 2
        assert_eq!(estimate_tokens("12345678"), 2);
    }

    #[test]
    fn test_estimate_tokens_single_char() {
        // 1 char -> (1+3)/4 = 1
        assert_eq!(estimate_tokens("a"), 1);
    }

    #[test]
    fn test_estimate_tokens_returns_positive() {
        // Any non-empty string should return > 0
        assert!(estimate_tokens("x") > 0);
        assert!(estimate_tokens("test string with multiple words") > 0);
    }

    #[test]
    fn test_estimate_tokens_no_panic_on_large_string() {
        // Test with a moderately large string to verify no overflow in normal range
        let large = "a".repeat(1_000_000);
        let tokens = estimate_tokens(&large);
        assert_eq!(tokens, 250_000); // 1_000_000 + 3 / 4 = 250_000
    }

    #[test]
    fn test_estimate_cost_zero() {
        assert!((estimate_cost(0, 0) - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_estimate_cost_calculation() {
        // 1M input tokens = $3.00, 1M output tokens = $15.00
        let cost = estimate_cost(1_000_000, 1_000_000);
        assert!((cost - 18.0).abs() < f64::EPSILON);
    }

    // --- SessionId newtype tests ---

    #[test]
    fn test_session_id_display() {
        let id = SessionId::new("test-123");
        assert_eq!(id.to_string(), "test-123");
        assert_eq!(id.as_str(), "test-123");
    }

    #[test]
    fn test_session_id_serde_roundtrip() {
        let id = SessionId::new("abc-def");
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, "\"abc-def\"");
        let deserialized: SessionId = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, id);
    }

    #[test]
    fn test_session_id_from_conversions() {
        let id1 = SessionId::from("hello");
        let id2 = SessionId::from(String::from("hello"));
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_session_id_into_inner() {
        let id = SessionId::new("inner-test");
        let inner: String = id.into_inner();
        assert_eq!(inner, "inner-test");
    }

    #[test]
    fn test_session_id_as_ref() {
        let id = SessionId::new("ref-test");
        let s: &str = id.as_ref();
        assert_eq!(s, "ref-test");
    }

    // --- Type serialization/parsing tests ---

    #[test]
    fn test_session_status_roundtrip() {
        for status in [
            SessionStatus::Active,
            SessionStatus::Ended,
            SessionStatus::Abandoned,
        ] {
            assert_eq!(SessionStatus::parse(status.as_str()), status);
        }
    }

    #[test]
    fn test_session_source_roundtrip() {
        for source in [
            SessionSource::Startup,
            SessionSource::Resume,
            SessionSource::Manual,
        ] {
            assert_eq!(SessionSource::parse(source.as_str()), source);
        }
    }

    #[test]
    fn test_snapshot_trigger_roundtrip() {
        for trigger in [
            SnapshotTrigger::Manual,
            SnapshotTrigger::Auto,
            SnapshotTrigger::Checkpoint,
            SnapshotTrigger::Resume,
            SnapshotTrigger::ContextPressure,
        ] {
            assert_eq!(SnapshotTrigger::parse(trigger.as_str()), trigger);
        }
    }

    #[test]
    fn test_event_type_roundtrip() {
        for et in [
            EventType::ToolUse,
            EventType::ToolResult,
            EventType::Message,
            EventType::Command,
            EventType::Error,
        ] {
            assert_eq!(EventType::parse(et.as_str()), et);
        }
    }
}
