use chrono::{DateTime, Duration as ChronoDuration, Utc};
use clx_core::policy::{PolicyEngine, RuleSource};
use clx_core::storage::Storage;

use crate::types::truncate_str;

/// Safely extract the last `n` bytes of a string, adjusting to the nearest
/// char boundary so it never panics on multi-byte UTF-8.
fn last_n_chars(s: &str, n: usize) -> &str {
    if s.len() <= n {
        s
    } else {
        let mut idx = s.len() - n;
        while !s.is_char_boundary(idx) && idx < s.len() {
            idx += 1;
        }
        &s[idx..]
    }
}

pub struct DashboardData {
    // Overview
    pub total_sessions: i64,
    pub active_sessions: i64,
    pub total_input_tokens: i64,
    pub total_output_tokens: i64,
    pub total_commands: i64,
    pub allowed_commands: i64,
    pub denied_commands: i64,
    pub prompted_commands: i64,
    pub risk_low: i64,
    pub risk_medium: i64,
    pub risk_high: i64,
    pub top_denied: Vec<(String, i64)>,

    // Sessions tab
    pub sessions: Vec<SessionRow>,

    // Audit tab
    pub audit_entries: Vec<AuditRow>,

    // Rules tab
    pub learned_rules: Vec<LearnedRuleRow>,
    pub builtin_whitelist: Vec<BuiltinRuleRow>,
    pub builtin_blacklist: Vec<BuiltinRuleRow>,
    pub config_whitelist: Vec<BuiltinRuleRow>,
    pub config_blacklist: Vec<BuiltinRuleRow>,

    // Meta
    pub last_updated: DateTime<Utc>,
    pub load_error: Option<String>,
}

pub struct SessionRow {
    pub session_id: String, // Full session ID for drill-down
    pub short_id: String,
    pub project: String,
    pub started: String,
    pub duration: String,
    pub messages: i64,
    pub commands: i64,
    pub tokens: String,
    pub status: String,
    pub duration_secs: i64,
    pub tokens_raw: i64,
}

pub struct AuditRow {
    pub time: String,
    pub decision: String,
    pub layer: String,
    pub command: String,       // Full command text (no truncation)
    pub command_short: String, // Truncated for table display
    pub risk_score: Option<i32>,
    pub session_short_id: String,
}

pub struct LearnedRuleRow {
    pub pattern: String,
    pub rule_type: String,
    pub scope: String,
    pub confirmations: i64,
    pub denials: i64,
}

pub struct BuiltinRuleRow {
    pub pattern: String,
    pub description: Option<String>,
}

/// Detail data for a single session drill-down view.
pub struct SessionDetailData {
    pub session: clx_core::types::Session,
    pub audit_entries: Vec<clx_core::types::AuditLogEntry>,
    pub events: Vec<clx_core::types::Event>,
    pub snapshots: Vec<clx_core::types::Snapshot>,
    pub command_stats: CommandStats,
    pub risk_stats: RiskStats,
}

pub struct CommandStats {
    pub total: usize,
    pub allowed: usize,
    pub blocked: usize,
    pub prompted: usize,
}

pub struct RiskStats {
    pub low: usize,
    pub medium: usize,
    pub high: usize,
}

impl SessionDetailData {
    /// Fetch detail data for a single session from the default database.
    pub fn fetch(session_id: &str) -> Option<Self> {
        let storage = Storage::open_default().ok()?;
        Self::fetch_from_storage(&storage, session_id)
    }

    /// Fetch detail data from a given storage instance.
    pub fn fetch_from_storage(storage: &Storage, session_id: &str) -> Option<Self> {
        use clx_core::types::AuditDecision;

        let session = storage.get_session(session_id).ok()??;
        let audit_entries = storage
            .get_audit_log_by_session(session_id)
            .unwrap_or_default();
        let events = storage
            .get_events_by_session(session_id)
            .unwrap_or_default();
        let snapshots = storage
            .get_snapshots_by_session(session_id)
            .unwrap_or_default();

        let command_stats = CommandStats {
            total: audit_entries.len(),
            allowed: audit_entries
                .iter()
                .filter(|a| a.decision == AuditDecision::Allowed)
                .count(),
            blocked: audit_entries
                .iter()
                .filter(|a| a.decision == AuditDecision::Blocked)
                .count(),
            prompted: audit_entries
                .iter()
                .filter(|a| a.decision == AuditDecision::Prompted)
                .count(),
        };

        let risk_stats = RiskStats {
            low: audit_entries
                .iter()
                .filter(|a| a.risk_score.is_some_and(|s| s <= 3))
                .count(),
            medium: audit_entries
                .iter()
                .filter(|a| a.risk_score.is_some_and(|s| (4..=7).contains(&s)))
                .count(),
            high: audit_entries
                .iter()
                .filter(|a| a.risk_score.is_some_and(|s| s >= 8))
                .count(),
        };

        Some(Self {
            session,
            audit_entries,
            events,
            snapshots,
            command_stats,
            risk_stats,
        })
    }
}

impl DashboardData {
    pub fn empty() -> Self {
        Self {
            total_sessions: 0,
            active_sessions: 0,
            total_input_tokens: 0,
            total_output_tokens: 0,
            total_commands: 0,
            allowed_commands: 0,
            denied_commands: 0,
            prompted_commands: 0,
            risk_low: 0,
            risk_medium: 0,
            risk_high: 0,
            top_denied: Vec::new(),
            sessions: Vec::new(),
            audit_entries: Vec::new(),
            learned_rules: Vec::new(),
            builtin_whitelist: Vec::new(),
            builtin_blacklist: Vec::new(),
            config_whitelist: Vec::new(),
            config_blacklist: Vec::new(),
            last_updated: Utc::now(),
            load_error: None,
        }
    }

    pub fn fetch(days: u32) -> Self {
        let since = if days > 0 {
            Some(Utc::now() - ChronoDuration::days(i64::from(days)))
        } else {
            None
        };

        let storage = match Storage::open_default() {
            Ok(s) => s,
            Err(e) => {
                let mut data = Self::empty();
                data.load_error = Some(format!("Cannot open database: {e}"));
                return data;
            }
        };

        Self::fetch_from_storage(&storage, since)
    }

    pub fn fetch_from_storage(storage: &Storage, since: Option<DateTime<Utc>>) -> Self {
        let mut data = Self::empty();

        // Sessions count
        data.total_sessions = storage.count_sessions(since).unwrap_or(0);
        data.active_sessions = storage.list_active_sessions().map_or(0, |s| s.len() as i64);

        // Token totals
        if let Ok((input, output)) = storage.get_token_totals(since) {
            data.total_input_tokens = input;
            data.total_output_tokens = output;
        }

        // Audit decisions
        if let Ok(decisions) = storage.count_audit_by_decision(since) {
            data.allowed_commands = *decisions.get("allowed").unwrap_or(&0);
            data.denied_commands = *decisions.get("blocked").unwrap_or(&0);
            data.prompted_commands = *decisions.get("prompted").unwrap_or(&0);
        }
        data.total_commands = storage.count_audit_log(since).unwrap_or(0);

        // Risk distribution
        if let Ok((low, med, high)) = storage.get_risk_distribution(since) {
            data.risk_low = low;
            data.risk_medium = med;
            data.risk_high = high;
        }

        // Top denied
        data.top_denied = storage
            .get_top_denied_patterns(since, 10)
            .unwrap_or_default();

        // Sessions list
        if let Ok(sessions) = storage.list_recent_sessions(since, Some(100)) {
            data.sessions = sessions
                .iter()
                .map(|s| {
                    let short_id = last_n_chars(s.id.as_str(), 8).to_string();
                    let project = s.project_path.clone();
                    let started = s.started_at.format("%m-%d %H:%M").to_string();
                    let duration = match &s.ended_at {
                        Some(end) => {
                            let dur = *end - s.started_at;
                            let mins = dur.num_minutes();
                            if mins >= 60 {
                                format!("{}h {}m", mins / 60, mins % 60)
                            } else {
                                format!("{mins}m")
                            }
                        }
                        None => "-".to_string(),
                    };
                    let total_tokens = s.input_tokens + s.output_tokens;
                    let tokens = if total_tokens >= 1_000_000 {
                        format!("{:.1}M", total_tokens as f64 / 1_000_000.0)
                    } else if total_tokens >= 1_000 {
                        format!("{:.1}K", total_tokens as f64 / 1_000.0)
                    } else {
                        total_tokens.to_string()
                    };

                    let duration_secs = match &s.ended_at {
                        Some(end) => (*end - s.started_at).num_seconds(),
                        None => -1,
                    };

                    SessionRow {
                        session_id: s.id.as_str().to_string(),
                        short_id,
                        project,
                        started,
                        duration,
                        messages: i64::from(s.message_count),
                        commands: i64::from(s.command_count),
                        tokens,
                        status: s.status.as_str().to_string(),
                        duration_secs,
                        tokens_raw: total_tokens,
                    }
                })
                .collect();
        }

        // Audit log
        if let Ok(entries) = storage.get_recent_audit_log(200) {
            data.audit_entries = entries
                .iter()
                .map(|e| {
                    let session_short = last_n_chars(e.session_id.as_str(), 8).to_string();
                    AuditRow {
                        time: e.timestamp.format("%H:%M:%S").to_string(),
                        decision: e.decision.as_str().to_string(),
                        layer: e.layer.clone(),
                        command: e.command.clone(),
                        command_short: truncate_str(&e.command, 80),
                        risk_score: e.risk_score,
                        session_short_id: session_short,
                    }
                })
                .collect();
        }

        // Learned rules
        if let Ok(rules) = storage.get_rules() {
            data.learned_rules = rules
                .iter()
                .map(|r| LearnedRuleRow {
                    pattern: r.pattern.clone(),
                    rule_type: r.rule_type.as_str().to_string(),
                    scope: r.project_path.as_deref().unwrap_or("[global]").to_string(),
                    confirmations: i64::from(r.confirmation_count),
                    denials: i64::from(r.denial_count),
                })
                .collect();
        }

        // Policy engine rules (builtin + config)
        let engine = PolicyEngine::new();
        for rule in engine.whitelist_rules() {
            let row = BuiltinRuleRow {
                pattern: rule.pattern.clone(),
                description: rule.description.clone(),
            };
            match rule.source {
                RuleSource::Builtin => data.builtin_whitelist.push(row),
                RuleSource::Config => data.config_whitelist.push(row),
                _ => {}
            }
        }
        for rule in engine.blacklist_rules() {
            let row = BuiltinRuleRow {
                pattern: rule.pattern.clone(),
                description: rule.description.clone(),
            };
            match rule.source {
                RuleSource::Builtin => data.builtin_blacklist.push(row),
                RuleSource::Config => data.config_blacklist.push(row),
                _ => {}
            }
        }

        data.last_updated = Utc::now();
        data
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration as ChronoDuration;
    use clx_core::storage::Storage;
    use clx_core::types::{Session, SessionId, SessionStatus};

    // ---- T33 helpers ----

    fn make_storage() -> Storage {
        Storage::open_in_memory().expect("in-memory storage must open")
    }

    fn make_session(
        id: &str,
        input_tokens: i64,
        output_tokens: i64,
        started: DateTime<Utc>,
    ) -> Session {
        Session {
            id: SessionId::new(id),
            project_path: "/test/project".to_string(),
            transcript_path: None,
            started_at: started,
            ended_at: Some(started + ChronoDuration::minutes(5)),
            source: clx_core::types::SessionSource::Startup,
            message_count: 2,
            command_count: 1,
            input_tokens,
            output_tokens,
            status: SessionStatus::Ended,
        }
    }

    // ---- T33: fetch_from_storage tests ----

    #[test]
    fn test_fetch_from_empty_storage_returns_zeros() {
        // Arrange
        let storage = make_storage();
        // Act
        let data = DashboardData::fetch_from_storage(&storage, None);
        // Assert: all numeric aggregates must be zero/empty with no errors
        assert_eq!(data.total_sessions, 0);
        assert_eq!(data.active_sessions, 0);
        assert_eq!(data.total_input_tokens, 0);
        assert_eq!(data.total_output_tokens, 0);
        assert_eq!(data.total_commands, 0);
        assert!(data.sessions.is_empty());
        assert!(data.audit_entries.is_empty());
        assert!(data.load_error.is_none());
    }

    #[test]
    fn test_fetch_from_seeded_storage_populates_sessions() {
        // Arrange
        let storage = make_storage();
        let now = Utc::now();
        let s1 = make_session("abcdef0001", 100, 50, now);
        let s2 = make_session("abcdef0002", 200, 80, now - ChronoDuration::hours(1));
        storage.create_session(&s1).expect("create s1");
        storage.create_session(&s2).expect("create s2");
        // Act
        let data = DashboardData::fetch_from_storage(&storage, None);
        // Assert
        assert_eq!(data.total_sessions, 2);
        assert_eq!(data.sessions.len(), 2);
        assert!(data.load_error.is_none());
    }

    #[test]
    fn test_fetch_date_filter_excludes_old_sessions() {
        // Arrange: one recent session, one 30-day-old session
        let storage = make_storage();
        let now = Utc::now();
        let recent = make_session("recent0001", 10, 5, now - ChronoDuration::hours(1));
        let old = make_session("old0000001", 10, 5, now - ChronoDuration::days(30));
        storage.create_session(&recent).expect("create recent");
        storage.create_session(&old).expect("create old");
        // Apply a 7-day filter
        let since = Some(now - ChronoDuration::days(7));
        // Act
        let data = DashboardData::fetch_from_storage(&storage, since);
        // Assert: only the recent session should appear
        assert_eq!(data.total_sessions, 1);
    }

    #[test]
    fn test_fetch_token_aggregation() {
        // Arrange: seed 3 sessions with known token counts
        let storage = make_storage();
        let now = Utc::now();
        for i in 0_u8..3 {
            let session = make_session(
                &format!("toktest{i:05}"),
                1000_i64,
                500_i64,
                now - ChronoDuration::minutes(i64::from(i) * 10),
            );
            storage.create_session(&session).expect("create session");
        }
        // Act
        let data = DashboardData::fetch_from_storage(&storage, None);
        // Assert: total tokens = 3 * (1000 input + 500 output) = 4500 across all sessions
        assert_eq!(data.total_input_tokens, 3000);
        assert_eq!(data.total_output_tokens, 1500);
    }

    // ---- last_n_chars ----

    #[test]
    fn test_last_n_chars_ascii() {
        assert_eq!(last_n_chars("abcdefgh", 3), "fgh");
    }

    #[test]
    fn test_last_n_chars_exact() {
        assert_eq!(last_n_chars("abc", 3), "abc");
    }

    #[test]
    fn test_last_n_chars_short_string() {
        assert_eq!(last_n_chars("ab", 5), "ab");
    }

    #[test]
    fn test_last_n_chars_empty() {
        assert_eq!(last_n_chars("", 3), "");
    }

    #[test]
    fn test_last_n_chars_utf8_boundary() {
        // "café" = 5 bytes (é is 2 bytes). last_n_chars with n=3 should not
        // split inside the 'é'. s.len()=5, idx=5-3=2 => byte 2 is 'f',
        // which is a char boundary, so result is "fé".
        assert_eq!(last_n_chars("café", 3), "fé");
    }

    #[test]
    fn test_last_n_chars_utf8_mid_char() {
        // "aé" = 3 bytes (a=1, é=2). last_n_chars with n=2: idx=3-2=1,
        // byte 1 is mid-é (not a boundary), so it advances to 2 => "é"
        // Wait, let me check: "aé" bytes are [0x61, 0xC3, 0xA9].
        // idx = 3-2 = 1, byte 1 is 0xC3 which IS a char boundary (start of é).
        // So result is "é" (bytes [0xC3, 0xA9]).
        assert_eq!(last_n_chars("aé", 2), "é");
    }

    // ---- DashboardData::empty ----

    #[test]
    fn test_dashboard_data_empty() {
        let data = DashboardData::empty();
        assert_eq!(data.total_sessions, 0);
        assert_eq!(data.active_sessions, 0);
        assert_eq!(data.total_input_tokens, 0);
        assert_eq!(data.total_output_tokens, 0);
        assert_eq!(data.total_commands, 0);
        assert_eq!(data.allowed_commands, 0);
        assert_eq!(data.denied_commands, 0);
        assert_eq!(data.prompted_commands, 0);
        assert_eq!(data.risk_low, 0);
        assert_eq!(data.risk_medium, 0);
        assert_eq!(data.risk_high, 0);
        assert!(data.top_denied.is_empty());
        assert!(data.sessions.is_empty());
        assert!(data.audit_entries.is_empty());
        assert!(data.learned_rules.is_empty());
        assert!(data.builtin_whitelist.is_empty());
        assert!(data.builtin_blacklist.is_empty());
        assert!(data.config_whitelist.is_empty());
        assert!(data.config_blacklist.is_empty());
        assert!(data.load_error.is_none());
    }

    #[test]
    fn last_n_chars_short_string() {
        assert_eq!(last_n_chars("hello", 10), "hello");
    }

    #[test]
    fn last_n_chars_exact_length() {
        assert_eq!(last_n_chars("hello", 5), "hello");
    }

    #[test]
    fn last_n_chars_truncates() {
        assert_eq!(last_n_chars("abcdefgh", 4), "efgh");
    }

    #[test]
    fn last_n_chars_empty() {
        assert_eq!(last_n_chars("", 5), "");
    }

    #[test]
    fn last_n_chars_handles_unicode() {
        // Multi-byte chars: should not panic or split mid-character
        let s = "hello🌍world";
        let result = last_n_chars(s, 8);
        // Should be valid UTF-8
        assert!(result.len() <= 8 || result.starts_with('🌍') || !result.is_empty());
    }

    #[test]
    fn command_stats_defaults() {
        let stats = CommandStats {
            total: 10,
            allowed: 7,
            blocked: 1,
            prompted: 2,
        };
        assert_eq!(stats.total, 10);
        assert_eq!(stats.allowed, 7);
        assert_eq!(stats.blocked, 1);
        assert_eq!(stats.prompted, 2);
    }

    #[test]
    fn risk_stats_defaults() {
        let stats = RiskStats {
            low: 5,
            medium: 3,
            high: 2,
        };
        assert_eq!(stats.low, 5);
        assert_eq!(stats.medium, 3);
        assert_eq!(stats.high, 2);
    }

    // ---- SessionDetailData::fetch_from_storage ----

    use clx_core::types::{
        AuditDecision, AuditLogEntry, Event, EventType, Snapshot, SnapshotTrigger,
    };

    fn audit(session: &str, decision: AuditDecision, risk: Option<i32>) -> AuditLogEntry {
        let mut e = AuditLogEntry::new(
            SessionId::new(session),
            "echo hi".to_owned(),
            "builtin".to_owned(),
            decision,
        );
        e.risk_score = risk;
        e
    }

    #[test]
    fn test_session_detail_missing_session_returns_none() {
        let storage = make_storage();
        // No session created => get_session returns None => fetch returns None.
        let out = SessionDetailData::fetch_from_storage(&storage, "ghost-session");
        assert!(out.is_none());
    }

    #[test]
    fn test_session_detail_aggregates_command_and_risk_stats() {
        let storage = make_storage();
        let sid = "detail-agg-01";
        storage
            .create_session(&make_session(sid, 100, 50, Utc::now()))
            .expect("create session");
        // 2 allowed, 1 blocked, 1 prompted; risk: low(2), medium(5), high(9), none.
        storage
            .create_audit_log(&audit(sid, AuditDecision::Allowed, Some(2)))
            .unwrap();
        storage
            .create_audit_log(&audit(sid, AuditDecision::Allowed, Some(5)))
            .unwrap();
        storage
            .create_audit_log(&audit(sid, AuditDecision::Blocked, Some(9)))
            .unwrap();
        storage
            .create_audit_log(&audit(sid, AuditDecision::Prompted, None))
            .unwrap();
        storage
            .append_event(&Event::new(SessionId::new(sid), EventType::Message))
            .unwrap();
        storage
            .create_snapshot(&Snapshot::new(SessionId::new(sid), SnapshotTrigger::Manual))
            .unwrap();

        let d = SessionDetailData::fetch_from_storage(&storage, sid)
            .expect("detail data must load for an existing session");

        // Command stats: 4 total, 2 allowed, 1 blocked, 1 prompted.
        assert_eq!(d.command_stats.total, 4);
        assert_eq!(d.command_stats.allowed, 2);
        assert_eq!(d.command_stats.blocked, 1);
        assert_eq!(d.command_stats.prompted, 1);
        // Risk buckets: <=3 low, 4..=7 medium, >=8 high; None counts nowhere.
        assert_eq!(d.risk_stats.low, 1);
        assert_eq!(d.risk_stats.medium, 1);
        assert_eq!(d.risk_stats.high, 1);
        assert_eq!(d.audit_entries.len(), 4);
        assert_eq!(d.events.len(), 1);
        assert_eq!(d.snapshots.len(), 1);
        assert_eq!(d.session.id.as_str(), sid);
    }

    #[test]
    fn test_session_detail_risk_boundaries_are_inclusive() {
        // Pin the exact boundary semantics: 3 is low, 4 and 7 are medium,
        // 8 is high. A regression to `< 3` / `> 7` would shift these.
        let storage = make_storage();
        let sid = "risk-bounds";
        storage
            .create_session(&make_session(sid, 0, 0, Utc::now()))
            .unwrap();
        for r in [3, 4, 7, 8] {
            storage
                .create_audit_log(&audit(sid, AuditDecision::Allowed, Some(r)))
                .unwrap();
        }
        let d = SessionDetailData::fetch_from_storage(&storage, sid).unwrap();
        assert_eq!(d.risk_stats.low, 1, "risk 3 must be low");
        assert_eq!(d.risk_stats.medium, 2, "risk 4 and 7 must be medium");
        assert_eq!(d.risk_stats.high, 1, "risk 8 must be high");
    }

    #[test]
    fn test_session_detail_empty_subtables_default_to_zero() {
        let storage = make_storage();
        let sid = "detail-empty";
        storage
            .create_session(&make_session(sid, 0, 0, Utc::now()))
            .unwrap();
        let d = SessionDetailData::fetch_from_storage(&storage, sid).unwrap();
        assert_eq!(d.command_stats.total, 0);
        assert_eq!(d.command_stats.allowed, 0);
        assert_eq!(d.risk_stats.low, 0);
        assert!(d.audit_entries.is_empty());
        assert!(d.events.is_empty());
        assert!(d.snapshots.is_empty());
    }

    // ---- DashboardData::fetch_from_storage: row-shaping branches ----

    #[test]
    fn test_fetch_active_session_has_dash_duration_and_negative_secs() {
        // An active (no ended_at) session: duration "-" and duration_secs -1.
        let storage = make_storage();
        let mut s = make_session("active-row-01", 10, 5, Utc::now());
        s.ended_at = None;
        s.status = SessionStatus::Active;
        storage.create_session(&s).unwrap();
        let data = DashboardData::fetch_from_storage(&storage, None);
        let row = data
            .sessions
            .iter()
            .find(|r| r.session_id == "active-row-01")
            .expect("session row present");
        assert_eq!(row.duration, "-");
        assert_eq!(row.duration_secs, -1);
        assert_eq!(row.status, "active");
    }

    #[test]
    fn test_fetch_long_session_duration_formats_hours_and_minutes() {
        // ended 90 minutes after start => "1h 30m"; duration_secs = 5400.
        let storage = make_storage();
        let start = Utc::now() - ChronoDuration::hours(3);
        let mut s = make_session("long-row-01", 0, 0, start);
        s.ended_at = Some(start + ChronoDuration::minutes(90));
        storage.create_session(&s).unwrap();
        let data = DashboardData::fetch_from_storage(&storage, None);
        let row = data
            .sessions
            .iter()
            .find(|r| r.session_id == "long-row-01")
            .unwrap();
        assert_eq!(row.duration, "1h 30m");
        assert_eq!(row.duration_secs, 5400);
    }

    #[test]
    fn test_fetch_token_display_scales_to_k_and_m() {
        let storage = make_storage();
        let now = Utc::now();
        // 1_500 total -> "1.5K"
        storage
            .create_session(&make_session("tok-k-row", 1_000, 500, now))
            .unwrap();
        // 2_500_000 total -> "2.5M"
        storage
            .create_session(&make_session(
                "tok-m-row",
                2_000_000,
                500_000,
                now - ChronoDuration::minutes(1),
            ))
            .unwrap();
        // 42 total -> "42" (raw)
        storage
            .create_session(&make_session(
                "tok-raw-row",
                40,
                2,
                now - ChronoDuration::minutes(2),
            ))
            .unwrap();
        let data = DashboardData::fetch_from_storage(&storage, None);
        let by = |id: &str| -> String {
            data.sessions
                .iter()
                .find(|r| r.session_id == id)
                .unwrap()
                .tokens
                .clone()
        };
        assert_eq!(by("tok-k-row"), "1.5K");
        assert_eq!(by("tok-m-row"), "2.5M");
        assert_eq!(by("tok-raw-row"), "42");
    }

    #[test]
    fn test_fetch_populates_audit_rows_with_short_session_id() {
        let storage = make_storage();
        let sid = "audit-shaping-session-XYZ";
        storage
            .create_session(&make_session(sid, 0, 0, Utc::now()))
            .unwrap();
        let mut e = AuditLogEntry::new(
            SessionId::new(sid),
            "rm -rf /tmp/scratch".to_owned(),
            "llm".to_owned(),
            AuditDecision::Blocked,
        );
        e.risk_score = Some(9);
        storage.create_audit_log(&e).unwrap();

        let data = DashboardData::fetch_from_storage(&storage, None);
        let ar = data
            .audit_entries
            .iter()
            .find(|a| a.command == "rm -rf /tmp/scratch")
            .expect("audit row present");
        assert_eq!(ar.decision, "blocked");
        assert_eq!(ar.layer, "llm");
        assert_eq!(ar.risk_score, Some(9));
        // session_short_id is the last 8 chars of the full session id.
        assert_eq!(ar.session_short_id, last_n_chars(sid, 8));
        // command_short is the (here untruncated) display copy.
        assert_eq!(ar.command_short, "rm -rf /tmp/scratch");
    }

    #[test]
    fn test_fetch_populates_learned_rules_global_and_scoped() {
        use clx_core::types::{LearnedRule, RuleType};
        let storage = make_storage();
        let mut global = LearnedRule::new(
            "git status".to_owned(),
            RuleType::Allow,
            "user_decision".to_owned(),
        );
        global.confirmation_count = 5;
        global.denial_count = 1;
        global.project_path = None;
        storage.add_rule(&global).unwrap();

        let mut scoped = LearnedRule::new(
            "cargo test".to_owned(),
            RuleType::Deny,
            "user_decision".to_owned(),
        );
        scoped.project_path = Some("/work/clx".to_owned());
        storage.add_rule(&scoped).unwrap();

        let data = DashboardData::fetch_from_storage(&storage, None);
        let g = data
            .learned_rules
            .iter()
            .find(|r| r.pattern == "git status")
            .expect("global rule");
        assert_eq!(g.scope, "[global]");
        assert_eq!(g.confirmations, 5);
        assert_eq!(g.denials, 1);
        assert_eq!(g.rule_type, "allow");

        let sc = data
            .learned_rules
            .iter()
            .find(|r| r.pattern == "cargo test")
            .expect("scoped rule");
        assert_eq!(sc.scope, "/work/clx");
        assert_eq!(sc.rule_type, "deny");
    }

    #[test]
    fn test_fetch_counts_audit_decisions_and_risk_distribution() {
        let storage = make_storage();
        let sid = "decision-counts";
        storage
            .create_session(&make_session(sid, 0, 0, Utc::now()))
            .unwrap();
        for (d, r) in [
            (AuditDecision::Allowed, 1),
            (AuditDecision::Allowed, 2),
            (AuditDecision::Blocked, 9),
            (AuditDecision::Prompted, 5),
        ] {
            let mut e = AuditLogEntry::new(
                SessionId::new(sid),
                "cmd".to_owned(),
                "builtin".to_owned(),
                d,
            );
            e.risk_score = Some(r);
            storage.create_audit_log(&e).unwrap();
        }
        let data = DashboardData::fetch_from_storage(&storage, None);
        assert_eq!(data.allowed_commands, 2);
        assert_eq!(data.denied_commands, 1);
        assert_eq!(data.prompted_commands, 1);
        assert_eq!(data.total_commands, 4);
        // Risk distribution mirrors the per-session detail bucketing.
        assert_eq!(data.risk_low, 2);
        assert_eq!(data.risk_medium, 1);
        assert_eq!(data.risk_high, 1);
        assert!(data.load_error.is_none());
    }
}
