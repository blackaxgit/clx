//! `clx_stats` tool — Get session statistics.

use serde_json::{Value, json};
use tracing::debug;

use crate::server::McpServer;
use crate::validation::validate_optional_i64_param;

impl McpServer {
    /// `clx_stats` - Get session statistics
    pub(crate) fn tool_stats(&self, args: &Value) -> Result<Value, (i32, String)> {
        let days = validate_optional_i64_param(args, "days", 1, 365)?.unwrap_or(7) as u32;

        debug!("Getting stats for last {} days", days);

        let since = chrono::Utc::now() - chrono::Duration::days(i64::from(days));

        // Get session counts
        let total_sessions = self.storage.count_sessions(Some(since)).unwrap_or(0);
        let active_sessions = self.storage.list_active_sessions().map_or(0, |s| s.len());

        // Get audit log statistics
        let decision_counts = self
            .storage
            .count_audit_by_decision(Some(since))
            .unwrap_or_default();
        let total_commands = decision_counts.values().sum::<i64>();
        let allowed = decision_counts.get("allow").copied().unwrap_or(0);
        let denied = decision_counts.get("deny").copied().unwrap_or(0);
        let asked = decision_counts.get("ask").copied().unwrap_or(0);

        // Get risk distribution
        let risk_dist = self
            .storage
            .get_risk_distribution(Some(since))
            .unwrap_or_default();

        // Get top denied patterns
        let top_denied = self
            .storage
            .get_top_denied_patterns(Some(since), 5)
            .unwrap_or_default();

        let stats = json!({
            "period_days": days,
            "sessions": {
                "total": total_sessions,
                "active": active_sessions
            },
            "commands": {
                "total": total_commands,
                "allowed": allowed,
                "denied": denied,
                "asked": asked,
                "allowed_percent": if total_commands > 0 { (allowed as f64 / total_commands as f64 * 100.0).round() } else { 0.0 },
                "denied_percent": if total_commands > 0 { (denied as f64 / total_commands as f64 * 100.0).round() } else { 0.0 }
            },
            "risk_distribution": risk_dist,
            "top_denied_patterns": top_denied
        });

        let text = serde_json::to_string_pretty(&stats).unwrap_or_else(|_| "{}".to_string());

        Ok(json!({
            "content": [{
                "type": "text",
                "text": text
            }]
        }))
    }
}
