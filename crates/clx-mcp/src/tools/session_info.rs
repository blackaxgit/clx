//! `clx_session_info` tool — Get current session details.

use serde_json::{Value, json};
use std::collections::HashMap;

use crate::server::McpServer;

impl McpServer {
    /// `clx_session_info` - Get current session details
    #[allow(clippy::unnecessary_wraps)] // Returns Result for consistent tool handler interface
    pub(crate) fn tool_session_info(&self, _args: &Value) -> Result<Value, (i32, String)> {
        let mut info = HashMap::new();

        info.insert("db_path".to_string(), json!(self.db_path));
        info.insert(
            "session_id".to_string(),
            json!(
                self.session_id
                    .as_ref()
                    .map_or("not set", clx_core::types::SessionId::as_str)
            ),
        );

        // Get session details if we have a session ID
        if let Some(session_id) = &self.session_id {
            match self.storage.get_session(session_id.as_str()) {
                Ok(Some(session)) => {
                    info.insert("project_path".to_string(), json!(session.project_path));
                    info.insert(
                        "started_at".to_string(),
                        json!(session.started_at.to_rfc3339()),
                    );
                    info.insert("status".to_string(), json!(session.status.as_str()));
                    info.insert("message_count".to_string(), json!(session.message_count));
                    info.insert("command_count".to_string(), json!(session.command_count));
                }
                Ok(None) => {
                    info.insert("session_status".to_string(), json!("session not found"));
                }
                Err(e) => {
                    info.insert(
                        "session_error".to_string(),
                        json!(format!("Failed to get session: {}", e)),
                    );
                }
            }

            // Get snapshot count
            if let Ok(snapshots) = self.storage.get_snapshots_by_session(session_id.as_str()) {
                info.insert("snapshot_count".to_string(), json!(snapshots.len()));
            }
        }

        // Get active sessions count
        if let Ok(sessions) = self.storage.list_active_sessions() {
            info.insert("active_sessions_count".to_string(), json!(sessions.len()));
        }

        // Get rules count
        if let Ok(rules) = self.storage.get_rules() {
            info.insert("rules_count".to_string(), json!(rules.len()));
        }

        Ok(json!({
            "content": [{
                "type": "text",
                "text": serde_json::to_string_pretty(&info).unwrap_or_else(|_| "{}".to_string())
            }]
        }))
    }
}
