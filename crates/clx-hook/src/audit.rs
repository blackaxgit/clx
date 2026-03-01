//! Audit logging for hook events.

use clx_core::redaction::redact_secrets;
use clx_core::storage::Storage;
use clx_core::types::{AuditDecision, AuditLogEntry, SessionId};
use tracing::warn;

/// Log an audit entry to the database
pub(crate) fn log_audit_entry(
    session_id: &SessionId,
    command: &str,
    working_dir: &str,
    layer: &str,
    decision: AuditDecision,
    risk_score: Option<i32>,
    reasoning: Option<&str>,
) {
    let Ok(storage) = Storage::open_default() else {
        return;
    };

    // Redact secrets from command before persisting to audit log
    let redacted_command = redact_secrets(command);

    let mut entry = AuditLogEntry::new(
        session_id.clone(),
        redacted_command,
        layer.to_string(),
        decision,
    );
    entry.working_dir = Some(working_dir.to_string());
    entry.risk_score = risk_score;
    entry.reasoning = reasoning.map(std::string::ToString::to_string);

    if let Err(e) = storage.create_audit_log(&entry) {
        warn!("Failed to create audit log: {}", e);
    }
}
