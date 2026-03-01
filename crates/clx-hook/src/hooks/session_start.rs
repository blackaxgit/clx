//! `SessionStart` hook handler - create session and load previous context.

use anyhow::Result;
use clx_core::storage::Storage;
use clx_core::types::{Session, SessionSource};
use tracing::{debug, error, info, warn};

use crate::context::{load_previous_session_summary, load_project_rules};
use crate::embedding::truncate_to_char_boundary;
use crate::output::output_generic;
use crate::types::HookInput;

/// Handle `SessionStart` hook - create session and load previous context
pub(crate) async fn handle_session_start(input: HookInput) -> Result<()> {
    let source = input.source.as_deref().unwrap_or("startup");

    info!(
        "SessionStart: Creating session {} (source: {})",
        input.session_id, source
    );

    // Open storage
    let storage = match Storage::open_default() {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to open storage: {}", e);
            // Still allow session to start even if storage fails
            eprintln!("CLX: Session started (storage unavailable)");
            return Ok(());
        }
    };

    // Check if session already exists (resume case)
    let existing_session = match storage.get_session(input.session_id.as_str()) {
        Ok(s) => s,
        Err(e) => {
            warn!("Failed to check existing session: {}", e);
            None
        }
    };

    if existing_session.is_some() {
        // Session already exists - this is a resume
        info!("Resuming existing session {}", input.session_id);
        eprintln!(
            "CLX: Resumed session {}",
            truncate_to_char_boundary(input.session_id.as_str(), 8)
        );
    } else {
        // Create new session
        let session_source = match source {
            "startup" => SessionSource::Startup,
            "resume" => SessionSource::Resume,
            _ => SessionSource::Startup,
        };

        let mut session = Session::new(input.session_id.clone(), input.cwd.clone());
        session.transcript_path.clone_from(&input.transcript_path);
        session.source = session_source;

        if let Err(e) = storage.create_session(&session) {
            warn!("Failed to create session: {}", e);
        } else {
            debug!("Created session {}", input.session_id);
        }
    }

    // --- Session recovery: detect and recover from abandoned sessions ---
    let mut recovery_context: Option<String> = None;
    let config = clx_core::config::Config::load().unwrap_or_default();
    if config.session_recovery.enabled {
        match storage.find_stale_active_sessions(
            &input.cwd,
            config.session_recovery.stale_hours,
            input.session_id.as_str(),
        ) {
            Ok(stale_sessions) => {
                for stale in &stale_sessions {
                    if let Err(e) = storage.mark_session_abandoned(stale.id.as_str()) {
                        warn!("Failed to mark session {} as abandoned: {e}", stale.id);
                    } else {
                        info!("Marked stale session {} as abandoned", stale.id);
                    }
                }

                // Load latest snapshot from most recently abandoned session
                if let Some(most_recent) = stale_sessions.first()
                    && let Ok(Some(snapshot)) = storage.get_latest_snapshot(most_recent.id.as_str())
                    && let Some(ref summary) = snapshot.summary
                {
                    recovery_context = Some(format!(
                        "[Recovered from interrupted session]\n\
                         Previous session ({}) was interrupted. Last checkpoint:\n{summary}",
                        truncate_to_char_boundary(most_recent.id.as_str(), 8),
                    ));
                    eprintln!(
                        "CLX: Recovered context from interrupted session {}",
                        truncate_to_char_boundary(most_recent.id.as_str(), 8)
                    );
                }
            }
            Err(e) => {
                warn!("Failed to check for stale sessions: {e}");
            }
        }
    }

    // Try to load previous session summary
    let previous_summary = load_previous_session_summary(&storage, &input.session_id, &input.cwd);

    // Load project rules from CLAUDE.md
    let project_rules = load_project_rules(&input.cwd);

    // Output session info to stderr (terminal-visible for the user)
    eprintln!(
        "CLX: Session {} started",
        truncate_to_char_boundary(input.session_id.as_str(), 8)
    );

    // Show CLX tools reminder on terminal
    eprintln!("CLX Tools: clx_recall, clx_remember, clx_rules, clx_checkpoint");

    // Build systemMessage combining previous session summary + critical rules
    let mut system_parts: Vec<String> = Vec::new();

    // Inject recovery context from abandoned sessions (persistent via systemMessage)
    if let Some(ref recovery) = recovery_context {
        system_parts.push(recovery.clone());
    }

    if let Some(ref summary) = previous_summary {
        system_parts.push(format!("[Previous Session Context]\n{summary}"));
    }

    if let Some(ref rules) = project_rules {
        system_parts.push(format!("[Project Rules]\n{rules}"));
    }

    // Always include CLX tools reminder in systemMessage
    system_parts.push(
        "CLX Tools: clx_recall {query} (search past sessions), clx_remember {content} (save info), clx_rules (refresh rules), clx_checkpoint (manual snapshot)".to_string()
    );

    let system_message = if system_parts.is_empty() {
        None
    } else {
        Some(system_parts.join("\n\n"))
    };

    // Output JSON to stdout with systemMessage for Claude's context
    output_generic("SessionStart", None, system_message.as_deref());

    Ok(())
}
