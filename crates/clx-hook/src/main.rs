//! CLX Hook Binary
//!
//! This binary intercepts and validates Claude Code commands before execution.
//!
//! Hook handlers:
//! - `PreToolUse`: Validates commands using Layer 0 (deterministic rules) and Layer 1 (LLM)
//! - `PostToolUse`: Logs events to database and tracks user decisions for learning
//! - `PreCompact`: Creates snapshots before context compression
//! - `SessionStart`: Creates session in database and loads previous session summary
//! - `SessionEnd`: Updates session status and creates final snapshot
//! - `SubagentStart`: Injects specialist rules into subagent context
//! - `UserPromptSubmit`: Injects orchestrator reminder on user prompts

mod audit;
mod context;
mod embedding;
mod hooks;
mod learning;
mod output;
mod transcript;
mod types;

#[cfg(test)]
mod tests;

use anyhow::Result;
use clx_core::redaction::redact_secrets;
use std::io::{self, Read};
use tracing::{debug, error, warn};

use hooks::{
    handle_post_tool_use, handle_pre_compact, handle_pre_tool_use, handle_session_end,
    handle_session_start, handle_subagent_start, handle_user_prompt_submit,
};
use output::output_decision;
use types::{HookInput, MAX_INPUT_SIZE};

#[tokio::main]
async fn main() -> Result<()> {
    clx_core::init_sqlite_vec();

    // Initialize tracing - only ERROR level to avoid confusing Claude Code
    // Claude Code interprets any stderr output as hook errors
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::ERROR.into()),
        )
        .with_writer(std::io::stderr)
        .init();

    // Read JSON input from stdin (limited to 1MB to prevent DoS via memory exhaustion)
    let mut input_str = String::new();
    let stdin = io::stdin();
    match stdin.take(MAX_INPUT_SIZE).read_to_string(&mut input_str) {
        Ok(bytes_read) => {
            if bytes_read as u64 >= MAX_INPUT_SIZE {
                eprintln!("CLX: Input exceeds maximum size of {MAX_INPUT_SIZE} bytes");
                let output = serde_json::json!({
                    "hookSpecificOutput": {
                        "hookEventName": "PreToolUse",
                        "permissionDecision": "block",
                        "permissionDecisionReason": "Input too large"
                    }
                });
                println!("{output}");
                std::process::exit(0);
            }
        }
        Err(_e) => {
            output_decision("allow", None, None, None);
            std::process::exit(0);
        }
    }

    debug!("Hook input: {}", redact_secrets(&input_str));

    // Parse the input
    let input: HookInput = match serde_json::from_str(&input_str) {
        Ok(input) => input,
        Err(e) => {
            error!("Failed to parse hook input: {}", e);
            output_decision(
                "ask",
                Some("CLX: Input parse error, manual confirmation required".to_string()),
                None,
                None,
            );
            std::process::exit(0);
        }
    };

    // Route based on hook event name
    let result = match input.hook_event_name.as_str() {
        "PreToolUse" => handle_pre_tool_use(input).await,
        "PostToolUse" => handle_post_tool_use(input).await,
        "PreCompact" => handle_pre_compact(input).await,
        "SessionStart" => handle_session_start(input).await,
        "SessionEnd" => handle_session_end(input).await,
        "SubagentStart" => handle_subagent_start(input).await,
        "UserPromptSubmit" => handle_user_prompt_submit(input).await,
        unknown => {
            warn!("Unknown hook event: {}", unknown);
            output_decision("allow", None, None, None);
            Ok(())
        }
    };

    if let Err(e) = result {
        error!("Hook handler error: {}", e);
        std::process::exit(0);
    }

    Ok(())
}
