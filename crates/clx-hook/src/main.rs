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
use std::io::{self, IsTerminal, Read};
use tracing::{debug, error, warn};

use hooks::{
    handle_post_tool_use, handle_pre_compact, handle_pre_tool_use, handle_session_end,
    handle_session_start, handle_subagent_start, handle_user_prompt_submit,
};
use output::output_decision;
use types::{HookInput, MAX_INPUT_SIZE};

fn print_usage() {
    eprintln!("clx-hook - Claude Code hook handler for CLX");
    eprintln!();
    eprintln!("This binary is invoked automatically by Claude Code via hooks.");
    eprintln!("It reads JSON input from stdin and is not intended for manual use.");
    eprintln!();
    eprintln!("Supported hook events: PreToolUse, PostToolUse, PreCompact,");
    eprintln!("  SessionStart, SessionEnd, SubagentStart, UserPromptSubmit");
    eprintln!();
    eprintln!("Configuration: ~/.clx/config.yaml");
    eprintln!("Documentation: https://github.com/blackaxgit/clx");
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();

    // Handle --help or -h
    if args.iter().any(|a| a == "--help" || a == "-h") {
        print_usage();
        return Ok(());
    }

    // If stdin is a terminal (no piped input), show usage
    if io::stdin().is_terminal() {
        print_usage();
        return Ok(());
    }

    clx_core::init_sqlite_vec();

    // Initialize tracing.
    // - stderr: ERROR only (Claude Code treats hook stderr as failure noise).
    // - file: WARN+ to the configured log file (created by hook on first write).
    //   Ensures the user-visible "log file silently dropped" surprise is fixed.
    let log_path = clx_core::config::Config::load().ok().and_then(|c| {
        let p = c.log_file_path();
        std::fs::create_dir_all(p.parent()?).ok()?;
        std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(&p)
            .ok()
            .map(std::sync::Mutex::new)
            .map(std::sync::Arc::new)
    });
    let stderr_layer = tracing_subscriber::fmt::layer()
        .with_writer(std::io::stderr)
        .with_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::ERROR.into()),
        );
    let file_layer = log_path.as_ref().map(|f| {
        let f = f.clone();
        tracing_subscriber::fmt::layer()
            .with_ansi(false)
            .with_writer(move || MutexFile(f.clone()))
            .with_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
            )
    });
    use tracing_subscriber::Layer;
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;
    tracing_subscriber::registry()
        .with(stderr_layer)
        .with(file_layer)
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

/// Adapter so `Arc<Mutex<File>>` can serve as a tracing-subscriber writer.
/// Each write acquires the mutex; fine for a short-lived hook process.
struct MutexFile(std::sync::Arc<std::sync::Mutex<std::fs::File>>);

impl std::io::Write for MutexFile {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .map_err(|_| std::io::Error::other("file mutex poisoned"))?
            .write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.0
            .lock()
            .map_err(|_| std::io::Error::other("file mutex poisoned"))?
            .flush()
    }
}
