//! CLX Hook Binary
//!
//! Thin entry point. Reads JSON from stdin, dispatches to the right handler,
//! and prints the response on stdout. All real work lives in the `clx_hook`
//! library (see `src/lib.rs` + `src/router.rs`). This binary owns only
//! process-level concerns: argument parsing, tracing setup, sqlite-vec
//! init, and constructing `HookDeps` for the router.
//!
//! Hook handlers (in the library): PreToolUse, PostToolUse, PreCompact,
//! SessionStart, SessionEnd, SubagentStart, UserPromptSubmit, Stop.

use std::io::{self, IsTerminal};
use std::process::ExitCode;

use clx_hook::{HookDeps, handle_event};

fn print_usage() {
    eprintln!("clx-hook - Claude Code hook handler for CLX");
    eprintln!();
    eprintln!("This binary is invoked automatically by Claude Code via hooks.");
    eprintln!("It reads JSON input from stdin and is not intended for manual use.");
    eprintln!();
    eprintln!("Supported hook events: PreToolUse, PostToolUse, PreCompact,");
    eprintln!("  SessionStart, SessionEnd, SubagentStart, UserPromptSubmit, Stop");
    eprintln!();
    eprintln!("Configuration: ~/.clx/config.yaml");
    eprintln!("Documentation: https://github.com/blackaxgit/clx");
}

#[tokio::main]
async fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();

    // --help / -h short-circuits before any I/O.
    if args.iter().any(|a| a == "--help" || a == "-h") {
        print_usage();
        return ExitCode::SUCCESS;
    }

    // If stdin is a terminal (no piped input), show usage and exit cleanly.
    if io::stdin().is_terminal() {
        print_usage();
        return ExitCode::SUCCESS;
    }

    clx_core::init_sqlite_vec();
    init_tracing();

    // Build router deps. If the storage layer cannot be opened we still want
    // Claude Code to see a clean exit (treating any non-zero as hook failure
    // noise); the router itself does the safe "allow" fallback when handlers
    // cannot do real work.
    let Some(deps) = HookDeps::from_process_defaults() else {
        return ExitCode::SUCCESS;
    };

    // Delegate to the library. handle_event consumes stdin, writes any
    // fallback JSON (oversize input / parse error) to stdout, and returns a
    // HookExit. Every variant maps to SUCCESS so Claude Code never sees
    // hook stderr noise.
    let _exit = handle_event(io::stdin(), io::stdout(), deps).await;
    ExitCode::SUCCESS
}

/// Initialize tracing.
///
/// - stderr: ERROR only. Claude Code treats hook stderr as failure noise.
/// - file: WARN+ to the configured log file. Created on first write so the
///   user-visible "log file silently dropped" surprise stays fixed.
fn init_tracing() {
    use tracing_subscriber::Layer;
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

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
    tracing_subscriber::registry()
        .with(stderr_layer)
        .with(file_layer)
        .init();
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
