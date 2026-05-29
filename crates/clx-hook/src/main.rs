//! CLX Hook Binary
//!
//! Thin entry point. Reads JSON from stdin, dispatches to the right handler,
//! and prints the response on stdout. Invoked automatically by the host
//! coding agent (Claude Code, Codex CLI, or Cursor) via that host's hook
//! protocol; the router detects the host from the envelope. All real work
//! lives in the `clx_hook` library (see `src/lib.rs` + `src/router.rs`). This
//! binary owns only process-level concerns: argument parsing, tracing setup,
//! sqlite-vec init, and constructing `HookDeps` for the router.
//!
//! Hook handlers (in the library): the eight Claude events `PreToolUse`,
//! `PostToolUse`, `PreCompact`, `SessionStart`, `SessionEnd`, `SubagentStart`,
//! `UserPromptSubmit`, `Stop`, plus the Codex-only `PermissionRequest` and
//! `PostCompact`.

use std::io::{self, IsTerminal};
use std::process::ExitCode;

use clx_hook::{
    CLAUDE_PROVENANCE_ENV_VARS, HookDeps, Provenance, classify_provenance, handle_event,
};
use tracing::warn;

fn print_usage() {
    eprintln!("clx-hook - CLX hook handler for Claude Code, Codex CLI, and Cursor");
    eprintln!();
    eprintln!("This binary is invoked automatically by the host coding agent via");
    eprintln!("that host's hook protocol; the router detects the host from the");
    eprintln!("envelope. It reads JSON input from stdin and is not intended for");
    eprintln!("manual use.");
    eprintln!();
    eprintln!("Supported hook events: PreToolUse, PostToolUse, PreCompact,");
    eprintln!("  SessionStart, SessionEnd, SubagentStart, UserPromptSubmit, Stop,");
    eprintln!("  plus the Codex-only PermissionRequest and PostCompact");
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

    // F7: best-effort hook-envelope provenance check at the orchestration
    // boundary (before any dispatch), NOT inside router::handle_event, so
    // the in-memory contract tests that call handle_event directly are
    // unaffected. We read the Claude-Code-set env vars here (the
    // infrastructure edge) and hand pure (name, value) pairs to the Domain
    // decision function. Claude Code 2026 provides no unforgeable token
    // (see classify_provenance docs), so this is defense-in-depth, not an
    // auth boundary. Decision: fail-safe, not fail-closed. When provenance
    // cannot be established (spoof attempt, OR a legitimate edge case such
    // as CI, a debugger, the contract-test harness, or a shell wrapper that
    // dropped the env), we log a WARN and still process. A false positive
    // that blocks every hook is a strictly worse outcome than the residual
    // local same-uid attacker risk already acknowledged in the threat
    // model. The WARN gives operators a forensic signal without a hard
    // crash that would break legitimate use.
    let env_pairs: Vec<(&str, Option<String>)> = CLAUDE_PROVENANCE_ENV_VARS
        .iter()
        .map(|name| (*name, std::env::var(name).ok()))
        .collect();
    if classify_provenance(&env_pairs) == Provenance::Unverified {
        warn!(
            "hook provenance unverified: no Claude Code env var present \
             ({}). Processing anyway (fail-safe); if unexpected, a local \
             process may be spoofing the hook envelope.",
            CLAUDE_PROVENANCE_ENV_VARS.join(", ")
        );
    }

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
