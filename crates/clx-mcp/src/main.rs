//! CLX MCP Server Binary
//!
//! This binary provides MCP (Model Context Protocol) tools to CLX's supported
//! coding-agent hosts (Claude Code, Codex CLI, Cursor).
//! It communicates via JSON-RPC over stdio.
//!
//! Tools provided:
//! - `clx_recall`: Semantic search for relevant context (with embedding-based search when available)
//! - `clx_remember`: Save information to the database with embeddings
//! - `clx_checkpoint`: Create a manual snapshot
//! - `clx_rules`: Manage whitelist/blacklist rules
//! - `clx_session_info`: Get current session details
//! - `clx_credentials`: Securely manage credentials via OS keychain
//! - `clx_stats`: Get session statistics

mod protocol;
mod server;
mod tools;
mod validation;

#[cfg(test)]
mod tests;

use anyhow::Result;
use std::io;
use tracing::info;

use server::McpServer;

fn main() -> Result<()> {
    warn_on_version_skew();

    clx_core::init_sqlite_vec();

    tracing_subscriber::fmt()
        .with_writer(io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("clx_mcp=info".parse().unwrap()),
        )
        .init();

    info!("CLX MCP Server starting...");

    let server = McpServer::new()?;
    server.run()?;

    info!("CLX MCP Server shutting down");
    Ok(())
}

/// Emits a one-shot version-skew warning to STDERR if the installed stamp in
/// `~/.clx/bin` differs from this binary's version.
///
/// Writes only to STDERR (the MCP stdio transport owns STDOUT) and never aborts
/// startup. Runs once, before any other startup work.
fn warn_on_version_skew() {
    if let Some(warning) = clx_core::version::version_skew_warning(
        &clx_core::paths::clx_dir(),
        clx_core::version::VERSION,
    ) {
        eprintln!("clx-mcp: {warning}");
    }
}
