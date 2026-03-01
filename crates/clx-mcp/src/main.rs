//! CLX MCP Server Binary
//!
//! This binary provides MCP (Model Context Protocol) tools for Claude Code integration.
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
