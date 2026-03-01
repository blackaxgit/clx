//! Tool implementations for the MCP server.
//!
//! Each tool is implemented in its own module using the split-impl pattern
//! (`impl McpServer` blocks in each file) so that tool methods have access
//! to all server state via `&self`.

pub mod checkpoint;
pub mod credentials;
pub mod recall;
pub mod remember;
pub mod rules;
pub mod session_info;
pub mod stats;
