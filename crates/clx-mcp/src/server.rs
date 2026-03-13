//! MCP Server core — struct definition, initialization, request dispatch, and I/O loop.

use anyhow::{Context, Result};
use serde_json::{Value, json};
use std::env;
use std::io::{self, Write};
use tracing::{debug, error, info, warn};

use clx_core::config::OllamaConfig;
use clx_core::credentials::CredentialStore;
use clx_core::embeddings::EmbeddingStore;
use clx_core::ollama::OllamaClient;
use clx_core::redaction::redact_secrets;
use clx_core::storage::Storage;
use clx_core::types::SessionId;

use crate::protocol::mcp_types::{
    InitializeResult, ServerCapabilities, ServerInfo, Tool, ToolsCapability,
};
use crate::protocol::types::{
    INVALID_PARAMS, INVALID_REQUEST, JsonRpcRequest, JsonRpcResponse, METHOD_NOT_FOUND, PARSE_ERROR,
};

/// Timeout for embedding generation in milliseconds (for recall/search operations)
pub(crate) const EMBEDDING_TIMEOUT_MS: u64 = 2000;

/// Timeout for embedding storage in milliseconds (for remember/checkpoint operations)
pub(crate) const EMBEDDING_STORE_TIMEOUT_MS: u64 = 5000;

/// Maximum number of semantic search results to return
pub(crate) const MAX_SEMANTIC_RESULTS: usize = 10;

/// Distance threshold for semantic search (lower = more similar)
/// Results with distance above this are considered less relevant
pub(crate) const SEMANTIC_DISTANCE_THRESHOLD: f32 = 1.5;

/// MCP server state
pub struct McpServer {
    pub(crate) storage: Storage,
    pub(crate) session_id: Option<SessionId>,
    pub(crate) db_path: String,
    pub(crate) credential_store: CredentialStore,
    /// Ollama client for embedding generation (initialized lazily)
    pub(crate) ollama_client: Option<OllamaClient>,
    /// Embedding store for vector search (initialized lazily)
    pub(crate) embedding_store: Option<EmbeddingStore>,
    /// Tokio runtime for async operations
    pub(crate) runtime: tokio::runtime::Runtime,
}

impl McpServer {
    pub fn new() -> Result<Self> {
        // Get database path from environment or use default
        let db_path = env::var("CLX_DB_PATH").unwrap_or_else(|_| {
            clx_core::paths::database_path()
                .to_string_lossy()
                .to_string()
        });

        let storage = Storage::open(&db_path).context("Failed to open database")?;
        let session_id = env::var("CLX_SESSION_ID").ok().map(SessionId::from);

        let credential_store = CredentialStore::new();

        // Create Tokio runtime for async operations
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("Failed to create Tokio runtime")?;

        // Initialize Ollama client with custom timeout for embeddings
        let ollama_config = OllamaConfig {
            timeout_ms: EMBEDDING_TIMEOUT_MS,
            ..OllamaConfig::default()
        };
        let ollama_client = match OllamaClient::new(ollama_config) {
            Ok(client) => Some(client),
            Err(e) => {
                warn!(
                    "Failed to create Ollama client: {}. Embeddings will be disabled.",
                    e
                );
                None
            }
        };

        // Initialize embedding store (may fail if sqlite-vec not available)
        let embedding_store = match Storage::create_embedding_store(&db_path) {
            Ok(store) => {
                if store.is_vector_search_enabled() {
                    info!("Embedding store initialized with vector search support");
                    Some(store)
                } else {
                    warn!(
                        "Embedding store created but vector search is disabled (sqlite-vec not loaded)"
                    );
                    Some(store)
                }
            }
            Err(e) => {
                warn!(
                    "Failed to create embedding store: {}. Semantic search will be disabled.",
                    e
                );
                None
            }
        };

        info!(
            "MCP server initialized with db_path={}, session_id={:?}, embeddings_enabled={}",
            db_path,
            session_id,
            embedding_store
                .as_ref()
                .is_some_and(clx_core::embeddings::EmbeddingStore::is_vector_search_enabled)
        );

        Ok(Self {
            storage,
            session_id,
            db_path,
            credential_store,
            ollama_client,
            embedding_store,
            runtime,
        })
    }

    /// Get all available tools
    #[allow(clippy::unused_self)] // Will use self for dynamic tool configuration
    pub fn get_tools(&self) -> Vec<Tool> {
        vec![
            Tool {
                name: "clx_recall".to_string(),
                description: "Search historical context using semantic search. Returns relevant snippets from previous sessions.".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "query": {
                            "type": "string",
                            "description": "Search query to find relevant context"
                        }
                    },
                    "required": ["query"]
                }),
            },
            Tool {
                name: "clx_remember".to_string(),
                description: "Save important information to the context database for future recall.".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "text": {
                            "type": "string",
                            "description": "The information to remember"
                        },
                        "tags": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Optional tags for categorization"
                        }
                    },
                    "required": ["text"]
                }),
            },
            Tool {
                name: "clx_checkpoint".to_string(),
                description: "Create a manual checkpoint/snapshot of the current session state.".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "note": {
                            "type": "string",
                            "description": "Optional note describing the checkpoint"
                        }
                    }
                }),
            },
            Tool {
                name: "clx_rules".to_string(),
                description: "Get project rules from CLAUDE.md or manage whitelist/blacklist rules for command validation.".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "action": {
                            "type": "string",
                            "enum": ["get_project_rules", "list", "add", "remove"],
                            "description": "Action: get_project_rules (get CLAUDE.md rules), list/add/remove (manage command rules)"
                        },
                        "category": {
                            "type": "string",
                            "description": "Optional category filter for get_project_rules (e.g., 'security', 'coding', 'testing')"
                        },
                        "pattern": {
                            "type": "string",
                            "description": "Pattern for add/remove actions (glob syntax)"
                        },
                        "rule_type": {
                            "type": "string",
                            "enum": ["whitelist", "blacklist"],
                            "description": "Type of rule for add action"
                        }
                    },
                    "required": ["action"]
                }),
            },
            Tool {
                name: "clx_session_info".to_string(),
                description: "Get information about the current CLX session.".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {}
                }),
            },
            Tool {
                name: "clx_credentials".to_string(),
                description: "Securely manage credentials using the system keychain. Store, retrieve, delete, or list API keys and secrets.".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "action": {
                            "type": "string",
                            "enum": ["get", "set", "delete", "list"],
                            "description": "Action to perform: get (retrieve), set (store), delete (remove), or list (show all keys)"
                        },
                        "key": {
                            "type": "string",
                            "description": "The credential key name (required for get, set, delete)"
                        },
                        "value": {
                            "type": "string",
                            "description": "The credential value to store (required for set action)"
                        },
                        "project": {
                            "type": "string",
                            "description": "Project name for credential fallback lookup. When provided with 'get' action, checks project-scoped credential first, then falls back to global."
                        }
                    },
                    "required": ["action"]
                }),
            },
            Tool {
                name: "clx_stats".to_string(),
                description: "Get session statistics including command counts, validation decisions, and usage metrics.".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "days": {
                            "type": "integer",
                            "description": "Number of days to include in stats (default: 7)"
                        }
                    }
                }),
            },
        ]
    }

    /// Handle initialize request
    #[allow(clippy::unused_self)] // Will use self for dynamic capability configuration
    pub fn handle_initialize(&self, _params: &Value) -> Value {
        let result = InitializeResult {
            protocol_version: "2024-11-05".to_string(),
            capabilities: ServerCapabilities {
                tools: ToolsCapability {
                    list_changed: false,
                },
            },
            server_info: ServerInfo {
                name: "clx-mcp".to_string(),
                version: clx_core::VERSION.to_string(),
            },
        };
        serde_json::to_value(result).unwrap_or(json!({}))
    }

    /// Handle tools/list request
    pub fn handle_tools_list(&self) -> Value {
        json!({
            "tools": self.get_tools()
        })
    }

    /// Handle tools/call request
    pub fn handle_tools_call(&self, params: &Value) -> Result<Value, (i32, String)> {
        let name = params
            .get("name")
            .and_then(|v| v.as_str())
            .ok_or((INVALID_PARAMS, "Missing tool name".to_string()))?;

        let arguments = params.get("arguments").cloned().unwrap_or(json!({}));

        debug!(
            "Calling tool: {} with arguments: {}",
            name,
            redact_secrets(&format!("{arguments:?}"))
        );

        match name {
            "clx_recall" => self.tool_recall(&arguments),
            "clx_remember" => self.tool_remember(&arguments),
            "clx_checkpoint" => self.tool_checkpoint(&arguments),
            "clx_rules" => self.tool_rules(&arguments),
            "clx_session_info" => self.tool_session_info(&arguments),
            "clx_credentials" => self.tool_credentials(&arguments),
            "clx_stats" => self.tool_stats(&arguments),
            _ => Err((METHOD_NOT_FOUND, format!("Unknown tool: {name}"))),
        }
    }

    /// Process a single JSON-RPC request and return a response
    pub fn process_request(&self, request: &JsonRpcRequest) -> JsonRpcResponse {
        if request.jsonrpc != "2.0" {
            return JsonRpcResponse::error(
                request.id.clone(),
                INVALID_REQUEST,
                "Invalid JSON-RPC version",
            );
        }

        match request.method.as_str() {
            "initialize" => {
                let result = self.handle_initialize(&request.params);
                JsonRpcResponse::success(request.id.clone(), result)
            }
            "initialized" => {
                // Notification, no response needed but we'll acknowledge
                JsonRpcResponse::success(request.id.clone(), json!({}))
            }
            "tools/list" => {
                let result = self.handle_tools_list();
                JsonRpcResponse::success(request.id.clone(), result)
            }
            "tools/call" => match self.handle_tools_call(&request.params) {
                Ok(result) => JsonRpcResponse::success(request.id.clone(), result),
                Err((code, message)) => JsonRpcResponse::error(request.id.clone(), code, &message),
            },
            "notifications/cancelled" => {
                // Handle cancellation notification
                JsonRpcResponse::success(request.id.clone(), json!({}))
            }
            "ping" => {
                // Health check
                JsonRpcResponse::success(request.id.clone(), json!({}))
            }
            _ => JsonRpcResponse::error(
                request.id.clone(),
                METHOD_NOT_FOUND,
                &format!("Method not found: {}", request.method),
            ),
        }
    }

    /// Maximum size for a single JSON-RPC message line (10 MB).
    ///
    /// Prevents memory exhaustion from malicious or malformed input.
    pub const MAX_LINE_SIZE: usize = 10 * 1024 * 1024;

    /// Read a single line from the reader with a size limit.
    ///
    /// Returns `Ok(None)` on EOF. Returns a JSON-RPC error response if the
    /// line exceeds `MAX_LINE_SIZE` bytes.
    pub fn read_bounded_line(
        reader: &mut impl io::BufRead,
        buf: &mut String,
    ) -> io::Result<Option<()>> {
        buf.clear();
        let mut total = 0usize;
        loop {
            let available = reader.fill_buf()?;
            if available.is_empty() {
                // EOF
                return if total == 0 { Ok(None) } else { Ok(Some(())) };
            }

            if let Some(newline_pos) = available.iter().position(|&b| b == b'\n') {
                // Found newline — consume up to and including it
                let chunk = &available[..newline_pos];
                total += chunk.len();
                if total > Self::MAX_LINE_SIZE {
                    // Consume the rest of the line so we can continue
                    let consume_len = newline_pos + 1;
                    reader.consume(consume_len);
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("Line exceeds maximum size of {} bytes", Self::MAX_LINE_SIZE),
                    ));
                }
                // Safe: fill_buf returns valid UTF-8 boundaries per BufRead on stdin
                buf.push_str(&String::from_utf8_lossy(chunk));
                let consume_len = newline_pos + 1; // +1 to skip the newline
                reader.consume(consume_len);
                return Ok(Some(()));
            }

            // No newline yet — consume entire buffer
            let len = available.len();
            total += len;
            if total > Self::MAX_LINE_SIZE {
                reader.consume(len);
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Line exceeds maximum size of {} bytes", Self::MAX_LINE_SIZE),
                ));
            }
            buf.push_str(&String::from_utf8_lossy(available));
            reader.consume(len);
        }
    }

    /// Run the server main loop
    pub fn run(&self) -> Result<()> {
        let stdin = io::stdin();
        let mut reader = stdin.lock();
        let mut stdout = io::stdout();
        let mut line_buf = String::new();

        loop {
            match Self::read_bounded_line(&mut reader, &mut line_buf) {
                Ok(None) => break, // EOF
                Ok(Some(())) => {}
                Err(e) => {
                    error!("Failed to read line: {}", e);
                    // If the line was too large, send a JSON-RPC error
                    if e.kind() == io::ErrorKind::InvalidData {
                        let response = JsonRpcResponse::error(
                            None,
                            PARSE_ERROR,
                            &format!("Message too large: {e}"),
                        );
                        let output = serde_json::to_string(&response)?;
                        writeln!(stdout, "{output}")?;
                        stdout.flush()?;
                    }
                    continue;
                }
            }

            if line_buf.trim().is_empty() {
                continue;
            }

            debug!("Received: {}", redact_secrets(&line_buf));

            let request: JsonRpcRequest = match serde_json::from_str(&line_buf) {
                Ok(req) => req,
                Err(e) => {
                    error!("Failed to parse request: {}", e);
                    let response =
                        JsonRpcResponse::error(None, PARSE_ERROR, &format!("Parse error: {e}"));
                    let output = serde_json::to_string(&response)?;
                    writeln!(stdout, "{output}")?;
                    stdout.flush()?;
                    continue;
                }
            };

            let response = self.process_request(&request);

            // Don't send response for notifications (requests without id)
            if request.id.is_some() || response.error.is_some() {
                let output = serde_json::to_string(&response)?;
                debug!("Sending: {}", redact_secrets(&output));
                writeln!(stdout, "{output}")?;
                stdout.flush()?;
            }
        }

        Ok(())
    }
}
