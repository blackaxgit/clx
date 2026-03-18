//! Ollama HTTP client for LLM inference and embeddings
//!
//! This module provides an async HTTP client for interacting with a local Ollama instance.
//! It supports text generation, embeddings, and model management.
//!
//! # Example
//!
//! ```no_run
//! use clx_core::ollama::OllamaClient;
//! use clx_core::config::OllamaConfig;
//!
//! # async fn example() -> Result<(), clx_core::ollama::OllamaError> {
//! let config = OllamaConfig::default();
//! let client = OllamaClient::new(config)?;
//!
//! // Check if Ollama is available
//! if client.is_available().await {
//!     // Generate text
//!     let response = client.generate("Hello, world!", None).await?;
//!     println!("Response: {}", response);
//!
//!     // Get embeddings
//!     let embeddings: Vec<f32> = client.embed("Some text to embed", None).await?;
//!     println!("Embedding dimension: {}", embeddings.len());
//! }
//! # Ok(())
//! # }
//! ```

use crate::config::OllamaConfig;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::Semaphore;

/// Maximum allowed response body size from Ollama (100KB).
const MAX_RESPONSE_SIZE: usize = 100_000;

/// Maximum number of concurrent Ollama HTTP requests.
const MAX_CONCURRENT_REQUESTS: usize = 5;

/// Timeout for health check requests (2 seconds).
const HEALTH_CHECK_TIMEOUT_MS: u64 = 2_000;

/// Maximum retries for health checks (1 retry = 2 attempts total).
const HEALTH_CHECK_MAX_RETRIES: u32 = 1;

/// Errors that can occur when interacting with Ollama
#[derive(Error, Debug)]
pub enum OllamaError {
    /// Failed to connect to Ollama server
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),

    /// Request timed out
    #[error("Request timed out after {0}ms")]
    Timeout(u64),

    /// HTTP request failed
    #[error("HTTP error: {0}")]
    HttpError(#[from] reqwest::Error),

    /// Invalid response from Ollama
    #[error("Invalid response: {0}")]
    InvalidResponse(String),

    /// Model not found
    #[error("Model not found: {0}")]
    ModelNotFound(String),

    /// Server returned an error
    #[error("Server error: {0}")]
    ServerError(String),

    /// Serialization/deserialization error
    #[error("Serialization error: {0}")]
    SerializationError(serde_json::Error),
}

/// Request body for /api/generate endpoint
#[derive(Debug, Serialize)]
struct GenerateRequest<'a> {
    model: &'a str,
    prompt: &'a str,
    stream: bool,
}

/// Response from /api/generate endpoint
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct GenerateResponse {
    response: String,
    done: bool,
}

/// Request body for /api/embeddings endpoint
#[derive(Debug, Serialize)]
struct EmbeddingsRequest<'a> {
    model: &'a str,
    prompt: &'a str,
}

/// Response from /api/embeddings endpoint
#[derive(Debug, Deserialize)]
struct EmbeddingsResponse {
    embedding: Vec<f32>,
}

/// Response from /api/tags endpoint (list models)
#[derive(Debug, Deserialize)]
struct TagsResponse {
    models: Vec<ModelInfo>,
}

/// Model information from /api/tags
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct ModelInfo {
    name: String,
}

/// Check whether a host string refers to a private, internal, or reserved IP/hostname.
///
/// Returns `true` if the host is:
/// - A private IPv4 address (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
/// - A link-local IPv4 address (169.254.0.0/16, including AWS/GCP metadata 169.254.169.254)
/// - A loopback address (127.0.0.0/8 or `::1`)
/// - A private IPv6 address (ULA `fc00::/7` or link-local `fe80::/10`)
/// - A hostname with an internal suffix (.local, .internal, .lan, .home, .corp, .intranet)
fn is_private_or_internal(host: &str) -> bool {
    // Strip brackets from IPv6 addresses (URL host_str returns "[::1]" form)
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);

    // Try parsing as an IP address first
    if let Ok(ip) = host.parse::<IpAddr>() {
        return match ip {
            IpAddr::V4(v4) => {
                v4.is_private()      // 10.x, 172.16-31.x, 192.168.x
                || v4.is_loopback()  // 127.x
                || v4.is_link_local() // 169.254.x (includes metadata endpoint)
            }
            IpAddr::V6(v6) => {
                v6.is_loopback() // ::1
                || {
                    let segments = v6.segments();
                    // ULA: fc00::/7 — first 7 bits are 1111110
                    (segments[0] & 0xfe00) == 0xfc00
                    // Link-local: fe80::/10 — first 10 bits are 1111111010
                    || (segments[0] & 0xffc0) == 0xfe80
                }
            }
        };
    }

    // Hostname-based checks for internal/non-routable domains
    let lower = host.to_lowercase();
    const INTERNAL_SUFFIXES: &[&str] =
        &[".local", ".internal", ".lan", ".home", ".corp", ".intranet"];
    INTERNAL_SUFFIXES
        .iter()
        .any(|suffix| lower.ends_with(suffix))
}

/// Async HTTP client for Ollama
#[derive(Debug, Clone)]
pub struct OllamaClient {
    /// HTTP client instance
    client: Client,
    /// Ollama server host URL
    host: String,
    /// Default model for text generation
    default_model: String,
    /// Default model for embeddings
    embedding_model: String,
    /// Request timeout in milliseconds
    timeout_ms: u64,
    /// Maximum number of retries for transient errors
    max_retries: u32,
    /// Initial retry delay in milliseconds
    retry_delay_ms: u64,
    /// Exponential backoff multiplier
    retry_backoff: f32,
    /// Semaphore to limit concurrent Ollama requests
    request_semaphore: Arc<Semaphore>,
}

impl OllamaClient {
    /// Create a new Ollama client from configuration
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP client cannot be created (e.g., TLS initialization failure),
    /// or if the host URL is not localhost (unless `CLX_ALLOW_REMOTE_OLLAMA=true`).
    pub fn new(config: OllamaConfig) -> std::result::Result<Self, OllamaError> {
        // Validate host URL — enforce localhost for security
        let url = reqwest::Url::parse(&config.host)
            .map_err(|e| OllamaError::ConnectionFailed(format!("Invalid Ollama URL: {e}")))?;

        match url.host_str() {
            Some("127.0.0.1" | "localhost" | "::1" | "[::1]") => {}
            Some(host) => {
                if std::env::var("CLX_ALLOW_REMOTE_OLLAMA").unwrap_or_default() != "true" {
                    return Err(OllamaError::ConnectionFailed(format!(
                        "Ollama host '{host}' is not localhost. Set CLX_ALLOW_REMOTE_OLLAMA=true to override."
                    )));
                }
                // Even with the remote override, block private/internal addresses
                // to prevent SSRF attacks against internal infrastructure
                if is_private_or_internal(host) {
                    return Err(OllamaError::ConnectionFailed(format!(
                        "Ollama host '{host}' is a private or internal address. \
                         Private IP ranges, link-local addresses, and internal hostnames \
                         are blocked to prevent SSRF attacks. Use a public IP or hostname."
                    )));
                }
                tracing::warn!(
                    "Using remote Ollama host: {} (security override active)",
                    host
                );
            }
            None => {
                return Err(OllamaError::ConnectionFailed(
                    "Ollama URL has no host".into(),
                ));
            }
        }

        let timeout = Duration::from_millis(config.timeout_ms);
        let client = Client::builder().timeout(timeout).build().map_err(|e| {
            OllamaError::ConnectionFailed(format!("Failed to create HTTP client: {e}"))
        })?;

        Ok(Self {
            client,
            host: config.host,
            default_model: config.model,
            embedding_model: config.embedding_model,
            timeout_ms: config.timeout_ms,
            max_retries: config.max_retries,
            retry_delay_ms: config.retry_delay_ms,
            retry_backoff: config.retry_backoff,
            request_semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT_REQUESTS)),
        })
    }

    /// Create a new Ollama client with custom host and timeout
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP client cannot be created
    pub fn with_host(
        host: impl Into<String>,
        timeout_ms: u64,
    ) -> std::result::Result<Self, OllamaError> {
        let config = OllamaConfig {
            host: host.into(),
            timeout_ms,
            ..Default::default()
        };
        Self::new(config)
    }

    /// Get the configured host URL
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Get the configured timeout in milliseconds
    #[must_use]
    pub fn timeout_ms(&self) -> u64 {
        self.timeout_ms
    }

    /// Check if Ollama server is available
    ///
    /// Returns true if the server is reachable and responding.
    /// Retries up to `max_retries` times with exponential backoff to handle
    /// transient failures (e.g., Ollama briefly busy loading a model).
    pub async fn is_available(&self) -> bool {
        let url = format!("{}/api/tags", self.host);
        let health_timeout = Duration::from_millis(HEALTH_CHECK_TIMEOUT_MS);
        let mut attempt = 0u32;
        loop {
            match self.client.get(&url).timeout(health_timeout).send().await {
                Ok(response) if response.status().is_success() => return true,
                Ok(_) | Err(_) if attempt < HEALTH_CHECK_MAX_RETRIES => {
                    let delay = (self.retry_delay_ms as f32
                        * self.retry_backoff.powi(attempt as i32))
                        as u64;
                    tracing::debug!(
                        "Ollama availability check failed (attempt {}/{}), retrying in {delay}ms",
                        attempt + 1,
                        HEALTH_CHECK_MAX_RETRIES + 1,
                    );
                    tokio::time::sleep(Duration::from_millis(delay)).await;
                    attempt += 1;
                }
                _ => return false,
            }
        }
    }

    /// Generic retry helper with exponential backoff for transient HTTP errors.
    ///
    /// Retries the given operation on transient reqwest errors (connection failures,
    /// timeouts) up to `max_retries` times with exponential backoff.
    fn retry_with_backoff<'a, F, Fut, T>(
        &'a self,
        operation: &'a str,
        f: F,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = std::result::Result<T, OllamaError>> + Send + 'a>,
    >
    where
        F: Fn() -> Fut + Send + Sync + 'a,
        Fut: std::future::Future<Output = std::result::Result<T, reqwest::Error>> + Send + 'a,
        T: Send + 'a,
    {
        Box::pin(async move {
            let mut attempt = 0u32;
            loop {
                match f().await {
                    Ok(result) => return Ok(result),
                    Err(e) => {
                        if self.is_transient_error(&e) && attempt < self.max_retries {
                            let delay = (self.retry_delay_ms as f32
                                * self.retry_backoff.powi(attempt as i32))
                                as u64;
                            tracing::debug!(
                                "Ollama {} request failed (attempt {}/{}), retrying in {}ms: {}",
                                operation,
                                attempt + 1,
                                self.max_retries + 1,
                                delay,
                                e
                            );
                            tokio::time::sleep(Duration::from_millis(delay)).await;
                            attempt += 1;
                        } else {
                            return self.map_reqwest_error(e);
                        }
                    }
                }
            }
        })
    }

    /// Parse a successful response body with a size limit.
    ///
    /// Reads the full response as bytes, checks the size against `MAX_RESPONSE_SIZE`,
    /// and deserializes the JSON into the requested type.
    async fn parse_response_with_limit<T: serde::de::DeserializeOwned>(
        response: reqwest::Response,
    ) -> std::result::Result<T, OllamaError> {
        let body_bytes = response.bytes().await.map_err(|e| {
            OllamaError::InvalidResponse(format!("Failed to read response body: {e}"))
        })?;
        if body_bytes.len() > MAX_RESPONSE_SIZE {
            return Err(OllamaError::InvalidResponse(format!(
                "Response too large: {} bytes (max {})",
                body_bytes.len(),
                MAX_RESPONSE_SIZE
            )));
        }
        serde_json::from_slice(&body_bytes)
            .map_err(|e| OllamaError::InvalidResponse(format!("JSON parse error: {e}")))
    }

    /// Acquire a concurrency permit before making an Ollama request.
    ///
    /// Limits the number of in-flight HTTP requests to prevent overwhelming Ollama.
    async fn acquire_permit(
        &self,
    ) -> std::result::Result<tokio::sync::OwnedSemaphorePermit, OllamaError> {
        self.request_semaphore
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| OllamaError::ConnectionFailed("Request semaphore closed".to_string()))
    }

    /// Generate text completion using the specified or default model
    ///
    /// # Arguments
    ///
    /// * `prompt` - The input prompt for text generation
    /// * `model` - Optional model name (uses default if None)
    ///
    /// # Returns
    ///
    /// The generated text response
    pub async fn generate(
        &self,
        prompt: &str,
        model: Option<&str>,
    ) -> std::result::Result<String, OllamaError> {
        let _permit = self.acquire_permit().await?;

        let model = model.unwrap_or(&self.default_model);
        let url = format!("{}/api/generate", self.host);

        let raw_response = self
            .retry_with_backoff("generate", || {
                let request = GenerateRequest {
                    model,
                    prompt,
                    stream: false,
                };
                self.client.post(&url).json(&request).send()
            })
            .await?;

        if raw_response.status().is_success() {
            let gen_response: GenerateResponse =
                Self::parse_response_with_limit(raw_response).await?;
            Ok(gen_response.response)
        } else if raw_response.status().as_u16() == 404 {
            Err(OllamaError::ModelNotFound(model.to_string()))
        } else {
            let status = raw_response.status();
            let body = raw_response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            Err(OllamaError::ServerError(format!("Status {status}: {body}")))
        }
    }

    /// Generate embeddings for the given text
    ///
    /// # Arguments
    ///
    /// * `text` - The text to generate embeddings for
    /// * `model` - Optional model name (uses default embedding model if None)
    ///
    /// # Returns
    ///
    /// A vector of floating-point embedding values
    pub async fn embed(
        &self,
        text: &str,
        model: Option<&str>,
    ) -> std::result::Result<Vec<f32>, OllamaError> {
        let _permit = self.acquire_permit().await?;

        let model = model.unwrap_or(&self.embedding_model);
        let url = format!("{}/api/embeddings", self.host);

        let raw_response = self
            .retry_with_backoff("embed", || {
                let request = EmbeddingsRequest {
                    model,
                    prompt: text,
                };
                self.client.post(&url).json(&request).send()
            })
            .await?;

        if raw_response.status().is_success() {
            let embed_response: EmbeddingsResponse =
                Self::parse_response_with_limit(raw_response).await?;
            Ok(embed_response.embedding)
        } else if raw_response.status().as_u16() == 404 {
            Err(OllamaError::ModelNotFound(model.to_string()))
        } else {
            let status = raw_response.status();
            let body = raw_response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            Err(OllamaError::ServerError(format!("Status {status}: {body}")))
        }
    }

    /// List available models
    ///
    /// # Returns
    ///
    /// A vector of model names available on the Ollama server
    pub async fn list_models(&self) -> std::result::Result<Vec<String>, OllamaError> {
        let _permit = self.acquire_permit().await?;

        let url = format!("{}/api/tags", self.host);

        let raw_response = self
            .retry_with_backoff("list_models", || self.client.get(&url).send())
            .await?;

        if raw_response.status().is_success() {
            let tags_response: TagsResponse = Self::parse_response_with_limit(raw_response).await?;
            Ok(tags_response.models.into_iter().map(|m| m.name).collect())
        } else {
            let status = raw_response.status();
            let body = raw_response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            Err(OllamaError::ServerError(format!("Status {status}: {body}")))
        }
    }

    /// Check if an error is transient and should be retried
    #[allow(clippy::unused_self)] // Kept as method for future config-dependent retry logic
    fn is_transient_error(&self, error: &reqwest::Error) -> bool {
        // Retry on connection errors or timeouts
        error.is_connect() || error.is_timeout()
    }

    /// Map reqwest errors to `OllamaError`
    fn map_reqwest_error<T>(&self, error: reqwest::Error) -> std::result::Result<T, OllamaError> {
        if error.is_timeout() {
            Err(OllamaError::Timeout(self.timeout_ms))
        } else if error.is_connect() {
            Err(OllamaError::ConnectionFailed(format!(
                "Could not connect to Ollama at {}: {}",
                self.host, error
            )))
        } else {
            Err(OllamaError::HttpError(error))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // T08 + T09 — Wiremock-based async HTTP tests
    // -----------------------------------------------------------------------
    mod async_tests {
        use super::*;
        use std::time::Duration;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        /// Start a wiremock server and build an `OllamaClient` pointed at it.
        ///
        /// `max_retries` is set to 0 so tests observe exactly one attempt and
        /// never sleep between retries. `timeout_ms` is kept at the default
        /// 60 s so only the dedicated timeout test overrides it.
        async fn mock_ollama() -> (MockServer, OllamaClient) {
            let server = MockServer::start().await;
            let config = OllamaConfig {
                host: server.uri(),
                max_retries: 0,
                ..OllamaConfig::default()
            };
            let client = OllamaClient::new(config).expect("failed to build OllamaClient in test");
            (server, client)
        }

        // ------------------------------------------------------------------
        // embed() tests
        // ------------------------------------------------------------------

        #[tokio::test]
        async fn embed_success_returns_embedding_vec() {
            // Arrange
            let (server, client) = mock_ollama().await;
            Mock::given(method("POST"))
                .and(path("/api/embeddings"))
                .respond_with(
                    ResponseTemplate::new(200)
                        .set_body_raw(r#"{"embedding":[0.1,0.2,0.3]}"#, "application/json"),
                )
                .mount(&server)
                .await;

            // Act
            let result = client.embed("hello", None).await;

            // Assert
            let embedding = result.expect("embed should succeed");
            assert_eq!(embedding.len(), 3);
        }

        #[tokio::test]
        async fn embed_http_500_returns_err() {
            // Arrange
            let (server, client) = mock_ollama().await;
            Mock::given(method("POST"))
                .and(path("/api/embeddings"))
                .respond_with(ResponseTemplate::new(500))
                .mount(&server)
                .await;

            // Act
            let result = client.embed("hello", None).await;

            // Assert
            assert!(result.is_err(), "expected Err on HTTP 500");
        }

        #[tokio::test]
        async fn embed_timeout_returns_err() {
            // Arrange — use a very short timeout so the test completes quickly.
            let server = MockServer::start().await;
            let config = OllamaConfig {
                host: server.uri(),
                max_retries: 0,
                timeout_ms: 100, // 100 ms client timeout
                ..OllamaConfig::default()
            };
            let client = OllamaClient::new(config).expect("failed to build OllamaClient in test");

            Mock::given(method("POST"))
                .and(path("/api/embeddings"))
                .respond_with(
                    ResponseTemplate::new(200).set_delay(Duration::from_secs(30)), // far exceeds the 100 ms timeout
                )
                .mount(&server)
                .await;

            // Act
            let result = client.embed("hello", None).await;

            // Assert
            assert!(result.is_err(), "expected Err on timeout");
        }

        #[tokio::test]
        async fn embed_explicit_model_param_succeeds() {
            // Arrange
            let (server, client) = mock_ollama().await;
            Mock::given(method("POST"))
                .and(path("/api/embeddings"))
                .respond_with(
                    ResponseTemplate::new(200)
                        .set_body_raw(r#"{"embedding":[0.5,0.6,0.7,0.8]}"#, "application/json"),
                )
                .mount(&server)
                .await;

            // Act — pass an explicit model name instead of relying on the default
            let result = client.embed("hello", Some("nomic-embed-text")).await;

            // Assert
            let embedding = result.expect("embed with explicit model should succeed");
            assert_eq!(embedding.len(), 4);
        }

        // ------------------------------------------------------------------
        // generate() tests
        // ------------------------------------------------------------------

        #[tokio::test]
        async fn generate_success_returns_response_text() {
            // Arrange
            let (server, client) = mock_ollama().await;
            Mock::given(method("POST"))
                .and(path("/api/generate"))
                .respond_with(
                    ResponseTemplate::new(200)
                        .set_body_raw(r#"{"response":"text","done":true}"#, "application/json"),
                )
                .mount(&server)
                .await;

            // Act
            let result = client.generate("Hello", None).await;

            // Assert
            let text = result.expect("generate should succeed");
            assert!(
                text.contains("text"),
                "response should contain 'text', got: {text}"
            );
        }

        #[tokio::test]
        async fn generate_empty_response_returns_empty_string() {
            // Arrange
            let (server, client) = mock_ollama().await;
            Mock::given(method("POST"))
                .and(path("/api/generate"))
                .respond_with(
                    ResponseTemplate::new(200)
                        .set_body_raw(r#"{"response":"","done":true}"#, "application/json"),
                )
                .mount(&server)
                .await;

            // Act
            let result = client.generate("Hello", None).await;

            // Assert
            let text = result.expect("generate with empty response should succeed");
            assert_eq!(text, "");
        }

        #[tokio::test]
        async fn generate_http_503_returns_err() {
            // Arrange
            let (server, client) = mock_ollama().await;
            Mock::given(method("POST"))
                .and(path("/api/generate"))
                .respond_with(ResponseTemplate::new(503))
                .mount(&server)
                .await;

            // Act
            let result = client.generate("Hello", None).await;

            // Assert
            assert!(result.is_err(), "expected Err on HTTP 503");
        }

        // ------------------------------------------------------------------
        // is_available() tests
        // ------------------------------------------------------------------

        #[tokio::test]
        async fn is_available_returns_true_when_server_up() {
            // Arrange — mount a 200 response on GET /api/tags (the health-check endpoint)
            let (server, client) = mock_ollama().await;
            Mock::given(method("GET"))
                .and(path("/api/tags"))
                .respond_with(
                    ResponseTemplate::new(200).set_body_raw(r#"{"models":[]}"#, "application/json"),
                )
                .mount(&server)
                .await;

            // Act
            let available = client.is_available().await;

            // Assert
            assert!(available, "client should report server as available");
        }

        #[tokio::test]
        async fn is_available_returns_false_when_no_successful_response() {
            // Arrange — wiremock returns 404 for unmatched requests; no mock
            // is mounted, so every request gets a 404, which is not a 2xx
            // success and therefore is_available() should return false.
            let (server, client) = mock_ollama().await;
            // Drop the server binding to suppress the "unused variable" lint
            // while keeping the server alive long enough for the request.
            let _ = &server;

            // Act
            let available = client.is_available().await;

            // Assert
            assert!(!available, "client should report server as unavailable");
        }

        #[tokio::test]
        async fn is_available_returns_false_on_http_error() {
            // Arrange — mount a mock that returns HTTP 500 on GET /api/tags
            let (server, client) = mock_ollama().await;
            Mock::given(method("GET"))
                .and(path("/api/tags"))
                .respond_with(ResponseTemplate::new(500))
                .mount(&server)
                .await;

            // Act
            let available = client.is_available().await;

            // Assert — a 500 response is not a success; the client must report unavailable
            assert!(
                !available,
                "HTTP 500 must cause is_available() to return false"
            );
        }

        // ------------------------------------------------------------------
        // list_models() tests
        // ------------------------------------------------------------------

        #[tokio::test]
        async fn list_models_success_returns_model_names() {
            // Arrange
            let (server, client) = mock_ollama().await;
            Mock::given(method("GET"))
                .and(path("/api/tags"))
                .respond_with(ResponseTemplate::new(200).set_body_raw(
                    r#"{"models":[{"name":"llama3.2:3b"},{"name":"mistral:7b"}]}"#,
                    "application/json",
                ))
                .mount(&server)
                .await;

            // Act
            let result = client.list_models().await;

            // Assert
            let models = result.expect("list_models should succeed");
            assert!(
                models.contains(&"llama3.2:3b".to_string()),
                "should contain llama3.2:3b, got: {models:?}"
            );
        }

        #[tokio::test]
        async fn list_models_empty_returns_empty_vec() {
            // Arrange
            let (server, client) = mock_ollama().await;
            Mock::given(method("GET"))
                .and(path("/api/tags"))
                .respond_with(
                    ResponseTemplate::new(200).set_body_raw(r#"{"models":[]}"#, "application/json"),
                )
                .mount(&server)
                .await;

            // Act
            let result = client.list_models().await;

            // Assert
            let models = result.expect("list_models with empty list should succeed");
            assert!(models.is_empty(), "expected empty vec, got: {models:?}");
        }

        #[tokio::test]
        async fn list_models_http_404_returns_err() {
            // Arrange
            let (server, client) = mock_ollama().await;
            Mock::given(method("GET"))
                .and(path("/api/tags"))
                .respond_with(ResponseTemplate::new(404))
                .mount(&server)
                .await;

            // Act
            let result = client.list_models().await;

            // Assert
            assert!(result.is_err(), "expected Err on HTTP 404");
        }
    }

    /// RAII guard that saves env var values on creation and restores them on drop.
    /// Guarantees cleanup even if the test panics.
    #[allow(unsafe_code)]
    struct EnvGuard {
        vars: Vec<(String, Option<String>)>,
    }

    impl EnvGuard {
        fn new(keys: &[&str]) -> Self {
            let vars = keys
                .iter()
                .map(|k| (k.to_string(), std::env::var(k).ok()))
                .collect();
            Self { vars }
        }
    }

    #[allow(unsafe_code)]
    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for (key, original) in &self.vars {
                // SAFETY: Serialized via #[serial_test::serial], no concurrent mutation.
                unsafe {
                    match original {
                        Some(val) => std::env::set_var(key, val),
                        None => std::env::remove_var(key),
                    }
                }
            }
        }
    }

    #[test]
    fn test_client_creation() {
        let config = OllamaConfig::default();
        let client = OllamaClient::new(config).expect("Failed to create client in test");

        assert_eq!(client.host(), "http://127.0.0.1:11434");
        assert_eq!(client.timeout_ms(), 60000);
    }

    #[test]
    fn test_client_with_custom_host() {
        let client = OllamaClient::with_host("http://localhost:8080", 10000)
            .expect("Failed to create client in test");

        assert_eq!(client.host(), "http://localhost:8080");
        assert_eq!(client.timeout_ms(), 10000);
    }

    #[test]
    fn test_error_display() {
        let conn_err = OllamaError::ConnectionFailed("test error".to_string());
        assert!(conn_err.to_string().contains("Connection failed"));

        let timeout_err = OllamaError::Timeout(5000);
        assert!(timeout_err.to_string().contains("5000ms"));

        let model_err = OllamaError::ModelNotFound("llama3".to_string());
        assert!(model_err.to_string().contains("llama3"));

        let server_err = OllamaError::ServerError("internal error".to_string());
        assert!(server_err.to_string().contains("internal error"));

        let invalid_err = OllamaError::InvalidResponse("bad json".to_string());
        assert!(invalid_err.to_string().contains("bad json"));
    }

    #[test]
    fn test_generate_request_serialization() {
        let request = GenerateRequest {
            model: "qwen3:1.7b",
            prompt: "Hello",
            stream: false,
        };
        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("qwen3:1.7b"));
        assert!(json.contains("Hello"));
        assert!(json.contains("\"stream\":false"));
    }

    #[test]
    fn test_embeddings_request_serialization() {
        let request = EmbeddingsRequest {
            model: "qwen3-embedding:0.6b",
            prompt: "Test text",
        };
        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("qwen3-embedding:0.6b"));
        assert!(json.contains("Test text"));
    }

    #[test]
    fn test_generate_response_deserialization() {
        let json = r#"{
            "response": "Hello there!",
            "done": true,
            "context": [1, 2, 3],
            "total_duration": 1000000,
            "eval_count": 10
        }"#;
        let response: GenerateResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.response, "Hello there!");
        assert!(response.done);
    }

    #[test]
    fn test_generate_response_minimal() {
        // Test with minimal response (only required fields)
        let json = r#"{"response": "Hi", "done": false}"#;
        let response: GenerateResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.response, "Hi");
        assert!(!response.done);
    }

    #[test]
    fn test_embeddings_response_deserialization() {
        let json = r#"{"embedding": [0.1, 0.2, 0.3, 0.4]}"#;
        let response: EmbeddingsResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.embedding.len(), 4);
        assert!((response.embedding[0] - 0.1).abs() < f32::EPSILON);
    }

    #[test]
    fn test_tags_response_deserialization() {
        let json = r#"{
            "models": [
                {"name": "llama3.2:3b", "size": 1234567890},
                {"name": "mistral:7b", "digest": "abc123"}
            ]
        }"#;
        let response: TagsResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.models.len(), 2);
        assert_eq!(response.models[0].name, "llama3.2:3b");
        assert_eq!(response.models[1].name, "mistral:7b");
    }

    #[test]
    fn test_tags_response_empty() {
        let json = r#"{"models": []}"#;
        let response: TagsResponse = serde_json::from_str(json).unwrap();
        assert!(response.models.is_empty());
    }

    #[test]
    fn test_client_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<OllamaClient>();
    }

    #[test]
    fn test_error_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<OllamaError>();
    }

    // --- H4: Localhost enforcement tests ---

    #[test]
    fn test_localhost_127_allowed() {
        let config = OllamaConfig {
            host: "http://127.0.0.1:11434".to_string(),
            ..Default::default()
        };
        assert!(OllamaClient::new(config).is_ok());
    }

    #[test]
    fn test_localhost_name_allowed() {
        let config = OllamaConfig {
            host: "http://localhost:11434".to_string(),
            ..Default::default()
        };
        assert!(OllamaClient::new(config).is_ok());
    }

    #[test]
    fn test_ipv6_loopback_allowed() {
        let config = OllamaConfig {
            host: "http://[::1]:11434".to_string(),
            ..Default::default()
        };
        assert!(
            OllamaClient::new(config).is_ok(),
            "IPv6 loopback [::1] should be allowed"
        );
    }

    #[test]
    #[serial_test::serial]
    #[allow(unsafe_code)]
    fn test_remote_host_rejected() {
        let _guard = EnvGuard::new(&["CLX_ALLOW_REMOTE_OLLAMA"]);
        // SAFETY: Serialized via #[serial_test::serial], no concurrent mutation.
        unsafe {
            std::env::remove_var("CLX_ALLOW_REMOTE_OLLAMA");
        }

        let config = OllamaConfig {
            host: "http://192.168.1.100:11434".to_string(),
            ..Default::default()
        };
        let result = OllamaClient::new(config);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("192.168.1.100"));
        assert!(err.contains("not localhost"));
    }

    #[test]
    #[serial_test::serial]
    #[allow(unsafe_code)]
    fn test_remote_host_rejected_fqdn() {
        let _guard = EnvGuard::new(&["CLX_ALLOW_REMOTE_OLLAMA"]);
        // SAFETY: Serialized via #[serial_test::serial], no concurrent mutation.
        unsafe {
            std::env::remove_var("CLX_ALLOW_REMOTE_OLLAMA");
        }

        let config = OllamaConfig {
            host: "http://ollama.example.com:11434".to_string(),
            ..Default::default()
        };
        let result = OllamaClient::new(config);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("ollama.example.com"));
    }

    #[test]
    fn test_invalid_url_rejected() {
        let config = OllamaConfig {
            host: "not-a-valid-url".to_string(),
            ..Default::default()
        };
        let result = OllamaClient::new(config);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("Invalid Ollama URL"));
    }

    #[test]
    #[serial_test::serial]
    #[allow(unsafe_code)]
    fn test_remote_public_host_allowed_with_override() {
        let _guard = EnvGuard::new(&["CLX_ALLOW_REMOTE_OLLAMA"]);

        // SAFETY: Serialized via #[serial_test::serial], no concurrent mutation.
        unsafe {
            std::env::set_var("CLX_ALLOW_REMOTE_OLLAMA", "true");
        }

        // Public IP should be allowed with the override
        let config = OllamaConfig {
            host: "http://8.8.8.8:11434".to_string(),
            ..Default::default()
        };
        let result = OllamaClient::new(config);
        assert!(result.is_ok(), "Public IP should be allowed with override");

        // Public hostname should also be allowed
        let config = OllamaConfig {
            host: "http://ollama.example.com:11434".to_string(),
            ..Default::default()
        };
        let result = OllamaClient::new(config);
        assert!(
            result.is_ok(),
            "Public hostname should be allowed with override"
        );
    }

    #[test]
    #[serial_test::serial]
    #[allow(unsafe_code)]
    fn test_private_ip_blocked_with_override() {
        let _guard = EnvGuard::new(&["CLX_ALLOW_REMOTE_OLLAMA"]);

        // SAFETY: Serialized via #[serial_test::serial], no concurrent mutation.
        unsafe {
            std::env::set_var("CLX_ALLOW_REMOTE_OLLAMA", "true");
        }

        // 192.168.x.x — private
        let config = OllamaConfig {
            host: "http://192.168.1.100:11434".to_string(),
            ..Default::default()
        };
        let result = OllamaClient::new(config);
        assert!(result.is_err(), "192.168.x should be blocked");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("private or internal"),
            "Error should mention private/internal: {err}"
        );

        // 10.x.x.x — private
        let config = OllamaConfig {
            host: "http://10.0.0.1:11434".to_string(),
            ..Default::default()
        };
        let result = OllamaClient::new(config);
        assert!(result.is_err(), "10.x should be blocked");

        // 172.16.x.x — private
        let config = OllamaConfig {
            host: "http://172.16.0.1:11434".to_string(),
            ..Default::default()
        };
        let result = OllamaClient::new(config);
        assert!(result.is_err(), "172.16.x should be blocked");

        // 172.31.x.x — upper bound of 172.16.0.0/12
        let config = OllamaConfig {
            host: "http://172.31.255.255:11434".to_string(),
            ..Default::default()
        };
        let result = OllamaClient::new(config);
        assert!(result.is_err(), "172.31.x should be blocked");
    }

    #[test]
    #[serial_test::serial]
    #[allow(unsafe_code)]
    fn test_link_local_and_metadata_blocked_with_override() {
        let _guard = EnvGuard::new(&["CLX_ALLOW_REMOTE_OLLAMA"]);

        // SAFETY: Serialized via #[serial_test::serial], no concurrent mutation.
        unsafe {
            std::env::set_var("CLX_ALLOW_REMOTE_OLLAMA", "true");
        }

        // Link-local 169.254.x.x
        let config = OllamaConfig {
            host: "http://169.254.1.1:11434".to_string(),
            ..Default::default()
        };
        let result = OllamaClient::new(config);
        assert!(result.is_err(), "169.254.x (link-local) should be blocked");

        // AWS/GCP metadata endpoint
        let config = OllamaConfig {
            host: "http://169.254.169.254:11434".to_string(),
            ..Default::default()
        };
        let result = OllamaClient::new(config);
        assert!(
            result.is_err(),
            "169.254.169.254 (metadata) should be blocked"
        );
    }

    #[test]
    #[serial_test::serial]
    #[allow(unsafe_code)]
    fn test_private_ipv6_blocked_with_override() {
        let _guard = EnvGuard::new(&["CLX_ALLOW_REMOTE_OLLAMA"]);

        // SAFETY: Serialized via #[serial_test::serial], no concurrent mutation.
        unsafe {
            std::env::set_var("CLX_ALLOW_REMOTE_OLLAMA", "true");
        }

        // ULA fc00::/7
        let config = OllamaConfig {
            host: "http://[fd12:3456:789a::1]:11434".to_string(),
            ..Default::default()
        };
        let result = OllamaClient::new(config);
        assert!(result.is_err(), "IPv6 ULA (fd..) should be blocked");

        // Link-local fe80::/10
        let config = OllamaConfig {
            host: "http://[fe80::1]:11434".to_string(),
            ..Default::default()
        };
        let result = OllamaClient::new(config);
        assert!(
            result.is_err(),
            "IPv6 link-local (fe80::) should be blocked"
        );
    }

    #[test]
    #[serial_test::serial]
    #[allow(unsafe_code)]
    fn test_internal_hostnames_blocked_with_override() {
        let _guard = EnvGuard::new(&["CLX_ALLOW_REMOTE_OLLAMA"]);

        // SAFETY: Serialized via #[serial_test::serial], no concurrent mutation.
        unsafe {
            std::env::set_var("CLX_ALLOW_REMOTE_OLLAMA", "true");
        }

        let internal_hosts = [
            "ollama.local",
            "ollama.internal",
            "server.lan",
            "nas.home",
            "gpu.corp",
            "ml.intranet",
        ];

        for host in &internal_hosts {
            let config = OllamaConfig {
                host: format!("http://{host}:11434"),
                ..Default::default()
            };
            let result = OllamaClient::new(config);
            assert!(
                result.is_err(),
                "Internal hostname '{host}' should be blocked"
            );
            let err = result.unwrap_err().to_string();
            assert!(
                err.contains("private or internal"),
                "Error for '{host}' should mention private/internal: {err}"
            );
        }
    }

    // --- Unit tests for is_private_or_internal (no env var needed) ---

    #[test]
    fn test_is_private_ipv4_10() {
        assert!(is_private_or_internal("10.0.0.1"));
        assert!(is_private_or_internal("10.255.255.255"));
    }

    #[test]
    fn test_is_private_ipv4_172() {
        assert!(is_private_or_internal("172.16.0.1"));
        assert!(is_private_or_internal("172.31.255.255"));
        // 172.32.x is NOT private
        assert!(!is_private_or_internal("172.32.0.1"));
    }

    #[test]
    fn test_is_private_ipv4_192() {
        assert!(is_private_or_internal("192.168.0.1"));
        assert!(is_private_or_internal("192.168.255.255"));
    }

    #[test]
    fn test_is_link_local_ipv4() {
        assert!(is_private_or_internal("169.254.0.1"));
        assert!(is_private_or_internal("169.254.169.254")); // metadata endpoint
        assert!(is_private_or_internal("169.254.255.255"));
    }

    #[test]
    fn test_is_loopback_ipv4() {
        assert!(is_private_or_internal("127.0.0.1"));
        assert!(is_private_or_internal("127.255.255.255"));
    }

    #[test]
    fn test_is_private_ipv6_ula() {
        assert!(is_private_or_internal("fd12:3456:789a::1"));
        assert!(is_private_or_internal("fc00::1"));
    }

    #[test]
    fn test_is_private_ipv6_link_local() {
        assert!(is_private_or_internal("fe80::1"));
        assert!(is_private_or_internal("fe80::abcd:1234"));
    }

    #[test]
    fn test_is_loopback_ipv6() {
        assert!(is_private_or_internal("::1"));
    }

    #[test]
    fn test_is_internal_hostnames() {
        assert!(is_private_or_internal("server.local"));
        assert!(is_private_or_internal("host.internal"));
        assert!(is_private_or_internal("nas.lan"));
        assert!(is_private_or_internal("box.home"));
        assert!(is_private_or_internal("gpu.corp"));
        assert!(is_private_or_internal("ml.intranet"));
        // Case insensitive
        assert!(is_private_or_internal("Server.LOCAL"));
        assert!(is_private_or_internal("HOST.INTERNAL"));
    }

    #[test]
    fn test_bracketed_ipv6_handled() {
        // reqwest::Url::host_str() returns IPv6 addresses with brackets
        assert!(is_private_or_internal("[fd12:3456:789a::1]"));
        assert!(is_private_or_internal("[fe80::1]"));
        assert!(is_private_or_internal("[::1]"));
        assert!(!is_private_or_internal("[2001:db8::1]"));
    }

    #[test]
    fn test_public_ip_not_private() {
        assert!(!is_private_or_internal("8.8.8.8"));
        assert!(!is_private_or_internal("1.1.1.1"));
        assert!(!is_private_or_internal("203.0.113.1"));
        assert!(!is_private_or_internal("93.184.216.34"));
    }

    #[test]
    fn test_public_ipv6_not_private() {
        assert!(!is_private_or_internal("2001:db8::1"));
        assert!(!is_private_or_internal("2607:f8b0:4004:800::200e"));
    }

    #[test]
    fn test_public_hostname_not_private() {
        assert!(!is_private_or_internal("ollama.example.com"));
        assert!(!is_private_or_internal("api.company.io"));
        assert!(!is_private_or_internal("gpu-server.cloud.net"));
    }
}
