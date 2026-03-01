//! Error types for CLX Core

use thiserror::Error;

use crate::credentials::CredentialError;
use crate::ollama::OllamaError;

/// Main error type for CLX operations
#[non_exhaustive]
#[derive(Error, Debug)]
pub enum Error {
    /// Configuration error
    #[error("Configuration error: {0}")]
    Config(String),

    /// Storage/database error
    #[error("Storage error: {0}")]
    Storage(#[from] rusqlite::Error),

    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// YAML parsing error
    #[error("YAML error: {0}")]
    Yaml(#[from] serde_yml::Error),

    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Policy violation
    #[error("Policy violation: {0}")]
    PolicyViolation(String),

    /// Context not found
    #[error("Context not found: {0}")]
    ContextNotFound(String),

    /// Invalid input
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    /// Ollama LLM service error
    #[error("Ollama error: {0}")]
    Ollama(#[from] OllamaError),

    /// Credential/keychain error
    #[error("Credential error: {0}")]
    Credential(#[from] CredentialError),

    /// HTTP request error
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
}

/// Result type alias using CLX Error
pub type Result<T> = std::result::Result<T, Error>;
