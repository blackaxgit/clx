//! Error types for CLX Core

use thiserror::Error;

use crate::credentials::CredentialError;

/// Main error type for CLX operations
#[non_exhaustive]
#[derive(Error, Debug)]
pub enum Error {
    /// Configuration error
    #[error("Configuration error: {0}")]
    Config(String),

    /// Config-trustlist error (malformed, unsupported version, or IO).
    ///
    /// Distinct from [`Error::Config`] so callers can tell a trustlist
    /// failure apart from a general configuration problem. The wrapped
    /// [`TrustError`] preserves the malformed-vs-version-vs-IO distinction.
    #[error("Trustlist error: {0}")]
    Trust(#[from] TrustError),

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

    /// Context not found
    #[error("Context not found: {0}")]
    ContextNotFound(String),

    /// Invalid input
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    /// Credential/keychain error
    #[error("Credential error: {0}")]
    Credential(#[from] CredentialError),

    /// HTTP request error
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
}

/// Errors from the per-project config trustlist loader
/// ([`crate::config::trust`]).
///
/// The variants preserve the fail-loud semantics of the original
/// `anyhow`-based loader while letting callers distinguish a malformed
/// file from an unsupported schema version from an IO failure. All three
/// are fail-loud: a trustlist read error must never silently re-trust.
#[derive(Error, Debug)]
pub enum TrustError {
    /// The trustlist file exists but is not valid JSON. Refusing to
    /// silently reset is itself a security property.
    #[error("trustlist at {path} is malformed JSON; refusing to silently reset: {source}")]
    Malformed {
        /// Path to the offending trustlist file.
        path: String,
        /// Underlying JSON parse error.
        source: serde_json::Error,
    },

    /// The trustlist declares a schema version this build does not support.
    #[error(
        "trustlist at {path} has unsupported version {found} (expected {expected}); \
         re-run `clx config-trust add` to upgrade"
    )]
    UnsupportedVersion {
        /// Path to the trustlist file.
        path: String,
        /// Version found on disk.
        found: u32,
        /// Version this build supports.
        expected: u32,
    },

    /// An IO error occurred while reading or writing the trustlist.
    #[error("trustlist IO error at {path}: {source}")]
    Io {
        /// Path to the trustlist file.
        path: String,
        /// Underlying IO error.
        source: std::io::Error,
    },

    /// A serialization error occurred while persisting the trustlist.
    #[error("failed to serialize trustlist: {0}")]
    Serialize(serde_json::Error),

    /// A supplied hash prefix was invalid (empty or ambiguous).
    #[error("{0}")]
    InvalidHashPrefix(String),
}

/// Result type alias using CLX Error
pub type Result<T> = std::result::Result<T, Error>;
