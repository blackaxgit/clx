//! Secure credentials management using system keychain
//!
//! This module provides secure storage for API keys and secrets using the
//! operating system's native keychain (macOS Keychain, Windows Credential Manager,
//! Linux Secret Service).
//!
//! # Example
//!
//! ```no_run
//! use clx_core::credentials::CredentialStore;
//!
//! let store = CredentialStore::new();
//!
//! // Store a credential
//! store.store("api_key", "secret_value").unwrap();
//!
//! // Retrieve it
//! let value = store.get("api_key").unwrap();
//! assert_eq!(value, Some("secret_value".to_string()));
//!
//! // Delete when done
//! store.delete("api_key").unwrap();
//! ```

use thiserror::Error;
use tracing::{debug, warn};

/// Service name for CLX credentials in the system keychain
const SERVICE_NAME: &str = "com.clx.credentials";

/// Prefix used for global credential keys
const GLOBAL_PREFIX: &str = "clx:global:";

/// Prefix used for project-scoped credential keys
const PROJECT_PREFIX: &str = "clx:project:";

/// Errors that can occur during credential operations
#[derive(Error, Debug)]
pub enum CredentialError {
    /// The requested credential was not found
    #[error("Credential not found: {0}")]
    NotFound(String),

    /// Access to the keychain was denied
    #[error("Keychain access denied: {0}")]
    AccessDenied(String),

    /// The keychain service is not available
    #[error("Keychain service unavailable: {0}")]
    ServiceUnavailable(String),

    /// Invalid credential key format
    #[error("Invalid credential key: {0}")]
    InvalidKey(String),

    /// Generic keychain error
    #[error("Keychain error: {0}")]
    Keychain(String),

    /// Storage error for the key index
    #[error("Storage error: {0}")]
    Storage(String),
}

/// Result type alias for credential operations (private to this module)
type Result<T> = std::result::Result<T, CredentialError>;

/// Secure credential store using the system keychain
///
/// Provides methods to store, retrieve, delete, and list credentials.
/// All credentials are stored in the system keychain under the service
/// name "com.clx.credentials".
#[derive(Debug, Clone)]
pub struct CredentialStore {
    service: String,
}

impl Default for CredentialStore {
    fn default() -> Self {
        Self::new()
    }
}

impl CredentialStore {
    /// Create a new credential store with the default service name
    #[must_use]
    pub fn new() -> Self {
        Self {
            service: SERVICE_NAME.to_string(),
        }
    }

    /// Create a new credential store with a custom service name
    ///
    /// This is primarily useful for testing to avoid conflicts with
    /// production credentials.
    pub fn with_service(service: impl Into<String>) -> Self {
        Self {
            service: service.into(),
        }
    }

    /// Store a credential in the keychain (global scope)
    ///
    /// # Arguments
    ///
    /// * `key` - The unique identifier for this credential
    /// * `value` - The secret value to store
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The key is empty or invalid
    /// - Access to the keychain is denied
    /// - The keychain service is unavailable
    pub fn store(&self, key: &str, value: &str) -> Result<()> {
        self.store_scoped(key, value, None)
    }

    /// Store a credential with optional project scope
    ///
    /// # Arguments
    ///
    /// * `key` - The unique identifier for this credential
    /// * `value` - The secret value to store
    /// * `project` - Optional project path for scoped storage
    ///
    /// If `project` is None, stores globally. Otherwise, stores for the specific project.
    pub fn store_scoped(&self, key: &str, value: &str, project: Option<&str>) -> Result<()> {
        self.validate_key(key)?;

        let prefixed_key = self.scoped_key(key, project);
        debug!(
            "Storing credential with key: {} (scope: {:?})",
            key, project
        );

        let entry = self.get_entry(&prefixed_key)?;

        entry
            .set_password(value)
            .map_err(|e| self.map_keyring_error(e, key))?;

        // Store in the key index for listing
        self.add_to_index_scoped(key, project)?;

        Ok(())
    }

    /// Retrieve a credential from the keychain (global scope)
    ///
    /// # Arguments
    ///
    /// * `key` - The unique identifier for the credential
    ///
    /// # Returns
    ///
    /// Returns `Ok(Some(value))` if the credential exists,
    /// `Ok(None)` if it does not exist,
    /// or an error if access is denied or the service is unavailable.
    pub fn get(&self, key: &str) -> Result<Option<String>> {
        self.get_scoped(key, None)
    }

    /// Retrieve a credential with optional project scope
    ///
    /// # Arguments
    ///
    /// * `key` - The unique identifier for the credential
    /// * `project` - Optional project path for scoped retrieval
    pub fn get_scoped(&self, key: &str, project: Option<&str>) -> Result<Option<String>> {
        self.validate_key(key)?;

        let prefixed_key = self.scoped_key(key, project);
        debug!(
            "Retrieving credential with key: {} (scope: {:?})",
            key, project
        );

        let entry = self.get_entry(&prefixed_key)?;

        match entry.get_password() {
            Ok(value) => Ok(Some(value)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(self.map_keyring_error(e, key)),
        }
    }

    /// Retrieve a credential with fallback from project to global
    ///
    /// First tries project-scoped credential, then falls back to global.
    ///
    /// # Arguments
    ///
    /// * `key` - The unique identifier for the credential
    /// * `project` - Project path to check first
    pub fn get_with_fallback(&self, key: &str, project: &str) -> Result<Option<String>> {
        // Try project-specific first
        if let Some(value) = self.get_scoped(key, Some(project))? {
            debug!("Found project-scoped credential for key: {}", key);
            return Ok(Some(value));
        }

        // Fall back to global
        debug!("Falling back to global credential for key: {}", key);
        self.get_scoped(key, None)
    }

    /// Delete a credential from the keychain (global scope)
    ///
    /// # Arguments
    ///
    /// * `key` - The unique identifier for the credential
    ///
    /// # Errors
    ///
    /// Returns an error if access is denied or the service is unavailable.
    /// Does not return an error if the credential does not exist.
    pub fn delete(&self, key: &str) -> Result<()> {
        self.delete_scoped(key, None)
    }

    /// Delete a credential with optional project scope
    ///
    /// # Arguments
    ///
    /// * `key` - The unique identifier for the credential
    /// * `project` - Optional project path for scoped deletion
    pub fn delete_scoped(&self, key: &str, project: Option<&str>) -> Result<()> {
        self.validate_key(key)?;

        let prefixed_key = self.scoped_key(key, project);
        debug!(
            "Deleting credential with key: {} (scope: {:?})",
            key, project
        );

        let entry = self.get_entry(&prefixed_key)?;

        match entry.delete_password() {
            Ok(()) => {
                // Remove from index
                self.remove_from_index_scoped(key, project)?;
                Ok(())
            }
            Err(keyring::Error::NoEntry) => {
                // Credential doesn't exist, remove from index anyway
                self.remove_from_index_scoped(key, project)?;
                Ok(())
            }
            Err(e) => Err(self.map_keyring_error(e, key)),
        }
    }

    /// List all stored global credential keys
    ///
    /// # Returns
    ///
    /// Returns a vector of credential keys that have been stored globally.
    /// Note: This reads from a separate index stored in the keychain,
    /// so it will only list credentials stored through this API.
    pub fn list(&self) -> Result<Vec<String>> {
        self.list_scoped(None)
    }

    /// List credential keys for a specific scope
    ///
    /// # Arguments
    ///
    /// * `project` - Optional project path. None for global credentials.
    pub fn list_scoped(&self, project: Option<&str>) -> Result<Vec<String>> {
        debug!("Listing stored credentials (scope: {:?})", project);
        self.get_index_scoped(project)
    }

    /// Check if a credential exists
    ///
    /// # Arguments
    ///
    /// * `key` - The unique identifier for the credential
    ///
    /// # Returns
    ///
    /// Returns `true` if the credential exists, `false` otherwise.
    pub fn exists(&self, key: &str) -> Result<bool> {
        Ok(self.get(key)?.is_some())
    }

    // Private helper methods

    #[allow(clippy::unused_self)] // Method signature kept for consistency with other helpers
    fn validate_key(&self, key: &str) -> Result<()> {
        if key.is_empty() {
            return Err(CredentialError::InvalidKey(
                "Key cannot be empty".to_string(),
            ));
        }

        if key.contains('\0') {
            return Err(CredentialError::InvalidKey(
                "Key cannot contain null characters".to_string(),
            ));
        }

        if key.len() > 255 {
            return Err(CredentialError::InvalidKey(
                "Key cannot exceed 255 characters".to_string(),
            ));
        }

        // Restrict to safe character set to prevent injection via scoped key format
        if !key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
        {
            return Err(CredentialError::InvalidKey(
                "Key must contain only alphanumeric characters, underscores, hyphens, and dots"
                    .to_string(),
            ));
        }

        // Prevent path traversal patterns
        if key.contains("..") {
            return Err(CredentialError::InvalidKey(
                "Key cannot contain '..'".to_string(),
            ));
        }

        Ok(())
    }

    #[allow(clippy::unused_self)] // Method signature kept for consistency
    fn scoped_key(&self, key: &str, project: Option<&str>) -> String {
        match project {
            Some(path) => format!("{PROJECT_PREFIX}{path}:{key}"),
            None => format!("{GLOBAL_PREFIX}{key}"),
        }
    }

    #[allow(clippy::unused_self)] // Method signature kept for consistency
    fn index_key(&self, project: Option<&str>) -> String {
        match project {
            Some(path) => format!("__clx_project_index__:{path}"),
            None => Self::INDEX_KEY.to_string(),
        }
    }

    fn get_entry(&self, key: &str) -> Result<keyring::Entry> {
        keyring::Entry::new(&self.service, key).map_err(|e| {
            CredentialError::ServiceUnavailable(format!("Failed to create keychain entry: {e}"))
        })
    }

    #[allow(clippy::unused_self)] // Method signature kept for consistency
    fn map_keyring_error(&self, error: keyring::Error, key: &str) -> CredentialError {
        match error {
            keyring::Error::NoEntry => CredentialError::NotFound(key.to_string()),
            keyring::Error::Ambiguous(_) => {
                CredentialError::Keychain(format!("Ambiguous credential for key: {key}"))
            }
            keyring::Error::TooLong(field, _) => {
                CredentialError::InvalidKey(format!("Field too long: {field}"))
            }
            keyring::Error::Invalid(field, _) => {
                CredentialError::InvalidKey(format!("Invalid field: {field}"))
            }
            keyring::Error::NoStorageAccess(platform_err) => {
                warn!("Keychain access denied: {:?}", platform_err);
                CredentialError::AccessDenied(
                    "Unable to access system keychain. Please check your security settings."
                        .to_string(),
                )
            }
            keyring::Error::PlatformFailure(platform_err) => {
                warn!("Platform keychain error: {:?}", platform_err);
                CredentialError::ServiceUnavailable(format!(
                    "Keychain service error: {platform_err:?}"
                ))
            }
            _ => CredentialError::Keychain(format!("Keychain error: {error}")),
        }
    }

    // Index management for listing credentials
    // We store a JSON array of keys in a special keychain entry

    const INDEX_KEY: &'static str = "__clx_credential_index__";

    fn get_index_scoped(&self, project: Option<&str>) -> Result<Vec<String>> {
        let index_key = self.index_key(project);
        let entry = self.get_entry(&index_key)?;

        match entry.get_password() {
            Ok(json_str) => serde_json::from_str(&json_str).map_err(|e| {
                CredentialError::Storage(format!("Failed to parse credential index: {e}"))
            }),
            Err(keyring::Error::NoEntry) => Ok(Vec::new()),
            Err(e) => Err(self.map_keyring_error(e, &index_key)),
        }
    }

    fn save_index_scoped(&self, keys: &[String], project: Option<&str>) -> Result<()> {
        let index_key = self.index_key(project);
        let entry = self.get_entry(&index_key)?;
        let json_str = serde_json::to_string(keys).map_err(|e| {
            CredentialError::Storage(format!("Failed to serialize credential index: {e}"))
        })?;

        entry
            .set_password(&json_str)
            .map_err(|e| self.map_keyring_error(e, &index_key))
    }

    fn add_to_index_scoped(&self, key: &str, project: Option<&str>) -> Result<()> {
        let mut keys = self.get_index_scoped(project)?;
        if !keys.contains(&key.to_string()) {
            keys.push(key.to_string());
            keys.sort();
            self.save_index_scoped(&keys, project)?;
        }
        Ok(())
    }

    fn remove_from_index_scoped(&self, key: &str, project: Option<&str>) -> Result<()> {
        let mut keys = self.get_index_scoped(project)?;
        keys.retain(|k| k != key);
        self.save_index_scoped(&keys, project)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Note: These tests require access to the system keychain.
    // They use a test-specific service name to avoid conflicts.

    fn test_store() -> CredentialStore {
        CredentialStore::with_service("com.clx.credentials.test")
    }

    #[test]
    fn test_validate_key_empty() {
        let store = test_store();
        let result = store.validate_key("");
        assert!(result.is_err());
        assert!(matches!(result, Err(CredentialError::InvalidKey(_))));
    }

    #[test]
    fn test_validate_key_null_char() {
        let store = test_store();
        let result = store.validate_key("test\0key");
        assert!(result.is_err());
        assert!(matches!(result, Err(CredentialError::InvalidKey(_))));
    }

    #[test]
    fn test_validate_key_too_long() {
        let store = test_store();
        let long_key = "a".repeat(256);
        let result = store.validate_key(&long_key);
        assert!(result.is_err());
        assert!(matches!(result, Err(CredentialError::InvalidKey(_))));
    }

    #[test]
    fn test_validate_key_valid() {
        let store = test_store();
        assert!(store.validate_key("valid_key").is_ok());
        assert!(store.validate_key("valid-key-123").is_ok());
        assert!(store.validate_key("OPENAI_API_KEY").is_ok());
        assert!(store.validate_key("some.dotted.key").is_ok());
    }

    // --- M10: Safe character set tests ---

    #[test]
    fn test_validate_key_rejects_special_chars() {
        let store = test_store();
        // Colon conflicts with scoping format
        let result = store.validate_key("key:with:colons");
        assert!(result.is_err());
        assert!(matches!(result, Err(CredentialError::InvalidKey(_))));

        // Slash could enable path traversal
        let result = store.validate_key("key/with/slashes");
        assert!(result.is_err());

        // Spaces
        let result = store.validate_key("key with spaces");
        assert!(result.is_err());

        // Unicode
        let result = store.validate_key("key_with_\u{00e9}");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_key_rejects_path_traversal() {
        let store = test_store();
        let result = store.validate_key("some..key");
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains(".."));
    }

    #[test]
    fn test_validate_key_allows_single_dot() {
        let store = test_store();
        assert!(store.validate_key("config.key").is_ok());
        assert!(store.validate_key("a.b.c").is_ok());
    }

    #[test]
    fn test_scoped_key() {
        let store = test_store();
        // Global scope
        assert_eq!(store.scoped_key("my_key", None), "clx:global:my_key");
        // Project scope
        assert_eq!(
            store.scoped_key("my_key", Some("/path/to/project")),
            "clx:project:/path/to/project:my_key"
        );
    }

    // Integration tests that require keychain access
    // These are marked with #[ignore] by default since they interact with the real keychain

    #[test]
    #[ignore = "Requires keychain access"]
    fn test_store_and_get() {
        let store = test_store();
        let key = "test_key_1";
        let value = "test_secret_value";

        // Clean up first
        let _ = store.delete(key);

        // Store
        store.store(key, value).expect("Failed to store credential");

        // Get
        let retrieved = store.get(key).expect("Failed to get credential");
        assert_eq!(retrieved, Some(value.to_string()));

        // Clean up
        store.delete(key).expect("Failed to delete credential");
    }

    #[test]
    #[ignore = "Requires keychain access"]
    fn test_get_nonexistent() {
        let store = test_store();
        let result = store.get("nonexistent_key_12345");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), None);
    }

    #[test]
    #[ignore = "Requires keychain access"]
    fn test_delete_nonexistent() {
        let store = test_store();
        // Should not error when deleting a nonexistent credential
        let result = store.delete("nonexistent_key_12345");
        assert!(result.is_ok());
    }

    #[test]
    #[ignore = "Requires keychain access"]
    fn test_exists() {
        let store = test_store();
        let key = "test_exists_key";

        // Clean up first
        let _ = store.delete(key);

        assert!(!store.exists(key).unwrap());

        store.store(key, "value").unwrap();
        assert!(store.exists(key).unwrap());

        store.delete(key).unwrap();
        assert!(!store.exists(key).unwrap());
    }

    #[test]
    #[ignore = "Requires keychain access"]
    fn test_list() {
        let store = test_store();
        let key1 = "test_list_key_1";
        let key2 = "test_list_key_2";

        // Clean up first
        let _ = store.delete(key1);
        let _ = store.delete(key2);

        store.store(key1, "value1").unwrap();
        store.store(key2, "value2").unwrap();

        let keys = store.list().unwrap();
        assert!(keys.contains(&key1.to_string()));
        assert!(keys.contains(&key2.to_string()));

        // Clean up
        store.delete(key1).unwrap();
        store.delete(key2).unwrap();
    }

    #[test]
    #[ignore = "Requires keychain access"]
    fn test_get_with_fallback_returns_global_when_no_project_credential() {
        let store = test_store();
        let key = "test_fallback_global_key";
        let project = "/tmp/test-project";

        // Ensure clean state
        let _ = store.delete_scoped(key, Some(project));
        let _ = store.delete(key);

        // Store only global credential
        store.store(key, "global_value").expect("store global");

        // get_with_fallback should return the global value
        let result = store
            .get_with_fallback(key, project)
            .expect("get_with_fallback");
        assert_eq!(result, Some("global_value".to_string()));

        // Clean up
        store.delete(key).expect("cleanup");
    }

    #[test]
    #[ignore = "Requires keychain access"]
    fn test_get_with_fallback_prefers_project_over_global() {
        let store = test_store();
        let key = "test_fallback_project_key";
        let project = "/tmp/test-project";

        // Ensure clean state
        let _ = store.delete_scoped(key, Some(project));
        let _ = store.delete(key);

        // Store both project-scoped and global credentials
        store
            .store_scoped(key, "project_value", Some(project))
            .expect("store project-scoped");
        store.store(key, "global_value").expect("store global");

        // get_with_fallback should return the project-scoped value
        let result = store
            .get_with_fallback(key, project)
            .expect("get_with_fallback");
        assert_eq!(result, Some("project_value".to_string()));

        // Clean up
        store
            .delete_scoped(key, Some(project))
            .expect("cleanup project");
        store.delete(key).expect("cleanup global");
    }

    #[test]
    #[ignore = "Requires keychain access"]
    fn test_overwrite() {
        let store = test_store();
        let key = "test_overwrite_key";

        // Clean up first
        let _ = store.delete(key);

        store.store(key, "value1").unwrap();
        assert_eq!(store.get(key).unwrap(), Some("value1".to_string()));

        store.store(key, "value2").unwrap();
        assert_eq!(store.get(key).unwrap(), Some("value2".to_string()));

        // Clean up
        store.delete(key).unwrap();
    }
}
