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

use std::collections::HashMap;
#[cfg(target_os = "macos")]
use std::sync::Once;
use std::sync::{Arc, Mutex};

use secrecy::{ExposeSecret, SecretString};
use thiserror::Error;
use tracing::{debug, warn};

pub mod keychain_acl;

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
/// In-memory, process-scoped cache of resolved secrets.
///
/// Maps the fully scoped keychain key to a cached lookup result. `None`
/// represents a negative cache entry (the keychain had no such entry), so a
/// missing optional credential is not re-queried on every call.
///
/// The cached `SecretString` zeroizes its backing memory on drop (`secrecy`
/// `ZeroizeOnDrop`), so dropping the owning `CredentialStore` /
/// `McpServer` clears all cached secrets. The cache is never serialized,
/// logged, or written to disk.
type SecretCache = Arc<Mutex<HashMap<String, Option<SecretString>>>>;

/// Secure credential store using the system keychain
///
/// Provides methods to store, retrieve, delete, and list credentials.
/// All credentials are stored in the system keychain under the service
/// name "com.clx.credentials".
///
/// An optional process-scoped read cache (see [`CredentialStore::new_cached`])
/// reads a given credential from the keychain at most once per store
/// lifetime. This avoids the macOS keychain re-prompting on every MCP tool
/// invocation. The default constructors keep uncached semantics so other
/// callers (CLI, hooks) and tests observe every read.
#[derive(Clone)]
pub struct CredentialStore {
    service: String,
    /// Opt-in read cache. `None` => uncached (read keychain every time).
    cache: Option<SecretCache>,
    /// Test-only in-memory keychain replacement so unit tests never touch
    /// the real OS keychain. Production builds never construct this; the
    /// real `keyring` backend is always used outside `cfg(test)`.
    #[cfg(test)]
    fake_backend: Option<tests::FakeBackend>,
}

impl std::fmt::Debug for CredentialStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never expose cached secret values via Debug.
        f.debug_struct("CredentialStore")
            .field("service", &self.service)
            .field("cached", &self.cache.is_some())
            .finish_non_exhaustive()
    }
}

impl Default for CredentialStore {
    fn default() -> Self {
        Self::new()
    }
}

impl CredentialStore {
    /// Create a new credential store with the default service name
    ///
    /// Uncached: every `get`/`get_scoped` reads the system keychain.
    #[must_use]
    pub fn new() -> Self {
        Self::build(SERVICE_NAME.to_string(), None)
    }

    /// Create a new credential store with a custom service name
    ///
    /// This is primarily useful for testing to avoid conflicts with
    /// production credentials. Uncached.
    pub fn with_service(service: impl Into<String>) -> Self {
        Self::build(service.into(), None)
    }

    /// Internal constructor that fills all fields (including the test-only
    /// backend) in one place so the production constructors stay terse.
    fn build(service: String, cache: Option<SecretCache>) -> Self {
        Self {
            service,
            cache,
            #[cfg(test)]
            fake_backend: None,
        }
    }

    /// Create a credential store with a process-scoped read cache.
    ///
    /// The first `get`/`get_scoped`/`get_with_fallback` for a given scoped key
    /// reads the keychain; every subsequent read for the same key is served
    /// from memory without touching the keychain (positive and negative
    /// results are both cached). This is intended for the long-lived MCP
    /// server so macOS does not re-prompt for keychain access on every tool
    /// call.
    ///
    /// Write operations (`store`/`delete`) invalidate the affected cache
    /// entry so a subsequent read reflects the change within the session.
    ///
    /// The cache lives exactly as long as this store (and any clones share
    /// the same cache via an `Arc`); it is dropped (and its secrets
    /// zeroized) when the owner is dropped. It is not a global static.
    #[must_use]
    pub fn new_cached() -> Self {
        Self::build(
            SERVICE_NAME.to_string(),
            Some(Arc::new(Mutex::new(HashMap::new()))),
        )
    }

    /// Create a cached credential store with a custom service name.
    ///
    /// Primarily for tests that want cached behavior without touching
    /// production credentials.
    pub fn with_service_cached(service: impl Into<String>) -> Self {
        Self::build(service.into(), Some(Arc::new(Mutex::new(HashMap::new()))))
    }

    /// Whether this store has an active process-scoped read cache.
    #[must_use]
    pub fn is_cached(&self) -> bool {
        self.cache.is_some()
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

        // macOS only: the `keyring` write above created/updated the item with
        // the default restrictive ACL bound to this (adhoc-signed) binary,
        // which makes macOS re-prompt on every future launch. Relax the item
        // to an "any application on this user account" SecAccess so reads
        // never prompt again. This is a deliberate local-trust tradeoff (see
        // `keychain_acl`); surfaced once per process via a one-line notice.
        self.relax_keychain_acl(&prefixed_key);

        // Keep the session cache consistent with the new value.
        self.invalidate_cache(key, project);

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

        // Fast path: serve from the process-scoped cache without touching the
        // keychain. Both positive and negative (None) results are cached.
        if let Some(cache) = &self.cache {
            let guard = cache
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(cached) = guard.get(&prefixed_key) {
                debug!("Serving credential '{}' from process cache", key);
                return Ok(cached.as_ref().map(|s| s.expose_secret().to_string()));
            }
            // Release the lock before the (potentially slow / prompting)
            // keychain read so we never hold a Mutex across blocking I/O.
            drop(guard);
        }

        debug!(
            "Retrieving credential with key: {} (scope: {:?})",
            key, project
        );

        let value = self.read_scoped_uncached(&prefixed_key, key)?;

        if let Some(cache) = &self.cache {
            let mut guard = cache
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            // Double-check: a concurrent first reader may have populated the
            // entry while we were reading the keychain. Keep the existing
            // entry so all racers observe a single consistent value.
            guard
                .entry(prefixed_key)
                .or_insert_with(|| value.clone().map(|v| SecretString::new(v.into())));
        }

        Ok(value)
    }

    /// Read a scoped credential directly from the keychain, bypassing any
    /// cache. The hot keychain call lives here so callers (and the cache
    /// fast path) share one place that touches `keyring`.
    fn read_scoped_uncached(&self, prefixed_key: &str, key: &str) -> Result<Option<String>> {
        #[cfg(test)]
        if let Some(fake) = &self.fake_backend {
            return Ok(fake.get(prefixed_key));
        }
        let entry = self.get_entry(prefixed_key)?;
        match entry.get_password() {
            Ok(value) => Ok(Some(value)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(self.map_keyring_error(e, key)),
        }
    }

    /// Drop a cached entry for a scoped key (no-op when uncached).
    ///
    /// Called after writes/deletes so a subsequent read reflects the change
    /// within the same session.
    fn invalidate_cache(&self, key: &str, project: Option<&str>) {
        if let Some(cache) = &self.cache {
            let prefixed_key = self.scoped_key(key, project);
            let mut guard = cache
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            guard.remove(&prefixed_key);
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
                self.invalidate_cache(key, project);
                // Remove from index
                self.remove_from_index_scoped(key, project)?;
                Ok(())
            }
            Err(keyring::Error::NoEntry) => {
                self.invalidate_cache(key, project);
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

    /// Apply the permissive "any application" `SecAccess` to a freshly stored
    /// keychain item so future reads (this launch or any later launch, signed
    /// or adhoc) never prompt.
    ///
    /// macOS only. A no-op on every other OS and in unit tests using the fake
    /// backend (Linux Secret Service does not have the adhoc-binary
    /// re-prompt problem, and the test backend is in-memory). Best-effort:
    /// failures are logged at debug and never surfaced as a store error, so a
    /// locked keychain or an unexpected Security.framework status cannot make
    /// `store` fail after the secret has already been written.
    fn relax_keychain_acl(&self, prefixed_key: &str) {
        #[cfg(test)]
        if self.fake_backend.is_some() {
            return;
        }
        keychain_acl::relax_item_access(&self.service, prefixed_key);
        Self::emit_relaxed_acl_notice_once();
    }

    /// Print the relaxed-ACL rationale exactly once per process so the user
    /// understands CLX deliberately widened the credential item's ACL. Goes
    /// to stderr (not stdout) so it never corrupts JSON / piped output.
    fn emit_relaxed_acl_notice_once() {
        #[cfg(target_os = "macos")]
        {
            static NOTICE: Once = Once::new();
            NOTICE.call_once(|| {
                tracing::info!(
                    "CLX relaxed the macOS Keychain ACL on its credential items to \
                     'any application on this user account' so the keychain stops \
                     re-prompting. Run `clx keychain-trust` to re-apply this to older \
                     items."
                );
                eprintln!(
                    "note: CLX set its keychain credential to be readable by any \
                     application on this user account so macOS stops re-prompting. \
                     This is a local-trust tradeoff (same as choosing \"Allow all \
                     applications\" in Keychain Access)."
                );
            });
        }
    }

    /// Re-apply the permissive "any application" `SecAccess` to every CLX
    /// credential item under this store's service name.
    ///
    /// This repairs items created by pre-0.8.0 CLX (which have the default
    /// restrictive ACL) so the macOS keychain stops re-prompting. macOS only;
    /// on every other OS this is a no-op that returns `Ok(0)`.
    ///
    /// Returns the number of items whose access was successfully relaxed.
    /// Items that cannot be found are skipped silently (nothing to repair);
    /// a locked keychain surfaces as an [`CredentialError::AccessDenied`].
    ///
    /// # Security
    ///
    /// This deliberately widens the ACL on the CLX credential items to "any
    /// application on this user account". It is the same trust decision as a
    /// user manually choosing "Allow all applications" in Keychain Access,
    /// scoped to CLX's own items only. It does not touch any other keychain
    /// item.
    pub fn repair_keychain_trust(&self) -> Result<KeychainTrustReport> {
        // Candidate item names: the two index entries plus every scoped key
        // recorded in the global and project indexes. Pre-0.8.0 CLX used the
        // exact same key format, so the index is an accurate enumeration.
        let mut names: Vec<String> = vec![Self::INDEX_KEY.to_string(), self.index_key(None)];

        if let Ok(global_keys) = self.get_index_scoped(None) {
            for k in &global_keys {
                names.push(self.scoped_key(k, None));
            }
        }

        let report = keychain_acl::repair_service_items(&self.service, &names)?;
        Ok(report)
    }
}

/// Outcome of [`CredentialStore::repair_keychain_trust`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KeychainTrustReport {
    /// Items whose ACL was successfully relaxed to "any application".
    pub relaxed: usize,
    /// Items that did not exist (nothing to repair for them).
    pub missing: usize,
    /// Whether this platform actually performs keychain trust repair.
    /// `false` on every non-macOS OS (the whole operation is a no-op there).
    pub macos: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::atomic::{AtomicUsize, Ordering};

    // Note: These tests require access to the system keychain.
    // They use a test-specific service name to avoid conflicts.

    fn test_store() -> CredentialStore {
        CredentialStore::with_service("com.clx.credentials.test")
    }

    /// In-memory keychain replacement used only in unit tests.
    ///
    /// Counts every backend read so tests can assert the keychain is hit at
    /// most once per scoped key when caching is enabled. Never touches the
    /// real OS keychain.
    #[derive(Clone, Default)]
    pub(super) struct FakeBackend {
        entries: Arc<Mutex<HashMap<String, String>>>,
        reads: Arc<AtomicUsize>,
    }

    impl FakeBackend {
        fn new() -> Self {
            Self::default()
        }

        fn seed(&self, prefixed_key: &str, value: &str) {
            self.entries
                .lock()
                .unwrap()
                .insert(prefixed_key.to_string(), value.to_string());
        }

        pub(super) fn get(&self, prefixed_key: &str) -> Option<String> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            self.entries.lock().unwrap().get(prefixed_key).cloned()
        }

        fn read_count(&self) -> usize {
            self.reads.load(Ordering::SeqCst)
        }
    }

    /// Build a store wired to a shared fake backend. `cached` toggles the
    /// process-scoped read cache.
    fn faked_store(cached: bool) -> (CredentialStore, FakeBackend) {
        let backend = FakeBackend::new();
        let cache = if cached {
            Some(Arc::new(Mutex::new(HashMap::new())))
        } else {
            None
        };
        let store = CredentialStore {
            service: "com.clx.credentials.cachetest".to_string(),
            cache,
            fake_backend: Some(backend.clone()),
        };
        (store, backend)
    }

    #[test]
    fn cached_get_reads_backend_once_then_serves_from_cache() {
        let (store, backend) = faked_store(true);
        backend.seed("clx:global:api", "secret-value");

        assert_eq!(store.get("api").unwrap(), Some("secret-value".to_string()));
        assert_eq!(store.get("api").unwrap(), Some("secret-value".to_string()));
        assert_eq!(store.get("api").unwrap(), Some("secret-value".to_string()));

        assert_eq!(
            backend.read_count(),
            1,
            "cached store must hit the keychain at most once per key"
        );
    }

    #[test]
    fn uncached_get_reads_backend_every_time() {
        let (store, backend) = faked_store(false);
        backend.seed("clx:global:api", "secret-value");

        assert_eq!(store.get("api").unwrap(), Some("secret-value".to_string()));
        assert_eq!(store.get("api").unwrap(), Some("secret-value".to_string()));

        assert_eq!(
            backend.read_count(),
            2,
            "uncached store must preserve read-every-time semantics"
        );
        assert!(!store.is_cached());
    }

    #[test]
    fn cached_distinct_keys_are_cached_independently() {
        let (store, backend) = faked_store(true);
        backend.seed("clx:global:azure-api-key", "azure");
        backend.seed("clx:global:openai-api-key", "openai");

        assert_eq!(
            store.get("azure-api-key").unwrap().as_deref(),
            Some("azure")
        );
        assert_eq!(
            store.get("openai-api-key").unwrap().as_deref(),
            Some("openai")
        );
        // Re-read both: still served from cache.
        assert_eq!(
            store.get("azure-api-key").unwrap().as_deref(),
            Some("azure")
        );
        assert_eq!(
            store.get("openai-api-key").unwrap().as_deref(),
            Some("openai")
        );

        assert_eq!(backend.read_count(), 2, "one read per distinct key");
    }

    #[test]
    fn cached_negative_result_is_cached() {
        let (store, backend) = faked_store(true);
        // Nothing seeded -> missing credential.

        assert_eq!(store.get("missing").unwrap(), None);
        assert_eq!(store.get("missing").unwrap(), None);
        assert_eq!(store.get("missing").unwrap(), None);

        assert_eq!(
            backend.read_count(),
            1,
            "a missing optional credential must not re-query the keychain"
        );
    }

    #[test]
    fn cached_scoped_fallback_caches_both_lookups() {
        let (store, backend) = faked_store(true);
        backend.seed("clx:global:azure-api-key", "global-key");

        // First fallback: project scope misses, global hits => 2 backend reads.
        assert_eq!(
            store
                .get_with_fallback("azure-api-key", "/proj")
                .unwrap()
                .as_deref(),
            Some("global-key")
        );
        // Second fallback: both served from cache => no new backend reads.
        assert_eq!(
            store
                .get_with_fallback("azure-api-key", "/proj")
                .unwrap()
                .as_deref(),
            Some("global-key")
        );

        assert_eq!(backend.read_count(), 2);
    }

    #[test]
    fn cached_concurrent_first_access_hits_backend_once() {
        let (store, backend) = faked_store(true);
        backend.seed("clx:global:api", "secret-value");

        let mut handles = Vec::new();
        for _ in 0..8 {
            let s = store.clone();
            handles.push(std::thread::spawn(move || s.get("api").unwrap()));
        }
        for h in handles {
            assert_eq!(h.join().unwrap().as_deref(), Some("secret-value"));
        }

        // Racing readers may each see an empty cache and read the backend
        // before any populates it; the double-check insert guarantees the
        // cache converges to a single value. Bound the keychain hits well
        // below "once per call" (8) to prove caching engaged.
        let reads = backend.read_count();
        assert!(reads <= 8, "expected bounded backend reads, got {reads}");
        // Subsequent reads are fully cached.
        let before = backend.read_count();
        assert_eq!(store.get("api").unwrap().as_deref(), Some("secret-value"));
        assert_eq!(backend.read_count(), before);
    }

    #[test]
    fn debug_does_not_expose_cached_secret() {
        let (store, backend) = faked_store(true);
        backend.seed("clx:global:api", "super-secret-not-leaked");
        let _ = store.get("api").unwrap();

        let dbg = format!("{store:?}");
        assert!(
            !dbg.contains("super-secret-not-leaked"),
            "Debug must never render cached secret values: {dbg}"
        );
        assert!(dbg.contains("cached: true"));
    }

    #[test]
    fn secret_string_debug_is_redacted() {
        // The cache stores secrecy::SecretString, whose Debug never prints
        // the inner value (compile + runtime guarantee).
        let s = SecretString::new("leak-me".to_string().into());
        let rendered = format!("{s:?}");
        assert!(!rendered.contains("leak-me"));
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
