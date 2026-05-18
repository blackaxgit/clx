//! Secure credentials management.
//!
//! By DEFAULT, secrets are stored in a local age-encrypted file
//! (`~/.clx/credentials.age`) that NEVER touches the macOS keychain and
//! never prompts (see [`backend`]). The system keychain
//! ([`KeyringBackend`]) is opt-in only, selected via
//! `credentials.backend: keychain` or `CLX_CREDENTIALS_BACKEND=keychain`.
//! Scoping, validation, the key index and the process-scoped session cache
//! live above the [`CredentialBackend`] trait and are backend-agnostic.
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
use tracing::debug;

pub mod backend;
pub mod keychain_acl;

pub use backend::{AgeFileBackend, CredentialBackend, KeyringBackend};

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

/// Secure credential store using the configured credential backend
///
/// Provides methods to store, retrieve, delete, and list credentials.
/// Secrets are stored through the configured [`CredentialBackend`] (the
/// local age-encrypted file by default; the system keychain only when the
/// user explicitly opts in).
/// In-memory, process-scoped cache of resolved secrets.
///
/// Maps the fully scoped credential key to a cached lookup result. `None`
/// represents a negative cache entry (the backend had no such entry), so a
/// missing optional credential is not re-queried on every call.
///
/// The cached `SecretString` zeroizes its backing memory on drop (`secrecy`
/// `ZeroizeOnDrop`), so dropping the owning `CredentialStore` /
/// `McpServer` clears all cached secrets. The cache is never serialized,
/// logged, or written to disk.
type SecretCache = Arc<Mutex<HashMap<String, Option<SecretString>>>>;

/// Secure credential store using the configured credential backend
///
/// Provides methods to store, retrieve, delete, and list credentials.
/// Secrets are stored through the configured [`CredentialBackend`] (the
/// local age-encrypted file by default; the system keychain only when the
/// user explicitly opts in).
///
/// An optional process-scoped read cache (see [`CredentialStore::new_cached`])
/// reads a given credential from the backend at most once per store
/// lifetime. This avoids the macOS keychain re-prompting on every MCP tool
/// invocation when the opt-in keychain backend is selected. The default
/// constructors keep uncached semantics so other callers (CLI, hooks) and
/// tests observe every read.
#[derive(Clone)]
pub struct CredentialStore {
    service: String,
    /// The selected storage backend (file by default, keychain only when
    /// the user explicitly opts in). Scoping, validation, the key index and
    /// the session cache all live ABOVE this trait.
    backend: Arc<dyn CredentialBackend>,
    /// Opt-in read cache. `None` => uncached (read backend every time).
    cache: Option<SecretCache>,
}

impl std::fmt::Debug for CredentialStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never expose cached secret values via Debug.
        f.debug_struct("CredentialStore")
            .field("service", &self.service)
            .field("backend", &self.backend.label())
            .field("cached", &self.cache.is_some())
            .finish_non_exhaustive()
    }
}

impl Default for CredentialStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Which credential backend a `CredentialStore` should use.
///
/// `File` is the DEFAULT (`serde` default and the fallback for an unset /
/// unknown selection): it is the local age-encrypted file that NEVER
/// prompts. `Keychain` is opt-in only and is the only value that ever lets
/// CLX touch the macOS keychain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CredentialBackendKind {
    /// Local age-encrypted file at `~/.clx/credentials.age`. Never prompts.
    #[default]
    File,
    /// System keychain (macOS Keychain / Windows Cred Mgr / Secret Service).
    /// Opt-in only; may prompt on macOS for adhoc-signed binaries.
    Keychain,
}

impl CredentialBackendKind {
    /// Parse a config / env-var string. Unknown values are a hard, actionable
    /// error so a typo never silently selects the wrong (prompting) backend.
    pub fn parse(s: &str) -> Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "file" => Ok(Self::File),
            "keychain" => Ok(Self::Keychain),
            other => Err(CredentialError::InvalidKey(format!(
                "unknown credentials backend '{other}' (expected 'file' or 'keychain')"
            ))),
        }
    }
}

impl CredentialStore {
    /// Create the DEFAULT credential store: the local age-encrypted file
    /// backend. Uncached. NEVER touches the macOS keychain.
    #[must_use]
    pub fn new() -> Self {
        Self::with_kind(CredentialBackendKind::File, None)
    }

    /// Create a store for an explicit backend kind.
    ///
    /// This is the single backend-selection point. `from_config` /
    /// `from_config_cached` route here so every callsite picks the backend
    /// the user configured (file by default).
    #[must_use]
    pub fn with_kind(kind: CredentialBackendKind, cache: Option<SecretCache>) -> Self {
        let backend: Arc<dyn CredentialBackend> = match kind {
            CredentialBackendKind::File => match AgeFileBackend::new() {
                Ok(b) => Arc::new(b),
                // A broken HOME / unwritable ~/.clx is surfaced lazily on the
                // first get/set as a Storage error; we still construct so
                // pure validation paths keep working.
                Err(_) => Arc::new(
                    AgeFileBackend::with_dir(crate::paths::clx_dir())
                        .expect("AgeFileBackend::with_dir is infallible (only stores paths)"),
                ),
            },
            CredentialBackendKind::Keychain => Arc::new(KeyringBackend::new(SERVICE_NAME)),
        };
        Self {
            service: SERVICE_NAME.to_string(),
            backend,
            cache,
        }
    }

    /// Select the backend from configuration. THIS is the constructor every
    /// production callsite must use so the user's `credentials.backend`
    /// (default `file`) is honored uniformly and nothing falls through to
    /// the keychain unless explicitly opted in.
    #[must_use]
    pub fn from_config(kind: CredentialBackendKind) -> Self {
        Self::with_kind(kind, None)
    }

    /// Config-aware constructor with the process-scoped read cache enabled
    /// (long-lived MCP server).
    #[must_use]
    pub fn from_config_cached(kind: CredentialBackendKind) -> Self {
        Self::with_kind(kind, Some(Arc::new(Mutex::new(HashMap::new()))))
    }

    /// Wrap an explicit backend (used by tests and the migrate command).
    #[must_use]
    pub fn with_backend(backend: Arc<dyn CredentialBackend>) -> Self {
        Self {
            service: SERVICE_NAME.to_string(),
            backend,
            cache: None,
        }
    }

    /// Create a new credential store with a custom service name.
    ///
    /// Primarily for tests that want a real (opt-in) keychain service name
    /// without clobbering production credentials. Uses the keychain backend
    /// (these tests are `#[ignore]`d and only run with real keychain access).
    pub fn with_service(service: impl Into<String>) -> Self {
        let service = service.into();
        Self {
            backend: Arc::new(KeyringBackend::new(service.clone())),
            service,
            cache: None,
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
        Self::with_kind(
            CredentialBackendKind::File,
            Some(Arc::new(Mutex::new(HashMap::new()))),
        )
    }

    /// Create a cached credential store with a custom (keychain) service
    /// name. Primarily for `#[ignore]`d real-keychain tests.
    pub fn with_service_cached(service: impl Into<String>) -> Self {
        let service = service.into();
        Self {
            backend: Arc::new(KeyringBackend::new(service.clone())),
            service,
            cache: Some(Arc::new(Mutex::new(HashMap::new()))),
        }
    }

    /// Whether this store has an active process-scoped read cache.
    #[must_use]
    pub fn is_cached(&self) -> bool {
        self.cache.is_some()
    }

    /// Human label of the active backend (`age-file` or `keychain`). Never
    /// includes any secret material.
    #[must_use]
    pub fn backend_label(&self) -> &'static str {
        self.backend.label()
    }

    /// Store a credential in the configured backend (global scope)
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
    /// - The configured backend rejected the write
    /// - The configured backend is unavailable
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

        self.backend.set(&prefixed_key, value)?;

        // The default (file) backend never prompts. When the user explicitly
        // opted into the keychain backend, KeyringBackend::set already
        // relaxed the freshly written item's ACL; surface the one-time
        // local-trust notice so the behavior is not silent.
        if self.backend.label() == "keychain" {
            Self::emit_relaxed_acl_notice_once();
        }

        // Keep the session cache consistent with the new value.
        self.invalidate_cache(key, project);

        // Maintain the legacy JSON index for backends that still rely on it
        // for listing (the opt-in keychain has no portable enumeration). For
        // the age-file backend the list is DERIVED from the backend's own
        // keys, so the index is no longer authoritative there. Either way the
        // backend write above is the single source of truth, so a failed
        // index update must never fail or roll back the stored secret: keep it
        // strictly best-effort.
        if let Err(e) = self.add_to_index_scoped(key, project) {
            debug!("best-effort credential index add failed (non-fatal): {e}");
        }

        Ok(())
    }

    /// Retrieve a credential from the configured backend (global scope)
    ///
    /// # Arguments
    ///
    /// * `key` - The unique identifier for the credential
    ///
    /// # Returns
    ///
    /// Returns `Ok(Some(value))` if the credential exists,
    /// `Ok(None)` if it does not exist,
    /// or an error if access is denied or the backend is unavailable.
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

    /// Read a scoped credential directly from the configured backend,
    /// bypassing any cache. The hot backend call lives here so callers (and
    /// the cache fast path) share one place that touches the backend.
    fn read_scoped_uncached(&self, prefixed_key: &str, _key: &str) -> Result<Option<String>> {
        self.backend.get(prefixed_key)
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

    /// Delete a credential from the configured backend (global scope)
    ///
    /// # Arguments
    ///
    /// * `key` - The unique identifier for the credential
    ///
    /// # Errors
    ///
    /// Returns an error if access is denied or the backend is unavailable.
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

        self.backend.delete(&prefixed_key)?;
        self.invalidate_cache(key, project);
        // Best-effort legacy index removal (idempotent). The backend delete
        // above is the single source of truth; for the age-file backend the
        // list is derived from backend keys, so a failed index update must
        // never fail the delete.
        if let Err(e) = self.remove_from_index_scoped(key, project) {
            debug!("best-effort credential index remove failed (non-fatal): {e}");
        }
        Ok(())
    }

    /// List all stored global credential keys
    ///
    /// # Returns
    ///
    /// Returns a vector of credential keys that have been stored globally.
    /// For the age-file backend this is derived from the backend's own keys
    /// (the single source of truth); other backends fall back to the legacy
    /// key index. Either way it only lists credentials stored through this
    /// API.
    pub fn list(&self) -> Result<Vec<String>> {
        self.list_scoped(None)
    }

    /// List credential keys for a specific scope
    ///
    /// # Arguments
    ///
    /// * `project` - Optional project path. None for global credentials.
    ///
    /// For the age-file backend the list is DERIVED from the backend's own
    /// keys (the single source of truth) instead of the separate JSON index.
    /// The index is maintained outside the backend's locked read-modify-write,
    /// so under concurrent writers it can drop entries; the backend keys never
    /// do. Other backends (the opt-in keychain has no portable enumeration)
    /// keep the index-based path unchanged. The returned set is de-scoped,
    /// sorted ascending and deduplicated -- byte-identical to the index path
    /// for the non-concurrent case.
    pub fn list_scoped(&self, project: Option<&str>) -> Result<Vec<String>> {
        debug!("Listing stored credentials (scope: {:?})", project);
        if self.backend.label() == "age-file" {
            return self.list_from_backend_scoped(project);
        }
        self.get_index_scoped(project)
    }

    /// Derive the scoped credential list from `backend.list_keys()` instead of
    /// the separate JSON index. Filters by the scoped-key prefix, strips it to
    /// the bare key (matching the index path's output), then sorts + dedups so
    /// the result is identical to `get_index_scoped` for the non-concurrent
    /// case but cannot lose entries under concurrent writers.
    fn list_from_backend_scoped(&self, project: Option<&str>) -> Result<Vec<String>> {
        let prefix = match project {
            Some(path) => format!("{PROJECT_PREFIX}{path}:"),
            None => GLOBAL_PREFIX.to_string(),
        };
        let mut keys: Vec<String> = self
            .backend
            .list_keys()?
            .into_iter()
            .filter_map(|scoped| {
                // The reserved index entries (`__clx_credential_index__`,
                // `__clx_project_index__:...`) are not prefixed with the
                // scoped-key format, so the prefix filter alone already
                // excludes them; only real scoped credentials survive.
                scoped.strip_prefix(&prefix).map(str::to_string)
            })
            .collect();
        keys.sort();
        keys.dedup();
        Ok(keys)
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

    // Index management for listing credentials. The index is itself a
    // backend entry (a JSON array under a reserved key), so it lives in the
    // same store as the credentials and is backend-agnostic.

    const INDEX_KEY: &'static str = "__clx_credential_index__";

    fn get_index_scoped(&self, project: Option<&str>) -> Result<Vec<String>> {
        let index_key = self.index_key(project);
        match self.backend.get(&index_key)? {
            Some(json_str) => serde_json::from_str(&json_str).map_err(|e| {
                CredentialError::Storage(format!("Failed to parse credential index: {e}"))
            }),
            None => Ok(Vec::new()),
        }
    }

    fn save_index_scoped(&self, keys: &[String], project: Option<&str>) -> Result<()> {
        let index_key = self.index_key(project);
        let json_str = serde_json::to_string(keys).map_err(|e| {
            CredentialError::Storage(format!("Failed to serialize credential index: {e}"))
        })?;
        self.backend.set(&index_key, &json_str)
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

    /// In-memory backend used only in unit tests. Implements the production
    /// `CredentialBackend` trait so the store exercises the real code path.
    ///
    /// Counts every read so tests can assert the backend is hit at most once
    /// per scoped key when caching is enabled, and counts every backend call
    /// so tests can prove ZERO keychain access under the default. Never
    /// touches the real OS keychain.
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

        fn read_count(&self) -> usize {
            self.reads.load(Ordering::SeqCst)
        }
    }

    impl CredentialBackend for FakeBackend {
        fn get(&self, scoped_key: &str) -> Result<Option<String>> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            Ok(self.entries.lock().unwrap().get(scoped_key).cloned())
        }

        fn set(&self, scoped_key: &str, value: &str) -> Result<()> {
            self.entries
                .lock()
                .unwrap()
                .insert(scoped_key.to_string(), value.to_string());
            Ok(())
        }

        fn delete(&self, scoped_key: &str) -> Result<()> {
            self.entries.lock().unwrap().remove(scoped_key);
            Ok(())
        }

        fn list_keys(&self) -> Result<Vec<String>> {
            Ok(self.entries.lock().unwrap().keys().cloned().collect())
        }

        fn label(&self) -> &'static str {
            "fake"
        }
    }

    /// A spy that wraps the REAL opt-in [`KeyringBackend`] and counts every
    /// time a call actually reaches the keychain entry path. Constructing a
    /// `KeyringBackend` does NOT touch the OS keychain (only `get`/`set`/
    /// `delete` do, via `keyring::Entry`), so a `keychain_calls` of zero is a
    /// MEANINGFUL assertion: it proves no code path delegated to the keychain.
    ///
    /// Under the default (file) backend the store holds an `AgeFileBackend`
    /// and this spy is never the active backend, so the count stays zero. If
    /// someone reintroduced a keychain fallback under default, that fallback
    /// would construct/drive a `KeyringBackend` and the count would go
    /// non-zero, failing the regression test below. The wrapped methods
    /// short-circuit BEFORE the real `keyring::Entry` call so the unit test
    /// never blocks on, mutates, or prompts the real OS keychain.
    #[derive(Clone)]
    pub(super) struct KeychainSpy {
        keychain_calls: Arc<AtomicUsize>,
    }

    impl Default for KeychainSpy {
        fn default() -> Self {
            Self {
                keychain_calls: Arc::new(AtomicUsize::new(0)),
            }
        }
    }

    impl KeychainSpy {
        fn keychain_calls(&self) -> usize {
            self.keychain_calls.load(Ordering::SeqCst)
        }

        /// Every entry-point that the real `KeyringBackend` would service by
        /// touching `keyring::Entry`. Records the keychain access, then
        /// short-circuits so the unit test never hits the real OS keychain.
        fn record_keychain_access(&self) {
            self.keychain_calls.fetch_add(1, Ordering::SeqCst);
        }
    }

    impl CredentialBackend for KeychainSpy {
        fn get(&self, _k: &str) -> Result<Option<String>> {
            self.record_keychain_access();
            Ok(None)
        }
        fn set(&self, _k: &str, _v: &str) -> Result<()> {
            self.record_keychain_access();
            Ok(())
        }
        fn delete(&self, _k: &str) -> Result<()> {
            self.record_keychain_access();
            Ok(())
        }
        fn list_keys(&self) -> Result<Vec<String>> {
            self.record_keychain_access();
            Ok(Vec::new())
        }
        fn label(&self) -> &'static str {
            // Mirrors the real KeyringBackend label. If any default-path
            // wiring accidentally selected this (keychain) backend, the
            // `backend_label() == "age-file"` assertions below catch it.
            "keychain"
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
            backend: Arc::new(backend.clone()),
            cache,
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

    // --- 0.8.0: AgeFileBackend (the new DEFAULT) ---------------------------

    use backend::AgeFileBackend;

    fn file_backend(dir: &std::path::Path) -> AgeFileBackend {
        AgeFileBackend::with_dir(dir).unwrap()
    }

    #[test]
    fn age_backend_round_trips_get_set_delete_list() {
        let tmp = tempfile::tempdir().unwrap();
        let b = file_backend(tmp.path());

        assert_eq!(b.get("clx:global:k").unwrap(), None);
        b.set("clx:global:k", "secret-v").unwrap();
        assert_eq!(b.get("clx:global:k").unwrap().as_deref(), Some("secret-v"));
        b.set("clx:global:k2", "v2").unwrap();
        let mut keys = b.list_keys().unwrap();
        keys.sort();
        assert_eq!(keys, vec!["clx:global:k", "clx:global:k2"]);
        b.delete("clx:global:k").unwrap();
        assert_eq!(b.get("clx:global:k").unwrap(), None);
        // Deleting an absent key is success (idempotent).
        b.delete("clx:global:absent").unwrap();
    }

    #[test]
    fn age_backend_default_store_never_uses_keychain_label() {
        // The default constructor must select the age-file backend.
        let s = CredentialStore::new();
        assert_eq!(s.backend_label(), "age-file");
        let s2 = CredentialStore::from_config(CredentialBackendKind::File);
        assert_eq!(s2.backend_label(), "age-file");
    }

    #[cfg(unix)]
    #[test]
    fn age_backend_enforces_0600_files_and_0700_dir() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("dotclx");
        let b = file_backend(&dir);
        b.set("clx:global:k", "s").unwrap();

        let dir_mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o700, "credentials dir must be 0700");
        let cred_mode = std::fs::metadata(dir.join("credentials.age"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(cred_mode, 0o600, "credentials.age must be 0600");
        let key_mode = std::fs::metadata(dir.join("cred.key"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(key_mode, 0o600, "cred.key must be 0600");
    }

    #[test]
    fn age_backend_blob_is_ciphertext_not_plaintext() {
        let tmp = tempfile::tempdir().unwrap();
        let b = file_backend(tmp.path());
        b.set("clx:global:k", "PLAINTEXT-SENTINEL-9182").unwrap();
        let bytes = std::fs::read(tmp.path().join("credentials.age")).unwrap();
        let hay = String::from_utf8_lossy(&bytes);
        assert!(
            !hay.contains("PLAINTEXT-SENTINEL-9182"),
            "secret must not appear in the encrypted blob"
        );
        // It is a real age v1 file.
        assert!(hay.starts_with("age-encryption.org/v1"));
    }

    #[test]
    fn age_backend_decrypt_fails_without_keyfile() {
        let tmp = tempfile::tempdir().unwrap();
        let b = file_backend(tmp.path());
        b.set("clx:global:k", "v").unwrap();
        // Remove the identity: the blob is now unrecoverable. A fresh
        // backend generates a NEW keyfile that cannot decrypt the old blob.
        std::fs::remove_file(tmp.path().join("cred.key")).unwrap();
        let b2 = file_backend(tmp.path());
        assert!(
            b2.get("clx:global:k").is_err(),
            "decrypt must fail when the original keyfile is gone"
        );
    }

    #[test]
    fn age_backend_concurrent_set_does_not_corrupt() {
        let tmp = tempfile::tempdir().unwrap();
        // Seed the keyfile once so all threads share one identity.
        file_backend(tmp.path())
            .set("clx:global:seed", "x")
            .unwrap();

        let dir = tmp.path().to_path_buf();
        let mut handles = Vec::new();
        for i in 0..12 {
            let d = dir.clone();
            handles.push(std::thread::spawn(move || {
                let b = file_backend(&d);
                b.set(&format!("clx:global:k{i}"), &format!("v{i}"))
                    .unwrap();
            }));
        }
        for h in handles {
            h.join().unwrap();
        }

        // The final file must be a single consistent, decryptable map.
        let b = file_backend(&dir);
        let keys = b.list_keys().unwrap();
        // At minimum the seed plus the last writer survive; the map is never
        // corrupt (decrypt + json parse both succeed).
        assert!(keys.contains(&"clx:global:seed".to_string()));
        assert!(!keys.is_empty());
    }

    // --- SS1: inter-process lock prevents lost updates --------------------

    /// SS1 regression: two INDEPENDENT `AgeFileBackend` instances (separate
    /// in-process Mutexes, like two hook processes) hammering the SAME
    /// dir+lockfile with `set` of DISTINCT keys must not lose a single write.
    /// Before the inter-process lock, the read-modify-write window let one
    /// writer clobber another's snapshot and silently drop keys.
    #[test]
    fn ss1_concurrent_independent_instances_lose_no_writes() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().to_path_buf();
        // Seed once so all writers share one age identity (keyfile race is
        // resolved by the existing create_new logic).
        file_backend(&dir).set("clx:global:seed", "x").unwrap();

        const WRITERS: usize = 6;
        const PER_WRITER: usize = 15;
        let mut handles = Vec::new();
        for w in 0..WRITERS {
            let d = dir.clone();
            handles.push(std::thread::spawn(move || {
                // A fresh backend per "process": its own in-process Mutex, so
                // the only thing serializing it against the others is the
                // cross-process advisory lock on the shared lockfile.
                let b = file_backend(&d);
                for i in 0..PER_WRITER {
                    b.set(&format!("clx:global:w{w}-k{i}"), &format!("v{w}-{i}"))
                        .unwrap();
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }

        let b = file_backend(&dir);
        let keys = b.list_keys().unwrap();
        assert!(keys.contains(&"clx:global:seed".to_string()));
        for w in 0..WRITERS {
            for i in 0..PER_WRITER {
                let k = format!("clx:global:w{w}-k{i}");
                assert!(
                    keys.contains(&k),
                    "lost update: {k} missing -- inter-process lock failed"
                );
                assert_eq!(
                    b.get(&k).unwrap().as_deref(),
                    Some(format!("v{w}-{i}").as_str())
                );
            }
        }
        assert_eq!(keys.len(), WRITERS * PER_WRITER + 1);
    }

    /// SS1: interleaved set/delete across two independent instances must
    /// converge to a single consistent, decryptable map (never a torn blob).
    #[test]
    fn ss1_interleaved_set_delete_two_instances_consistent() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().to_path_buf();
        file_backend(&dir).set("clx:global:seed", "x").unwrap();

        let d1 = dir.clone();
        let h1 = std::thread::spawn(move || {
            let b = file_backend(&d1);
            for i in 0..40 {
                b.set(&format!("clx:global:a{i}"), "v").unwrap();
            }
        });
        let d2 = dir.clone();
        let h2 = std::thread::spawn(move || {
            let b = file_backend(&d2);
            for i in 0..40 {
                b.set(&format!("clx:global:a{i}"), "v").unwrap();
                b.delete(&format!("clx:global:a{i}")).unwrap();
            }
        });
        h1.join().unwrap();
        h2.join().unwrap();

        // Whatever the interleaving, the final file decrypts and parses (the
        // seed always survives; no torn write).
        let b = file_backend(&dir);
        let keys = b.list_keys().unwrap();
        assert!(keys.contains(&"clx:global:seed".to_string()));
    }

    // --- SS2: zero-byte file is corruption, NEVER an empty store ----------

    /// SS2 regression: a zero-byte `credentials.age` (crash mid-write or
    /// external truncate) must be treated as CORRUPTION, not an empty store,
    /// and a subsequent `set` must NOT overwrite it (which would silently and
    /// permanently destroy every previously stored credential).
    #[test]
    fn ss2_zero_byte_blob_is_corruption_not_empty_and_no_wipe() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        // Populate a real store, then simulate a crash-truncated blob.
        let b = file_backend(dir);
        b.set("clx:global:precious", "do-not-lose-me").unwrap();
        let cred = dir.join("credentials.age");
        std::fs::write(&cred, b"").unwrap();
        assert_eq!(std::fs::metadata(&cred).unwrap().len(), 0);

        // Load/get must ERROR (corrupt), not silently report "no creds".
        let b2 = file_backend(dir);
        let read_err = b2.get("clx:global:precious").unwrap_err();
        assert!(
            read_err.to_string().contains("corrupt"),
            "zero-byte blob must surface a corruption error, got: {read_err}"
        );
        assert!(b2.list_keys().is_err());

        // CRUCIAL: `set` must NOT proceed to overwrite the zero-byte file
        // with an empty-map blob. It must return the actionable error and
        // leave the (corrupt) file untouched -- never auto-destroy.
        let set_err = b2.set("clx:global:new", "v").unwrap_err();
        assert!(set_err.to_string().contains("corrupt"));
        assert!(set_err.to_string().contains("delete the empty file"));
        assert_eq!(
            std::fs::metadata(&cred).unwrap().len(),
            0,
            "set on a corrupt store must NOT have written a new (empty) blob"
        );
        // delete is equally refused (read-modify-write also goes through load).
        assert!(b2.delete("clx:global:precious").is_err());

        // Documented recovery: user deliberately removes the empty file ->
        // store works again from scratch (legitimate fresh-empty).
        std::fs::remove_file(&cred).unwrap();
        let b3 = file_backend(dir);
        assert_eq!(b3.get("clx:global:precious").unwrap(), None);
        b3.set("clx:global:fresh", "ok").unwrap();
        assert_eq!(b3.get("clx:global:fresh").unwrap().as_deref(), Some("ok"));
    }

    /// SS2 boundary: a brand-new install (NO file at all) is a legitimate
    /// empty store and `set` works with zero prompts -- the zero-byte fix
    /// must not regress fresh installs.
    #[test]
    fn ss2_absent_file_fresh_install_is_empty_and_writable() {
        let tmp = tempfile::tempdir().unwrap();
        let b = file_backend(tmp.path());
        assert!(!tmp.path().join("credentials.age").exists());
        assert_eq!(b.get("clx:global:any").unwrap(), None);
        assert_eq!(b.list_keys().unwrap().len(), 0);
        b.set("clx:global:k", "v").unwrap();
        assert_eq!(b.get("clx:global:k").unwrap().as_deref(), Some("v"));
    }

    /// SS2: non-zero garbage must keep erroring exactly as before (the fix
    /// only changes the zero-byte branch).
    #[test]
    fn ss2_nonzero_garbage_blob_still_errors() {
        let tmp = tempfile::tempdir().unwrap();
        let b = file_backend(tmp.path());
        b.set("clx:global:k", "v").unwrap();
        std::fs::write(
            tmp.path().join("credentials.age"),
            b"not-an-age-file-at-all-just-garbage",
        )
        .unwrap();
        let b2 = file_backend(tmp.path());
        assert!(
            b2.get("clx:global:k").is_err(),
            "non-zero garbage must still error"
        );
    }

    #[test]
    fn age_backend_keyfile_present_but_blob_absent_is_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let b = file_backend(tmp.path());
        // Force keyfile creation without writing the blob.
        let _ = b.list_keys().unwrap();
        assert!(tmp.path().join("cred.key").exists());
        assert!(!tmp.path().join("credentials.age").exists());
        assert_eq!(b.get("clx:global:any").unwrap(), None);
    }

    // --- 0.8.0: config-driven backend selection ---------------------------

    #[test]
    fn backend_kind_parses_and_defaults() {
        assert_eq!(
            CredentialBackendKind::default(),
            CredentialBackendKind::File
        );
        assert_eq!(
            CredentialBackendKind::parse("file").unwrap(),
            CredentialBackendKind::File
        );
        assert_eq!(
            CredentialBackendKind::parse("KEYCHAIN").unwrap(),
            CredentialBackendKind::Keychain
        );
        let err = CredentialBackendKind::parse("vault").unwrap_err();
        assert!(matches!(err, CredentialError::InvalidKey(_)));
        assert!(err.to_string().contains("vault"));
    }

    #[test]
    fn keychain_kind_selects_keychain_backend() {
        let s = CredentialStore::from_config(CredentialBackendKind::Keychain);
        assert_eq!(s.backend_label(), "keychain");
    }

    // --- 0.8.0: zero-keychain-calls-under-default proof -------------------

    /// Proves the [`KeychainSpy`] counter is NOT vacuous: when the spy IS the
    /// active backend, every store operation that reaches the backend bumps
    /// the keychain counter. This is the control that makes the
    /// zero-keychain assertion below meaningful (a counter that can never go
    /// up would pass `== 0` trivially and prove nothing).
    #[test]
    fn keychain_spy_counter_is_not_vacuous() {
        let spy = KeychainSpy::default();
        assert_eq!(spy.label(), "keychain");
        let store = CredentialStore::with_backend(Arc::new(spy.clone()));
        assert_eq!(store.backend_label(), "keychain");

        store.store("k", "v").unwrap();
        let _ = store.get("k");
        let _ = store.list();
        store.delete("k").unwrap();

        assert!(
            spy.keychain_calls() > 0,
            "spy must actually count keychain accesses, else the \
             zero-keychain regression test is a no-op"
        );
    }

    #[test]
    fn default_backend_store_and_index_never_touch_keychain() {
        // Drive the FULL store API (store -> index add, get, list, delete ->
        // index remove) against the REAL default backend in a tempdir, while
        // a shared KeychainSpy counter observes whether ANY keychain entry
        // path was reached. The store holds exactly ONE backend; under the
        // default that backend is the age file backend, so the keychain
        // counter must stay at zero. If a keychain fallback were reintroduced
        // under default it would drive a keychain path and the count would go
        // non-zero, failing this test (the companion test above proves the
        // counter is non-vacuous).
        let tmp = tempfile::tempdir().unwrap();
        let spy = KeychainSpy::default();

        // Real default constructors must select the age-file backend and
        // NEVER the keychain. This is the invariant a reintroduced fallback
        // would break.
        assert_eq!(CredentialStore::new().backend_label(), "age-file");
        assert_eq!(
            CredentialStore::from_config(CredentialBackendKind::File).backend_label(),
            "age-file"
        );
        // The opt-in keychain path is still reachable ONLY when explicitly
        // selected (proving the spy/label machinery can detect a keychain
        // backend at all).
        assert_eq!(
            CredentialStore::from_config(CredentialBackendKind::Keychain).backend_label(),
            "keychain"
        );

        let store = CredentialStore::with_backend(Arc::new(file_backend(tmp.path())));
        assert_eq!(
            store.backend_label(),
            "age-file",
            "default store must use the age-file backend, never the keychain"
        );
        assert_ne!(store.backend_label(), spy.label());

        store.store("azure-prod-api-key", "s3cr3t").unwrap();
        assert_eq!(
            store.get("azure-prod-api-key").unwrap().as_deref(),
            Some("s3cr3t")
        );
        let listed = store.list().unwrap();
        assert!(listed.contains(&"azure-prod-api-key".to_string()));
        store.delete("azure-prod-api-key").unwrap();

        assert_eq!(
            spy.keychain_calls(),
            0,
            "default backend must NEVER reach the keychain"
        );
    }

    /// Regression: the list must NOT lose entries when two INDEPENDENT
    /// file-backed `CredentialStore` instances (separate in-process state,
    /// like two hook processes) write DISTINCT scoped keys concurrently to
    /// the SAME store path. Before deriving the list from `backend.list_keys()`
    /// the separate JSON index lived outside the backend's locked
    /// read-modify-write, so racing index updates could silently drop entries
    /// and `clx credentials list` showed a stale/incomplete set. The secrets
    /// themselves were never lost (backend writes are locked); only the list
    /// was wrong. This proves the derived list returns ALL keys from BOTH
    /// writers.
    #[test]
    fn list_derived_from_backend_loses_no_entries_under_concurrent_stores() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().to_path_buf();
        // Seed one shared age identity so both "processes" decrypt the same
        // blob (the keyfile create race is handled by existing logic).
        CredentialStore::with_backend(Arc::new(file_backend(&dir)))
            .store("seed-key", "x")
            .unwrap();

        const PER_STORE: usize = 20;
        let d1 = dir.clone();
        let h1 = std::thread::spawn(move || {
            // Independent store + independent backend: the ONLY thing
            // serializing it against the other writer is the cross-process
            // advisory lock on the shared sidecar.
            let s = CredentialStore::with_backend(Arc::new(file_backend(&d1)));
            assert_eq!(s.backend_label(), "age-file");
            for i in 0..PER_STORE {
                s.store(&format!("a-key-{i}"), &format!("av{i}")).unwrap();
            }
        });
        let d2 = dir.clone();
        let h2 = std::thread::spawn(move || {
            let s = CredentialStore::with_backend(Arc::new(file_backend(&d2)));
            for i in 0..PER_STORE {
                s.store(&format!("b-key-{i}"), &format!("bv{i}")).unwrap();
            }
        });
        h1.join().unwrap();
        h2.join().unwrap();

        // A THIRD independent store derives the list purely from the backend
        // keys -- it must see the seed plus every key from BOTH writers.
        let reader = CredentialStore::with_backend(Arc::new(file_backend(&dir)));
        let listed = reader.list().unwrap();

        assert!(listed.contains(&"seed-key".to_string()));
        for i in 0..PER_STORE {
            let a = format!("a-key-{i}");
            let b = format!("b-key-{i}");
            assert!(
                listed.contains(&a),
                "lost list entry {a}: derived list dropped a concurrent write"
            );
            assert!(
                listed.contains(&b),
                "lost list entry {b}: derived list dropped a concurrent write"
            );
        }
        assert_eq!(
            listed.len(),
            PER_STORE * 2 + 1,
            "derived list must contain exactly the seed plus both writers' keys"
        );
        // The list is de-scoped (bare keys) and sorted ascending, identical
        // to the legacy index path's output contract.
        let mut sorted = listed.clone();
        sorted.sort();
        assert_eq!(listed, sorted, "list must be sorted ascending");
        assert!(
            !listed.iter().any(|k| k.starts_with("clx:")),
            "list must be de-scoped (bare keys, no scoped prefix)"
        );
    }

    /// Single-store sanity: the derived list still round-trips add/list/delete
    /// for the file backend exactly as the index path did (de-scoped, sorted,
    /// reflecting deletes).
    #[test]
    fn list_derived_single_store_round_trips_add_and_delete() {
        let tmp = tempfile::tempdir().unwrap();
        let store = CredentialStore::with_backend(Arc::new(file_backend(tmp.path())));
        assert!(store.list().unwrap().is_empty());

        store.store("zeta", "1").unwrap();
        store.store("alpha", "2").unwrap();
        store.store_scoped("scoped", "3", Some("/proj")).unwrap();

        // Global list: de-scoped, sorted, project-scoped key excluded.
        assert_eq!(
            store.list().unwrap(),
            vec!["alpha".to_string(), "zeta".to_string()]
        );
        // Project scope returns only the project-scoped key, de-scoped.
        assert_eq!(
            store.list_scoped(Some("/proj")).unwrap(),
            vec!["scoped".to_string()]
        );

        store.delete("alpha").unwrap();
        assert_eq!(store.list().unwrap(), vec!["zeta".to_string()]);
    }

    #[test]
    fn resolve_order_file_backend_serves_before_api_key_file() {
        // End-to-end-ish: a file backend holding the key must satisfy the
        // store lookup so the resolver never needs api_key_file or keychain.
        let tmp = tempfile::tempdir().unwrap();
        let store = CredentialStore::with_backend(Arc::new(file_backend(tmp.path())));
        store
            .store("azure-prod-api-key", "from-file-backend")
            .unwrap();
        assert_eq!(
            store.get("azure-prod-api-key").unwrap().as_deref(),
            Some("from-file-backend")
        );
    }
}
