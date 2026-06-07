//! Pluggable credential backends.
//!
//! [`CredentialStore`](super::CredentialStore) owns an `Arc<dyn
//! CredentialBackend>`. All scoped-key building, validation, the key index,
//! and the process-scoped session cache live ABOVE this trait and are
//! backend-agnostic; only the final read/write/delete/list of an
//! already-scoped key is delegated here.
//!
//! # Why a file backend is the default
//!
//! No macOS keychain API can serve an unsigned / adhoc-signed binary
//! prompt-free. The data-protection keychain rejects unsigned binaries with
//! `errSecMissingEntitlement` (-34018, Apple TN3137); the legacy keychain
//! prompts on every read and the "Always Allow" ACL never persists for an
//! adhoc cdhash. The keychain therefore CANNOT be the default backend. CLX
//! defaults to [`AgeFileBackend`]: an age-encrypted file under `~/.clx` that
//! is pure local file IO and NEVER prompts. The keychain
//! ([`KeyringBackend`]) is reachable ONLY when the user explicitly selects
//! `credentials.backend: keychain` (or `CLX_CREDENTIALS_BACKEND=keychain`).

use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use fs4::FileExt;
use fs4::TryLockError;
use secrecy::ExposeSecret;

use super::{CredentialError, Result};

/// Storage/retrieval of already-scoped credential keys.
///
/// Implementations MUST NOT prompt the user under any default code path.
/// `get` returns `Ok(None)` for a missing key (never an error), and MUST NOT
/// fall back to any other store: the layer above tries env / `api_key_file`.
pub trait CredentialBackend: Send + Sync {
    /// Fetch a secret by fully scoped key. `Ok(None)` if absent.
    fn get(&self, scoped_key: &str) -> Result<Option<String>>;
    /// Store (or overwrite) a secret by fully scoped key.
    fn set(&self, scoped_key: &str, value: &str) -> Result<()>;
    /// Delete a secret. Absent key is success (idempotent).
    fn delete(&self, scoped_key: &str) -> Result<()>;
    /// Every scoped key currently stored (used for the index reconcile).
    fn list_keys(&self) -> Result<Vec<String>>;
    /// Human label for diagnostics. Never includes secret material.
    fn label(&self) -> &'static str;
}

// ---------------------------------------------------------------------------
// AgeFileBackend (DEFAULT) -- age-encrypted file, never prompts.
// ---------------------------------------------------------------------------

/// Encrypted-file credential backend (the CLX default).
///
/// * Secrets live in `<dir>/credentials.age` (mode 0600), an age v1
///   (X25519 + ChaCha20-Poly1305) blob wrapping a JSON map of
///   `scoped_key -> secret`.
/// * The age identity is a random X25519 key at `<dir>/cred.key` (mode 0600),
///   generated on first use. No machine-id-derived material.
/// * `<dir>` (`~/.clx` in production) is forced to mode 0700.
/// * Every `set`/`delete` re-encrypts the whole map and writes it via
///   temp-file + atomic rename, so concurrent writers never observe a partial
///   file and the store never corrupts.
///
/// Pure file IO: this NEVER prompts and is identical on every OS.
///
/// # Concurrency contract
///
/// CLX hooks run as SEPARATE OS processes (one per hook invocation). The full
/// load -> decrypt -> mutate -> encrypt -> temp-write -> rename cycle is
/// serialized two ways:
///
/// * `write_lock` (in-process [`Mutex`]) prevents thread races and reduces
///   inter-process lock contention within one process.
/// * An advisory exclusive `flock`/`LockFileEx` on a dedicated sidecar
///   (`credentials.age.lock`, NOT the data file we rename over) serializes
///   the entire RMW across processes, so two concurrent hooks can never read
///   the same snapshot and silently drop each other's write. The lock is held
///   by an RAII guard released on every exit path including panic, and is
///   acquired with a bounded timeout so a stuck holder degrades the hook with
///   a clear error instead of hanging the host agent forever.
pub struct AgeFileBackend {
    dir: PathBuf,
    cred_file: PathBuf,
    key_file: PathBuf,
    lock_file: PathBuf,
    /// Serializes this process's read-modify-write cycles. Cross-process
    /// safety is provided by the advisory lock on `lock_file`.
    write_lock: Mutex<()>,
}

/// Max time to wait for the inter-process credential lock before giving up.
/// A hook that cannot acquire the lock returns a clear error and degrades
/// gracefully rather than hanging the host agent indefinitely.
const LOCK_TIMEOUT: Duration = Duration::from_secs(10);

/// Poll interval while waiting on a contended advisory lock.
const LOCK_POLL_INTERVAL: Duration = Duration::from_millis(25);

/// Number of times the READ path retries a transient zero-byte
/// `credentials.age` before surfacing a hard corruption error (FIX-8).
///
/// A zero-byte file is the brief window an external truncation (or a crash
/// mid-write) leaves before a valid blob reappears. The lock-free read path
/// can observe that window and would otherwise hard-error on the LLM-auth
/// path. A few short retries ride out the transient window without weakening
/// the WRITE path, which still fail-closes on zero bytes (never overwrites).
const READ_ZERO_BYTE_RETRIES: u32 = 3;

/// Delay between zero-byte read retries.
const READ_ZERO_BYTE_RETRY_DELAY: Duration = Duration::from_millis(20);

/// RAII guard holding the cross-process advisory exclusive lock. The lock is
/// released when the underlying file handle is dropped (and, as a hard
/// guarantee, on process death: advisory `flock`/`fcntl` locks are released
/// by the kernel when the owning process exits, so a killed holder never
/// wedges other processes).
struct InterProcessLockGuard {
    file: fs::File,
}

impl Drop for InterProcessLockGuard {
    fn drop(&mut self) {
        // Best-effort explicit unlock; the OS also releases on fd close.
        let _ = FileExt::unlock(&self.file);
    }
}

impl AgeFileBackend {
    /// Backend rooted at `~/.clx`.
    pub fn new() -> Result<Self> {
        Self::with_dir(crate::paths::clx_dir())
    }

    /// Backend rooted at an explicit directory (tests use a tempdir).
    pub fn with_dir(dir: impl Into<PathBuf>) -> Result<Self> {
        let dir = dir.into();
        Ok(Self {
            cred_file: dir.join("credentials.age"),
            key_file: dir.join("cred.key"),
            lock_file: dir.join("credentials.age.lock"),
            dir,
            write_lock: Mutex::new(()),
        })
    }

    fn map_err(ctx: &str, e: impl std::fmt::Display) -> CredentialError {
        CredentialError::Storage(format!("{ctx}: {e}"))
    }

    /// Ensure `dir` exists and is 0700 (best-effort tighten on Unix).
    fn ensure_dir(&self) -> Result<()> {
        if !self.dir.exists() {
            fs::create_dir_all(&self.dir)
                .map_err(|e| Self::map_err("create credentials dir", e))?;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&self.dir, fs::Permissions::from_mode(0o700));
        }
        Ok(())
    }

    /// Load (or first-run generate) the age identity. Generation is atomic
    /// (write temp + `create_new` rename), so two racing processes converge
    /// on a single keyfile and never corrupt it.
    fn load_identity(&self) -> Result<age::x25519::Identity> {
        use std::str::FromStr;

        if let Ok(contents) = fs::read_to_string(&self.key_file) {
            let line = contents
                .lines()
                .find(|l| !l.trim().is_empty() && !l.starts_with('#'))
                .ok_or_else(|| Self::map_err("read keyfile", "keyfile is empty"))?;
            return age::x25519::Identity::from_str(line.trim())
                .map_err(|e| Self::map_err("parse keyfile", e));
        }

        self.ensure_dir()?;
        let identity = age::x25519::Identity::generate();
        let serialized = identity.to_string(); // SecretString of "AGE-SECRET-KEY-1..."
        let body = format!(
            "# created by clx {} -- DO NOT SHARE. Loss of this file makes \
             credentials.age unrecoverable.\n{}\n",
            env!("CARGO_PKG_VERSION"),
            serialized.expose_secret()
        );

        // Atomic create: a uniquely-named temp file then create_new rename.
        // If another process already created the keyfile, adopt theirs.
        let tmp = self.tmp_path("cred.key");
        Self::write_private(&tmp, body.as_bytes())?;
        if Self::link_create_new(&tmp, &self.key_file).is_err() {
            // Another process won the create race; adopt their keyfile.
            let _ = fs::remove_file(&tmp);
            let contents = fs::read_to_string(&self.key_file)
                .map_err(|e| Self::map_err("read keyfile after race", e))?;
            let line = contents
                .lines()
                .find(|l| !l.trim().is_empty() && !l.starts_with('#'))
                .ok_or_else(|| Self::map_err("read keyfile after race", "empty"))?;
            return age::x25519::Identity::from_str(line.trim())
                .map_err(|e| Self::map_err("parse keyfile after race", e));
        }
        Ok(identity)
    }

    /// Unique temp path beside the target so rename is same-filesystem.
    fn tmp_path(&self, stem: &str) -> PathBuf {
        let pid = std::process::id();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        self.dir.join(format!(".{stem}.{pid}.{nanos}.tmp"))
    }

    /// Write bytes to `path` with 0600 perms (created or truncated).
    fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts
            .open(path)
            .map_err(|e| Self::map_err("open temp file", e))?;
        f.write_all(bytes)
            .map_err(|e| Self::map_err("write temp file", e))?;
        f.sync_all()
            .map_err(|e| Self::map_err("fsync temp file", e))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
        }
        Ok(())
    }

    /// Atomically publish a "create only if absent" file: hard-link the temp
    /// into place (fails if the target exists) then unlink the temp. Used for
    /// the one-shot keyfile so racing first-runs cannot clobber each other.
    fn link_create_new(tmp: &Path, dest: &Path) -> Result<()> {
        match fs::hard_link(tmp, dest) {
            Ok(()) => {
                let _ = fs::remove_file(tmp);
                Ok(())
            }
            Err(e) => Err(Self::map_err("publish keyfile", e)),
        }
    }

    /// Decrypt the credentials map.
    ///
    /// # Recovery contract
    ///
    /// * File ABSENT (fresh install) -> legitimate empty store. Zero prompts.
    /// * File present, valid age blob -> decrypted map.
    /// * File present, ZERO bytes -> treated as CORRUPTION, not an empty
    ///   store. A zero-byte file is exactly what a crash mid-write (before
    ///   temp+rename completes) or an external `truncate` produces. Returning
    ///   an empty map here would let the next `set`/`delete` overwrite it with
    ///   an empty-map blob and PERMANENTLY destroy every stored credential.
    ///   We instead surface an actionable error and NEVER auto-destroy. The
    ///   only safe recovery is the user deliberately removing the empty file
    ///   (then `set`/`migrate` repopulates from scratch).
    /// * File present, non-zero garbage -> already errors at the age decoder;
    ///   that behavior is preserved.
    fn load_map(&self, identity: &age::x25519::Identity) -> Result<BTreeMap<String, String>> {
        let encrypted = match fs::read(&self.cred_file) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(BTreeMap::new()),
            Err(e) => return Err(Self::map_err("read credentials.age", e)),
        };
        if encrypted.is_empty() {
            return Err(self.zero_byte_corruption_error());
        }
        let decryptor = age::Decryptor::new(&encrypted[..])
            .map_err(|e| Self::map_err("init age decryptor (corrupt credentials.age?)", e))?;
        let mut reader = decryptor
            .decrypt(std::iter::once(identity as &dyn age::Identity))
            .map_err(|e| Self::map_err("decrypt credentials.age (wrong/lost keyfile?)", e))?;
        let mut plaintext = Vec::new();
        reader
            .read_to_end(&mut plaintext)
            .map_err(|e| Self::map_err("read decrypted credentials", e))?;
        serde_json::from_slice(&plaintext)
            .map_err(|e| Self::map_err("parse decrypted credentials json", e))
    }

    /// The hard, actionable error surfaced when `credentials.age` exists but is
    /// zero bytes. Centralised so the read-retry path (FIX-8) and the
    /// write/`with_map` path share one message and the WRITE path keeps its
    /// never-overwrite guarantee.
    fn zero_byte_corruption_error(&self) -> CredentialError {
        CredentialError::Storage(format!(
            "credentials store is corrupt: {} exists but is zero bytes \
             (a crash or external truncate during a prior write). CLX will \
             NOT overwrite it, to avoid destroying credentials that may \
             have existed. To recover, delete the empty file deliberately \
             (`rm {}`) and re-run `clx credentials set <key> <value>` (or \
             `clx credentials migrate`) to repopulate it.",
            self.cred_file.display(),
            self.cred_file.display(),
        ))
    }

    /// Read-path map loader with a short bounded retry on a *transient*
    /// zero-byte file (FIX-8).
    ///
    /// The lock-free `get`/`list_keys` paths can momentarily observe the brief
    /// window where an external truncation has emptied `credentials.age` before
    /// a valid blob reappears. Rather than hard-error on the LLM-auth path, we
    /// retry the read a few times. A *persistently* zero-byte file still
    /// surfaces the same corruption error as before — so a real truncation is
    /// not masked, and the WRITE path's fail-closed no-overwrite behaviour is
    /// untouched (writes never call this).
    fn load_map_read(&self, identity: &age::x25519::Identity) -> Result<BTreeMap<String, String>> {
        let mut attempt = 0u32;
        loop {
            // Distinguish a zero-byte file (retryable) from any other error
            // (NotFound -> empty map, decode errors -> hard error). We only
            // retry when the file is present AND empty.
            let is_zero_byte = matches!(
                fs::metadata(&self.cred_file),
                Ok(meta) if meta.len() == 0
            );
            if is_zero_byte && attempt < READ_ZERO_BYTE_RETRIES {
                attempt += 1;
                std::thread::sleep(READ_ZERO_BYTE_RETRY_DELAY);
                continue;
            }
            return self.load_map(identity);
        }
    }

    /// Encrypt+atomically persist the map (temp file + rename).
    fn store_map(
        &self,
        identity: &age::x25519::Identity,
        map: &BTreeMap<String, String>,
    ) -> Result<()> {
        self.ensure_dir()?;
        let plaintext =
            serde_json::to_vec(map).map_err(|e| Self::map_err("serialize credentials", e))?;
        let recipient = identity.to_public();
        let encryptor =
            age::Encryptor::with_recipients(std::iter::once(&recipient as &dyn age::Recipient))
                .map_err(|e| Self::map_err("init age encryptor", e))?;
        let mut encrypted = Vec::new();
        {
            let mut writer = encryptor
                .wrap_output(&mut encrypted)
                .map_err(|e| Self::map_err("start age stream", e))?;
            writer
                .write_all(&plaintext)
                .map_err(|e| Self::map_err("encrypt credentials", e))?;
            writer
                .finish()
                .map_err(|e| Self::map_err("finalize age stream", e))?;
        }

        let tmp = self.tmp_path("credentials.age");
        Self::write_private(&tmp, &encrypted)?;
        // Atomic replace: rename over the destination on the same filesystem.
        fs::rename(&tmp, &self.cred_file).map_err(|e| {
            let _ = fs::remove_file(&tmp);
            Self::map_err("atomically replace credentials.age", e)
        })?;
        Ok(())
    }

    /// Acquire the cross-process advisory exclusive lock on the dedicated
    /// sidecar lockfile, blocking up to [`LOCK_TIMEOUT`].
    ///
    /// We lock the sidecar, never `credentials.age` itself: the data file is
    /// replaced via rename, and locking a file you rename over is racy (the
    /// lock would be bound to an inode that gets unlinked). The sidecar is
    /// created once and never renamed, so its inode is stable.
    ///
    /// On timeout we return a clear error rather than block forever, so a
    /// stuck holder degrades the hook gracefully instead of hanging the host
    /// agent. The kernel releases advisory locks on fd close AND on process
    /// death, so a killed holder never permanently wedges other processes.
    fn acquire_interprocess_lock(&self) -> Result<InterProcessLockGuard> {
        self.ensure_dir()?;
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let file = opts
            .open(&self.lock_file)
            .map_err(|e| Self::map_err("open credentials lockfile", e))?;

        let deadline = Instant::now() + LOCK_TIMEOUT;
        loop {
            match FileExt::try_lock(&file) {
                Ok(()) => return Ok(InterProcessLockGuard { file }),
                Err(TryLockError::WouldBlock) => {
                    if Instant::now() >= deadline {
                        return Err(CredentialError::Storage(format!(
                            "could not acquire the credential store lock within {}s \
                             (another process is holding {}). Aborting WITHOUT \
                             writing so no credential is lost; retry shortly.",
                            LOCK_TIMEOUT.as_secs(),
                            self.lock_file.display(),
                        )));
                    }
                    std::thread::sleep(LOCK_POLL_INTERVAL);
                }
                Err(TryLockError::Error(e)) => {
                    return Err(Self::map_err("lock credentials store", e));
                }
            }
        }
    }

    fn with_map<R>(
        &self,
        f: impl FnOnce(&mut BTreeMap<String, String>, &age::x25519::Identity) -> Result<R>,
    ) -> Result<R> {
        // In-process Mutex first: cheap, prevents thread races, and reduces
        // contention on the inter-process lock.
        let _thread_guard = self
            .write_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // Cross-process advisory lock around the ENTIRE read-modify-write so
        // two hook processes can never lose each other's write. RAII: dropped
        // (and unlocked) on every exit path including `?` early-return and
        // panic.
        let _proc_guard = self.acquire_interprocess_lock()?;
        let identity = self.load_identity()?;
        let mut map = self.load_map(&identity)?;
        let out = f(&mut map, &identity)?;
        Ok(out)
    }
}

impl CredentialBackend for AgeFileBackend {
    fn get(&self, scoped_key: &str) -> Result<Option<String>> {
        let identity = self.load_identity()?;
        Ok(self.load_map_read(&identity)?.get(scoped_key).cloned())
    }

    fn set(&self, scoped_key: &str, value: &str) -> Result<()> {
        self.with_map(|map, id| {
            map.insert(scoped_key.to_string(), value.to_string());
            self.store_map(id, map)
        })
    }

    fn delete(&self, scoped_key: &str) -> Result<()> {
        self.with_map(|map, id| {
            if map.remove(scoped_key).is_some() {
                self.store_map(id, map)?;
            }
            Ok(())
        })
    }

    fn list_keys(&self) -> Result<Vec<String>> {
        let identity = self.load_identity()?;
        Ok(self.load_map_read(&identity)?.into_keys().collect())
    }

    fn label(&self) -> &'static str {
        "age-file"
    }
}

// Never print the on-disk paths' secret contents via Debug.
impl std::fmt::Debug for AgeFileBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgeFileBackend")
            .field("dir", &self.dir)
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// KeyringBackend (OPT-IN ONLY) -- the legacy system keychain.
// ---------------------------------------------------------------------------

/// System-keychain backend. Selected ONLY when the user explicitly sets
/// `credentials.backend: keychain` (or `CLX_CREDENTIALS_BACKEND=keychain`).
///
/// This is the verbatim, behavior-preserving move of the previously
/// hardwired `keyring::Entry` logic. With the default (`file`) backend this
/// type is never constructed, so the macOS keychain is never touched.
pub struct KeyringBackend {
    service: String,
}

impl KeyringBackend {
    pub fn new(service: impl Into<String>) -> Self {
        Self {
            service: service.into(),
        }
    }

    fn entry(&self, key: &str) -> Result<keyring::Entry> {
        keyring::Entry::new(&self.service, key).map_err(|e| {
            CredentialError::ServiceUnavailable(format!("Failed to create keychain entry: {e}"))
        })
    }

    fn map_keyring_error(error: keyring::Error, key: &str) -> CredentialError {
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
                tracing::warn!("Keychain access denied: {:?}", platform_err);
                CredentialError::AccessDenied(
                    "Unable to access system keychain. Please check your security settings."
                        .to_string(),
                )
            }
            keyring::Error::PlatformFailure(platform_err) => {
                tracing::warn!("Platform keychain error: {:?}", platform_err);
                CredentialError::ServiceUnavailable(format!(
                    "Keychain service error: {platform_err:?}"
                ))
            }
            _ => CredentialError::Keychain(format!("Keychain error: {error}")),
        }
    }

    /// Service name this backend binds to (used by the macOS ACL relax/repair
    /// helpers, which only matter on the opt-in keychain path).
    #[must_use]
    pub fn service(&self) -> &str {
        &self.service
    }
}

impl CredentialBackend for KeyringBackend {
    fn get(&self, scoped_key: &str) -> Result<Option<String>> {
        let entry = self.entry(scoped_key)?;
        match entry.get_password() {
            Ok(value) => Ok(Some(value)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(Self::map_keyring_error(e, scoped_key)),
        }
    }

    fn set(&self, scoped_key: &str, value: &str) -> Result<()> {
        let entry = self.entry(scoped_key)?;
        entry
            .set_password(value)
            .map_err(|e| Self::map_keyring_error(e, scoped_key))?;
        // macOS only: relax the freshly written item's ACL so the opt-in
        // keychain path does not re-prompt on every launch.
        super::keychain_acl::relax_item_access(&self.service, scoped_key);
        Ok(())
    }

    fn delete(&self, scoped_key: &str) -> Result<()> {
        let entry = self.entry(scoped_key)?;
        match entry.delete_password() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(Self::map_keyring_error(e, scoped_key)),
        }
    }

    fn list_keys(&self) -> Result<Vec<String>> {
        // The keychain has no portable enumeration; the index lives above the
        // trait (see CredentialStore index entries). Returning empty here is
        // correct: list() uses the index, not this method.
        Ok(Vec::new())
    }

    fn label(&self) -> &'static str {
        "keychain"
    }
}
