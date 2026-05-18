//! Per-project config file-hash trustlist (0.8.0 §3.11).
//!
//! Power users can opt-in to non-inert project config keys (e.g.
//! `providers.azure.endpoint`) by trusting a specific file by content hash.
//!
//! # Security model
//!
//! - **Per-machine, per-user, per-file-hash.** Trust lives in
//!   `~/.clx/trusted_configs.json` (file mode `0600` on Unix). It is NEVER
//!   committed to a repository and does NOT propagate via git. A trusted
//!   config on machine A is untrusted on machine B until the user runs
//!   `clx config-trust add` again.
//! - **Hash-bound.** Trust is keyed by `sha256(file_contents)`. Any byte-level
//!   edit to the file invalidates trust automatically; the next config load
//!   falls back to the inert-key filter in
//!   [`crate::config::project::filter_inert_only`].
//! - **No path-only trust.** Path is stored for display only; the
//!   `is_trusted` check is content-hash exact.
//! - **Independent of `clx trust` mode.** The auto-allow-Bash trust token
//!   from PR #15 (see [`crate::types::TrustToken`]) is a separate concern.
//!   Do not conflate them.
//!
//! # File format
//!
//! ```json
//! {
//!   "version": 1,
//!   "entries": [
//!     {
//!       "hash": "sha256:abc...64hex",
//!       "path": "/Users/x/repo/.clx/config.yaml",
//!       "added_at": "2026-05-16T10:00:00Z"
//!     }
//!   ]
//! }
//! ```
//!
//! A missing file is treated as an empty list (no error). Malformed JSON
//! returns an error so a user-visible message can be shown — silent reset
//! would be a security regression.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Current on-disk schema version. Bump on breaking format changes; older
/// versions fail-loud rather than silently re-trust.
pub const TRUSTLIST_VERSION: u32 = 1;

/// Filename inside `~/.clx/` that stores the trustlist.
pub const TRUSTLIST_FILENAME: &str = "trusted_configs.json";

/// One trusted-config record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustedConfig {
    /// SHA-256 of the raw file contents, prefixed with `sha256:`.
    pub hash: String,
    /// Canonicalized path at the time of trust (display only).
    pub path: PathBuf,
    /// UTC timestamp when the entry was added.
    pub added_at: DateTime<Utc>,
}

/// Persisted trustlist (entries + schema version).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustList {
    #[serde(default = "default_version")]
    pub version: u32,
    #[serde(default)]
    entries: Vec<TrustedConfig>,
}

fn default_version() -> u32 {
    TRUSTLIST_VERSION
}

impl Default for TrustList {
    fn default() -> Self {
        Self {
            version: TRUSTLIST_VERSION,
            entries: Vec::new(),
        }
    }
}

/// Default path: `<clx_dir>/trusted_configs.json`.
#[must_use]
pub fn trusted_configs_path() -> PathBuf {
    crate::paths::clx_dir().join(TRUSTLIST_FILENAME)
}

impl TrustList {
    /// Load the trustlist from the default path. Missing file => empty list.
    /// Malformed JSON => error.
    pub fn load() -> Result<Self> {
        Self::load_from(&trusted_configs_path())
    }

    /// Load the trustlist from an explicit path. Missing file => empty list.
    pub fn load_from(path: &Path) -> Result<Self> {
        match fs::read_to_string(path) {
            Ok(content) => {
                let parsed: Self = serde_json::from_str(&content).with_context(|| {
                    format!(
                        "trustlist at {} is malformed JSON; refusing to silently reset",
                        path.display()
                    )
                })?;
                if parsed.version != TRUSTLIST_VERSION {
                    bail!(
                        "trustlist at {} has unsupported version {} (expected {}); re-run `clx config-trust add` to upgrade",
                        path.display(),
                        parsed.version,
                        TRUSTLIST_VERSION
                    );
                }
                Ok(parsed)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(anyhow::Error::from(e)
                .context(format!("failed to read trustlist at {}", path.display()))),
        }
    }

    /// Atomically persist the trustlist to the default path with mode `0600`
    /// on Unix.
    pub fn save(&self) -> Result<()> {
        self.save_to(&trusted_configs_path())
    }

    /// Atomic save to an explicit path. Writes to `<path>.tmp` first, sets
    /// `0600` on Unix, then renames over the target.
    pub fn save_to(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!("failed to create trustlist parent dir {}", parent.display())
            })?;
        }

        let tmp = path.with_extension("json.tmp");
        let json = serde_json::to_string_pretty(self)?;

        // Open with mode 0600 from the start on Unix to avoid a window where
        // the file is world-readable.
        let mut opts = fs::OpenOptions::new();
        opts.create(true).write(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts
            .open(&tmp)
            .with_context(|| format!("failed to open trustlist tmp file {}", tmp.display()))?;
        f.write_all(json.as_bytes())?;
        f.sync_all().ok();
        drop(f);

        // On non-Unix, set best-effort permissions after open (no-op for our
        // current Unix-only target but cheap to keep portable).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = fs::Permissions::from_mode(0o600);
            fs::set_permissions(&tmp, perms).ok();
        }

        fs::rename(&tmp, path)
            .with_context(|| format!("failed to rename {} -> {}", tmp.display(), path.display()))?;
        Ok(())
    }

    /// Return true if the given full hash (incl. `sha256:` prefix) is trusted.
    #[must_use]
    pub fn is_trusted(&self, file_hash: &str) -> bool {
        self.entries.iter().any(|e| e.hash == file_hash)
    }

    /// Add an entry. Deduplicates by hash: returns `true` if a new entry was
    /// appended, `false` if the hash was already trusted.
    pub fn add(&mut self, path: PathBuf, hash: String) -> bool {
        if self.entries.iter().any(|e| e.hash == hash) {
            return false;
        }
        self.entries.push(TrustedConfig {
            hash,
            path,
            added_at: Utc::now(),
        });
        true
    }

    /// Remove an entry by full hash or unambiguous hash prefix.
    ///
    /// Prefix must be at least 6 chars to avoid accidental wipes. Returns
    /// `Ok(true)` on removal, `Ok(false)` if no match, `Err` on ambiguity.
    pub fn remove(&mut self, hash_or_prefix: &str) -> Result<bool> {
        let needle = hash_or_prefix.trim();
        if needle.is_empty() {
            bail!("hash prefix is empty");
        }

        let matches: Vec<usize> = self
            .entries
            .iter()
            .enumerate()
            .filter(|(_, e)| e.hash == needle || e.hash.starts_with(needle))
            .map(|(i, _)| i)
            .collect();

        match matches.len() {
            0 => Ok(false),
            1 => {
                self.entries.remove(matches[0]);
                Ok(true)
            }
            n => bail!("hash prefix '{needle}' is ambiguous ({n} matches); supply more characters"),
        }
    }

    /// Immutable view of all entries.
    #[must_use]
    pub fn list(&self) -> &[TrustedConfig] {
        &self.entries
    }

    /// Number of trusted entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True if there are no trusted entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Compute the SHA-256 of a raw config file's textual contents, prefixed
/// with `sha256:`. Deterministic over identical byte sequences.
#[must_use]
pub fn compute_file_hash(content: &str) -> String {
    let digest = Sha256::digest(content.as_bytes());
    format!("sha256:{}", hex::encode(digest))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;
    use tempfile::TempDir;

    fn tmp_path(td: &TempDir) -> PathBuf {
        td.path().join("trusted_configs.json")
    }

    #[test]
    fn compute_file_hash_is_deterministic() {
        let a = compute_file_hash("hello\n");
        let b = compute_file_hash("hello\n");
        assert_eq!(a, b);
        assert!(a.starts_with("sha256:"));
        assert_eq!(a.len(), "sha256:".len() + 64);
    }

    #[test]
    fn compute_file_hash_changes_on_edit() {
        let a = compute_file_hash("hello\n");
        let b = compute_file_hash("hello\nworld\n");
        assert_ne!(a, b);
    }

    #[test]
    fn compute_file_hash_known_vector() {
        // Empty string SHA-256 (well-known test vector).
        assert_eq!(
            compute_file_hash(""),
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    #[serial]
    fn load_missing_file_returns_empty() {
        let td = TempDir::new().unwrap();
        let path = tmp_path(&td);
        let tl = TrustList::load_from(&path).unwrap();
        assert!(tl.is_empty());
        assert_eq!(tl.len(), 0);
    }

    #[test]
    #[serial]
    fn save_load_roundtrip() {
        let td = TempDir::new().unwrap();
        let path = tmp_path(&td);

        let mut tl = TrustList::default();
        let hash = compute_file_hash("providers:\n  azure:\n");
        assert!(tl.add(PathBuf::from("/tmp/proj/.clx/config.yaml"), hash.clone()));
        tl.save_to(&path).unwrap();

        let loaded = TrustList::load_from(&path).unwrap();
        assert_eq!(loaded.len(), 1);
        assert!(loaded.is_trusted(&hash));
        assert_eq!(
            loaded.list()[0].path,
            PathBuf::from("/tmp/proj/.clx/config.yaml")
        );
    }

    #[test]
    #[serial]
    fn add_deduplicates_by_hash() {
        let mut tl = TrustList::default();
        let h = compute_file_hash("x");
        assert!(tl.add(PathBuf::from("/a"), h.clone()));
        // Second add with same hash, different path => no-op.
        assert!(!tl.add(PathBuf::from("/b"), h.clone()));
        assert_eq!(tl.len(), 1);
    }

    #[test]
    #[serial]
    fn remove_returns_false_on_missing() {
        let mut tl = TrustList::default();
        let ok = tl.remove("sha256:deadbeefcafe").unwrap();
        assert!(!ok);
    }

    #[test]
    #[serial]
    fn remove_by_exact_hash() {
        let mut tl = TrustList::default();
        let h = compute_file_hash("y");
        tl.add(PathBuf::from("/y"), h.clone());
        assert!(tl.remove(&h).unwrap());
        assert!(tl.is_empty());
    }

    #[test]
    #[serial]
    fn remove_by_unambiguous_prefix() {
        let mut tl = TrustList::default();
        let h = compute_file_hash("unique-content-prefix-test");
        tl.add(PathBuf::from("/q"), h.clone());
        // First 16 chars of the hex part is unambiguous in a 1-entry list.
        let prefix: String = h.chars().take("sha256:".len() + 16).collect();
        assert!(tl.remove(&prefix).unwrap());
        assert!(tl.is_empty());
    }

    #[test]
    #[serial]
    fn remove_empty_prefix_errors() {
        let mut tl = TrustList::default();
        assert!(tl.remove("").is_err());
        assert!(tl.remove("   ").is_err());
    }

    #[test]
    #[serial]
    fn is_trusted_requires_exact_match() {
        let mut tl = TrustList::default();
        let h = compute_file_hash("abc");
        tl.add(PathBuf::from("/abc"), h.clone());
        assert!(tl.is_trusted(&h));
        // Truncated hash must NOT be considered trusted (defence-in-depth).
        assert!(!tl.is_trusted(&h[..h.len() - 1]));
        // Unrelated hash.
        assert!(!tl.is_trusted(&compute_file_hash("other")));
    }

    #[test]
    #[serial]
    fn malformed_json_returns_error_not_panic() {
        let td = TempDir::new().unwrap();
        let path = tmp_path(&td);
        fs::write(&path, "{not valid json").unwrap();
        let err = TrustList::load_from(&path).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("malformed"), "unexpected error: {msg}");
    }

    #[test]
    #[serial]
    fn unsupported_version_returns_error() {
        let td = TempDir::new().unwrap();
        let path = tmp_path(&td);
        fs::write(&path, r#"{"version": 999, "entries": []}"#).unwrap();
        let err = TrustList::load_from(&path).unwrap_err();
        assert!(format!("{err}").contains("unsupported version"));
    }

    #[cfg(unix)]
    #[test]
    #[serial]
    fn save_sets_0600_mode_on_unix() {
        use std::os::unix::fs::PermissionsExt;
        let td = TempDir::new().unwrap();
        let path = tmp_path(&td);
        let tl = TrustList::default();
        tl.save_to(&path).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "expected mode 0600, got {mode:o}");
    }

    #[test]
    #[serial]
    fn save_overwrites_existing_atomically() {
        let td = TempDir::new().unwrap();
        let path = tmp_path(&td);

        // First write.
        let mut tl = TrustList::default();
        let h1 = compute_file_hash("v1");
        tl.add(PathBuf::from("/v1"), h1.clone());
        tl.save_to(&path).unwrap();

        // Overwrite.
        let mut tl2 = TrustList::default();
        let h2 = compute_file_hash("v2");
        tl2.add(PathBuf::from("/v2"), h2.clone());
        tl2.save_to(&path).unwrap();

        let loaded = TrustList::load_from(&path).unwrap();
        assert_eq!(loaded.len(), 1);
        assert!(loaded.is_trusted(&h2));
        assert!(!loaded.is_trusted(&h1));

        // No leftover .tmp file.
        let tmp = path.with_extension("json.tmp");
        assert!(!tmp.exists(), "atomic rename should remove the tmp file");
    }
}
