//! Behavior tests for the config-trust file-hash trustlist (Wave D, spec
//! `specs/_prerelease/03-credentials-config.md` section 3.7 and edge/failure
//! row E21).
//!
//! Exercises the public `clx_core::config::trust` API (`TrustList`,
//! `compute_file_hash`, `trusted_configs_path`) end to end against a
//! tempdir-redirected HOME. Per-machine semantics are proven by showing the
//! trustlist is keyed by content hash and lives under `~/.clx`, never in the
//! repo. `#[serial]` guards HOME mutation. No network.

use clx_core::config::trust::{
    TRUSTLIST_VERSION, TrustList, compute_file_hash, trusted_configs_path,
};
use serial_test::serial;

/// Redirect HOME so `trusted_configs_path()` resolves under a tempdir.
struct HomeGuard {
    tmp: tempfile::TempDir,
    prev: Option<String>,
}

impl HomeGuard {
    #[allow(unsafe_code)]
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let prev = std::env::var("HOME").ok();
        // SAFETY: single-threaded by #[serial] on every caller.
        unsafe {
            std::env::set_var("HOME", tmp.path());
        }
        Self { tmp, prev }
    }
    fn home(&self) -> &std::path::Path {
        self.tmp.path()
    }
}

impl Drop for HomeGuard {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        unsafe {
            match &self.prev {
                Some(v) => std::env::set_var("HOME", v),
                None => std::env::remove_var("HOME"),
            }
        }
    }
}

// =========================================================================
// 1. SHA-256 trustlist add / list / remove round-trip via the default path
// =========================================================================

#[test]
#[serial]
fn add_save_load_list_roundtrip_at_default_path() {
    let home = HomeGuard::new();

    let body = "providers:\n  azure-prod:\n    kind: azure_openai\n";
    let hash = compute_file_hash(body);
    assert!(hash.starts_with("sha256:"));
    assert_eq!(hash.len(), "sha256:".len() + 64, "hex SHA-256 is 64 chars");

    let mut tl = TrustList::default();
    assert_eq!(tl.version, TRUSTLIST_VERSION);
    assert!(tl.is_empty());
    assert!(tl.add(
        std::path::PathBuf::from("/repo/.clx/config.yaml"),
        hash.clone()
    ));
    tl.save().unwrap();

    // The file lands under the redirected ~/.clx, not in any repo.
    let expected = home.home().join(".clx").join("trusted_configs.json");
    assert_eq!(trusted_configs_path(), expected);
    assert!(expected.is_file(), "trustlist must persist under ~/.clx");

    let loaded = TrustList::load().unwrap();
    assert_eq!(loaded.len(), 1);
    assert!(loaded.is_trusted(&hash));
    assert_eq!(
        loaded.list()[0].path,
        std::path::PathBuf::from("/repo/.clx/config.yaml")
    );

    // Remove by full hash, persist, reload empty.
    let mut tl2 = TrustList::load().unwrap();
    assert!(tl2.remove(&hash).unwrap());
    tl2.save().unwrap();
    assert!(TrustList::load().unwrap().is_empty());
}

#[test]
#[serial]
fn remove_by_unambiguous_prefix_and_ambiguity_rules() {
    let _home = HomeGuard::new();
    let mut tl = TrustList::default();
    let h = compute_file_hash("unique-trust-content-xyz");
    tl.add(std::path::PathBuf::from("/q"), h.clone());

    // NOTE: the ">= 6 char prefix" guard is enforced by the
    // `clx config-trust remove` CLI layer, NOT by TrustList::remove. At the
    // library level any non-empty prefix that uniquely matches removes the
    // entry; ambiguity is an Err.
    let prefix: String = h.chars().take("sha256:".len() + 16).collect();
    assert!(
        tl.remove(&prefix).unwrap(),
        "unambiguous prefix removes entry"
    );
    assert!(tl.is_empty());

    // Ambiguous prefix across two entries => Err (not a silent wipe).
    let mut tl_amb = TrustList::default();
    tl_amb.add(std::path::PathBuf::from("/a"), compute_file_hash("a"));
    tl_amb.add(std::path::PathBuf::from("/b"), compute_file_hash("b"));
    // "sha256:" prefixes every hash -> ambiguous with 2 entries.
    let amb = tl_amb.remove("sha256:");
    assert!(
        amb.is_err(),
        "an ambiguous prefix must error, never wipe multiple entries"
    );
    assert_eq!(tl_amb.len(), 2, "no entry removed on ambiguity");

    // No match => Ok(false), not an error.
    let mut tl2 = TrustList::default();
    assert!(!tl2.remove("sha256:deadbeefcafe").unwrap());
    // Empty needle => error.
    assert!(tl2.remove("   ").is_err());
}

#[test]
#[serial]
fn add_deduplicates_by_hash_not_path() {
    let _home = HomeGuard::new();
    let mut tl = TrustList::default();
    let h = compute_file_hash("same-bytes");
    assert!(tl.add(std::path::PathBuf::from("/a/.clx/config.yaml"), h.clone()));
    // Same hash, different path => no new entry.
    assert!(!tl.add(std::path::PathBuf::from("/b/.clx/config.yaml"), h.clone()));
    assert_eq!(tl.len(), 1);
}

// =========================================================================
// 2. Hash invalidation on edit (3.7) -- the core security property
// =========================================================================

#[test]
#[serial]
fn any_byte_edit_changes_the_hash_and_breaks_trust() {
    let _home = HomeGuard::new();
    let original = "providers:\n  ok:\n    kind: azure_openai\n    endpoint: https://a.test\n";
    let h_orig = compute_file_hash(original);

    let mut tl = TrustList::default();
    tl.add(
        std::path::PathBuf::from("/p/.clx/config.yaml"),
        h_orig.clone(),
    );
    tl.save().unwrap();

    // A single added space changes the SHA-256, so the edited file is no
    // longer trusted (trust is content-hash exact, not path-based).
    let edited = "providers:\n  ok:\n    kind: azure_openai\n    endpoint: https://a.test \n";
    let h_edit = compute_file_hash(edited);
    assert_ne!(h_orig, h_edit, "any byte change must change the hash");

    let loaded = TrustList::load().unwrap();
    assert!(loaded.is_trusted(&h_orig), "original still trusted");
    assert!(
        !loaded.is_trusted(&h_edit),
        "edited content must NOT be trusted automatically"
    );
}

#[test]
#[serial]
fn is_trusted_requires_exact_match_no_prefix_trust() {
    let _home = HomeGuard::new();
    let mut tl = TrustList::default();
    let h = compute_file_hash("abc");
    tl.add(std::path::PathBuf::from("/abc"), h.clone());

    assert!(tl.is_trusted(&h));
    // A truncated hash must NOT be trusted (defence in depth).
    assert!(!tl.is_trusted(&h[..h.len() - 1]));
    // Unrelated content hash.
    assert!(!tl.is_trusted(&compute_file_hash("other")));
}

#[test]
fn compute_file_hash_is_deterministic_and_well_known() {
    // Deterministic over identical bytes.
    assert_eq!(compute_file_hash("hello\n"), compute_file_hash("hello\n"));
    // Distinct content => distinct hash.
    assert_ne!(compute_file_hash("a"), compute_file_hash("b"));
    // Well-known empty-string SHA-256 vector.
    assert_eq!(
        compute_file_hash(""),
        "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

// =========================================================================
// 3. Per-machine, non-propagating; malformed / unsupported (3.7, E21)
// =========================================================================

#[test]
#[serial]
fn trustlist_is_per_machine_under_home_not_in_repo() {
    let home = HomeGuard::new();
    let mut tl = TrustList::default();
    tl.add(
        std::path::PathBuf::from("/repo/.clx/config.yaml"),
        compute_file_hash("x"),
    );
    tl.save().unwrap();

    // The only persisted artifact is under ~/.clx; nothing is written into
    // the (display-only) project path, so it cannot propagate via git.
    let machine_file = home.home().join(".clx").join("trusted_configs.json");
    assert!(machine_file.is_file());
    assert!(
        !std::path::Path::new("/repo/.clx/config.yaml").exists(),
        "trust must not materialise anything in the repo path"
    );

    // A different HOME (a different machine/user) starts with an empty list.
    drop(home);
    let other = HomeGuard::new();
    assert!(
        TrustList::load().unwrap().is_empty(),
        "trust must NOT propagate across machines/users"
    );
    drop(other);
}

#[test]
#[serial]
fn missing_trustlist_loads_as_empty_not_error() {
    let _home = HomeGuard::new();
    // Fresh HOME, no file created.
    let tl = TrustList::load().unwrap();
    assert!(tl.is_empty());
    assert_eq!(tl.len(), 0);
    assert!(!tl.is_trusted(&compute_file_hash("anything")));
}

#[test]
#[serial]
fn malformed_json_is_load_error_refuses_silent_reset(// E21
) {
    let home = HomeGuard::new();
    let path = home.home().join(".clx").join("trusted_configs.json");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, "{ this is not json").unwrap();

    let err = TrustList::load().expect_err("malformed trustlist must error");
    assert!(
        format!("{err}").contains("malformed"),
        "must refuse a silent reset (security regression), got: {err}"
    );
}

#[test]
#[serial]
fn unsupported_version_is_load_error() {
    let home = HomeGuard::new();
    let path = home.home().join(".clx").join("trusted_configs.json");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, r#"{"version": 9999, "entries": []}"#).unwrap();

    let err = TrustList::load().expect_err("unsupported version must error");
    assert!(
        format!("{err}").contains("unsupported version"),
        "got: {err}"
    );
}

#[cfg(unix)]
#[test]
#[serial]
fn save_writes_0600_and_is_atomic() {
    use std::os::unix::fs::PermissionsExt;
    let home = HomeGuard::new();
    let mut tl = TrustList::default();
    tl.add(std::path::PathBuf::from("/v1"), compute_file_hash("v1"));
    tl.save().unwrap();

    let path = home.home().join(".clx").join("trusted_configs.json");
    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "trustlist must be 0600, got {mode:o}");

    // Overwrite atomically; no leftover .tmp.
    let mut tl2 = TrustList::default();
    tl2.add(std::path::PathBuf::from("/v2"), compute_file_hash("v2"));
    tl2.save().unwrap();
    assert!(
        !path.with_extension("json.tmp").exists(),
        "atomic rename must leave no .tmp file"
    );
    let loaded = TrustList::load().unwrap();
    assert_eq!(loaded.len(), 1);
    assert!(loaded.is_trusted(&compute_file_hash("v2")));
    assert!(!loaded.is_trusted(&compute_file_hash("v1")));
}
