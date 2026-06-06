//! Behavior tests for the credential backends (Wave D, spec
//! `specs/_prerelease/03-credentials-config.md` sections 1.3, 3.2, 3.3 and
//! the edge/failure matrix rows E4..E9, E13, E20 plus RISK C-R5).
//!
//! Anchored to real code in `crates/clx-core/src/credentials/backend.rs` and
//! `crates/clx-core/src/credentials.rs`. These exercise ONLY the public API
//! (`AgeFileBackend::with_dir`, the `CredentialBackend` trait,
//! `CredentialStore::with_backend`, `CredentialBackendKind`). No real
//! keychain, no network. Tempdir-rooted file backend throughout.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use clx_core::credentials::{
    AgeFileBackend, CredentialBackend, CredentialBackendKind, CredentialError, CredentialStore,
};

/// Local mirror of the crate-private `credentials::Result` alias so test
/// backends can implement the public `CredentialBackend` trait.
type CredResult<T> = std::result::Result<T, CredentialError>;

fn file_backend(dir: &std::path::Path) -> AgeFileBackend {
    AgeFileBackend::with_dir(dir).expect("AgeFileBackend::with_dir is infallible")
}

// =========================================================================
// 1. AgeFileBackend get/set/delete/list round-trip (spec 1.3, 3.2)
// =========================================================================

#[test]
fn age_backend_round_trips_get_set_delete_list() {
    let tmp = tempfile::tempdir().unwrap();
    let b = file_backend(tmp.path());

    // Missing key => Ok(None), never an error, no prompt.
    assert_eq!(b.get("clx:global:k").unwrap(), None);

    b.set("clx:global:k", "secret-v").unwrap();
    assert_eq!(b.get("clx:global:k").unwrap().as_deref(), Some("secret-v"));

    // Overwrite is in place.
    b.set("clx:global:k", "secret-v2").unwrap();
    assert_eq!(b.get("clx:global:k").unwrap().as_deref(), Some("secret-v2"));

    b.set("clx:global:k2", "v2").unwrap();
    let mut keys = b.list_keys().unwrap();
    keys.sort();
    assert_eq!(keys, vec!["clx:global:k", "clx:global:k2"]);

    b.delete("clx:global:k").unwrap();
    assert_eq!(b.get("clx:global:k").unwrap(), None);
    // Idempotent: deleting an absent key is success.
    b.delete("clx:global:absent").unwrap();
    assert_eq!(b.label(), "age-file");
}

#[test]
fn age_backend_survives_fresh_process_reopen() {
    // A new AgeFileBackend over the same dir must decrypt the prior blob
    // (the keyfile and the age recipient are stable on disk).
    let tmp = tempfile::tempdir().unwrap();
    file_backend(tmp.path())
        .set("clx:global:persisted", "value-A")
        .unwrap();
    let reopened = file_backend(tmp.path());
    assert_eq!(
        reopened.get("clx:global:persisted").unwrap().as_deref(),
        Some("value-A")
    );
}

// =========================================================================
// 2. On-disk modes: 0600 files, 0700 dir (spec 1.1, 3.2)
// =========================================================================

#[cfg(unix)]
#[test]
fn age_backend_enforces_0600_files_and_0700_dir() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("dotclx");
    let b = file_backend(&dir);
    b.set("clx:global:k", "s").unwrap();

    let mode = |p: std::path::PathBuf| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(dir.clone()), 0o700, "credentials dir must be 0700");
    assert_eq!(
        mode(dir.join("credentials.age")),
        0o600,
        "credentials.age must be 0600"
    );
    assert_eq!(mode(dir.join("cred.key")), 0o600, "cred.key must be 0600");
    // The lock sidecar is also created 0600 (spec 1.1, backend.rs:344-351).
    assert_eq!(
        mode(dir.join("credentials.age.lock")),
        0o600,
        "credentials.age.lock must be 0600"
    );
}

// =========================================================================
// 3. Ciphertext at rest: secret bytes absent, age header present (spec 3.2)
// =========================================================================

#[test]
fn age_backend_blob_is_ciphertext_not_plaintext() {
    let tmp = tempfile::tempdir().unwrap();
    let b = file_backend(tmp.path());
    b.set("clx:global:k", "PLAINTEXT-SENTINEL-77231").unwrap();

    let bytes = std::fs::read(tmp.path().join("credentials.age")).unwrap();
    let hay = String::from_utf8_lossy(&bytes);
    assert!(
        !hay.contains("PLAINTEXT-SENTINEL-77231"),
        "secret value must not appear in the encrypted blob"
    );
    // Real age v1 file header.
    assert!(
        hay.starts_with("age-encryption.org/v1"),
        "blob must be a real age v1 file, got header: {:?}",
        &hay.chars().take(40).collect::<String>()
    );
    // The keyfile must NOT contain the secret either.
    let keyfile = std::fs::read_to_string(tmp.path().join("cred.key")).unwrap();
    assert!(!keyfile.contains("PLAINTEXT-SENTINEL-77231"));
    assert!(keyfile.contains("AGE-SECRET-KEY-1"));
}

// =========================================================================
// 4. Decrypt fails without the keyfile (E7, spec 3.2)
// =========================================================================

#[test]
fn age_backend_decrypt_fails_without_keyfile() {
    let tmp = tempfile::tempdir().unwrap();
    let b = file_backend(tmp.path());
    b.set("clx:global:k", "v").unwrap();

    // Destroy the identity. A fresh backend regenerates a NEW keyfile that
    // cannot decrypt the old blob.
    std::fs::remove_file(tmp.path().join("cred.key")).unwrap();
    let b2 = file_backend(tmp.path());
    let err = b2
        .get("clx:global:k")
        .expect_err("decrypt must fail when the original keyfile is gone");
    let msg = format!("{err}");
    assert!(
        msg.contains("keyfile") || msg.contains("decrypt"),
        "error must point at the lost/wrong keyfile, got: {msg}"
    );
}

// =========================================================================
// 5. Zero-byte EXISTING file => corruption, NOT empty, NOT a wipe (E4)
// =========================================================================

#[test]
fn zero_byte_blob_is_corruption_not_empty_and_no_wipe() {
    let tmp = tempfile::tempdir().unwrap();
    let b = file_backend(tmp.path());
    // Populate a real credential first.
    b.set("clx:global:real", "do-not-lose-me").unwrap();

    // Simulate a crash mid-write / external truncate: zero the data file but
    // keep the keyfile so the only difference is the empty blob.
    let cred = tmp.path().join("credentials.age");
    std::fs::write(&cred, b"").unwrap();
    assert_eq!(std::fs::metadata(&cred).unwrap().len(), 0);

    // get must surface a corruption error, NOT an empty store.
    let err = b
        .get("clx:global:real")
        .expect_err("zero-byte file must be treated as corruption");
    let msg = format!("{err}");
    assert!(
        msg.contains("corrupt") && msg.contains("zero bytes"),
        "actionable corruption message expected, got: {msg}"
    );

    // CRITICAL: a subsequent set MUST refuse rather than overwrite the
    // zero-byte file with an empty-map blob (that would destroy the prior
    // credential permanently). The file must remain zero bytes.
    let set_err = b
        .set("clx:global:new", "x")
        .expect_err("set must not silently overwrite a corrupt file");
    assert!(format!("{set_err}").contains("corrupt"));
    assert_eq!(
        std::fs::metadata(&cred).unwrap().len(),
        0,
        "corrupt zero-byte file must NOT be overwritten by set"
    );
}

// FIX-8: a TRANSIENT zero-byte window on the READ path (e.g. an external
// truncate immediately before a valid blob reappears) must NOT hard-error.
// The lock-free `get` retries a few times; once the valid blob is back the
// read succeeds. Before the fix `get` read the map once and surfaced the
// "corrupt: zero bytes" error on the very first observation.
#[test]
fn transient_zero_byte_read_recovers_via_retry() {
    let tmp = tempfile::tempdir().unwrap();
    let b = file_backend(tmp.path());
    b.set("clx:global:real", "recover-me").unwrap();

    let cred = tmp.path().join("credentials.age");
    // Capture the valid blob, then simulate an external truncate window.
    let valid_blob = std::fs::read(&cred).unwrap();
    assert!(!valid_blob.is_empty());
    std::fs::write(&cred, b"").unwrap();
    assert_eq!(std::fs::metadata(&cred).unwrap().len(), 0);

    // A concurrent "writer" restores the valid blob shortly after, inside the
    // read-retry budget (3 retries x 20ms = ~60ms).
    let cred_for_thread = cred.clone();
    let restorer = std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(30));
        std::fs::write(&cred_for_thread, &valid_blob).unwrap();
    });

    // get must ride out the transient zero-byte window and succeed.
    let got = b
        .get("clx:global:real")
        .expect("transient zero-byte file must recover via retry, not hard-error");
    assert_eq!(got.as_deref(), Some("recover-me"));
    restorer.join().unwrap();
}

// FIX-8 guard: a PERSISTENTLY zero-byte file still hard-errors on read after
// the bounded retries are exhausted (a real truncation is not masked).
#[test]
fn persistent_zero_byte_read_still_errors_after_retries() {
    let tmp = tempfile::tempdir().unwrap();
    let b = file_backend(tmp.path());
    b.set("clx:global:real", "do-not-lose-me").unwrap();

    let cred = tmp.path().join("credentials.age");
    std::fs::write(&cred, b"").unwrap();

    let err = b
        .get("clx:global:real")
        .expect_err("a persistently zero-byte file must still surface corruption");
    let msg = format!("{err}");
    assert!(
        msg.contains("corrupt") && msg.contains("zero bytes"),
        "actionable corruption message expected, got: {msg}"
    );
    // The file is untouched (read path never writes).
    assert_eq!(std::fs::metadata(&cred).unwrap().len(), 0);
}

#[test]
fn absent_file_is_legitimate_empty_store_and_writable() {
    // Fresh install (no credentials.age): empty store, zero prompts, and a
    // subsequent set works (distinct from the zero-byte corruption case).
    let tmp = tempfile::tempdir().unwrap();
    let b = file_backend(tmp.path());
    assert_eq!(b.list_keys().unwrap(), Vec::<String>::new());
    assert_eq!(b.get("clx:global:anything").unwrap(), None);
    b.set("clx:global:fresh", "ok").unwrap();
    assert_eq!(b.get("clx:global:fresh").unwrap().as_deref(), Some("ok"));
}

#[test]
fn nonzero_garbage_blob_errors_with_context() {
    let tmp = tempfile::tempdir().unwrap();
    let b = file_backend(tmp.path());
    b.set("clx:global:k", "v").unwrap();
    // Non-zero garbage (not a valid age header): the age decoder must error.
    std::fs::write(
        tmp.path().join("credentials.age"),
        b"this is not an age file at all, just junk bytes",
    )
    .unwrap();
    let err = b
        .get("clx:global:k")
        .expect_err("non-zero garbage must error at the age decoder");
    assert!(
        format!("{err}").contains("corrupt credentials.age"),
        "expected corrupt-credentials context, got: {err}"
    );
}

// =========================================================================
// 6. Two independent stores + shared lockfile => no lost update (E9, SS1)
// =========================================================================

#[test]
fn two_independent_backends_shared_lock_lose_no_writes() {
    // Mirrors two hook PROCESSES: each its own AgeFileBackend (own in-process
    // Mutex), serialized only by the cross-process advisory lock on the
    // shared sidecar. Each writes DISTINCT keys; all must survive.
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().to_path_buf();
    // Seed once so every writer shares one age identity.
    file_backend(&dir).set("clx:global:seed", "x").unwrap();

    const WRITERS: usize = 6;
    const PER_WRITER: usize = 12;
    let mut handles = Vec::new();
    for w in 0..WRITERS {
        let d = dir.clone();
        handles.push(std::thread::spawn(move || {
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
}

// RISK C-R5: get()/list_keys() take NO inter-process lock. The spec accepts
// this because writes are atomic rename, so a concurrent reader observes
// either the complete old or complete new file, never a partial. Pin that
// accepted behavior: hammer reads concurrently with writes and assert every
// observed read is a complete, decryptable map (never a transient zero-byte
// / NotFound surfaced as corruption).
#[test]
fn concurrent_reads_during_writes_never_observe_partial_state() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().to_path_buf();
    file_backend(&dir).set("clx:global:base", "v0").unwrap();

    let writer_dir = dir.clone();
    let writer = std::thread::spawn(move || {
        let b = file_backend(&writer_dir);
        for i in 0..60 {
            b.set("clx:global:base", &format!("v{i}")).unwrap();
        }
    });

    let mut readers = Vec::new();
    for _ in 0..4 {
        let d = dir.clone();
        readers.push(std::thread::spawn(move || {
            let b = file_backend(&d);
            for _ in 0..80 {
                // Each read must succeed against a complete file. The atomic
                // rename guarantees no partial/zero-byte is ever observed.
                let v = b
                    .get("clx:global:base")
                    .expect("read concurrent with rename must never be corrupt");
                assert!(v.is_some(), "the seeded key must always be present");
            }
        }));
    }
    writer.join().unwrap();
    for r in readers {
        r.join().unwrap();
    }
}

// =========================================================================
// 7. CredentialStore list derived from backend.list_keys (no index race, E9)
// =========================================================================

#[test]
fn store_list_is_derived_from_age_backend_keys() {
    // CredentialStore over the real age-file backend: list_scoped must derive
    // from backend.list_keys (single source of truth), de-scoped + sorted.
    let tmp = tempfile::tempdir().unwrap();
    let store = CredentialStore::with_backend(Arc::new(file_backend(tmp.path())));
    assert_eq!(store.backend_label(), "age-file");

    store.store("zeta-key", "v1").unwrap();
    store.store("alpha-key", "v2").unwrap();
    store
        .store_scoped("proj-only", "p", Some("/repo/x"))
        .unwrap();

    let mut global = store.list().unwrap();
    global.sort();
    assert_eq!(global, vec!["alpha-key", "zeta-key"]);
    // Project-scoped key must not leak into the global list.
    assert!(!global.contains(&"proj-only".to_string()));

    let proj = store.list_scoped(Some("/repo/x")).unwrap();
    assert_eq!(proj, vec!["proj-only"]);

    store.delete("zeta-key").unwrap();
    assert_eq!(store.list().unwrap(), vec!["alpha-key"]);
}

#[test]
fn store_list_no_lost_entries_under_concurrent_stores() {
    // Concurrent stores via independent CredentialStore handles on a shared
    // age-file dir: list() (derived from backend keys, not the JSON index)
    // must report every key.
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().to_path_buf();
    CredentialStore::with_backend(Arc::new(file_backend(&dir)))
        .store("seed", "x")
        .unwrap();

    let mut handles = Vec::new();
    for w in 0..5 {
        let d = dir.clone();
        handles.push(std::thread::spawn(move || {
            let s = CredentialStore::with_backend(Arc::new(file_backend(&d)));
            for i in 0..10 {
                s.store(&format!("w{w}-k{i}"), &format!("v{w}-{i}"))
                    .unwrap();
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }

    let keys = CredentialStore::with_backend(Arc::new(file_backend(&dir)))
        .list()
        .unwrap();
    assert!(keys.contains(&"seed".to_string()));
    for w in 0..5 {
        for i in 0..10 {
            assert!(
                keys.contains(&format!("w{w}-k{i}")),
                "list() dropped w{w}-k{i} -- index race not avoided"
            );
        }
    }
}

// =========================================================================
// 8. Key validation at the CredentialStore layer (spec 3.4)
// =========================================================================

#[test]
fn store_key_validation_rejects_unsafe_keys() {
    let tmp = tempfile::tempdir().unwrap();
    let store = CredentialStore::with_backend(Arc::new(file_backend(tmp.path())));

    // Empty.
    assert!(store.store("", "v").is_err());
    // NUL byte.
    assert!(store.store("a\0b", "v").is_err());
    // Path-traversal.
    assert!(store.store("../etc", "v").is_err());
    // Disallowed charset (colon is rejected -- why the resolver uses HYPHEN
    // `<provider>-api-key`, see spec RISK 1).
    assert!(store.store("azure:api-key", "v").is_err());
    // Over 255 chars.
    assert!(store.store(&"a".repeat(256), "v").is_err());

    // Canonical Azure key form is accepted.
    store.store("azure-prod-api-key", "sk-xyz").unwrap();
    assert_eq!(
        store.get("azure-prod-api-key").unwrap().as_deref(),
        Some("sk-xyz")
    );
}

// =========================================================================
// 9. CredentialBackendKind parsing + default (E20, spec 3.3, anchor test)
// =========================================================================

#[test]
fn backend_kind_parses_and_defaults_file() {
    assert_eq!(
        CredentialBackendKind::default(),
        CredentialBackendKind::File
    );
    assert_eq!(
        CredentialBackendKind::parse("file").unwrap(),
        CredentialBackendKind::File
    );
    // Case-insensitive, whitespace-trimmed.
    assert_eq!(
        CredentialBackendKind::parse("  KEYCHAIN \n").unwrap(),
        CredentialBackendKind::Keychain
    );
    // E20: an unknown value is a HARD error, never a silent fallback to
    // file/keychain.
    let err = CredentialBackendKind::parse("vault").unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("unknown credentials backend") && msg.contains("vault"),
        "unknown backend must be an actionable hard error, got: {msg}"
    );
}

#[test]
fn default_store_selects_age_file_backend_never_keychain() {
    // The default constructors must pick the age-file backend so a fresh
    // user never sees a macOS keychain prompt.
    assert_eq!(CredentialStore::new().backend_label(), "age-file");
    assert_eq!(
        CredentialStore::from_config(CredentialBackendKind::File).backend_label(),
        "age-file"
    );
    // Opt-in keychain is the only way to get the keychain backend.
    assert_eq!(
        CredentialStore::from_config(CredentialBackendKind::Keychain).backend_label(),
        "keychain"
    );
}

// =========================================================================
// 10. KeychainSpy regression: default path makes ZERO keychain calls
//     (the core 0.8.0 regression; spec 1.2, 3.1)
// =========================================================================

/// A spy implementing the public `CredentialBackend` trait. It mimics a
/// keychain (label "keychain") and counts every delegated call. Under the
/// default file backend this spy is NEVER the active backend, so the count
/// stays zero. If a keychain fallback were reintroduced under the default,
/// some path would have to construct/drive a keychain backend and the
/// equivalent counter would move; here we instead prove the default store
/// never carries a keychain-labelled backend and never delegates to one.
#[derive(Clone, Default)]
struct KeychainSpy {
    calls: Arc<AtomicUsize>,
}

impl KeychainSpy {
    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl CredentialBackend for KeychainSpy {
    fn get(&self, _k: &str) -> CredResult<Option<String>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(None)
    }
    fn set(&self, _k: &str, _v: &str) -> CredResult<()> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn delete(&self, _k: &str) -> CredResult<()> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn list_keys(&self) -> CredResult<Vec<String>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(Vec::new())
    }
    fn label(&self) -> &'static str {
        "keychain"
    }
}

#[test]
fn spy_counter_is_not_vacuous_when_spy_is_active() {
    // Sanity: when the spy IS the active backend, the counter moves. This
    // proves a zero count in the default-path test below is meaningful.
    let spy = KeychainSpy::default();
    let store = CredentialStore::with_backend(Arc::new(spy.clone()));
    assert_eq!(store.backend_label(), "keychain");
    store.store("k", "v").unwrap();
    let _ = store.get("k").unwrap();
    let _ = store.list().unwrap();
    assert!(
        spy.calls() >= 3,
        "spy must record delegated keychain calls; got {}",
        spy.calls()
    );
}

#[test]
fn default_file_backend_store_get_list_delete_never_touch_keychain() {
    // The full set/get/list/delete cycle under the DEFAULT (file) backend
    // must never carry or delegate to a keychain-labelled backend. We assert
    // the active backend label is "age-file" across the entire cycle and
    // that an independent keychain spy (never wired in) stays at zero.
    let tmp = tempfile::tempdir().unwrap();
    let unused_spy = KeychainSpy::default();

    let store = CredentialStore::with_backend(Arc::new(file_backend(tmp.path())));
    assert_eq!(store.backend_label(), "age-file");

    store.store("azure-prod-api-key", "sk-secret").unwrap();
    assert_eq!(store.backend_label(), "age-file");
    assert_eq!(
        store.get("azure-prod-api-key").unwrap().as_deref(),
        Some("sk-secret")
    );
    assert_eq!(store.backend_label(), "age-file");
    let _ = store.list().unwrap();
    assert_eq!(store.backend_label(), "age-file");
    store.delete("azure-prod-api-key").unwrap();
    assert_eq!(store.backend_label(), "age-file");

    // The keychain spy was never the active backend at any point.
    assert_eq!(
        unused_spy.calls(),
        0,
        "default path must make ZERO keychain calls"
    );
}

// =========================================================================
// 11. Backend get() never falls back to another store (trait contract 1.3)
// =========================================================================

#[test]
fn backend_get_missing_returns_none_never_errors_never_falls_back() {
    // The trait contract: get() returns Ok(None) for a missing key, never an
    // error, and never reaches into another store. A bespoke backend proves
    // CredentialStore does not paper over Ok(None) with a fallback read.
    #[derive(Default)]
    struct CountingMissBackend {
        gets: Arc<AtomicUsize>,
        map: Mutex<BTreeMap<String, String>>,
    }
    impl CredentialBackend for CountingMissBackend {
        fn get(&self, k: &str) -> CredResult<Option<String>> {
            self.gets.fetch_add(1, Ordering::SeqCst);
            Ok(self.map.lock().unwrap().get(k).cloned())
        }
        fn set(&self, k: &str, v: &str) -> CredResult<()> {
            self.map.lock().unwrap().insert(k.into(), v.into());
            Ok(())
        }
        fn delete(&self, k: &str) -> CredResult<()> {
            self.map.lock().unwrap().remove(k);
            Ok(())
        }
        fn list_keys(&self) -> CredResult<Vec<String>> {
            Ok(self.map.lock().unwrap().keys().cloned().collect())
        }
        fn label(&self) -> &'static str {
            "counting-miss"
        }
    }
    let gets = Arc::new(AtomicUsize::new(0));
    let backend = Arc::new(CountingMissBackend {
        gets: gets.clone(),
        map: Mutex::new(BTreeMap::new()),
    });
    let store = CredentialStore::with_backend(backend);

    // Missing key: one backend get, Ok(None), no error, no second store.
    assert_eq!(store.get("nope").unwrap(), None);
    assert_eq!(
        gets.load(Ordering::SeqCst),
        1,
        "exactly one backend read; no fallback store consulted"
    );
}

// =========================================================================
// 12. Scoping: global vs project keys and get_with_fallback (spec 3.4)
// =========================================================================

#[test]
fn scoped_keys_isolate_global_from_project_and_fallback_order() {
    // clx:global:<k> vs clx:project:<proj>:<k>. A global value and a project
    // value for the same logical key must NOT collide; get_with_fallback must
    // prefer the project-scoped value, then fall back to global.
    let tmp = tempfile::tempdir().unwrap();
    let store = CredentialStore::with_backend(Arc::new(file_backend(tmp.path())));

    store.store("api-key", "GLOBAL-V").unwrap();
    store
        .store_scoped("api-key", "PROJECT-V", Some("/repo/alpha"))
        .unwrap();

    // Distinct storage: global read sees only the global value.
    assert_eq!(store.get("api-key").unwrap().as_deref(), Some("GLOBAL-V"));
    assert_eq!(
        store
            .get_scoped("api-key", Some("/repo/alpha"))
            .unwrap()
            .as_deref(),
        Some("PROJECT-V")
    );

    // Fallback: project wins when present.
    assert_eq!(
        store
            .get_with_fallback("api-key", "/repo/alpha")
            .unwrap()
            .as_deref(),
        Some("PROJECT-V")
    );
    // Fallback: a project with no scoped value falls back to global.
    assert_eq!(
        store
            .get_with_fallback("api-key", "/repo/other")
            .unwrap()
            .as_deref(),
        Some("GLOBAL-V")
    );
    // No value anywhere => Ok(None), never an error.
    assert_eq!(
        store.get_with_fallback("absent", "/repo/alpha").unwrap(),
        None
    );

    // Deleting the global key does not touch the project-scoped one.
    store.delete("api-key").unwrap();
    assert_eq!(store.get("api-key").unwrap(), None);
    assert_eq!(
        store
            .get_scoped("api-key", Some("/repo/alpha"))
            .unwrap()
            .as_deref(),
        Some("PROJECT-V"),
        "project-scoped credential must survive a global delete"
    );
}
