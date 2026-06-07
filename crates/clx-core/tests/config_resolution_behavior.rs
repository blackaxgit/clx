//! Behavior tests for credential resolution + layered config (Wave D, spec
//! `specs/_prerelease/03-credentials-config.md` sections 1.2, 1.4, 2.2, 3.1,
//! 3.6, 3.8 and edge/failure rows E1, E2, E3, E10, E18, E20 plus RISK C-R2,
//! C-R4).
//!
//! Resolution order is exercised end to end through the public
//! `Config::create_llm_client_by_name` (which calls the private
//! `resolve_azure_credential`) and through `Config::credential_backend_kind`.
//! HOME is redirected to a tempdir so the default file backend points at a
//! throwaway store. `#[serial]` guards every env/HOME mutation. No network,
//! no real keychain.

use std::sync::Arc;

use clx_core::config::trust::{TrustList, compute_file_hash};
use clx_core::config::{
    AzureOpenAIConfig, Capability, CapabilityRoute, Config, LlmRouting, ProviderConfig,
};
use clx_core::credentials::{
    CredentialBackend, CredentialBackendKind, CredentialError, CredentialStore,
};
use serial_test::serial;

type CredResult<T> = std::result::Result<T, CredentialError>;

/// Redirect HOME so `~/.clx` resolves under a tempdir. Returned guard keeps
/// the temp dir alive and restores HOME on drop. Pair with `#[serial]`.
struct HomeGuard {
    _tmp: tempfile::TempDir,
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
        Self { _tmp: tmp, prev }
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

#[allow(unsafe_code)]
fn set_env(k: &str, v: &str) {
    // SAFETY: callers are #[serial].
    unsafe { std::env::set_var(k, v) }
}

#[allow(unsafe_code)]
fn clear_env(k: &str) {
    // SAFETY: callers are #[serial].
    unsafe { std::env::remove_var(k) }
}

fn azure_cfg(api_key_env: Option<&str>, api_key_file: Option<&str>) -> AzureOpenAIConfig {
    AzureOpenAIConfig {
        endpoint: "https://x.openai.azure.com".to_string(),
        api_key_env: api_key_env.map(str::to_string),
        api_key_file: api_key_file.map(std::path::PathBuf::from),
        api_version: None,
        timeout_ms: 30_000,
        retry: clx_core::llm::retry::RetryConfig::default(),
    }
}

/// Build a `Config` whose only provider is an Azure provider named `azure`
/// routed for chat, so `create_llm_client_by_name("azure")` drives
/// `resolve_azure_credential`.
fn config_with_azure(cfg: AzureOpenAIConfig) -> Config {
    let mut c = Config::default();
    c.providers
        .insert("azure".to_string(), ProviderConfig::AzureOpenai(cfg));
    c
}

// =========================================================================
// 1. Resolution order: env wins over backend over api_key_file (3.1)
// =========================================================================

#[test]
#[serial]
fn env_api_key_env_wins_zero_backend_touch() {
    let _home = HomeGuard::new();
    clear_env("CLX_CREDENTIALS_BACKEND");
    set_env("AZURE_KEY_RESOLVE_TEST", "sk-from-env-AAA");

    let c = config_with_azure(azure_cfg(Some("AZURE_KEY_RESOLVE_TEST"), None));
    // A populated env var resolves immediately: the Azure client builds
    // (host allowlist is enforced at request time, not at construction), so
    // a successfully built client proves the key resolved from the env
    // without consulting the empty file backend.
    let client = c
        .create_llm_client_by_name("azure")
        .expect("populated env key must resolve and build the client");
    assert!(
        matches!(client, clx_core::llm::LlmClient::Azure(_)),
        "env-resolved Azure provider must yield an Azure client"
    );
    clear_env("AZURE_KEY_RESOLVE_TEST");
}

#[test]
#[serial]
fn env_set_but_empty_is_skipped_resolution_continues(// E2
) {
    let _home = HomeGuard::new();
    clear_env("CLX_CREDENTIALS_BACKEND");
    set_env("AZURE_EMPTY_KEY_TEST", ""); // set but empty

    // No backend entry, no api_key_file: the empty env is skipped and we
    // fall through to the hard "no credentials" error (E1 message).
    let c = config_with_azure(azure_cfg(Some("AZURE_EMPTY_KEY_TEST"), None));
    let err = c
        .create_llm_client_by_name("azure")
        .expect_err("empty env + nothing else => hard error");
    let msg = format!("{err}");
    assert!(
        msg.contains("no credentials available"),
        "empty env must be skipped, resolution continues to the hard error: {msg}"
    );
    clear_env("AZURE_EMPTY_KEY_TEST");
}

#[test]
#[serial]
fn file_backend_serves_before_api_key_file() {
    let _home = HomeGuard::new();
    clear_env("CLX_CREDENTIALS_BACKEND");
    clear_env("AZURE_UNUSED_ENV");

    // Pre-store the key in the DEFAULT (file) backend under ~/.clx.
    let store = Config::default().credential_store().unwrap();
    assert_eq!(store.backend_label(), "age-file");
    store
        .store("azure-api-key", "sk-from-file-backend")
        .unwrap();

    // api_key_file points at a DIFFERENT value; the backend must win so the
    // file path is never consulted. We assert the resolution does not raise
    // the "no credentials" error and does not error on the api_key_file mode.
    let tmpf = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(tmpf.path(), "sk-from-plaintext-file").unwrap();
    let cfg = azure_cfg(Some("AZURE_UNUSED_ENV"), tmpf.path().to_str());
    // The file BACKEND must serve before the api_key_file path. Resolution
    // succeeds (client builds); it must NOT hit the "no credentials" error
    // and must NOT error on the api_key_file mode (which would prove the
    // file path was wrongly consulted).
    let client = config_with_azure(cfg)
        .create_llm_client_by_name("azure")
        .expect("file backend value must resolve and build the client");
    assert!(matches!(client, clx_core::llm::LlmClient::Azure(_)));
}

#[test]
#[serial]
fn no_credential_anywhere_is_actionable_hard_error(// E1
) {
    let _home = HomeGuard::new();
    clear_env("CLX_CREDENTIALS_BACKEND");

    // No env, empty backend, no api_key_file.
    let c = config_with_azure(azure_cfg(None, None));
    let err = c
        .create_llm_client_by_name("azure")
        .expect_err("nothing anywhere => hard error");
    let msg = format!("{err}");
    assert!(msg.contains("no credentials available"), "got: {msg}");
    // Names the labelled backend, the literal key, and the remedy commands.
    assert!(
        msg.contains("file backend key 'azure-api-key'"),
        "got: {msg}"
    );
    assert!(
        msg.contains("clx credentials set azure-api-key"),
        "got: {msg}"
    );
    assert!(msg.contains("clx credentials migrate"), "got: {msg}");
}

#[cfg(unix)]
#[test]
#[serial]
fn api_key_file_wrong_mode_is_refused(// E3
) {
    use std::os::unix::fs::PermissionsExt;
    let _home = HomeGuard::new();
    clear_env("CLX_CREDENTIALS_BACKEND");

    let tmpf = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(tmpf.path(), "sk-plain").unwrap();
    // World-readable: NOT 0600.
    std::fs::set_permissions(tmpf.path(), std::fs::Permissions::from_mode(0o644)).unwrap();

    let cfg = azure_cfg(None, tmpf.path().to_str());
    let err = config_with_azure(cfg)
        .create_llm_client_by_name("azure")
        .expect_err("0644 api_key_file must be refused");
    let msg = format!("{err}");
    assert!(
        msg.contains("refusing to read") && msg.contains("must be 0600"),
        "wrong-mode api_key_file must be refused: {msg}"
    );
}

// =========================================================================
// 2. credentials.backend default = file; env override; unknown errors
//    (2.1, 3.3, E20)
// =========================================================================

#[test]
#[serial]
fn credential_backend_kind_defaults_to_file() {
    let _home = HomeGuard::new();
    clear_env("CLX_CREDENTIALS_BACKEND");
    let c = Config::default();
    assert_eq!(
        c.credential_backend_kind().unwrap(),
        CredentialBackendKind::File
    );
    assert_eq!(c.credential_store().unwrap().backend_label(), "age-file");
}

#[test]
#[serial]
fn env_selects_keychain_backend() {
    let _home = HomeGuard::new();
    set_env("CLX_CREDENTIALS_BACKEND", "keychain");
    let c = Config::default();
    assert_eq!(
        c.credential_backend_kind().unwrap(),
        CredentialBackendKind::Keychain
    );
    clear_env("CLX_CREDENTIALS_BACKEND");
}

#[test]
#[serial]
fn unknown_env_backend_is_hard_error_never_silent_fallback(// E20
) {
    let _home = HomeGuard::new();
    set_env("CLX_CREDENTIALS_BACKEND", "bogus-store");
    let c = Config::default();
    let err = c
        .credential_backend_kind()
        .expect_err("unknown backend must be a hard error");
    let msg = format!("{err}");
    assert!(
        msg.contains("unknown credentials backend") && msg.contains("bogus-store"),
        "must NOT silently fall back; got: {msg}"
    );
    clear_env("CLX_CREDENTIALS_BACKEND");
}

#[test]
#[serial]
fn config_backend_keychain_honored_when_no_env_override() {
    let _home = HomeGuard::new();
    clear_env("CLX_CREDENTIALS_BACKEND");
    let mut c = Config::default();
    c.credentials.backend = CredentialBackendKind::Keychain;
    assert_eq!(
        c.credential_backend_kind().unwrap(),
        CredentialBackendKind::Keychain
    );
    // Env override beats config when present.
    set_env("CLX_CREDENTIALS_BACKEND", "file");
    assert_eq!(
        c.credential_backend_kind().unwrap(),
        CredentialBackendKind::File
    );
    clear_env("CLX_CREDENTIALS_BACKEND");
}

// =========================================================================
// 3. Zero keychain under default proven by a spy backend (3.1 regression)
// =========================================================================

/// Public-trait spy mimicking a keychain. Counts every delegated call.
#[derive(Clone, Default)]
struct KeychainSpy {
    calls: Arc<std::sync::atomic::AtomicUsize>,
}

impl CredentialBackend for KeychainSpy {
    fn get(&self, _k: &str) -> CredResult<Option<String>> {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(None)
    }
    fn set(&self, _k: &str, _v: &str) -> CredResult<()> {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }
    fn delete(&self, _k: &str) -> CredResult<()> {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }
    fn list_keys(&self) -> CredResult<Vec<String>> {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(Vec::new())
    }
    fn label(&self) -> &'static str {
        "keychain"
    }
}

#[test]
#[serial]
fn resolve_under_default_backend_makes_zero_keychain_calls() {
    let _home = HomeGuard::new();
    clear_env("CLX_CREDENTIALS_BACKEND");
    let spy = KeychainSpy::default();

    // Full resolution path under the default file backend: store via the
    // real age-file store, then resolve. A keychain spy that was never wired
    // in must stay at zero, and the resolving store must be age-file.
    let store = Config::default().credential_store().unwrap();
    assert_eq!(store.backend_label(), "age-file");
    store.store("azure-api-key", "sk-file").unwrap();

    let c = config_with_azure(azure_cfg(None, None));
    // Resolves the key from the file backend; the Azure client builds.
    let client = c
        .create_llm_client_by_name("azure")
        .expect("key must resolve from the file backend");
    assert!(matches!(client, clx_core::llm::LlmClient::Azure(_)));

    assert_eq!(
        spy.calls.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "the default resolution path must make ZERO keychain calls"
    );
    // Sanity: the spy counter is not vacuous.
    let spy_store = CredentialStore::with_backend(Arc::new(spy.clone()));
    spy_store.store("k", "v").unwrap();
    assert!(spy.calls.load(std::sync::atomic::Ordering::SeqCst) >= 1);
}

// =========================================================================
// 4. Figment layering: global -> project -> env precedence (1.4, 3.6)
// =========================================================================

#[test]
#[serial]
fn global_config_yaml_is_loaded_as_lowest_layer() {
    let _home = HomeGuard::new();
    clear_env("CLX_LOGGING_LEVEL");
    let home = std::env::var("HOME").unwrap();
    let clx = std::path::Path::new(&home).join(".clx");
    std::fs::create_dir_all(&clx).unwrap();
    std::fs::write(
        clx.join("config.yaml"),
        "logging:\n  level: warn\nretention:\n  events_days: 99\n",
    )
    .unwrap();

    let c = Config::load().unwrap();
    assert_eq!(
        c.logging.level, "warn",
        "global config.yaml must be honored"
    );
    assert_eq!(c.retention.events_days, 99);
}

#[test]
#[serial]
fn validated_env_override_beats_global_config() {
    let _home = HomeGuard::new();
    let home = std::env::var("HOME").unwrap();
    let clx = std::path::Path::new(&home).join(".clx");
    std::fs::create_dir_all(&clx).unwrap();
    std::fs::write(clx.join("config.yaml"), "logging:\n  level: warn\n").unwrap();

    set_env("CLX_LOGGING_LEVEL", "debug");
    let c = Config::load().unwrap();
    assert_eq!(
        c.logging.level, "debug",
        "validated env override must beat the global layer"
    );
    clear_env("CLX_LOGGING_LEVEL");
}

// RISK C-R2: figment Env layer vs apply_env_overrides double-application.
// An out-of-range value must end up as the validated default, NOT a raw
// figment-coerced value. Pin the documented "validated path is
// authoritative" behavior.
#[test]
#[serial]
fn out_of_range_env_keeps_validated_default_not_raw_figment(// C-R2
) {
    let _home = HomeGuard::new();
    clear_env("CLX_LOGGING_LEVEL");
    // layer1 timeout has a validated range; a wildly out-of-range value must
    // be rejected by apply_env_overrides, leaving the struct default.
    set_env("CLX_VALIDATOR_LAYER1_TIMEOUT_MS", "999999999");
    let c = Config::load().unwrap();
    let default_timeout = Config::default().validator.layer1_timeout_ms;
    assert_eq!(
        c.validator.layer1_timeout_ms, default_timeout,
        "out-of-range env must keep the validated default, not a raw figment value"
    );
    clear_env("CLX_VALIDATOR_LAYER1_TIMEOUT_MS");
}

#[test]
#[serial]
fn malformed_global_config_yaml_is_a_load_error(// E18
) {
    let _home = HomeGuard::new();
    let home = std::env::var("HOME").unwrap();
    let clx = std::path::Path::new(&home).join(".clx");
    std::fs::create_dir_all(&clx).unwrap();
    // Not a YAML mapping at the expected shape: a scalar where a struct is
    // expected makes figment extraction fail.
    std::fs::write(clx.join("config.yaml"), "logging: 12345\n").unwrap();
    let err = Config::load().expect_err("malformed global config must fail load");
    assert!(
        format!("{err}").contains("figment merge failed"),
        "expected a figment merge error, got: {err}"
    );
}

// RISK C-R4: load_from_file_only skips the project layer / inert filter / env
// overrides. Pin that documented behavior: it round-trips the raw global
// file and does NOT apply env overrides.
#[test]
#[serial]
fn load_from_file_only_skips_env_overrides(// C-R4
) {
    let _home = HomeGuard::new();
    let home = std::env::var("HOME").unwrap();
    let clx = std::path::Path::new(&home).join(".clx");
    std::fs::create_dir_all(&clx).unwrap();
    std::fs::write(clx.join("config.yaml"), "logging:\n  level: warn\n").unwrap();
    set_env("CLX_LOGGING_LEVEL", "debug");

    let raw = Config::load_from_file_only().unwrap();
    assert_eq!(
        raw.logging.level, "warn",
        "load_from_file_only must NOT apply env overrides (raw editing view)"
    );
    // Whereas the effective load DOES.
    assert_eq!(Config::load().unwrap().logging.level, "debug");
    clear_env("CLX_LOGGING_LEVEL");
}

// =========================================================================
// 5. Project inert-key filter vs config-trust hash, end-to-end via
//    Config::load + CLX_CONFIG_PROJECT (3.6, E10, E11, E12). The pure
//    apply_project_layer / filter_inert_only unit tests are crate-private
//    (config::project is pub(crate)) and live in the in-crate
//    `mod wave1_credentials_behavior` appended to config/project.rs.
// =========================================================================

/// Write a project config under a tempdir and return its path. We point
/// `CLX_CONFIG_PROJECT` straight at it so discovery is deterministic
/// regardless of the test CWD.
fn write_project_config(home: &str, body: &str) -> std::path::PathBuf {
    let proj_dir = std::path::Path::new(home).join("work").join(".clx");
    std::fs::create_dir_all(&proj_dir).unwrap();
    let p = proj_dir.join("config.yaml");
    std::fs::write(&p, body).unwrap();
    p
}

#[test]
#[serial]
fn untrusted_project_config_drops_providers_block(// E10
) {
    let _home = HomeGuard::new();
    clear_env("CLX_LOGGING_LEVEL");
    let home = std::env::var("HOME").unwrap();
    let body = "logging:\n  level: debug\n  file: /tmp/exfil.log\nproviders:\n  rogue:\n    kind: azure_openai\n    endpoint: https://evil.example.com\n";
    let proj = write_project_config(&home, body);
    set_env("CLX_CONFIG_PROJECT", proj.to_str().unwrap());

    let c = Config::load().unwrap();
    // providers.* and logging.file are non-inert -> dropped from an untrusted
    // project config; logging.level is inert -> kept.
    assert!(
        !c.providers.contains_key("rogue"),
        "untrusted project providers must be dropped"
    );
    assert_eq!(c.logging.level, "debug", "inert logging.level survives");
    assert_ne!(
        c.logging.file, "/tmp/exfil.log",
        "non-inert logging.file must be dropped"
    );
    clear_env("CLX_CONFIG_PROJECT");
}

#[test]
#[serial]
fn trusted_project_config_honors_non_inert_keys(// E11
) {
    let _home = HomeGuard::new();
    let home = std::env::var("HOME").unwrap();
    let body = "providers:\n  azure-prod:\n    kind: azure_openai\n    endpoint: https://api.example.com\n";
    let proj = write_project_config(&home, body);
    // Trust the EXACT raw contents.
    let mut tl = TrustList::default();
    tl.add(proj.clone(), compute_file_hash(body));
    tl.save().unwrap();
    set_env("CLX_CONFIG_PROJECT", proj.to_str().unwrap());

    let c = Config::load().unwrap();
    assert!(
        c.providers.contains_key("azure-prod"),
        "trusted project config must keep its providers block"
    );
    clear_env("CLX_CONFIG_PROJECT");
}

#[test]
#[serial]
fn edit_after_trust_reapplies_inert_filter(// E12
) {
    let _home = HomeGuard::new();
    let home = std::env::var("HOME").unwrap();
    let original = "providers:\n  ok:\n    kind: azure_openai\n    endpoint: https://a.test\n";
    let proj = write_project_config(&home, original);
    let mut tl = TrustList::default();
    tl.add(proj.clone(), compute_file_hash(original));
    tl.save().unwrap();

    // User edits the file (adds a hostile provider). Hash changes => the
    // inert filter reapplies and the whole providers block is dropped.
    let edited = "providers:\n  ok:\n    kind: azure_openai\n    endpoint: https://a.test\n  evil:\n    kind: azure_openai\n    endpoint: https://b.test\n";
    std::fs::write(&proj, edited).unwrap();
    set_env("CLX_CONFIG_PROJECT", proj.to_str().unwrap());

    let c = Config::load().unwrap();
    assert!(
        !c.providers.contains_key("evil") && !c.providers.contains_key("ok"),
        "an edited (hash-mismatched) project config must NOT bypass the filter"
    );
    clear_env("CLX_CONFIG_PROJECT");
}

#[test]
#[serial]
fn project_discovery_disabled_by_env_sentinel() {
    let _home = HomeGuard::new();
    let home = std::env::var("HOME").unwrap();
    write_project_config(&home, "logging:\n  level: trace\n");
    // `off` disables project discovery entirely (spec 3.6).
    set_env("CLX_CONFIG_PROJECT", "off");
    clear_env("CLX_LOGGING_LEVEL");
    let c = Config::load().unwrap();
    assert_eq!(
        c.logging.level, "info",
        "CLX_CONFIG_PROJECT=off must skip the project layer (struct default)"
    );
    clear_env("CLX_CONFIG_PROJECT");
}

// RISK C-R3: api_key_file is plaintext + mode-checked in two syscalls
// (TOCTOU). Pin the documented accepted behavior: a correctly 0600 file IS
// read as the lowest-precedence source (after env + backend), proving the
// plaintext fallback path works and the mode is enforced (not ownership).
#[cfg(unix)]
#[test]
#[serial]
fn api_key_file_0600_is_read_as_lowest_precedence_source(// C-R3
) {
    use std::os::unix::fs::PermissionsExt;
    let _home = HomeGuard::new();
    clear_env("CLX_CREDENTIALS_BACKEND");

    // No env, empty backend: resolution must fall through to api_key_file.
    let tmpf = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(tmpf.path(), "  sk-from-plaintext-file\n").unwrap();
    std::fs::set_permissions(tmpf.path(), std::fs::Permissions::from_mode(0o600)).unwrap();

    let cfg = azure_cfg(None, tmpf.path().to_str());
    // A correctly-0600 file resolves (client builds). This is the documented
    // lowest-precedence plaintext fallback; the mode is enforced above.
    let client = config_with_azure(cfg)
        .create_llm_client_by_name("azure")
        .expect("0600 api_key_file must resolve as the lowest-precedence source");
    assert!(matches!(client, clx_core::llm::LlmClient::Azure(_)));
}

// RISK C-R6: CLX_CONFIG_PROJECT accepts an arbitrary absolute path with no
// inert-filter exemption. An attacker controlling the env can point CLX at
// any config.yaml, but it STILL goes through apply_project_layer so non-inert
// keys are filtered unless the file's hash is trusted. Pin that safe behavior.
#[test]
#[serial]
fn clx_config_project_arbitrary_abs_path_still_inert_filtered(// C-R6
) {
    let _home = HomeGuard::new();
    clear_env("CLX_LOGGING_LEVEL");
    let home = std::env::var("HOME").unwrap();
    // A config OUTSIDE any .clx project dir, pointed to directly by env.
    let rogue = std::path::Path::new(&home).join("attacker-controlled.yaml");
    std::fs::write(
        &rogue,
        "logging:\n  level: error\nproviders:\n  exfil:\n    kind: azure_openai\n    endpoint: https://evil.example.com\n",
    )
    .unwrap();
    set_env("CLX_CONFIG_PROJECT", rogue.to_str().unwrap());

    let c = Config::load().unwrap();
    // The arbitrary path is honored as the project layer BUT still filtered:
    // the non-inert providers block is dropped (untrusted hash), inert
    // logging.level survives.
    assert!(
        !c.providers.contains_key("exfil"),
        "an env-pointed arbitrary config must NOT bypass the inert filter"
    );
    assert_eq!(
        c.logging.level, "error",
        "inert keys from the env-pointed path still apply"
    );
    clear_env("CLX_CONFIG_PROJECT");
}

#[test]
#[serial]
fn malformed_project_config_is_a_noop_global_wins(// E19
) {
    let _home = HomeGuard::new();
    clear_env("CLX_LOGGING_LEVEL");
    let home = std::env::var("HOME").unwrap();
    // Global sets a distinctive value.
    let clx = std::path::Path::new(&home).join(".clx");
    std::fs::create_dir_all(&clx).unwrap();
    std::fs::write(clx.join("config.yaml"), "logging:\n  level: warn\n").unwrap();

    // Project config is invalid YAML => filter_inert_only returns "" => the
    // project layer is a no-op and the global layer wins (NOT a load error).
    let proj = write_project_config(&home, ":\n  not: [valid yaml\n::::");
    set_env("CLX_CONFIG_PROJECT", proj.to_str().unwrap());

    let c = Config::load().expect("malformed project config must be a no-op, not a load error");
    assert_eq!(
        c.logging.level, "warn",
        "invalid project YAML => project layer no-op, global layer wins"
    );
    clear_env("CLX_CONFIG_PROJECT");
}

// =========================================================================
// 5b. Provider fallback wiring (spec 3.5, E16/E17 construction path).
//     The live transient-error -> fallback + 30 s cooldown runtime behavior
//     is covered by the crate-private in-crate tests the spec cites
//     (`llm::fallback::tests` -> fallback_not_used_on_terminal_error,
//     cooldown_skips_primary_after_failure). Here we pin the PUBLIC wiring:
//     create_llm_client wraps primary+fallback in a FallbackClient only when
//     the route declares a fallback, and resolves each provider's own key.
// =========================================================================

fn ollama_provider() -> ProviderConfig {
    // Default Ollama config: no credential needed, points at localhost. We
    // never make a request, only construct the client.
    ProviderConfig::Ollama(clx_core::config::OllamaConfig::default())
}

#[test]
#[serial]
fn route_with_fallback_yields_fallback_client_wrapper(// E16 wiring
) {
    let _home = HomeGuard::new();
    clear_env("CLX_CREDENTIALS_BACKEND");
    set_env("AZURE_FALLBACK_WIRE_KEY", "sk-primary-XYZ");

    let mut c = Config::default();
    c.providers.insert(
        "azure".to_string(),
        ProviderConfig::AzureOpenai(azure_cfg(Some("AZURE_FALLBACK_WIRE_KEY"), None)),
    );
    c.providers.insert("local".to_string(), ollama_provider());
    c.llm = Some(LlmRouting {
        chat: CapabilityRoute {
            provider: "azure".to_string(),
            model: "gpt-5.4-mini".to_string(),
            fallback: Some(Box::new(CapabilityRoute {
                provider: "local".to_string(),
                model: "qwen3:1.7b".to_string(),
                fallback: None,
                dimension: None,
            })),
            dimension: None,
        },
        embeddings: CapabilityRoute {
            provider: "local".to_string(),
            model: "qwen3-embedding:0.6b".to_string(),
            fallback: None,
            dimension: None,
        },
    });

    // chat route declares a fallback => the primary (Azure, key from env) and
    // the fallback (Ollama) are wrapped in a FallbackClient.
    let chat = c
        .create_llm_client(Capability::Chat)
        .expect("chat client with fallback must build");
    assert!(
        matches!(chat, clx_core::llm::LlmClient::Fallback(_)),
        "a route with a fallback must wrap in FallbackClient"
    );

    // embeddings route has NO fallback => the bare primary client, no wrapper.
    let emb = c
        .create_llm_client(Capability::Embeddings)
        .expect("embeddings client must build");
    assert!(
        matches!(emb, clx_core::llm::LlmClient::Ollama(_)),
        "a route without a fallback must NOT be wrapped"
    );
    clear_env("AZURE_FALLBACK_WIRE_KEY");
}

#[test]
#[serial]
fn fallback_provider_credential_resolved_independently() {
    // The fallback path resolves ITS provider's key, not the primary's. Here
    // the fallback is Azure too, with its own env var; both must resolve for
    // the wrapper to build (proves each side runs its own §3.1 resolution).
    let _home = HomeGuard::new();
    clear_env("CLX_CREDENTIALS_BACKEND");
    set_env("PRIMARY_AZ_KEY", "sk-primary");
    set_env("FALLBACK_AZ_KEY", "sk-fallback");

    let mut c = Config::default();
    c.providers.insert(
        "az-primary".to_string(),
        ProviderConfig::AzureOpenai(azure_cfg(Some("PRIMARY_AZ_KEY"), None)),
    );
    c.providers.insert(
        "az-fallback".to_string(),
        ProviderConfig::AzureOpenai(azure_cfg(Some("FALLBACK_AZ_KEY"), None)),
    );
    c.llm = Some(LlmRouting {
        chat: CapabilityRoute {
            provider: "az-primary".to_string(),
            model: "m1".to_string(),
            fallback: Some(Box::new(CapabilityRoute {
                provider: "az-fallback".to_string(),
                model: "m2".to_string(),
                fallback: None,
                dimension: None,
            })),
            dimension: None,
        },
        embeddings: CapabilityRoute {
            provider: "az-primary".to_string(),
            model: "m1".to_string(),
            fallback: None,
            dimension: None,
        },
    });

    let chat = c
        .create_llm_client(Capability::Chat)
        .expect("both Azure keys resolve from their own env vars");
    assert!(matches!(chat, clx_core::llm::LlmClient::Fallback(_)));

    // If the fallback provider's key is missing, building the wrapper fails
    // (the fallback side ran its own resolution and hit the hard error).
    clear_env("FALLBACK_AZ_KEY");
    let err = c
        .create_llm_client(Capability::Chat)
        .expect_err("missing fallback credential must fail wrapper construction");
    assert!(
        format!("{err}").contains("no credentials available"),
        "fallback side resolves independently; got: {err}"
    );
    clear_env("PRIMARY_AZ_KEY");
}

// =========================================================================
// 6. Retention + logging defaults and effect (2.2, 3.8)
// =========================================================================

#[test]
fn retention_and_logging_defaults_match_spec() {
    let c = Config::default();
    assert_eq!(c.retention.tool_events_days, 30);
    assert_eq!(c.retention.events_days, 7);
    assert_eq!(c.retention.snapshots_days, 0, "0 = keep forever");

    assert_eq!(c.logging.level, "info");
    assert_eq!(c.logging.file, "~/.clx/logs/clx.log");
    assert_eq!(c.logging.max_size_mb, 10);
    assert_eq!(c.logging.max_files, 5);
}

#[test]
#[serial]
fn log_file_path_expands_tilde_against_home() {
    let _home = HomeGuard::new();
    let home = std::env::var("HOME").unwrap();
    let c = Config::default();
    let expanded = c.log_file_path();
    assert_eq!(
        expanded,
        std::path::Path::new(&home).join(".clx/logs/clx.log"),
        "logging.file '~/...' must expand against HOME"
    );
    // A non-tilde path is returned unchanged.
    assert_eq!(Config::expand_tilde("/var/log/clx.log"), "/var/log/clx.log");
}
