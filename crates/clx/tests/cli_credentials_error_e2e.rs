//! Wave: `clx credentials` error-path + azure-annotation e2e tests.
//!
//! `cli_credentials_deep_e2e.rs` covers the CRUD success arms, the
//! ollama provider annotation, and the migrate already-present
//! short-circuit. It never drives:
//!   * the `store.get` -> `Err(e)` arm of `Get` (credentials.rs:119-129),
//!     both the HUMAN bail and the `--json` `{key,error}` arm. This is
//!     reached hermetically by corrupting the age ciphertext on disk so
//!     decryption fails (no keychain, no network).
//!   * the `ProviderConfig::AzureOpenai(_)` annotation branch of `List`
//!     (credentials.rs:166) -- the ollama branch is already covered; this
//!     pins the azure label `(azure_openai)`.
//!
//! Hermetic: isolated HOME, age file backend, dry-run, no network, no
//! keychain. The corruption is applied to the tempdir-local
//! `~/.clx/credentials.age` only.

#![allow(clippy::doc_markdown)]

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

fn clx(tmp: &TempDir) -> Command {
    let mut cmd = Command::cargo_bin("clx").expect("clx binary");
    cmd.env("HOME", tmp.path())
        .env("XDG_DATA_HOME", tmp.path().join("xdg-data"))
        .env("XDG_CONFIG_HOME", tmp.path().join("xdg-config"))
        .env("CLX_CREDENTIALS_BACKEND", "age")
        .env("CLX_MODEL_FETCH_DRYRUN", "1")
        .env("CLX_LOG", "error");
    cmd
}

fn tmp() -> TempDir {
    tempfile::tempdir().expect("tempdir")
}

fn home_path(t: &TempDir, rel: &str) -> std::path::PathBuf {
    t.path().join(rel)
}

/// Store a credential (creates `~/.clx/credentials.age` + `cred.key`),
/// then overwrite the ciphertext with bytes that are NOT a valid age
/// header so the next decrypt fails with a Storage error.
fn corrupt_age_ciphertext(t: &TempDir) {
    clx(t)
        .args(["credentials", "set", "SEED", "v"])
        .assert()
        .success();
    let age = home_path(t, ".clx/credentials.age");
    assert!(age.exists(), "set must have created the age file");
    std::fs::write(&age, b"this-is-not-a-valid-age-file\x00\x01\x02").unwrap();
}

// ===========================================================================
// Get -> Err(e) arm (credentials.rs:119-129)
// ===========================================================================

#[test]
fn credentials_get_human_bails_on_corrupt_store() {
    let t = tmp();
    corrupt_age_ciphertext(&t);
    clx(&t)
        .args(["credentials", "get", "SEED"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "Failed to retrieve credential 'SEED'",
        ));
}

#[test]
fn credentials_get_json_emits_error_field_on_corrupt_store_exit_zero() {
    // The `--json` Err arm prints `{key, error}` and exits 0 (no bail).
    let t = tmp();
    corrupt_age_ciphertext(&t);
    let out = clx(&t)
        .args(["--json", "credentials", "get", "SEED"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value =
        serde_json::from_str(&String::from_utf8(out).unwrap()).expect("json get is JSON");
    assert_eq!(v["key"], "SEED");
    assert!(
        v["error"].as_str().is_some_and(|s| !s.is_empty()),
        "corrupt-store json get must carry a non-empty error: {v}"
    );
    assert!(
        v.get("value").is_none() || v["value"].is_null(),
        "no value must be emitted when the store is unreadable: {v}"
    );
}

// ===========================================================================
// List azure_openai annotation branch (credentials.rs:163-167)
// ===========================================================================

#[test]
fn credentials_list_human_annotates_azure_provider_api_key() {
    // Seed an azure_openai provider named `azure-prod`, store
    // `azure-prod-api-key` -> the renderer strips `-api-key`, resolves
    // the provider, and appends ` (azure_openai)`.
    let t = tmp();
    let clx_dir = home_path(&t, ".clx");
    std::fs::create_dir_all(&clx_dir).unwrap();
    std::fs::write(
        clx_dir.join("config.yaml"),
        concat!(
            "providers:\n",
            "  azure-prod:\n",
            "    kind: azure_openai\n",
            "    endpoint: \"https://x.openai.azure.com\"\n",
            "    api_key_env: \"AZURE_OPENAI_API_KEY\"\n",
            "    timeout_ms: 30000\n",
        ),
    )
    .unwrap();
    clx(&t)
        .args(["credentials", "set", "azure-prod-api-key", "tok"])
        .assert()
        .success();
    clx(&t)
        .args(["credentials", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("azure-prod-api-key"))
        .stdout(predicate::str::contains("(azure_openai)"))
        // The ollama label must NOT appear for an azure provider.
        .stdout(predicate::str::contains("(ollama)").not());
}
