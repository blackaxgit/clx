//! Wave: `clx credentials` DEEP e2e tests -- full CRUD success pipelines.
//!
//! Drives the success arms of `commands/credentials.rs` that the offline
//! suite never reaches:
//!   * `Set`  -> store success (`credentials.rs:66-87`), both json + human.
//!   * `Get`  -> Ok(Some) success (`:90-104`), both json + human (raw value).
//!   * `List` -> non-empty render incl. the provider-annotation hyphen
//!     path `<provider>-api-key` -> ` (ollama)` (`:135-181`, C-R1).
//!   * `Delete` -> success (`:249-268`), then `Get` -> Ok(None) failure.
//!   * `Migrate` -> the "already present in the configured backend"
//!     no-op arm (`:183-206`), both json + human -- the ONLY hermetic
//!     migrate arm (it short-circuits BEFORE any keychain read).
//!
//! Isolation: HOME + XDG redirected into a fresh RAII `tempfile::TempDir`.
//! `CLX_CREDENTIALS_BACKEND=file` forces the age-encrypted file backend,
//! so NO macOS keychain is touched and there is no prompt. The migrate
//! test stays on the already-present short-circuit so the keychain read
//! is never executed.

#![allow(clippy::doc_markdown)]

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

fn clx(tmp: &TempDir) -> Command {
    let mut cmd = Command::cargo_bin("clx").expect("clx binary");
    cmd.env("HOME", tmp.path())
        .env("XDG_DATA_HOME", tmp.path().join("xdg-data"))
        .env("XDG_CONFIG_HOME", tmp.path().join("xdg-config"))
        .env("CLX_CREDENTIALS_BACKEND", "file")
        .env("CLX_MODEL_FETCH_DRYRUN", "1")
        .env("CLX_LOG", "error");
    cmd
}

fn tmp() -> TempDir {
    tempfile::tempdir().expect("tempdir")
}

// ===========================================================================
// Set -> Get -> Delete -> Get(None) round trip
// ===========================================================================

#[test]
fn credentials_set_then_get_returns_raw_value_human() {
    // Human `get` prints ONLY the value (pipe-friendly), per :100-103.
    let t = tmp();
    clx(&t)
        .args(["credentials", "set", "MY_KEY", "s3cr3t-val"])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Credential 'MY_KEY' stored successfully.",
        ));
    let out = clx(&t)
        .args(["credentials", "get", "MY_KEY"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    assert_eq!(
        String::from_utf8(out).unwrap().trim(),
        "s3cr3t-val",
        "human get must print only the raw value"
    );
}

#[test]
fn credentials_set_then_get_json_returns_key_and_value() {
    let t = tmp();
    clx(&t)
        .args(["--json", "credentials", "set", "K1", "v1"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"success\":true"));
    let out = clx(&t)
        .args(["--json", "credentials", "get", "K1"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8(out).unwrap()).unwrap();
    assert_eq!(v["key"], "K1");
    assert_eq!(v["value"], "v1");
}

#[test]
fn credentials_delete_then_get_is_not_found() {
    let t = tmp();
    clx(&t)
        .args(["credentials", "set", "GONE", "x"])
        .assert()
        .success();
    clx(&t)
        .args(["credentials", "delete", "GONE"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Credential 'GONE' deleted."));
    // Human get on a missing key bails (anyhow) -> non-zero exit.
    clx(&t)
        .args(["credentials", "get", "GONE"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Credential 'GONE' not found"));
}

#[test]
fn credentials_delete_json_arm_reports_success() {
    let t = tmp();
    clx(&t)
        .args(["credentials", "set", "D1", "y"])
        .assert()
        .success();
    clx(&t)
        .args(["--json", "credentials", "delete", "D1"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"action\":\"delete\""))
        .stdout(predicate::str::contains("\"success\":true"));
}

#[test]
fn credentials_get_missing_json_arm_emits_error_field_exit_zero() {
    // `--json` get on an absent key is NOT a hard failure: it prints a
    // JSON object with an "error" field and exits 0 (:106-114).
    let t = tmp();
    let out = clx(&t)
        .args(["--json", "credentials", "get", "NOPE"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8(out).unwrap()).unwrap();
    assert_eq!(v["key"], "NOPE");
    assert!(v["value"].is_null());
    assert!(v["error"].as_str().is_some());
}

// ===========================================================================
// List: non-empty + provider-annotation hyphen path (C-R1)
// ===========================================================================

#[test]
fn credentials_list_human_annotates_provider_api_key_with_ollama() {
    // Seed a config with an `ollama` provider named `azure-prod`, then
    // store `azure-prod-api-key`. The list renderer must strip the
    // `-api-key` suffix, find the provider, and append ` (ollama)`
    // (credentials.rs:160-171, the canonical hyphen separator path).
    let t = tmp();
    let clx_dir = t.path().join(".clx");
    std::fs::create_dir_all(&clx_dir).unwrap();
    std::fs::write(
        clx_dir.join("config.yaml"),
        concat!(
            "providers:\n",
            "  azure-prod:\n",
            "    kind: ollama\n",
            "    host: \"http://127.0.0.1:1\"\n",
            "    model: \"m\"\n",
            "    embedding_model: \"e\"\n",
            "    embedding_dim: 768\n",
        ),
    )
    .unwrap();
    clx(&t)
        .args(["credentials", "set", "azure-prod-api-key", "tok"])
        .assert()
        .success();
    clx(&t)
        .args(["credentials", "set", "PLAIN_KEY", "v"])
        .assert()
        .success();
    clx(&t)
        .args(["credentials", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Stored Credentials"))
        .stdout(predicate::str::contains("azure-prod-api-key"))
        .stdout(predicate::str::contains("(ollama)"))
        .stdout(predicate::str::contains("Total: 2 credentials"));
}

#[test]
fn credentials_list_json_lists_all_stored_keys() {
    let t = tmp();
    clx(&t)
        .args(["credentials", "set", "A", "1"])
        .assert()
        .success();
    clx(&t)
        .args(["credentials", "set", "B", "2"])
        .assert()
        .success();
    let out = clx(&t)
        .args(["--json", "credentials", "list"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8(out).unwrap()).unwrap();
    let creds = v["credentials"].as_array().expect("credentials array");
    let names: Vec<&str> = creds.iter().filter_map(serde_json::Value::as_str).collect();
    assert!(names.contains(&"A"), "list must include A: {v}");
    assert!(names.contains(&"B"), "list must include B: {v}");
}

#[test]
fn credentials_list_singular_label_for_one_credential() {
    // The pluralization arm: exactly one credential -> "1 credential"
    // (no trailing 's').
    let t = tmp();
    clx(&t)
        .args(["credentials", "set", "ONLY", "v"])
        .assert()
        .success();
    clx(&t)
        .args(["credentials", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Total: 1 credential"))
        .stdout(predicate::str::contains("Total: 1 credentials").not());
}

// ===========================================================================
// Migrate: already-present short-circuit (hermetic; no keychain read)
// ===========================================================================

#[test]
fn credentials_migrate_already_present_json_is_noop() {
    // Store the key in the file backend FIRST so migrate short-circuits
    // at the `store.get(key)` Ok(Some) arm and never touches the
    // keychain (credentials.rs:184-206, json arm).
    let t = tmp();
    clx(&t)
        .args(["credentials", "set", "azure-prod-api-key", "already"])
        .assert()
        .success();
    let out = clx(&t)
        .args(["--json", "credentials", "migrate", "azure-prod-api-key"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8(out).unwrap()).unwrap();
    assert_eq!(v["action"], "migrate");
    assert_eq!(v["migrated"], false);
    assert_eq!(v["reason"], "already present in the configured backend");
}

#[test]
fn credentials_migrate_already_present_human_arm() {
    let t = tmp();
    clx(&t)
        .args(["credentials", "set", "K", "v"])
        .assert()
        .success();
    clx(&t)
        .args(["credentials", "migrate", "K"])
        .assert()
        .success()
        .stdout(predicate::str::contains("nothing to migrate"));
}
