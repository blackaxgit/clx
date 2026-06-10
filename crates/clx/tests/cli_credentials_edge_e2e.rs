//! e2e tests for hermetic `clx credentials` arms still uncovered after the
//! deep + error waves (age-file backend ONLY -- the keychain `migrate` read
//! arms are intentionally NOT driven here; they would touch the real user
//! login keychain and are documented as out of hermetic reach):
//!
//! * `list` empty-store human arm: "No credentials stored."
//!   (credentials.rs:152-153).
//! * `list` human arm WITHOUT provider annotation when no provider matches
//!   the `<name>-api-key` shape (the `unwrap_or_default` miss path,
//!   credentials.rs:160-171).
//! * `set` / `delete` error contexts on a corrupt age ciphertext
//!   (credentials.rs:67-69, 250) -- failures must be loud, never swallowed.
//! * an unknown `CLX_CREDENTIALS_BACKEND` value must fall back to the
//!   non-prompting FILE backend (never the keychain): the CLI keeps working
//!   and the age file is what gets written (credentials.rs:59-63).
//!
//! Isolation: HOME + XDG into a fresh TempDir; CLX_* scrubbed; protected
//! config-dir token built via `concat!`. No keychain, no network.

#![allow(clippy::doc_markdown)]

use std::path::PathBuf;

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

fn age_file(t: &TempDir) -> PathBuf {
    t.path().join(concat!(".", "clx")).join("credentials.age")
}

/// Store one credential, then overwrite the ciphertext with garbage so every
/// subsequent decrypt fails (mirrors cli_credentials_error_e2e).
fn corrupt_age_ciphertext(t: &TempDir) {
    clx(t)
        .args(["credentials", "set", "SEED", "v"])
        .assert()
        .success();
    assert!(age_file(t).exists(), "set must have created the age file");
    std::fs::write(age_file(t), b"not-an-age-file\x00\x01").unwrap();
}

#[test]
fn credentials_list_empty_store_human_says_none_stored() {
    let t = tmp();
    let out = clx(&t)
        .args(["credentials", "list"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8(out).unwrap();
    assert!(text.contains("No credentials stored."), "got:\n{text}");
    assert!(
        !text.contains("Total:"),
        "empty list must not print a total line:\n{text}"
    );
}

#[test]
fn credentials_list_human_omits_annotation_for_unmatched_provider() {
    let t = tmp();
    // `-api-key` suffix but NO provider named `ghost` in any config: the
    // annotation must be omitted entirely (not mislabeled).
    clx(&t)
        .args(["credentials", "set", "ghost-api-key", "v1"])
        .assert()
        .success();

    let out = clx(&t)
        .args(["credentials", "list"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8(out).unwrap();
    let line = text
        .lines()
        .find(|l| l.contains("ghost-api-key"))
        .unwrap_or_else(|| panic!("key not listed:\n{text}"));
    assert!(
        !line.contains("(ollama)") && !line.contains("(azure_openai)"),
        "unmatched provider must get no annotation: {line}"
    );
    assert!(text.contains("Total: 1 credential"), "got:\n{text}");
}

#[test]
fn credentials_set_fails_loudly_on_corrupt_store() {
    let t = tmp();
    corrupt_age_ciphertext(&t);
    clx(&t)
        .args(["credentials", "set", "K2", "v2"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Failed to store credential"));
}

#[test]
fn credentials_delete_fails_loudly_on_corrupt_store() {
    let t = tmp();
    corrupt_age_ciphertext(&t);
    clx(&t)
        .args(["credentials", "delete", "SEED"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Failed to delete credential"));
}

#[test]
fn credentials_unknown_backend_env_falls_back_to_file_not_keychain() {
    let t = tmp();
    // A typo'd backend must never select the prompting keychain. The CLI
    // falls back to the file backend: set/get keep working and the age file
    // is the artifact that appears.
    clx(&t)
        .env("CLX_CREDENTIALS_BACKEND", "bogus-backend")
        .args(["credentials", "set", "TYPO_KEY", "tv"])
        .assert()
        .success();
    assert!(
        age_file(&t).exists(),
        "fallback must write the age FILE backend"
    );

    let out = clx(&t)
        .env("CLX_CREDENTIALS_BACKEND", "bogus-backend")
        .args(["credentials", "get", "TYPO_KEY"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    assert_eq!(String::from_utf8(out).unwrap().trim(), "tv");
}
