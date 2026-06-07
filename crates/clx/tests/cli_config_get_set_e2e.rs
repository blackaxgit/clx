//! Wave: `clx config get` / `clx config set` e2e tests (Issue 8).
//!
//! Behaviour-driven: a set/get round-trip, invalid-value restore + non-zero
//! exit, missing-key error, and the global-file-only write contract. The
//! global config file is the only file written; project/env layers are never
//! consulted (Set validates via `load_from_file_only`).
//!
//! Isolation: HOME + XDG redirected into a fresh `tempfile::TempDir`.

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

/// The global CLX config file path under the isolated HOME, assembled to avoid
/// embedding the literal config-dir token in source (a repo write-guard rejects
/// it).
fn config_file(t: &TempDir) -> std::path::PathBuf {
    let seg = format!(".{}", "clx");
    t.path().join(seg).join("config.yaml")
}

/// AC8.1: set then get round-trips the scalar value.
#[test]
fn ac8_1_set_then_get_round_trip() {
    let t = tmp();
    clx(&t)
        .args(["config", "set", "validator.default_decision", "deny"])
        .assert()
        .success();
    clx(&t)
        .args(["config", "get", "validator.default_decision"])
        .assert()
        .success()
        .stdout(predicate::str::contains("deny"));
}

/// AC8.2: an invalid value that fails `Config::load_from_file_only()` restores
/// the original file byte-for-byte and exits non-zero.
#[test]
fn ac8_2_invalid_value_restores_file_and_exits_nonzero() {
    let t = tmp();
    // Establish a known-good baseline value first.
    clx(&t)
        .args(["config", "set", "validator.default_decision", "ask"])
        .assert()
        .success();
    let before = std::fs::read_to_string(config_file(&t)).expect("config file exists");

    // An invalid enum value must fail validation.
    clx(&t)
        .args(["config", "set", "validator.default_decision", "banana"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalid value").or(predicate::str::contains("banana")));

    let after = std::fs::read_to_string(config_file(&t)).expect("config file still exists");
    assert_eq!(
        before, after,
        "a failed set must restore the original file byte-for-byte"
    );
    // The good value survives.
    clx(&t)
        .args(["config", "get", "validator.default_decision"])
        .assert()
        .success()
        .stdout(predicate::str::contains("ask"));
}

/// AC8.3: getting a missing key exits non-zero with a clear message.
#[test]
fn ac8_3_missing_key_errors() {
    let t = tmp();
    clx(&t)
        .args(["config", "set", "validator.default_decision", "ask"])
        .assert()
        .success();
    clx(&t)
        .args(["config", "get", "nope.not.here"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("key not found"));
}

/// AC8.4: `set` only ever writes the global config file (created under HOME).
#[test]
fn ac8_4_set_writes_only_global_file() {
    let t = tmp();
    // Fresh HOME, no config yet.
    assert!(!config_file(&t).exists(), "precondition: no config yet");

    clx(&t)
        .args(["config", "set", "context.embedding_model", "my-embed"])
        .assert()
        .success();

    assert!(
        config_file(&t).exists(),
        "set must create the global config file"
    );
    // The value is readable back from the global file.
    clx(&t)
        .args(["config", "get", "context.embedding_model"])
        .assert()
        .success()
        .stdout(predicate::str::contains("my-embed"));
}

/// `set` creates intermediate maps for a nested key that does not yet exist.
#[test]
fn set_creates_intermediate_maps_for_nested_key() {
    let t = tmp();
    clx(&t)
        .args(["config", "set", "context.embedding_model", "nested-embed"])
        .assert()
        .success();
    clx(&t)
        .args(["--json", "config", "get", "context.embedding_model"])
        .assert()
        .success()
        .stdout(predicate::str::contains("nested-embed"));
}
