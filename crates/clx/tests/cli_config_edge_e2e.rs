//! e2e tests for `clx config get/set` edge arms the get/set wave skipped:
//!
//! * `get` on a NON-scalar key must refuse to print a subtree
//!   (config.rs:254-262, 329-330).
//! * `get` with no config file on disk fails with the actionable
//!   read-context error (config.rs:318-323).
//! * `set` parses a float value (parse_value float arm, config.rs:274-276)
//!   and round-trips it through `get`.
//! * `set` with NO pre-existing file creates it; an invalid value on a
//!   missing file removes the just-created file (the `original: None`
//!   restore arm, config.rs:385-387).
//! * `set` through a scalar intermediate replaces it with a mapping
//!   (config.rs:299-301).
//!
//! Isolation: HOME + XDG into a fresh TempDir; CLX_* scrubbed; protected
//! config-dir token built via `concat!`.

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

fn config_file(t: &TempDir) -> PathBuf {
    t.path().join(concat!(".", "clx")).join("config.yaml")
}

/// Seed a config file on disk without running install.
fn seed_config(t: &TempDir, yaml: &str) {
    std::fs::create_dir_all(config_file(t).parent().unwrap()).unwrap();
    std::fs::write(config_file(t), yaml).unwrap();
}

#[test]
fn config_get_refuses_non_scalar_subtree() {
    let t = tmp();
    seed_config(&t, "validator:\n  enabled: true\n");

    clx(&t)
        .args(["config", "get", "validator"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not a scalar"));
}

#[test]
fn config_get_without_config_file_fails_with_read_context() {
    let t = tmp();
    clx(&t)
        .args(["config", "get", "validator.enabled"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Failed to read config file"));
}

#[test]
fn config_set_float_value_roundtrips_through_get() {
    let t = tmp();
    seed_config(&t, "validator:\n  enabled: true\n");

    clx(&t)
        .args(["config", "set", "auto_recall.similarity_threshold", "0.42"])
        .assert()
        .success();

    let out = clx(&t)
        .args(["config", "get", "auto_recall.similarity_threshold"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    assert_eq!(String::from_utf8(out).unwrap().trim(), "0.42");

    // It was written as a YAML number, not a quoted string.
    let raw = std::fs::read_to_string(config_file(&t)).unwrap();
    let v: serde_yml::Value = serde_yml::from_str(&raw).unwrap();
    assert!(
        v["auto_recall"]["similarity_threshold"].is_number(),
        "float must be stored as a number:\n{raw}"
    );
}

#[test]
fn config_set_creates_missing_file_then_invalid_value_removes_created_file() {
    // Arm 1: no file -> a valid set creates it.
    let t = tmp();
    assert!(!config_file(&t).exists());
    clx(&t)
        .args(["config", "set", "validator.default_decision", "deny"])
        .assert()
        .success();
    assert!(config_file(&t).exists(), "set must create a missing file");
    let out = clx(&t)
        .args(["config", "get", "validator.default_decision"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    assert_eq!(String::from_utf8(out).unwrap().trim(), "deny");

    // Arm 2: fresh home, INVALID value on a missing file -> the just-created
    // file is removed again (no half-valid config left behind).
    let t2 = tmp();
    clx(&t2)
        .args(["config", "set", "validator.default_decision", "banana"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("config left unchanged"));
    assert!(
        !config_file(&t2).exists(),
        "invalid set on a missing file must not leave a file behind"
    );
}

/// `--json config set` reports the structured success record
/// (config.rs:392-401).
#[test]
fn config_set_json_arm_reports_success() {
    let t = tmp();
    seed_config(&t, "validator:\n  enabled: true\n");

    let out = clx(&t)
        .args([
            "--json",
            "config",
            "set",
            "validator.default_decision",
            "deny",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8(out).unwrap()).unwrap();
    assert_eq!(v["action"], "set");
    assert_eq!(v["key"], "validator.default_decision");
    assert_eq!(v["value"], "deny");
    assert_eq!(v["success"], true);
}

/// An invalid value on an EXISTING file restores the exact original bytes --
/// including a YAML comment, which a re-serialization would have destroyed
/// (config.rs:376-383).
#[test]
fn config_set_invalid_value_restores_existing_file_bytes_exactly() {
    let t = tmp();
    let original = "# sentinel-comment\nvalidator:\n  enabled: true\n";
    seed_config(&t, original);

    clx(&t)
        .args(["config", "set", "validator.default_decision", "banana"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("config left unchanged"));

    assert_eq!(
        std::fs::read_to_string(config_file(&t)).unwrap(),
        original,
        "restore must be byte-exact (comment preserved)"
    );
}

/// `get` renders bool and null scalars (yaml_scalar_to_string arms,
/// config.rs:257-259). `get` reads the RAW file, so an extra key is fine.
#[test]
fn config_get_renders_bool_and_null_scalars() {
    let t = tmp();
    seed_config(&t, "validator:\n  enabled: true\nempty_key:\n");

    let out = clx(&t)
        .args(["config", "get", "validator.enabled"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    assert_eq!(String::from_utf8(out).unwrap().trim(), "true");

    let out = clx(&t)
        .args(["config", "get", "empty_key"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    assert_eq!(String::from_utf8(out).unwrap().trim(), "null");
}

/// `set` stores bool and integer values typed, not as strings (parse_value
/// bool/int arms, config.rs:268-273).
#[test]
fn config_set_bool_and_int_values_are_stored_typed() {
    let t = tmp();
    seed_config(&t, "validator:\n  enabled: true\n");

    clx(&t)
        .args(["config", "set", "validator.enabled", "false"])
        .assert()
        .success();
    clx(&t)
        .args(["config", "set", "retention.tool_events_days", "7"])
        .assert()
        .success();

    let raw = std::fs::read_to_string(config_file(&t)).unwrap();
    let v: serde_yml::Value = serde_yml::from_str(&raw).unwrap();
    assert_eq!(
        v["validator"]["enabled"],
        serde_yml::Value::Bool(false),
        "bool stored typed:\n{raw}"
    );
    assert_eq!(
        v["retention"]["tool_events_days"].as_i64(),
        Some(7),
        "int stored typed:\n{raw}"
    );
}

/// A scalar ROOT document is replaced by a mapping so the dotted set can
/// proceed (config.rs:284-286).
#[test]
fn config_set_replaces_scalar_root_document() {
    let t = tmp();
    seed_config(&t, "just-a-scalar\n");

    clx(&t)
        .args(["config", "set", "validator.default_decision", "deny"])
        .assert()
        .success();

    let out = clx(&t)
        .args(["config", "get", "validator.default_decision"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    assert_eq!(String::from_utf8(out).unwrap().trim(), "deny");
}

/// `--json config reset` on a FRESH home creates the parent dir and the
/// default file without prompting (config.rs:136-152).
#[test]
fn config_reset_json_on_fresh_home_creates_default_file() {
    let t = tmp();
    assert!(!config_file(&t).exists());

    let out = clx(&t)
        .args(["--json", "config", "reset"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8(out).unwrap()).unwrap();
    assert_eq!(v["action"], "reset");
    assert_eq!(v["success"], true);
    assert!(
        config_file(&t).exists(),
        "reset must write the default file"
    );
}

/// `config edit` on a FRESH home creates the parent dir + default file before
/// launching the editor (config.rs:62-75); a no-op editor keeps it green.
#[test]
fn config_edit_json_on_fresh_home_creates_default_file() {
    let t = tmp();
    assert!(!config_file(&t).exists());

    clx(&t)
        .env("EDITOR", "/usr/bin/true")
        .args(["--json", "config", "edit"])
        .assert()
        .success();
    assert!(
        config_file(&t).exists(),
        "edit must create a missing default config"
    );
}

#[test]
fn config_set_replaces_scalar_intermediate_with_mapping() {
    let t = tmp();
    // `validator` is a scalar here; the dotted set must replace it with a map.
    seed_config(&t, "validator: banana\n");

    clx(&t)
        .args(["config", "set", "validator.default_decision", "allow"])
        .assert()
        .success();

    let out = clx(&t)
        .args(["config", "get", "validator.default_decision"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    assert_eq!(String::from_utf8(out).unwrap().trim(), "allow");
}
