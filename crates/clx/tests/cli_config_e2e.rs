//! Wave: `clx config` + `config-trust` + version/maintenance e2e tests.
//!
//! Anchored to `specs/_prerelease/03-credentials-config.md` sections 3.7
//! (config-trust file-hash trustlist) and 5.3, and
//! `specs/_prerelease/04-integration.md` (config / version / maintenance
//! command table). Behaviour-driven: asserts observable CLI output and
//! exit codes, not internal state.
//!
//! Isolation: every command runs with `HOME`, `XDG_DATA_HOME`,
//! `XDG_CONFIG_HOME` redirected into a fresh `tempfile::TempDir`. All
//! clx-core path resolution (`~/.clx`) and the default `file` credential
//! backend land in throwaway space. The real `~/.clx`, `~/.claude` and the
//! macOS keychain are never touched. No network, no model download.
//!
//! NOTE on the real subcommand surface: `clx config` has NO
//! `show/get/set/path` subcommands. The real `ConfigAction` enum is
//! `Edit | Reset | Migrate`, plus a bare `clx config` that prints the
//! resolved config as YAML (`commands/config.rs`). These tests pin that
//! real surface rather than an assumed one.

// e2e prose references config keys / JSON identifiers; pedantic doc lints
// only add noise here.
#![allow(clippy::doc_markdown)]

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

/// A `clx` command with HOME + XDG fully isolated to `tmp`.
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

fn home_path(t: &TempDir, rel: &str) -> std::path::PathBuf {
    t.path().join(rel)
}

// ===========================================================================
// `clx config` (bare): prints resolved configuration as YAML
// ===========================================================================

#[test]
fn config_bare_prints_yaml_with_header_on_fresh_home() {
    // Fresh HOME (no config.yaml on disk): defaults are synthesised and
    // printed. Must succeed and emit the human header + recognisable keys.
    let t = tmp();
    clx(&t)
        .arg("config")
        .assert()
        .success()
        .stdout(predicate::str::contains("Current Configuration"))
        .stdout(predicate::str::contains("validator"));
}

#[test]
fn config_json_roundtrips_through_serde() {
    let t = tmp();
    let out = clx(&t)
        .args(["--json", "config"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value =
        serde_json::from_str(&String::from_utf8(out).unwrap()).expect("config --json is JSON");
    assert!(v.is_object(), "config --json must be a JSON object: {v}");
}

#[test]
fn config_reset_writes_default_config_file_under_isolated_home() {
    // `--json` reset skips the interactive y/N prompt and writes
    // ~/.clx/config.yaml inside the isolated HOME only.
    let t = tmp();
    clx(&t)
        .args(["--json", "config", "reset"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"action\":\"reset\""));
    assert!(
        home_path(&t, ".clx/config.yaml").exists(),
        "reset must write config.yaml under the isolated HOME"
    );
    // The real ~/.clx must never be created outside the tempdir; we only
    // assert the isolated copy exists (negative is structurally guaranteed
    // by HOME redirection).
}

#[test]
fn config_reset_is_idempotent() {
    let t = tmp();
    clx(&t)
        .args(["--json", "config", "reset"])
        .assert()
        .success();
    clx(&t)
        .args(["--json", "config", "reset"])
        .assert()
        .success();
}

#[test]
fn config_reads_back_a_seeded_on_disk_value() {
    // Seed an on-disk config with a non-default validator.enabled=false and
    // assert the bare `config` output reflects the seeded file (round-trip
    // read path, config/mod.rs layering).
    let t = tmp();
    let cfg_dir = home_path(&t, ".clx");
    std::fs::create_dir_all(&cfg_dir).unwrap();
    std::fs::write(
        cfg_dir.join("config.yaml"),
        "validator:\n  enabled: false\n",
    )
    .unwrap();
    clx(&t)
        .args(["--json", "config"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"enabled\": false"));
}

#[test]
fn config_with_malformed_yaml_fails_loudly_not_panic() {
    // Edge/failure: a corrupt config.yaml must produce a clean non-zero
    // exit (anyhow error), never a panic / signal.
    let t = tmp();
    let cfg_dir = home_path(&t, ".clx");
    std::fs::create_dir_all(&cfg_dir).unwrap();
    std::fs::write(cfg_dir.join("config.yaml"), "this: : not: valid: yaml: [").unwrap();
    let out = clx(&t).arg("config").output().expect("spawn");
    assert!(
        out.status.code().is_some(),
        "malformed config must exit with a code, not a signal"
    );
    assert!(
        !out.status.success(),
        "malformed config.yaml must fail loudly"
    );
}

#[test]
fn config_migrate_with_no_config_file_fails_cleanly() {
    // Failure path: nothing to migrate when no config.yaml exists.
    let t = tmp();
    clx(&t)
        .args(["config", "migrate"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("nothing to migrate"));
}

#[test]
fn config_migrate_already_new_schema_fails_cleanly() {
    // Failure path: a config already on the new schema cannot be migrated.
    let t = tmp();
    clx(&t)
        .args(["--json", "config", "reset"])
        .assert()
        .success();
    clx(&t)
        .args(["config", "migrate"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("nothing to migrate"));
}

// ===========================================================================
// `clx config-trust` (spec 03 §3.7 / §5.3): file-hash trustlist
// ===========================================================================

#[test]
fn config_trust_list_on_empty_trustlist_reports_none() {
    let t = tmp();
    clx(&t)
        .args(["config-trust", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("No trusted project configs"));
}

#[test]
fn config_trust_list_json_empty_has_zero_count() {
    let t = tmp();
    let out = clx(&t)
        .args(["--json", "config-trust", "list"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8(out).unwrap()).unwrap();
    assert_eq!(v["count"], 0);
    assert!(v["entries"].as_array().unwrap().is_empty());
}

#[test]
fn config_trust_add_then_list_then_remove_roundtrip() {
    // §5.3 walkthrough: add a real file by hash, see it in list, remove it.
    let t = tmp();
    let proj = home_path(&t, "work/.clx");
    std::fs::create_dir_all(&proj).unwrap();
    let cfg = proj.join("config.yaml");
    std::fs::write(&cfg, "providers: {}\n").unwrap();

    // add -y skips the interactive prompt.
    let add_out = clx(&t)
        .args(["--json", "config-trust", "add"])
        .arg(&cfg)
        .arg("-y")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let added: serde_json::Value =
        serde_json::from_str(&String::from_utf8(add_out).unwrap()).unwrap();
    assert_eq!(added["status"], "added");
    let hash = added["hash"].as_str().expect("hash string").to_string();
    assert!(hash.starts_with("sha256:"), "hash must be sha256: {hash}");

    // list now shows exactly one entry.
    let list_out = clx(&t)
        .args(["--json", "config-trust", "list"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let listed: serde_json::Value =
        serde_json::from_str(&String::from_utf8(list_out).unwrap()).unwrap();
    assert_eq!(listed["count"], 1);

    // remove by full hash.
    clx(&t)
        .args(["--json", "config-trust", "remove", &hash])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"status\": \"removed\""));

    // list is empty again.
    let after = clx(&t)
        .args(["--json", "config-trust", "list"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8(after).unwrap()).unwrap();
    assert_eq!(v["count"], 0);
}

#[test]
fn config_trust_add_missing_file_fails() {
    let t = tmp();
    clx(&t)
        .args(["config-trust", "add", "/no/such/config.yaml", "-y"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("config file not found"));
}

#[test]
fn config_trust_remove_unknown_hash_is_not_found_not_error() {
    // Removing an absent hash is a clean "not_found", exit 0 (idempotent).
    let t = tmp();
    clx(&t)
        .args([
            "--json",
            "config-trust",
            "remove",
            "sha256:deadbeefdeadbeef",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"status\": \"not_found\""));
}

// ===========================================================================
// Quick wins: version (I-R1 license pin) + maintenance trim
// ===========================================================================

#[test]
fn version_reports_mpl_2_0_license_not_mit() {
    // RISK I-R1 regression pin: human `clx version` says MPL-2.0.
    let t = tmp();
    clx(&t)
        .arg("version")
        .assert()
        .success()
        .stdout(predicate::str::contains("License: MPL-2.0"))
        .stdout(predicate::str::contains("License: MIT").not());
}

#[test]
fn version_string_is_nonempty_and_named_clx() {
    let t = tmp();
    let out = clx(&t)
        .args(["--json", "version"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8(out).unwrap()).unwrap();
    assert_eq!(v["name"], "clx");
    assert!(
        v["version"].as_str().is_some_and(|s| !s.is_empty()),
        "version must be a non-empty string: {v}"
    );
}

#[test]
fn maintenance_trim_dry_run_reports_counts_on_fresh_db() {
    let t = tmp();
    clx(&t).args(["--json", "install"]).assert().success();
    let out = clx(&t)
        .args(["--json", "maintenance", "trim", "--dry-run"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8(out).unwrap()).unwrap();
    assert_eq!(v["dry_run"], true);
    assert!(v["tool_events_would_delete"].is_number());
}

#[test]
fn maintenance_trim_human_output_on_fresh_db_succeeds() {
    // Non-JSON path of trim (different code branch) must also succeed.
    let t = tmp();
    clx(&t).args(["--json", "install"]).assert().success();
    clx(&t)
        .args(["maintenance", "trim", "--dry-run"])
        .assert()
        .success();
}
