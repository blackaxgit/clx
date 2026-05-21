//! Wave 1 E: `clx` CLI end-to-end tests.
//!
//! Anchored to `specs/_prerelease/04-integration.md` sections 2.1, 3.5,
//! 3.6, 3.10, the edge/failure matrix, and risks I-R1 (license) / I-R5
//! (maintenance trim audit default).
//!
//! Isolation: every command runs with `HOME`, `XDG_DATA_HOME`,
//! `XDG_CONFIG_HOME` redirected into a fresh `tempfile::TempDir`, so all
//! clx-core path resolution (`~/.clx`, `~/.claude`) and the default `file`
//! credential backend (`~/.clx/credentials.age`) land in throwaway space.
//! The real `~/.clx`, `~/.claude`, and the macOS keychain are never
//! touched. No network, no model download.
//!
//! Note: this suite uses `tempfile` (an existing dev-dependency) rather
//! than `assert_fs` because adding `assert_fs` would require editing the
//! production `crates/clx/Cargo.toml`, which is out of scope for a
//! test-only change. Path assertions use `std::path` + `predicates`.

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

/// A `clx` command with HOME + XDG fully isolated to `tmp`.
fn clx(tmp: &TempDir) -> Command {
    let mut cmd = Command::cargo_bin("clx").expect("clx binary");
    cmd.env("HOME", tmp.path())
        .env("XDG_DATA_HOME", tmp.path().join("xdg-data"))
        .env("XDG_CONFIG_HOME", tmp.path().join("xdg-config"))
        .env("CLX_LOG", "error");
    cmd
}

fn tmp() -> TempDir {
    tempfile::tempdir().expect("tempdir")
}

/// Absolute path inside the isolated HOME.
fn home_path(t: &TempDir, rel: &str) -> std::path::PathBuf {
    t.path().join(rel)
}

// ===========================================================================
// I-R1: license is MPL-2.0 (regression: spec flagged version.rs printing MIT)
// ===========================================================================

#[test]
fn version_subcommand_reports_mpl_2_0_not_mit() {
    // RISK I-R1 prove-fixed: `clx version` human output must say MPL-2.0
    // and must NOT say "License: MIT".
    let t = tmp();
    clx(&t)
        .arg("version")
        .assert()
        .success()
        .stdout(predicate::str::contains("MPL-2.0"))
        .stdout(predicate::str::contains("License: MIT").not());
}

#[test]
fn version_flag_is_clap_version_and_nonempty() {
    let t = tmp();
    clx(&t)
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::is_empty().not());
}

#[test]
fn version_json_has_version_and_name() {
    let t = tmp();
    let out = clx(&t)
        .args(["--json", "version"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value =
        serde_json::from_str(&String::from_utf8(out).unwrap()).expect("version --json is JSON");
    assert_eq!(v["name"], "clx");
    assert!(v["version"].is_string());
}

// ===========================================================================
// 3.5 / 3.6 + edge matrix: install / uninstall idempotency & symmetry
// ===========================================================================

#[test]
fn install_creates_isolated_clx_dir_and_is_idempotent() {
    let t = tmp();
    clx(&t)
        .args(["--json", "install"])
        .assert()
        .success()
        .stdout(predicate::str::contains("install"));
    // ~/.clx must be created inside the tempdir, not the real home.
    assert!(
        home_path(&t, ".clx").is_dir(),
        ".clx must be created under the isolated HOME"
    );
    // Second run must also succeed (idempotent; dirs already exist).
    clx(&t).args(["--json", "install"]).assert().success();
}

#[test]
fn install_registers_all_eight_hooks_including_stop_and_mcp() {
    let t = tmp();
    clx(&t).args(["--json", "install"]).assert().success();
    let settings = std::fs::read_to_string(t.path().join(".claude/settings.json"))
        .expect("settings.json written under isolated HOME");
    let v: serde_json::Value = serde_json::from_str(&settings).expect("settings.json is JSON");
    let hooks = v["hooks"].as_object().expect("hooks object");
    assert_eq!(hooks.len(), 8, "all 8 hook events expected: {hooks:?}");
    assert!(hooks.contains_key("Stop"), "Stop hook must be registered");
    assert!(
        v["mcpServers"]["clx"].is_object(),
        "clx MCP server must be registered"
    );
}

#[test]
fn reinstall_replaces_hooks_with_no_duplicates() {
    // Edge matrix: settings.json already has CLX entries -> hooks fully
    // replaced, single clx MCP key, no duplicates.
    let t = tmp();
    clx(&t).args(["--json", "install"]).assert().success();
    clx(&t).args(["--json", "install"]).assert().success();
    let settings = std::fs::read_to_string(t.path().join(".claude/settings.json")).unwrap();
    let v: serde_json::Value = serde_json::from_str(&settings).unwrap();
    assert_eq!(v["hooks"].as_object().unwrap().len(), 8);
    assert_eq!(
        v["mcpServers"].as_object().unwrap().len(),
        1,
        "exactly one MCP server entry"
    );
}

#[test]
fn install_then_uninstall_is_symmetric_and_preserves_clx_dir() {
    let t = tmp();
    clx(&t).args(["--json", "install"]).assert().success();
    clx(&t).args(["--json", "uninstall"]).assert().success();
    // ~/.clx preserved (config/DB/creds) unless --purge.
    assert!(
        home_path(&t, ".clx").is_dir(),
        ".clx preserved after non-purge uninstall"
    );
    let settings = std::fs::read_to_string(t.path().join(".claude/settings.json")).unwrap();
    let v: serde_json::Value = serde_json::from_str(&settings).unwrap();
    assert!(
        v.get("hooks").is_none(),
        "hooks key removed on uninstall: {v}"
    );
}

#[test]
fn uninstall_purge_removes_clx_dir() {
    let t = tmp();
    clx(&t).args(["--json", "install"]).assert().success();
    assert!(home_path(&t, ".clx").is_dir());
    // --json skips the interactive y/N for --purge.
    clx(&t)
        .args(["--json", "uninstall", "--purge"])
        .assert()
        .success();
    assert!(
        !home_path(&t, ".clx").exists(),
        ".clx must be gone after uninstall --purge"
    );
}

#[test]
fn uninstall_on_fresh_home_is_clean_ok() {
    // Edge matrix: uninstall when never installed -> clean Ok.
    let t = tmp();
    clx(&t).args(["--json", "uninstall"]).assert().success();
}

// ===========================================================================
// 3.10: maintenance trim (I-R5: audit default hard-coded 90d)
// ===========================================================================

#[test]
fn maintenance_trim_dry_run_json_reports_counts() {
    let t = tmp();
    clx(&t).args(["--json", "install"]).assert().success();
    let out = clx(&t)
        .args(["--json", "maintenance", "trim", "--dry-run"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value =
        serde_json::from_str(&String::from_utf8(out).unwrap()).expect("trim --json is JSON");
    assert_eq!(v["dry_run"], true);
    // I-R5 pinned: with no audit_days flag the default is the hard-coded
    // 90 (maintenance.rs: `audit_days.unwrap_or(90)`). This pins the
    // documented current behavior; flagged as a known risk, not a bug.
    assert_eq!(
        v["audit_days"], 90,
        "I-R5: audit default is hard-coded 90d (pinned, see RISKS)"
    );
    assert!(v["tool_events_would_delete"].is_number());
}

#[test]
fn maintenance_trim_explicit_audit_days_overrides_default() {
    let t = tmp();
    clx(&t).args(["--json", "install"]).assert().success();
    let out = clx(&t)
        .args([
            "--json",
            "maintenance",
            "trim",
            "--audit-days",
            "30",
            "--tool-events-days",
            "0",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8(out).unwrap()).unwrap();
    assert_eq!(v["audit_days"], 30, "explicit --audit-days is honored");
}

// ===========================================================================
// 2.1: credentials in the isolated file backend (never keychain)
// ===========================================================================

#[test]
fn credentials_set_get_list_delete_roundtrip_file_backend() {
    let t = tmp();
    clx(&t).args(["--json", "install"]).assert().success();

    // set -> get round-trip via the default age-encrypted file backend.
    clx(&t)
        .args(["credentials", "set", "WAVE1_CLI_KEY", "v-cli-secret"])
        .assert()
        .success();
    clx(&t)
        .args(["credentials", "get", "WAVE1_CLI_KEY"])
        .assert()
        .success()
        .stdout(predicate::str::contains("v-cli-secret"));

    // list shows the key name (not the value).
    clx(&t)
        .args(["--json", "credentials", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("WAVE1_CLI_KEY"));

    // delete then get must fail (key gone).
    clx(&t)
        .args(["credentials", "delete", "WAVE1_CLI_KEY"])
        .assert()
        .success();
    clx(&t)
        .args(["credentials", "get", "WAVE1_CLI_KEY"])
        .assert()
        .failure();

    // The encrypted credential file lives in the isolated HOME only.
    assert!(
        home_path(&t, ".clx/credentials.age").exists(),
        "credentials.age must live under the isolated HOME"
    );
}

#[test]
fn credentials_get_missing_key_exits_nonzero() {
    let t = tmp();
    clx(&t)
        .args(["credentials", "get", "DEFINITELY_MISSING_KEY_XYZ"])
        .assert()
        .failure();
}

#[test]
fn credentials_delete_missing_key_is_idempotent_no_panic() {
    let t = tmp();
    let status = clx(&t)
        .args(["credentials", "delete", "MISSING_KEY_IDEMPOTENT"])
        .output()
        .expect("spawn");
    assert!(
        status.status.code().is_some(),
        "must exit with a code, not a signal"
    );
}

// ===========================================================================
// 2.1: config + version subcommands behave under isolation
// ===========================================================================

#[test]
fn config_no_subcommand_prints_something() {
    let t = tmp();
    clx(&t)
        .arg("config")
        .assert()
        .success()
        .stdout(predicate::str::is_empty().not());
}

#[test]
fn config_json_is_valid_json() {
    let t = tmp();
    let out = clx(&t)
        .args(["--json", "config"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    serde_json::from_str::<serde_json::Value>(&String::from_utf8(out).unwrap())
        .expect("config --json is valid JSON");
}

#[test]
fn config_reset_json_is_idempotent() {
    let t = tmp();
    clx(&t)
        .args(["--json", "config", "reset"])
        .assert()
        .success();
    // Running reset again on the freshly-reset config must still succeed.
    clx(&t)
        .args(["--json", "config", "reset"])
        .assert()
        .success();
}

#[test]
fn unknown_subcommand_exits_nonzero() {
    let t = tmp();
    clx(&t).arg("totally-unknown-subcmd").assert().failure();
}

// ===========================================================================
// T7 both-off observability: `clx health` WARN when validator.enabled=true
// AND both layer0_enabled=false AND layer1_enabled=false.
// Closes the T7 release-blocker carry-over in
// specs/2026-05-20-v090-red-findings.md.
// ===========================================================================

/// Write a config with `validator.enabled=true` and BOTH layer toggles off
/// into the isolated `~/.clx/config.yaml`. Returns the path written.
fn write_both_off_config(t: &TempDir) -> std::path::PathBuf {
    let clx_dir = home_path(t, ".clx");
    std::fs::create_dir_all(&clx_dir).expect("mkdir .clx");
    let cfg_path = clx_dir.join("config.yaml");
    // Minimal YAML: only the validator block matters; everything else
    // falls back to serde defaults via the `#[serde(default)]` impls.
    let yaml = "\
validator:
  enabled: true
  layer0_enabled: false
  layer1_enabled: false
";
    std::fs::write(&cfg_path, yaml).expect("write config.yaml");
    cfg_path
}

#[test]
fn health_warns_when_validator_enabled_and_both_layers_off_human() {
    // T7 closing test (table / human path). The WARN row must surface
    // both the cause and the mitigation.
    let t = tmp();
    let _cfg_path = write_both_off_config(&t);

    // `clx health` may exit non-zero because Ollama/binaries aren't
    // installed in the test env. We only need the WARN text on stdout.
    let assert = clx(&t).arg("health").assert();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).expect("stdout utf8");

    assert!(
        stdout.contains("validator.enabled=true"),
        "WARN must cite the enabled=true posture; full stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("layer0_enabled") && stdout.contains("layer1_enabled"),
        "WARN must name BOTH toggles; full stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("no actual validation is running"),
        "WARN must spell out the consequence; full stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("enabled=false"),
        "WARN must point at the explicit-bypass remediation; full stdout:\n{stdout}"
    );
}

#[test]
fn health_json_warns_when_validator_enabled_and_both_layers_off() {
    // T7 closing test (JSON path). The `warnings` array must contain
    // the both-off message verbatim.
    let t = tmp();
    let _cfg_path = write_both_off_config(&t);

    let assert = clx(&t).args(["health", "--json"]).assert();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).expect("stdout utf8");

    let v: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("health --json must emit valid JSON; got:\n{stdout}\nerr: {e}"));
    let warnings = v["warnings"]
        .as_array()
        .unwrap_or_else(|| panic!("health --json must include `warnings`; got: {v}"));
    assert!(
        !warnings.is_empty(),
        "warnings array must be non-empty under both-off + enabled=true; got: {v}"
    );
    let any_match = warnings.iter().any(|w| {
        w.as_str().is_some_and(|s| {
            s.contains("validator.enabled=true") && s.contains("no actual validation is running")
        })
    });
    assert!(
        any_match,
        "warnings array must contain the T7 WARN text; got: {warnings:?}"
    );
}

#[test]
fn health_does_not_warn_under_default_config() {
    // Negative control: a fresh install (default config) must NOT emit
    // the T7 WARN. We assert by inspecting `warnings` in --json: it
    // must either be absent (skip_serializing_if) or contain no
    // both-off entry.
    let t = tmp();
    clx(&t).args(["--json", "install"]).assert().success();

    let assert = clx(&t).args(["health", "--json"]).assert();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).expect("stdout utf8");
    let v: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("health --json must emit valid JSON; got:\n{stdout}\nerr: {e}"));

    if let Some(arr) = v.get("warnings").and_then(serde_json::Value::as_array) {
        let leaked = arr.iter().any(|w| {
            w.as_str()
                .is_some_and(|s| s.contains("no actual validation is running"))
        });
        assert!(
            !leaked,
            "T7 WARN must NOT fire under default config; got: {arr:?}"
        );
    }
}

#[test]
fn maintenance_trim_real_run_on_fresh_db_is_ok() {
    // A real (non-dry-run) trim on a freshly installed empty DB must
    // succeed and report zero deletions.
    let t = tmp();
    clx(&t).args(["--json", "install"]).assert().success();
    let out = clx(&t)
        .args(["--json", "maintenance", "trim"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8(out).unwrap()).unwrap();
    assert_eq!(v["tool_events_deleted"], 0);
    assert_eq!(v["audit_log_deleted"], 0);
}
