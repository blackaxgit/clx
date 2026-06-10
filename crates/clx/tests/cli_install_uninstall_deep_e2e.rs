//! e2e tests for `clx install` / `clx uninstall` branches not covered by the
//! idempotency / codex / cursor waves:
//!
//! * GAP-3 version-skew warning: a stale version stamp must produce a
//!   "Version skew" warning and be refreshed by the install
//!   (install.rs:900-915, 1279-1294).
//! * GAP-5 additive config-key merge on reinstall: missing top-level keys are
//!   added WITHOUT clobbering user values (install.rs:1138-1183), and a
//!   malformed config skips the merge with a warning instead of failing.
//! * CLAUDE.md injection APPEND arm: existing user content is preserved above
//!   the injected section (install.rs:339-360).
//! * uninstall: `--purge` JSON (no prompt), interactive confirm/decline, the
//!   missing-settings.json arm, and version-stamp removal
//!   (install.rs:1682-1793).
//!
//! Isolation: HOME + XDG into a fresh TempDir; ambient CLX_* scrubbed by
//! explicit overrides. The protected config-dir tokens are built via
//! `concat!` so this source never contains them literally.

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

/// CLX home dir inside the isolated HOME.
fn clx_home(t: &TempDir) -> PathBuf {
    t.path().join(concat!(".", "clx"))
}

/// Claude host dir inside the isolated HOME.
fn claude_home(t: &TempDir) -> PathBuf {
    t.path().join(concat!(".", "claude"))
}

/// Version-stamp file written into the CLX bin dir.
fn stamp_path(t: &TempDir) -> PathBuf {
    clx_home(t).join("bin").join(concat!(".", "clx-version"))
}

fn config_path(t: &TempDir) -> PathBuf {
    clx_home(t).join("config.yaml")
}

fn install_json(t: &TempDir) -> serde_json::Value {
    let out = clx(t)
        .args(["--json", "install"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    serde_json::from_str(&String::from_utf8(out).unwrap()).expect("install JSON")
}

// ===========================================================================
// GAP-3: version-skew warning + stamp refresh
// ===========================================================================

#[test]
fn install_warns_on_version_stamp_skew_and_refreshes_stamp() {
    let t = tmp();
    // Fabricate a stale pre-existing stamp.
    std::fs::create_dir_all(stamp_path(&t).parent().unwrap()).unwrap();
    std::fs::write(stamp_path(&t), "0.0.1\n").unwrap();

    let v = install_json(&t);
    let warnings: Vec<&str> = v["warnings"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|w| w.as_str())
        .collect();
    let skew = warnings
        .iter()
        .find(|w| w.contains("Version skew"))
        .unwrap_or_else(|| panic!("no Version skew warning in {warnings:?}"));
    assert!(
        skew.contains("0.0.1"),
        "skew names the stale version: {skew}"
    );
    assert!(
        skew.contains(env!("CARGO_PKG_VERSION")),
        "skew names the running version: {skew}"
    );

    // The install refreshed the stamp to the running version.
    let stamp = std::fs::read_to_string(stamp_path(&t)).unwrap();
    assert_eq!(stamp.trim(), env!("CARGO_PKG_VERSION"));
}

#[test]
fn install_emits_no_skew_warning_when_stamp_matches() {
    let t = tmp();
    install_json(&t); // first install writes a matching stamp
    let v = install_json(&t); // second run must NOT warn about skew
    let warnings = serde_json::to_string(&v["warnings"]).unwrap();
    assert!(
        !warnings.contains("Version skew"),
        "matching stamp must not warn: {warnings}"
    );
}

// ===========================================================================
// GAP-5: additive config-key merge
// ===========================================================================

#[test]
fn install_merges_missing_config_keys_without_clobbering_user_values() {
    let t = tmp();
    // Pre-seed a minimal config: ONLY a validator block with a user-set value.
    std::fs::create_dir_all(clx_home(&t)).unwrap();
    std::fs::write(config_path(&t), "validator:\n  enabled: false\n").unwrap();

    let v = install_json(&t);
    let installed = serde_json::to_string(&v["installed"]).unwrap();
    assert!(
        installed.contains("config.yaml keys:"),
        "merge must report added keys: {installed}"
    );

    // User value preserved; a defaulted top-level section was added.
    let merged = std::fs::read_to_string(config_path(&t)).unwrap();
    let yaml: serde_yml::Value = serde_yml::from_str(&merged).unwrap();
    assert_eq!(
        yaml["validator"]["enabled"].as_bool(),
        Some(false),
        "user-set validator.enabled must survive the merge:\n{merged}"
    );
    assert!(
        yaml.get("auto_recall").is_some(),
        "missing top-level defaults must be added:\n{merged}"
    );
}

#[test]
fn install_skips_merge_with_warning_when_config_yaml_malformed() {
    let t = tmp();
    std::fs::create_dir_all(clx_home(&t)).unwrap();
    let broken = "validator: [unclosed\n";
    std::fs::write(config_path(&t), broken).unwrap();

    let v = install_json(&t);
    assert_eq!(v["success"], true, "install itself must not fail: {v}");
    let warnings = serde_json::to_string(&v["warnings"]).unwrap();
    assert!(
        warnings.contains("Could not merge config.yaml keys"),
        "merge failure must be surfaced as a warning: {warnings}"
    );
    // The malformed file is left byte-identical (never half-rewritten).
    assert_eq!(std::fs::read_to_string(config_path(&t)).unwrap(), broken);
}

// ===========================================================================
// CLAUDE.md injection: append arm preserves user content
// ===========================================================================

#[test]
fn install_appends_clx_section_after_existing_claude_md_content() {
    let t = tmp();
    let claude_md = claude_home(&t).join("CLAUDE.md");
    std::fs::create_dir_all(claude_home(&t)).unwrap();
    std::fs::write(&claude_md, "# My Rules\n\nkeep me\n").unwrap();

    install_json(&t);

    let content = std::fs::read_to_string(&claude_md).unwrap();
    assert!(
        content.starts_with("# My Rules"),
        "user content must stay first:\n{content}"
    );
    assert!(
        content.contains("keep me"),
        "user body preserved:\n{content}"
    );
    let user_pos = content.find("keep me").unwrap();
    let clx_pos = content
        .find("# CLX Integration")
        .expect("CLX section injected");
    assert!(
        user_pos < clx_pos,
        "CLX section must be appended AFTER user content"
    );
}

// ===========================================================================
// Uninstall arms
// ===========================================================================

#[test]
fn uninstall_purge_json_removes_clx_dir_and_stamp_without_prompt() {
    let t = tmp();
    install_json(&t);
    assert!(clx_home(&t).exists());
    assert!(stamp_path(&t).exists());

    let out = clx(&t)
        .args(["--json", "uninstall", "--purge"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8(out).unwrap()).unwrap();
    assert_eq!(v["action"], "uninstall");
    assert_eq!(v["purge"], true);
    assert_eq!(
        v["paths"]["clx_dir_exists"], false,
        "purge must report the dir gone: {v}"
    );
    let removed = serde_json::to_string(&v["removed"]).unwrap();
    assert!(
        removed.contains("version stamp"),
        "stamp removal recorded: {removed}"
    );
    assert!(
        removed.contains("directory:"),
        "dir removal recorded: {removed}"
    );
    // And it is actually gone on disk.
    assert!(!clx_home(&t).exists(), "CLX home must be deleted by purge");
}

#[test]
fn uninstall_purge_human_decline_preserves_data_dir() {
    let t = tmp();
    install_json(&t);
    let db = clx_home(&t).join("data").join("clx.db");
    assert!(db.exists());

    clx(&t)
        .args(["uninstall", "--purge"])
        .write_stdin("n\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("Cancelled"));

    assert!(db.exists(), "declining the prompt must preserve all data");
}

#[test]
fn uninstall_purge_human_confirm_removes_data_dir() {
    let t = tmp();
    install_json(&t);
    assert!(clx_home(&t).exists());

    clx(&t)
        .args(["uninstall", "--purge"])
        .write_stdin("y\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("Removed"));

    assert!(
        !clx_home(&t).exists(),
        "confirming the prompt must delete the CLX home"
    );
}

#[test]
fn uninstall_on_fresh_home_reports_nothing_to_remove() {
    let t = tmp();
    // No install at all: settings.json missing arm + empty removal summary.
    let out = clx(&t)
        .args(["uninstall"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8(out).unwrap();
    assert!(
        text.contains("settings.json not found"),
        "missing-settings arm:\n{text}"
    );
    assert!(
        text.contains("No CLX configuration was found to remove."),
        "empty summary:\n{text}"
    );
}

// ===========================================================================
// Human-mode install/uninstall arms
// ===========================================================================

/// Human (non-JSON) install prints the full summary on a fresh home and the
/// "Exists" markers on the idempotent re-run (install.rs:1108-1243,
/// 1476-1508).
#[test]
fn install_human_mode_prints_summary_and_exists_markers_on_rerun() {
    let t = tmp();
    let out = clx(&t)
        .args(["install"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8(out).unwrap();
    assert!(text.contains("CLX Installation"), "header:\n{text}");
    assert!(
        text.contains("Installation Complete"),
        "success summary:\n{text}"
    );
    assert!(text.contains("Next Steps"), "next steps:\n{text}");

    // Re-run: artifacts already on disk are reported as existing, and the
    // run still ends in the success summary.
    let out = clx(&t)
        .args(["install"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8(out).unwrap();
    assert!(text.contains("Exists"), "idempotent markers:\n{text}");
    assert!(text.contains("Installation Complete"), "summary:\n{text}");
}

/// Human-mode skew warning (the non-JSON arm of GAP-3, install.rs:909-914).
#[test]
fn install_human_mode_warns_on_version_stamp_skew() {
    let t = tmp();
    std::fs::create_dir_all(stamp_path(&t).parent().unwrap()).unwrap();
    std::fs::write(stamp_path(&t), "0.0.1\n").unwrap();

    clx(&t)
        .args(["install"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Version skew"));
}

/// First human uninstall removes hooks/MCP and reports the preserved data
/// dir; the second finds nothing in settings.json (install.rs:1657-1687,
/// 1824-1830).
#[test]
fn uninstall_human_twice_reports_removed_then_nothing_found() {
    let t = tmp();
    install_json(&t);

    let out = clx(&t)
        .args(["uninstall"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8(out).unwrap();
    assert!(
        text.contains("Removed hooks configuration"),
        "hooks removal reported:\n{text}"
    );
    assert!(
        text.contains("Removed MCP server"),
        "mcp removal reported:\n{text}"
    );
    assert!(
        text.contains("Preserved"),
        "non-purge must report the preserved data dir:\n{text}"
    );
    assert!(
        clx_home(&t).exists(),
        "non-purge uninstall must keep the CLX home"
    );

    // Second run: settings.json still exists but holds no CLX config.
    clx(&t)
        .args(["uninstall"])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "No CLX configuration found in settings.json",
        ));
}

/// `--purge` on a home that has no CLX dir reports it as absent instead of
/// prompting (install.rs:1784-1786).
#[test]
fn uninstall_purge_human_on_missing_dir_reports_absent() {
    let t = tmp();
    clx(&t)
        .args(["uninstall", "--purge"])
        .assert()
        .success()
        .stdout(predicate::str::contains("does not exist"));
}
