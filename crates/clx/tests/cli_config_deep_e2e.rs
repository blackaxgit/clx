//! Wave: `clx config` DEEP e2e tests -- mutation/success pipelines.
//!
//! The existing `cli_config_e2e.rs` covers the bare-print, `--json`,
//! reset (`--json` skips the prompt), malformed-yaml failure, and the
//! two `migrate` failure guards. It never drives:
//!   * `ConfigAction::Edit` success (config.rs:43-92) -- the editor is
//!     spawned and exits 0, plus the "create default if missing" arm and
//!     the human "Opening ... with ..." arm.
//!   * `ConfigAction::Reset` interactive arm (config.rs:99-113) -- the
//!     y/N prompt, both the confirmed-write and the cancelled paths.
//!   * `migrate()` SUCCESS (config.rs:177-213) -- legacy `ollama:` block
//!     translated to `providers:`/`llm:`, `.bak` written, atomic replace.
//!
//! Isolation: HOME + XDG redirected into a fresh RAII `tempfile::TempDir`.
//! The "editor" is a throwaway shell script inside the same tempdir, so
//! nothing escapes the sandbox and there is no interactive blocking.

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

fn home_path(t: &TempDir, rel: &str) -> std::path::PathBuf {
    t.path().join(rel)
}

/// Write an executable noop "editor" into the tempdir and return its path
/// as a string. Exiting 0 makes the `status.success()` check pass.
fn noop_editor(t: &TempDir) -> String {
    let p = t.path().join("noop-editor.sh");
    std::fs::write(&p, "#!/bin/sh\nexit 0\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&p).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&p, perms).unwrap();
    }
    p.display().to_string()
}

/// An "editor" that appends a sentinel line to the file it is given, so a
/// reread can prove the edit pipeline reached the file.
fn writing_editor(t: &TempDir) -> String {
    let p = t.path().join("writing-editor.sh");
    std::fs::write(
        &p,
        "#!/bin/sh\nprintf '\\n# clx-edit-sentinel: touched\\n' >> \"$1\"\nexit 0\n",
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&p).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&p, perms).unwrap();
    }
    p.display().to_string()
}

/// An "editor" that exits non-zero, driving the `!status.success()`
/// bail arm of `ConfigAction::Edit`.
fn failing_editor(t: &TempDir) -> String {
    let p = t.path().join("failing-editor.sh");
    std::fs::write(&p, "#!/bin/sh\nexit 3\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&p).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&p, perms).unwrap();
    }
    p.display().to_string()
}

// ===========================================================================
// ConfigAction::Edit success (config.rs:43-92)
// ===========================================================================

#[test]
fn config_edit_creates_default_then_opens_editor_json() {
    // Fresh HOME: no config.yaml -> the "create default" arm writes it,
    // then the editor (noop, exit 0) is spawned. `--json` arm prints the
    // edit action object with path + editor.
    let t = tmp();
    let editor = noop_editor(&t);
    let out = clx(&t)
        .env("EDITOR", &editor)
        .args(["--json", "config", "edit"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value =
        serde_json::from_str(&String::from_utf8(out).unwrap()).expect("edit --json is JSON");
    assert_eq!(v["action"], "edit");
    assert_eq!(v["editor"], editor);
    assert!(
        home_path(&t, ".clx/config.yaml").exists(),
        "edit must create the default config when absent"
    );
}

#[test]
fn config_edit_human_arm_prints_opening_message() {
    // Human (non-json) arm: "Created default config" + "Opening ... with".
    let t = tmp();
    let editor = noop_editor(&t);
    clx(&t)
        .env("EDITOR", &editor)
        .args(["config", "edit"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Created default config at:"))
        .stdout(predicate::str::contains("Opening"))
        .stdout(predicate::str::contains("with"));
}

#[test]
fn config_edit_actually_reaches_the_file_on_disk() {
    // A writing editor proves the spawned process received the real
    // config path: the sentinel line is present on reread.
    let t = tmp();
    let editor = writing_editor(&t);
    clx(&t)
        .env("EDITOR", &editor)
        .args(["config", "edit"])
        .assert()
        .success();
    let body = std::fs::read_to_string(home_path(&t, ".clx/config.yaml")).unwrap();
    assert!(
        body.contains("# clx-edit-sentinel: touched"),
        "editor must have been handed the real config path; got:\n{body}"
    );
}

#[test]
fn config_edit_bails_when_editor_exits_nonzero() {
    // `!status.success()` arm: editor exits 3 -> command fails with the
    // "Editor exited with non-zero status" anyhow message, not a panic.
    let t = tmp();
    let editor = failing_editor(&t);
    clx(&t)
        .env("EDITOR", &editor)
        .args(["config", "edit"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "Editor exited with non-zero status",
        ));
}

#[test]
fn config_edit_does_not_recreate_an_existing_config() {
    // Second arm of the "exists?" check: a pre-existing config.yaml is
    // left untouched (no "Created default config" line).
    let t = tmp();
    let cfg_dir = home_path(&t, ".clx");
    std::fs::create_dir_all(&cfg_dir).unwrap();
    std::fs::write(cfg_dir.join("config.yaml"), "validator:\n  enabled: true\n").unwrap();
    let editor = noop_editor(&t);
    clx(&t)
        .env("EDITOR", &editor)
        .args(["config", "edit"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Created default config").not());
}

// ===========================================================================
// ConfigAction::Reset interactive arm (config.rs:99-113)
// ===========================================================================

#[test]
fn config_reset_interactive_confirm_writes_default() {
    // Human reset with stdin "y": the prompt is shown, the file is
    // written, and the success line is printed.
    let t = tmp();
    clx(&t)
        .args(["config", "reset"])
        .write_stdin("y\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("Reset configuration to defaults?"))
        .stdout(predicate::str::contains("Configuration reset to defaults."));
    assert!(
        home_path(&t, ".clx/config.yaml").exists(),
        "confirmed reset must write config.yaml"
    );
}

#[test]
fn config_reset_interactive_decline_cancels_without_writing() {
    // stdin "n": the cancel arm prints "Cancelled." and writes nothing.
    let t = tmp();
    clx(&t)
        .args(["config", "reset"])
        .write_stdin("n\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("Cancelled."));
    assert!(
        !home_path(&t, ".clx/config.yaml").exists(),
        "declined reset must NOT create config.yaml"
    );
}

// ===========================================================================
// migrate() SUCCESS (config.rs:177-213)
// ===========================================================================

#[test]
fn config_migrate_legacy_ollama_block_succeeds_and_backs_up() {
    // Seed a legacy `ollama:`-only config. migrate() must translate it to
    // the new `providers:`/`llm:` schema, write a `.bak`, atomically
    // replace the file, and (here) emit the `--json` success object.
    let t = tmp();
    let cfg_dir = home_path(&t, ".clx");
    std::fs::create_dir_all(&cfg_dir).unwrap();
    std::fs::write(
        cfg_dir.join("config.yaml"),
        concat!(
            "ollama:\n",
            "  host: \"http://localhost:11434\"\n",
            "  model: \"qwen2.5:3b\"\n",
            "  embedding_model: \"nomic-embed-text\"\n",
            "  embedding_dim: 768\n",
        ),
    )
    .unwrap();
    let out = clx(&t)
        .args(["--json", "config", "migrate"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value =
        serde_json::from_str(&String::from_utf8(out).unwrap()).expect("migrate --json is JSON");
    assert_eq!(v["action"], "migrate");
    assert_eq!(v["success"], true);

    // Backup exists and the migrated file now carries the new schema.
    assert!(
        cfg_dir.join("config.yaml.bak").exists(),
        "migrate must write a .bak backup"
    );
    let migrated = std::fs::read_to_string(cfg_dir.join("config.yaml")).unwrap();
    let parsed: serde_yml::Value = serde_yml::from_str(&migrated).unwrap();
    assert!(
        parsed
            .get("providers")
            .is_some_and(serde_yml::Value::is_mapping),
        "migrated config must have a providers: mapping; got:\n{migrated}"
    );
    assert!(
        parsed.get("llm").is_some_and(serde_yml::Value::is_mapping),
        "migrated config must have an llm: routing block; got:\n{migrated}"
    );
}

#[test]
fn config_migrate_legacy_human_arm_reports_backup_path() {
    // Non-json arm of migrate() success: "migrated config; backup at ...".
    let t = tmp();
    let cfg_dir = home_path(&t, ".clx");
    std::fs::create_dir_all(&cfg_dir).unwrap();
    std::fs::write(
        cfg_dir.join("config.yaml"),
        "ollama:\n  host: \"http://localhost:11434\"\n  embedding_dim: 768\n",
    )
    .unwrap();
    clx(&t)
        .args(["config", "migrate"])
        .assert()
        .success()
        .stdout(predicate::str::contains("migrated config; backup at"));
}

#[test]
fn config_migrate_then_reread_round_trips_through_loader() {
    // After a successful migrate the bare `config --json` must still load
    // cleanly (the written schema is valid for the normal loader path).
    let t = tmp();
    let cfg_dir = home_path(&t, ".clx");
    std::fs::create_dir_all(&cfg_dir).unwrap();
    std::fs::write(
        cfg_dir.join("config.yaml"),
        "ollama:\n  host: \"http://localhost:11434\"\n  embedding_dim: 768\n",
    )
    .unwrap();
    clx(&t)
        .args(["--json", "config", "migrate"])
        .assert()
        .success();
    let out = clx(&t)
        .args(["--json", "config"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8(out).unwrap())
        .expect("post-migrate config --json must still be valid JSON");
    assert!(v.is_object());
}
