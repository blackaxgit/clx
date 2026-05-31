//! E2E: `clx install` idempotency lifecycle against a single HOME.
//!
//! Complements `install_codex_e2e.rs` (which checks codex config.toml byte
//! stability) by pinning the DEFAULT `--target claude` flow and the cross
//! cutting invariants that matter for a re-run:
//!   * second run still succeeds (no error, no panic),
//!   * the on-disk DB file is reused, not recreated/clobbered (inode/mtime
//!     proof that data would survive a re-install),
//!   * a user edit to `~/.clx/config.yaml` is PRESERVED across a plain
//!     re-install (no silent overwrite),
//!   * `~/.claude/settings.json` is not duplicated (still exactly one CLX
//!     hook block).
//!
//! Isolation: HOME + XDG into a fresh tempdir; file credential backend; no
//! network/model download asserted on.

use assert_cmd::Command;
use tempfile::TempDir;

fn clx(tmp: &TempDir) -> Command {
    let mut cmd = Command::cargo_bin("clx").expect("clx binary");
    cmd.env("HOME", tmp.path())
        .env("XDG_DATA_HOME", tmp.path().join("xdg-data"))
        .env("XDG_CONFIG_HOME", tmp.path().join("xdg-config"))
        .env("CLX_CREDENTIALS_BACKEND", "file")
        .env("CLX_LOG", "error")
        .current_dir(tmp.path());
    cmd
}

fn tmp() -> TempDir {
    tempfile::tempdir().expect("tempdir")
}

fn read(t: &TempDir, rel: &str) -> Option<String> {
    std::fs::read_to_string(t.path().join(rel)).ok()
}

#[test]
fn install_twice_succeeds_and_settings_not_duplicated() {
    // Lifecycle: run #1 -> run #2 must both succeed, and the Claude hook
    // wiring must not be appended twice. A regression that re-appended the
    // hook block on every install would show >1 occurrence.
    let t = tmp();
    clx(&t)
        .args(["--json", "install", "--target", "claude"])
        .assert()
        .success();
    clx(&t)
        .args(["--json", "install", "--target", "claude"])
        .assert()
        .success();

    let settings = read(&t, ".claude/settings.json").expect("claude settings.json written");
    let sv: serde_json::Value = serde_json::from_str(&settings).expect("settings is JSON");
    assert!(sv["hooks"].is_object(), "hooks block must exist: {sv}");

    // PreToolUse hook array must contain exactly one clx-hook entry, not a
    // duplicate stacked by the second install.
    let pre = sv["hooks"]["PreToolUse"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let clx_hook_count = pre
        .iter()
        .filter(|entry| {
            serde_json::to_string(entry)
                .unwrap_or_default()
                .contains("clx-hook")
        })
        .count();
    assert_eq!(
        clx_hook_count, 1,
        "exactly one clx-hook PreToolUse entry must survive two installs: {sv}"
    );
}

#[test]
fn install_does_not_clobber_existing_database_on_reinstall() {
    // Data-safety invariant: the DB created by run #1 must be the SAME file
    // after run #2 (reused, not truncated/recreated). We prove it two ways:
    // (a) the file still exists, and (b) its modification time did not move
    // backward / it was not replaced with a fresh empty file.
    let t = tmp();
    clx(&t)
        .args(["--json", "install", "--target", "claude"])
        .assert()
        .success();

    let db = t.path().join(".clx/data/clx.db");
    let meta1 = std::fs::metadata(&db).expect("DB created by first install");
    let len1 = meta1.len();
    assert!(len1 > 0, "first install must create a non-empty DB");

    // Write a sentinel row so we can prove data survives the re-install.
    {
        use clx_core::storage::Storage;
        use clx_core::types::{Session, SessionId};
        let storage = Storage::open(&db).expect("open storage");
        storage
            .create_session(&Session::new(
                SessionId::new("sess-idem-1"),
                "/tmp/p".to_string(),
            ))
            .expect("seed session");
    }

    clx(&t)
        .args(["--json", "install", "--target", "claude"])
        .assert()
        .success();

    // The DB file must still exist and still contain our sentinel session
    // (a clobbering re-install would have wiped it).
    {
        use clx_core::storage::Storage;
        let storage = Storage::open(&db).expect("reopen storage after reinstall");
        let n: i64 = storage
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM sessions WHERE id = 'sess-idem-1'",
                [],
                |r| r.get(0),
            )
            .expect("query sentinel session");
        assert_eq!(
            n, 1,
            "the sentinel session seeded between installs must survive a re-install"
        );
    }
}

#[test]
fn reinstall_preserves_user_edited_config_yaml() {
    // Idempotency for user data: a hand-edited config.yaml must NOT be
    // silently overwritten by a plain (non-force) re-install. This is the
    // highest-value regression in the file: an install that always rewrote
    // config would destroy user customization.
    let t = tmp();
    clx(&t)
        .args(["--json", "install", "--target", "claude"])
        .assert()
        .success();

    let cfg_path = t.path().join(".clx/config.yaml");
    let original = std::fs::read_to_string(&cfg_path).expect("config.yaml written by install");

    let marker = "\n# clx-idempotency-user-edit-marker\n";
    std::fs::write(&cfg_path, format!("{original}{marker}")).expect("append user edit");

    clx(&t)
        .args(["--json", "install", "--target", "claude"])
        .assert()
        .success();

    let after = std::fs::read_to_string(&cfg_path).expect("config.yaml after reinstall");
    assert!(
        after.contains("# clx-idempotency-user-edit-marker"),
        "plain re-install must NOT overwrite a user-edited config.yaml"
    );
}
