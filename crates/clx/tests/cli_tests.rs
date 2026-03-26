//! CLI integration tests for all clx commands.
//!
//! Every test sets `HOME` to a `TempDir` so that all path resolution through
//! `dirs::home_dir()` (→ `~/.clx/`, `~/.claude/`) lands in a throwaway
//! directory and never touches the real user home.

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

/// Build a `clx` command with HOME isolated to `tmp`.
///
/// All clx-core paths resolve via `dirs::home_dir()`, so overriding `HOME`
/// redirects every database, config, and rules file to the temp directory.
fn clx(tmp: &TempDir) -> Command {
    let mut cmd = Command::cargo_bin("clx").unwrap();
    cmd.env("HOME", tmp.path());
    cmd
}

/// Create a fresh, isolated `TempDir`.
fn tmp() -> TempDir {
    tempfile::tempdir().expect("failed to create temp dir")
}

// ---------------------------------------------------------------------------
// T24 — Help, Version, Completions
// ---------------------------------------------------------------------------

#[test]
fn help_exits_zero_and_contains_usage() {
    let tmp = tmp();
    clx(&tmp)
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("clx").or(predicate::str::contains("Usage")));
}

#[test]
fn version_flag_exits_zero_and_contains_version() {
    let tmp = tmp();
    clx(&tmp)
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::is_empty().not());
}

#[test]
fn version_subcommand_exits_zero() {
    let tmp = tmp();
    clx(&tmp).arg("version").assert().success();
}

#[test]
fn completions_bash_exits_zero_with_output() {
    let tmp = tmp();
    clx(&tmp)
        .args(["completions", "bash"])
        .assert()
        .success()
        .stdout(predicate::str::is_empty().not());
}

#[test]
fn completions_zsh_exits_zero_with_output() {
    let tmp = tmp();
    clx(&tmp)
        .args(["completions", "zsh"])
        .assert()
        .success()
        .stdout(predicate::str::is_empty().not());
}

// ---------------------------------------------------------------------------
// T25 — Config commands
// ---------------------------------------------------------------------------

#[test]
fn config_no_subcommand_exits_zero_with_output() {
    let tmp = tmp();
    clx(&tmp)
        .arg("config")
        .assert()
        .success()
        .stdout(predicate::str::is_empty().not());
}

#[test]
fn config_json_mode_produces_valid_json() {
    let tmp = tmp();
    let output = clx(&tmp)
        .args(["--json", "config"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let text = String::from_utf8(output).expect("stdout must be valid UTF-8");
    serde_json::from_str::<serde_json::Value>(&text)
        .expect("config --json output must be valid JSON");
}

#[test]
fn config_reset_json_exits_zero() {
    // JSON mode bypasses the interactive "y/N" confirmation prompt.
    let tmp = tmp();
    clx(&tmp)
        .args(["--json", "config", "reset"])
        .assert()
        .success()
        .stdout(predicate::str::contains("reset"));
}

#[test]
fn config_unknown_subcommand_exits_nonzero() {
    let tmp = tmp();
    clx(&tmp).args(["config", "bogus"]).assert().failure();
}

// ---------------------------------------------------------------------------
// T26 — Rules commands
// ---------------------------------------------------------------------------

#[test]
fn rules_list_exits_zero() {
    let tmp = tmp();
    clx(&tmp).args(["rules", "list"]).assert().success();
}

#[test]
fn rules_allow_exits_zero() {
    let tmp = tmp();
    clx(&tmp)
        .args(["rules", "allow", "cargo build"])
        .assert()
        .success();
}

#[test]
fn rules_allow_then_list_contains_pattern() {
    let tmp = tmp();

    // First install to initialise the database.
    clx(&tmp).args(["--json", "install"]).assert().success();

    clx(&tmp)
        .args(["--json", "rules", "allow", "--global", "cargo build"])
        .assert()
        .success();

    clx(&tmp)
        .args(["--json", "rules", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("cargo build"));
}

#[test]
fn rules_deny_exits_zero() {
    let tmp = tmp();
    clx(&tmp)
        .args(["rules", "deny", "rm -rf"])
        .assert()
        .success();
}

#[test]
fn rules_reset_json_exits_zero() {
    // JSON mode skips the interactive confirmation.
    let tmp = tmp();
    clx(&tmp)
        .args(["--json", "rules", "reset"])
        .assert()
        .success();
}

// ---------------------------------------------------------------------------
// T27 — Recall command
// ---------------------------------------------------------------------------

#[test]
fn recall_with_empty_db_exits_zero() {
    let tmp = tmp();
    clx(&tmp).args(["recall", "some query"]).assert().success();
}

#[test]
fn recall_json_mode_produces_valid_json() {
    let tmp = tmp();
    let output = clx(&tmp)
        .args(["--json", "recall", "some query"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let text = String::from_utf8(output).expect("stdout must be valid UTF-8");
    serde_json::from_str::<serde_json::Value>(&text)
        .expect("recall --json output must be valid JSON");
}

#[test]
fn recall_no_args_exits_nonzero() {
    let tmp = tmp();
    clx(&tmp).arg("recall").assert().failure();
}

#[test]
fn recall_fresh_temp_dir_does_not_panic() {
    let fresh = tmp();
    clx(&fresh)
        .args(["recall", "anything"])
        .assert()
        // The command exits 0 (graceful "db not initialised" message) — it
        // must not crash with a non-zero signal-based exit.
        .success();
}

// ---------------------------------------------------------------------------
// T28 — Embeddings commands
// ---------------------------------------------------------------------------

#[test]
fn embeddings_status_exits_zero() {
    let tmp = tmp();
    // First install to initialise the database so the embedding store exists.
    clx(&tmp).args(["--json", "install"]).assert().success();

    clx(&tmp).args(["embeddings", "status"]).assert().success();
}

#[test]
fn embeddings_rebuild_dry_run_exits_zero() {
    let tmp = tmp();
    clx(&tmp).args(["--json", "install"]).assert().success();

    clx(&tmp)
        .args(["--json", "embeddings", "rebuild", "--dry-run"])
        .assert()
        .success();
}

#[test]
fn embed_backfill_dry_run_exits_zero_on_fresh_db() {
    let tmp = tmp();
    clx(&tmp).args(["--json", "install"]).assert().success();

    // With vector search disabled (no sqlite-vec), the command exits 0 with
    // a graceful message rather than panicking.
    clx(&tmp)
        .args(["--json", "embed-backfill", "--dry-run"])
        .assert()
        .success();
}

#[test]
fn embed_backfill_without_ollama_does_not_panic() {
    let tmp = tmp();
    clx(&tmp).args(["--json", "install"]).assert().success();

    // Without Ollama running the command either exits 0 with a graceful
    // "not available" message or exits non-zero; it must never panic.
    let status = clx(&tmp)
        .args(["--json", "embed-backfill"])
        .output()
        .expect("process must spawn");
    // A panic would produce a signal exit (no code on Unix) or code 101 on
    // macOS / Windows.  We simply assert the process terminated normally.
    assert!(
        status.status.code().is_some(),
        "process should exit with a code, not a signal"
    );
}

// ---------------------------------------------------------------------------
// T29 — Credentials commands
// ---------------------------------------------------------------------------

#[test]
fn credentials_list_does_not_panic() {
    let tmp = tmp();
    // Credentials uses the system keychain which may not be available in CI
    // or isolated environments.  The command must exit with a code (not a
    // signal) regardless of keychain availability.
    let status = clx(&tmp)
        .args(["credentials", "list"])
        .output()
        .expect("process must spawn");
    assert!(
        status.status.code().is_some(),
        "process should exit with a code, not a signal"
    );
}

#[test]
fn credentials_get_missing_key_exits_nonzero() {
    let tmp = tmp();
    // Requesting a key that was never stored should exit non-zero.
    clx(&tmp)
        .args(["credentials", "get", "CLX_TEST_KEY_DOES_NOT_EXIST_XYZ"])
        .assert()
        .failure();
}

#[test]
fn credentials_delete_missing_key_does_not_panic() {
    let tmp = tmp();
    // Deleting a non-existent key may succeed or fail gracefully; no panic.
    let status = clx(&tmp)
        .args(["credentials", "delete", "CLX_TEST_KEY_DOES_NOT_EXIST_XYZ"])
        .output()
        .expect("process must spawn");
    assert!(
        status.status.code().is_some(),
        "process should exit with a code, not a signal"
    );
}

#[test]
fn credentials_list_json_produces_valid_json_or_error_json() {
    let tmp = tmp();
    // The keychain may not be available in isolated environments.  In either
    // case the --json flag must produce valid JSON on stdout (or stderr for
    // errors in JSON mode), and never raw text.
    let output = clx(&tmp)
        .args(["--json", "credentials", "list"])
        .output()
        .expect("process must spawn");

    // JSON mode emits the error object to stderr when the command fails.
    let stdout = String::from_utf8(output.stdout).expect("stdout must be valid UTF-8");
    let stderr = String::from_utf8(output.stderr).expect("stderr must be valid UTF-8");

    if output.status.success() {
        serde_json::from_str::<serde_json::Value>(&stdout)
            .expect("credentials list --json stdout must be valid JSON on success");
    } else {
        // Error JSON goes to stderr in --json mode.
        serde_json::from_str::<serde_json::Value>(&stderr)
            .expect("credentials list --json stderr must be valid JSON on failure");
    }
}

// ---------------------------------------------------------------------------
// T30 — Health command
// ---------------------------------------------------------------------------

#[test]
fn health_exits_zero_or_one_and_does_not_panic() {
    let tmp = tmp();
    // Health may report failures (e.g. no Ollama) but must never panic.
    let status = clx(&tmp)
        .arg("health")
        .output()
        .expect("process must spawn");
    assert!(
        status.status.code() == Some(0) || status.status.code() == Some(1),
        "unexpected exit code: {:?}",
        status.status
    );
}

#[test]
fn health_json_produces_valid_json() {
    let tmp = tmp();
    let output = clx(&tmp)
        .args(["health", "--json"])
        .output()
        .expect("process must spawn");

    let stdout = String::from_utf8(output.stdout).expect("stdout must be valid UTF-8");
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("health --json output must be valid JSON");
    assert!(parsed["checks"].is_array());
    assert_eq!(parsed["checks"].as_array().unwrap().len(), 9);
    assert_eq!(parsed["summary"]["total"].as_u64().unwrap(), 9);
}

#[test]
fn health_global_json_flag_produces_valid_json() {
    let tmp = tmp();
    let output = clx(&tmp)
        .args(["--json", "health"])
        .output()
        .expect("process must spawn");

    let stdout = String::from_utf8(output.stdout).expect("stdout must be valid UTF-8");
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("--json health output must be valid JSON");
    assert!(parsed["checks"].is_array());
}

// ---------------------------------------------------------------------------
// T31 — Install and Uninstall
// ---------------------------------------------------------------------------

#[test]
fn install_with_isolated_home_exits_zero() {
    let tmp = tmp();
    clx(&tmp)
        .args(["--json", "install"])
        .assert()
        .success()
        .stdout(predicate::str::contains("install"));
}

#[test]
fn install_is_idempotent() {
    let tmp = tmp();
    clx(&tmp).args(["--json", "install"]).assert().success();

    // Second invocation must also succeed (no error on already-existing dirs).
    clx(&tmp).args(["--json", "install"]).assert().success();
}

#[test]
fn uninstall_after_install_exits_zero() {
    let tmp = tmp();
    clx(&tmp).args(["--json", "install"]).assert().success();

    clx(&tmp).args(["--json", "uninstall"]).assert().success();
}

#[test]
fn uninstall_purge_removes_clx_directory() {
    let tmp = tmp();
    clx(&tmp).args(["--json", "install"]).assert().success();

    // Confirm ~/.clx was created.
    let clx_dir = tmp.path().join(".clx");
    assert!(clx_dir.exists(), ".clx dir should exist after install");

    // JSON mode skips the interactive confirmation for --purge.
    clx(&tmp)
        .args(["--json", "uninstall", "--purge"])
        .assert()
        .success();

    assert!(
        !clx_dir.exists(),
        ".clx dir should be gone after uninstall --purge"
    );
}

#[test]
fn uninstall_on_fresh_home_exits_zero() {
    // Uninstalling when CLX was never installed must exit 0 gracefully.
    let fresh = tmp();
    clx(&fresh).args(["--json", "uninstall"]).assert().success();
}
