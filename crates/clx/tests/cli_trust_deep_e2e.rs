//! Wave: `clx trust` + `clx config-trust` DEEP e2e tests.
//!
//! The existing offline suite (`cli_tests.rs` T32) only drives the
//! `trust on` (default duration, human), `trust off`, and the
//! `--json trust status` active/inactive read-backs. `cli_config_e2e.rs`
//! covers config-trust empty list, the json add->list->remove roundtrip,
//! missing-file add, and unknown-hash remove. Neither exercises:
//!   * `handle_on` duration guards: too-short (trust.rs:139-144) and
//!     too-long (`:145-150`), plus `--session` binding (`:155-159`,200-201).
//!   * `handle_on` `--json` success object (`:184-191`).
//!   * `handle_off` `--json` arm (`:220-225`) and the "was not active"
//!     human arm (`:233`).
//!   * `handle_status` HUMAN active render (`:268-282`) and the human
//!     inactive render.
//!   * config-trust `add` already-trusted json + human (`:342-357`),
//!     the interactive y/N confirm + abort prompt (`:360-382`), and the
//!     human "Trusted ..." success arm (`:396-403`).
//!   * config-trust `list` non-empty HUMAN table render (`:424-446`).
//!   * config-trust `remove` HUMAN removed / not-found arms (`:462-466`).
//!
//! Behaviour contracts only: real stdout/stderr/exit/file-state. No impl
//! pinning. Hermetic: HOME + XDG into a fresh tempdir, age file backend,
//! model fetch dry-run, no network, no keychain.

#![allow(clippy::doc_markdown)]

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

fn clx(tmp: &TempDir) -> Command {
    let mut cmd = Command::cargo_bin("clx").expect("clx binary");
    cmd.env("HOME", tmp.path())
        .env("XDG_DATA_HOME", tmp.path().join("xdg-data"))
        .env("XDG_CONFIG_HOME", tmp.path().join("xdg-config"))
        .env("CLX_CREDENTIALS_BACKEND", "age")
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
// handle_on: duration guards (trust.rs:139-150)
// ===========================================================================

#[test]
fn trust_on_duration_below_five_minutes_is_rejected() {
    // 1m < the hard 300s minimum -> bail("Duration too short...").
    let t = tmp();
    clx(&t)
        .args(["trust", "on", "--duration", "1m"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Duration too short"));
    // Guard fired BEFORE any token write.
    assert!(
        !home_path(&t, ".clx/.trust_mode_token").exists(),
        "rejected duration must not create a trust token"
    );
}

#[test]
fn trust_on_duration_above_max_is_rejected() {
    // 999h vastly exceeds trust_mode_max_duration -> bail("too long").
    let t = tmp();
    clx(&t)
        .args(["trust", "on", "--duration", "999h"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Duration too long"))
        .stderr(predicate::str::contains("trust_mode_max_duration"));
    assert!(!home_path(&t, ".clx/.trust_mode_token").exists());
}

#[test]
fn trust_on_invalid_duration_suffix_is_rejected() {
    // parse_duration("5x") -> Err -> propagated as a clean failure.
    let t = tmp();
    clx(&t)
        .args(["trust", "on", "--duration", "5x"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Unknown duration suffix"));
}

// ===========================================================================
// handle_on: --json success object + --session binding (trust.rs:155-191)
// ===========================================================================

#[test]
fn trust_on_json_emits_enabled_status_and_writes_0600_token() {
    let t = tmp();
    let out = clx(&t)
        .args(["--json", "trust", "on", "--duration", "30m"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value =
        serde_json::from_str(&String::from_utf8(out).unwrap()).expect("trust on --json is JSON");
    assert_eq!(v["status"], "enabled");
    assert_eq!(v["duration_secs"], 1800);
    assert_eq!(
        v["session_bound"], false,
        "no --session -> session_bound false"
    );
    let token = home_path(&t, ".clx/.trust_mode_token");
    assert!(token.exists(), "json trust on must persist the token");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&token).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "trust token must be 0600, got {mode:o}");
    }
}

#[test]
fn trust_on_session_binds_to_claude_session_id_human_arm() {
    // --session + CLAUDE_CODE_SESSION_ID set -> token.session_id = Some,
    // human arm prints "Bound to current session" (trust.rs:200-201),
    // and a follow-up json status reports session_bound = true.
    let t = tmp();
    clx(&t)
        .env("CLAUDE_CODE_SESSION_ID", "sess-xyz")
        .args(["trust", "on", "--session", "--duration", "30m"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Trust mode"))
        .stdout(predicate::str::contains("enabled"))
        .stdout(predicate::str::contains("Bound to current session"));
    let out = clx(&t)
        .args(["--json", "trust", "status"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8(out).unwrap()).unwrap();
    assert_eq!(v["active"], true);
    assert_eq!(
        v["session_bound"], true,
        "a --session token must report session_bound true on read-back"
    );
}

#[test]
fn trust_on_session_without_env_is_not_bound() {
    // --session but CLAUDE_CODE_SESSION_ID absent -> std::env::var Err ->
    // session_id None -> session_bound false (the `.ok()` None arm).
    let t = tmp();
    let out = clx(&t)
        .env_remove("CLAUDE_CODE_SESSION_ID")
        .args(["--json", "trust", "on", "--session", "--duration", "30m"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8(out).unwrap()).unwrap();
    assert_eq!(
        v["session_bound"], false,
        "--session with no session id env must NOT bind"
    );
}

// ===========================================================================
// handle_off: --json arm + "was not active" arm (trust.rs:220-233)
// ===========================================================================

#[test]
fn trust_off_json_reports_was_active_true_after_on() {
    let t = tmp();
    clx(&t).args(["trust", "on"]).assert().success();
    let out = clx(&t)
        .args(["--json", "trust", "off"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8(out).unwrap()).unwrap();
    assert_eq!(v["status"], "disabled");
    assert_eq!(
        v["was_active"], true,
        "off after on must report was_active true"
    );
    assert!(
        !home_path(&t, ".clx/.trust_mode_token").exists(),
        "off must remove the token file"
    );
}

#[test]
fn trust_off_json_reports_was_active_false_when_inactive() {
    let t = tmp();
    let out = clx(&t)
        .args(["--json", "trust", "off"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8(out).unwrap()).unwrap();
    assert_eq!(v["was_active"], false);
}

#[test]
fn trust_off_human_when_not_active_says_was_not_active() {
    // The else-branch human arm (trust.rs:233): no token -> the
    // "Trust mode was not active." line, exit 0.
    let t = tmp();
    clx(&t)
        .args(["trust", "off"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Trust mode was not active."));
}

// ===========================================================================
// handle_status: HUMAN active + inactive render (trust.rs:266-291)
// ===========================================================================

#[test]
fn trust_status_human_active_shows_remaining_and_expires() {
    let t = tmp();
    clx(&t)
        .args(["trust", "on", "--duration", "2h"])
        .assert()
        .success();
    clx(&t)
        .args(["trust", "status"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Trust mode is"))
        .stdout(predicate::str::contains("ACTIVE"))
        .stdout(predicate::str::contains("Remaining:"))
        .stdout(predicate::str::contains("Expires:"));
}

#[test]
fn trust_status_human_inactive_on_fresh_home() {
    let t = tmp();
    clx(&t)
        .args(["trust", "status"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Trust mode is"))
        .stdout(predicate::str::contains("inactive"));
}

#[test]
fn trust_status_with_expired_token_cleans_it_up_and_reports_inactive() {
    // read_valid_token: a token whose expires_at is in the PAST takes the
    // else arm -> fs::remove_file + None (trust.rs:113-115). Status then
    // reports inactive AND the stale token file is gone afterwards.
    let t = tmp();
    let clx_dir = home_path(&t, ".clx");
    std::fs::create_dir_all(&clx_dir).unwrap();
    let token_file = clx_dir.join(".trust_mode_token");
    // RFC3339 timestamp far in the past.
    std::fs::write(
        &token_file,
        concat!(
            "{\n",
            "  \"enabled_at\": \"2000-01-01T00:00:00+00:00\",\n",
            "  \"expires_at\": \"2000-01-01T01:00:00+00:00\",\n",
            "  \"duration_secs\": 3600,\n",
            "  \"session_id\": null,\n",
            "  \"enabled_by\": \"cli\"\n",
            "}\n",
        ),
    )
    .unwrap();
    let out = clx(&t)
        .args(["--json", "trust", "status"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8(out).unwrap()).unwrap();
    assert_eq!(
        v["active"], false,
        "an expired token must read back as inactive"
    );
    assert!(
        !token_file.exists(),
        "read_valid_token must delete the expired token file"
    );
}

#[test]
fn trust_status_human_active_session_line_when_bound() {
    // The `if t.session_id.is_some()` Session-bound human line (:280-282).
    let t = tmp();
    clx(&t)
        .env("CLAUDE_CODE_SESSION_ID", "sess-abc")
        .args(["trust", "on", "--session", "--duration", "1h"])
        .assert()
        .success();
    clx(&t)
        .env("CLAUDE_CODE_SESSION_ID", "sess-abc")
        .args(["trust", "status"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Session:"))
        .stdout(predicate::str::contains("bound to current session"));
}

// ===========================================================================
// config-trust add: already-trusted json + human (trust.rs:341-357)
// ===========================================================================

fn seed_project_config(t: &TempDir) -> std::path::PathBuf {
    let proj = home_path(t, "work/.clx");
    std::fs::create_dir_all(&proj).unwrap();
    let cfg = proj.join("config.yaml");
    std::fs::write(&cfg, "providers: {}\n").unwrap();
    cfg
}

#[test]
fn config_trust_add_already_trusted_json_is_idempotent() {
    let t = tmp();
    let cfg = seed_project_config(&t);
    clx(&t)
        .args(["--json", "config-trust", "add"])
        .arg(&cfg)
        .arg("-y")
        .assert()
        .success();
    // Second add of the same (unchanged) file: already_trusted json arm.
    let out = clx(&t)
        .args(["--json", "config-trust", "add"])
        .arg(&cfg)
        .arg("-y")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8(out).unwrap()).unwrap();
    assert_eq!(v["status"], "already_trusted");
    assert!(
        v["hash"].as_str().unwrap().starts_with("sha256:"),
        "already_trusted must echo the sha256 hash: {v}"
    );
}

#[test]
fn config_trust_add_already_trusted_human_arm() {
    let t = tmp();
    let cfg = seed_project_config(&t);
    clx(&t)
        .args(["config-trust", "add"])
        .arg(&cfg)
        .arg("-y")
        .assert()
        .success();
    clx(&t)
        .args(["config-trust", "add"])
        .arg(&cfg)
        .arg("-y")
        .assert()
        .success()
        .stdout(predicate::str::contains("is already trusted"));
}

// ===========================================================================
// config-trust add: interactive y/N prompt (trust.rs:360-382)
// ===========================================================================

#[test]
fn config_trust_add_interactive_confirm_y_trusts_and_prints_human_success() {
    // No -y, not --json -> the prompt path. stdin "y" -> tl.add+save and
    // the human "Trusted ..." success arm (trust.rs:396-403).
    let t = tmp();
    let cfg = seed_project_config(&t);
    clx(&t)
        .args(["config-trust", "add"])
        .arg(&cfg)
        .write_stdin("y\n")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "About to trust per-project config",
        ))
        .stdout(predicate::str::contains("Proceed? [y/N]"))
        .stdout(predicate::str::contains("Trusted"));
    // The entry is now persisted: list shows exactly one.
    let out = clx(&t)
        .args(["--json", "config-trust", "list"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8(out).unwrap()).unwrap();
    assert_eq!(v["count"], 1, "confirmed add must persist the entry");
}

#[test]
fn config_trust_add_interactive_decline_aborts_without_persisting() {
    // stdin "n" -> the abort arm: "aborted." and NOTHING persisted.
    let t = tmp();
    let cfg = seed_project_config(&t);
    clx(&t)
        .args(["config-trust", "add"])
        .arg(&cfg)
        .write_stdin("n\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("aborted."));
    let out = clx(&t)
        .args(["--json", "config-trust", "list"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8(out).unwrap()).unwrap();
    assert_eq!(
        v["count"], 0,
        "declined add must NOT persist a trustlist entry"
    );
}

// ===========================================================================
// config-trust list: non-empty HUMAN table render (trust.rs:424-446)
// ===========================================================================

#[test]
fn config_trust_list_human_non_empty_renders_table_with_hash_and_path() {
    let t = tmp();
    let cfg = seed_project_config(&t);
    clx(&t)
        .args(["config-trust", "add"])
        .arg(&cfg)
        .arg("-y")
        .assert()
        .success();
    clx(&t)
        .args(["config-trust", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("HASH"))
        .stdout(predicate::str::contains("ADDED_AT"))
        .stdout(predicate::str::contains("PATH"))
        .stdout(predicate::str::contains("sha256:"))
        .stdout(predicate::str::contains("1 entries; trustlist at"));
}

// ===========================================================================
// config-trust remove: HUMAN removed / not-found arms (trust.rs:462-466)
// ===========================================================================

#[test]
fn config_trust_remove_human_removed_arm() {
    let t = tmp();
    let cfg = seed_project_config(&t);
    let add = clx(&t)
        .args(["--json", "config-trust", "add"])
        .arg(&cfg)
        .arg("-y")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8(add).unwrap()).unwrap();
    let hash = v["hash"].as_str().unwrap().to_string();
    clx(&t)
        .args(["config-trust", "remove", &hash])
        .assert()
        .success()
        .stdout(predicate::str::contains("Removed"));
    // Idempotent: list now empty.
    clx(&t)
        .args(["config-trust", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("No trusted project configs"));
}

#[test]
fn config_trust_remove_human_not_found_arm_exit_zero() {
    let t = tmp();
    clx(&t)
        .args(["config-trust", "remove", "sha256:nomatchabcdef"])
        .assert()
        .success()
        .stdout(predicate::str::contains("No entry matched"));
}

#[test]
fn config_trust_remove_ambiguous_prefix_is_clean_error() {
    // Two distinct trusted files; an over-short common-ish prefix is
    // either ambiguous (bail) or just unmatched -- either way it must NOT
    // panic and must be a controlled outcome.
    let t = tmp();
    let p1 = home_path(&t, "a/.clx");
    let p2 = home_path(&t, "b/.clx");
    std::fs::create_dir_all(&p1).unwrap();
    std::fs::create_dir_all(&p2).unwrap();
    let c1 = p1.join("config.yaml");
    let c2 = p2.join("config.yaml");
    std::fs::write(&c1, "providers: {}\n# a\n").unwrap();
    std::fs::write(&c2, "providers: {}\n# b\n").unwrap();
    clx(&t)
        .args(["config-trust", "add"])
        .arg(&c1)
        .arg("-y")
        .assert()
        .success();
    clx(&t)
        .args(["config-trust", "add"])
        .arg(&c2)
        .arg("-y")
        .assert()
        .success();
    // "sha256:" is a prefix of BOTH -> ambiguous bail (>=2 matches).
    clx(&t)
        .args(["config-trust", "remove", "sha256:"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("ambiguous"));
}
