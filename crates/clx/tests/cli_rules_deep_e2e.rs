//! Wave: `clx rules` DEEP e2e tests -- human render + interactive reset.
//!
//! The existing `cli_rules_e2e.rs` drives only `--json` allow/deny/reset
//! and the empty-store human list. It never exercises:
//!   * the NON-empty learned-rules HUMAN render (rules.rs:165-184): the
//!     allow `+`/deny `-` indicator branch, the `[global]` vs `[<path>]`
//!     scope branch, and the `(confirmed: N, denied: M)` line.
//!   * the `allow` HUMAN success arm incl. the project Scope line
//!     (rules.rs:212-223).
//!   * the `deny` HUMAN success arm incl. the project Scope line
//!     (rules.rs:248-259).
//!   * the `reset` INTERACTIVE prompt path (rules.rs:266-282): the
//!     warning text, the confirmed (`y`) and cancelled (`n`) branches,
//!     and the `--all` vs default warning-message branch.
//!   * the `reset` default (non-`--all`) `source == "user_decision"`
//!     filter: CLI rules use source "cli", so a default reset deletes 0
//!     while `--all` deletes them (rules.rs:291, deleted_count branch).
//!
//! Behaviour contracts only. Hermetic isolated HOME; `--json install`
//! initialises the learned-rules DB exactly like the existing suite.

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

// ===========================================================================
// allow / deny HUMAN success arms incl. Scope line (rules.rs:212-259)
// ===========================================================================

#[test]
fn rules_allow_human_prints_success_and_project_scope() {
    let t = tmp();
    clx(&t).args(["--json", "install"]).assert().success();
    clx(&t)
        .args(["rules", "allow", "npm run build*"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Added whitelist rule:"))
        .stdout(predicate::str::contains("npm run build*"))
        // default (not --global) -> the "Scope:" line is printed with a
        // concrete project path (the test cwd), NOT the word "global".
        .stdout(predicate::str::contains("Scope:"));
}

#[test]
fn rules_allow_global_human_omits_project_scope_line() {
    // `--global` -> the `if !*global` Scope block is skipped entirely.
    let t = tmp();
    clx(&t).args(["--json", "install"]).assert().success();
    clx(&t)
        .args(["rules", "allow", "cargo fmt", "--global"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Added whitelist rule:"))
        .stdout(predicate::str::contains("Scope:").not());
}

#[test]
fn rules_deny_human_prints_success_and_project_scope() {
    let t = tmp();
    clx(&t).args(["--json", "install"]).assert().success();
    clx(&t)
        .args(["rules", "deny", "curl evil.test"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Added blacklist rule:"))
        .stdout(predicate::str::contains("curl evil.test"))
        .stdout(predicate::str::contains("Scope:"));
}

#[test]
fn rules_deny_global_human_omits_project_scope_line() {
    let t = tmp();
    clx(&t).args(["--json", "install"]).assert().success();
    clx(&t)
        .args(["rules", "deny", "shutdown now", "--global"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Added blacklist rule:"))
        .stdout(predicate::str::contains("Scope:").not());
}

// ===========================================================================
// Non-empty learned-rules HUMAN render (rules.rs:160-184)
// ===========================================================================

#[test]
fn rules_list_human_renders_learned_allow_and_deny_with_scope_and_counts() {
    let t = tmp();
    clx(&t).args(["--json", "install"]).assert().success();
    // One global allow, one project-scoped deny -> exercises BOTH the
    // +/- indicator branch AND the [global] vs [<path>] scope branch.
    clx(&t)
        .args(["rules", "allow", "ls -la", "--global"])
        .assert()
        .success();
    clx(&t)
        .args(["rules", "deny", "rm -rf /tmp/zap"])
        .assert()
        .success();
    clx(&t)
        .args(["rules", "list"])
        .assert()
        .success()
        // The learned section header reflects a non-zero count.
        .stdout(predicate::str::contains("Learned Rules"))
        // Global rule renders the [global] scope marker.
        .stdout(predicate::str::contains("ls -la"))
        .stdout(predicate::str::contains("[global]"))
        // Project rule renders a bracketed path scope (not [global]).
        .stdout(predicate::str::contains("rm -rf /tmp/zap"))
        // The confirmed/denied counter line is emitted for learned rules.
        .stdout(predicate::str::contains("confirmed:"))
        .stdout(predicate::str::contains("denied:"))
        // And the "No learned rules yet." empty arm is NOT taken.
        .stdout(predicate::str::contains("No learned rules yet.").not());
}

// ===========================================================================
// reset INTERACTIVE prompt path (rules.rs:266-282)
// ===========================================================================

#[test]
fn rules_reset_interactive_decline_keeps_rules() {
    let t = tmp();
    clx(&t).args(["--json", "install"]).assert().success();
    clx(&t)
        .args(["rules", "allow", "keep-me", "--global"])
        .assert()
        .success();
    // No --json -> interactive prompt; stdin "n" -> Cancelled, nothing deleted.
    clx(&t)
        .args(["rules", "reset"])
        .write_stdin("n\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("Warning:"))
        .stdout(predicate::str::contains(
            "This will delete all automatically learned rules.",
        ))
        .stdout(predicate::str::contains("Continue? [y/N]"))
        .stdout(predicate::str::contains("Cancelled."));
    // Rule survived the declined reset.
    let out = clx(&t)
        .args(["--json", "rules", "list"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8(out).unwrap()).unwrap();
    let learned = v["learned"].as_array().unwrap();
    assert!(
        learned.iter().any(|r| r["pattern"] == "keep-me"),
        "declined reset must NOT delete learned rules: {v}"
    );
}

#[test]
fn rules_reset_all_warning_text_differs_and_confirm_deletes() {
    // `--all` selects the stronger warning string AND, on "y", deletes
    // every rule (CLI rules have source "cli", so only the --all branch
    // of the `*all || source == "user_decision"` filter removes them).
    let t = tmp();
    clx(&t).args(["--json", "install"]).assert().success();
    clx(&t)
        .args(["rules", "allow", "doomed", "--global"])
        .assert()
        .success();
    clx(&t)
        .args(["rules", "reset", "--all"])
        .write_stdin("y\n")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "This will delete ALL learned rules (including manually added ones).",
        ))
        .stdout(predicate::str::contains("Deleted 1 learned rules."));
    let out = clx(&t)
        .args(["--json", "rules", "list"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8(out).unwrap()).unwrap();
    assert!(
        v["learned"].as_array().unwrap().is_empty(),
        "confirmed reset --all must clear every learned rule: {v}"
    );
}

#[test]
fn rules_reset_default_confirm_spares_cli_sourced_rules() {
    // The default (non --all) reset only deletes source=="user_decision".
    // CLI-added rules carry source "cli", so a confirmed default reset
    // reports 0 deleted and the rule survives -- the OTHER side of the
    // `*all || rule.source == "user_decision"` branch.
    let t = tmp();
    clx(&t).args(["--json", "install"]).assert().success();
    clx(&t)
        .args(["rules", "allow", "survivor", "--global"])
        .assert()
        .success();
    clx(&t)
        .args(["rules", "reset"])
        .write_stdin("y\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("Deleted 0 learned rules."));
    let out = clx(&t)
        .args(["--json", "rules", "list"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8(out).unwrap()).unwrap();
    assert!(
        v["learned"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["pattern"] == "survivor"),
        "default reset must spare cli-sourced rules: {v}"
    );
}
