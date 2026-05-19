//! Wave: `clx rules` e2e tests.
//!
//! Anchored to `specs/_prerelease/01-validation.md` (policy rules: builtin
//! / config / learned) and the `04-integration.md` command table
//! (`rules <action>`). Behaviour-driven: add then list shows the rule;
//! reset then list omits it; project-scoped vs global scope is observable;
//! invalid input is a clean clap error.
//!
//! Real subcommand surface (`commands/rules.rs`): `RulesAction` is
//! `List | Allow {pattern, --global} | Deny {pattern, --global}
//! | Reset {--all}`. There is no `add`/`remove`/`get_project` -- those
//! map onto `allow`/`deny`/`reset` and `list`. Tests pin the real shape.
//!
//! Isolation: HOME + XDG redirected into a fresh `tempfile::TempDir`, so
//! the learned-rules DB (`~/.clx/data/clx.db`) lands in throwaway space.
//! `--json` is used for mutating commands so the interactive y/N prompt on
//! `reset` is skipped (it would otherwise block on stdin).

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

// ===========================================================================
// `clx rules list`: builtin rules present even on a fresh store
// ===========================================================================

#[test]
fn rules_list_on_fresh_home_shows_builtin_and_no_learned() {
    let t = tmp();
    clx(&t)
        .args(["rules", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Builtin Whitelist"))
        .stdout(predicate::str::contains("Builtin Blacklist"))
        .stdout(predicate::str::contains("No learned rules yet."));
}

#[test]
fn rules_list_json_is_well_formed_with_builtin_arrays() {
    let t = tmp();
    let out = clx(&t)
        .args(["--json", "rules", "list"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value =
        serde_json::from_str(&String::from_utf8(out).unwrap()).expect("rules --json is JSON");
    assert!(
        v["builtin_blacklist"]
            .as_array()
            .is_some_and(|a| !a.is_empty()),
        "builtin blacklist must be non-empty: {v}"
    );
    assert!(
        v["learned"].as_array().is_some_and(std::vec::Vec::is_empty),
        "fresh store has no learned rules: {v}"
    );
}

// ===========================================================================
// allow / deny then list shows the learned rule; reset removes it
// ===========================================================================

#[test]
fn rules_allow_then_list_shows_the_rule() {
    let t = tmp();
    clx(&t).args(["--json", "install"]).assert().success();
    clx(&t)
        .args(["--json", "rules", "allow", "npm test*"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"action\":\"allow\""))
        .stdout(predicate::str::contains("\"success\":true"));
    clx(&t)
        .args(["--json", "rules", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("npm test*"));
}

#[test]
fn rules_deny_then_list_shows_the_rule() {
    let t = tmp();
    clx(&t).args(["--json", "install"]).assert().success();
    clx(&t)
        .args(["--json", "rules", "deny", "rm -rf /tmp/x"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"action\":\"deny\""));
    clx(&t)
        .args(["--json", "rules", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("rm -rf /tmp/x"));
}

#[test]
fn rules_global_scope_vs_project_scope_is_observable() {
    // A `--global` rule has no project_path; a default rule is project
    // scoped (project_path = cwd). The list JSON exposes project_path.
    let t = tmp();
    clx(&t).args(["--json", "install"]).assert().success();
    clx(&t)
        .args(["--json", "rules", "allow", "cargo build", "--global"])
        .assert()
        .success();
    clx(&t)
        .args(["--json", "rules", "allow", "cargo test"])
        .assert()
        .success();
    let out = clx(&t)
        .args(["--json", "rules", "list"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8(out).unwrap()).unwrap();
    let learned = v["learned"].as_array().expect("learned array");
    let global = learned
        .iter()
        .find(|r| r["pattern"] == "cargo build")
        .expect("global rule present");
    assert!(
        global["project_path"].is_null(),
        "a --global rule must have no project_path: {global}"
    );
    let project = learned
        .iter()
        .find(|r| r["pattern"] == "cargo test")
        .expect("project rule present");
    assert!(
        project["project_path"].is_string(),
        "a default rule must be project-scoped: {project}"
    );
}

#[test]
fn rules_reset_all_then_list_omits_learned_rules() {
    let t = tmp();
    clx(&t).args(["--json", "install"]).assert().success();
    clx(&t)
        .args(["--json", "rules", "allow", "ls -la"])
        .assert()
        .success();
    // `--json` reset skips the interactive y/N prompt.
    clx(&t)
        .args(["--json", "rules", "reset", "--all"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"action\":\"reset\""));
    let out = clx(&t)
        .args(["--json", "rules", "list"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8(out).unwrap()).unwrap();
    assert!(
        v["learned"].as_array().is_some_and(std::vec::Vec::is_empty),
        "reset --all must clear learned rules: {v}"
    );
}

#[test]
fn rules_reset_json_on_empty_store_reports_zero_deleted() {
    let t = tmp();
    clx(&t).args(["--json", "install"]).assert().success();
    clx(&t)
        .args(["--json", "rules", "reset", "--all"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"deleted_count\":0"));
}

// ===========================================================================
// Invalid input
// ===========================================================================

#[test]
fn rules_allow_missing_pattern_is_clap_error() {
    // `pattern` is a required positional for `allow`.
    let t = tmp();
    clx(&t)
        .args(["rules", "allow"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Usage").or(predicate::str::contains("required")));
}

#[test]
fn rules_unknown_subcommand_is_clap_error() {
    let t = tmp();
    clx(&t).args(["rules", "frobnicate"]).assert().failure();
}

#[test]
fn rules_no_subcommand_is_clap_error() {
    // `RulesAction` is a required subcommand (not Option).
    let t = tmp();
    clx(&t).args(["rules"]).assert().failure();
}
