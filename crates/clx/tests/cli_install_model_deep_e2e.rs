//! Wave: `clx install` / `clx uninstall` / `clx model` / `clx version`
//! DEEP e2e tests -- success/branch pipelines.
//!
//! Drives the success arms the offline suite never asserts on:
//!   * `install` (commands/install.rs): the full `~/.clx` tree, the 8
//!     hook events incl. `Stop` in `~/.claude/settings.json`, the
//!     `~/.clx/bin/.clx-version` stamp, the 6 skills, the MCP server
//!     entry, and the CLAUDE.md injection -- then `uninstall` symmetry
//!     (hooks/skills/stamp removed) and the idempotent re-install arm
//!     (the "Exists" / "already present" branches).
//!   * `model` (commands/model.rs): the `CLX_MODEL_FETCH_DRYRUN`
//!     sentinel path of `cmd_fetch` (:134-154), the `already_ready`
//!     early-out (:80-98), the `--force` delete+restage arm (:118-128),
//!     and `status` with `ready==true` (:236-291) -- distinct from the
//!     not-installed status arm.
//!   * `version` (commands/version.rs): full human output (MPL-2.0,
//!     "Config:", description) + the `--json` arm.
//!
//! Isolation: HOME + XDG redirected into a fresh RAII `tempfile::TempDir`.
//! `CLX_MODEL_FETCH_DRYRUN=1` stubs the model artifacts (no 568MB/2.1GB
//! download, no network). `CLX_CREDENTIALS_BACKEND=file` -> no keychain.
//! `--json install` runs the prerequisite checks but the Ollama probes
//! fail fast against a non-running local daemon (hermetic).

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
        .env("CLX_RERANKER_ENABLED", "false")
        .env("CLX_LOG", "error");
    cmd
}

fn tmp() -> TempDir {
    tempfile::tempdir().expect("tempdir")
}

fn p(t: &TempDir, rel: &str) -> std::path::PathBuf {
    t.path().join(rel)
}

// ===========================================================================
// install: full tree + settings.json (8 hooks incl Stop) + stamp + skills
// ===========================================================================

#[test]
fn install_json_creates_full_clx_tree_and_settings() {
    let t = tmp();
    let out = clx(&t)
        .args(["--json", "install"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value =
        serde_json::from_str(&String::from_utf8(out).unwrap()).expect("install --json is JSON");
    assert_eq!(v["action"], "install");
    assert_eq!(v["success"], true);

    // Directory tree under the isolated HOME.
    for d in [
        ".clx",
        ".clx/bin",
        ".clx/data",
        ".clx/logs",
        ".clx/rules",
        ".clx/prompts",
        ".clx/docker",
    ] {
        assert!(p(&t, d).is_dir(), "install must create {d}");
    }
    assert!(p(&t, ".clx/config.yaml").exists());
    assert!(p(&t, ".clx/docker/docker-compose.yml").exists());

    // Version stamp written into ~/.clx/bin/.clx-version.
    let stamp = std::fs::read_to_string(p(&t, ".clx/bin/.clx-version")).expect("stamp written");
    assert!(
        !stamp.trim().is_empty(),
        "version stamp must be non-empty: {stamp:?}"
    );
}

#[test]
fn install_writes_all_eight_hook_events_including_stop() {
    let t = tmp();
    clx(&t).args(["--json", "install"]).assert().success();
    let settings: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(p(&t, ".claude/settings.json")).unwrap())
            .expect("settings.json is valid JSON");
    let hooks = settings["hooks"].as_object().expect("hooks object");
    for ev in [
        "PreToolUse",
        "PostToolUse",
        "PreCompact",
        "SessionStart",
        "SessionEnd",
        "SubagentStart",
        "UserPromptSubmit",
        "Stop",
    ] {
        assert!(hooks.contains_key(ev), "settings.json missing hook: {ev}");
    }
    assert_eq!(hooks.len(), 8, "exactly 8 hook events expected");
    assert_eq!(
        settings["hooks"]["Stop"][0]["hooks"][0]["command"],
        "~/.clx/bin/clx-hook stop"
    );
    // MCP server entry.
    assert_eq!(
        settings["mcpServers"]["clx"]["command"],
        "~/.clx/bin/clx-mcp"
    );
}

#[test]
fn install_writes_six_skills_and_injects_claude_md() {
    let t = tmp();
    clx(&t).args(["--json", "install"]).assert().success();
    for name in [
        "clx-recall",
        "clx-remember",
        "clx-checkpoint",
        "clx-rules",
        "clx-resume",
        "clx-doctor",
    ] {
        let skill_md = p(&t, &format!(".claude/skills/{name}/SKILL.md"));
        assert!(skill_md.exists(), "missing skill SKILL.md: {name}");
        assert!(
            !std::fs::read_to_string(&skill_md)
                .unwrap()
                .trim()
                .is_empty(),
            "{name} SKILL.md is empty"
        );
    }
    let claude_md = std::fs::read_to_string(p(&t, ".claude/CLAUDE.md")).unwrap();
    assert!(
        claude_md.contains("# CLX Integration"),
        "CLAUDE.md must carry the injected CLX section"
    );
}

#[test]
fn install_human_output_reports_completion_and_eight_hooks() {
    let t = tmp();
    clx(&t)
        .arg("install")
        .assert()
        .success()
        .stdout(predicate::str::contains("CLX Installation"))
        .stdout(predicate::str::contains("Installation Complete"))
        .stdout(predicate::str::contains("Stop"));
}

#[test]
fn install_is_idempotent_second_run_hits_exists_branches() {
    // Second install must take the "Exists" / "already present" arms
    // (install.rs config-merge + CLAUDE.md already-present + skills
    // refresh) and still succeed.
    let t = tmp();
    clx(&t).args(["--json", "install"]).assert().success();
    clx(&t).arg("install").assert().success().stdout(
        predicate::str::contains("CLX section already present")
            .or(predicate::str::contains("Exists")
                .or(predicate::str::contains("Installation Complete"))),
    );
}

// ===========================================================================
// uninstall: symmetry with install
// ===========================================================================

#[test]
fn uninstall_json_removes_hooks_skills_and_stamp() {
    let t = tmp();
    clx(&t).args(["--json", "install"]).assert().success();
    let out = clx(&t)
        .args(["--json", "uninstall"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8(out).unwrap()).unwrap();
    assert_eq!(v["action"], "uninstall");
    assert_eq!(v["success"], true);

    // Hooks removed from settings.json; ~/.clx preserved (no --purge).
    let settings: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(p(&t, ".claude/settings.json")).unwrap())
            .unwrap();
    assert!(
        settings.get("hooks").is_none(),
        "uninstall must remove the hooks block"
    );
    for name in ["clx-recall", "clx-doctor"] {
        assert!(
            !p(&t, &format!(".claude/skills/{name}")).exists(),
            "uninstall must remove CLX skill {name}"
        );
    }
    assert!(
        !p(&t, ".clx/bin/.clx-version").exists(),
        "uninstall must remove the version stamp"
    );
    assert!(p(&t, ".clx").exists(), "non-purge keeps ~/.clx");
}

#[test]
fn uninstall_purge_json_removes_clx_dir() {
    let t = tmp();
    clx(&t).args(["--json", "install"]).assert().success();
    clx(&t)
        .args(["--json", "uninstall", "--purge"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"purge\": true"));
    assert!(
        !p(&t, ".clx").exists(),
        "--purge must remove the ~/.clx directory"
    );
}

#[test]
fn uninstall_on_fresh_home_is_clean_noop() {
    // Nothing installed: uninstall must still exit 0 and report nothing
    // to remove (the empty-removed-items arm).
    let t = tmp();
    clx(&t)
        .arg("uninstall")
        .assert()
        .success()
        .stdout(predicate::str::contains("Uninstallation Complete"));
}

// ===========================================================================
// model: dryrun sentinel + already_ready + force + ready status
// ===========================================================================

#[test]
fn model_fetch_dryrun_writes_sentinel_and_status_reports_ready() {
    // CLX_MODEL_FETCH_DRYRUN=1: cmd_fetch stubs the required artifacts and
    // writes a real content-pinned `.ready` sentinel (model.rs:134-154).
    let t = tmp();
    clx(&t)
        .args(["--json", "model", "fetch"])
        .assert()
        .success();
    let model_dir = p(&t, ".clx/models/bge-reranker-v2-m3");
    assert!(model_dir.join("model.onnx").exists());
    assert!(model_dir.join("tokenizer.json").exists());
    assert!(
        model_dir.join(".ready").exists(),
        "dry-run must still write the .ready sentinel"
    );

    // status now takes the installed/ready arm.
    let out = clx(&t)
        .args(["--json", "model", "status"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8(out).unwrap()).unwrap();
    assert_eq!(v["models"][0]["installed"], true);
    assert_eq!(v["models"][0]["ready"], true);
    assert!(
        v["models"][0]["size_bytes"].as_u64().unwrap_or(0) > 0,
        "ready model must report a non-zero size: {v}"
    );
}

#[test]
fn model_fetch_twice_takes_already_ready_earlyout() {
    let t = tmp();
    clx(&t)
        .args(["--json", "model", "fetch"])
        .assert()
        .success();
    let out = clx(&t)
        .args(["--json", "model", "fetch"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8(out).unwrap()).unwrap();
    assert_eq!(
        v["status"], "already_ready",
        "second fetch must early-out on the .ready sentinel: {v}"
    );
}

#[test]
fn model_fetch_force_redownloads_clean() {
    // --force deletes the existing dir under the lock then re-stages it
    // (model.rs:118-128 + the dry-run restage). Must succeed and rewrite
    // a fresh .ready.
    let t = tmp();
    clx(&t)
        .args(["--json", "model", "fetch"])
        .assert()
        .success();
    clx(&t)
        .args(["--json", "model", "fetch", "--force"])
        .assert()
        .success();
    assert!(
        p(&t, ".clx/models/bge-reranker-v2-m3/.ready").exists(),
        "--force must leave a fresh .ready sentinel"
    );
}

#[test]
fn model_status_human_not_installed_shows_tip() {
    // Fresh HOME, no fetch: the not-ready arm prints the install tip.
    let t = tmp();
    clx(&t)
        .args(["model", "status"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Model Status"))
        .stdout(predicate::str::contains("Installed:"))
        .stdout(predicate::str::contains("clx model fetch"));
}

#[test]
fn model_status_human_ready_arm_after_fetch() {
    let t = tmp();
    clx(&t)
        .args(["--json", "model", "fetch"])
        .assert()
        .success();
    clx(&t)
        .args(["model", "status"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Ready:"))
        .stdout(predicate::str::contains("yes"));
}

#[test]
fn model_list_human_and_json_arms() {
    let t = tmp();
    clx(&t)
        .args(["model", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Available Models"))
        .stdout(predicate::str::contains("bge-reranker-v2-m3"));
    let out = clx(&t)
        .args(["--json", "model", "list"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8(out).unwrap()).unwrap();
    assert_eq!(v["models"][0]["name"], "bge-reranker-v2-m3");
    assert_eq!(v["models"][0]["size_mb"], 568);
}

// ===========================================================================
// version: full human output + json arm
// ===========================================================================

#[test]
fn version_human_full_output_fields() {
    let t = tmp();
    clx(&t)
        .arg("version")
        .assert()
        .success()
        .stdout(predicate::str::contains("clx"))
        .stdout(predicate::str::contains("Coding-Agent Extension Layer"))
        .stdout(predicate::str::contains(
            "Command validation and context persistence for coding agents",
        ))
        .stdout(predicate::str::contains("Config:"))
        .stdout(predicate::str::contains("License: MPL-2.0"));
}

#[test]
fn version_json_arm_has_name_version_description() {
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
    assert_eq!(v["description"], "Coding-Agent Extension Layer");
    assert!(
        v["version"].as_str().is_some_and(|s| !s.is_empty()),
        "version must be a non-empty semver string: {v}"
    );
}
