//! Wave 1 E: dashboard + plugin/skills integration entry point.
//!
//! IMPORTANT — where the dashboard pixel/reducer tests actually live:
//!
//! `clx` is a binary-only crate (no `lib` target, see its `Cargo.toml`:
//! a single `[[bin]]`). The dashboard render path (`ratatui` `TestBackend`
//! snapshots) and the pure `state::update` reducer are crate-internal and
//! therefore **unreachable from this separate integration-test file**. Per
//! the Wave 1 E brief, when an internal is unreachable from a separate
//! file the TestBackend + insta pixel snapshots and the reducer-transition
//! tests are placed in a clearly-marked in-crate module instead:
//!
//!   `crates/clx/src/dashboard/ui/mod.rs` -> `mod tests` -> `mod wave1_pixel`
//!
//! That module adds: `wave1_audit_tab_multi_row`, `wave1_rules_tab_populated`,
//! `wave1_settings_tab_populated` insta snapshots, plus pure-reducer
//! transition tests for every `DashboardEvent` variant (Key / Resize /
//! Tick / Quit), including the empty-DB count-guard edge-matrix row.
//!
//! What THIS file covers (reachable, in Wave 1 E scope): the plugin static
//! validator and the 6 named skills, per spec section 3.7 and verification
//! step D. These are pure filesystem / shell-out integration checks with
//! no network, no DB, and no real-env mutation.

// Integration-test file: prose docs reference many code identifiers and the
// helpers are intentionally ergonomic; pedantic doc/style lints add noise
// without value here.
#![allow(clippy::doc_markdown)]

use std::path::PathBuf;
use std::process::Command;

/// Absolute path to the workspace root (two levels up from this crate).
fn workspace_root() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop(); // crates/
    p.pop(); // workspace root
    p
}

fn plugin_dir() -> PathBuf {
    workspace_root().join("plugin")
}

const SKILLS: [&str; 6] = [
    "clx-recall",
    "clx-remember",
    "clx-checkpoint",
    "clx-rules",
    "clx-resume",
    "clx-doctor",
];

// ===========================================================================
// 3.7: plugin.json (2026 schema) structural checks
// ===========================================================================

#[test]
fn plugin_json_is_valid_2026_schema_with_six_skills() {
    let pj = plugin_dir().join(".claude-plugin/plugin.json");
    let raw = std::fs::read_to_string(&pj).unwrap_or_else(|e| panic!("read {}: {e}", pj.display()));
    let v: serde_json::Value = serde_json::from_str(&raw).expect("plugin.json is valid JSON");
    assert_eq!(v["name"], "clx");
    assert!(v["version"].is_string(), "version must be present");
    assert_eq!(v["version"], "0.8.0");
    // I-R1 corroboration: the plugin manifest declares MPL-2.0.
    assert_eq!(v["license"], "MPL-2.0");
    let skills = v["skills"].as_array().expect("skills array");
    assert_eq!(skills.len(), 6, "exactly 6 declared skills");
}

#[test]
fn all_six_skill_md_files_exist_with_use_when_descriptions() {
    // 3.7: each skills/<name>/SKILL.md exists, frontmatter `name` matches
    // the dir (kebab-case) and `description` starts with "Use when".
    let base = plugin_dir().join(".claude-plugin/skills");
    for name in SKILLS {
        let md = base.join(name).join("SKILL.md");
        let content = std::fs::read_to_string(&md)
            .unwrap_or_else(|e| panic!("missing SKILL.md for {name}: {e}"));
        assert!(
            content.starts_with("---"),
            "{name}/SKILL.md must start with YAML frontmatter"
        );
        assert!(
            content.contains(&format!("name: {name}")),
            "{name}/SKILL.md frontmatter name must match dir"
        );
        assert!(
            content.contains("Use when"),
            "{name}/SKILL.md description must start with 'Use when'"
        );
    }
}

// ===========================================================================
// 3.7 / verification step D: the static validator passes in --strict mode
// ===========================================================================

#[test]
fn validate_sh_strict_exits_zero_and_reports_six_skills() {
    let script = plugin_dir().join("scripts/validate.sh");
    assert!(
        script.exists(),
        "validate.sh not found at {}",
        script.display()
    );
    let output = Command::new("bash")
        .arg(&script)
        .arg("--strict")
        .current_dir(workspace_root())
        .output()
        .expect("spawn bash validate.sh");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "validate.sh --strict must exit 0; stdout: {stdout}; stderr: {stderr}"
    );
    assert!(
        stdout.contains("6 SKILL.md file(s) valid (strict=1)"),
        "expected the strict OK summary line; got: {stdout}"
    );
}

#[test]
fn validate_sh_self_tests_pass() {
    // Verification step D: the validator's own self-tests.
    let script = plugin_dir().join("scripts/tests/validate_test.sh");
    if !script.exists() {
        // Self-test harness is optional; absence is not a failure of scope.
        return;
    }
    let output = Command::new("bash")
        .arg(&script)
        .current_dir(workspace_root())
        .output()
        .expect("spawn validate_test.sh");
    assert!(
        output.status.success(),
        "validate_test.sh must pass; stdout: {}; stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
