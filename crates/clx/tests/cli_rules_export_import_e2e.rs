//! Wave: `clx rules export` / `import` + scope-aware `reset` e2e (Issue 10).
//!
//! Behaviour-driven: export->import round-trips user rules and is idempotent;
//! import re-validates each entry through the shared secret + malformed gates
//! (rejecting bad entries, importing the valid ones); a legit wildcard rule
//! `Bash(npm run build*)` round-trips (not rejected); reset default
//! (`--learned-only`) preserves explicit global allows while `--all` removes
//! them; garbage JSON errors cleanly with no partial corruption.
//!
//! Isolation: HOME + XDG redirected into a fresh `tempfile::TempDir`. Mutating
//! commands use `--json` to skip the interactive `reset` y/N prompt.

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

/// Read the `learned` array from `rules list --json`.
fn learned_patterns(t: &TempDir) -> Vec<String> {
    let out = clx(t)
        .args(["--json", "rules", "list"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8(out).unwrap()).unwrap();
    v["learned"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["pattern"].as_str().unwrap().to_owned())
        .collect()
}

/// AC10.2: export then import round-trips user rules, and a re-import is
/// idempotent (the upsert keys on pattern).
#[test]
fn ac10_2_export_import_round_trip_idempotent() {
    let t = tmp();
    clx(&t).args(["--json", "install"]).assert().success();
    // Seed two well-formed GLOBAL rules.
    clx(&t)
        .args(["--json", "rules", "allow", "Bash(cargo build)", "--global"])
        .assert()
        .success();
    clx(&t)
        .args(["--json", "rules", "deny", "Bash(rm)", "--global"])
        .assert()
        .success();

    let file = t.path().join("rules.json");
    let file_s = file.to_string_lossy().to_string();

    clx(&t)
        .args(["--json", "rules", "export", &file_s])
        .assert()
        .success();
    assert!(file.exists(), "export must create the file");

    // Wipe everything, then import.
    clx(&t)
        .args(["--json", "rules", "reset", "--all"])
        .assert()
        .success();
    assert!(
        learned_patterns(&t).is_empty(),
        "store cleared before import"
    );

    clx(&t)
        .args(["--json", "rules", "import", &file_s])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"imported\":2"));

    let after = learned_patterns(&t);
    assert!(after.contains(&"Bash(cargo build)".to_owned()), "{after:?}");
    assert!(after.contains(&"Bash(rm)".to_owned()), "{after:?}");

    // Idempotent re-import: still exactly the same two rules.
    clx(&t)
        .args(["--json", "rules", "import", &file_s])
        .assert()
        .success();
    let again = learned_patterns(&t);
    assert_eq!(again.len(), 2, "re-import must be idempotent: {again:?}");
}

/// AC10.3: an import file with a secret-bearing and a malformed entry rejects
/// those while importing the valid one.
#[test]
fn ac10_3_import_rejects_secret_and_malformed_imports_valid() {
    let t = tmp();
    clx(&t).args(["--json", "install"]).assert().success();

    let file = t.path().join("mixed.json");
    // One valid, one malformed (shell metachar `;`), one secret-bearing.
    let body = serde_json::json!({
        "version": 1,
        "rules": [
            { "pattern": "Bash(cargo test)", "rule_type": "allow" },
            { "pattern": "Bash(a; b)", "rule_type": "allow" },
            { "pattern": "Bash(curl -H 'Authorization: Bearer sk-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789')", "rule_type": "allow" }
        ]
    });
    std::fs::write(&file, serde_json::to_string_pretty(&body).unwrap()).unwrap();

    clx(&t)
        .args(["--json", "rules", "import", &file.to_string_lossy()])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"imported\":1"))
        .stdout(predicate::str::contains("\"rejected\":2"));

    let after = learned_patterns(&t);
    assert_eq!(after, vec!["Bash(cargo test)".to_owned()], "{after:?}");
}

/// Round-trip of a legit wildcard rule: `Bash(npm run build*)` must NOT be
/// rejected (is_well_formed_pattern allows `*`).
#[test]
fn import_accepts_wildcard_pattern() {
    let t = tmp();
    clx(&t).args(["--json", "install"]).assert().success();

    let file = t.path().join("wild.json");
    let body = serde_json::json!({
        "version": 1,
        "rules": [ { "pattern": "Bash(npm run build*)", "rule_type": "allow" } ]
    });
    std::fs::write(&file, serde_json::to_string(&body).unwrap()).unwrap();

    clx(&t)
        .args(["--json", "rules", "import", &file.to_string_lossy()])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"imported\":1"))
        .stdout(predicate::str::contains("\"rejected\":0"));

    assert!(
        learned_patterns(&t).contains(&"Bash(npm run build*)".to_owned()),
        "wildcard rule must import"
    );
}

/// Security regression: an import entry with an unknown/unsupported `rule_type`
/// (e.g. "graylist" or a typo) must be REJECTED, never silently coerced into an
/// allow rule (fail-open via RuleType default).
#[test]
fn import_rejects_unknown_rule_type_no_fail_open() {
    let t = tmp();
    clx(&t).args(["--json", "install"]).assert().success();

    let file = t.path().join("badtype.json");
    let body = serde_json::json!({
        "version": 1,
        "rules": [
            { "pattern": "Bash(rm -rf /)", "rule_type": "graylist" },
            { "pattern": "Bash(whatever)", "rule_type": "totally-bogus" },
            { "pattern": "Bash(cargo test)", "rule_type": "allow" }
        ]
    });
    std::fs::write(&file, serde_json::to_string(&body).unwrap()).unwrap();

    clx(&t)
        .args(["--json", "rules", "import", &file.to_string_lossy()])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"imported\":1"))
        .stdout(predicate::str::contains("\"rejected\":2"));

    // Only the valid allow rule landed; the bogus-typed entries did NOT.
    let after = learned_patterns(&t);
    assert_eq!(after, vec!["Bash(cargo test)".to_owned()], "{after:?}");
    assert!(
        !after.contains(&"Bash(rm -rf /)".to_owned()),
        "unknown rule_type must not import as an allow rule"
    );
}

/// AC10.4: reset default (`--learned-only`) preserves explicit global allows;
/// `--all` removes them.
#[test]
fn ac10_4_reset_default_preserves_global_allow_all_removes() {
    let t = tmp();
    clx(&t).args(["--json", "install"]).assert().success();
    // An explicit global allow is stored with source="cli", not "user_decision".
    clx(&t)
        .args(["--json", "rules", "allow", "Bash(cargo build)", "--global"])
        .assert()
        .success();

    // Default reset (learned-only) must NOT remove the explicit global allow.
    clx(&t)
        .args(["--json", "rules", "reset"])
        .assert()
        .success();
    assert!(
        learned_patterns(&t).contains(&"Bash(cargo build)".to_owned()),
        "default reset must preserve explicit global allows"
    );

    // Explicit --learned-only behaves the same.
    clx(&t)
        .args(["--json", "rules", "reset", "--learned-only"])
        .assert()
        .success();
    assert!(
        learned_patterns(&t).contains(&"Bash(cargo build)".to_owned()),
        "--learned-only must preserve explicit global allows"
    );

    // --all removes everything.
    clx(&t)
        .args(["--json", "rules", "reset", "--all"])
        .assert()
        .success();
    assert!(
        learned_patterns(&t).is_empty(),
        "--all must remove explicit global allows too"
    );
}

/// AC10.5: a garbage JSON file errors cleanly (non-zero) with no partial
/// corruption of the existing store.
#[test]
fn ac10_5_garbage_json_errors_cleanly() {
    let t = tmp();
    clx(&t).args(["--json", "install"]).assert().success();
    clx(&t)
        .args(["--json", "rules", "allow", "Bash(cargo build)", "--global"])
        .assert()
        .success();

    let file = t.path().join("garbage.json");
    std::fs::write(&file, "NOT VALID JSON ][[").unwrap();

    clx(&t)
        .args(["--json", "rules", "import", &file.to_string_lossy()])
        .assert()
        .failure()
        .stderr(predicate::str::contains("malformed").or(predicate::str::contains("parse")));

    // The pre-existing rule is untouched (no partial corruption).
    assert!(
        learned_patterns(&t).contains(&"Bash(cargo build)".to_owned()),
        "garbage import must not corrupt the existing store"
    );
}

/// An unknown future envelope version is rejected with a clear message.
#[test]
fn import_rejects_unknown_future_version() {
    let t = tmp();
    clx(&t).args(["--json", "install"]).assert().success();

    let file = t.path().join("future.json");
    let body = serde_json::json!({
        "version": 999,
        "rules": [ { "pattern": "Bash(cargo build)", "rule_type": "allow" } ]
    });
    std::fs::write(&file, serde_json::to_string(&body).unwrap()).unwrap();

    clx(&t)
        .args(["--json", "rules", "import", &file.to_string_lossy()])
        .assert()
        .failure()
        .stderr(predicate::str::contains("version"));
}
