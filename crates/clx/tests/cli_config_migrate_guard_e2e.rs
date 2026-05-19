//! Wave: `clx config migrate` schema-guard e2e test.
//!
//! `cli_config_deep_e2e.rs` covers migrate SUCCESS; `cli_config_e2e.rs`
//! covers the "file not found" and "neither legacy nor new sections"
//! bail guards. The remaining uncovered guard is config.rs:166-167:
//! a config that ALREADY uses the new `providers:` schema must bail with
//! "config already uses the new schema; nothing to migrate" and must NOT
//! rewrite the file or drop a `.bak`.
//!
//! Hermetic isolated HOME; age file backend; dry-run; no network.

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

#[test]
fn config_migrate_bails_when_already_new_schema_and_leaves_file_intact() {
    let t = tmp();
    let cfg_dir = t.path().join(".clx");
    std::fs::create_dir_all(&cfg_dir).unwrap();
    let cfg = cfg_dir.join("config.yaml");
    // A config that already uses the NEW providers: schema (no `ollama:`).
    let original = concat!(
        "providers:\n",
        "  azure-prod:\n",
        "    kind: azure_openai\n",
        "    endpoint: \"https://x.openai.azure.com\"\n",
        "    api_key_env: \"AZURE_OPENAI_API_KEY\"\n",
        "    timeout_ms: 30000\n",
    );
    std::fs::write(&cfg, original).unwrap();

    clx(&t)
        .args(["config", "migrate"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "config already uses the new schema; nothing to migrate",
        ));

    // Guard fired before any write/backup: file byte-identical, no .bak.
    let after = std::fs::read_to_string(&cfg).unwrap();
    assert_eq!(
        after, original,
        "new-schema guard must not rewrite the config"
    );
    assert!(
        !cfg_dir.join("config.yaml.bak").exists(),
        "new-schema guard must not create a .bak backup"
    );
}
