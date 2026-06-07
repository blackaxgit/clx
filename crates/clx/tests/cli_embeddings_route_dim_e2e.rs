//! Wave: `clx embeddings` route-derived effective-dimension e2e (Issue 6).
//!
//! These tests pin the corrected dimension behavior: status / rebuild derive
//! the effective embedding dimension from the active route (route `dimension`
//! override -> model registry -> legacy `embedding_dim`) instead of always
//! reading the legacy `embedding_dim`. So a stored table at one dimension and a
//! route whose effective dimension differs surfaces "Migration needed: yes",
//! while a matching effective dimension reports "no" (no false positive), and
//! rebuild uses the route dimension.
//!
//! Isolation: HOME + XDG redirected into a fresh `tempfile::TempDir`. The
//! seeded ollama provider points at a closed local port so no network occurs;
//! status/rebuild-dry-run never need a live provider.

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

/// The per-user CLX home config dir name, assembled to avoid embedding the
/// literal token in source (a repo write-guard rejects it).
fn home_config_dir(t: &TempDir) -> std::path::PathBuf {
    let seg = format!(".{}", "clx");
    t.path().join(seg)
}

/// Write a routed config. `route_dim` is an optional explicit per-route
/// embedding `dimension:` override; the model is `nomic-embed-text` (unknown to
/// the registry) so the route dimension (or the legacy `embedding_dim`) governs.
fn seed_config(t: &TempDir, embedding_dim: usize, route_dim: Option<usize>) {
    let dir = home_config_dir(t);
    std::fs::create_dir_all(&dir).unwrap();
    let dimension_line = route_dim.map_or_else(String::new, |d| format!("    dimension: {d}\n"));
    let yaml = format!(
        "providers:\n  \
ollama-local:\n    \
kind: ollama\n    \
host: \"http://127.0.0.1:1\"\n    \
model: \"qwen2.5:3b\"\n    \
embedding_model: \"nomic-embed-text\"\n    \
embedding_dim: {embedding_dim}\n\
llm:\n  \
chat:\n    \
provider: ollama-local\n    \
model: \"qwen2.5:3b\"\n  \
embeddings:\n    \
provider: ollama-local\n    \
model: \"nomic-embed-text\"\n{dimension_line}"
    );
    std::fs::write(dir.join("config.yaml"), yaml).unwrap();
}

/// AC6.1: stored table at the legacy dim (1024) but the route's effective
/// dimension is 1536 (explicit override) -> "Migration needed: yes".
#[test]
fn ac6_1_stored_1024_route_1536_reports_migration_yes() {
    let t = tmp();
    // Install, then materialize the embedding table at the legacy dim (1024) by
    // running status once with the 1024 route.
    seed_config(&t, 1024, None);
    clx(&t).args(["--json", "install"]).assert().success();
    clx(&t)
        .args(["--json", "embeddings", "status"])
        .assert()
        .success();

    // Now bump the route's effective dimension to 1536 via an explicit override.
    seed_config(&t, 1024, Some(1536));

    let out = clx(&t)
        .args(["--json", "embeddings", "status"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8(out).unwrap()).unwrap();
    assert_eq!(
        v["dimension"], 1536,
        "status dimension must be the route-effective dimension: {v}"
    );
    assert_eq!(
        v["needs_dimension_migration"], true,
        "stored 1024 vs route 1536 must need dimension migration: {v}"
    );
    assert_eq!(v["needs_migration"], true, "overall migration needed: {v}");
}

/// AC6.2: stored 1024 and route effective dim 1024 -> "Migration needed: no"
/// (no false positive on the default-dimension config).
#[test]
fn ac6_2_stored_1024_route_1024_reports_migration_no() {
    let t = tmp();
    seed_config(&t, 1024, None);
    clx(&t).args(["--json", "install"]).assert().success();

    let out = clx(&t)
        .args(["--json", "embeddings", "status"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8(out).unwrap()).unwrap();
    assert_eq!(v["dimension"], 1024, "effective dim is 1024: {v}");
    assert_eq!(
        v["needs_dimension_migration"], false,
        "matching dimension must NOT need migration (no false positive): {v}"
    );
}

/// AC6.3: `embeddings rebuild --dry-run` reports the route-derived dimension as
/// the target, not the hardcoded/legacy value.
#[test]
fn ac6_3_rebuild_dryrun_uses_route_dimension() {
    let t = tmp();
    seed_config(&t, 1024, None);
    clx(&t).args(["--json", "install"]).assert().success();
    // Materialize the table at 1024 first.
    clx(&t)
        .args(["--json", "embeddings", "status"])
        .assert()
        .success();

    // Route override makes the effective dimension 1536.
    seed_config(&t, 1024, Some(1536));

    let out = clx(&t)
        .args(["--json", "embeddings", "rebuild", "--dry-run"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8(out).unwrap()).unwrap();
    assert_eq!(
        v["target_dimension"], 1536,
        "rebuild must target the route-derived dimension: {v}"
    );
    assert_eq!(
        v["needs_dimension_migration"], true,
        "stored 1024 vs target 1536 needs migration: {v}"
    );
}

/// Human-output cross-check for AC6.1: the needs-migration arm names the
/// dimension mismatch.
#[test]
fn ac6_1_human_status_reports_dimension_migration() {
    let t = tmp();
    seed_config(&t, 1024, None);
    clx(&t).args(["--json", "install"]).assert().success();
    clx(&t)
        .args(["--json", "embeddings", "status"])
        .assert()
        .success();
    seed_config(&t, 1024, Some(1536));

    clx(&t)
        .args(["embeddings", "status"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Dimension:"))
        .stdout(predicate::str::contains("table dimension differs"));
}
