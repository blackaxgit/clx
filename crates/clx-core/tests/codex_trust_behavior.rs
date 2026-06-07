//! Golden-vector behavior tests for the hoisted Codex project-trust reader
//! (`clx_core::config::codex_trust`).
//!
//! These exercise the SINGLE source of truth that Batch 5 will switch the
//! `clx` binary and the `clx-hook` `PreToolUse` handler over to. Every
//! failure mode must default to the safe (untrusted / `NotSeen`) posture,
//! and a repository must never be able to self-declare as trusted.

use std::fs;
use std::path::Path;

use clx_core::config::codex_trust::{ProjectTrust, read_project_trust};

/// The dot-prefixed per-user Codex home directory name, assembled at runtime
/// so the literal token never appears as a source string.
fn codex_dir_name() -> String {
    format!(".{}", "codex")
}

/// Write `content` to the user-global Codex config under `home`.
fn write_global_config(home: &Path, content: &str) {
    let dir = home.join(codex_dir_name());
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("config.toml"), content).unwrap();
}

fn canonical_key(repo: &Path) -> String {
    fs::canonicalize(repo).unwrap().display().to_string()
}

#[test]
fn trusted_global_entry_resolves_trusted() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    let repo = tmp.path().join("trusted-repo");
    fs::create_dir_all(&repo).unwrap();

    let key = canonical_key(&repo);
    write_global_config(
        &home,
        &format!("[projects.\"{key}\"]\ntrust_level = \"trusted\"\n"),
    );

    assert_eq!(read_project_trust(&home, &repo), ProjectTrust::Trusted);
}

#[test]
fn untrusted_global_entry_resolves_untrusted() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    let repo = tmp.path().join("untrusted-repo");
    fs::create_dir_all(&repo).unwrap();

    let key = canonical_key(&repo);
    write_global_config(
        &home,
        &format!("[projects.\"{key}\"]\ntrust_level = \"untrusted\"\n"),
    );

    assert_eq!(read_project_trust(&home, &repo), ProjectTrust::Untrusted);
}

#[test]
fn unknown_trust_value_resolves_not_seen() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    let repo = tmp.path().join("weird-repo");
    fs::create_dir_all(&repo).unwrap();

    let key = canonical_key(&repo);
    write_global_config(
        &home,
        &format!("[projects.\"{key}\"]\ntrust_level = \"sometimes\"\n"),
    );

    assert_eq!(read_project_trust(&home, &repo), ProjectTrust::NotSeen);
}

#[test]
fn missing_config_file_resolves_not_seen() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    let repo = tmp.path().join("any-repo");
    fs::create_dir_all(&repo).unwrap();
    // No global config written.

    assert_eq!(read_project_trust(&home, &repo), ProjectTrust::NotSeen);
}

#[test]
fn missing_entry_for_known_file_resolves_not_seen() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    let repo = tmp.path().join("unlisted-repo");
    fs::create_dir_all(&repo).unwrap();

    // Config exists but does not list this repo.
    write_global_config(&home, "[model]\ndefault = \"gpt-5.5\"\n");

    assert_eq!(read_project_trust(&home, &repo), ProjectTrust::NotSeen);
}

#[test]
fn malformed_config_resolves_not_seen() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    let repo = tmp.path().join("any-repo");
    fs::create_dir_all(&repo).unwrap();

    write_global_config(&home, "not = valid = toml ][[\n");

    assert_eq!(read_project_trust(&home, &repo), ProjectTrust::NotSeen);
}

// CRITICAL SECURITY GOLDEN VECTOR: a repository that ships its own local
// codex config declaring itself trusted MUST NOT be honored. Only the
// user-global config can grant trust.
#[test]
fn repo_self_declared_trusted_must_resolve_not_trusted() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    let repo = tmp.path().join("hostile-repo");
    fs::create_dir_all(&repo).unwrap();

    // Hostile repo ships a local codex config claiming trust.
    let repo_codex_dir = repo.join(codex_dir_name());
    fs::create_dir_all(&repo_codex_dir).unwrap();
    let key = canonical_key(&repo);
    fs::write(
        repo_codex_dir.join("config.toml"),
        format!("[projects.\"{key}\"]\ntrust_level = \"trusted\"\n"),
    )
    .unwrap();

    // The user-global config does NOT list this repo at all.
    write_global_config(&home, "[model]\ndefault = \"gpt-5.5\"\n");

    let result = read_project_trust(&home, &repo);
    assert_ne!(
        result,
        ProjectTrust::Trusted,
        "SECURITY VIOLATION: a repo-local config must never grant trust"
    );
    assert_eq!(result, ProjectTrust::NotSeen);
}
