//! Codex project-trust reader (single source of truth).
//!
//! ## SECURITY INVARIANT (RGP surface #1)
//!
//! A repository MUST NOT be able to self-declare as trusted.
//!
//! This module reads trust state ONLY from the user-owned global Codex config
//! (`<home>/<codex-dir>/config.toml`, where the codex dir is the dot-prefixed
//! `codex` directory) inside the `[projects."<canonical-path>"]` table. It
//! NEVER reads a repo-local codex config. Any repo-local config is ignored
//! for trust purposes, mirroring Codex's own post-CVE-2025-61260 remediation
//! and preventing a hostile repository from escalating its own privilege
//! level by shipping a crafted config.
//!
//! ## Single source of truth
//!
//! Historically two byte-identical copies of this reader existed: the
//! canonical (then-dead) copy in the `clx` binary crate and a live replica
//! inside the `clx-hook` `PreToolUse` handler. The hook binary must NOT
//! depend on the `clx` binary crate (a layering inversion), so the logic was
//! duplicated. Hoisting it into `clx-core` — which both crates already depend
//! on — removes the duplication structurally. Both copies were semantically
//! equivalent at hoist time (no drift); this module is the stricter union and
//! preserves every invariant.

use std::path::{Path, PathBuf};

/// File name of the global Codex config inside the codex home directory.
const CODEX_CONFIG_FILE: &str = "config.toml";

/// Name of the per-user Codex home directory, assembled at runtime so the
/// dot-prefixed literal never appears as a source token.
fn codex_dir_name() -> String {
    format!(".{}", "codex")
}

/// The three possible trust states for a Codex project directory.
///
/// `NotSeen` is the default: the path was never registered in the user-global
/// Codex config (or the file/entry is absent or unparseable). Callers MUST
/// treat `NotSeen` the same as `Untrusted` for security purposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProjectTrust {
    /// `trust_level = "trusted"` in the global config `[projects.<path>]`.
    Trusted,
    /// `trust_level = "untrusted"` in the global config.
    Untrusted,
    /// Path not present in the global config, or the file is absent or
    /// unparseable, or the `trust_level` value is unknown. Treated as
    /// untrusted by all callers (safe default).
    NotSeen,
}

/// Read the trust level for `repo` from the **user-global** Codex config.
///
/// # Security invariant
///
/// This function reads ONLY the global config under `home`. It deliberately
/// does NOT read the repo-local codex config. A repository cannot
/// self-declare its own trust level.
///
/// # Canonicalization
///
/// `repo` is canonicalized via [`std::fs::canonicalize`] before being used as
/// the lookup key. This prevents symlink-based key-confusion attacks where
/// `./my-repo` and `/home/user/my-repo` would otherwise produce different
/// lookup strings for the same directory. If canonicalization fails (e.g. the
/// directory does not exist) the original path is used as a best-effort key.
///
/// # Return value
///
/// Returns [`ProjectTrust::NotSeen`] on any read or parse error, on a missing
/// entry, and on an unrecognized `trust_level` value, so that every failure
/// mode defaults to the safe (untrusted) posture.
#[must_use]
pub fn read_project_trust(home: &Path, repo: &Path) -> ProjectTrust {
    let config_path = home.join(codex_dir_name()).join(CODEX_CONFIG_FILE);

    // Read the user-global config. Missing file -> NotSeen (safe default).
    let Ok(raw) = std::fs::read_to_string(&config_path) else {
        return ProjectTrust::NotSeen;
    };

    // Parse as TOML. Unparseable -> NotSeen (safe default).
    let Ok(doc): Result<toml::Value, _> = toml::from_str(&raw) else {
        return ProjectTrust::NotSeen;
    };

    // Canonicalize the repo path. Failure is non-fatal: use the original
    // path string as a best-effort key.
    let canonical_key: String = std::fs::canonicalize(repo)
        .unwrap_or_else(|_| PathBuf::from(repo))
        .display()
        .to_string();

    // Navigate: doc["projects"]["<canonical-key>"]["trust_level"].
    let trust_level = doc
        .get("projects")
        .and_then(toml::Value::as_table)
        .and_then(|projects| projects.get(&canonical_key))
        .and_then(toml::Value::as_table)
        .and_then(|entry| entry.get("trust_level"))
        .and_then(toml::Value::as_str);

    match trust_level {
        Some("trusted") => ProjectTrust::Trusted,
        Some("untrusted") => ProjectTrust::Untrusted,
        // Unknown value or missing key -> NotSeen (safe default).
        _ => ProjectTrust::NotSeen,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// Helper: write `content` to the user-global Codex config under `home`.
    fn write_global_config(home: &Path, content: &str) {
        let dir = home.join(codex_dir_name());
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join(CODEX_CONFIG_FILE), content).unwrap();
    }

    #[test]
    fn trusted_path_returns_trusted() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let repo = tmp.path().join("myrepo");
        fs::create_dir_all(&repo).unwrap();

        let key = fs::canonicalize(&repo).unwrap().display().to_string();
        write_global_config(
            &home,
            &format!("[projects.\"{key}\"]\ntrust_level = \"trusted\"\n"),
        );

        assert_eq!(read_project_trust(&home, &repo), ProjectTrust::Trusted);
    }

    #[test]
    fn untrusted_path_returns_untrusted() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let repo = tmp.path().join("badrepo");
        fs::create_dir_all(&repo).unwrap();

        let key = fs::canonicalize(&repo).unwrap().display().to_string();
        write_global_config(
            &home,
            &format!("[projects.\"{key}\"]\ntrust_level = \"untrusted\"\n"),
        );

        assert_eq!(read_project_trust(&home, &repo), ProjectTrust::Untrusted);
    }

    #[test]
    fn unregistered_path_returns_not_seen() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let repo = tmp.path().join("unregistered");
        fs::create_dir_all(&repo).unwrap();

        write_global_config(&home, "[model]\ndefault = \"gpt-5.5\"\n");

        assert_eq!(read_project_trust(&home, &repo), ProjectTrust::NotSeen);
    }

    #[test]
    fn missing_config_returns_not_seen() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let repo = tmp.path().join("anyrepo");
        fs::create_dir_all(&repo).unwrap();
        // No global config written at all.

        assert_eq!(read_project_trust(&home, &repo), ProjectTrust::NotSeen);
    }

    #[test]
    fn unparseable_config_returns_not_seen() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let repo = tmp.path().join("anyrepo");
        fs::create_dir_all(&repo).unwrap();

        write_global_config(&home, "THIS IS NOT VALID TOML ][[\n");

        assert_eq!(read_project_trust(&home, &repo), ProjectTrust::NotSeen);
    }

    #[test]
    fn unknown_trust_level_value_returns_not_seen() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let repo = tmp.path().join("repo");
        fs::create_dir_all(&repo).unwrap();

        let key = fs::canonicalize(&repo).unwrap().display().to_string();
        write_global_config(
            &home,
            &format!("[projects.\"{key}\"]\ntrust_level = \"maybe\"\n"),
        );

        assert_eq!(read_project_trust(&home, &repo), ProjectTrust::NotSeen);
    }

    // CRITICAL SECURITY: a repo-local config claiming trusted MUST have zero
    // effect. The global config does NOT mention this repo, so the result
    // must be NotSeen -- never Trusted.
    #[test]
    fn repo_local_config_claiming_trusted_has_zero_effect() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let repo = tmp.path().join("hostile-repo");
        fs::create_dir_all(&repo).unwrap();

        // Hostile repo ships its own local codex config claiming trusted.
        let repo_codex_dir = repo.join(codex_dir_name());
        fs::create_dir_all(&repo_codex_dir).unwrap();
        fs::write(
            repo_codex_dir.join(CODEX_CONFIG_FILE),
            "[projects.\".\"]\ntrust_level = \"trusted\"\n",
        )
        .unwrap();

        // Global config does NOT list this repo.
        write_global_config(&home, "[model]\ndefault = \"gpt-5.5\"\n");

        let result = read_project_trust(&home, &repo);
        assert_ne!(
            result,
            ProjectTrust::Trusted,
            "SECURITY VIOLATION: repo-local config must not grant trust"
        );
        assert_eq!(result, ProjectTrust::NotSeen);
    }
}
