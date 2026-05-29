//! Codex project-trust reader (P6 security invariant).
//!
//! ## SECURITY INVARIANT (RGP surface #1)
//!
//! A repository MUST NOT be able to self-declare as trusted.
//!
//! This module reads trust state ONLY from the user-owned
//! `~/.codex/config.toml` under the `[projects."<canonical-path>"]` table.
//! It NEVER reads `<repo>/.codex/config.toml`.  Any repo-local config is
//! ignored for trust purposes, which mirrors Codex's own post-CVE-2025-61260
//! remediation and prevents a hostile repository from escalating its own
//! privilege level by shipping a crafted `.codex/config.toml`.
//!
//! ## Usage
//!
//! ```ignore
//! use clx::codex::trust::{ProjectTrust, read_project_trust};
//! let trust = read_project_trust(&home, &repo_path);
//! ```

use std::path::{Path, PathBuf};

/// The three possible trust states for a Codex project directory.
///
/// `NotSeen` is the default: the path was never registered in
/// `~/.codex/config.toml`.  Callers must treat `NotSeen` the same as
/// `Untrusted` for security purposes.
// P4 wires the call site after this P6 module lands; suppress dead_code
// until then so -D warnings does not fail between phases.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum ProjectTrust {
    /// `trust_level = "trusted"` in `~/.codex/config.toml [projects.<path>]`.
    Trusted,
    /// `trust_level = "untrusted"` in `~/.codex/config.toml`.
    Untrusted,
    /// Path not present in `~/.codex/config.toml`, or the file is absent or
    /// unparseable.  Treated as untrusted by all callers.
    NotSeen,
}

/// Read the trust level for `repo` from the **user-global**
/// `~/.codex/config.toml`.
///
/// # Security invariant
///
/// This function reads ONLY `home/.codex/config.toml`.  It deliberately does
/// NOT read `repo/.codex/config.toml`.  A repository cannot self-declare its
/// own trust level.
///
/// # Canonicalization
///
/// `repo` is canonicalized via [`std::fs::canonicalize`] before being used as
/// the lookup key.  This prevents symlink-based key-confusion attacks where
/// `./my-repo` and `/home/user/my-repo` would otherwise produce different
/// lookup strings for the same directory.  If canonicalization fails (e.g.
/// directory does not exist) the original path is used as a best-effort key.
///
/// # Return value
///
/// Returns [`ProjectTrust::NotSeen`] on any read or parse error so that all
/// failure modes default to the safe (untrusted) posture.
// P4 wires the call site after this P6 module lands.
#[allow(dead_code)]
#[must_use]
pub fn read_project_trust(home: &Path, repo: &Path) -> ProjectTrust {
    let config_path = home.join(".codex").join("config.toml");

    // Read the user-global config.  Missing file -> NotSeen (safe default).
    let Ok(raw) = std::fs::read_to_string(&config_path) else {
        return ProjectTrust::NotSeen;
    };

    // Parse as TOML.  Unparseable -> NotSeen (safe default).
    let Ok(doc): Result<toml::Value, _> = toml::from_str(&raw) else {
        return ProjectTrust::NotSeen;
    };

    // Canonicalize the repo path.  Failure is non-fatal: use original string.
    let canonical_key: String = std::fs::canonicalize(repo)
        .unwrap_or_else(|_| PathBuf::from(repo))
        .display()
        .to_string();

    // Navigate: doc["projects"]["<canonical-key>"]["trust_level"]
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

    /// Helper: write `content` to `home/.codex/config.toml`.
    fn write_global_config(home: &Path, content: &str) {
        let dir = home.join(".codex");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("config.toml"), content).unwrap();
    }

    // T1: trusted path returns Trusted
    #[test]
    fn trusted_path_returns_trusted() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let repo = tmp.path().join("myrepo");
        fs::create_dir_all(&repo).unwrap();

        let canonical = fs::canonicalize(&repo).unwrap();
        let key = canonical.display().to_string();

        write_global_config(
            &home,
            &format!("[projects.\"{key}\"]\ntrust_level = \"trusted\"\n"),
        );

        assert_eq!(read_project_trust(&home, &repo), ProjectTrust::Trusted);
    }

    // T2: untrusted path returns Untrusted
    #[test]
    fn untrusted_path_returns_untrusted() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let repo = tmp.path().join("badrepo");
        fs::create_dir_all(&repo).unwrap();

        let canonical = fs::canonicalize(&repo).unwrap();
        let key = canonical.display().to_string();

        write_global_config(
            &home,
            &format!("[projects.\"{key}\"]\ntrust_level = \"untrusted\"\n"),
        );

        assert_eq!(read_project_trust(&home, &repo), ProjectTrust::Untrusted);
    }

    // T3: path not in config returns NotSeen
    #[test]
    fn unregistered_path_returns_not_seen() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let repo = tmp.path().join("unregistered");
        fs::create_dir_all(&repo).unwrap();

        write_global_config(&home, "[model]\ndefault = \"gpt-5.5\"\n");

        assert_eq!(read_project_trust(&home, &repo), ProjectTrust::NotSeen);
    }

    // T4: missing config.toml returns NotSeen
    #[test]
    fn missing_config_toml_returns_not_seen() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let repo = tmp.path().join("anyrepo");
        fs::create_dir_all(&repo).unwrap();
        // No ~/.codex/config.toml written at all.

        assert_eq!(read_project_trust(&home, &repo), ProjectTrust::NotSeen);
    }

    // T5: unparseable config.toml returns NotSeen
    #[test]
    fn unparseable_config_returns_not_seen() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let repo = tmp.path().join("anyrepo");
        fs::create_dir_all(&repo).unwrap();

        write_global_config(&home, "THIS IS NOT VALID TOML ][[\n");

        assert_eq!(read_project_trust(&home, &repo), ProjectTrust::NotSeen);
    }

    // T6 (CRITICAL SECURITY): repo-local .codex/config.toml claiming trusted
    // MUST have zero effect.  The global ~/.codex/config.toml does NOT
    // mention this repo, so the result must be NotSeen -- not Trusted.
    #[test]
    fn repo_local_config_claiming_trusted_has_zero_effect() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let repo = tmp.path().join("hostile-repo");
        fs::create_dir_all(&repo).unwrap();

        // Hostile repo ships its own .codex/config.toml claiming trusted.
        let repo_codex_dir = repo.join(".codex");
        fs::create_dir_all(&repo_codex_dir).unwrap();
        fs::write(
            repo_codex_dir.join("config.toml"),
            "[projects.\".\"]\ntrust_level = \"trusted\"\n",
        )
        .unwrap();

        // Global config does NOT list this repo.
        write_global_config(&home, "[model]\ndefault = \"gpt-5.5\"\n");

        let result = read_project_trust(&home, &repo);
        assert_ne!(
            result,
            ProjectTrust::Trusted,
            "SECURITY VIOLATION: repo-local .codex/config.toml must not grant trust"
        );
        assert_eq!(
            result,
            ProjectTrust::NotSeen,
            "expected NotSeen when only the repo-local file claims trusted"
        );
    }

    // T7: unknown trust_level string returns NotSeen
    #[test]
    fn unknown_trust_level_value_returns_not_seen() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let repo = tmp.path().join("repo");
        fs::create_dir_all(&repo).unwrap();

        let canonical = fs::canonicalize(&repo).unwrap();
        let key = canonical.display().to_string();

        write_global_config(
            &home,
            &format!("[projects.\"{key}\"]\ntrust_level = \"maybe\"\n"),
        );

        assert_eq!(read_project_trust(&home, &repo), ProjectTrust::NotSeen);
    }
}
