//! Runtime version-skew detection.
//!
//! `clx install` copies the `clx`, `clx-hook`, and `clx-mcp` binaries into
//! `~/.clx/bin` and records the installing version in a `.clx-version` stamp.
//! The host coding agent (Claude Code et al.) invokes those copies by absolute
//! path. After a package-manager upgrade (e.g. `brew upgrade clx`) the copies
//! and their stamp can go stale while the freshly upgraded `clx` on `PATH` does
//! not, leaving the long-lived `clx-hook` / `clx-mcp` processes silently
//! running an old build.
//!
//! This module provides a single, pure, testable comparison that those
//! binaries call once at startup so the skew becomes a loud, actionable signal
//! instead of a silent no-op.

use std::path::{Path, PathBuf};

/// Version of the currently-running binary (the crate's `CARGO_PKG_VERSION`,
/// shared across the workspace).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// File name of the install stamp written under `~/.clx/bin`.
pub const VERSION_STAMP_FILE: &str = ".clx-version";

/// Path to the install version stamp for the given CLX home directory
/// (`<home>/bin/.clx-version`). `home` is the `~/.clx` directory.
#[must_use]
pub fn version_stamp_path(home: &Path) -> PathBuf {
    home.join("bin").join(VERSION_STAMP_FILE)
}

/// Reads the install version stamp under `home`, if present and non-empty.
///
/// Returns `None` when the stamp file is absent or contains only whitespace
/// (CLX has not been installed into `~/.clx/bin`).
#[must_use]
pub fn read_version_stamp(home: &Path) -> Option<String> {
    std::fs::read_to_string(version_stamp_path(home))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Compares the installed `.clx-version` stamp under `home` against the
/// `running` binary version (typically [`VERSION`], i.e.
/// `env!("CARGO_PKG_VERSION")`, supplied by the caller).
///
/// Returns:
/// - `Some(warning)` when a stamp is present and differs from `running`. The
///   message names both versions and points at `clx install` to refresh.
/// - `None` when the versions match, or when no (non-empty) stamp file exists.
///   An absent stamp means CLX is not installed into `~/.clx/bin`, so reporting
///   skew would be a false alarm.
///
/// Pure aside from reading the stamp file derived from `home`; safe to call
/// once at process startup. The caller decides where to surface the message
/// (e.g. STDERR for the hook/MCP binaries, a `clx health` row).
#[must_use]
pub fn version_skew_warning(home: &Path, running: &str) -> Option<String> {
    let installed = read_version_stamp(home)?;
    if installed == running {
        return None;
    }
    Some(format!(
        "CLX version skew: installed stamp {installed} != running binary {running}; \
         run `clx install` to refresh ~/.clx/bin"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn write_stamp(home: &Path, contents: &str) {
        let bin = home.join("bin");
        fs::create_dir_all(&bin).expect("create bin dir");
        fs::write(version_stamp_path(home), contents).expect("write stamp");
    }

    #[test]
    fn skew_when_stamp_older_than_running_binary() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let home = tmp.path();
        write_stamp(home, "0.9.0\n");

        let warning = version_skew_warning(home, "0.10.0")
            .expect("expected Some(warning) when stamp differs from running version");

        assert!(
            warning.contains("0.9.0"),
            "warning must name the installed stamp version, got: {warning}"
        );
        assert!(
            warning.contains("0.10.0"),
            "warning must name the running binary version, got: {warning}"
        );
        assert!(
            warning.contains("clx install"),
            "warning must point at remediation, got: {warning}"
        );
    }

    #[test]
    fn no_skew_when_stamp_equals_running_binary() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let home = tmp.path();
        write_stamp(home, "0.10.0\n");

        assert_eq!(
            version_skew_warning(home, "0.10.0"),
            None,
            "matching versions must not report skew"
        );
    }

    #[test]
    fn no_false_skew_when_stamp_absent() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let home = tmp.path();
        // No stamp written: CLX is not installed into ~/.clx/bin.

        assert_eq!(
            version_skew_warning(home, "0.10.0"),
            None,
            "absent stamp must not be reported as version skew"
        );
    }

    #[test]
    fn empty_stamp_is_not_skew() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let home = tmp.path();
        write_stamp(home, "   \n");

        assert_eq!(
            version_skew_warning(home, "0.10.0"),
            None,
            "blank/whitespace stamp must be treated as absent, not skew"
        );
    }

    #[test]
    fn version_const_matches_cargo_pkg_version() {
        assert_eq!(VERSION, env!("CARGO_PKG_VERSION"));
    }
}
