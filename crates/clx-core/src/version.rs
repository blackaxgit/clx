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

use std::io::Read;
use std::path::{Path, PathBuf};

/// Version of the currently-running binary (the crate's `CARGO_PKG_VERSION`,
/// shared across the workspace).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// File name of the install stamp written under `~/.clx/bin`.
pub const VERSION_STAMP_FILE: &str = ".clx-version";

/// Upper bound on bytes read from the version stamp. A legitimate stamp is a
/// short semver string; anything larger is treated as anomalous and ignored so
/// a FIFO, dangling/oversized file, or hostile path at the stamp location cannot
/// hang or balloon memory at hook/MCP startup.
const STAMP_READ_CAP: u64 = 256;

/// Path to the install version stamp for the given CLX home directory
/// (`<home>/bin/.clx-version`). `home` is the `~/.clx` directory.
#[must_use]
pub fn version_stamp_path(home: &Path) -> PathBuf {
    home.join("bin").join(VERSION_STAMP_FILE)
}

/// Reads the install version stamp under `home`, if present and non-empty.
///
/// Returns `None` when the stamp file is absent, contains only whitespace
/// (CLX has not been installed into `~/.clx/bin`), or is anomalous in a way that
/// makes reading it unsafe. Specifically, `None` is returned without hanging or
/// panicking when the stamp path:
/// - is not a regular file (directory, FIFO, or a symlink resolving to a
///   non-regular file — `metadata` follows symlinks), or
/// - reports a size greater than [`STAMP_READ_CAP`].
///
/// The read itself is also capped at [`STAMP_READ_CAP`] bytes independently of
/// the reported size, defending against special files whose metadata understates
/// their length.
#[must_use]
pub fn read_version_stamp(home: &Path) -> Option<String> {
    let path = version_stamp_path(home);
    // `metadata` follows symlinks, so a symlink to a dir/FIFO is rejected here
    // exactly as a direct dir/FIFO would be.
    let meta = std::fs::metadata(&path).ok()?;
    if !meta.is_file() || meta.len() > STAMP_READ_CAP {
        return None;
    }
    let file = std::fs::File::open(&path).ok()?;
    let mut buf = Vec::new();
    file.take(STAMP_READ_CAP).read_to_end(&mut buf).ok()?;
    String::from_utf8(buf)
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
    fn oversized_stamp_is_ignored() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let home = tmp.path();
        // Well past STAMP_READ_CAP; differs from the running version, so the
        // only reason to return None is the size guard.
        let big = "9".repeat((STAMP_READ_CAP as usize) + 1024);
        write_stamp(home, &big);

        // Must not hang or panic, and must not report skew.
        assert_eq!(read_version_stamp(home), None);
        assert_eq!(version_skew_warning(home, "0.10.0"), None);
    }

    #[test]
    fn non_regular_stamp_path_is_ignored() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let home = tmp.path();
        // Create a directory where the stamp file is expected.
        fs::create_dir_all(version_stamp_path(home)).expect("mkdir stamp-as-dir");

        // Must not panic; a non-regular path is treated as "no stamp".
        assert_eq!(read_version_stamp(home), None);
        assert_eq!(version_skew_warning(home, "0.10.0"), None);
    }

    #[test]
    fn version_const_matches_cargo_pkg_version() {
        assert_eq!(VERSION, env!("CARGO_PKG_VERSION"));
    }
}
