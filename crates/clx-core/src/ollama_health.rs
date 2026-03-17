//! File-based health cache for Ollama availability.
//!
//! Shares Ollama health status between short-lived hook processes via a
//! timestamp file at `~/.clx/data/ollama_health`. This avoids redundant
//! health checks when Ollama is known to be down (or up).

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use crate::paths::data_dir;

/// Name of the health cache file.
const HEALTH_FILE: &str = "ollama_health";

/// Maximum age of a health cache entry before it is considered stale.
const CACHE_TTL_SECS: u64 = 30;

/// Cached Ollama health status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthStatus {
    /// Ollama was recently confirmed available.
    Available,
    /// Ollama was recently confirmed unavailable.
    Unavailable,
    /// No recent health data (file missing, stale, or unreadable).
    Unknown,
}

/// Resolve the health cache file path.
fn health_file_path() -> PathBuf {
    data_dir().join(HEALTH_FILE)
}

/// Read cached health status from a specific path.
fn read_health_from(path: &Path) -> HealthStatus {
    let Ok(metadata) = fs::metadata(path) else {
        return HealthStatus::Unknown;
    };

    let age = SystemTime::now()
        .duration_since(metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH))
        .unwrap_or(Duration::from_secs(u64::MAX));

    if age > Duration::from_secs(CACHE_TTL_SECS) {
        return HealthStatus::Unknown;
    }

    match fs::read_to_string(path) {
        Ok(s) if s.trim() == "ok" => HealthStatus::Available,
        Ok(s) if s.trim() == "down" => HealthStatus::Unavailable,
        _ => HealthStatus::Unknown,
    }
}

/// Write health status to a specific path.
fn write_health_to(path: &Path, available: bool) {
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let _ = fs::write(path, if available { "ok" } else { "down" });
}

/// Read the cached Ollama health status from disk.
///
/// Returns [`HealthStatus::Unknown`] if the file is missing, stale (older
/// than 30 seconds), or contains unrecognised content.
#[must_use]
pub fn read_cached_health() -> HealthStatus {
    read_health_from(&health_file_path())
}

/// Write the current Ollama health status to disk.
///
/// Best-effort: silently ignores write failures (e.g., permission issues).
/// Creates parent directories if needed.
pub fn write_health(available: bool) {
    write_health_to(&health_file_path(), available);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Create a temp file path for isolated testing.
    fn temp_health_path() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "clx-health-test-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::create_dir_all(&dir);
        dir.join(HEALTH_FILE)
    }

    #[test]
    fn unknown_when_no_file() {
        let path = std::env::temp_dir().join("clx-health-nonexistent-file");
        let _ = fs::remove_file(&path);
        assert_eq!(read_health_from(&path), HealthStatus::Unknown);
    }

    #[test]
    fn write_and_read_available() {
        let path = temp_health_path();
        write_health_to(&path, true);
        assert_eq!(read_health_from(&path), HealthStatus::Available);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn write_and_read_unavailable() {
        let path = temp_health_path();
        write_health_to(&path, false);
        assert_eq!(read_health_from(&path), HealthStatus::Unavailable);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn health_status_debug_and_clone() {
        let status = HealthStatus::Available;
        let cloned = status;
        assert_eq!(format!("{cloned:?}"), "Available");
    }
}
