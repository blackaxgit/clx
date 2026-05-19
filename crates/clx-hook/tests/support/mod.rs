//! Shared test support for the `clx-hook` subprocess tests.
//!
//! Every test in this crate spawns the real `clx-hook` binary with a
//! redirected `HOME`. Two hard requirements come out of that:
//!
//! 1. **RAII isolation.** The temp `HOME` MUST be a [`tempfile::TempDir`]
//!    bound to a local that lives to the end of the test. `tempfile`
//!    creates a uniquely named directory via `mkdtemp(3)` (no PID reuse,
//!    parallel-safe) and removes it on `Drop` *even when the test panics*
//!    while unwinding. A trailing `remove_dir_all` is NOT good enough: any
//!    panic before it leaks the directory forever.
//!
//! 2. **No 2.1 GB model download.** `handle_user_prompt_submit` calls
//!    `maybe_prefetch_reranker_model()`, which spawns
//!    `clx model fetch --background` whenever the bge-reranker-v2-m3 model
//!    is missing and `auto_recall.reranker_enabled` is `true` (the
//!    default when no config file is present). Pointed at a throwaway
//!    `HOME`, that fetch downloads ~2.1 GB into `$HOME/.clx/models` and,
//!    on a panic before cleanup, leaks it. We force
//!    `CLX_MODEL_FETCH_DRYRUN` on every spawned child so `clx model fetch`
//!    writes a few-byte stub instead of downloading anything. This is
//!    defense-in-depth: it holds even for tests that do not (or cannot)
//!    write `reranker_enabled: false` into a sandbox config.
//!
//! Use [`isolated_clx_home`] for the `TempDir` and [`harden_command`] to
//! stamp the hermetic env onto every `Command`. After the child runs,
//! call [`assert_home_size_bounded`] so any future regression that
//! re-enables a real model fetch fails loudly instead of silently
//! leaking gigabytes.

#![allow(dead_code)]

use std::path::Path;
use std::process::Command;

/// Upper bound for the total size of an isolated test `HOME` (bytes).
///
/// A hermetic hook run writes a tiny `SQLite` DB, a small config file, and
/// log lines: well under a megabyte. The dry-run model stub is a handful
/// of `b"dryrun"` files. 50 MiB is comfortably above any legitimate
/// hermetic footprint yet ~40x below a single real model artifact, so a
/// reintroduced 2.1 GB download trips this instantly.
pub const MAX_HOME_BYTES: u64 = 50 * 1024 * 1024;

/// Create a uniquely named, RAII-cleaned temp directory to use as `HOME`.
///
/// The returned [`tempfile::TempDir`] MUST be kept in a binding that
/// lives until the end of the test; its `Drop` removes the directory
/// recursively, including on panic/unwind. `mkdtemp` guarantees a unique
/// name so parallel tests never collide (no `process::id()` reuse).
#[must_use]
pub fn isolated_clx_home() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("clx-hook-test-")
        .tempdir()
        .expect("failed to create isolated temp HOME")
}

/// Stamp the hermetic env required by every spawned `clx-hook` child.
///
/// * `HOME` -> the isolated temp dir (sandboxes `~/.clx`).
/// * `CLX_LOG=error` -> suppress log noise (matches sibling tests).
/// * `CLX_MODEL_FETCH_DRYRUN=1` -> if the hook spawns
///   `clx model fetch --background`, it writes a few-byte stub instead
///   of downloading the 2.1 GB bge-reranker-v2-m3 model. Guarantees the
///   recall pipeline degrades to RRF-only and `$HOME/.clx/models` never
///   grows.
///
/// Returns the same `&mut Command` for chaining.
pub fn harden_command<'a>(cmd: &'a mut Command, home: &Path) -> &'a mut Command {
    cmd.env("HOME", home)
        .env("CLX_LOG", "error")
        .env("CLX_MODEL_FETCH_DRYRUN", "1")
}

/// Recursively sum the byte size of every regular file under `root`.
fn dir_size_bytes(root: &Path) -> u64 {
    let mut total = 0u64;
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(ft) = entry.file_type() else { continue };
            if ft.is_dir() {
                stack.push(entry.path());
                continue;
            }
            if !ft.is_file() {
                // Symlinks / sockets / FIFOs have no byte size to count.
                continue;
            }
            if let Ok(meta) = entry.metadata() {
                total += meta.len();
            }
        }
    }
    total
}

/// Regression guard: assert the isolated `HOME` stayed small and that no
/// real reranker model was placed under `.clx/models`.
///
/// This is the loud failure that protects against a future change
/// re-enabling a model download in tests (the ~2.1 GB disk leak).
pub fn assert_home_size_bounded(home: &Path) {
    let models = home.join(".clx/models");
    if models.exists() {
        let model_bytes = dir_size_bytes(&models);
        assert!(
            model_bytes < 5 * 1024 * 1024,
            "isolated HOME has a real reranker model under {} ({} bytes); \
             the test must run with CLX_MODEL_FETCH_DRYRUN and/or \
             reranker_enabled:false so no 2.1 GB model is downloaded",
            models.display(),
            model_bytes
        );
    }

    let total = dir_size_bytes(home);
    assert!(
        total < MAX_HOME_BYTES,
        "isolated test HOME at {} grew to {} bytes (limit {} bytes); \
         a model download likely leaked into the throwaway HOME",
        home.display(),
        total,
        MAX_HOME_BYTES
    );
}
/// Proves the RAII contract: a `TempDir` is removed on `Drop`, which runs
/// even while a panic unwinds the stack. Exposed as a plain helper so a
/// single includer can wrap it in a `#[test]` (integration test crates do
/// not honor `#[cfg(test)]` on a `#[path]`-included module, so the proof
/// lives here as a fn and is invoked from exactly one test).
pub fn assert_tempdir_removed_even_on_panic() {
    let outcome = std::panic::catch_unwind(|| {
        let guard = isolated_clx_home();
        let p = guard.path().to_path_buf();
        assert!(p.exists(), "guard dir must exist while alive");
        // Panic while `guard` is still in scope; unwind must drop it and
        // remove the directory. Return the path so we can re-check it.
        std::panic::panic_any(p);
    });
    let leaked = outcome
        .expect_err("closure must have panicked")
        .downcast::<std::path::PathBuf>()
        .expect("panic payload is the guard path");
    assert!(
        !leaked.exists(),
        "TempDir must be removed on Drop even when a panic unwinds: {}",
        leaked.display()
    );
}
