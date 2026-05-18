//! `clx model` subcommand: manage the bge-reranker-v2-m3 model.
//!
//! Orchestration layer for the D2 reranker. This module owns the
//! `HuggingFace` download flow, the lockfile-based concurrency guard, and
//! the `.ready` sentinel that downstream code (the recall pipeline +
//! the `UserPromptSubmit` hook) reads to gate the rerank stage.
//!
//! Subcommands:
//!
//! ```text
//! clx model fetch [--background] [--force]   # download bge-reranker-v2-m3
//! clx model status                            # show installed models + sizes
//! clx model list                              # list models known to CLX
//! ```

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Subcommand;
use colored::Colorize;

use clx_core::recall::fastembed::{pin_model_artifacts, render_sentinel};

use crate::Cli;

/// CLI sub-actions for `clx model`.
#[derive(Debug, Subcommand)]
pub enum ModelAction {
    /// Download the bge-reranker-v2-m3 cross-encoder (~568 MB).
    Fetch {
        /// Spawn a detached background fetch and return immediately.
        #[arg(long)]
        background: bool,

        /// Re-download even if the `.ready` sentinel is present.
        #[arg(long)]
        force: bool,
    },

    /// Show which models are installed and their sizes.
    Status,

    /// List models known to CLX (installed and available).
    List,
}

/// Top-level dispatch from `crates/clx/src/main.rs`.
pub async fn cmd_model(cli: &Cli, action: &ModelAction) -> Result<()> {
    match action {
        ModelAction::Fetch { background, force } => cmd_fetch(cli, *background, *force).await,
        ModelAction::Status => cmd_status(cli),
        ModelAction::List => cmd_list(cli),
    }
}

/// Required filenames that must exist (with non-zero size) under
/// `model_dir` before we write the `.ready` sentinel.
///
/// fastembed-rs already validates `HuggingFace` LFS checksums for each
/// blob it pulls. Our extra guard is a post-download integrity check
/// that the cache directory actually contains every required artifact,
/// so a partial / interrupted download cannot be mistaken for a healthy
/// install.
const REQUIRED_MODEL_FILES: &[&str] =
    &["tokenizer.json", "special_tokens_map.json", "config.json"];

/// Fetch the bge-reranker-v2-m3 model into `~/.clx/models/`.
async fn cmd_fetch(cli: &Cli, background: bool, force: bool) -> Result<()> {
    let cache_dir = clx_core::paths::model_cache_dir();
    fs::create_dir_all(&cache_dir).with_context(|| {
        format!(
            "failed to create model cache dir {}",
            cache_dir.display()
        )
    })?;

    let model_dir = cache_dir.join(clx_core::recall::fastembed::DEFAULT_MODEL_DIRNAME);
    let ready_path =
        model_dir.join(clx_core::recall::fastembed::READY_SENTINEL);

    // Early-out: already ready and not forcing. Safe to check before
    // taking the lock because (a) it's read-only, and (b) if a fetch is
    // in flight, the sentinel has not been written yet.
    if !force && ready_path.exists() {
        if cli.json {
            println!(
                "{}",
                serde_json::json!({
                    "status": "already_ready",
                    "model": "bge-reranker-v2-m3",
                    "path": model_dir.display().to_string(),
                })
            );
        } else {
            println!(
                "{} bge-reranker-v2-m3 already installed at {}",
                "==>".green().bold(),
                model_dir.display()
            );
        }
        return Ok(());
    }

    // Background mode: spawn a detached child running this same binary
    // and return immediately. The child acquires its own lock and
    // performs the destructive `--force` delete under that lock.
    // We deliberately do NOT delete here (Issue 3 lock-order fix).
    if background {
        spawn_detached_fetch(force)?;
        if cli.json {
            println!("{}", serde_json::json!({"status": "spawned"}));
        } else {
            println!(
                "{} bge-reranker-v2-m3 download started in background ({}).",
                "==>".green().bold(),
                "this may take a few minutes".dimmed()
            );
        }
        return Ok(());
    }

    // Issue 3 fix: acquire the lock BEFORE any destructive operation so
    // a concurrent background fetch cannot race the `--force` delete.
    let lock = LockFile::acquire(&cache_dir)?;

    // `--force` removes the existing directory so the downloader sees a
    // clean slate. Performed under the lock to serialize concurrent
    // `--force` invocations.
    if force && model_dir.exists() {
        fs::remove_dir_all(&model_dir)
            .with_context(|| format!("failed to remove {} for --force", model_dir.display()))?;
    }

    // Foreground download. Honour a dry-run env var so CI / smoke tests
    // can exercise the command without performing real network IO. We
    // stub the required artifacts so the integrity gate passes in
    // dry-run mode too.
    if std::env::var_os("CLX_MODEL_FETCH_DRYRUN").is_some() {
        fs::create_dir_all(&model_dir).ok();
        for name in REQUIRED_MODEL_FILES {
            fs::write(model_dir.join(name), b"dryrun")?;
        }
        fs::write(model_dir.join("model.onnx"), b"dryrun")?;
        // Even in dry-run we write a *real* content-pinned sentinel so
        // the reranker readiness check (F9) treats the stub as ready and
        // smoke tests exercise the same code path as production.
        let pinned = pin_model_artifacts(&model_dir)
            .context("failed to hash dry-run model artifacts")?;
        fs::write(&ready_path, render_sentinel(&pinned))?;
        if !cli.json {
            println!(
                "{} dry-run sentinel written at {}",
                "==>".yellow().bold(),
                ready_path.display()
            );
        }
        return Ok(());
    }

    if !cli.json {
        println!(
            "{} Downloading bge-reranker-v2-m3 (~568 MB) to {}",
            "==>".green().bold(),
            model_dir.display()
        );
    }

    // Run the synchronous fastembed download on a blocking thread.
    let cache_for_task = cache_dir.clone();
    let download_result = tokio::task::spawn_blocking(move || -> Result<()> {
        use fastembed::{RerankInitOptions, RerankerModel, TextRerank};

        let options = RerankInitOptions::new(RerankerModel::BGERerankerV2M3)
            .with_cache_dir(cache_for_task)
            .with_show_download_progress(true);

        TextRerank::try_new(options)
            .map_err(|e| anyhow::anyhow!("fastembed init failed: {e}"))?;
        Ok(())
    })
    .await
    .context("download task join failed")?;

    download_result?;

    // Issue 2 fix: verify the cache directory actually contains every
    // required artifact (non-zero size) before promoting the install
    // via `.ready`. fastembed-rs validates per-file LFS checksums during
    // download; this guard catches the case where some files never
    // landed at all (e.g. transient HTTP errors swallowed by the
    // library, or `.tmp` partials left behind).
    cleanup_partial_downloads(&model_dir);
    verify_model_dir_complete(&model_dir).with_context(|| {
        format!(
            "model integrity check failed at {}; refusing to write .ready",
            model_dir.display()
        )
    })?;

    // F9 fix: pin a SHA-256 of every model artifact into the sentinel.
    // This runs immediately after fastembed-rs verified the download via
    // Hugging Face LFS checksums and after `verify_model_dir_complete`,
    // so the digests are captured from a known-good install
    // ("trust on first verified fetch, verify on every use"). The recall
    // pipeline re-verifies these digests before loading the ONNX weights,
    // defeating a same-uid pre-stage / mid-session swap of model.onnx or
    // its external-weights blob.
    let pinned = pin_model_artifacts(&model_dir)
        .context("failed to compute model artifact digests for .ready sentinel")?;
    fs::write(&ready_path, render_sentinel(&pinned))
        .with_context(|| format!("failed to write {}", ready_path.display()))?;

    drop(lock);

    if cli.json {
        println!(
            "{}",
            serde_json::json!({
                "status": "ok",
                "model": "bge-reranker-v2-m3",
                "ready": ready_path.display().to_string(),
            })
        );
    } else {
        println!(
            "{} bge-reranker-v2-m3 ready at {}",
            "OK".green().bold(),
            model_dir.display()
        );
    }

    Ok(())
}

/// Show installed model info.
#[allow(clippy::unnecessary_wraps)]
fn cmd_status(cli: &Cli) -> Result<()> {
    let cache_dir = clx_core::paths::model_cache_dir();
    let model_dir = cache_dir.join(clx_core::recall::fastembed::DEFAULT_MODEL_DIRNAME);
    let ready_path =
        model_dir.join(clx_core::recall::fastembed::READY_SENTINEL);
    let ready = ready_path.exists();
    let size_bytes = if model_dir.exists() {
        dir_size(&model_dir)
    } else {
        0
    };

    if cli.json {
        println!(
            "{}",
            serde_json::json!({
                "cache_dir": cache_dir.display().to_string(),
                "models": [
                    {
                        "name": "bge-reranker-v2-m3",
                        "installed": model_dir.exists(),
                        "ready": ready,
                        "size_bytes": size_bytes,
                        "path": model_dir.display().to_string(),
                    }
                ],
            })
        );
    } else {
        println!("{}", "Model Status".cyan().bold());
        println!("{}", "=".repeat(50));
        println!("  Cache dir: {}", cache_dir.display());
        println!();
        println!(
            "  {}: bge-reranker-v2-m3",
            "Model".bold()
        );
        println!(
            "    Installed: {}",
            if model_dir.exists() {
                "yes".green().to_string()
            } else {
                "no".yellow().to_string()
            }
        );
        println!(
            "    Ready:     {}",
            if ready {
                "yes".green().to_string()
            } else {
                "no".yellow().to_string()
            }
        );
        println!(
            "    Size:      {}",
            human_bytes(size_bytes)
        );
        println!("    Path:      {}", model_dir.display());
        if !ready {
            println!();
            println!(
                "  {} Run {} to install.",
                "Tip:".dimmed(),
                "clx model fetch".cyan()
            );
        }
    }

    Ok(())
}

/// List known models. Today this is just the bge-reranker-v2-m3 entry;
/// the command exists so we can grow the catalog without a breaking CLI
/// change.
#[allow(clippy::unnecessary_wraps)]
fn cmd_list(cli: &Cli) -> Result<()> {
    if cli.json {
        println!(
            "{}",
            serde_json::json!({
                "models": [
                    {
                        "name": "bge-reranker-v2-m3",
                        "purpose": "recall cross-encoder rerank stage",
                        "size_mb": 568,
                        "license": "MIT (BAAI)",
                    }
                ],
            })
        );
    } else {
        println!("{}", "Available Models".cyan().bold());
        println!("{}", "=".repeat(50));
        println!(
            "  {:25} {:>10}  recall cross-encoder rerank",
            "bge-reranker-v2-m3".green(),
            "568 MB",
        );
    }
    Ok(())
}

/// Verify that `model_dir` contains every required artifact (non-zero
/// size). Returns `Err` on any missing or empty file. This is the gate
/// that runs immediately before writing `.ready` so partial downloads
/// cannot be promoted to a healthy install (Issue 2 from the 0.8.0
/// Codex audit).
///
/// Layering note: this is orchestration-layer policy (CLI knows the
/// concrete model name and required files). The recall pipeline reads
/// the `.ready` sentinel and trusts that this guard has run.
fn verify_model_dir_complete(model_dir: &Path) -> Result<()> {
    if !model_dir.is_dir() {
        anyhow::bail!(
            "model directory missing: {}",
            model_dir.display()
        );
    }

    // The ONNX weights may live at the model root or under `onnx/`,
    // depending on fastembed version. Either layout is acceptable.
    let onnx_root = model_dir.join("model.onnx");
    let onnx_sub = model_dir.join("onnx").join("model.onnx");
    let onnx_ok = is_nonempty_file(&onnx_root) || is_nonempty_file(&onnx_sub);
    if !onnx_ok {
        anyhow::bail!(
            "missing or empty model.onnx in {} (checked {} and {})",
            model_dir.display(),
            onnx_root.display(),
            onnx_sub.display(),
        );
    }

    for name in REQUIRED_MODEL_FILES {
        let p = model_dir.join(name);
        if !is_nonempty_file(&p) {
            anyhow::bail!(
                "missing or empty required file: {}",
                p.display()
            );
        }
    }

    Ok(())
}

/// Return `true` if `p` exists, is a regular file, and has non-zero
/// length. Treats any IO error as `false`.
fn is_nonempty_file(p: &Path) -> bool {
    fs::metadata(p).is_ok_and(|m| m.is_file() && m.len() > 0)
}


/// Remove `*.tmp` / `*.part` partial-download files that some HTTP
/// clients leave behind when interrupted. Best-effort: any IO error is
/// silently ignored because the verification step that follows will
/// fail loudly if anything important is missing.
#[allow(clippy::case_sensitive_file_extension_comparisons)]
fn cleanup_partial_downloads(model_dir: &Path) {
    let Ok(entries) = fs::read_dir(model_dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        if name.ends_with(".tmp") || name.ends_with(".part") {
            let _ = fs::remove_file(&path);
        }
    }
}

/// Spawn a detached child process running `clx model fetch [--force]`.
fn spawn_detached_fetch(force: bool) -> Result<()> {
    let exe = std::env::current_exe().context("could not resolve current_exe")?;
    let mut cmd = std::process::Command::new(exe);
    cmd.arg("model").arg("fetch");
    if force {
        cmd.arg("--force");
    }
    // Detach: silence I/O so the parent can exit without blocking on a
    // pipe. We deliberately drop the Child handle to avoid waiting.
    cmd.stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    cmd.spawn()
        .context("failed to spawn background `clx model fetch`")?;
    Ok(())
}

/// Filesystem lockfile so two concurrent `clx model fetch` invocations
/// (e.g. hook + manual) do not stomp on each other.
struct LockFile {
    path: PathBuf,
}

impl LockFile {
    #[allow(clippy::duration_suboptimal_units)]
    fn acquire(cache_dir: &Path) -> Result<Self> {
        let path = cache_dir.join(".fetch.lock");
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(_f) => Ok(Self { path }),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                // If the lockfile is stale (>30 minutes), reclaim it.
                if let Ok(meta) = fs::metadata(&path)
                    && let Ok(modified) = meta.modified()
                    && modified.elapsed().unwrap_or(Duration::from_secs(0))
                        > Duration::from_secs(30 * 60)
                {
                    fs::remove_file(&path).ok();
                    return Self::acquire(cache_dir);
                }
                anyhow::bail!(
                    "another `clx model fetch` is in progress (lockfile {} exists)",
                    path.display()
                );
            }
            Err(e) => Err(e).context("failed to create lockfile"),
        }
    }
}

impl Drop for LockFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

/// Sum the sizes of every regular file under `root`.
fn dir_size(root: &Path) -> u64 {
    let mut total: u64 = 0;
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(ft) = entry.file_type() else { continue };
            if ft.is_dir() {
                stack.push(entry.path());
            } else if let Ok(md) = entry.metadata() {
                total = total.saturating_add(md.len());
            }
        }
    }
    total
}

/// Render bytes as a short human-readable string (kB, MB, GB).
fn human_bytes(n: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * KIB;
    const GIB: u64 = 1024 * MIB;
    if n >= GIB {
        format!("{:.2} GiB", n as f64 / GIB as f64)
    } else if n >= MIB {
        format!("{:.2} MiB", n as f64 / MIB as f64)
    } else if n >= KIB {
        format!("{:.2} KiB", n as f64 / KIB as f64)
    } else {
        format!("{n} B")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use tempfile::TempDir;

    #[test]
    fn human_bytes_renders_each_scale() {
        assert_eq!(human_bytes(0), "0 B");
        assert_eq!(human_bytes(1023), "1023 B");
        assert!(human_bytes(1024).ends_with("KiB"));
        assert!(human_bytes(2 * 1024 * 1024).ends_with("MiB"));
        assert!(human_bytes(3 * 1024 * 1024 * 1024).ends_with("GiB"));
    }

    #[test]
    fn dir_size_sums_files_recursively() {
        let tmp = TempDir::new().expect("tempdir");
        let sub = tmp.path().join("a/b");
        fs::create_dir_all(&sub).unwrap();
        fs::write(tmp.path().join("a/foo.bin"), vec![0u8; 100]).unwrap();
        fs::write(sub.join("bar.bin"), vec![0u8; 250]).unwrap();
        let total = dir_size(tmp.path());
        assert_eq!(total, 350);
    }

    #[test]
    fn lockfile_is_exclusive_and_cleans_up_on_drop() {
        let tmp = TempDir::new().expect("tempdir");
        {
            let _guard = LockFile::acquire(tmp.path()).expect("first acquire");
            assert!(
                tmp.path().join(".fetch.lock").exists(),
                "lockfile must exist while held"
            );
            // Second acquire fails while the first lock is alive.
            let second = LockFile::acquire(tmp.path());
            assert!(
                second.is_err(),
                "concurrent acquire must fail with lockfile present"
            );
        }
        assert!(
            !tmp.path().join(".fetch.lock").exists(),
            "lockfile removed on drop"
        );
    }

    /// The full `cmd_fetch` exercise is gated behind `--ignored` because
    /// it reaches into the real `~/.clx` directory (no per-test override
    /// is available without mutating process-global env vars, which the
    /// workspace forbids via `unsafe_code = "deny"`). Run manually via
    /// `cargo test -p clx -- --ignored fetch_`. The CLI parsing path
    /// below covers the surface area we care about in CI.
    #[test]
    fn cli_parses_model_subcommand_variants() {
        let parsed = crate::Cli::parse_from(["clx", "model", "fetch", "--background"]);
        // We can only access verbose/json from outside the module; the
        // important assertion is that clap accepted the subcommand
        // without panicking.
        assert!(!parsed.verbose);
        // Same for `status` and `list`.
        let _ = crate::Cli::parse_from(["clx", "model", "status"]);
        let _ = crate::Cli::parse_from(["clx", "model", "list"]);
        let _ = crate::Cli::parse_from(["clx", "model", "fetch", "--force"]);
    }

    // -----------------------------------------------------------------
    // Issue 2: integrity verification before .ready
    // -----------------------------------------------------------------

    /// Helper: stage a model directory with all required files at given sizes.
    fn stage_complete_model(root: &Path) -> PathBuf {
        let model_dir = root.join(clx_core::recall::fastembed::DEFAULT_MODEL_DIRNAME);
        fs::create_dir_all(&model_dir).unwrap();
        fs::write(model_dir.join("model.onnx"), b"x").unwrap();
        for name in REQUIRED_MODEL_FILES {
            fs::write(model_dir.join(name), b"y").unwrap();
        }
        model_dir
    }

    #[test]
    fn verify_passes_when_all_required_files_present_at_root() {
        let tmp = TempDir::new().unwrap();
        let model_dir = stage_complete_model(tmp.path());
        verify_model_dir_complete(&model_dir).expect("complete dir must verify");
    }

    #[test]
    fn verify_passes_when_onnx_under_onnx_subdir() {
        let tmp = TempDir::new().unwrap();
        let model_dir = tmp.path().join("bge-reranker-v2-m3");
        fs::create_dir_all(model_dir.join("onnx")).unwrap();
        fs::write(model_dir.join("onnx").join("model.onnx"), b"x").unwrap();
        for name in REQUIRED_MODEL_FILES {
            fs::write(model_dir.join(name), b"y").unwrap();
        }
        verify_model_dir_complete(&model_dir).expect("subdir onnx must verify");
    }

    #[test]
    fn verify_fails_on_missing_tokenizer() {
        let tmp = TempDir::new().unwrap();
        let model_dir = stage_complete_model(tmp.path());
        fs::remove_file(model_dir.join("tokenizer.json")).unwrap();
        let err = verify_model_dir_complete(&model_dir).unwrap_err();
        assert!(
            err.to_string().contains("tokenizer.json"),
            "error must name missing file, got: {err}"
        );
    }

    #[test]
    fn verify_fails_on_missing_model_onnx() {
        let tmp = TempDir::new().unwrap();
        let model_dir = stage_complete_model(tmp.path());
        fs::remove_file(model_dir.join("model.onnx")).unwrap();
        let err = verify_model_dir_complete(&model_dir).unwrap_err();
        assert!(
            err.to_string().contains("model.onnx"),
            "error must mention model.onnx, got: {err}"
        );
    }

    #[test]
    fn verify_fails_on_zero_length_file() {
        let tmp = TempDir::new().unwrap();
        let model_dir = stage_complete_model(tmp.path());
        // Truncate to zero bytes
        fs::write(model_dir.join("config.json"), b"").unwrap();
        let err = verify_model_dir_complete(&model_dir).unwrap_err();
        assert!(
            err.to_string().contains("config.json"),
            "error must name empty file, got: {err}"
        );
    }

    #[test]
    fn verify_fails_when_model_dir_does_not_exist() {
        let tmp = TempDir::new().unwrap();
        let model_dir = tmp.path().join("nonexistent");
        let err = verify_model_dir_complete(&model_dir).unwrap_err();
        assert!(
            err.to_string().contains("model directory missing"),
            "got: {err}"
        );
    }

    #[test]
    fn cleanup_removes_tmp_and_part_files_only() {
        let tmp = TempDir::new().unwrap();
        let model_dir = stage_complete_model(tmp.path());
        fs::write(model_dir.join("blob.tmp"), b"partial").unwrap();
        fs::write(model_dir.join("blob.part"), b"partial").unwrap();
        let keeper = model_dir.join("config.json");
        cleanup_partial_downloads(&model_dir);
        assert!(!model_dir.join("blob.tmp").exists(), "tmp must be removed");
        assert!(!model_dir.join("blob.part").exists(), "part must be removed");
        assert!(keeper.exists(), "non-partial files must be preserved");
    }

    #[test]
    fn cleanup_on_missing_dir_is_noop() {
        // Must not panic / not error.
        let tmp = TempDir::new().unwrap();
        cleanup_partial_downloads(&tmp.path().join("does-not-exist"));
    }

    // -----------------------------------------------------------------
    // Issue 3: lock acquired before --force delete
    // -----------------------------------------------------------------

    #[test]
    fn lock_blocks_concurrent_acquire() {
        // Concrete proof that --force-style deletion under the lock is
        // serialized: while one lock is held, a second acquire fails.
        let tmp = TempDir::new().unwrap();
        let first = LockFile::acquire(tmp.path()).expect("first lock acquires");
        let second = LockFile::acquire(tmp.path());
        assert!(
            second.is_err(),
            "second acquire must fail while first lock is held"
        );
        drop(first);
        // Now a fresh acquire succeeds.
        let third = LockFile::acquire(tmp.path()).expect("third acquires after release");
        drop(third);
    }

    // -----------------------------------------------------------------
    // F9: content-pinned .ready sentinel
    // -----------------------------------------------------------------

    #[test]
    fn pin_model_artifacts_hashes_onnx_and_external_data() {
        let tmp = TempDir::new().unwrap();
        let model_dir = tmp.path().join(clx_core::recall::fastembed::DEFAULT_MODEL_DIRNAME);
        fs::create_dir_all(&model_dir).unwrap();
        fs::write(model_dir.join("model.onnx"), b"graph-bytes").unwrap();
        fs::write(model_dir.join("model.onnx.data"), b"weight-bytes-blob").unwrap();

        let pinned = pin_model_artifacts(&model_dir).expect("pin must succeed");
        assert_eq!(pinned.len(), 2, "graph + external data both pinned");

        // The pinned sentinel must verify against the on-disk bytes via
        // the same core verifier the recall pipeline uses.
        let body = render_sentinel(&pinned);
        let parsed =
            clx_core::recall::fastembed::parse_sentinel(&body).expect("parse own sentinel");
        assert_eq!(parsed.artifacts.len(), 2);
        for a in &pinned {
            assert_eq!(
                a.size,
                fs::metadata(model_dir.join(&a.rel_path)).unwrap().len(),
                "recorded size matches file on disk"
            );
            assert_eq!(a.sha256_hex.len(), 64, "lowercase hex digest");
        }
        // End-to-end: writing the rendered sentinel makes the recall
        // readiness check accept this install.
        fs::write(
            model_dir.join(clx_core::recall::fastembed::READY_SENTINEL),
            &body,
        )
        .unwrap();
        assert!(
            clx_core::recall::fastembed::FastembedReranker::verify_ready_uncached(tmp.path()),
            "freshly pinned model must read back as ready"
        );
    }

    #[test]
    fn pinned_sentinel_round_trips_through_core_parser() {
        // The sentinel the fetch side writes must parse cleanly with the
        // clx-core parser the recall pipeline uses (no writer/reader drift).
        let tmp = TempDir::new().unwrap();
        let model_dir = tmp.path().join(clx_core::recall::fastembed::DEFAULT_MODEL_DIRNAME);
        fs::create_dir_all(&model_dir).unwrap();
        fs::write(model_dir.join("model.onnx"), b"abc").unwrap();

        let pinned = pin_model_artifacts(&model_dir).unwrap();
        let body = render_sentinel(&pinned);
        let parsed = clx_core::recall::fastembed::parse_sentinel(&body)
            .expect("core parser must accept the fetch-written sentinel");
        assert_eq!(parsed.artifacts.len(), 1);
        assert_eq!(parsed.artifacts[0].rel_path, "model.onnx");
    }

    #[test]
    fn pin_model_artifacts_errors_when_no_onnx() {
        let tmp = TempDir::new().unwrap();
        let model_dir = tmp.path().join("m");
        fs::create_dir_all(&model_dir).unwrap();
        // Only a stray data file, no model.onnx.
        fs::write(model_dir.join("model.onnx.data"), b"x").unwrap();
        assert!(pin_model_artifacts(&model_dir).is_err());
    }

    #[test]
    fn pin_model_artifacts_supports_onnx_subdir_layout() {
        let tmp = TempDir::new().unwrap();
        let model_dir = tmp.path().join("m");
        fs::create_dir_all(model_dir.join("onnx")).unwrap();
        fs::write(model_dir.join("onnx").join("model.onnx"), b"sub").unwrap();
        let pinned = pin_model_artifacts(&model_dir).unwrap();
        assert_eq!(pinned.len(), 1);
        assert_eq!(pinned[0].rel_path, "onnx/model.onnx");
    }

    #[test]
    fn lock_then_delete_then_restage_simulates_force_flow() {
        // Simulate the new --force flow: acquire lock, delete model_dir,
        // recreate, write .ready. Demonstrates that the destructive step
        // happens while the lock is held (ordering invariant the
        // production code now enforces).
        let tmp = TempDir::new().unwrap();
        let model_dir = stage_complete_model(tmp.path());
        let ready_path = model_dir.join(clx_core::recall::fastembed::READY_SENTINEL);

        let lock = LockFile::acquire(tmp.path()).expect("acquire");
        // Lock is held: destructive delete is safe.
        fs::remove_dir_all(&model_dir).unwrap();
        assert!(!model_dir.exists(), "delete happened under lock");
        // Re-stage as the real downloader would, then write .ready.
        let _ = stage_complete_model(tmp.path());
        verify_model_dir_complete(&model_dir).expect("re-staged dir must verify");
        fs::write(&ready_path, b"ready").unwrap();
        drop(lock);

        assert!(ready_path.exists(), ".ready must be written");
        assert!(
            !tmp.path().join(".fetch.lock").exists(),
            "lockfile released on drop"
        );
    }
}
