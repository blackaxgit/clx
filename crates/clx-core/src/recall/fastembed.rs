//! Infrastructure adapter that implements [`super::rerank::Reranker`] on
//! top of the `fastembed-rs` cross-encoder.
//!
//! This is the only file in `clx-core` that knows about the `fastembed`
//! crate. The recall pipeline depends solely on the [`Reranker`] trait
//! defined in `rerank.rs`, so swapping the backend (or stubbing it for
//! tests) does not perturb domain code.
//!
//! ## Lifecycle
//!
//! - `FastembedReranker::new(model_dir)` constructs the adapter cheaply
//!   without loading the model. The 568 MB ONNX weights are loaded
//!   lazily on the first `score()` call via a `std::sync::OnceLock`.
//! - `is_ready()` is filesystem-cheap: it checks for the `.ready`
//!   sentinel that `clx model fetch` writes after SHA-256 verification.
//!   This lets the hook short-circuit while the model still downloads.
//! - `score()` itself runs the model on a Tokio blocking thread so the
//!   ONNX runtime (synchronous, CPU-bound) does not stall the runtime's
//!   worker threads.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::OnceLock;

use async_trait::async_trait;
use fastembed::{RerankInitOptions, RerankerModel, TextRerank};
use tracing::{debug, warn};

use super::rerank::{RerankError, Reranker};

/// Filename of the readiness sentinel written by `clx model fetch` after
/// a successful download and SHA-256 verification.
pub const READY_SENTINEL: &str = ".ready";

/// Default model directory name under [`crate::paths::model_cache_dir`].
pub const DEFAULT_MODEL_DIRNAME: &str = "bge-reranker-v2-m3";

/// `fastembed-rs` cross-encoder adapter.
///
/// Construct via [`FastembedReranker::with_default_path`] for the
/// out-of-the-box `~/.clx/models/bge-reranker-v2-m3/` location, or via
/// [`FastembedReranker::new`] when the user has configured a custom path.
pub struct FastembedReranker {
    /// Root directory under which the `fastembed` HuggingFace cache lives.
    cache_dir: PathBuf,
    /// Lazy ONNX session. Initialised on first `score()` call so that
    /// process startup stays fast even when the model is large.
    inner: OnceLock<Arc<TextRerank>>,
}

impl FastembedReranker {
    /// Construct an adapter against an explicit cache directory.
    ///
    /// The directory should be the parent of the model folder (e.g.
    /// `~/.clx/models/`), not the model folder itself; `fastembed-rs`
    /// owns the layout below this path.
    #[must_use]
    pub fn new(cache_dir: PathBuf) -> Self {
        Self {
            cache_dir,
            inner: OnceLock::new(),
        }
    }

    /// Construct an adapter using the default CLX model cache location
    /// (`~/.clx/models/`).
    #[must_use]
    pub fn with_default_path() -> Self {
        Self::new(crate::paths::model_cache_dir())
    }

    /// Path to the readiness sentinel file
    /// (`{cache_dir}/bge-reranker-v2-m3/.ready`). Public so the
    /// `clx model fetch` orchestrator can write the same file the
    /// adapter reads.
    #[must_use]
    pub fn ready_sentinel_path(&self) -> PathBuf {
        self.cache_dir
            .join(DEFAULT_MODEL_DIRNAME)
            .join(READY_SENTINEL)
    }

    /// Filesystem-cheap readiness check shared by the trait
    /// implementation and the hook's prefetch gate.
    #[must_use]
    pub fn ready_at(cache_dir: &Path) -> bool {
        cache_dir
            .join(DEFAULT_MODEL_DIRNAME)
            .join(READY_SENTINEL)
            .exists()
    }

    /// Lazily initialise the ONNX session. Returns a cloned `Arc` so
    /// callers can drop it without tearing down the cache.
    fn ensure_loaded(&self) -> Result<Arc<TextRerank>, RerankError> {
        if let Some(existing) = self.inner.get() {
            return Ok(existing.clone());
        }

        debug!(
            "loading bge-reranker-v2-m3 from cache_dir={}",
            self.cache_dir.display()
        );

        let options = RerankInitOptions::new(RerankerModel::BGERerankerV2M3)
            .with_cache_dir(self.cache_dir.clone())
            .with_show_download_progress(false);

        let model = TextRerank::try_new(options)
            .map_err(|e| RerankError::Backend(format!("fastembed init failed: {e}")))?;

        // OnceLock::set returns Err if a concurrent thread won the race;
        // in that case we simply use the value the winner installed.
        let arc = Arc::new(model);
        match self.inner.set(arc.clone()) {
            Ok(()) => Ok(arc),
            Err(_) => Ok(self
                .inner
                .get()
                .expect("OnceLock populated by concurrent winner")
                .clone()),
        }
    }
}

#[async_trait]
impl Reranker for FastembedReranker {
    async fn score(&self, query: &str, candidates: &[&str]) -> Result<Vec<f32>, RerankError> {
        if candidates.is_empty() {
            return Ok(Vec::new());
        }

        // Snapshot the inputs into owned strings so they can move into
        // the blocking task. fastembed's API takes `Vec<S>` so we have
        // to allocate here regardless.
        let query_owned = query.to_string();
        let docs_owned: Vec<String> = candidates.iter().map(|s| (*s).to_string()).collect();
        let expected = docs_owned.len();

        let model = self.ensure_loaded()?;

        let scores = tokio::task::spawn_blocking(move || {
            // Use a single batch (size = candidates.len()) since the
            // recall pipeline already truncates to ~10 candidates by
            // the time we get here; the per-batch overhead dominates.
            let results = model
                .rerank(query_owned.as_str(), docs_owned.iter().map(String::as_str).collect(), false, Some(expected.max(1)))
                .map_err(|e| RerankError::Backend(format!("fastembed rerank: {e}")))?;

            // fastembed returns results re-sorted by score desc; we
            // need them in input order so the caller can zip back to
            // their hits. The `index` field preserves the original
            // position, so we restore that ordering here.
            let mut by_index: Vec<(usize, f32)> =
                results.into_iter().map(|r| (r.index, r.score)).collect();
            by_index.sort_by_key(|(idx, _)| *idx);

            if by_index.len() != expected {
                return Err(RerankError::OutputLengthMismatch {
                    expected,
                    got: by_index.len(),
                });
            }

            Ok::<Vec<f32>, RerankError>(
                by_index.into_iter().map(|(_, score)| score).collect(),
            )
        })
        .await
        .map_err(|e| {
            warn!("rerank blocking task join error: {e}");
            RerankError::Backend(format!("blocking task join: {e}"))
        })??;

        Ok(scores)
    }

    fn is_ready(&self) -> bool {
        Self::ready_at(&self.cache_dir)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn is_ready_false_when_sentinel_missing() {
        let tmp = TempDir::new().expect("tempdir");
        let adapter = FastembedReranker::new(tmp.path().to_path_buf());
        assert!(!adapter.is_ready(), "no sentinel => not ready");
    }

    #[test]
    fn is_ready_true_when_sentinel_present() {
        let tmp = TempDir::new().expect("tempdir");
        let model_dir = tmp.path().join(DEFAULT_MODEL_DIRNAME);
        std::fs::create_dir_all(&model_dir).expect("mkdir model dir");
        std::fs::write(model_dir.join(READY_SENTINEL), b"ok").expect("write sentinel");

        let adapter = FastembedReranker::new(tmp.path().to_path_buf());
        assert!(adapter.is_ready(), "sentinel => ready");
    }

    #[test]
    fn ready_sentinel_path_layout() {
        let tmp = TempDir::new().expect("tempdir");
        let adapter = FastembedReranker::new(tmp.path().to_path_buf());
        let expected = tmp
            .path()
            .join(DEFAULT_MODEL_DIRNAME)
            .join(READY_SENTINEL);
        assert_eq!(adapter.ready_sentinel_path(), expected);
    }

    #[test]
    fn ready_at_helper_matches_instance_method() {
        let tmp = TempDir::new().expect("tempdir");
        assert!(!FastembedReranker::ready_at(tmp.path()));
        let model_dir = tmp.path().join(DEFAULT_MODEL_DIRNAME);
        std::fs::create_dir_all(&model_dir).expect("mkdir");
        std::fs::write(model_dir.join(READY_SENTINEL), b"").expect("write");
        assert!(FastembedReranker::ready_at(tmp.path()));
    }
}
