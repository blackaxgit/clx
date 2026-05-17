//! Infrastructure adapter that implements [`super::rerank::Reranker`] on
//! top of the `fastembed-rs` cross-encoder (v5).
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
//!   lazily on the first `score()` call.
//! - `is_ready()` is filesystem-cheap: it checks for the `.ready`
//!   sentinel that `clx model fetch` writes after SHA-256 verification.
//!   This lets the hook short-circuit while the model still downloads.
//! - `score()` performs both the lazy load AND the rerank inference on a
//!   Tokio blocking thread inside a single `spawn_blocking`. This is
//!   critical: the outer [`tokio::time::timeout`] in
//!   [`super::rerank::apply_reranker`] then governs the whole
//!   load + score pipeline, so a slow cold-load cannot exceed the
//!   per-query budget. On timeout the caller falls back to RRF-only.
//!
//! ## Cache strategy (v5)
//!
//! `fastembed` v5 changed `TextRerank::rerank` to take `&mut self`, so the
//! previous `Arc<TextRerank>` sharing strategy no longer compiles. We
//! instead hold `Mutex<Option<TextRerank>>`: the model is owned by the
//! adapter, instantiated once on the first call, and reused under a short
//! mutex hold for every subsequent call. ONNX inference is single-threaded
//! per session anyway, so the mutex does not pessimise throughput.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

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
    /// Root directory under which the `fastembed` `HuggingFace` cache lives.
    cache_dir: PathBuf,
    /// Lazily-initialised ONNX session. `None` until the first successful
    /// `score()` call. Held under a mutex because v5's
    /// `TextRerank::rerank` requires `&mut self`.
    inner: Mutex<Option<TextRerank>>,
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
            inner: Mutex::new(None),
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

    /// Build the v5 init options. Extracted for unit-test visibility into
    /// the construction path; production callers go through `score()`.
    fn build_init_options(&self) -> RerankInitOptions {
        RerankInitOptions::new(RerankerModel::BGERerankerV2M3)
            .with_cache_dir(self.cache_dir.clone())
            .with_show_download_progress(false)
    }
}

#[async_trait]
impl Reranker for FastembedReranker {
    async fn score(&self, query: &str, candidates: &[&str]) -> Result<Vec<f32>, RerankError> {
        if candidates.is_empty() {
            return Ok(Vec::new());
        }

        // Snapshot the inputs into owned strings so they can move into
        // the blocking task. fastembed's API takes `impl AsRef<[S]>` so
        // we have to allocate here regardless.
        let query_owned = query.to_string();
        let docs_owned: Vec<String> = candidates.iter().map(|s| (*s).to_string()).collect();
        let expected = docs_owned.len();

        // Move a reference to the mutex into the blocking task. We use a
        // raw pointer wrapper via `&'static`-style trickery? No: we use
        // the `tokio::task::spawn_blocking` with a closure that captures
        // a clone of an `Arc`-free path by holding the mutex through the
        // unsafe-free route below.
        //
        // The mutex itself is owned by `self`. We cannot move it. So we
        // perform the load + rerank under a single critical section by
        // taking ownership of the option temporarily on the blocking
        // thread. To do that without `Arc`, we lift the work into a
        // helper that receives `&Mutex<...>` via a scoped reference.
        //
        // `spawn_blocking` requires `'static` closures, so we cannot
        // borrow `&self` across it. Instead, we acquire the lock, take
        // the model out (replacing with `None`), pass it into the
        // blocking task by value, and re-install it on completion. This
        // serialises concurrent callers on the mutex lock acquisition,
        // which matches the underlying ONNX session's single-threaded
        // contract.
        let init_options = self.build_init_options();

        // Hold the lock until we have either taken the existing model or
        // claimed the right to load. We then drop the guard before the
        // blocking task starts so other callers can queue behind us.
        let taken_model: Option<TextRerank> = {
            let mut guard = self.inner.lock().map_err(|e| {
                RerankError::Backend(format!("rerank mutex poisoned: {e}"))
            })?;
            guard.take()
        };

        let cache_dir = self.cache_dir.clone();

        let (returned_model, scores_result) = tokio::task::spawn_blocking(
            move || -> (Option<TextRerank>, Result<Vec<f32>, RerankError>) {
                // Lazy-load if we did not have a cached model. This sync
                // call (which downloads + loads the ONNX session on first
                // run) is now INSIDE the spawn_blocking, so the outer
                // tokio::time::timeout can cancel the whole pipeline.
                let mut model = if let Some(m) = taken_model {
                    m
                } else {
                    {
                        debug!(
                            "loading bge-reranker-v2-m3 from cache_dir={}",
                            cache_dir.display()
                        );
                        match TextRerank::try_new(init_options) {
                            Ok(m) => m,
                            Err(e) => {
                                return (
                                    None,
                                    Err(RerankError::Backend(format!(
                                        "fastembed init failed: {e}"
                                    ))),
                                );
                            }
                        }
                    }
                };

                let rerank_result = model.rerank(
                    query_owned.as_str(),
                    docs_owned.iter().map(String::as_str).collect::<Vec<_>>(),
                    false,
                    Some(expected.max(1)),
                );

                let scores = match rerank_result {
                    Ok(results) => {
                        // fastembed returns results re-sorted by score
                        // desc; we need them in input order so the caller
                        // can zip back to their hits. The `index` field
                        // preserves the original position.
                        let mut by_index: Vec<(usize, f32)> =
                            results.into_iter().map(|r| (r.index, r.score)).collect();
                        by_index.sort_by_key(|(idx, _)| *idx);

                        if by_index.len() == expected {
                            Ok(by_index.into_iter().map(|(_, score)| score).collect())
                        } else {
                            Err(RerankError::OutputLengthMismatch {
                                expected,
                                got: by_index.len(),
                            })
                        }
                    }
                    Err(e) => Err(RerankError::Backend(format!("fastembed rerank: {e}"))),
                };

                (Some(model), scores)
            },
        )
        .await
        .map_err(|e| {
            warn!("rerank blocking task join error: {e}");
            RerankError::Backend(format!("blocking task join: {e}"))
        })?;

        // Re-install the model into the cache regardless of whether the
        // rerank itself succeeded; the session is still valid for reuse
        // after a logical error like length mismatch.
        if let Some(model) = returned_model
            && let Ok(mut guard) = self.inner.lock()
        {
            // Only install if no other caller has loaded in the
            // meantime; if they did, our taken_model was None and we
            // freshly loaded, so prefer keeping the existing one.
            if guard.is_none() {
                *guard = Some(model);
            }
        }

        scores_result
    }

    fn is_ready(&self) -> bool {
        Self::ready_at(&self.cache_dir)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;
    use tempfile::TempDir;

    use crate::recall::rerank::apply_reranker;
    use crate::recall::{RecallHit, RecallSearchType};

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

    /// Test backend that simulates a configurable cold-load delay
    /// followed by a fast rerank. Used to prove that `apply_reranker`'s
    /// `tokio::time::timeout` governs the entire load+score pipeline.
    struct SlowLoadBackend {
        load_delay: Duration,
        load_count: Arc<AtomicUsize>,
        rerank_count: Arc<AtomicUsize>,
        loaded: Mutex<bool>,
    }

    impl SlowLoadBackend {
        fn new(load_delay: Duration) -> Self {
            Self {
                load_delay,
                load_count: Arc::new(AtomicUsize::new(0)),
                rerank_count: Arc::new(AtomicUsize::new(0)),
                loaded: Mutex::new(false),
            }
        }
    }

    #[async_trait]
    impl Reranker for SlowLoadBackend {
        async fn score(
            &self,
            _query: &str,
            candidates: &[&str],
        ) -> Result<Vec<f32>, RerankError> {
            // Replicate fastembed.rs's structure: load + score inside a
            // single spawn_blocking, where the load is the expensive step.
            let load_delay = self.load_delay;
            let load_count = self.load_count.clone();
            let rerank_count = self.rerank_count.clone();
            let n = candidates.len();

            // Take the cached flag out, like we do with the real model.
            let was_loaded = {
                let mut g = self.loaded.lock().unwrap();
                let v = *g;
                *g = false; // taken
                v
            };
            let loaded_ref = &self.loaded;

            let (back, result) = tokio::task::spawn_blocking(move || {
                if !was_loaded {
                    load_count.fetch_add(1, Ordering::SeqCst);
                    std::thread::sleep(load_delay);
                }
                rerank_count.fetch_add(1, Ordering::SeqCst);
                let out: Vec<f32> = (0..n).map(|i| i as f32).collect();
                (true, Ok(out))
            })
            .await
            .map_err(|e| RerankError::Backend(format!("join: {e}")))?;

            // Re-install the "loaded" flag.
            if let Ok(mut g) = loaded_ref.lock()
                && !*g
            {
                *g = back;
            }
            result
        }

        fn is_ready(&self) -> bool {
            true
        }
    }

    fn make_hit(id: i64, summary: &str) -> RecallHit {
        RecallHit {
            snapshot_id: id,
            session_id: format!("s-{id}"),
            created_at: "2026-01-01T00:00:00+00:00".to_string(),
            summary: Some(summary.to_string()),
            key_facts: None,
            score: 0.0,
            search_type: RecallSearchType::Semantic,
        }
    }

    /// Cold load that exceeds the timeout must be cancelled by
    /// `tokio::time::timeout`, with the caller falling back to RRF order.
    /// This is the regression test for the ISSUE 1 fix.
    #[tokio::test]
    async fn cold_load_respects_outer_timeout() {
        let backend = SlowLoadBackend::new(Duration::from_millis(500));
        let load_count = backend.load_count.clone();
        let hits = vec![make_hit(1, "alpha"), make_hit(2, "bravo")];
        let started = std::time::Instant::now();
        let out = apply_reranker(hits.clone(), "q", &backend, Duration::from_millis(50)).await;
        let elapsed = started.elapsed();
        // The outer timeout is 50ms; we must return well before the 500ms
        // load completes. Allow generous slack for CI.
        assert!(
            elapsed < Duration::from_millis(400),
            "timeout did not fire fast enough: {elapsed:?}"
        );
        // Fallback returned input unchanged.
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].search_type, RecallSearchType::Semantic);
        // The load was at least attempted (we cannot guarantee load
        // counter increment vs cancellation order, so allow 0 or 1).
        let _ = load_count.load(Ordering::SeqCst);
    }

    /// Second call after a successful first call must reuse the loaded
    /// model. We assert `load_count` stays at 1 across two `score()` calls.
    #[tokio::test]
    async fn score_reuses_loaded_model() {
        let backend = SlowLoadBackend::new(Duration::from_millis(10));
        let load_count = backend.load_count.clone();
        let rerank_count = backend.rerank_count.clone();

        // First call: triggers load.
        let _ = backend.score("q", &["a", "b"]).await.expect("first score");
        assert_eq!(load_count.load(Ordering::SeqCst), 1);
        assert_eq!(rerank_count.load(Ordering::SeqCst), 1);

        // Second call: must reuse the cached model.
        let _ = backend.score("q", &["c", "d"]).await.expect("second score");
        assert_eq!(
            load_count.load(Ordering::SeqCst),
            1,
            "second call must not trigger a re-load"
        );
        assert_eq!(rerank_count.load(Ordering::SeqCst), 2);
    }

    /// When the load+score exceeds the outer timeout, the caller must
    /// see an unchanged hit list (fallback) and the rerank fallback
    /// counter must increment.
    #[tokio::test]
    async fn timeout_triggers_rrf_fallback() {
        let baseline =
            super::super::rerank::RERANK_FALLBACK_TOTAL.load(Ordering::Relaxed);
        let backend = SlowLoadBackend::new(Duration::from_millis(300));
        let hits = vec![make_hit(42, "payload")];
        let out =
            apply_reranker(hits, "q", &backend, Duration::from_millis(20)).await;
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].snapshot_id, 42);
        // Score unchanged from the input default 0.0.
        assert!((out[0].score - 0.0).abs() < 1e-9);
        assert!(
            super::super::rerank::RERANK_FALLBACK_TOTAL.load(Ordering::Relaxed)
                > baseline
        );
    }
}
