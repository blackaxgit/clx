//! Cross-encoder rerank stage for the recall pipeline (D2).
//!
//! This module is the **domain layer**: it defines the [`Reranker`] trait
//! and the pure `apply_reranker` orchestration helper. The actual model
//! loading and inference lives in [`crate::recall::fastembed`] (infra
//! layer) behind this trait so the recall pipeline stays I/O free at the
//! domain boundary.
//!
//! ## Pipeline contract
//!
//! `apply_reranker` is intended to be called between the RRF fusion step
//! and the time-decay step inside [`crate::recall::RecallEngine::query`].
//! It wraps the underlying backend in a [`tokio::time::timeout`] so a slow
//! or stuck model never blows the per-query latency budget; on timeout,
//! backend error, or `is_ready() == false`, it returns the input list
//! unchanged so the recall request always succeeds with RRF-only results.
//!
//! Reranked hits have their `score` field replaced with the cross-encoder
//! score (mapped into `[0.0, 1.0]` via a logistic squashing), are sorted
//! descending by that score, and have their `search_type` promoted to
//! [`RecallSearchType::Hybrid`].

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use thiserror::Error;
use tracing::warn;

use super::{RecallHit, RecallSearchType};

/// Errors raised by a [`Reranker`] backend.
#[derive(Debug, Error)]
pub enum RerankError {
    /// The underlying model file is not yet available on disk.
    #[error("reranker model not loaded")]
    ModelNotLoaded,

    /// The model produced a score vector of unexpected length.
    #[error("reranker output length mismatch: expected {expected}, got {got}")]
    OutputLengthMismatch { expected: usize, got: usize },

    /// Any other failure from the underlying backend.
    #[error("reranker backend error: {0}")]
    Backend(String),
}

/// Domain-layer trait for the rerank stage.
///
/// Implementations must be `Send + Sync` because the recall pipeline runs
/// inside a Tokio task and may be invoked from multiple worker threads.
/// The trait is intentionally narrow: it accepts a query plus a slice of
/// candidate document strings, and returns a vector of scores in the same
/// order as the candidates.
#[async_trait]
pub trait Reranker: Send + Sync {
    /// Score every `candidates[i]` against `query`. The returned vector
    /// must have the same length as `candidates`.
    async fn score(&self, query: &str, candidates: &[&str]) -> Result<Vec<f32>, RerankError>;

    /// Whether the backend is ready to serve scoring requests. When this
    /// returns `false`, [`apply_reranker`] short-circuits and returns its
    /// input unchanged (RRF-only fallback). Implementations should make
    /// this cheap: a simple filesystem `.exists()` check on a `.ready`
    /// sentinel is enough.
    fn is_ready(&self) -> bool;
}

/// Process-wide counter of rerank fallbacks (timeout, backend error, or
/// model not ready). Exposed for tests and for future telemetry plumbing.
pub static RERANK_FALLBACK_TOTAL: AtomicU64 = AtomicU64::new(0);

/// Tracks whether we have already emitted the "model not ready" warning
/// in this process. Avoids log spam when every recall query hits the
/// fallback path while the model downloads in the background.
static MODEL_NOT_READY_WARNED: AtomicU64 = AtomicU64::new(0);

/// Apply the rerank stage to a list of RRF-fused hits.
///
/// * `hits` - the RRF-fused candidate list to rerank. Owned input; the
///   function returns the same vec on the fallback path (no allocation
///   wasted).
/// * `query` - the user query that produced the candidate list.
/// * `backend` - the cross-encoder backend.
/// * `timeout` - per-call timeout. On expiry, the input list is returned
///   unchanged and `RERANK_FALLBACK_TOTAL` is incremented.
///
/// ## Behaviour summary
///
/// | Condition                              | Output                                  |
/// | -------------------------------------- | --------------------------------------- |
/// | `hits.is_empty()`                      | empty vec (no-op)                       |
/// | `!backend.is_ready()`                  | input unchanged, one-shot WARN          |
/// | `backend.score` returns `Err(_)`       | input unchanged, `RERANK_FALLBACK_TOTAL++` |
/// | `tokio::time::timeout` elapses         | input unchanged, `RERANK_FALLBACK_TOTAL++` |
/// | output length != input length         | input unchanged, `RERANK_FALLBACK_TOTAL++` |
/// | otherwise                              | scored, sorted desc, search_type=Hybrid |
pub async fn apply_reranker(
    hits: Vec<RecallHit>,
    query: &str,
    backend: &dyn Reranker,
    timeout: Duration,
) -> Vec<RecallHit> {
    if hits.is_empty() {
        return hits;
    }

    if !backend.is_ready() {
        // One-shot warn per process so the recall log is not spammed
        // while the model downloads in the background.
        if MODEL_NOT_READY_WARNED
            .compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            warn!(
                "bge-reranker-v2-m3 not yet downloaded; recall using RRF-only \
                 until model is ready. Run `clx model fetch` to fetch now."
            );
        }
        return hits;
    }

    // Build the candidate string slice. Hits with no summary contribute
    // an empty string so the model still produces a score for them
    // rather than us having to drop the row.
    let candidates: Vec<&str> = hits
        .iter()
        .map(|h| h.summary.as_deref().unwrap_or(""))
        .collect();

    let score_result =
        tokio::time::timeout(timeout, backend.score(query, &candidates)).await;

    let scores = match score_result {
        Ok(Ok(scores)) => scores,
        Ok(Err(err)) => {
            RERANK_FALLBACK_TOTAL.fetch_add(1, Ordering::Relaxed);
            warn!("reranker backend error, falling back to RRF order: {err}");
            return hits;
        }
        Err(_elapsed) => {
            RERANK_FALLBACK_TOTAL.fetch_add(1, Ordering::Relaxed);
            warn!(
                "reranker timed out after {} ms, falling back to RRF order",
                timeout.as_millis()
            );
            return hits;
        }
    };

    if scores.len() != hits.len() {
        RERANK_FALLBACK_TOTAL.fetch_add(1, Ordering::Relaxed);
        warn!(
            "reranker returned {} scores for {} candidates; falling back to RRF order",
            scores.len(),
            hits.len()
        );
        return hits;
    }

    let mut reranked: Vec<RecallHit> = hits
        .into_iter()
        .zip(scores)
        .map(|(mut hit, raw)| {
            hit.score = squash_to_unit(raw);
            hit.search_type = RecallSearchType::Hybrid;
            hit
        })
        .collect();

    reranked.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| b.snapshot_id.cmp(&a.snapshot_id))
    });

    reranked
}

/// Map a raw cross-encoder logit into `[0.0, 1.0]` via the logistic
/// function. The cross-encoder produces unbounded real-valued scores
/// (typically `[-10, +10]`); downstream stages assume scores in
/// `[0.0, 1.0]`, so we squash here once and never re-squash.
fn squash_to_unit(raw: f32) -> f64 {
    let raw = f64::from(raw);
    1.0 / (1.0 + (-raw).exp())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Mock backend that returns pre-canned scores in input order.
    /// Used to exercise `apply_reranker` deterministically without
    /// touching disk or the real model.
    struct MockReranker {
        ready: bool,
        scores: Vec<f32>,
        /// Optional artificial delay so tests can exercise the timeout
        /// path without depending on real model latency.
        delay: Option<Duration>,
        /// If `Some`, `score` returns this error instead of `Ok`.
        force_error: Option<RerankError>,
        /// Captures the most-recently-seen `candidates.len()` for assertions.
        observed_calls: Mutex<usize>,
    }

    impl MockReranker {
        fn ready_with(scores: Vec<f32>) -> Self {
            Self {
                ready: true,
                scores,
                delay: None,
                force_error: None,
                observed_calls: Mutex::new(0),
            }
        }

        fn not_ready() -> Self {
            Self {
                ready: false,
                scores: Vec::new(),
                delay: None,
                force_error: None,
                observed_calls: Mutex::new(0),
            }
        }

        fn with_delay(mut self, delay: Duration) -> Self {
            self.delay = Some(delay);
            self
        }

        fn with_error(mut self, err: RerankError) -> Self {
            self.force_error = Some(err);
            self
        }
    }

    #[async_trait]
    impl Reranker for MockReranker {
        async fn score(
            &self,
            _query: &str,
            candidates: &[&str],
        ) -> Result<Vec<f32>, RerankError> {
            *self.observed_calls.lock().unwrap() = candidates.len();
            if let Some(delay) = self.delay {
                tokio::time::sleep(delay).await;
            }
            if let Some(err) = &self.force_error {
                return Err(match err {
                    RerankError::ModelNotLoaded => RerankError::ModelNotLoaded,
                    RerankError::OutputLengthMismatch { expected, got } => {
                        RerankError::OutputLengthMismatch {
                            expected: *expected,
                            got: *got,
                        }
                    }
                    RerankError::Backend(msg) => RerankError::Backend(msg.clone()),
                });
            }
            Ok(self.scores.clone())
        }

        fn is_ready(&self) -> bool {
            self.ready
        }
    }

    fn hit(snapshot_id: i64, score: f64, summary: Option<&str>) -> RecallHit {
        RecallHit {
            snapshot_id,
            session_id: format!("session-{snapshot_id}"),
            created_at: "2026-01-01T00:00:00+00:00".to_string(),
            summary: summary.map(str::to_string),
            key_facts: Some(format!("facts {snapshot_id}")),
            score,
            search_type: RecallSearchType::Semantic,
        }
    }

    #[tokio::test]
    async fn empty_hits_returns_empty() {
        let mock = MockReranker::ready_with(vec![]);
        let out = apply_reranker(Vec::new(), "any", &mock, Duration::from_millis(50)).await;
        assert!(out.is_empty());
    }

    #[tokio::test]
    async fn single_hit_passes_through_with_new_score() {
        let mock = MockReranker::ready_with(vec![3.0]); // logistic(3.0) ~ 0.953
        let input = vec![hit(1, 0.0, Some("alpha"))];
        let out = apply_reranker(input, "q", &mock, Duration::from_millis(50)).await;
        assert_eq!(out.len(), 1);
        assert!(out[0].score > 0.9, "score {} should be > 0.9", out[0].score);
        assert_eq!(out[0].search_type, RecallSearchType::Hybrid);
    }

    #[tokio::test]
    async fn reorders_by_score_desc() {
        // Three input hits with mock scores [0.0, 5.0, 1.0]
        // -> logistic: [0.5, ~0.993, ~0.731]
        // -> expected order: B (snapshot_id=2), C (3), A (1).
        let mock = MockReranker::ready_with(vec![0.0, 5.0, 1.0]);
        let input = vec![
            hit(1, 0.0, Some("alpha")),
            hit(2, 0.0, Some("bravo")),
            hit(3, 0.0, Some("charlie")),
        ];
        let out = apply_reranker(input, "q", &mock, Duration::from_millis(50)).await;
        assert_eq!(out.len(), 3);
        assert_eq!(out[0].snapshot_id, 2);
        assert_eq!(out[1].snapshot_id, 3);
        assert_eq!(out[2].snapshot_id, 1);
        // All marked hybrid.
        for h in &out {
            assert_eq!(h.search_type, RecallSearchType::Hybrid);
        }
    }

    #[tokio::test]
    async fn timeout_returns_input_unchanged() {
        let baseline = RERANK_FALLBACK_TOTAL.load(Ordering::Relaxed);
        let mock = MockReranker::ready_with(vec![5.0])
            .with_delay(Duration::from_millis(200));
        let input = vec![hit(1, 0.7, Some("alpha"))];
        let out = apply_reranker(input.clone(), "q", &mock, Duration::from_millis(20)).await;
        assert_eq!(out.len(), 1);
        // Score must be the original (0.7) not the squashed mock (~0.993).
        assert!((out[0].score - 0.7).abs() < 1e-9);
        // Search type stays Semantic (not promoted to Hybrid).
        assert_eq!(out[0].search_type, RecallSearchType::Semantic);
        assert!(RERANK_FALLBACK_TOTAL.load(Ordering::Relaxed) > baseline);
    }

    #[tokio::test]
    async fn backend_error_returns_input_unchanged() {
        let baseline = RERANK_FALLBACK_TOTAL.load(Ordering::Relaxed);
        let mock = MockReranker::ready_with(vec![1.0])
            .with_error(RerankError::Backend("boom".to_string()));
        let input = vec![hit(7, 0.42, Some("payload"))];
        let out = apply_reranker(input, "q", &mock, Duration::from_millis(50)).await;
        assert_eq!(out.len(), 1);
        assert!((out[0].score - 0.42).abs() < 1e-9);
        assert_eq!(out[0].search_type, RecallSearchType::Semantic);
        assert!(RERANK_FALLBACK_TOTAL.load(Ordering::Relaxed) > baseline);
    }

    #[tokio::test]
    async fn marks_search_type_hybrid_on_success() {
        let mock = MockReranker::ready_with(vec![2.0, 1.0]);
        let input = vec![
            hit(1, 0.0, Some("a")),
            hit(2, 0.0, Some("b")),
        ];
        let out = apply_reranker(input, "q", &mock, Duration::from_millis(50)).await;
        assert_eq!(out.len(), 2);
        for h in &out {
            assert_eq!(h.search_type, RecallSearchType::Hybrid);
        }
    }

    #[tokio::test]
    async fn handles_missing_summary_without_panic() {
        let mock = MockReranker::ready_with(vec![1.5, 0.5]);
        let input = vec![
            hit(1, 0.0, None),         // no summary -> empty string in candidates
            hit(2, 0.0, Some("text")),
        ];
        let out = apply_reranker(input, "q", &mock, Duration::from_millis(50)).await;
        assert_eq!(out.len(), 2);
        // The first hit (snapshot_id=1) had higher mock score so it wins.
        assert_eq!(out[0].snapshot_id, 1);
    }

    #[tokio::test]
    async fn not_ready_short_circuits_without_calling_score() {
        let mock = MockReranker::not_ready();
        let input = vec![hit(1, 0.5, Some("payload"))];
        let out = apply_reranker(input.clone(), "q", &mock, Duration::from_millis(50)).await;
        // Returned unchanged; mock.score was never called.
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].snapshot_id, 1);
        assert!((out[0].score - 0.5).abs() < 1e-9);
        assert_eq!(*mock.observed_calls.lock().unwrap(), 0);
    }

    #[tokio::test]
    async fn output_length_mismatch_falls_back() {
        // Mock returns 1 score for 2 candidates -> mismatch.
        let baseline = RERANK_FALLBACK_TOTAL.load(Ordering::Relaxed);
        let mock = MockReranker::ready_with(vec![1.0]);
        let input = vec![hit(1, 0.3, Some("a")), hit(2, 0.4, Some("b"))];
        let out = apply_reranker(input, "q", &mock, Duration::from_millis(50)).await;
        assert_eq!(out.len(), 2);
        // Scores unchanged.
        assert!((out[0].score - 0.3).abs() < 1e-9);
        assert!((out[1].score - 0.4).abs() < 1e-9);
        assert!(RERANK_FALLBACK_TOTAL.load(Ordering::Relaxed) > baseline);
    }

    #[test]
    fn squash_maps_into_unit_interval() {
        assert!((squash_to_unit(0.0) - 0.5).abs() < 1e-9);
        let high = squash_to_unit(10.0);
        let low = squash_to_unit(-10.0);
        assert!(high > 0.99 && high < 1.0);
        assert!(low > 0.0 && low < 0.01);
    }
}
