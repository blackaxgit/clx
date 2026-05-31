//! Unit tests for the recall ranking path's public boundary: `apply_reranker`.
//!
//! The `rrf` and `decay` modules are `pub(crate)`, so the nearest practical
//! public boundary for the rerank/fusion-ordering behavior is
//! `clx_core::recall::apply_reranker`, which is re-exported from the crate.
//! These tests drive it through a deterministic in-test `Reranker` mock and
//! assert externally observable ordering, tie-breaking, fallback, and
//! empty/single-item edges.
//!
//! Fault model targeted: a regression that drops the descending-by-score sort,
//! swallows the length-mismatch guard, or fails to fall back to the input
//! order on backend error / timeout would change the observable hit ordering
//! returned to the recall caller.

use std::time::Duration;

use async_trait::async_trait;
use clx_core::recall::rerank::{RerankError, Reranker};
use clx_core::recall::{RecallHit, RecallSearchType, apply_reranker};

fn hit(snapshot_id: i64, score: f64) -> RecallHit {
    RecallHit {
        snapshot_id,
        session_id: format!("session-{snapshot_id}"),
        created_at: "2026-01-01T00:00:00+00:00".to_string(),
        summary: Some(format!("Summary {snapshot_id}")),
        key_facts: Some(format!("Facts {snapshot_id}")),
        score,
        search_type: RecallSearchType::Hybrid,
    }
}

/// Deterministic mock reranker. Returns a fixed score vector (aligned to the
/// candidate order it is given), or a forced error, or reports not-ready.
struct MockReranker {
    ready: bool,
    scores: Vec<f32>,
    error: Option<RerankError>,
}

impl MockReranker {
    fn ready_with(scores: Vec<f32>) -> Self {
        Self {
            ready: true,
            scores,
            error: None,
        }
    }
    fn not_ready() -> Self {
        Self {
            ready: false,
            scores: vec![],
            error: None,
        }
    }
    fn with_error(err: RerankError) -> Self {
        Self {
            ready: true,
            scores: vec![],
            error: Some(err),
        }
    }
}

#[async_trait]
impl Reranker for MockReranker {
    async fn score(&self, _query: &str, candidates: &[&str]) -> Result<Vec<f32>, RerankError> {
        if let Some(err) = &self.error {
            return match err {
                RerankError::ModelNotLoaded => Err(RerankError::ModelNotLoaded),
                RerankError::OutputLengthMismatch { expected, got } => {
                    Err(RerankError::OutputLengthMismatch {
                        expected: *expected,
                        got: *got,
                    })
                }
                RerankError::Backend(msg) => Err(RerankError::Backend(msg.clone())),
            };
        }
        // Default: return the configured scores. If empty, mirror the candidate
        // count with a flat score so the length guard passes.
        if self.scores.is_empty() {
            Ok(vec![0.0; candidates.len()])
        } else {
            Ok(self.scores.clone())
        }
    }

    fn is_ready(&self) -> bool {
        self.ready
    }
}

/// Ordering correctness: the reranker score vector must drive the final order,
/// overriding the inbound (RRF) order. Highest reranker score lands first.
#[tokio::test]
async fn rerank_reorders_by_descending_reranker_score() {
    // Inbound order is 10, 11, 12 (ids). Reranker prefers id 11 (logit 9.0),
    // then id 12 (logit 4.0), then id 10 (logit -2.0).
    let input = vec![hit(10, 0.9), hit(11, 0.5), hit(12, 0.4)];
    let mock = MockReranker::ready_with(vec![-2.0, 9.0, 4.0]);

    let out = apply_reranker(input, "q", &mock, Duration::from_millis(500)).await;

    let order: Vec<i64> = out.iter().map(|h| h.snapshot_id).collect();
    assert_eq!(
        order,
        vec![11, 12, 10],
        "rerank must reorder by descending reranker score, got {order:?}"
    );
    // Score field is replaced by the cross-encoder score (monotone in logit):
    // the new top must outscore the new bottom.
    assert!(
        out[0].score > out[2].score,
        "top hit must carry a higher post-rerank score than bottom: {:?}",
        out.iter().map(|h| h.score).collect::<Vec<_>>()
    );
}

/// Tie-breaking: equal reranker scores must produce a deterministic, stable
/// ordering (no panic on `partial_cmp` of equal floats, no nondeterminism).
#[tokio::test]
async fn rerank_equal_scores_are_deterministic() {
    let input = vec![hit(1, 0.3), hit(2, 0.3), hit(3, 0.3)];
    let mock = MockReranker::ready_with(vec![1.0, 1.0, 1.0]);

    let out_a = apply_reranker(input.clone(), "q", &mock, Duration::from_millis(500)).await;
    let out_b = apply_reranker(input, "q", &mock, Duration::from_millis(500)).await;

    let ids_a: Vec<i64> = out_a.iter().map(|h| h.snapshot_id).collect();
    let ids_b: Vec<i64> = out_b.iter().map(|h| h.snapshot_id).collect();
    assert_eq!(ids_a, ids_b, "equal-score rerank must be deterministic");
    assert_eq!(ids_a.len(), 3, "no hit may be dropped on ties");
}

/// Empty input: rerank of an empty candidate list returns empty, never panics.
#[tokio::test]
async fn rerank_empty_input_returns_empty() {
    let mock = MockReranker::ready_with(vec![]);
    let out = apply_reranker(Vec::new(), "q", &mock, Duration::from_millis(500)).await;
    assert!(out.is_empty(), "empty input must yield empty output");
}

/// Single item: rerank of a one-element list returns that element unchanged in
/// identity (same `snapshot_id`), with the reranker score applied.
#[tokio::test]
async fn rerank_single_item_preserved() {
    let input = vec![hit(7, 0.1)];
    let mock = MockReranker::ready_with(vec![5.0]);
    let out = apply_reranker(input, "q", &mock, Duration::from_millis(500)).await;
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].snapshot_id, 7);
}

/// Not-ready backend: pipeline must short-circuit and return the input order
/// UNCHANGED (RRF-only fallback). This proves the readiness guard.
#[tokio::test]
async fn rerank_not_ready_returns_input_order_unchanged() {
    let input = vec![hit(1, 0.9), hit(2, 0.8), hit(3, 0.7)];
    let mock = MockReranker::not_ready();
    let out = apply_reranker(input.clone(), "q", &mock, Duration::from_millis(500)).await;
    let order: Vec<i64> = out.iter().map(|h| h.snapshot_id).collect();
    assert_eq!(
        order,
        vec![1, 2, 3],
        "not-ready backend must preserve inbound order"
    );
    // Scores must be untouched on fallback.
    assert!((out[0].score - 0.9).abs() < f64::EPSILON);
}

/// Backend error: pipeline must fall back to the inbound order unchanged.
#[tokio::test]
async fn rerank_backend_error_falls_back_to_input_order() {
    let input = vec![hit(1, 0.9), hit(2, 0.8)];
    let mock = MockReranker::with_error(RerankError::Backend("boom".to_string()));
    let out = apply_reranker(input.clone(), "q", &mock, Duration::from_millis(500)).await;
    let order: Vec<i64> = out.iter().map(|h| h.snapshot_id).collect();
    assert_eq!(
        order,
        vec![1, 2],
        "backend error must preserve inbound order"
    );
}

/// Length mismatch: if the backend returns the wrong number of scores, the
/// pipeline must reject the rerank and keep the inbound order (guard against
/// index-misalignment that would scramble or corrupt results).
#[tokio::test]
async fn rerank_length_mismatch_falls_back_to_input_order() {
    let input = vec![hit(1, 0.9), hit(2, 0.8), hit(3, 0.7)];
    // Three candidates but only two scores returned.
    let mock = MockReranker::ready_with(vec![5.0, 1.0]);
    let out = apply_reranker(input.clone(), "q", &mock, Duration::from_millis(500)).await;
    let order: Vec<i64> = out.iter().map(|h| h.snapshot_id).collect();
    assert_eq!(
        order,
        vec![1, 2, 3],
        "length mismatch must preserve inbound order, not scramble it"
    );
}

/// Timeout: a slow backend must trigger the RRF-only fallback within budget,
/// returning the inbound order unchanged rather than hanging or erroring.
#[tokio::test]
async fn rerank_timeout_falls_back_to_input_order() {
    struct SlowBackend;
    #[async_trait]
    impl Reranker for SlowBackend {
        async fn score(&self, _q: &str, candidates: &[&str]) -> Result<Vec<f32>, RerankError> {
            tokio::time::sleep(Duration::from_millis(300)).await;
            Ok(vec![9.0; candidates.len()])
        }
        fn is_ready(&self) -> bool {
            true
        }
    }
    let input = vec![hit(1, 0.9), hit(2, 0.8)];
    let out = apply_reranker(input.clone(), "q", &SlowBackend, Duration::from_millis(20)).await;
    let order: Vec<i64> = out.iter().map(|h| h.snapshot_id).collect();
    assert_eq!(order, vec![1, 2], "timeout must fall back to inbound order");
}
